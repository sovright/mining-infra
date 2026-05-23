//! Forge sidecar for Stratum V1 mining pools

use bedrock_forge::{BlockReceiver, RawBlockSegment, RelayPayload, reassemble_raw_block};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

mod poller;
mod relay;

use forge_sidecar::compact::build_compact_block;
use forge_sidecar::config;
use forge_sidecar::rpc::ZebraRpc;
use forge_sidecar::submit::{
    SubmissionOutcome, SubmitBlockMode, handle_relay_compact_block, handle_relay_raw_block,
};
use poller::{TemplatePoller, TemplateUpdate};
use relay::ForgeRelay;

#[derive(Parser, Debug)]
#[command(name = "forge-sidecar")]
#[command(about = "Forge relay sidecar for Stratum V1 mining pools")]
struct Args {
    /// Configuration file path (TOML)
    #[arg(long, short = 'c')]
    config: Option<String>,

    /// Zebra RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8232")]
    zebra_url: String,

    /// Forge relay peer addresses
    #[arg(long)]
    relay_peer: Vec<String>,

    /// Authentication key (hex, 32 bytes)
    #[arg(long)]
    auth_key: Option<String>,

    /// Local bind address for forge
    #[arg(long, default_value = "0.0.0.0:0")]
    bind_addr: String,

    /// Number of FEC data shards for relay traffic
    #[arg(long, default_value = "10")]
    data_shards: usize,

    /// Number of FEC parity shards for relay traffic
    #[arg(long, default_value = "3")]
    parity_shards: usize,

    /// Poll interval in milliseconds
    #[arg(long, default_value = "100")]
    poll_interval_ms: u64,

    /// Disable local Zebra template announcements into FORGE
    #[arg(long)]
    disable_template_announcements: bool,

    /// Receive reconstructed compact blocks from the FORGE relay client
    #[arg(long)]
    receive_relay_blocks: bool,

    /// Submit eligible relay-received blocks to Zebra
    #[arg(long)]
    enable_submitblock: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("forge_sidecar=info".parse()?),
        )
        .init();

    let args = Args::parse();

    // Load config file if specified, CLI args override config
    let (
        zebra_url,
        relay_peers,
        auth_key,
        bind_addr,
        data_shards,
        parity_shards,
        poll_interval_ms,
        announce_templates,
        receive_relay_blocks,
        enable_submitblock,
    ) = if let Some(config_path) = &args.config {
        let cfg = config::Config::from_file(std::path::Path::new(config_path))?;
        (
            cfg.zebra_url.clone(),
            cfg.parsed_relay_peers()?,
            cfg.parsed_auth_key()?,
            cfg.parsed_bind_addr()?,
            cfg.data_shards,
            cfg.parity_shards,
            cfg.poll_interval_ms,
            cfg.announce_templates,
            cfg.receive_relay_blocks,
            cfg.enable_submitblock,
        )
    } else {
        // Use CLI args
        if args.relay_peer.is_empty() {
            return Err("relay_peer is required (use --relay-peer or --config)".into());
        }

        let relay_peers: Vec<SocketAddr> = args
            .relay_peer
            .iter()
            .map(|s| s.parse())
            .collect::<Result<Vec<_>, _>>()?;

        let auth_key: [u8; 32] = if let Some(key_hex) = &args.auth_key {
            let bytes = hex::decode(key_hex)?;
            if bytes.len() != 32 {
                return Err("auth_key must be 32 bytes (64 hex characters)".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else {
            [0u8; 32]
        };

        let bind_addr: SocketAddr = args.bind_addr.parse()?;

        (
            args.zebra_url.clone(),
            relay_peers,
            auth_key,
            bind_addr,
            args.data_shards,
            args.parity_shards,
            args.poll_interval_ms,
            !args.disable_template_announcements,
            args.receive_relay_blocks,
            args.enable_submitblock,
        )
    };

    if enable_submitblock && !receive_relay_blocks {
        return Err("enable_submitblock requires receive_relay_blocks".into());
    }
    if !announce_templates && !receive_relay_blocks {
        return Err(
            "disable_template_announcements requires receive_relay_blocks so the sidecar has work"
                .into(),
        );
    }

    info!(zebra_url = %zebra_url, "Starting forge sidecar");

    // Initialize Zebra RPC client
    let rpc = Arc::new(ZebraRpc::new(&zebra_url).await?);
    info!("Connected to Zebra RPC");

    // Initialize forge relay
    let relay = ForgeRelay::new_with_fec(
        relay_peers.clone(),
        auth_key,
        bind_addr,
        data_shards,
        parity_shards,
    )?;
    relay.init().await?;
    if receive_relay_blocks {
        let receiver = relay.start_with_receiver().await?;
        let mode = if enable_submitblock {
            SubmitBlockMode::Live
        } else {
            SubmitBlockMode::DryRun
        };
        spawn_relay_block_handler(receiver, Arc::clone(&rpc), mode);
    } else {
        relay.start().await?;
    }
    let relay = Arc::new(relay);

    if !announce_templates {
        info!("Template announcements disabled; sidecar running relay receive only");
        std::future::pending::<()>().await;
        return Ok(());
    }

    // Create template channel
    let (tx, mut rx) = mpsc::channel::<TemplateUpdate>(16);

    // Start template poller
    let poll_interval = Duration::from_millis(poll_interval_ms);
    let poller = TemplatePoller::new(Arc::clone(&rpc), poll_interval);
    tokio::spawn(async move {
        poller.run(tx).await;
    });

    info!(
        relay_peers = ?relay_peers,
        poll_interval_ms = poll_interval_ms,
        "Sidecar running"
    );

    // Main loop: receive template updates and announce
    while let Some(update) = rx.recv().await {
        match build_compact_block(&update.template, 0) {
            Ok(compact) => {
                let tx_count = compact.tx_count();
                if let Err(e) = relay.announce(compact).await {
                    error!(error = %e, "Failed to announce compact block");
                } else {
                    info!(
                        height = update.template.height,
                        tx_count, "Announced compact block"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to build compact block");
            }
        }
    }

    Ok(())
}

fn spawn_relay_block_handler(
    mut receiver: BlockReceiver,
    rpc: Arc<ZebraRpc>,
    mode: SubmitBlockMode,
) {
    tokio::spawn(async move {
        let mut raw_segments: HashMap<[u8; 32], Vec<Option<RawBlockSegment>>> = HashMap::new();
        while let Some(payload) = receiver.recv_payload().await {
            match payload {
                RelayPayload::CompactBlock(compact) => {
                    log_submission_outcome(
                        handle_relay_compact_block(rpc.as_ref(), &compact, mode).await,
                    );
                }
                RelayPayload::RawBlockSegment(segment) => {
                    let block_hash = segment.block_hash;
                    let segment_count = segment.segment_count as usize;
                    let entry = raw_segments
                        .entry(block_hash)
                        .or_insert_with(|| vec![None; segment_count]);
                    if entry.len() != segment_count {
                        warn!(
                            block_hash = %hex::encode(block_hash),
                            "Relay raw block segment has inconsistent segment count"
                        );
                        raw_segments.remove(&block_hash);
                        continue;
                    }
                    let index = segment.segment_index as usize;
                    if index >= entry.len() {
                        warn!(
                            block_hash = %hex::encode(block_hash),
                            segment_index = segment.segment_index,
                            segment_count = segment.segment_count,
                            "Relay raw block segment index out of bounds"
                        );
                        continue;
                    }
                    entry[index] = Some(segment);
                    if entry.iter().all(Option::is_some) {
                        let complete: Vec<RawBlockSegment> =
                            entry.iter().filter_map(Clone::clone).collect();
                        raw_segments.remove(&block_hash);
                        match reassemble_raw_block(&complete) {
                            Ok(raw_block) => {
                                log_submission_outcome(
                                    handle_relay_raw_block(
                                        rpc.as_ref(),
                                        &raw_block,
                                        Some(block_hash),
                                        mode,
                                    )
                                    .await,
                                );
                            }
                            Err(error) => {
                                warn!(%error, "Relay raw block segments did not reassemble");
                            }
                        }
                    }
                }
            }
        }
        warn!("Relay block receiver closed");
    });
}

fn log_submission_outcome(
    outcome: Result<SubmissionOutcome, forge_sidecar::submit::RelayBlockError>,
) {
    match outcome {
        Ok(SubmissionOutcome::DryRun(candidate)) => {
            info!(
                block_hash = %candidate.block_hash,
                tx_count = candidate.tx_count,
                block_bytes = candidate.block_bytes,
                "Relay block submit dry-run candidate"
            );
        }
        Ok(SubmissionOutcome::Submitted { candidate, result }) => {
            info!(
                block_hash = %candidate.block_hash,
                tx_count = candidate.tx_count,
                block_bytes = candidate.block_bytes,
                result = ?result,
                "Relay block submitted to Zebra"
            );
        }
        Err(error) => {
            warn!(%error, "Relay block is not a submit candidate");
        }
    }
}
