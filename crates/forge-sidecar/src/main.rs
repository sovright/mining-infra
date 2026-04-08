//! Forge sidecar for Stratum V1 mining pools

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

mod poller;
mod relay;

use forge_sidecar::compact::build_compact_block;
use forge_sidecar::config;
use forge_sidecar::rpc::ZebraRpc;
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

    /// Poll interval in milliseconds
    #[arg(long, default_value = "100")]
    poll_interval_ms: u64,
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
    let (zebra_url, relay_peers, auth_key, bind_addr, poll_interval_ms) =
        if let Some(config_path) = &args.config {
            let cfg = config::Config::from_file(std::path::Path::new(config_path))?;
            (
                cfg.zebra_url.clone(),
                cfg.parsed_relay_peers()?,
                cfg.parsed_auth_key()?,
                cfg.parsed_bind_addr()?,
                cfg.poll_interval_ms,
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
                args.poll_interval_ms,
            )
        };

    info!(zebra_url = %zebra_url, "Starting forge sidecar");

    // Initialize Zebra RPC client
    let rpc = Arc::new(ZebraRpc::new(&zebra_url).await?);
    info!("Connected to Zebra RPC");

    // Initialize forge relay
    let relay = ForgeRelay::new(relay_peers.clone(), auth_key, bind_addr)?;
    relay.init().await?;
    relay.start().await?;
    let relay = Arc::new(relay);

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
