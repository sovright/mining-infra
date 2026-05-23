//! Forge sidecar for Stratum V1 mining pools

use bedrock_forge::{BlockReceiver, RawBlockSegment, RelayPayload, reassemble_raw_block};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

    /// Maximum incomplete raw blocks to buffer while waiting for segments
    #[arg(long, default_value = "128")]
    raw_segment_max_incomplete_blocks: usize,

    /// Maximum total raw segment payload bytes to hold in memory
    #[arg(long, default_value = "67108864")]
    raw_segment_max_payload_bytes: usize,

    /// Maximum age in seconds for an incomplete raw block segment set
    #[arg(long, default_value = "120")]
    raw_segment_ttl_secs: u64,
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
        raw_segment_max_incomplete_blocks,
        raw_segment_max_payload_bytes,
        raw_segment_ttl_secs,
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
            cfg.raw_segment_max_incomplete_blocks,
            cfg.raw_segment_max_payload_bytes,
            cfg.raw_segment_ttl_secs,
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
            args.raw_segment_max_incomplete_blocks,
            args.raw_segment_max_payload_bytes,
            args.raw_segment_ttl_secs,
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
    let raw_segment_buffer_config = RawSegmentBufferConfig::new(
        raw_segment_max_incomplete_blocks,
        raw_segment_max_payload_bytes,
        Duration::from_secs(raw_segment_ttl_secs),
    )?;

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
        spawn_relay_block_handler(receiver, Arc::clone(&rpc), mode, raw_segment_buffer_config);
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
    raw_segment_buffer_config: RawSegmentBufferConfig,
) {
    tokio::spawn(async move {
        let mut raw_segments = RawSegmentBuffer::new(raw_segment_buffer_config);
        while let Some(payload) = receiver.recv_payload().await {
            match payload {
                RelayPayload::CompactBlock(compact) => {
                    log_submission_outcome(
                        handle_relay_compact_block(rpc.as_ref(), &compact, mode).await,
                    );
                }
                RelayPayload::RawBlockSegment(segment) => {
                    let block_hash = segment.block_hash;
                    let segment_index = segment.segment_index;
                    let segment_count = segment.segment_count;
                    match raw_segments.insert(segment, Instant::now()) {
                        RawSegmentInsert::Pending => {}
                        RawSegmentInsert::Complete(segments) => {
                            match reassemble_raw_block(&segments) {
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
                        RawSegmentInsert::Dropped { reason } => warn!(
                            block_hash = %hex::encode(block_hash),
                            segment_index,
                            segment_count,
                            reason,
                            "Dropping relay raw block segment"
                        ),
                    }
                }
            }
        }
        warn!("Relay block receiver closed");
    });
}

#[derive(Clone, Copy, Debug)]
struct RawSegmentBufferConfig {
    max_incomplete_blocks: usize,
    max_total_payload_bytes: usize,
    ttl: Duration,
}

impl RawSegmentBufferConfig {
    fn new(
        max_incomplete_blocks: usize,
        max_total_payload_bytes: usize,
        ttl: Duration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if max_incomplete_blocks == 0 {
            return Err("raw_segment_max_incomplete_blocks must be > 0".into());
        }
        if max_total_payload_bytes == 0 {
            return Err("raw_segment_max_payload_bytes must be > 0".into());
        }
        if ttl.is_zero() {
            return Err("raw_segment_ttl_secs must be > 0".into());
        }
        Ok(Self {
            max_incomplete_blocks,
            max_total_payload_bytes,
            ttl,
        })
    }
}

struct RawSegmentEntry {
    first_seen: Instant,
    bytes: usize,
    segments: Vec<Option<RawBlockSegment>>,
}

struct RawSegmentBuffer {
    config: RawSegmentBufferConfig,
    entries: HashMap<[u8; 32], RawSegmentEntry>,
    total_payload_bytes: usize,
}

enum RawSegmentInsert {
    Pending,
    Complete(Vec<RawBlockSegment>),
    Dropped { reason: &'static str },
}

impl RawSegmentBuffer {
    fn new(config: RawSegmentBufferConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            total_payload_bytes: 0,
        }
    }

    fn insert(&mut self, segment: RawBlockSegment, now: Instant) -> RawSegmentInsert {
        self.expire(now);

        let block_hash = segment.block_hash;
        let segment_count = segment.segment_count as usize;
        let segment_index = segment.segment_index as usize;
        if segment_count == 0 || segment_index >= segment_count {
            return RawSegmentInsert::Dropped {
                reason: "invalid segment metadata",
            };
        }
        if segment.payload.len() > self.config.max_total_payload_bytes {
            return RawSegmentInsert::Dropped {
                reason: "segment payload exceeds raw segment byte limit",
            };
        }

        if !self.entries.contains_key(&block_hash) {
            self.evict_oldest_until_below_block_limit();
            if self.entries.len() >= self.config.max_incomplete_blocks {
                return RawSegmentInsert::Dropped {
                    reason: "raw segment block limit exhausted",
                };
            }
            self.entries.insert(
                block_hash,
                RawSegmentEntry {
                    first_seen: now,
                    bytes: 0,
                    segments: vec![None; segment_count],
                },
            );
        }

        let Some(entry) = self.entries.get_mut(&block_hash) else {
            return RawSegmentInsert::Dropped {
                reason: "raw segment entry unavailable",
            };
        };
        if entry.segments.len() != segment_count {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "inconsistent raw segment count",
            };
        }
        if entry.segments[segment_index].is_some() {
            return RawSegmentInsert::Pending;
        }
        let next_total = self
            .total_payload_bytes
            .saturating_add(segment.payload.len());
        if next_total > self.config.max_total_payload_bytes {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "raw segment byte limit exhausted",
            };
        }

        entry.bytes = entry.bytes.saturating_add(segment.payload.len());
        self.total_payload_bytes = next_total;
        entry.segments[segment_index] = Some(segment);

        if self
            .entries
            .get(&block_hash)
            .is_some_and(|entry| entry.segments.iter().all(Option::is_some))
        {
            let entry = self.remove_entry(&block_hash).expect("entry exists");
            let segments = entry
                .segments
                .into_iter()
                .map(|segment| segment.expect("complete segment set"))
                .collect();
            RawSegmentInsert::Complete(segments)
        } else {
            RawSegmentInsert::Pending
        }
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter_map(|(block_hash, entry)| {
                let expired = now
                    .checked_duration_since(entry.first_seen)
                    .is_some_and(|age| age >= self.config.ttl);
                expired.then_some(*block_hash)
            })
            .collect();
        for block_hash in expired {
            self.remove_entry(&block_hash);
        }
    }

    fn evict_oldest_until_below_block_limit(&mut self) {
        while self.entries.len() >= self.config.max_incomplete_blocks {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.first_seen)
                .map(|(block_hash, _)| *block_hash)
            else {
                break;
            };
            self.remove_entry(&oldest);
        }
    }

    fn remove_entry(&mut self, block_hash: &[u8; 32]) -> Option<RawSegmentEntry> {
        let entry = self.entries.remove(block_hash)?;
        self.total_payload_bytes = self.total_payload_bytes.saturating_sub(entry.bytes);
        Some(entry)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_forge::split_raw_block;

    fn buffer_config(
        max_incomplete_blocks: usize,
        max_total_payload_bytes: usize,
        ttl: Duration,
    ) -> RawSegmentBufferConfig {
        RawSegmentBufferConfig::new(max_incomplete_blocks, max_total_payload_bytes, ttl).unwrap()
    }

    #[test]
    fn raw_segment_buffer_completes_and_frees_bytes() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
        let block_hash = [0x42; 32];
        let raw_block = vec![0xab; 25];
        let mut segments =
            split_raw_block(block_hash, &raw_block, RawBlockSegment::HEADER_LEN + 5).unwrap();
        assert!(segments.len() > 1);
        let last = segments.pop().unwrap();
        let now = Instant::now();

        for segment in segments {
            assert!(matches!(
                buffer.insert(segment, now),
                RawSegmentInsert::Pending
            ));
        }

        match buffer.insert(last, now) {
            RawSegmentInsert::Complete(segments) => {
                assert_eq!(reassemble_raw_block(&segments).unwrap(), raw_block);
            }
            RawSegmentInsert::Pending => panic!("expected complete segment set"),
            RawSegmentInsert::Dropped { reason } => panic!("unexpected drop: {reason}"),
        }
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
    }

    #[test]
    fn raw_segment_buffer_expires_incomplete_entries() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(1)));
        let now = Instant::now();
        let first =
            split_raw_block([0x01; 32], &[1, 2, 3, 4], RawBlockSegment::HEADER_LEN + 2).unwrap();
        let second =
            split_raw_block([0x02; 32], &[5, 6, 7, 8], RawBlockSegment::HEADER_LEN + 2).unwrap();

        assert!(matches!(
            buffer.insert(first[0].clone(), now),
            RawSegmentInsert::Pending
        ));
        assert_eq!(buffer.entries.len(), 1);

        assert!(matches!(
            buffer.insert(second[0].clone(), now + Duration::from_secs(2)),
            RawSegmentInsert::Pending
        ));
        assert_eq!(buffer.entries.len(), 1);
        assert!(buffer.entries.contains_key(&[0x02; 32]));
    }

    #[test]
    fn raw_segment_buffer_enforces_payload_byte_limit() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 5, Duration::from_secs(60)));
        let segments = split_raw_block(
            [0x03; 32],
            &[1, 2, 3, 4, 5, 6],
            RawBlockSegment::HEADER_LEN + 3,
        )
        .unwrap();

        assert!(matches!(
            buffer.insert(segments[0].clone(), Instant::now()),
            RawSegmentInsert::Pending
        ));
        assert!(matches!(
            buffer.insert(segments[1].clone(), Instant::now()),
            RawSegmentInsert::Dropped {
                reason: "raw segment byte limit exhausted"
            }
        ));
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
    }

    #[test]
    fn raw_segment_buffer_evicts_oldest_when_block_limit_is_full() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(1, 1024, Duration::from_secs(60)));
        let now = Instant::now();
        let first =
            split_raw_block([0x04; 32], &[1, 2, 3, 4], RawBlockSegment::HEADER_LEN + 2).unwrap();
        let second =
            split_raw_block([0x05; 32], &[5, 6, 7, 8], RawBlockSegment::HEADER_LEN + 2).unwrap();

        assert!(matches!(
            buffer.insert(first[0].clone(), now),
            RawSegmentInsert::Pending
        ));
        assert!(matches!(
            buffer.insert(second[0].clone(), now + Duration::from_millis(1)),
            RawSegmentInsert::Pending
        ));

        assert_eq!(buffer.entries.len(), 1);
        assert!(buffer.entries.contains_key(&[0x05; 32]));
    }
}
