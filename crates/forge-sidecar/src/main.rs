//! Forge sidecar for Stratum V1 mining pools

use bedrock_forge::{
    BlockReceiver, CompactBlock, MempoolProvider, RawBlockSegment, RelayPayload, TxCache,
    TxCacheConfig, TxCacheInsertOutcome, TxCacheSnapshot, TxFeedRecord, WtxId,
    reassemble_raw_block,
};
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

mod poller;
mod relay;

use forge_sidecar::compact::build_compact_block;
use forge_sidecar::config;
use forge_sidecar::rpc::ZebraRpc;
use forge_sidecar::submit::{
    RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitBlockStatus,
    handle_relay_compact_block, handle_relay_compact_block_with_mempool, handle_relay_raw_block,
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

    /// Reconstruct relay compact blocks with short IDs from the sidecar mempool
    #[arg(long)]
    compact_reconstruction_enabled: bool,

    /// Maintain a sidecar-local transaction cache for compact reconstruction
    #[arg(long)]
    tx_cache_enabled: bool,

    /// Optional local TCP bind address for transaction-feed ingestion
    #[arg(long)]
    tx_feed_bind_addr: Option<String>,

    /// Maximum transactions to keep in the sidecar transaction cache
    #[arg(long, default_value = "50000")]
    tx_cache_max_entries: usize,

    /// Maximum total transaction bytes to keep in the sidecar transaction cache
    #[arg(long, default_value = "134217728")]
    tx_cache_max_bytes: usize,

    /// Maximum individual transaction payload size to cache
    #[arg(long, default_value = "2097152")]
    tx_cache_max_tx_bytes: usize,

    /// Maximum incomplete raw blocks to buffer while waiting for segments
    #[arg(long, default_value = "128")]
    raw_segment_max_incomplete_blocks: usize,

    /// Maximum total raw segment payload bytes to hold in memory
    #[arg(long, default_value = "67108864")]
    raw_segment_max_payload_bytes: usize,

    /// Maximum age in seconds for an incomplete raw block segment set
    #[arg(long, default_value = "120")]
    raw_segment_ttl_secs: u64,

    /// Outbound relay packets to send before applying send-burst-delay-micros
    #[arg(long, default_value = "0")]
    send_burst_packets: usize,

    /// Optional client-side delay after each outbound relay packet burst
    #[arg(long, default_value = "0")]
    send_burst_delay_micros: u64,

    /// Optional Prometheus textfile path for sidecar receive metrics
    #[arg(long)]
    metrics_textfile: Option<PathBuf>,
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
        compact_reconstruction_enabled,
        tx_cache_enabled,
        tx_feed_bind_addr,
        tx_cache_max_entries,
        tx_cache_max_bytes,
        tx_cache_max_tx_bytes,
        raw_segment_max_incomplete_blocks,
        raw_segment_max_payload_bytes,
        raw_segment_ttl_secs,
        send_burst_packets,
        send_burst_delay_micros,
        metrics_textfile,
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
            cfg.compact_reconstruction_enabled,
            cfg.tx_cache_enabled,
            cfg.tx_feed_bind_addr.clone(),
            cfg.tx_cache_max_entries,
            cfg.tx_cache_max_bytes,
            cfg.tx_cache_max_tx_bytes,
            cfg.raw_segment_max_incomplete_blocks,
            cfg.raw_segment_max_payload_bytes,
            cfg.raw_segment_ttl_secs,
            cfg.send_burst_packets,
            cfg.send_burst_delay_micros,
            cfg.metrics_textfile.clone(),
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
            args.compact_reconstruction_enabled,
            args.tx_cache_enabled,
            args.tx_feed_bind_addr.clone(),
            args.tx_cache_max_entries,
            args.tx_cache_max_bytes,
            args.tx_cache_max_tx_bytes,
            args.raw_segment_max_incomplete_blocks,
            args.raw_segment_max_payload_bytes,
            args.raw_segment_ttl_secs,
            args.send_burst_packets,
            args.send_burst_delay_micros,
            args.metrics_textfile.clone(),
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
    if tx_feed_bind_addr.is_some() && !tx_cache_enabled {
        return Err("tx_feed_bind_addr requires tx_cache_enabled".into());
    }
    let raw_segment_buffer_config = RawSegmentBufferConfig::new(
        raw_segment_max_incomplete_blocks,
        raw_segment_max_payload_bytes,
        Duration::from_secs(raw_segment_ttl_secs),
    )?;

    info!(zebra_url = %zebra_url, "Starting forge sidecar");
    let metrics = Arc::new(SidecarMetrics::default());
    let mempool = Arc::new(SidecarMempool::from_tx_cache_config(SidecarTxCacheConfig {
        enabled: tx_cache_enabled,
        max_entries: tx_cache_max_entries,
        max_bytes: tx_cache_max_bytes,
        max_tx_bytes: tx_cache_max_tx_bytes,
    }));
    if let Some(snapshot) = mempool.tx_cache_snapshot() {
        metrics.set_tx_cache_snapshot(&snapshot);
    }
    if let Some(bind_addr) = tx_feed_bind_addr {
        let bind_addr: SocketAddr = bind_addr.parse()?;
        let local_addr =
            start_tx_feed_listener(bind_addr, Arc::clone(&mempool), Arc::clone(&metrics)).await?;
        info!(%local_addr, "Sidecar transaction feed listener started");
    }
    if let Some(path) = metrics_textfile {
        spawn_metrics_textfile_writer(Arc::clone(&metrics), mempool.tx_cache(), path);
    }

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
        send_burst_packets,
        Duration::from_micros(send_burst_delay_micros),
    )?;
    relay.init().await?;
    if receive_relay_blocks {
        let receiver = relay.start_with_receiver().await?;
        let mode = if enable_submitblock {
            SubmitBlockMode::Live
        } else {
            SubmitBlockMode::DryRun
        };
        spawn_relay_block_handler(
            receiver,
            Arc::clone(&rpc),
            mode,
            compact_reconstruction_enabled,
            raw_segment_buffer_config,
            Arc::clone(&metrics),
            Arc::clone(&mempool),
        );
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

async fn handle_relay_compact_payload<S, M>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
    compact_reconstruction_enabled: bool,
    mempool: &M,
    metrics: &SidecarMetrics,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    M: MempoolProvider,
{
    if compact_reconstruction_enabled && !compact.short_ids.is_empty() {
        metrics.inc_compact_reconstruction_attempts();
        let outcome =
            handle_relay_compact_block_with_mempool(submitter, compact, mode, mempool).await;
        record_compact_reconstruction_outcome(&outcome, metrics);
        outcome
    } else {
        handle_relay_compact_block(submitter, compact, mode).await
    }
}

fn spawn_relay_block_handler<M>(
    mut receiver: BlockReceiver,
    rpc: Arc<ZebraRpc>,
    mode: SubmitBlockMode,
    compact_reconstruction_enabled: bool,
    raw_segment_buffer_config: RawSegmentBufferConfig,
    metrics: Arc<SidecarMetrics>,
    mempool: Arc<M>,
) where
    M: MempoolProvider + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut raw_segments = RawSegmentBuffer::new(raw_segment_buffer_config);
        let mut cleanup_interval =
            tokio::time::interval(raw_segment_cleanup_interval(raw_segment_buffer_config.ttl));
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                payload = receiver.recv_payload() => {
                    let Some(payload) = payload else {
                        warn!("Relay block receiver closed");
                        break;
                    };
                    match payload {
                        RelayPayload::CompactBlock(compact) => {
                            metrics.inc_compact_blocks_received();
                            let outcome = handle_relay_compact_payload(
                                rpc.as_ref(),
                                &compact,
                                mode,
                                compact_reconstruction_enabled,
                                mempool.as_ref(),
                                metrics.as_ref(),
                            )
                            .await;
                            log_submission_outcome(outcome, metrics.as_ref());
                        }
                        RelayPayload::RawBlockSegment(segment) => {
                            metrics.inc_raw_segments_received();
                            let block_hash = segment.block_hash;
                            let segment_index = segment.segment_index;
                            let segment_count = segment.segment_count;
                            let segment_payload_bytes = segment.payload.len();
                            info!(
                                block_hash = %hex::encode(block_hash),
                                segment_index,
                                segment_count,
                                segment_payload_bytes,
                                "Relay raw block segment received"
                            );
                            match raw_segments.insert(segment, Instant::now()) {
                                RawSegmentInsert::Pending => {
                                    raw_segments.update_metrics(metrics.as_ref());
                                    info!(
                                        block_hash = %hex::encode(block_hash),
                                        segment_index,
                                        segment_count,
                                        "Relay raw block segment buffered"
                                    );
                                }
                                RawSegmentInsert::Complete(segments) => {
                                    metrics.inc_raw_segment_sets_completed();
                                    raw_segments.update_metrics(metrics.as_ref());
                                    let completed_segments = segments.len();
                                    match reassemble_raw_block(&segments) {
                                        Ok(raw_block) => {
                                            info!(
                                                block_hash = %hex::encode(block_hash),
                                                segment_count = completed_segments,
                                                raw_block_bytes = raw_block.len(),
                                                "Relay raw block segments complete"
                                            );
                                            log_submission_outcome(
                                                handle_relay_raw_block(
                                                    rpc.as_ref(),
                                                    &raw_block,
                                                    Some(block_hash),
                                                    mode,
                                                )
                                                .await,
                                                metrics.as_ref(),
                                            );
                                        }
                                        Err(error) => {
                                            metrics.inc_raw_segment_reassembly_failures();
                                            warn!(%error, "Relay raw block segments did not reassemble");
                                        }
                                    }
                                }
                                RawSegmentInsert::Dropped { reason } => {
                                    metrics.inc_raw_segment_drops();
                                    raw_segments.update_metrics(metrics.as_ref());
                                    warn!(
                                        block_hash = %hex::encode(block_hash),
                                        segment_index,
                                        segment_count,
                                        reason,
                                        "Dropping relay raw block segment"
                                    );
                                }
                            }
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    expire_raw_segment_buffer(
                        &mut raw_segments,
                        metrics.as_ref(),
                        Instant::now(),
                    );
                }
            }
        }
    });
}

#[derive(Clone)]
struct EmptyMempool;

impl MempoolProvider for EmptyMempool {
    fn get_wtxids(&self) -> Vec<WtxId> {
        Vec::new()
    }

    fn get_tx_data(&self, _wtxid: &WtxId) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
struct SidecarTxCacheConfig {
    enabled: bool,
    max_entries: usize,
    max_bytes: usize,
    max_tx_bytes: usize,
}

#[derive(Clone)]
enum SidecarMempool {
    Empty(EmptyMempool),
    TxCache(TxCache),
}

impl SidecarMempool {
    fn from_tx_cache_config(config: SidecarTxCacheConfig) -> Self {
        if config.enabled {
            Self::TxCache(TxCache::new(TxCacheConfig {
                max_entries: config.max_entries,
                max_bytes: config.max_bytes,
                max_tx_bytes: config.max_tx_bytes,
            }))
        } else {
            Self::Empty(EmptyMempool)
        }
    }

    fn tx_cache(&self) -> Option<TxCache> {
        match self {
            Self::Empty(_) => None,
            Self::TxCache(cache) => Some(cache.clone()),
        }
    }

    fn tx_cache_snapshot(&self) -> Option<TxCacheSnapshot> {
        self.tx_cache().map(|cache| cache.snapshot())
    }
}

impl MempoolProvider for SidecarMempool {
    fn get_wtxids(&self) -> Vec<WtxId> {
        match self {
            Self::Empty(mempool) => mempool.get_wtxids(),
            Self::TxCache(cache) => cache.get_wtxids(),
        }
    }

    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>> {
        match self {
            Self::Empty(mempool) => mempool.get_tx_data(wtxid),
            Self::TxCache(cache) => cache.get_tx_data(wtxid),
        }
    }
}

fn ingest_sidecar_tx_payload(
    mempool: &SidecarMempool,
    metrics: &SidecarMetrics,
    wtxid: WtxId,
    tx_bytes: Vec<u8>,
) -> Option<TxCacheInsertOutcome> {
    let cache = mempool.tx_cache()?;
    let outcome = cache.insert(wtxid, tx_bytes);
    metrics.set_tx_cache_snapshot(&cache.snapshot());
    Some(outcome)
}

async fn start_tx_feed_listener(
    bind_addr: SocketAddr,
    mempool: Arc<SidecarMempool>,
    metrics: Arc<SidecarMetrics>,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    tokio::spawn(run_tx_feed_listener(listener, mempool, metrics));
    Ok(local_addr)
}

async fn run_tx_feed_listener(
    listener: TcpListener,
    mempool: Arc<SidecarMempool>,
    metrics: Arc<SidecarMetrics>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(handle_tx_feed_connection(
                    stream,
                    peer,
                    Arc::clone(&mempool),
                    Arc::clone(&metrics),
                ));
            }
            Err(error) => {
                warn!(%error, "Sidecar transaction feed listener failed to accept connection");
                break;
            }
        }
    }
}

async fn handle_tx_feed_connection(
    stream: TcpStream,
    peer: SocketAddr,
    mempool: Arc<SidecarMempool>,
    metrics: Arc<SidecarMetrics>,
) {
    let mut lines = BufReader::new(stream).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => match TxFeedRecord::parse_line(&line) {
                Ok(record) => {
                    let tx_bytes_len = record.tx_bytes.len();
                    match ingest_sidecar_tx_payload(
                        &mempool,
                        &metrics,
                        record.wtxid,
                        record.tx_bytes,
                    ) {
                        Some(outcome) => {
                            debug!(
                                %peer,
                                tx_bytes = tx_bytes_len,
                                cache_entries = outcome.entries,
                                cache_bytes = outcome.bytes,
                                inserted = outcome.inserted,
                                "Sidecar transaction feed payload processed"
                            );
                        }
                        None => {
                            warn!(%peer, "Sidecar transaction feed received payload while tx cache is disabled")
                        }
                    }
                }
                Err(error) => {
                    warn!(%peer, %error, "Dropping invalid sidecar transaction feed line")
                }
            },
            Ok(None) => break,
            Err(error) => {
                warn!(%peer, %error, "Sidecar transaction feed connection failed");
                break;
            }
        }
    }
}

fn raw_segment_cleanup_interval(ttl: Duration) -> Duration {
    std::cmp::min(ttl, Duration::from_secs(30))
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

    fn expire(&mut self, now: Instant) -> usize {
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
        let expired_count = expired.len();
        for block_hash in expired {
            self.remove_entry(&block_hash);
        }
        expired_count
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

    fn update_metrics(&self, metrics: &SidecarMetrics) {
        metrics.set_raw_segment_buffer_state(self.entries.len(), self.total_payload_bytes);
    }
}

fn expire_raw_segment_buffer(
    raw_segments: &mut RawSegmentBuffer,
    metrics: &SidecarMetrics,
    now: Instant,
) -> usize {
    let expired_count = raw_segments.expire(now);
    if expired_count > 0 {
        raw_segments.update_metrics(metrics);
        info!(
            expired_raw_segment_blocks = expired_count,
            "Expired incomplete relay raw block segment sets"
        );
    }
    expired_count
}

fn log_submission_outcome(
    outcome: Result<SubmissionOutcome, forge_sidecar::submit::RelayBlockError>,
    metrics: &SidecarMetrics,
) {
    match outcome {
        Ok(SubmissionOutcome::DryRun(candidate)) => {
            metrics.inc_submit_dry_run_candidates();
            info!(
                block_hash = %candidate.block_hash,
                tx_count = candidate.tx_count,
                block_bytes = candidate.block_bytes,
                "Relay block submit dry-run candidate"
            );
        }
        Ok(SubmissionOutcome::Submitted { candidate, status }) => match status {
            SubmitBlockStatus::Accepted => {
                metrics.inc_submit_successes();
                info!(
                    block_hash = %candidate.block_hash,
                    tx_count = candidate.tx_count,
                    block_bytes = candidate.block_bytes,
                    submit_status = status.as_str(),
                    "Relay block accepted by Zebra"
                );
            }
            SubmitBlockStatus::Duplicate => {
                metrics.inc_submit_duplicates();
                info!(
                    block_hash = %candidate.block_hash,
                    tx_count = candidate.tx_count,
                    block_bytes = candidate.block_bytes,
                    submit_status = status.as_str(),
                    "Relay block already known to Zebra"
                );
            }
        },
        Err(error) => {
            metrics.inc_submit_rejections();
            warn!(%error, "Relay block is not a submit candidate");
        }
    }
}

fn record_compact_reconstruction_outcome(
    outcome: &Result<SubmissionOutcome, RelayBlockError>,
    metrics: &SidecarMetrics,
) {
    match outcome {
        Ok(_) => metrics.inc_compact_reconstruction_completes(),
        Err(RelayBlockError::ReconstructionIncomplete { .. }) => {
            metrics.inc_compact_reconstruction_incompletes();
        }
        Err(RelayBlockError::ReconstructionInvalid { .. }) => {
            metrics.inc_compact_reconstruction_invalids();
        }
        Err(_) => metrics.inc_compact_reconstruction_invalids(),
    }
}

#[derive(Default)]
struct SidecarMetrics {
    compact_blocks_received: AtomicU64,
    compact_reconstruction_attempts: AtomicU64,
    compact_reconstruction_completes: AtomicU64,
    compact_reconstruction_incompletes: AtomicU64,
    compact_reconstruction_invalids: AtomicU64,
    raw_segments_received: AtomicU64,
    raw_segment_sets_completed: AtomicU64,
    raw_segment_drops: AtomicU64,
    raw_segment_reassembly_failures: AtomicU64,
    submit_dry_run_candidates: AtomicU64,
    submit_successes: AtomicU64,
    submit_duplicates: AtomicU64,
    submit_rejections: AtomicU64,
    raw_segment_incomplete_blocks: AtomicUsize,
    raw_segment_payload_bytes: AtomicUsize,
    tx_cache_entries: AtomicUsize,
    tx_cache_bytes: AtomicUsize,
    tx_cache_max_entries: AtomicUsize,
    tx_cache_max_bytes: AtomicUsize,
    tx_cache_max_tx_bytes: AtomicUsize,
    tx_cache_evicted_entries_total: AtomicUsize,
    tx_cache_evicted_bytes_total: AtomicUsize,
    tx_cache_dropped_too_large_total: AtomicUsize,
}

impl SidecarMetrics {
    fn inc_compact_blocks_received(&self) {
        self.compact_blocks_received.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_compact_reconstruction_attempts(&self) {
        self.compact_reconstruction_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_compact_reconstruction_completes(&self) {
        self.compact_reconstruction_completes
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_compact_reconstruction_incompletes(&self) {
        self.compact_reconstruction_incompletes
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_compact_reconstruction_invalids(&self) {
        self.compact_reconstruction_invalids
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_raw_segments_received(&self) {
        self.raw_segments_received.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_raw_segment_sets_completed(&self) {
        self.raw_segment_sets_completed
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_raw_segment_drops(&self) {
        self.raw_segment_drops.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_raw_segment_reassembly_failures(&self) {
        self.raw_segment_reassembly_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_submit_dry_run_candidates(&self) {
        self.submit_dry_run_candidates
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_submit_successes(&self) {
        self.submit_successes.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_submit_duplicates(&self) {
        self.submit_duplicates.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_submit_rejections(&self) {
        self.submit_rejections.fetch_add(1, Ordering::Relaxed);
    }

    fn set_raw_segment_buffer_state(&self, incomplete_blocks: usize, payload_bytes: usize) {
        self.raw_segment_incomplete_blocks
            .store(incomplete_blocks, Ordering::Relaxed);
        self.raw_segment_payload_bytes
            .store(payload_bytes, Ordering::Relaxed);
    }

    fn set_tx_cache_snapshot(&self, snapshot: &TxCacheSnapshot) {
        self.tx_cache_entries
            .store(snapshot.entries, Ordering::Relaxed);
        self.tx_cache_bytes.store(snapshot.bytes, Ordering::Relaxed);
        self.tx_cache_max_entries
            .store(snapshot.max_entries, Ordering::Relaxed);
        self.tx_cache_max_bytes
            .store(snapshot.max_bytes, Ordering::Relaxed);
        self.tx_cache_max_tx_bytes
            .store(snapshot.max_tx_bytes, Ordering::Relaxed);
        self.tx_cache_evicted_entries_total
            .store(snapshot.evicted_entries_total, Ordering::Relaxed);
        self.tx_cache_evicted_bytes_total
            .store(snapshot.evicted_bytes_total, Ordering::Relaxed);
        self.tx_cache_dropped_too_large_total
            .store(snapshot.dropped_too_large_total, Ordering::Relaxed);
    }

    fn render_prometheus_text(&self) -> String {
        let compact_blocks_received = self.compact_blocks_received.load(Ordering::Relaxed);
        let compact_reconstruction_attempts =
            self.compact_reconstruction_attempts.load(Ordering::Relaxed);
        let compact_reconstruction_completes = self
            .compact_reconstruction_completes
            .load(Ordering::Relaxed);
        let compact_reconstruction_incompletes = self
            .compact_reconstruction_incompletes
            .load(Ordering::Relaxed);
        let compact_reconstruction_invalids =
            self.compact_reconstruction_invalids.load(Ordering::Relaxed);
        let raw_segments_received = self.raw_segments_received.load(Ordering::Relaxed);
        let raw_segment_sets_completed = self.raw_segment_sets_completed.load(Ordering::Relaxed);
        let raw_segment_drops = self.raw_segment_drops.load(Ordering::Relaxed);
        let raw_segment_reassembly_failures =
            self.raw_segment_reassembly_failures.load(Ordering::Relaxed);
        let submit_dry_run_candidates = self.submit_dry_run_candidates.load(Ordering::Relaxed);
        let submit_successes = self.submit_successes.load(Ordering::Relaxed);
        let submit_duplicates = self.submit_duplicates.load(Ordering::Relaxed);
        let submit_rejections = self.submit_rejections.load(Ordering::Relaxed);
        let raw_segment_incomplete_blocks =
            self.raw_segment_incomplete_blocks.load(Ordering::Relaxed);
        let raw_segment_payload_bytes = self.raw_segment_payload_bytes.load(Ordering::Relaxed);
        let tx_cache_entries = self.tx_cache_entries.load(Ordering::Relaxed);
        let tx_cache_bytes = self.tx_cache_bytes.load(Ordering::Relaxed);
        let tx_cache_max_entries = self.tx_cache_max_entries.load(Ordering::Relaxed);
        let tx_cache_max_bytes = self.tx_cache_max_bytes.load(Ordering::Relaxed);
        let tx_cache_max_tx_bytes = self.tx_cache_max_tx_bytes.load(Ordering::Relaxed);
        let tx_cache_evicted_entries_total =
            self.tx_cache_evicted_entries_total.load(Ordering::Relaxed);
        let tx_cache_evicted_bytes_total =
            self.tx_cache_evicted_bytes_total.load(Ordering::Relaxed);
        let tx_cache_dropped_too_large_total = self
            .tx_cache_dropped_too_large_total
            .load(Ordering::Relaxed);

        format!(
            concat!(
                "# TYPE forge_sidecar_relay_compact_blocks_received_total counter\n",
                "forge_sidecar_relay_compact_blocks_received_total {compact_blocks_received}\n",
                "# TYPE forge_sidecar_relay_compact_reconstruction_attempts_total counter\n",
                "forge_sidecar_relay_compact_reconstruction_attempts_total {compact_reconstruction_attempts}\n",
                "# TYPE forge_sidecar_relay_compact_reconstruction_completes_total counter\n",
                "forge_sidecar_relay_compact_reconstruction_completes_total {compact_reconstruction_completes}\n",
                "# TYPE forge_sidecar_relay_compact_reconstruction_incompletes_total counter\n",
                "forge_sidecar_relay_compact_reconstruction_incompletes_total {compact_reconstruction_incompletes}\n",
                "# TYPE forge_sidecar_relay_compact_reconstruction_invalids_total counter\n",
                "forge_sidecar_relay_compact_reconstruction_invalids_total {compact_reconstruction_invalids}\n",
                "# TYPE forge_sidecar_relay_raw_segments_received_total counter\n",
                "forge_sidecar_relay_raw_segments_received_total {raw_segments_received}\n",
                "# TYPE forge_sidecar_relay_raw_segment_sets_completed_total counter\n",
                "forge_sidecar_relay_raw_segment_sets_completed_total {raw_segment_sets_completed}\n",
                "# TYPE forge_sidecar_relay_raw_segment_drops_total counter\n",
                "forge_sidecar_relay_raw_segment_drops_total {raw_segment_drops}\n",
                "# TYPE forge_sidecar_relay_raw_segment_reassembly_failures_total counter\n",
                "forge_sidecar_relay_raw_segment_reassembly_failures_total {raw_segment_reassembly_failures}\n",
                "# TYPE forge_sidecar_relay_submit_dry_run_candidates_total counter\n",
                "forge_sidecar_relay_submit_dry_run_candidates_total {submit_dry_run_candidates}\n",
                "# TYPE forge_sidecar_relay_submit_successes_total counter\n",
                "forge_sidecar_relay_submit_successes_total {submit_successes}\n",
                "# TYPE forge_sidecar_relay_submit_duplicates_total counter\n",
                "forge_sidecar_relay_submit_duplicates_total {submit_duplicates}\n",
                "# TYPE forge_sidecar_relay_submit_rejections_total counter\n",
                "forge_sidecar_relay_submit_rejections_total {submit_rejections}\n",
                "# TYPE forge_sidecar_raw_segment_incomplete_blocks gauge\n",
                "forge_sidecar_raw_segment_incomplete_blocks {raw_segment_incomplete_blocks}\n",
                "# TYPE forge_sidecar_raw_segment_payload_bytes gauge\n",
                "forge_sidecar_raw_segment_payload_bytes {raw_segment_payload_bytes}\n",
                "# TYPE forge_sidecar_tx_cache_entries gauge\n",
                "forge_sidecar_tx_cache_entries {tx_cache_entries}\n",
                "# TYPE forge_sidecar_tx_cache_bytes gauge\n",
                "forge_sidecar_tx_cache_bytes {tx_cache_bytes}\n",
                "# TYPE forge_sidecar_tx_cache_max_entries gauge\n",
                "forge_sidecar_tx_cache_max_entries {tx_cache_max_entries}\n",
                "# TYPE forge_sidecar_tx_cache_max_bytes gauge\n",
                "forge_sidecar_tx_cache_max_bytes {tx_cache_max_bytes}\n",
                "# TYPE forge_sidecar_tx_cache_max_tx_bytes gauge\n",
                "forge_sidecar_tx_cache_max_tx_bytes {tx_cache_max_tx_bytes}\n",
                "# TYPE forge_sidecar_tx_cache_evicted_entries_total counter\n",
                "forge_sidecar_tx_cache_evicted_entries_total {tx_cache_evicted_entries_total}\n",
                "# TYPE forge_sidecar_tx_cache_evicted_bytes_total counter\n",
                "forge_sidecar_tx_cache_evicted_bytes_total {tx_cache_evicted_bytes_total}\n",
                "# TYPE forge_sidecar_tx_cache_dropped_too_large_total counter\n",
                "forge_sidecar_tx_cache_dropped_too_large_total {tx_cache_dropped_too_large_total}\n",
            ),
            compact_blocks_received = compact_blocks_received,
            compact_reconstruction_attempts = compact_reconstruction_attempts,
            compact_reconstruction_completes = compact_reconstruction_completes,
            compact_reconstruction_incompletes = compact_reconstruction_incompletes,
            compact_reconstruction_invalids = compact_reconstruction_invalids,
            raw_segments_received = raw_segments_received,
            raw_segment_sets_completed = raw_segment_sets_completed,
            raw_segment_drops = raw_segment_drops,
            raw_segment_reassembly_failures = raw_segment_reassembly_failures,
            submit_dry_run_candidates = submit_dry_run_candidates,
            submit_successes = submit_successes,
            submit_duplicates = submit_duplicates,
            submit_rejections = submit_rejections,
            raw_segment_incomplete_blocks = raw_segment_incomplete_blocks,
            raw_segment_payload_bytes = raw_segment_payload_bytes,
            tx_cache_entries = tx_cache_entries,
            tx_cache_bytes = tx_cache_bytes,
            tx_cache_max_entries = tx_cache_max_entries,
            tx_cache_max_bytes = tx_cache_max_bytes,
            tx_cache_max_tx_bytes = tx_cache_max_tx_bytes,
            tx_cache_evicted_entries_total = tx_cache_evicted_entries_total,
            tx_cache_evicted_bytes_total = tx_cache_evicted_bytes_total,
            tx_cache_dropped_too_large_total = tx_cache_dropped_too_large_total,
        )
    }
}

fn spawn_metrics_textfile_writer(
    metrics: Arc<SidecarMetrics>,
    tx_cache: Option<TxCache>,
    path: PathBuf,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Some(cache) = &tx_cache {
                metrics.set_tx_cache_snapshot(&cache.snapshot());
            }
            let text = metrics.render_prometheus_text();
            if let Err(error) = write_metrics_textfile(&path, &text) {
                warn!(%error, path = %path.display(), "Failed to write forge sidecar metrics textfile");
            }
        }
    });
}

fn write_metrics_textfile(
    path: &Path,
    text: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text)?;
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_forge::{
        AuthDigest, CompactBlockBuilder, TestMempool, TxId, WtxId, split_raw_block,
    };
    use std::sync::atomic::Ordering;

    use forge_sidecar::submit::{SubmitBlock, SubmitFuture};

    #[derive(Default)]
    struct CountingSubmitter {
        calls: AtomicUsize,
    }

    impl SubmitBlock for CountingSubmitter {
        fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(None) })
        }
    }

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

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
    fn raw_segment_buffer_updates_metrics() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
        let metrics = SidecarMetrics::default();
        let raw_block = vec![0xab; 25];
        let segments =
            split_raw_block([0x06; 32], &raw_block, RawBlockSegment::HEADER_LEN + 5).unwrap();
        let now = Instant::now();

        assert!(matches!(
            buffer.insert(segments[0].clone(), now),
            RawSegmentInsert::Pending
        ));
        buffer.update_metrics(&metrics);

        assert_eq!(
            metrics
                .raw_segment_incomplete_blocks
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.raw_segment_payload_bytes.load(Ordering::Relaxed),
            segments[0].payload.len()
        );
    }

    #[test]
    fn raw_segment_cleanup_refreshes_metrics_without_new_segments() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(1)));
        let metrics = SidecarMetrics::default();
        let now = Instant::now();
        let segments =
            split_raw_block([0x07; 32], &[1, 2, 3, 4], RawBlockSegment::HEADER_LEN + 2).unwrap();

        assert!(matches!(
            buffer.insert(segments[0].clone(), now),
            RawSegmentInsert::Pending
        ));
        buffer.update_metrics(&metrics);
        assert_eq!(
            metrics
                .raw_segment_incomplete_blocks
                .load(Ordering::Relaxed),
            1
        );

        let expired =
            expire_raw_segment_buffer(&mut buffer, &metrics, now + Duration::from_secs(2));

        assert_eq!(expired, 1);
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
        assert_eq!(
            metrics
                .raw_segment_incomplete_blocks
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(metrics.raw_segment_payload_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn raw_segment_cleanup_interval_caps_long_ttls() {
        assert_eq!(
            raw_segment_cleanup_interval(Duration::from_secs(120)),
            Duration::from_secs(30)
        );
        assert_eq!(
            raw_segment_cleanup_interval(Duration::from_secs(10)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn sidecar_mempool_uses_tx_cache_when_enabled() {
        let mempool = SidecarMempool::from_tx_cache_config(SidecarTxCacheConfig {
            enabled: true,
            max_entries: 8,
            max_bytes: 1024,
            max_tx_bytes: 512,
        });
        let tx_cache = mempool.tx_cache().expect("tx cache provider");
        let wtxid = make_wtxid(0x42);
        let tx = vec![0xde, 0xad, 0xbe, 0xef];

        tx_cache.insert(wtxid, tx.clone());

        assert_eq!(mempool.get_tx_data(&wtxid), Some(tx));
        assert_eq!(mempool.tx_cache_snapshot().unwrap().max_entries, 8);
    }

    #[test]
    fn sidecar_tx_feed_inserts_into_enabled_cache_and_updates_metrics() {
        let mempool = SidecarMempool::from_tx_cache_config(SidecarTxCacheConfig {
            enabled: true,
            max_entries: 8,
            max_bytes: 1024,
            max_tx_bytes: 512,
        });
        let metrics = SidecarMetrics::default();
        let wtxid = make_wtxid(0x77);
        let tx = vec![0xde, 0xad, 0xbe, 0xef];

        let outcome = ingest_sidecar_tx_payload(&mempool, &metrics, wtxid, tx.clone())
            .expect("enabled tx cache should ingest feed payload");

        assert!(outcome.inserted);
        assert_eq!(outcome.entries, 1);
        assert_eq!(outcome.bytes, tx.len());
        assert_eq!(mempool.get_tx_data(&wtxid), Some(tx));

        let text = metrics.render_prometheus_text();
        assert!(text.contains("forge_sidecar_tx_cache_entries 1"));
        assert!(text.contains("forge_sidecar_tx_cache_bytes 4"));
        assert!(text.contains("forge_sidecar_tx_cache_max_entries 8"));
        assert!(text.contains("forge_sidecar_tx_cache_max_bytes 1024"));
        assert!(text.contains("forge_sidecar_tx_cache_max_tx_bytes 512"));
    }

    #[tokio::test]
    async fn sidecar_tx_feed_listener_accepts_line_payloads() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let mempool = Arc::new(SidecarMempool::from_tx_cache_config(SidecarTxCacheConfig {
            enabled: true,
            max_entries: 8,
            max_bytes: 1024,
            max_tx_bytes: 512,
        }));
        let metrics = Arc::new(SidecarMetrics::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(run_tx_feed_listener(
            listener,
            Arc::clone(&mempool),
            Arc::clone(&metrics),
        ));
        let wtxid = make_wtxid(0x78);
        let tx = vec![0xca, 0xfe, 0xba, 0xbe];

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(TxFeedRecord::encode_line(wtxid, &tx).as_bytes())
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if mempool.get_tx_data(&wtxid).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("tx feed listener should insert payload");

        handle.abort();
        assert_eq!(mempool.get_tx_data(&wtxid), Some(tx));
        let text = metrics.render_prometheus_text();
        assert!(text.contains("forge_sidecar_tx_cache_entries 1"));
        assert!(text.contains("forge_sidecar_tx_cache_bytes 4"));
    }

    #[tokio::test]
    async fn relay_compact_handler_uses_injected_mempool_for_short_ids() {
        let header = vec![0xcd; bedrock_forge::ZCASH_FULL_HEADER_SIZE];
        let nonce = 42;
        let coinbase_wtxid = make_wtxid(0x01);
        let tx1_wtxid = make_wtxid(0x02);
        let coinbase = vec![0x01, 0x02];
        let tx1 = vec![0x03, 0x04, 0x05];
        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase_wtxid, coinbase.clone());
        builder.add_transaction(tx1_wtxid, tx1.clone());

        let mut peer_mempool = TestMempool::new();
        peer_mempool.insert(tx1_wtxid, tx1.clone());
        let compact = builder.build(&peer_mempool);
        assert_eq!(compact.short_ids.len(), 1);

        let mut sidecar_mempool = TestMempool::new();
        sidecar_mempool.insert(tx1_wtxid, tx1.clone());
        let metrics = SidecarMetrics::default();
        let submitter = CountingSubmitter::default();

        let outcome = handle_relay_compact_payload(
            &submitter,
            &compact,
            SubmitBlockMode::DryRun,
            true,
            &sidecar_mempool,
            &metrics,
        )
        .await
        .unwrap();

        match outcome {
            SubmissionOutcome::DryRun(candidate) => {
                assert_eq!(candidate.tx_count, 2);
                assert_eq!(
                    candidate.block_bytes,
                    header.len() + 1 + coinbase.len() + tx1.len()
                );
            }
            SubmissionOutcome::Submitted { .. } => panic!("dry-run must not submit"),
        }
        assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            metrics
                .compact_reconstruction_attempts
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .compact_reconstruction_completes
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn sidecar_metrics_render_prometheus_text() {
        let metrics = SidecarMetrics::default();
        metrics.inc_compact_blocks_received();
        metrics.inc_compact_reconstruction_attempts();
        metrics.inc_compact_reconstruction_completes();
        metrics.inc_compact_reconstruction_incompletes();
        metrics.inc_compact_reconstruction_invalids();
        metrics.inc_raw_segments_received();
        metrics.inc_raw_segment_sets_completed();
        metrics.inc_raw_segment_drops();
        metrics.inc_raw_segment_reassembly_failures();
        metrics.inc_submit_dry_run_candidates();
        metrics.inc_submit_successes();
        metrics.inc_submit_duplicates();
        metrics.inc_submit_rejections();
        metrics.set_raw_segment_buffer_state(2, 4096);
        metrics.set_tx_cache_snapshot(&bedrock_forge::TxCacheSnapshot {
            entries: 3,
            bytes: 2048,
            max_entries: 8,
            max_bytes: 4096,
            max_tx_bytes: 512,
            evicted_entries_total: 1,
            evicted_bytes_total: 128,
            dropped_too_large_total: 2,
        });

        let text = metrics.render_prometheus_text();

        assert!(text.contains("forge_sidecar_relay_compact_blocks_received_total 1"));
        assert!(text.contains("forge_sidecar_relay_compact_reconstruction_attempts_total 1"));
        assert!(text.contains("forge_sidecar_relay_compact_reconstruction_completes_total 1"));
        assert!(text.contains("forge_sidecar_relay_compact_reconstruction_incompletes_total 1"));
        assert!(text.contains("forge_sidecar_relay_compact_reconstruction_invalids_total 1"));
        assert!(text.contains("forge_sidecar_relay_raw_segments_received_total 1"));
        assert!(text.contains("forge_sidecar_relay_raw_segment_sets_completed_total 1"));
        assert!(text.contains("forge_sidecar_relay_raw_segment_drops_total 1"));
        assert!(text.contains("forge_sidecar_relay_raw_segment_reassembly_failures_total 1"));
        assert!(text.contains("forge_sidecar_relay_submit_dry_run_candidates_total 1"));
        assert!(text.contains("forge_sidecar_relay_submit_successes_total 1"));
        assert!(text.contains("forge_sidecar_relay_submit_duplicates_total 1"));
        assert!(text.contains("forge_sidecar_relay_submit_rejections_total 1"));
        assert!(text.contains("forge_sidecar_raw_segment_incomplete_blocks 2"));
        assert!(text.contains("forge_sidecar_raw_segment_payload_bytes 4096"));
        assert!(text.contains("forge_sidecar_tx_cache_entries 3"));
        assert!(text.contains("forge_sidecar_tx_cache_bytes 2048"));
        assert!(text.contains("forge_sidecar_tx_cache_max_entries 8"));
        assert!(text.contains("forge_sidecar_tx_cache_max_bytes 4096"));
        assert!(text.contains("forge_sidecar_tx_cache_max_tx_bytes 512"));
        assert!(text.contains("forge_sidecar_tx_cache_evicted_entries_total 1"));
        assert!(text.contains("forge_sidecar_tx_cache_evicted_bytes_total 128"));
        assert!(text.contains("forge_sidecar_tx_cache_dropped_too_large_total 2"));
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
