//! Relay sidecar for Stratum V1 mining pools

use clap::Parser;
use sovright_relay::{
    ArrivalSink, BlockReceiver, CompactBlock, MempoolProvider, RawBlockSegment, RelayPayload,
    TxCache, TxCacheConfig, TxCacheInsertOutcome, TxCacheSnapshot, TxFeedRecord, WtxId,
    ZCASH_FULL_HEADER_SIZE, reassemble_raw_block, zcash_block_hash,
};
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

use poller::{TemplatePoller, TemplateUpdate};
use relay::RelayWrapper;
use sovright_relay_sidecar::chain_view::{ZebraChainView, ZebraChainViewConfig};
use sovright_relay_sidecar::compact::build_compact_block;
use sovright_relay_sidecar::config;
use sovright_relay_sidecar::mempool_sync::run_zebra_mempool_sync;
use sovright_relay_sidecar::rpc::ZebraRpc;
use sovright_relay_sidecar::submit::{
    RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitBlockStatus,
    SubmitRejectionClass, handle_relay_compact_block, handle_relay_compact_block_with_gate,
    handle_relay_compact_block_with_mempool, handle_relay_raw_block,
    handle_relay_raw_block_with_gate,
};
use sovright_relay_sidecar::submit_gate::SubmitGate;
use tokio::sync::Mutex as TokioMutex;

#[derive(Parser, Debug)]
#[command(name = "sovright-relay-sidecar")]
#[command(about = "Relay sidecar for Stratum V1 mining pools")]
struct Args {
    /// Configuration file path (TOML)
    #[arg(long, short = 'c')]
    config: Option<String>,

    /// Zebra RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8232")]
    zebra_url: String,

    /// Sovright relay peer addresses
    #[arg(long)]
    relay_peer: Vec<String>,

    /// Authentication key (hex, 32 bytes)
    #[arg(long)]
    auth_key: Option<String>,

    /// Local bind address for relay
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

    /// Receive reconstructed compact blocks from the Sovright relay client
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
                .add_directive("sovright_relay_sidecar=info".parse()?),
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
        submit_gate_cfg,
        zebra_mempool_sync_enabled,
        zebra_mempool_sync_interval_ms,
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
            Some(cfg.submit_gate.clone()),
            cfg.zebra_mempool_sync_enabled,
            cfg.zebra_mempool_sync_interval_ms,
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
            None,
            false, // zebra mempool sync is config-only (off for bare CLI)
            2000,
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

    info!(zebra_url = %zebra_url, "Starting relay sidecar");
    let arrival_sink = std::env::var_os("SOVRIGHT_RELAY_ARRIVAL_LOG")
        .map(PathBuf::from)
        .and_then(|path| match ArrivalSink::new(&path) {
            Ok(sink) => {
                info!(path = %path.display(), "Compact-block relay arrival logging enabled");
                Some(sink)
            }
            Err(error) => {
                warn!(%error, "Failed to open relay arrival log; continuing without it");
                None
            }
        });
    let metrics = Arc::new(SidecarMetrics {
        arrival_sink,
        ..SidecarMetrics::default()
    });
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

    // Fold the local Zebra mempool into the reconstruction cache (opt-in). The
    // relay tx-feed only captures the ingress peers' relayed subset; Zebra sees
    // the full mempool, so this closes the compact-reconstruction coverage gap.
    if zebra_mempool_sync_enabled {
        match mempool.tx_cache() {
            Some(cache) => {
                let sync_rpc = Arc::clone(&rpc);
                let sync_metrics = Arc::clone(&metrics);
                let interval = Duration::from_millis(zebra_mempool_sync_interval_ms.max(100));
                info!(
                    interval_ms = zebra_mempool_sync_interval_ms,
                    "Zebra mempool sync enabled"
                );
                tokio::spawn(run_zebra_mempool_sync(
                    sync_rpc,
                    cache,
                    interval,
                    move || sync_metrics.inc_zebra_mempool_sync_inserts(),
                ));
            }
            None => warn!("zebra_mempool_sync_enabled but tx cache is disabled; ignoring"),
        }
    }

    // Initialize relay
    let relay = RelayWrapper::new_with_fec(
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
        // Build the optional safety gate. The gate is constructed exactly when
        // submit_gate.enabled = true in the TOML config; on the CLI fallback it
        // is always None. The ZebraChainView feeds the gate's parent-known
        // check and is shared so we can also use it for parent-height lookups
        // on each candidate before invoking the gated handler.
        let (gate, chain_view) = if let Some(cfg) = submit_gate_cfg.as_ref().filter(|c| c.enabled) {
            let chain_view = ZebraChainView::new(ZebraChainViewConfig::default());
            // Spawn the polling task; drop the JoinHandle since the view's
            // lifetime is bound by the main loop. Dropping the chain_view
            // Arc on shutdown cancels the poller.
            let _poller = Arc::clone(&chain_view).start(Arc::clone(&rpc));
            let gate = Arc::new(TokioMutex::new(SubmitGate::new(
                cfg.to_gate_config(),
                Arc::clone(&chain_view),
            )));
            info!("Safety gate enabled");
            (Some(gate), Some(chain_view))
        } else {
            (None, None)
        };

        spawn_relay_block_handler(
            receiver,
            Arc::clone(&rpc),
            mode,
            compact_reconstruction_enabled,
            raw_segment_buffer_config,
            Arc::clone(&metrics),
            Arc::clone(&mempool),
            gate,
            chain_view,
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

/// Capacity of the fast-path submit dedup ring (block hashes).
const FAST_PATH_DEDUP_CAPACITY: usize = 256;
/// TTL for a fast-path dedup entry. A skeleton and the full compact block for
/// the same block arrive within a few hundred milliseconds, so this only needs
/// to bridge that race; sized generously to also absorb slow reorg retries.
const FAST_PATH_DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// Bounded, time-windowed set of block hashes already reconstructed and
/// submitted (or dry-run built) by a fast path -- the skeleton or the non-gated
/// full compact block. It guarantees a block is never submitted twice when both
/// its skeleton and its full compact block arrive: whichever reconstructs first
/// records the hash, and the other becomes a no-op. Kept local to the
/// single-threaded receive task, so no lock is needed. Mirrors the submit-gate
/// dedup ring (that ring only covers the all-prefilled gated path).
struct HashDedupRing {
    capacity: usize,
    window: Duration,
    entries: std::collections::VecDeque<(String, Instant)>,
}

impl HashDedupRing {
    fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            entries: std::collections::VecDeque::with_capacity(capacity.max(1)),
        }
    }

    fn contains(&mut self, hash: &str, now: Instant) -> bool {
        self.evict_expired(now);
        self.entries.iter().any(|(h, _)| h == hash)
    }

    fn record(&mut self, hash: String, now: Instant) {
        self.evict_expired(now);
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((hash, now));
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some((_, ts)) = self.entries.front() {
            if now.duration_since(*ts) > self.window {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Reconstruct + submit a compact block on a fast path -- either the skeleton
/// (`is_skeleton = true`) or the non-gated full compact block -- deduplicating
/// by block hash so the skeleton and the full compact block for the same block
/// never both submit.
///
/// The skeleton path reconstructs from the mempool and submits ONLY on a
/// complete reconstruction; an unresolved short_id drops silently (the full
/// compact block is the push fallback) and never triggers getblocktxn. Both
/// paths record the block hash on a successful submit/dry-run, and skip when the
/// hash is already present.
#[allow(clippy::too_many_arguments)]
async fn submit_compact_fast_path<S, M>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
    compact_reconstruction_enabled: bool,
    mempool: &M,
    metrics: &SidecarMetrics,
    dedup: &mut HashDedupRing,
    now: Instant,
    is_skeleton: bool,
) where
    S: SubmitBlock + Sync,
    M: MempoolProvider,
{
    let block_hash = hex::encode(zcash_block_hash(&compact.header));
    if dedup.contains(&block_hash, now) {
        // The other fast path already reconstructed + submitted this block.
        if is_skeleton {
            metrics.inc_skeleton_deduplicated();
        } else {
            metrics.inc_full_block_deduplicated();
        }
        debug!(
            block_hash = %block_hash,
            is_skeleton,
            "fast-path block already submitted; skipping duplicate"
        );
        return;
    }

    let outcome = if is_skeleton {
        metrics.inc_skeleton_received();
        // A skeleton submits ONLY on complete mempool reconstruction; it never
        // sends getblocktxn (the full compact block is the push fallback).
        handle_relay_compact_block_with_mempool(submitter, compact, mode, mempool).await
    } else {
        handle_relay_compact_payload(
            submitter,
            compact,
            mode,
            compact_reconstruction_enabled,
            mempool,
            metrics,
        )
        .await
    };

    match &outcome {
        Ok(SubmissionOutcome::Submitted { .. }) | Ok(SubmissionOutcome::DryRun(_)) => {
            dedup.record(block_hash, now);
            if is_skeleton {
                metrics.inc_skeleton_submit_successes();
            }
        }
        Ok(SubmissionOutcome::NeedsTransactions { .. }) => {
            // Incomplete reconstruction. For a skeleton this is the expected
            // miss: drop and wait for the full compact block. Do NOT record the
            // hash, so the full block still submits.
            if is_skeleton {
                metrics.inc_skeleton_incomplete();
            }
        }
        Ok(SubmissionOutcome::GateRejected { .. }) => {}
        Err(_) => {
            if is_skeleton {
                metrics.inc_skeleton_incomplete();
            }
        }
    }
    log_submission_outcome(outcome, metrics, None);
}

#[allow(clippy::too_many_arguments)]
fn spawn_relay_block_handler<M>(
    mut receiver: BlockReceiver,
    rpc: Arc<ZebraRpc>,
    mode: SubmitBlockMode,
    compact_reconstruction_enabled: bool,
    raw_segment_buffer_config: RawSegmentBufferConfig,
    metrics: Arc<SidecarMetrics>,
    mempool: Arc<M>,
    gate: Option<Arc<TokioMutex<SubmitGate<Arc<ZebraChainView>>>>>,
    chain_view: Option<Arc<ZebraChainView>>,
) where
    M: MempoolProvider + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut raw_segments = RawSegmentBuffer::new(raw_segment_buffer_config);
        // Fast-path submit dedup shared by the skeleton and the non-gated
        // compact block paths (see `submit_compact_fast_path`).
        let mut fast_path_dedup =
            HashDedupRing::new(FAST_PATH_DEDUP_CAPACITY, FAST_PATH_DEDUP_WINDOW);
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
                            // Gate the candidate when configured and not in
                            // mempool-reconstruction mode (the gated handler
                            // doesn't support short_id reconstruction yet).
                            let use_gate = gate.is_some()
                                && (!compact_reconstruction_enabled
                                    || compact.short_ids.is_empty());
                            if let (true, Some(gate), Some(chain_view)) =
                                (use_gate, &gate, &chain_view)
                            {
                                // Check the shared dedup ring before gated submit,
                                // so a raw-segment completion that submitted first
                                // blocks this path too.
                                let header_hash = hex::encode(zcash_block_hash(&compact.header));
                                if fast_path_dedup.contains(&header_hash, Instant::now()) {
                                    metrics.inc_full_block_deduplicated();
                                    debug!(
                                        block_hash = %header_hash,
                                        "gated compact block already submitted; skipping duplicate"
                                    );
                                    continue;
                                }
                                let parent_height = if compact.header.len() >= 36 {
                                    let mut prev_hash = [0u8; 32];
                                    prev_hash.copy_from_slice(&compact.header[4..36]);
                                    chain_view
                                        .height_of(rpc.as_ref(), &prev_hash)
                                        .await
                                        .ok()
                                        .flatten()
                                        .unwrap_or(0)
                                } else {
                                    0
                                };
                                let outcome = {
                                    let mut gate_guard = gate.lock().await;
                                    handle_relay_compact_block_with_gate(
                                        rpc.as_ref(),
                                        &compact,
                                        mode,
                                        &mut gate_guard,
                                        parent_height,
                                    )
                                    .await
                                };
                                // Per-cause GateRejected metric is incremented in
                                // log_submission_outcome; here we tick the
                                // accepted-by-gate counter for outcomes that came
                                // through the gated handler and were not rejected.
                                if matches!(
                                    outcome,
                                    Ok(SubmissionOutcome::DryRun(_))
                                        | Ok(SubmissionOutcome::Submitted { .. })
                                ) {
                                    metrics.inc_submit_gate_accepted();
                                    // Record in the shared dedup ring so the raw-segment
                                    // path won't also submit the same block.
                                    fast_path_dedup.record(header_hash, Instant::now());
                                }
                                log_submission_outcome(outcome, metrics.as_ref(), None);
                            } else {
                                // Non-gated fast path: reconstruct + submit with
                                // block-hash dedup, so a skeleton and the full
                                // compact block for the same block never both
                                // submit (in either race order).
                                submit_compact_fast_path(
                                    rpc.as_ref(),
                                    &compact,
                                    mode,
                                    compact_reconstruction_enabled,
                                    mempool.as_ref(),
                                    metrics.as_ref(),
                                    &mut fast_path_dedup,
                                    Instant::now(),
                                    false,
                                )
                                .await;
                            }
                        }
                        RelayPayload::CompactSkeleton(compact) => {
                            // Skeleton fast path: attempt full mempool
                            // reconstruction. On a complete reconstruction submit
                            // and record the block hash (so the later full compact
                            // block is a no-op); on any unresolved short_id drop
                            // silently and wait for the full compact block.
                            submit_compact_fast_path(
                                rpc.as_ref(),
                                &compact,
                                mode,
                                compact_reconstruction_enabled,
                                mempool.as_ref(),
                                metrics.as_ref(),
                                &mut fast_path_dedup,
                                Instant::now(),
                                true,
                            )
                            .await;
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
                                RawSegmentInsert::Complete {
                                    segments,
                                    first_seen,
                                } => {
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
                                             // Dedup against compact/skeleton paths: the
                                             // consensus block hash is the shared key.
                                             let raw_block_hash =
                                                 hex::encode(zcash_block_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]));
                                             if fast_path_dedup.contains(&raw_block_hash, Instant::now())
                                             {
                                                 debug!(
                                                     block_hash = %raw_block_hash,
                                                     "raw segment already submitted by compact path; skipping duplicate"
                                                 );
                                                 continue;
                                             }
                                             let raw_outcome = if let (Some(gate), Some(chain_view)) =
                                                 (&gate, &chain_view)
                                            {
                                                let parent_height = if raw_block.len() >= 36 {
                                                    let mut prev_hash = [0u8; 32];
                                                    prev_hash.copy_from_slice(&raw_block[4..36]);
                                                    chain_view
                                                        .height_of(rpc.as_ref(), &prev_hash)
                                                        .await
                                                        .ok()
                                                        .flatten()
                                                        .unwrap_or(0)
                                                } else {
                                                    0
                                                };
                                                let mut gate_guard = gate.lock().await;
                                                handle_relay_raw_block_with_gate(
                                                    rpc.as_ref(),
                                                    &raw_block,
                                                    Some(block_hash),
                                                    mode,
                                                    &mut gate_guard,
                                                    parent_height,
                                                )
                                                .await
                                            } else {
                                                handle_relay_raw_block(
                                                    rpc.as_ref(),
                                                    &raw_block,
                                                    Some(block_hash),
                                                    mode,
                                                )
                                                .await
                                            };
                                            if gate.is_some()
                                                && matches!(
                                                    raw_outcome,
                                                    Ok(SubmissionOutcome::DryRun(_))
                                                        | Ok(SubmissionOutcome::Submitted { .. })
                                                )
                                            {
                                                metrics.inc_submit_gate_accepted();
                                            }
                                             // Relay-internal latency from the first raw
                                             // segment chunk of this block arriving to the
                                             // submit decision (mesh-receive → reassemble →
                                             // gate → submit).
                                            let first_seen_to_submit_ms =
                                                first_seen.elapsed().as_millis() as u64;
                                            if matches!(
                                                raw_outcome,
                                                Ok(SubmissionOutcome::Submitted { .. })
                                                    | Ok(SubmissionOutcome::DryRun(_))
                                            ) {
                                                // Record in shared dedup ring so compact-block
                                                // paths won't also submit this consensus block.
                                                fast_path_dedup.record(raw_block_hash, Instant::now());
                                            }
                                            if matches!(
                                                raw_outcome,
                                                Ok(SubmissionOutcome::Submitted { .. })
                                            ) {
                                                metrics.observe_first_seen_to_submit_ms(
                                                    first_seen_to_submit_ms,
                                                );
                                            }
                                            log_submission_outcome(
                                                raw_outcome,
                                                metrics.as_ref(),
                                                Some(first_seen_to_submit_ms),
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
    metrics.inc_tx_feed_payload(tx_bytes.len());
    let cache = mempool.tx_cache()?;
    let outcome = cache.insert(wtxid, tx_bytes);
    if outcome.dropped_too_large > 0 {
        metrics.add_tx_feed_dropped_too_large(outcome.dropped_too_large);
    }
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
                            metrics.inc_tx_feed_cache_disabled();
                            warn!(%peer, "Sidecar transaction feed received payload while tx cache is disabled")
                        }
                    }
                }
                Err(error) => {
                    metrics.inc_tx_feed_invalid_lines();
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
    Complete {
        segments: Vec<RawBlockSegment>,
        first_seen: Instant,
    },
    Dropped {
        reason: &'static str,
    },
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
            let first_seen = entry.first_seen;
            let segments = entry
                .segments
                .into_iter()
                .map(|segment| segment.expect("complete segment set"))
                .collect();
            RawSegmentInsert::Complete {
                segments,
                first_seen,
            }
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
    outcome: Result<SubmissionOutcome, sovright_relay_sidecar::submit::RelayBlockError>,
    metrics: &SidecarMetrics,
    first_seen_to_submit_ms: Option<u64>,
) {
    match outcome {
        Ok(SubmissionOutcome::DryRun(candidate)) => {
            metrics.inc_submit_dry_run_candidates();
            info!(
                block_hash = %candidate.block_hash,
                consensus_block_hash = %candidate.consensus_block_hash,
                tx_count = candidate.tx_count,
                block_bytes = candidate.block_bytes,
                "Relay block submit dry-run candidate"
            );
        }
        Ok(SubmissionOutcome::NeedsTransactions {
            request,
            missing_indexes,
            missing_wtxids,
            unresolved_short_ids,
        }) => {
            info!(
                block_hash = %request.block_hash,
                requested_tx_count = request.indexes.len(),
                missing_indexes,
                missing_wtxids,
                unresolved_short_ids,
                "Relay compact block needs transaction fallback"
            );
        }
        Ok(SubmissionOutcome::Submitted { candidate, status }) => match status {
            SubmitBlockStatus::Accepted => {
                metrics.inc_submit_successes();
                info!(
                    block_hash = %candidate.block_hash,
                    consensus_block_hash = %candidate.consensus_block_hash,
                    tx_count = candidate.tx_count,
                    block_bytes = candidate.block_bytes,
                    submit_status = status.as_str(),
                    ?first_seen_to_submit_ms,
                    "Relay block accepted by Zebra"
                );
            }
            SubmitBlockStatus::Duplicate => {
                metrics.inc_submit_duplicates();
                info!(
                    block_hash = %candidate.block_hash,
                    consensus_block_hash = %candidate.consensus_block_hash,
                    tx_count = candidate.tx_count,
                    block_bytes = candidate.block_bytes,
                    submit_status = status.as_str(),
                    ?first_seen_to_submit_ms,
                    "Relay block already known to Zebra"
                );
            }
        },
        Ok(SubmissionOutcome::GateRejected { candidate, reason }) => {
            // The safety gate rejected the candidate before it reached
            // submit_block. The staging service drives this path on every
            // reassembled candidate (shadow mode), and a production-mode
            // sidecar with gate.enabled = true treats it as a normal skip.
            metrics.inc_submit_gate_rejected(reason);
            info!(
                block_hash = %candidate.block_hash,
                consensus_block_hash = %candidate.consensus_block_hash,
                tx_count = candidate.tx_count,
                block_bytes = candidate.block_bytes,
                gate_reason = reason.as_str(),
                "Relay block rejected by safety gate before submitblock"
            );
        }
        Err(error) => match error {
            RelayBlockError::SubmitRejected(reason, class) => {
                metrics.inc_submit_rejections(class);
                warn!(
                    %reason,
                    rejection_class = class.as_str(),
                    "Relay block rejected by Zebra"
                );
            }
            RelayBlockError::SubmitFailed(error) => {
                metrics.inc_submit_rpc_failures();
                warn!(%error, "Relay block submitblock RPC failed");
            }
            error => {
                metrics.inc_not_submit_candidates();
                warn!(%error, "Relay block is not a submit candidate");
            }
        },
    }
}

/// Bucket a reconstruction failure reason into a stable metric label.
///
/// The reason string is human-readable and carries the detail an operator needs;
/// the label is what makes the failure countable without reading logs. Anything
/// unrecognised lands in `other` rather than being dropped, so a new failure
/// mode still shows up somewhere.
fn classify_reconstruction_invalid(reason: &str) -> &'static str {
    if reason.contains("duplicate prefilled") {
        "duplicate_prefilled"
    } else if reason.contains("out of bounds") {
        "prefilled_out_of_bounds"
    } else {
        "other"
    }
}

fn record_compact_reconstruction_outcome(
    outcome: &Result<SubmissionOutcome, RelayBlockError>,
    metrics: &SidecarMetrics,
) {
    match outcome {
        Ok(SubmissionOutcome::NeedsTransactions {
            request,
            missing_indexes,
            missing_wtxids,
            unresolved_short_ids,
        }) => {
            metrics.inc_compact_reconstruction_incompletes();
            metrics
                .add_compact_reconstruction_missing_detail(*missing_wtxids, *unresolved_short_ids);
            metrics.add_compact_reconstruction_getblocktxn_request(request.indexes.len());
            debug!(
                block_hash = %request.block_hash,
                requested_tx_count = request.indexes.len(),
                missing_indexes,
                missing_wtxids,
                unresolved_short_ids,
                "Prepared getblocktxn fallback for incomplete compact reconstruction"
            );
        }
        Ok(other) => {
            metrics.inc_compact_reconstruction_completes();
            if let Some(hash) = other.candidate_consensus_hash() {
                metrics.record_relay_compact_arrival(hash);
            }
        }
        Err(RelayBlockError::ReconstructionIncomplete {
            block_hash: _,
            missing_indexes: _,
            missing_wtxids,
            unresolved_short_ids,
        }) => {
            metrics.inc_compact_reconstruction_incompletes();
            metrics.add_compact_reconstruction_missing_detail(
                missing_wtxids.len(),
                unresolved_short_ids.len(),
            );
        }
        Err(RelayBlockError::ReconstructionInvalid { reason }) => {
            // The reason used to be discarded by a `{ .. }` pattern. It is the
            // only thing that says WHY reconstruction failed, and without it 66
            // fleet-wide failures produced no diagnostic trail at all.
            let kind = classify_reconstruction_invalid(reason);
            metrics.inc_compact_reconstruction_invalids(kind);
            warn!(
                reason = %reason,
                kind,
                "Compact block reconstruction produced an invalid block"
            );
        }
        Err(error) => {
            // Previously folded into the invalid counter, which made "invalid"
            // a catch-all that overstated true reconstruction invalidity and
            // left everything else with no signal of its own.
            metrics.inc_compact_reconstruction_errors();
            warn!(%error, "Compact block path failed before reconstruction could judge it");
        }
    }
}

#[derive(Default)]
struct SidecarMetrics {
    compact_blocks_received: AtomicU64,
    compact_reconstruction_attempts: AtomicU64,
    compact_reconstruction_completes: AtomicU64,
    compact_reconstruction_incompletes: AtomicU64,
    compact_reconstruction_invalids: AtomicU64,
    compact_reconstruction_invalids_duplicate_prefilled: AtomicU64,
    compact_reconstruction_invalids_out_of_bounds: AtomicU64,
    compact_reconstruction_invalids_other: AtomicU64,
    compact_reconstruction_errors: AtomicU64,
    compact_reconstruction_missing_wtxids: AtomicU64,
    compact_reconstruction_unresolved_short_ids: AtomicU64,
    compact_reconstruction_getblocktxn_requests: AtomicU64,
    compact_reconstruction_getblocktxn_requested_transactions: AtomicU64,
    /// Compact skeletons received on the fast path.
    skeleton_received: AtomicU64,
    /// Skeletons reconstructed from the mempool and submitted before the full
    /// compact block arrived -- the skeleton-first wins.
    skeleton_submit_successes: AtomicU64,
    /// Skeletons that could not fully reconstruct (an unresolved short_id), so
    /// the sidecar dropped them and waited for the full compact block.
    skeleton_incomplete: AtomicU64,
    /// Skeletons dropped because the block was already submitted (the full
    /// compact block won the race first).
    skeleton_deduplicated: AtomicU64,
    /// Full compact blocks dropped because a skeleton already submitted the
    /// block -- the no-double-submit path when the skeleton wins.
    full_block_deduplicated: AtomicU64,
    raw_segments_received: AtomicU64,
    raw_segment_sets_completed: AtomicU64,
    raw_segment_drops: AtomicU64,
    raw_segment_reassembly_failures: AtomicU64,
    submit_dry_run_candidates: AtomicU64,
    submit_successes: AtomicU64,
    submit_duplicates: AtomicU64,
    /// Relay-internal latency (milliseconds) from the first raw segment chunk
    /// of a block arriving to the submit decision. Rendered as a sum/count pair
    /// so Prometheus can derive the average over the submit path.
    relay_first_seen_to_submit_ms_sum: AtomicU64,
    relay_first_seen_to_submit_ms_count: AtomicU64,
    submit_rpc_failures: AtomicU64,
    submit_rejections: AtomicU64,
    submit_rejections_race_lost: AtomicU64,
    submit_rejections_invalid: AtomicU64,
    submit_rejections_unknown: AtomicU64,
    not_submit_candidates: AtomicU64,
    /// Per-cause counters for the submit safety gate. Incremented in
    /// `handle_relay_*_block_with_gate` so the staging service can attribute
    /// gate decisions while running in shadow mode (enable_submitblock=false).
    submit_gate_accepted: AtomicU64,
    submit_gate_rejected_pow: AtomicU64,
    submit_gate_rejected_unknown_parent: AtomicU64,
    submit_gate_rejected_out_of_window: AtomicU64,
    submit_gate_rejected_duplicate: AtomicU64,
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
    tx_feed_payloads: AtomicU64,
    tx_feed_bytes: AtomicU64,
    tx_feed_invalid_lines: AtomicU64,
    tx_feed_cache_disabled: AtomicU64,
    tx_feed_dropped_too_large: AtomicU64,
    /// Transactions folded into the tx cache from the local Zebra mempool.
    zebra_mempool_sync_inserts: AtomicU64,
    /// Optional per-block relay arrival log (shared with relay-node). Records a
    /// `relay_block_received` event when a compact block is reconstructed from
    /// the mempool, so the observatory times the fast compact-block path.
    arrival_sink: Option<ArrivalSink>,
}

impl SidecarMetrics {
    fn inc_zebra_mempool_sync_inserts(&self) {
        self.zebra_mempool_sync_inserts
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Log a compact-block relay arrival by its Zcash consensus block hash.
    fn record_relay_compact_arrival(&self, consensus_hash: &str) {
        if let Some(sink) = &self.arrival_sink {
            sink.relay_block_received(consensus_hash);
        }
    }

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

    fn inc_compact_reconstruction_errors(&self) {
        self.compact_reconstruction_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_compact_reconstruction_invalids(&self, kind: &str) {
        match kind {
            "duplicate_prefilled" => &self.compact_reconstruction_invalids_duplicate_prefilled,
            "prefilled_out_of_bounds" => &self.compact_reconstruction_invalids_out_of_bounds,
            _ => &self.compact_reconstruction_invalids_other,
        }
        .fetch_add(1, Ordering::Relaxed);
        self.compact_reconstruction_invalids
            .fetch_add(1, Ordering::Relaxed);
    }

    fn add_compact_reconstruction_missing_detail(
        &self,
        missing_wtxids: usize,
        unresolved_short_ids: usize,
    ) {
        self.compact_reconstruction_missing_wtxids
            .fetch_add(missing_wtxids as u64, Ordering::Relaxed);
        self.compact_reconstruction_unresolved_short_ids
            .fetch_add(unresolved_short_ids as u64, Ordering::Relaxed);
    }

    fn add_compact_reconstruction_getblocktxn_request(&self, requested_transactions: usize) {
        self.compact_reconstruction_getblocktxn_requests
            .fetch_add(1, Ordering::Relaxed);
        self.compact_reconstruction_getblocktxn_requested_transactions
            .fetch_add(requested_transactions as u64, Ordering::Relaxed);
    }

    fn inc_skeleton_received(&self) {
        self.skeleton_received.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_skeleton_submit_successes(&self) {
        self.skeleton_submit_successes
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_skeleton_incomplete(&self) {
        self.skeleton_incomplete.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_skeleton_deduplicated(&self) {
        self.skeleton_deduplicated.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_full_block_deduplicated(&self) {
        self.full_block_deduplicated.fetch_add(1, Ordering::Relaxed);
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

    /// Record one relay first-seen-to-submit latency observation, accumulating
    /// the sum and count so Prometheus can derive an average.
    fn observe_first_seen_to_submit_ms(&self, ms: u64) {
        self.relay_first_seen_to_submit_ms_sum
            .fetch_add(ms, Ordering::Relaxed);
        self.relay_first_seen_to_submit_ms_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_submit_rpc_failures(&self) {
        self.submit_rpc_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_submit_rejections(&self, class: SubmitRejectionClass) {
        // Unlabelled total kept: existing alerts and dashboards read the bare
        // name, and it is still the right denominator-free "how many rejections".
        self.submit_rejections.fetch_add(1, Ordering::Relaxed);
        let counter = match class {
            SubmitRejectionClass::RaceLost => &self.submit_rejections_race_lost,
            SubmitRejectionClass::Invalid => &self.submit_rejections_invalid,
            SubmitRejectionClass::Unknown => &self.submit_rejections_unknown,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_not_submit_candidates(&self) {
        self.not_submit_candidates.fetch_add(1, Ordering::Relaxed);
    }

    // Consumed by the upcoming `bedrock-forge-submitblock-staging` service
    // (separate ticket on the deployment side); the in-process sidecar does
    // not produce SubmissionOutcome::GateRejected on its own paths today.
    #[allow(dead_code)]
    fn inc_submit_gate_accepted(&self) {
        self.submit_gate_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the gate-rejection counter that matches `reason`. Called
    /// once per `SubmissionOutcome::GateRejected` in the handler match arm.
    fn inc_submit_gate_rejected(&self, reason: sovright_relay_sidecar::submit_gate::RejectReason) {
        let counter = match reason {
            sovright_relay_sidecar::submit_gate::RejectReason::HeaderMutated => {
                &self.submit_gate_rejected_pow
            }
            sovright_relay_sidecar::submit_gate::RejectReason::UnknownParent => {
                &self.submit_gate_rejected_unknown_parent
            }
            sovright_relay_sidecar::submit_gate::RejectReason::OutOfHeightWindow => {
                &self.submit_gate_rejected_out_of_window
            }
            sovright_relay_sidecar::submit_gate::RejectReason::DuplicateSubmit => {
                &self.submit_gate_rejected_duplicate
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
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

    fn inc_tx_feed_payload(&self, bytes: usize) {
        self.tx_feed_payloads.fetch_add(1, Ordering::Relaxed);
        self.tx_feed_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn inc_tx_feed_invalid_lines(&self) {
        self.tx_feed_invalid_lines.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_tx_feed_cache_disabled(&self) {
        self.tx_feed_cache_disabled.fetch_add(1, Ordering::Relaxed);
    }

    fn add_tx_feed_dropped_too_large(&self, count: usize) {
        self.tx_feed_dropped_too_large
            .fetch_add(count as u64, Ordering::Relaxed);
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
        let cri_duplicate_prefilled = self
            .compact_reconstruction_invalids_duplicate_prefilled
            .load(Ordering::Relaxed);
        let cri_out_of_bounds = self
            .compact_reconstruction_invalids_out_of_bounds
            .load(Ordering::Relaxed);
        let cri_other = self
            .compact_reconstruction_invalids_other
            .load(Ordering::Relaxed);
        let compact_reconstruction_errors =
            self.compact_reconstruction_errors.load(Ordering::Relaxed);
        let compact_reconstruction_missing_wtxids = self
            .compact_reconstruction_missing_wtxids
            .load(Ordering::Relaxed);
        let compact_reconstruction_unresolved_short_ids = self
            .compact_reconstruction_unresolved_short_ids
            .load(Ordering::Relaxed);
        let compact_reconstruction_getblocktxn_requests = self
            .compact_reconstruction_getblocktxn_requests
            .load(Ordering::Relaxed);
        let compact_reconstruction_getblocktxn_requested_transactions = self
            .compact_reconstruction_getblocktxn_requested_transactions
            .load(Ordering::Relaxed);
        let skeleton_received = self.skeleton_received.load(Ordering::Relaxed);
        let skeleton_submit_successes = self.skeleton_submit_successes.load(Ordering::Relaxed);
        let skeleton_incomplete = self.skeleton_incomplete.load(Ordering::Relaxed);
        let skeleton_deduplicated = self.skeleton_deduplicated.load(Ordering::Relaxed);
        let full_block_deduplicated = self.full_block_deduplicated.load(Ordering::Relaxed);
        let raw_segments_received = self.raw_segments_received.load(Ordering::Relaxed);
        let raw_segment_sets_completed = self.raw_segment_sets_completed.load(Ordering::Relaxed);
        let raw_segment_drops = self.raw_segment_drops.load(Ordering::Relaxed);
        let raw_segment_reassembly_failures =
            self.raw_segment_reassembly_failures.load(Ordering::Relaxed);
        let submit_dry_run_candidates = self.submit_dry_run_candidates.load(Ordering::Relaxed);
        let submit_successes = self.submit_successes.load(Ordering::Relaxed);
        let submit_duplicates = self.submit_duplicates.load(Ordering::Relaxed);
        let relay_first_seen_to_submit_ms_sum = self
            .relay_first_seen_to_submit_ms_sum
            .load(Ordering::Relaxed);
        let relay_first_seen_to_submit_ms_count = self
            .relay_first_seen_to_submit_ms_count
            .load(Ordering::Relaxed);
        let submit_rpc_failures = self.submit_rpc_failures.load(Ordering::Relaxed);
        let submit_rejections = self.submit_rejections.load(Ordering::Relaxed);
        let submit_rejections_race_lost = self.submit_rejections_race_lost.load(Ordering::Relaxed);
        let submit_rejections_invalid = self.submit_rejections_invalid.load(Ordering::Relaxed);
        let submit_rejections_unknown = self.submit_rejections_unknown.load(Ordering::Relaxed);
        let not_submit_candidates = self.not_submit_candidates.load(Ordering::Relaxed);
        let submit_gate_accepted = self.submit_gate_accepted.load(Ordering::Relaxed);
        let submit_gate_rejected_pow = self.submit_gate_rejected_pow.load(Ordering::Relaxed);
        let submit_gate_rejected_unknown_parent = self
            .submit_gate_rejected_unknown_parent
            .load(Ordering::Relaxed);
        let submit_gate_rejected_out_of_window = self
            .submit_gate_rejected_out_of_window
            .load(Ordering::Relaxed);
        let submit_gate_rejected_duplicate =
            self.submit_gate_rejected_duplicate.load(Ordering::Relaxed);
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
        let tx_feed_payloads = self.tx_feed_payloads.load(Ordering::Relaxed);
        let tx_feed_bytes = self.tx_feed_bytes.load(Ordering::Relaxed);
        let tx_feed_invalid_lines = self.tx_feed_invalid_lines.load(Ordering::Relaxed);
        let tx_feed_cache_disabled = self.tx_feed_cache_disabled.load(Ordering::Relaxed);
        let tx_feed_dropped_too_large = self.tx_feed_dropped_too_large.load(Ordering::Relaxed);
        let zebra_mempool_sync_inserts = self.zebra_mempool_sync_inserts.load(Ordering::Relaxed);

        format!(
            concat!(
                "# TYPE sovright_relay_sidecar_relay_compact_blocks_received_total counter\n",
                "sovright_relay_sidecar_relay_compact_blocks_received_total {compact_blocks_received}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_attempts_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_attempts_total {compact_reconstruction_attempts}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_completes_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_completes_total {compact_reconstruction_completes}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_incompletes_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_incompletes_total {compact_reconstruction_incompletes}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_invalids_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total {compact_reconstruction_invalids}\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total{{reason=\"duplicate_prefilled\"}} {cri_duplicate_prefilled}\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total{{reason=\"prefilled_out_of_bounds\"}} {cri_out_of_bounds}\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total{{reason=\"other\"}} {cri_other}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_errors_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_errors_total {compact_reconstruction_errors}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_missing_wtxids_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_missing_wtxids_total {compact_reconstruction_missing_wtxids}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_unresolved_short_ids_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_unresolved_short_ids_total {compact_reconstruction_unresolved_short_ids}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_getblocktxn_requests_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_getblocktxn_requests_total {compact_reconstruction_getblocktxn_requests}\n",
                "# TYPE sovright_relay_sidecar_relay_compact_reconstruction_getblocktxn_requested_transactions_total counter\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_getblocktxn_requested_transactions_total {compact_reconstruction_getblocktxn_requested_transactions}\n",
                "# TYPE sovright_relay_sidecar_skeleton_received_total counter\n",
                "sovright_relay_sidecar_skeleton_received_total {skeleton_received}\n",
                "# TYPE sovright_relay_sidecar_skeleton_submit_successes_total counter\n",
                "sovright_relay_sidecar_skeleton_submit_successes_total {skeleton_submit_successes}\n",
                "# TYPE sovright_relay_sidecar_skeleton_incomplete_total counter\n",
                "sovright_relay_sidecar_skeleton_incomplete_total {skeleton_incomplete}\n",
                "# TYPE sovright_relay_sidecar_skeleton_deduplicated_total counter\n",
                "sovright_relay_sidecar_skeleton_deduplicated_total {skeleton_deduplicated}\n",
                "# TYPE sovright_relay_sidecar_skeleton_full_block_deduplicated_total counter\n",
                "sovright_relay_sidecar_skeleton_full_block_deduplicated_total {full_block_deduplicated}\n",
                "# TYPE sovright_relay_sidecar_relay_raw_segments_received_total counter\n",
                "sovright_relay_sidecar_relay_raw_segments_received_total {raw_segments_received}\n",
                "# TYPE sovright_relay_sidecar_relay_raw_segment_sets_completed_total counter\n",
                "sovright_relay_sidecar_relay_raw_segment_sets_completed_total {raw_segment_sets_completed}\n",
                "# TYPE sovright_relay_sidecar_relay_raw_segment_drops_total counter\n",
                "sovright_relay_sidecar_relay_raw_segment_drops_total {raw_segment_drops}\n",
                "# TYPE sovright_relay_sidecar_relay_raw_segment_reassembly_failures_total counter\n",
                "sovright_relay_sidecar_relay_raw_segment_reassembly_failures_total {raw_segment_reassembly_failures}\n",
                "# TYPE sovright_relay_sidecar_relay_submit_dry_run_candidates_total counter\n",
                "sovright_relay_sidecar_relay_submit_dry_run_candidates_total {submit_dry_run_candidates}\n",
                "# TYPE sovright_relay_sidecar_relay_submit_successes_total counter\n",
                "sovright_relay_sidecar_relay_submit_successes_total {submit_successes}\n",
                "# TYPE sovright_relay_sidecar_relay_submit_duplicates_total counter\n",
                "sovright_relay_sidecar_relay_submit_duplicates_total {submit_duplicates}\n",
                "# TYPE sovright_relay_sidecar_relay_first_seen_to_submit_ms_sum counter\n",
                "sovright_relay_sidecar_relay_first_seen_to_submit_ms_sum {relay_first_seen_to_submit_ms_sum}\n",
                "# TYPE sovright_relay_sidecar_relay_first_seen_to_submit_ms_count counter\n",
                "sovright_relay_sidecar_relay_first_seen_to_submit_ms_count {relay_first_seen_to_submit_ms_count}\n",
                "# TYPE sovright_relay_sidecar_relay_submit_rpc_failures_total counter\n",
                "sovright_relay_sidecar_relay_submit_rpc_failures_total {submit_rpc_failures}\n",
                "# TYPE sovright_relay_sidecar_relay_submit_rejections_total counter\n",
                "sovright_relay_sidecar_relay_submit_rejections_total {submit_rejections}\n",
                "sovright_relay_sidecar_relay_submit_rejections_total{{reason=\"race_lost\"}} {submit_rejections_race_lost}\n",
                "sovright_relay_sidecar_relay_submit_rejections_total{{reason=\"invalid\"}} {submit_rejections_invalid}\n",
                "sovright_relay_sidecar_relay_submit_rejections_total{{reason=\"unknown\"}} {submit_rejections_unknown}\n",
                "# TYPE sovright_relay_sidecar_relay_not_submit_candidates_total counter\n",
                "sovright_relay_sidecar_relay_not_submit_candidates_total {not_submit_candidates}\n",
                "# TYPE sovright_relay_sidecar_submit_gate_accepted_total counter\n",
                "sovright_relay_sidecar_submit_gate_accepted_total {submit_gate_accepted}\n",
                "# TYPE sovright_relay_sidecar_submit_gate_rejected_total counter\n",
                "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"header_mutated\"}} {submit_gate_rejected_pow}\n",
                "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"unknown_parent\"}} {submit_gate_rejected_unknown_parent}\n",
                "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"out_of_height_window\"}} {submit_gate_rejected_out_of_window}\n",
                "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"duplicate_submit\"}} {submit_gate_rejected_duplicate}\n",
                "# TYPE sovright_relay_sidecar_raw_segment_incomplete_blocks gauge\n",
                "sovright_relay_sidecar_raw_segment_incomplete_blocks {raw_segment_incomplete_blocks}\n",
                "# TYPE sovright_relay_sidecar_raw_segment_payload_bytes gauge\n",
                "sovright_relay_sidecar_raw_segment_payload_bytes {raw_segment_payload_bytes}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_entries gauge\n",
                "sovright_relay_sidecar_tx_cache_entries {tx_cache_entries}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_bytes gauge\n",
                "sovright_relay_sidecar_tx_cache_bytes {tx_cache_bytes}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_max_entries gauge\n",
                "sovright_relay_sidecar_tx_cache_max_entries {tx_cache_max_entries}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_max_bytes gauge\n",
                "sovright_relay_sidecar_tx_cache_max_bytes {tx_cache_max_bytes}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_max_tx_bytes gauge\n",
                "sovright_relay_sidecar_tx_cache_max_tx_bytes {tx_cache_max_tx_bytes}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_evicted_entries_total counter\n",
                "sovright_relay_sidecar_tx_cache_evicted_entries_total {tx_cache_evicted_entries_total}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_evicted_bytes_total counter\n",
                "sovright_relay_sidecar_tx_cache_evicted_bytes_total {tx_cache_evicted_bytes_total}\n",
                "# TYPE sovright_relay_sidecar_tx_cache_dropped_too_large_total counter\n",
                "sovright_relay_sidecar_tx_cache_dropped_too_large_total {tx_cache_dropped_too_large_total}\n",
                "# TYPE sovright_relay_sidecar_tx_feed_payloads_total counter\n",
                "sovright_relay_sidecar_tx_feed_payloads_total {tx_feed_payloads}\n",
                "# TYPE sovright_relay_sidecar_tx_feed_bytes_total counter\n",
                "sovright_relay_sidecar_tx_feed_bytes_total {tx_feed_bytes}\n",
                "# TYPE sovright_relay_sidecar_tx_feed_invalid_lines_total counter\n",
                "sovright_relay_sidecar_tx_feed_invalid_lines_total {tx_feed_invalid_lines}\n",
                "# TYPE sovright_relay_sidecar_tx_feed_cache_disabled_total counter\n",
                "sovright_relay_sidecar_tx_feed_cache_disabled_total {tx_feed_cache_disabled}\n",
                "# TYPE sovright_relay_sidecar_tx_feed_dropped_too_large_total counter\n",
                "sovright_relay_sidecar_tx_feed_dropped_too_large_total {tx_feed_dropped_too_large}\n",
                "# TYPE sovright_relay_sidecar_zebra_mempool_sync_inserts_total counter\n",
                "sovright_relay_sidecar_zebra_mempool_sync_inserts_total {zebra_mempool_sync_inserts}\n",
            ),
            compact_blocks_received = compact_blocks_received,
            compact_reconstruction_attempts = compact_reconstruction_attempts,
            compact_reconstruction_completes = compact_reconstruction_completes,
            compact_reconstruction_incompletes = compact_reconstruction_incompletes,
            compact_reconstruction_invalids = compact_reconstruction_invalids,
            cri_duplicate_prefilled = cri_duplicate_prefilled,
            cri_out_of_bounds = cri_out_of_bounds,
            cri_other = cri_other,
            compact_reconstruction_errors = compact_reconstruction_errors,
            compact_reconstruction_missing_wtxids = compact_reconstruction_missing_wtxids,
            compact_reconstruction_unresolved_short_ids =
                compact_reconstruction_unresolved_short_ids,
            compact_reconstruction_getblocktxn_requests =
                compact_reconstruction_getblocktxn_requests,
            compact_reconstruction_getblocktxn_requested_transactions =
                compact_reconstruction_getblocktxn_requested_transactions,
            skeleton_received = skeleton_received,
            skeleton_submit_successes = skeleton_submit_successes,
            skeleton_incomplete = skeleton_incomplete,
            skeleton_deduplicated = skeleton_deduplicated,
            full_block_deduplicated = full_block_deduplicated,
            raw_segments_received = raw_segments_received,
            raw_segment_sets_completed = raw_segment_sets_completed,
            raw_segment_drops = raw_segment_drops,
            raw_segment_reassembly_failures = raw_segment_reassembly_failures,
            submit_dry_run_candidates = submit_dry_run_candidates,
            submit_successes = submit_successes,
            submit_duplicates = submit_duplicates,
            relay_first_seen_to_submit_ms_sum = relay_first_seen_to_submit_ms_sum,
            relay_first_seen_to_submit_ms_count = relay_first_seen_to_submit_ms_count,
            submit_rpc_failures = submit_rpc_failures,
            submit_rejections = submit_rejections,
            submit_rejections_race_lost = submit_rejections_race_lost,
            submit_rejections_invalid = submit_rejections_invalid,
            submit_rejections_unknown = submit_rejections_unknown,
            not_submit_candidates = not_submit_candidates,
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
            tx_feed_payloads = tx_feed_payloads,
            tx_feed_bytes = tx_feed_bytes,
            tx_feed_invalid_lines = tx_feed_invalid_lines,
            tx_feed_cache_disabled = tx_feed_cache_disabled,
            tx_feed_dropped_too_large = tx_feed_dropped_too_large,
            zebra_mempool_sync_inserts = zebra_mempool_sync_inserts,
            submit_gate_accepted = submit_gate_accepted,
            submit_gate_rejected_pow = submit_gate_rejected_pow,
            submit_gate_rejected_unknown_parent = submit_gate_rejected_unknown_parent,
            submit_gate_rejected_out_of_window = submit_gate_rejected_out_of_window,
            submit_gate_rejected_duplicate = submit_gate_rejected_duplicate,
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
                warn!(%error, path = %path.display(), "Failed to write relay sidecar metrics textfile");
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
    use sovright_relay::{
        AuthDigest, CompactBlockBuilder, PrefilledTx, ShortId, TestMempool, TxId, WtxId,
        split_raw_block,
    };
    use std::sync::atomic::Ordering;

    use sovright_relay_sidecar::submit::{SubmitBlock, SubmitFuture};

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
            RawSegmentInsert::Complete {
                segments,
                first_seen,
            } => {
                assert_eq!(reassemble_raw_block(&segments).unwrap(), raw_block);
                assert_eq!(first_seen, now);
            }
            RawSegmentInsert::Pending => panic!("expected complete segment set"),
            RawSegmentInsert::Dropped { reason } => panic!("unexpected drop: {reason}"),
        }
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
    }

    #[test]
    fn raw_segment_buffer_reports_first_seen_of_first_insert() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
        let block_hash = [0x77; 32];
        let raw_block = vec![0xcd; 25];
        let mut segments =
            split_raw_block(block_hash, &raw_block, RawBlockSegment::HEADER_LEN + 5).unwrap();
        assert!(segments.len() > 1);
        let last = segments.pop().unwrap();

        let t0 = Instant::now();
        let t1 = t0.checked_add(Duration::from_millis(50)).unwrap();

        // The first insert happens at t0; every remaining segment (including the
        // completing one) arrives later at t1.
        for segment in segments {
            assert!(matches!(
                buffer.insert(segment, t0),
                RawSegmentInsert::Pending
            ));
        }
        match buffer.insert(last, t1) {
            RawSegmentInsert::Complete { first_seen, .. } => {
                // first_seen must reflect the FIRST insert, not the completing one.
                assert_eq!(first_seen, t0);
            }
            RawSegmentInsert::Pending => panic!("expected complete segment set"),
            RawSegmentInsert::Dropped { reason } => panic!("unexpected drop: {reason}"),
        }
    }

    #[tokio::test]
    async fn skeleton_wins_then_full_block_is_a_noop() {
        // A skeleton whose short_ids all resolve in the mempool reconstructs and
        // submits; the subsequent full compact block for the same block hash is
        // deduped -- never a double submit.
        let submitter = CountingSubmitter::default();
        let metrics = SidecarMetrics::default();
        let mut dedup = HashDedupRing::new(16, Duration::from_secs(60));
        let now = Instant::now();

        let header = vec![0xab; 2189];
        let nonce = 9;
        let coinbase = vec![0x01, 0x02];
        let tx1 = vec![0x03, 0x04, 0x05];
        let wtxid = make_wtxid(0x11);
        let short_id = ShortId::compute(&wtxid, &zcash_block_hash(&header), nonce);
        let skeleton = CompactBlock::new(
            header.clone(),
            nonce,
            vec![short_id],
            vec![PrefilledTx {
                index: 0,
                tx_data: coinbase.clone(),
            }],
        );
        let mut mempool = TestMempool::new();
        mempool.insert(wtxid, tx1);

        submit_compact_fast_path(
            &submitter,
            &skeleton,
            SubmitBlockMode::Live,
            true,
            &mempool,
            &metrics,
            &mut dedup,
            now,
            true,
        )
        .await;
        assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.skeleton_submit_successes.load(Ordering::Relaxed), 1);

        // Full compact block for the same block -> deduped, no second submit.
        let full = skeleton.clone();
        submit_compact_fast_path(
            &submitter,
            &full,
            SubmitBlockMode::Live,
            true,
            &mempool,
            &metrics,
            &mut dedup,
            now,
            false,
        )
        .await;
        assert_eq!(
            submitter.calls.load(Ordering::SeqCst),
            1,
            "block must never be submitted twice"
        );
        assert_eq!(metrics.full_block_deduplicated.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn incomplete_skeleton_waits_and_full_block_submits() {
        // A skeleton with an unresolved short_id does not submit; the full
        // compact block (the origin prefills that tx as the push fallback) then
        // reconstructs without the mempool and submits normally.
        let submitter = CountingSubmitter::default();
        let metrics = SidecarMetrics::default();
        let mut dedup = HashDedupRing::new(16, Duration::from_secs(60));
        let now = Instant::now();

        let header = vec![0xcd; 2189];
        let nonce = 3;
        let coinbase = vec![0x01];
        let tx1 = vec![0x02, 0x03];
        let short_id = ShortId::compute(&make_wtxid(0x21), &zcash_block_hash(&header), nonce);
        let empty_mempool = TestMempool::new();

        let skeleton = CompactBlock::new(
            header.clone(),
            nonce,
            vec![short_id],
            vec![PrefilledTx {
                index: 0,
                tx_data: coinbase.clone(),
            }],
        );
        submit_compact_fast_path(
            &submitter,
            &skeleton,
            SubmitBlockMode::Live,
            true,
            &empty_mempool,
            &metrics,
            &mut dedup,
            now,
            true,
        )
        .await;
        assert_eq!(
            submitter.calls.load(Ordering::SeqCst),
            0,
            "incomplete skeleton must not submit"
        );
        assert_eq!(metrics.skeleton_incomplete.load(Ordering::Relaxed), 1);

        // Full compact block: coinbase + tx1 both prefilled -> submits.
        let full = CompactBlock::new(
            header,
            nonce,
            Vec::new(),
            vec![
                PrefilledTx {
                    index: 0,
                    tx_data: coinbase,
                },
                PrefilledTx {
                    index: 0,
                    tx_data: tx1,
                },
            ],
        );
        submit_compact_fast_path(
            &submitter,
            &full,
            SubmitBlockMode::Live,
            true,
            &empty_mempool,
            &metrics,
            &mut dedup,
            now,
            false,
        )
        .await;
        assert_eq!(
            submitter.calls.load(Ordering::SeqCst),
            1,
            "full compact block submits after an incomplete skeleton"
        );
    }

    #[tokio::test]
    async fn full_block_wins_then_late_skeleton_is_a_noop() {
        // Reverse race: the full compact block submits first, so a later
        // skeleton for the same block is deduped.
        let submitter = CountingSubmitter::default();
        let metrics = SidecarMetrics::default();
        let mut dedup = HashDedupRing::new(16, Duration::from_secs(60));
        let now = Instant::now();

        let header = vec![0xef; 2189];
        let nonce = 5;
        let coinbase = vec![0x01];
        let tx1 = vec![0x02, 0x03];
        let wtxid = make_wtxid(0x31);
        let short_id = ShortId::compute(&wtxid, &zcash_block_hash(&header), nonce);

        let full = CompactBlock::new(
            header.clone(),
            nonce,
            Vec::new(),
            vec![
                PrefilledTx {
                    index: 0,
                    tx_data: coinbase.clone(),
                },
                PrefilledTx {
                    index: 0,
                    tx_data: tx1.clone(),
                },
            ],
        );
        let mut mempool = TestMempool::new();
        mempool.insert(wtxid, tx1);
        submit_compact_fast_path(
            &submitter,
            &full,
            SubmitBlockMode::Live,
            true,
            &mempool,
            &metrics,
            &mut dedup,
            now,
            false,
        )
        .await;
        assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);

        let skeleton = CompactBlock::new(
            header,
            nonce,
            vec![short_id],
            vec![PrefilledTx {
                index: 0,
                tx_data: coinbase,
            }],
        );
        submit_compact_fast_path(
            &submitter,
            &skeleton,
            SubmitBlockMode::Live,
            true,
            &mempool,
            &metrics,
            &mut dedup,
            now,
            true,
        )
        .await;
        assert_eq!(
            submitter.calls.load(Ordering::SeqCst),
            1,
            "late skeleton must not resubmit"
        );
        assert_eq!(metrics.skeleton_deduplicated.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn skeleton_metrics_render_in_prometheus_text() {
        let metrics = SidecarMetrics::default();
        metrics.inc_skeleton_received();
        metrics.inc_skeleton_submit_successes();
        metrics.inc_skeleton_incomplete();
        metrics.inc_skeleton_deduplicated();
        metrics.inc_full_block_deduplicated();
        let text = metrics.render_prometheus_text();
        assert!(text.contains("sovright_relay_sidecar_skeleton_received_total 1"));
        assert!(text.contains("sovright_relay_sidecar_skeleton_submit_successes_total 1"));
        assert!(text.contains("sovright_relay_sidecar_skeleton_incomplete_total 1"));
        assert!(text.contains("sovright_relay_sidecar_skeleton_deduplicated_total 1"));
        assert!(text.contains("sovright_relay_sidecar_skeleton_full_block_deduplicated_total 1"));
    }

    #[test]
    fn hash_dedup_ring_expires_and_bounds() {
        let mut ring = HashDedupRing::new(2, Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(!ring.contains("a", t0));
        ring.record("a".to_string(), t0);
        assert!(ring.contains("a", t0));
        // Expired after the window.
        assert!(!ring.contains("a", t0 + Duration::from_secs(31)));
        // Capacity bound evicts the oldest.
        let t1 = t0 + Duration::from_secs(1);
        ring.record("x".to_string(), t1);
        ring.record("y".to_string(), t1);
        ring.record("z".to_string(), t1);
        assert!(!ring.contains("x", t1), "oldest evicted at capacity");
        assert!(ring.contains("y", t1));
        assert!(ring.contains("z", t1));
    }

    #[test]
    fn observe_first_seen_to_submit_ms_accumulates_sum_and_count() {
        let metrics = SidecarMetrics::default();
        metrics.observe_first_seen_to_submit_ms(100);
        metrics.observe_first_seen_to_submit_ms(50);

        let text = metrics.render_prometheus_text();
        assert!(
            text.contains("sovright_relay_sidecar_relay_first_seen_to_submit_ms_sum 150"),
            "unexpected sum render: {text}"
        );
        assert!(
            text.contains("sovright_relay_sidecar_relay_first_seen_to_submit_ms_count 2"),
            "unexpected count render: {text}"
        );
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
        assert!(text.contains("sovright_relay_sidecar_tx_feed_payloads_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_bytes_total 4"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_invalid_lines_total 0"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_cache_disabled_total 0"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_dropped_too_large_total 0"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_entries 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_bytes 4"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_max_entries 8"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_max_bytes 1024"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_max_tx_bytes 512"));
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
        assert!(text.contains("sovright_relay_sidecar_tx_feed_payloads_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_bytes_total 4"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_entries 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_bytes 4"));
    }

    #[tokio::test]
    async fn sidecar_tx_feed_listener_counts_invalid_lines() {
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

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"not-a-valid-feed-record\n")
            .await
            .unwrap();
        drop(stream);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let text = metrics.render_prometheus_text();
                if text.contains("sovright_relay_sidecar_tx_feed_invalid_lines_total 1") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("tx feed listener should count invalid lines");

        handle.abort();
        let text = metrics.render_prometheus_text();
        assert!(text.contains("sovright_relay_sidecar_tx_feed_payloads_total 0"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_invalid_lines_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_entries 0"));
    }

    #[tokio::test]
    async fn relay_compact_handler_uses_injected_mempool_for_short_ids() {
        let header = vec![0xcd; sovright_relay::ZCASH_FULL_HEADER_SIZE];
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
            SubmissionOutcome::NeedsTransactions { .. } => {
                panic!("complete mempool should not need tx fallback")
            }
            SubmissionOutcome::Submitted { .. } => panic!("dry-run must not submit"),
            SubmissionOutcome::GateRejected { .. } => {
                panic!("ungated path must not surface GateRejected")
            }
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

    #[tokio::test]
    async fn relay_compact_handler_prepares_getblocktxn_on_reconstruction_miss() {
        let header = vec![0xef; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let nonce = 7;
        let coinbase_wtxid = make_wtxid(0x01);
        let missing_wtxid = make_wtxid(0x21);
        let coinbase = vec![0x01, 0x02];
        let tx1 = vec![0x03, 0x04, 0x05];
        let mut builder = CompactBlockBuilder::new(header, nonce);
        builder.add_transaction(coinbase_wtxid, coinbase);
        builder.add_transaction(missing_wtxid, tx1);

        let mut peer_mempool = TestMempool::new();
        peer_mempool.insert(missing_wtxid, vec![0x03, 0x04, 0x05]);
        let compact = builder.build(&peer_mempool);
        assert_eq!(compact.short_ids.len(), 1);

        let sidecar_mempool = TestMempool::new();
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
            SubmissionOutcome::NeedsTransactions {
                request,
                missing_indexes,
                missing_wtxids,
                unresolved_short_ids,
            } => {
                assert_eq!(request.block_hash, compact.header_hash());
                assert_eq!(request.indexes, vec![1]);
                assert_eq!(missing_indexes, 1);
                assert_eq!(missing_wtxids, 0);
                assert_eq!(unresolved_short_ids, 1);
            }
            SubmissionOutcome::DryRun(_) => panic!("missing txs should not produce a candidate"),
            SubmissionOutcome::Submitted { .. } => panic!("dry-run must not submit"),
            SubmissionOutcome::GateRejected { .. } => {
                panic!("ungated path must not surface GateRejected")
            }
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
                .compact_reconstruction_incompletes
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .compact_reconstruction_getblocktxn_requests
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .compact_reconstruction_getblocktxn_requested_transactions
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.submit_rejections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn compact_reconstruction_incomplete_records_missing_detail_metrics() {
        let metrics = SidecarMetrics::default();
        let outcome = Err(RelayBlockError::ReconstructionIncomplete {
            block_hash: sovright_relay::BlockHash::from_bytes([0x30; 32]),
            missing_indexes: vec![1, 2, 3, 4, 5],
            missing_wtxids: vec![make_wtxid(0x31), make_wtxid(0x32)],
            unresolved_short_ids: vec![
                sovright_relay::ShortId::from_bytes([1, 2, 3, 4, 5, 6]),
                sovright_relay::ShortId::from_bytes([2, 3, 4, 5, 6, 7]),
                sovright_relay::ShortId::from_bytes([3, 4, 5, 6, 7, 8]),
            ],
        });

        record_compact_reconstruction_outcome(&outcome, &metrics);

        let text = metrics.render_prometheus_text();
        assert!(
            text.contains(
                "sovright_relay_sidecar_relay_compact_reconstruction_incompletes_total 1"
            )
        );
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_missing_wtxids_total 2"
        ));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_unresolved_short_ids_total 3"
        ));
    }

    #[test]
    fn local_candidate_errors_are_not_submit_rejections() {
        let metrics = SidecarMetrics::default();

        log_submission_outcome(
            Err(RelayBlockError::MissingTransactions { short_ids: 1 }),
            &metrics,
            None,
        );

        let text = metrics.render_prometheus_text();
        assert!(text.contains("sovright_relay_sidecar_relay_not_submit_candidates_total 1"));
        assert!(text.contains("sovright_relay_sidecar_relay_submit_rpc_failures_total 0"));
        assert!(text.contains("sovright_relay_sidecar_relay_submit_rejections_total 0"));
    }

    #[test]
    fn sidecar_metrics_render_prometheus_text() {
        let metrics = SidecarMetrics::default();
        metrics.inc_compact_blocks_received();
        metrics.inc_compact_reconstruction_attempts();
        metrics.inc_compact_reconstruction_completes();
        metrics.inc_compact_reconstruction_incompletes();
        metrics.inc_compact_reconstruction_invalids("duplicate_prefilled");
        metrics.inc_compact_reconstruction_errors();
        metrics.add_compact_reconstruction_missing_detail(2, 3);
        metrics.add_compact_reconstruction_getblocktxn_request(4);
        metrics.inc_raw_segments_received();
        metrics.inc_raw_segment_sets_completed();
        metrics.inc_raw_segment_drops();
        metrics.inc_raw_segment_reassembly_failures();
        metrics.inc_submit_dry_run_candidates();
        metrics.inc_submit_successes();
        metrics.inc_submit_duplicates();
        metrics.inc_submit_rejections(SubmitRejectionClass::RaceLost);
        metrics.inc_submit_rejections(SubmitRejectionClass::Invalid);
        metrics.inc_submit_rejections(SubmitRejectionClass::Unknown);
        metrics.inc_tx_feed_payload(512);
        metrics.inc_tx_feed_invalid_lines();
        metrics.inc_tx_feed_cache_disabled();
        metrics.add_tx_feed_dropped_too_large(2);
        metrics.set_raw_segment_buffer_state(2, 4096);
        metrics.set_tx_cache_snapshot(&sovright_relay::TxCacheSnapshot {
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

        assert!(text.contains("sovright_relay_sidecar_relay_compact_blocks_received_total 1"));
        assert!(
            text.contains("sovright_relay_sidecar_relay_compact_reconstruction_attempts_total 1")
        );
        assert!(
            text.contains("sovright_relay_sidecar_relay_compact_reconstruction_completes_total 1")
        );
        assert!(
            text.contains(
                "sovright_relay_sidecar_relay_compact_reconstruction_incompletes_total 1"
            )
        );
        assert!(
            text.contains("sovright_relay_sidecar_relay_compact_reconstruction_invalids_total 1")
        );
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_missing_wtxids_total 2"
        ));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_unresolved_short_ids_total 3"
        ));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_getblocktxn_requests_total 1"
        ));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_getblocktxn_requested_transactions_total 4"
        ));
        assert!(text.contains("sovright_relay_sidecar_relay_raw_segments_received_total 1"));
        assert!(text.contains("sovright_relay_sidecar_relay_raw_segment_sets_completed_total 1"));
        assert!(text.contains("sovright_relay_sidecar_relay_raw_segment_drops_total 1"));
        assert!(
            text.contains("sovright_relay_sidecar_relay_raw_segment_reassembly_failures_total 1")
        );
        assert!(text.contains("sovright_relay_sidecar_relay_submit_dry_run_candidates_total 1"));
        assert!(text.contains("sovright_relay_sidecar_relay_submit_successes_total 1"));
        assert!(text.contains("sovright_relay_sidecar_relay_submit_duplicates_total 1"));
        // Three increments above, one per class: the unlabelled total is their sum
        // and stays the series existing alerts and dashboards read.
        assert!(text.contains("sovright_relay_sidecar_relay_submit_rejections_total 3"));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_submit_rejections_total{reason=\"race_lost\"} 1"
        ));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_submit_rejections_total{reason=\"invalid\"} 1"
        ));
        assert!(text.contains(
            "sovright_relay_sidecar_relay_submit_rejections_total{reason=\"unknown\"} 1"
        ));
        assert!(text.contains("sovright_relay_sidecar_raw_segment_incomplete_blocks 2"));
        assert!(text.contains("sovright_relay_sidecar_raw_segment_payload_bytes 4096"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_entries 3"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_bytes 2048"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_max_entries 8"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_max_bytes 4096"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_max_tx_bytes 512"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_evicted_entries_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_evicted_bytes_total 128"));
        assert!(text.contains("sovright_relay_sidecar_tx_cache_dropped_too_large_total 2"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_payloads_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_bytes_total 512"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_invalid_lines_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_cache_disabled_total 1"));
        assert!(text.contains("sovright_relay_sidecar_tx_feed_dropped_too_large_total 2"));
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

    // --- reconstruction failure attribution ---------------------------------
    //
    // Measured 2026-09-03: 92 compact reconstruction attempts across the fleet,
    // 26 complete, 66 counted "invalid" -- 72% failure, and 94% on
    // relay-asia-east1-1. missing_wtxids and unresolved_short_ids were ZERO on
    // every host, so the tx cache held everything reconstruction asked for; the
    // failures are not cache misses. We could not say more than that, because
    // the handler matched `ReconstructionInvalid { .. }` and threw the reason
    // string away, and an `Err(_)` arm folded every other error into the same
    // counter. 66 failures, zero diagnostic trail.

    #[test]
    fn invalid_reasons_are_classified_for_metrics() {
        assert_eq!(
            classify_reconstruction_invalid("duplicate prefilled position 7"),
            "duplicate_prefilled"
        );
        assert_eq!(
            classify_reconstruction_invalid("prefilled index 12 out of bounds for 9 txs"),
            "prefilled_out_of_bounds"
        );
    }

    #[test]
    fn an_unrecognised_reason_is_kept_as_other_not_dropped() {
        // A new failure mode must land somewhere countable rather than vanish.
        assert_eq!(
            classify_reconstruction_invalid("merkle root mismatch"),
            "other"
        );
        assert_eq!(classify_reconstruction_invalid(""), "other");
    }

    #[test]
    fn non_reconstruction_errors_are_not_counted_as_invalid() {
        // The old `Err(_) => inc_invalids()` arm made "invalid" a catch-all, so
        // the number overstated true reconstruction invalidity and no separate
        // signal existed for anything else going wrong.
        let m = SidecarMetrics::default();
        record_compact_reconstruction_outcome(&Err(RelayBlockError::EmptyTransactions), &m);
        assert_eq!(m.compact_reconstruction_invalids.load(Ordering::Relaxed), 0);
        assert_eq!(m.compact_reconstruction_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn invalid_reconstruction_counts_and_labels_its_reason() {
        let m = SidecarMetrics::default();
        record_compact_reconstruction_outcome(
            &Err(RelayBlockError::ReconstructionInvalid {
                reason: "duplicate prefilled position 3".to_string(),
            }),
            &m,
        );
        assert_eq!(m.compact_reconstruction_invalids.load(Ordering::Relaxed), 1);
        let text = m.render_prometheus_text();
        assert!(text.contains(
            "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total{reason=\"duplicate_prefilled\"} 1"
        ), "{text}");
        assert!(
            text.contains("sovright_relay_sidecar_relay_compact_reconstruction_errors_total 0")
        );
    }
}
