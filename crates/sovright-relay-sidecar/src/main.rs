//! Relay sidecar for Stratum V1 mining pools

use clap::Parser;
use sovright_relay::{
    ArrivalSink, BlockBodyError, BlockReceiver, BoundBlock, BoundRawConfig, CompactBlock,
    MempoolProvider, RawBlockSegment, RelayPayload, TxCache, TxCacheConfig, TxCacheInsertOutcome,
    TxCacheSnapshot, TxFeedRecord, WtxId, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    zcash_block_hash,
};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

mod bound_tasks;
mod poller;
mod relay;

use bound_tasks::{Body, BoundTaskLimits, BoundTasks, HeldCopies, body_of};
use poller::{TemplatePoller, TemplateUpdate};
use relay::RelayWrapper;
use sovright_relay_sidecar::chain_view::{ZebraChainView, ZebraChainViewConfig};
use sovright_relay_sidecar::compact::build_compact_block;
use sovright_relay_sidecar::config;
use sovright_relay_sidecar::dual_submit::{DualSubmit, SecondarySample, build_submitter};
use sovright_relay_sidecar::mempool_sync::run_zebra_mempool_sync;
use sovright_relay_sidecar::metrics_textfile::write_metrics_textfile;
use sovright_relay_sidecar::rpc::ZebraRpc;
use sovright_relay_sidecar::submit::{
    RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitBlockStatus,
    SubmitRejectionClass, UnverifiedLimits, build_submission_candidate, handle_relay_compact_block,
    handle_relay_compact_block_with_mempool, handle_relay_raw_block, submit_unverified_raw_block,
    unreadable_body, validate_then_gate_compact_block, validate_then_gate_raw_block,
    zebra_has_the_block,
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

    /// Raw segment buffer byte budget, including payloads, slots and entries
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
                .add_directive("sovright_relay_sidecar=info".parse()?)
                .add_directive("sovright_relay::relay::bound_raw=warn".parse()?),
        )
        .init();

    let args = Args::parse();
    // #130 PR B research, off unless asked for.
    let bound_raw = sovright_relay::bound_raw_switch()?;
    if bound_raw {
        info!(target: "sovright_relay_sidecar", "Bound raw switch on");
    }

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
    if bound_raw && !receive_relay_blocks {
        warn!("SOVRIGHT_RELAY_BOUND_RAW is on but receive_relay_blocks is off; ignoring");
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

    // A/B settings are config-file only: production runs with --config, and
    // keeping them out of the big CLI/config tuple avoids churning three
    // destructuring sites for a measurement feature.
    let (zebra_url_secondary, submit_log_path, secondary_submit_sample) = match &args.config {
        Some(path) => {
            let cfg = config::Config::from_file(std::path::Path::new(path))?;
            (
                cfg.zebra_url_secondary.clone(),
                cfg.submit_log_path.clone(),
                cfg.secondary_submit_sample,
            )
        }
        None => (None, None, SecondarySample::All),
    };

    // Optional A/B second target. `submitter` wraps the RPC client; when no
    // secondary is configured it is the primary plus (optional) logging and
    // nothing else changes. Every submit path receives `submitter` rather than
    // `rpc`, so the second target cannot be forgotten on one path -- the
    // failure that left #88 inert on four of five call sites.
    let secondary_submitter: Option<(Arc<dyn SubmitBlock + Send + Sync>, String)> =
        match &zebra_url_secondary {
            Some(url) => match ZebraRpc::new(url).await {
                Ok(client) => {
                    info!(secondary_url = %url, "A/B secondary submit target enabled");
                    Some((
                        Arc::new(client) as Arc<dyn SubmitBlock + Send + Sync>,
                        url.clone(),
                    ))
                }
                Err(error) => {
                    // A secondary that will not connect must not stop the
                    // sidecar: it is measurement, not production.
                    warn!(%error, secondary_url = %url, "secondary submit target unavailable; continuing with primary only");
                    None
                }
            },
            None => None,
        };
    let submitter = Arc::new(
        build_submitter(
            Arc::clone(&rpc),
            &zebra_url,
            secondary_submitter
                .as_ref()
                .map(|(node, url)| (Arc::clone(node), url.as_str())),
            submit_log_path.as_deref().map(std::path::Path::new),
        )
        .with_secondary_sample(secondary_submit_sample),
    );
    if submitter.has_secondary() {
        info!(sample = ?secondary_submit_sample, "submitblock will be mirrored to the secondary node");
    }

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

    // Initialize relay.
    let relay = RelayWrapper::new_with_fec(
        relay_peers.clone(),
        auth_key,
        bind_addr,
        data_shards,
        parity_shards,
        send_burst_packets,
        Duration::from_micros(send_burst_delay_micros),
        bound_raw.then(BoundRawConfig::default),
    )?;
    relay.init().await?;
    let relay_block_handler = if receive_relay_blocks {
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
        let unreadable_submit = submit_gate_cfg
            .as_ref()
            .and_then(UnreadableSubmit::from_config);
        if let Some(unreadable) = &unreadable_submit {
            warn!(
                budget = ?unreadable.budget,
                "Emergency bypass on: raw blocks this sidecar cannot read go to Zebra without \
                 the Merkle and duplicate checks. Only blocks in the mainnet target range \
                 qualify"
            );
            metrics
                .unreadable_submit_enabled
                .store(true, Ordering::Relaxed);
        }
        let (gate, chain_view) = if let Some(cfg) = submit_gate_cfg.as_ref().filter(|c| c.enabled) {
            let chain_view = ZebraChainView::new(ZebraChainViewConfig::default());
            // Spawn the polling task; drop the JoinHandle since the view's
            // lifetime is bound by the main loop. Dropping the chain_view
            // Arc on shutdown cancels the poller.
            let _poller = Arc::clone(&chain_view).start(Arc::clone(&rpc));
            let mut gate_config = cfg.to_gate_config();
            // The bound path brings competing bodies of one block, and a legacy gate would
            // let the first of them close the block whatever Zebra says of it.
            if bound_raw && !gate_config.competing_bodies {
                info!("Bound raw switch on: the submit gate runs its competing-body rules");
                gate_config.competing_bodies = true;
            }
            let gate = Arc::new(TokioMutex::new(SubmitGate::new(
                gate_config,
                Arc::clone(&chain_view),
            )));
            info!("Safety gate enabled");
            (Some(gate), Some(chain_view))
        } else {
            (None, None)
        };

        Some(spawn_relay_block_handler(
            receiver,
            Arc::clone(&rpc),
            Arc::clone(&submitter),
            mode,
            compact_reconstruction_enabled,
            raw_segment_buffer_config,
            Arc::clone(&metrics),
            Arc::clone(&mempool),
            gate,
            chain_view,
            unreadable_submit,
            BoundTaskLimits::default(),
        ))
    } else {
        relay.start().await?;
        None
    };
    // A stopped receive/submit task must not leave an apparently healthy sidecar.
    let handler_exit = async move {
        match relay_block_handler {
            Some(handler) => match handler.await {
                Ok(()) => std::io::Error::other("relay block handler stopped"),
                Err(error) => std::io::Error::other(error),
            },
            None => std::future::pending().await,
        }
    };
    tokio::pin!(handler_exit);
    let relay = Arc::new(relay);

    if !announce_templates {
        info!("Template announcements disabled; sidecar running relay receive only");
        return Err(handler_exit.await.into());
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
    loop {
        let update = tokio::select! {
            update = rx.recv() => match update {
                Some(update) => update,
                None => break,
            },
            error = &mut handler_exit => return Err(error.into()),
        };
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
            // NOT "incomplete": this arm is a submit failure or rejection, not
            // a missing transaction. Counting it as incomplete made a storm of
            // Zebra rejections read as ordinary mempool misses, hiding the
            // defect for as long as anyone looked only at the metric.
            if is_skeleton {
                metrics.inc_skeleton_submit_errors();
            }
        }
    }
    log_submission_outcome(outcome, metrics, None);
}

/// What was held and can go now, then what comes in.
async fn next_payload(
    receiver: &mut BlockReceiver,
    again: &mut VecDeque<RelayPayload>,
) -> Option<RelayPayload> {
    match again.pop_front() {
        Some(payload) => Some(payload),
        None => receiver.recv_payload().await,
    }
}

async fn next_bound_block(
    blocks: &mut Option<tokio::sync::mpsc::Receiver<BoundBlock>>,
) -> Option<BoundBlock> {
    match blocks {
        Some(blocks) => blocks.recv().await,
        None => std::future::pending().await,
    }
}

/// The checks a whole raw block goes through, however it got here.
async fn check_and_submit_raw_block(
    rpc: &Arc<ZebraRpc>,
    submitter: &Arc<DualSubmit<Arc<ZebraRpc>>>,
    raw_block: &[u8],
    block_hash: [u8; 32],
    mode: SubmitBlockMode,
    gate: Option<&Arc<TokioMutex<SubmitGate<Arc<ZebraChainView>>>>>,
    chain_view: Option<&Arc<ZebraChainView>>,
) -> Result<SubmissionOutcome, RelayBlockError> {
    if let (Some(gate), Some(chain_view)) = (gate, chain_view) {
        validate_then_gate_raw_block(
            submitter.as_ref(),
            raw_block,
            Some(block_hash),
            mode,
            gate,
            || chain_view.observe_candidate_parent(rpc.as_ref(), raw_block),
        )
        .await
    } else {
        handle_relay_raw_block(submitter.as_ref(), raw_block, Some(block_hash), mode).await
    }
}

/// What the work on a whole block needs, on whichever task does it.
#[derive(Clone)]
struct BlockWork {
    rpc: Arc<ZebraRpc>,
    submitter: Arc<DualSubmit<Arc<ZebraRpc>>>,
    mode: SubmitBlockMode,
    gate: Option<Arc<TokioMutex<SubmitGate<Arc<ZebraChainView>>>>>,
    chain_view: Option<Arc<ZebraChainView>>,
    unreadable_submit: Option<UnreadableSubmit>,
    metrics: Arc<SidecarMetrics>,
}

/// What a block by the legacy ways leaves to wait while a task works on its block.
enum HeldCopy {
    Payload(RelayPayload),
    Segments {
        segments: Vec<RawBlockSegment>,
        block_hash: [u8; 32],
        first_seen: Instant,
    },
}

/// The bytes a compact block comes to, if it carries them all.
fn compact_body(compact: &CompactBlock) -> Option<Body> {
    let candidate = build_submission_candidate(compact).ok()?;
    Some(body_of(&hex::decode(candidate.block_hex).ok()?))
}

/// A bound block as the receive task takes it. Past this it is a task's, and nothing here waits
/// for that.
fn start_bound_block(
    block: BoundBlock,
    work: &BlockWork,
    tasks: &mut BoundTasks,
    fast_path_dedup: &mut HashDedupRing,
) {
    work.metrics.inc_raw_segment_sets_completed();
    let Some(header) = block.raw().get(..ZCASH_FULL_HEADER_SIZE) else {
        work.metrics.inc_raw_segment_reassembly_failures();
        block.give_back();
        return;
    };
    let block_hash = zcash_block_hash(header);
    let hash_hex = hex::encode(block_hash);
    if fast_path_dedup.contains(&hash_hex, Instant::now()) {
        debug!(block_hash = %hash_hex, "bound block already submitted; skipping");
        block.finish();
        return;
    }
    let body = body_of(block.raw());
    tasks.spawn(
        hash_hex,
        body,
        handle_bound_block(block, block_hash, work.clone()),
    );
}

/// One whole bound block, through the same checks as a reassembled raw block, and then
/// settled by what came of it. It has no record but its owners, and only an outcome that
/// says this block is dealt with ends them for good. Any other end lets a copy in, and that
/// goes for a task cancelled here too, as the block and the gate's slot go with it. True if
/// Zebra has the block from this, which the receive task records for the other ways in.
async fn handle_bound_block(block: BoundBlock, block_hash: [u8; 32], work: BlockWork) -> bool {
    let first_seen = Instant::now();
    let metrics = &work.metrics;
    let gate = work.gate.as_ref();
    let chain_view = work.chain_view.as_ref();
    let outcome = check_and_submit_raw_block(
        &work.rpc,
        &work.submitter,
        block.raw(),
        block_hash,
        work.mode,
        gate,
        chain_view,
    )
    .await;
    if let (Some(error), Some(unreadable), Some(gate), Some(chain_view)) = (
        unreadable_body(&outcome),
        work.unreadable_submit.as_ref(),
        gate,
        chain_view,
    ) {
        unreadable.spawn(UnverifiedSubmission {
            submitter: Arc::clone(&work.submitter),
            rpc: Arc::clone(&work.rpc),
            gate: Arc::clone(gate),
            chain_view: Arc::clone(chain_view),
            metrics: Arc::clone(metrics),
            mode: work.mode,
            raw_block: block.raw().to_vec(),
            error,
            first_seen,
        });
        block.give_back();
        return false;
    }
    // A dry run passed the gate but told Zebra nothing, so it is not a delivery: counting
    // it as one would close the block on a body nobody checked, and the real body would
    // never be measured.
    let passed = matches!(
        outcome,
        Ok(SubmissionOutcome::Submitted { .. }) | Ok(SubmissionOutcome::DryRun(_))
    );
    let delivered = matches!(outcome, Ok(SubmissionOutcome::Submitted { .. }));
    let known_to_zebra = zebra_has_the_block(&outcome, gate.map(Arc::as_ref)).await;
    if passed && gate.is_some() {
        metrics.inc_submit_gate_accepted();
    }
    let first_seen_to_submit_ms = first_seen.elapsed().as_millis() as u64;
    if matches!(outcome, Ok(SubmissionOutcome::Submitted { .. })) {
        metrics.observe_first_seen_to_submit_ms(first_seen_to_submit_ms);
    }
    log_submission_outcome(outcome, metrics.as_ref(), Some(first_seen_to_submit_ms));
    if delivered || known_to_zebra {
        block.finish();
    } else {
        block.give_back();
    }
    delivered
}

/// A legacy block whose segments are all here, the rest of the way to Zebra. This runs on the
/// receive task, as the legacy ways always have.
async fn finish_raw_segments(
    segments: Vec<RawBlockSegment>,
    block_hash: [u8; 32],
    first_seen: Instant,
    work: &BlockWork,
    fast_path_dedup: &mut HashDedupRing,
) {
    let completed_segments = segments.len();
    match reassemble_raw_block(&segments) {
        Ok(raw_block) => {
            let Some(header) = raw_block.get(..ZCASH_FULL_HEADER_SIZE) else {
                work.metrics.inc_raw_segment_reassembly_failures();
                warn!(
                    raw_block_bytes = raw_block.len(),
                    "Relay raw block is shorter than its header"
                );
                return;
            };
            info!(
                block_hash = %hex::encode(block_hash),
                segment_count = completed_segments,
                raw_block_bytes = raw_block.len(),
                "Relay raw block segments complete"
            );
            // Dedup against compact/skeleton paths: the
            // consensus block hash is the shared key.
            let raw_block_hash = hex::encode(zcash_block_hash(header));
            if fast_path_dedup.contains(&raw_block_hash, Instant::now()) {
                debug!(
                    block_hash = %raw_block_hash,
                    "raw segment already submitted by compact path; skipping duplicate"
                );
                return;
            }
            let raw_outcome = check_and_submit_raw_block(
                &work.rpc,
                &work.submitter,
                &raw_block,
                block_hash,
                work.mode,
                work.gate.as_ref(),
                work.chain_view.as_ref(),
            )
            .await;
            if let (Some(error), Some(unreadable), Some(gate), Some(chain_view)) = (
                unreadable_body(&raw_outcome),
                &work.unreadable_submit,
                &work.gate,
                &work.chain_view,
            ) {
                // Off the receive task, which must keep
                // reading while Zebra judges this.
                unreadable.spawn(UnverifiedSubmission {
                    submitter: Arc::clone(&work.submitter),
                    rpc: Arc::clone(&work.rpc),
                    gate: Arc::clone(gate),
                    chain_view: Arc::clone(chain_view),
                    metrics: Arc::clone(&work.metrics),
                    mode: work.mode,
                    raw_block,
                    error,
                    first_seen,
                });
                return;
            }
            if work.gate.is_some()
                && matches!(
                    raw_outcome,
                    Ok(SubmissionOutcome::DryRun(_)) | Ok(SubmissionOutcome::Submitted { .. })
                )
            {
                work.metrics.inc_submit_gate_accepted();
            }
            // Relay-internal latency from the first raw
            // segment chunk of this block arriving to the
            // submit decision (mesh-receive → reassemble →
            // gate → submit).
            let first_seen_to_submit_ms = first_seen.elapsed().as_millis() as u64;
            if matches!(
                raw_outcome,
                Ok(SubmissionOutcome::Submitted { .. }) | Ok(SubmissionOutcome::DryRun(_))
            ) {
                // Record in shared dedup ring so compact-block
                // paths won't also submit this consensus block.
                fast_path_dedup.record(raw_block_hash, Instant::now());
            }
            if matches!(raw_outcome, Ok(SubmissionOutcome::Submitted { .. })) {
                work.metrics
                    .observe_first_seen_to_submit_ms(first_seen_to_submit_ms);
            }
            log_submission_outcome(
                raw_outcome,
                work.metrics.as_ref(),
                Some(first_seen_to_submit_ms),
            );
        }
        Err(error) => {
            work.metrics.inc_raw_segment_reassembly_failures();
            warn!(%error, "Relay raw block segments did not reassemble");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_relay_block_handler<M>(
    mut receiver: BlockReceiver,
    rpc: Arc<ZebraRpc>,
    // The submitter every submit path uses. Distinct from `rpc`, which is still
    // needed for chain-view height lookups that are not submissions.
    submitter: Arc<DualSubmit<Arc<ZebraRpc>>>,
    mode: SubmitBlockMode,
    compact_reconstruction_enabled: bool,
    raw_segment_buffer_config: RawSegmentBufferConfig,
    metrics: Arc<SidecarMetrics>,
    mempool: Arc<M>,
    gate: Option<Arc<TokioMutex<SubmitGate<Arc<ZebraChainView>>>>>,
    chain_view: Option<Arc<ZebraChainView>>,
    unreadable_submit: Option<UnreadableSubmit>,
    bound_limits: BoundTaskLimits,
) -> tokio::task::JoinHandle<()>
where
    M: MempoolProvider + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let work = BlockWork {
            rpc: Arc::clone(&rpc),
            submitter: Arc::clone(&submitter),
            mode,
            gate: gate.clone(),
            chain_view: chain_view.clone(),
            unreadable_submit,
            metrics: Arc::clone(&metrics),
        };
        let mut bound_blocks = receiver.take_bound_blocks();
        let mut bound_tasks = BoundTasks::new(bound_limits);
        let mut held = HeldCopies::new(bound_limits.held);
        let mut again = VecDeque::new();
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
                // With no room blocks stay in their channel, and this task goes on.
                block = next_bound_block(&mut bound_blocks), if bound_tasks.has_room() => {
                    match block {
                        Some(block) => {
                            start_bound_block(block, &work, &mut bound_tasks, &mut fast_path_dedup);
                        }
                        None => bound_blocks = None,
                    }
                }
                end = bound_tasks.next_end(), if !bound_tasks.is_idle() => {
                    if end.delivered {
                        fast_path_dedup.record(end.block.clone(), Instant::now());
                    }
                    for copy in held.task_ended(&bound_tasks, &end) {
                        match copy {
                            HeldCopy::Payload(payload) => again.push_back(payload),
                            HeldCopy::Segments { segments, block_hash, first_seen } => {
                                finish_raw_segments(
                                    segments,
                                    block_hash,
                                    first_seen,
                                    &work,
                                    &mut fast_path_dedup,
                                )
                                .await;
                            }
                        }
                    }
                }
                payload = next_payload(&mut receiver, &mut again) => {
                    let Some(payload) = payload else {
                        warn!("Relay block receiver closed");
                        break;
                    };
                    if !bound_tasks.is_idle()
                        && let RelayPayload::CompactBlock(compact)
                        | RelayPayload::CompactSkeleton(compact) = &payload
                    {
                        let hash_hex = hex::encode(zcash_block_hash(&compact.header));
                        let body = compact_body(compact);
                        if let Some(place) = held.place_for(&bound_tasks, &hash_hex, body) {
                            held.hold(place, HeldCopy::Payload(payload));
                            continue;
                        }
                    }
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
                                let outcome = validate_then_gate_compact_block(
                                    submitter.as_ref(),
                                    &compact,
                                    mode,
                                    gate,
                                    || chain_view.observe_candidate_parent(rpc.as_ref(), &compact.header),
                                )
                                .await;
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
                                    submitter.as_ref(),
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
                                submitter.as_ref(),
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
                                    let hash_hex = hex::encode(block_hash);
                                    let body = if bound_tasks.is_idle() {
                                        None
                                    } else {
                                        reassemble_raw_block(&segments).ok().map(|raw| body_of(&raw))
                                    };
                                    if let Some(place) = held.place_for(&bound_tasks, &hash_hex, body) {
                                        let copy = HeldCopy::Segments {
                                            segments,
                                            block_hash,
                                            first_seen,
                                        };
                                        held.hold(place, copy);
                                        continue;
                                    }
                                    finish_raw_segments(
                                        segments,
                                        block_hash,
                                        first_seen,
                                        &work,
                                        &mut fast_path_dedup,
                                    )
                                    .await;
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
        // A found block at Zebra gets its time, each task up to its budget where it waits. What
        // was held for one goes with this task: there is nothing left to run it.
        while !bound_tasks.is_idle() {
            bound_tasks.next_end().await;
        }
    })
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
    buffered_bytes: usize,
    segments: Vec<Option<RawBlockSegment>>,
}

struct RawSegmentBuffer {
    config: RawSegmentBufferConfig,
    entries: HashMap<[u8; 32], RawSegmentEntry>,
    total_payload_bytes: usize,
    // Charge payload capacities plus slot and entry sizes. Allocator bookkeeping
    // and HashMap spare capacity remain bounded overhead outside this budget.
    total_buffered_bytes: usize,
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
            total_buffered_bytes: 0,
        }
    }

    fn insert(&mut self, segment: RawBlockSegment, now: Instant) -> RawSegmentInsert {
        self.expire(now);

        let block_hash = segment.block_hash;
        let segment_count = segment.segment_count as usize;
        let segment_index = segment.segment_index as usize;
        if segment_count == 0 || segment_index >= segment_count {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "invalid segment metadata",
            };
        }
        // These are untrusted object declarations, independent of the size of
        // this authenticated frame. Bound them before allocating any slots.
        let raw_len = match usize::try_from(segment.raw_block_len) {
            Ok(len) if len <= self.config.max_total_payload_bytes => len,
            _ => {
                self.remove_entry(&block_hash);
                return RawSegmentInsert::Dropped {
                    reason: "raw block length exceeds raw segment byte limit",
                };
            }
        };
        if segment_count > raw_len.max(1) || segment.payload.len() > raw_len {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "invalid raw block length or segment count",
            };
        }
        let metadata_bytes = segment_count
            .checked_mul(std::mem::size_of::<Option<RawBlockSegment>>())
            .and_then(|slots| {
                slots.checked_add(std::mem::size_of::<([u8; 32], RawSegmentEntry)>())
            });
        let Some(metadata_bytes) = metadata_bytes.filter(|bytes| {
            bytes
                .checked_add(segment.payload.capacity())
                .is_some_and(|total| total <= self.config.max_total_payload_bytes)
        }) else {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "raw segment metadata exceeds byte limit",
            };
        };

        if !self.entries.contains_key(&block_hash) {
            self.evict_oldest_until_below_block_limit();
            if self.entries.len() >= self.config.max_incomplete_blocks {
                return RawSegmentInsert::Dropped {
                    reason: "raw segment block limit exhausted",
                };
            }
            if self
                .total_buffered_bytes
                .checked_add(metadata_bytes)
                .and_then(|bytes| bytes.checked_add(segment.payload.capacity()))
                .is_none_or(|bytes| bytes > self.config.max_total_payload_bytes)
            {
                return RawSegmentInsert::Dropped {
                    reason: "raw segment byte limit exhausted",
                };
            }
            let mut slots = Vec::new();
            if slots.try_reserve_exact(segment_count).is_err()
                || self.entries.try_reserve(1).is_err()
            {
                return RawSegmentInsert::Dropped {
                    reason: "raw segment allocation failed",
                };
            }
            slots.resize_with(segment_count, || None);
            self.entries.insert(
                block_hash,
                RawSegmentEntry {
                    first_seen: now,
                    bytes: 0,
                    buffered_bytes: metadata_bytes,
                    segments: slots,
                },
            );
            self.total_buffered_bytes += metadata_bytes;
        }

        let Some(entry) = self.entries.get_mut(&block_hash) else {
            return RawSegmentInsert::Dropped {
                reason: "raw segment entry unavailable",
            };
        };
        if entry.segments.len() != segment_count
            || entry.segments.iter().flatten().next().is_some_and(|first| {
                first.raw_block_len != segment.raw_block_len
                    || first.raw_block_digest != segment.raw_block_digest
            })
        {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "inconsistent raw segment metadata",
            };
        }
        if entry.segments[segment_index].is_some() {
            return RawSegmentInsert::Pending;
        }
        let next_total = self
            .total_buffered_bytes
            .checked_add(segment.payload.capacity());
        if next_total.is_none_or(|total| total > self.config.max_total_payload_bytes)
            || entry
                .bytes
                .checked_add(segment.payload.len())
                .is_none_or(|bytes| bytes > raw_len)
        {
            self.remove_entry(&block_hash);
            return RawSegmentInsert::Dropped {
                reason: "raw segment byte limit exhausted",
            };
        }

        entry.bytes += segment.payload.len();
        entry.buffered_bytes += segment.payload.capacity();
        self.total_payload_bytes += segment.payload.len();
        self.total_buffered_bytes = next_total.expect("checked admission budget");
        entry.segments[segment_index] = Some(segment);

        if self
            .entries
            .get(&block_hash)
            .is_some_and(|entry| entry.segments.iter().all(Option::is_some))
        {
            let entry = self.remove_entry(&block_hash).expect("entry exists");
            let first_seen = entry.first_seen;
            let mut segments = Vec::new();
            if segments.try_reserve_exact(segment_count).is_err() {
                return RawSegmentInsert::Dropped {
                    reason: "raw segment allocation failed",
                };
            }
            segments.extend(entry.segments.into_iter().flatten());
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
        self.total_buffered_bytes = self
            .total_buffered_bytes
            .saturating_sub(entry.buffered_bytes);
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

/// The emergency bypass, as the receive task runs it: each attempt on a task of its
/// own, so nothing else waits on Zebra.
#[derive(Clone)]
struct UnreadableSubmit {
    budget: Duration,
    /// One permit per attempt running, across all blocks. Attempts per block do not
    /// bound this, because each new header brings its own.
    running: Arc<tokio::sync::Semaphore>,
}

/// One reassembled block on its way through the bypass.
struct UnverifiedSubmission {
    submitter: Arc<DualSubmit<Arc<ZebraRpc>>>,
    rpc: Arc<ZebraRpc>,
    gate: Arc<TokioMutex<SubmitGate<Arc<ZebraChainView>>>>,
    chain_view: Arc<ZebraChainView>,
    metrics: Arc<SidecarMetrics>,
    mode: SubmitBlockMode,
    raw_block: Vec<u8>,
    error: BlockBodyError,
    first_seen: Instant,
}

impl UnreadableSubmit {
    /// `None` unless the bypass is on, which also needs the gate.
    fn from_config(config: &config::SubmitGateConfig) -> Option<Self> {
        (config.enabled && config.submit_unreadable_blocks).then(|| {
            Self::new(
                Duration::from_secs(config.unreadable_submit_budget_secs),
                config.unreadable_attempts_per_block,
            )
        })
    }

    fn new(budget: Duration, max_running: usize) -> Self {
        Self {
            budget,
            running: Arc::new(tokio::sync::Semaphore::new(max_running)),
        }
    }

    fn spawn(&self, submission: UnverifiedSubmission) {
        let Ok(permit) = Arc::clone(&self.running).try_acquire_owned() else {
            warn!("Emergency bypass is at its limit; refusing an unreadable block");
            submission.metrics.inc_submit_gate_rejected(
                sovright_relay_sidecar::submit_gate::RejectReason::UnverifiedLimit,
            );
            return;
        };
        let budget = self.budget;
        tokio::spawn(async move {
            let _permit = permit;
            let UnverifiedSubmission {
                submitter,
                rpc,
                gate,
                chain_view,
                metrics,
                mode,
                raw_block,
                error,
                first_seen,
            } = submission;
            let outcome = submit_unverified_raw_block(
                submitter.as_ref(),
                &raw_block,
                error,
                mode,
                gate.as_ref(),
                UnverifiedLimits {
                    budget,
                    bypassed: &metrics.block_body_unverified,
                },
                || chain_view.observe_candidate_parent(rpc.as_ref(), &raw_block),
            )
            .await;
            if matches!(
                outcome,
                Ok(SubmissionOutcome::DryRun(_)) | Ok(SubmissionOutcome::Submitted { .. })
            ) {
                metrics.inc_submit_gate_accepted();
            }
            let first_seen_to_submit_ms = first_seen.elapsed().as_millis() as u64;
            log_submission_outcome(outcome, metrics.as_ref(), Some(first_seen_to_submit_ms));
        });
    }
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
            RelayBlockError::InvalidBlockBody(error) => {
                metrics.inc_block_body_rejected(&error);
                warn!(%error, "Relay block body refused before submitblock");
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

/// The same bucket for a filled block that failed body validation.
///
/// A merkle mismatch is the expected label for a short-id collision or a stale
/// mempool copy -- failures that previously reached Zebra as a submit rejection
/// instead of being caught locally. It needs its own bucket precisely because it
/// is the one we expect to see, and a repeated txid needs another: its root can
/// match, so counting it as a mismatch sends whoever reads the metric after
/// short-id collisions that never happened.
fn classify_invalid_assembly(error: &BlockBodyError) -> &'static str {
    match error {
        BlockBodyError::MerkleMismatch => "merkle_mismatch",
        BlockBodyError::DuplicateTxid { .. } => "duplicate_txid",
        _ => "other",
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
        Err(RelayBlockError::InvalidBlockBody(error)) => {
            let kind = classify_invalid_assembly(error);
            metrics.inc_compact_reconstruction_invalids(kind);
            warn!(%error, kind, "Compact block reconstruction produced an invalid block");
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
    compact_reconstruction_invalids_merkle_mismatch: AtomicU64,
    compact_reconstruction_invalids_duplicate_txid: AtomicU64,
    compact_reconstruction_invalids_other: AtomicU64,
    block_body_rejections: [AtomicU64; BlockBodyError::ALL.len()],
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
    /// Skeleton submissions that failed or were rejected -- distinct from a
    /// skeleton we simply could not complete from the mempool.
    skeleton_submit_errors: AtomicU64,
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
    submit_rejections_inconclusive: AtomicU64,
    not_submit_candidates: AtomicU64,
    /// Per-cause counters for the submit safety gate. Incremented in
    /// `handle_relay_*_block_with_gate` so the staging service can attribute
    /// gate decisions while running in shadow mode (enable_submitblock=false).
    submit_gate_accepted: AtomicU64,
    submit_gate_rejected_pow: AtomicU64,
    submit_gate_rejected_unknown_parent: AtomicU64,
    submit_gate_rejected_out_of_window: AtomicU64,
    submit_gate_rejected_duplicate: AtomicU64,
    submit_gate_rejected_unverified_limit: AtomicU64,
    submit_gate_rejected_strict_limit: AtomicU64,
    submit_gate_rejected_refused_body: AtomicU64,
    block_body_unverified: AtomicU64,
    unreadable_submit_enabled: AtomicBool,
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

    fn inc_block_body_rejected(&self, error: &BlockBodyError) {
        self.block_body_rejections[error.kind_index()].fetch_add(1, Ordering::Relaxed);
    }

    fn inc_compact_reconstruction_invalids(&self, kind: &str) {
        match kind {
            "duplicate_prefilled" => &self.compact_reconstruction_invalids_duplicate_prefilled,
            "prefilled_out_of_bounds" => &self.compact_reconstruction_invalids_out_of_bounds,
            "merkle_mismatch" => &self.compact_reconstruction_invalids_merkle_mismatch,
            "duplicate_txid" => &self.compact_reconstruction_invalids_duplicate_txid,
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

    fn inc_skeleton_submit_errors(&self) {
        self.skeleton_submit_errors.fetch_add(1, Ordering::Relaxed);
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
            SubmitRejectionClass::Inconclusive => &self.submit_rejections_inconclusive,
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
            sovright_relay_sidecar::submit_gate::RejectReason::UnverifiedLimit => {
                &self.submit_gate_rejected_unverified_limit
            }
            sovright_relay_sidecar::submit_gate::RejectReason::StrictLimit => {
                &self.submit_gate_rejected_strict_limit
            }
            sovright_relay_sidecar::submit_gate::RejectReason::RefusedBody => {
                &self.submit_gate_rejected_refused_body
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
        let cri_merkle_mismatch = self
            .compact_reconstruction_invalids_merkle_mismatch
            .load(Ordering::Relaxed);
        let cri_duplicate_txid = self
            .compact_reconstruction_invalids_duplicate_txid
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
        let skeleton_submit_errors = self.skeleton_submit_errors.load(Ordering::Relaxed);
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

        let mut text = format!(
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
                "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total{{reason=\"merkle_mismatch\"}} {cri_merkle_mismatch}\n",
                "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total{{reason=\"duplicate_txid\"}} {cri_duplicate_txid}\n",
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
                "# TYPE sovright_relay_sidecar_skeleton_submit_errors_total counter\n",
                "sovright_relay_sidecar_skeleton_submit_errors_total {skeleton_submit_errors}\n",
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
            cri_merkle_mismatch = cri_merkle_mismatch,
            cri_duplicate_txid = cri_duplicate_txid,
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
            skeleton_submit_errors = skeleton_submit_errors,
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
        );
        text.push_str(&format!(
            "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"unverified_limit\"}} {}\n",
            self.submit_gate_rejected_unverified_limit
                .load(Ordering::Relaxed)
        ));
        text.push_str(&format!(
            "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"strict_limit\"}} {}\n",
            self.submit_gate_rejected_strict_limit
                .load(Ordering::Relaxed)
        ));
        text.push_str(&format!(
            "sovright_relay_sidecar_submit_gate_rejected_total{{reason=\"refused_body\"}} {}\n",
            self.submit_gate_rejected_refused_body
                .load(Ordering::Relaxed)
        ));
        text.push_str(&format!(
            "sovright_relay_sidecar_relay_submit_rejections_total{{reason=\"inconclusive\"}} {}\n",
            self.submit_rejections_inconclusive.load(Ordering::Relaxed)
        ));
        text.push_str(&format!(
            "# TYPE sovright_relay_sidecar_relay_block_body_unverified_total counter\n\
             sovright_relay_sidecar_relay_block_body_unverified_total {}\n\
             # TYPE sovright_relay_sidecar_unreadable_block_submit_enabled gauge\n\
             sovright_relay_sidecar_unreadable_block_submit_enabled {}\n",
            self.block_body_unverified.load(Ordering::Relaxed),
            u8::from(self.unreadable_submit_enabled.load(Ordering::Relaxed))
        ));
        text.push_str("# TYPE sovright_relay_sidecar_relay_block_body_rejected_total counter\n");
        for (kind, count) in BlockBodyError::ALL.iter().zip(&self.block_body_rejections) {
            text.push_str(&format!(
                "sovright_relay_sidecar_relay_block_body_rejected_total{{reason=\"{}\"}} {}\n",
                kind.label(),
                count.load(Ordering::Relaxed)
            ));
        }
        text
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

#[cfg(test)]
mod bound_path_tests;
#[cfg(test)]
mod known_gap_eviction_tests;
#[cfg(test)]
mod known_gap_s10_tests;
#[cfg(test)]
mod lease_buffer_harness_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use sovright_relay::{
        AuthDigest, CompactBlockBuilder, PrefilledTx, ShortId, TestMempool, TxId, WtxId,
        split_raw_block,
    };
    use std::sync::atomic::Ordering;

    use sovright_relay::test_support::{committed_header, parseable_transaction};
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

    /// A test header that actually commits to `txs`.
    ///
    /// Reconstruction verifies the header's merkle root, so filler bytes are
    /// now (correctly) rejected before any of these paths run. Committing
    /// properly keeps each test about the behaviour it names.
    fn header_committing_to(txs: &[Vec<u8>]) -> Vec<u8> {
        let mut header = vec![0xcd; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let txids: Vec<[u8; 32]> = txs
            .iter()
            .map(|t| sovright_relay::txid_from_tx_bytes(t))
            .collect();
        let root = sovright_relay::merkle_root(&txids).expect("tests commit to >=1 tx");
        header[36..68].copy_from_slice(&root);
        header
    }

    /// Block 3470793 with a transaction changed: still parses, new txid.
    fn bad_mainnet_transactions() -> Vec<Vec<u8>> {
        let mut txs = zcash_pool_common::fixtures::mainnet_transactions();
        txs[3][60] ^= 0x01;
        txs
    }

    fn mainnet_compact(txs: &[Vec<u8>]) -> CompactBlock {
        CompactBlock::new(
            zcash_pool_common::fixtures::mainnet_serialized_header(),
            0,
            Vec::new(),
            txs.iter()
                .map(|tx| PrefilledTx {
                    index: 0,
                    tx_data: tx.clone(),
                })
                .collect(),
        )
    }

    #[test]
    fn a_block_body_rejection_is_counted_by_reason() {
        let metrics = SidecarMetrics::default();

        log_submission_outcome(
            Err(RelayBlockError::InvalidBlockBody(
                BlockBodyError::MerkleMismatch,
            )),
            &metrics,
            None,
        );

        let text = metrics.render_prometheus_text();
        let name = "sovright_relay_sidecar_relay_block_body_rejected_total";
        assert!(text.contains(&format!("{name}{{reason=\"merkle_mismatch\"}} 1")));
        assert!(text.contains(&format!("{name}{{reason=\"duplicate_txid\"}} 0")));
    }

    /// A rejected body must not take the header's slot in the fast-path dedup,
    /// in dry-run or live mode.
    #[tokio::test]
    async fn a_bad_body_does_not_take_the_fast_path_slot() {
        for mode in [SubmitBlockMode::DryRun, SubmitBlockMode::Live] {
            let submitter = CountingSubmitter::default();
            let metrics = SidecarMetrics::default();
            let mut dedup = HashDedupRing::new(16, Duration::from_secs(60));
            let mempool = TestMempool::new();
            let now = Instant::now();

            for txs in [
                bad_mainnet_transactions(),
                zcash_pool_common::fixtures::mainnet_transactions(),
            ] {
                submit_compact_fast_path(
                    &submitter,
                    &mainnet_compact(&txs),
                    mode,
                    false,
                    &mempool,
                    &metrics,
                    &mut dedup,
                    now,
                    false,
                )
                .await;
            }

            assert_eq!(metrics.full_block_deduplicated.load(Ordering::Relaxed), 0);
            let good_calls = usize::from(matches!(mode, SubmitBlockMode::Live));
            assert_eq!(submitter.calls.load(Ordering::SeqCst), good_calls);
        }
    }

    /// Through the reassembly buffer: the bad body completes and is refused,
    /// then the good one completes and is submitted byte for byte.
    #[tokio::test]
    async fn reassembled_raw_bodies_are_validated() {
        let good = zcash_pool_common::fixtures::mainnet_raw_block();
        let mut bad = good.clone();
        let tx = bad_mainnet_transactions().swap_remove(3);
        let genuine = zcash_pool_common::fixtures::mainnet_transactions().swap_remove(3);
        let offset = good
            .windows(genuine.len())
            .position(|window| window == genuine.as_slice())
            .unwrap();
        bad[offset..offset + tx.len()].copy_from_slice(&tx);
        let hash = zcash_block_hash(&good[..ZCASH_FULL_HEADER_SIZE]);
        let submitter = CountingSubmitter::default();
        let mut buffer =
            RawSegmentBuffer::new(buffer_config(8, 1024 * 1024, Duration::from_secs(60)));
        let frame = RawBlockSegment::HEADER_LEN + 8 * 1024;

        for (raw, submitted) in [(&bad, 0), (&good, 1)] {
            let mut complete = None;
            for segment in sovright_relay::split_raw_block(hash, raw, frame).unwrap() {
                if let RawSegmentInsert::Complete { segments, .. } =
                    buffer.insert(segment, Instant::now())
                {
                    complete = Some(segments);
                }
            }
            let block = reassemble_raw_block(&complete.expect("all segments arrived")).unwrap();
            assert_eq!(&block, raw);
            let outcome =
                handle_relay_raw_block(&submitter, &block, Some(hash), SubmitBlockMode::Live).await;
            assert_eq!(outcome.is_ok(), submitted == 1);
            assert_eq!(submitter.calls.load(Ordering::SeqCst), submitted);
        }
    }

    fn buffer_config(
        max_incomplete_blocks: usize,
        max_total_payload_bytes: usize,
        ttl: Duration,
    ) -> RawSegmentBufferConfig {
        RawSegmentBufferConfig::new(max_incomplete_blocks, max_total_payload_bytes, ttl).unwrap()
    }

    #[test]
    fn raw_segment_rejects_unbounded_declarations_before_buffering() {
        for (raw_len, count) in [(u64::MAX, 1), (1025, 2), (2, u16::MAX)] {
            let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
            let mut segment = split_raw_block([1; 32], &[1], 1024).unwrap().remove(0);
            segment.raw_block_len = raw_len;
            segment.segment_count = count;
            assert!(
                matches!(
                    buffer.insert(segment, Instant::now()),
                    RawSegmentInsert::Dropped { .. }
                ),
                "admitted raw length {raw_len}, segment count {count}"
            );
            assert!(buffer.entries.is_empty());
            assert_eq!(buffer.total_payload_bytes, 0);
        }
    }

    #[test]
    fn raw_segment_slot_allocation_must_fit_aggregate_budget() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
        // Eight one-byte segments require more than 1KiB of resident slot metadata.
        let segments = split_raw_block([1; 32], &[1; 8], RawBlockSegment::HEADER_LEN + 1).unwrap();
        assert!(matches!(
            buffer.insert(segments[0].clone(), Instant::now()),
            RawSegmentInsert::Dropped { .. }
        ));
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
    }

    #[test]
    fn raw_segment_inconsistent_metadata_releases_existing_entry() {
        for change_digest in [false, true] {
            let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
            let mut segments =
                split_raw_block([1; 32], &[1, 2], RawBlockSegment::HEADER_LEN + 1).unwrap();
            assert!(matches!(
                buffer.insert(segments[0].clone(), Instant::now()),
                RawSegmentInsert::Pending
            ));
            if change_digest {
                segments[1].raw_block_digest[0] ^= 1;
            } else {
                segments[1].raw_block_len = 3;
            }
            assert!(matches!(
                buffer.insert(segments[1].clone(), Instant::now()),
                RawSegmentInsert::Dropped { .. }
            ));
            assert!(buffer.entries.is_empty());
            assert_eq!(buffer.total_payload_bytes, 0);
        }
    }

    #[test]
    fn raw_segment_aggregate_metadata_budget_boundary_and_cleanup() {
        let metadata = std::mem::size_of::<([u8; 32], RawSegmentEntry)>()
            + 2 * std::mem::size_of::<Option<RawBlockSegment>>();
        let budget = 2 * metadata + 4;
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, budget, Duration::from_secs(1)));
        let now = Instant::now();
        let sets: Vec<_> = (1..=3)
            .map(|seed| {
                split_raw_block([seed; 32], &[1, 2, 3, 4], RawBlockSegment::HEADER_LEN + 2).unwrap()
            })
            .collect();
        // Two entries plus two 2-byte payloads exactly fill the admission budget.
        for set in &sets[..2] {
            assert!(matches!(
                buffer.insert(set[0].clone(), now),
                RawSegmentInsert::Pending
            ));
        }
        assert!(matches!(
            buffer.insert(sets[2][0].clone(), now),
            RawSegmentInsert::Dropped { .. }
        ));
        assert_eq!(buffer.entries.len(), 2);
        // An existing entry exceeding the budget is removed and releases its slots too.
        assert!(matches!(
            buffer.insert(sets[0][1].clone(), now),
            RawSegmentInsert::Dropped { .. }
        ));
        assert!(matches!(
            buffer.insert(sets[1][1].clone(), now),
            RawSegmentInsert::Complete { .. }
        ));
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
        assert!(matches!(
            buffer.insert(sets[2][0].clone(), now),
            RawSegmentInsert::Pending
        ));
        assert_eq!(buffer.expire(now + Duration::from_secs(1)), 1);
        assert!(matches!(
            buffer.insert(sets[0][0].clone(), now),
            RawSegmentInsert::Pending
        ));
        assert!(matches!(
            buffer.insert(sets[1][0].clone(), now),
            RawSegmentInsert::Pending
        ));
    }

    #[test]
    fn raw_segment_rejects_payloads_exceeding_declared_length() {
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, 1024, Duration::from_secs(60)));
        let mut segments =
            split_raw_block([1; 32], &[1, 2, 3, 4], RawBlockSegment::HEADER_LEN + 2).unwrap();
        for segment in &mut segments {
            segment.raw_block_len = 3;
        }
        assert!(matches!(
            buffer.insert(segments[0].clone(), Instant::now()),
            RawSegmentInsert::Pending
        ));
        assert!(matches!(
            buffer.insert(segments[1].clone(), Instant::now()),
            RawSegmentInsert::Dropped { .. }
        ));
        assert!(buffer.entries.is_empty());
        assert_eq!(buffer.total_payload_bytes, 0);
    }

    #[tokio::test]
    async fn raw_segment_handler_survives_authenticated_short_object_then_valid_object() {
        use sovright_relay::{
            BlockChunker, Chunk, ChunkHeader, ClientConfig, RelayClient, RelaySession,
        };
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let key = [0x42; 32];
        let mut client = RelayClient::new(
            ClientConfig::new(vec![peer_addr], key)
                .with_bind_addr("127.0.0.1:0".parse().unwrap())
                .with_fec(2, 1),
        )
        .unwrap();
        client.bind().await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let (receiver, outgoing) = client.take_receiver().unwrap();
        let client_task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
        let rpc = Arc::new(ZebraRpc::new("http://127.0.0.1:1").await.unwrap());
        let submitter = Arc::new(DualSubmit::primary_only(Arc::clone(&rpc), "unused", None));
        let metrics = Arc::new(SidecarMetrics::default());
        let handler_task = spawn_relay_block_handler(
            receiver,
            rpc,
            submitter,
            SubmitBlockMode::DryRun,
            false,
            buffer_config(8, 65536, Duration::from_secs(60)),
            Arc::clone(&metrics),
            Arc::new(EmptyMempool),
            None,
            None,
            None,
            BoundTaskLimits::default(),
        );

        let valid = zcash_pool_common::fixtures::mainnet_raw_block();
        let valid_hash = zcash_block_hash(&valid[..ZCASH_FULL_HEADER_SIZE]);
        let chunker = BlockChunker::new(2, 1).unwrap();
        let session = RelaySession::new(peer_addr, "test", key);
        for (hash, raw) in [([1; 32], vec![1]), (valid_hash, valid)] {
            for segment in split_raw_block(hash, &raw, 2048).unwrap() {
                for chunk in chunker.raw_block_segment_to_chunks(&segment).unwrap() {
                    let h = &chunk.header;
                    let mac = session.compute_hmac(
                        &h.block_hash,
                        h.chunk_id,
                        h.total_chunks,
                        h.payload_len,
                        &chunk.payload,
                    );
                    let header = ChunkHeader::new_raw_block_segment_authenticated(
                        &h.block_hash,
                        h.chunk_id,
                        h.total_chunks,
                        h.payload_len,
                        mac,
                    );
                    peer.send_to(&Chunk::new(header, chunk.payload).to_bytes(), client_addr)
                        .await
                        .unwrap();
                }
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            while metrics.submit_dry_run_candidates.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        client_task.abort();
        let handler_result = tokio::time::timeout(Duration::from_secs(2), handler_task).await;
        assert!(
            result.is_ok(),
            "receive/submit task stopped before the valid object"
        );
        handler_result
            .expect("handler did not stop after receiver closed")
            .expect("handler panicked");
        assert_eq!(metrics.submit_dry_run_candidates.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.raw_segment_sets_completed.load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics
                .raw_segment_reassembly_failures
                .load(Ordering::Relaxed),
            1
        );
    }

    /// The real receive task, from UDP through the raw buffer to the decision, with
    /// a client whose chunks the test sends by hand.
    struct ReceiveTask {
        peer: tokio::net::UdpSocket,
        peer_addr: SocketAddr,
        client_addr: SocketAddr,
        client_task: tokio::task::JoinHandle<Result<(), sovright_relay::TransportError>>,
        handler_task: tokio::task::JoinHandle<()>,
        metrics: Arc<SidecarMetrics>,
    }

    const TEST_KEY: [u8; 32] = [0x42; 32];

    impl ReceiveTask {
        /// The gate is disabled, so the tests need no chain behind it; the lib tests
        /// cover its decisions.
        async fn start(
            zebra_url: &str,
            mode: SubmitBlockMode,
            unreadable_submit: Option<UnreadableSubmit>,
        ) -> Self {
            use sovright_relay::{ClientConfig, RelayClient};
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let mut client = RelayClient::new(
                ClientConfig::new(vec![peer_addr], TEST_KEY)
                    .with_bind_addr("127.0.0.1:0".parse().unwrap())
                    .with_fec(2, 1),
            )
            .unwrap();
            client.bind().await.unwrap();
            let client_addr = client.local_addr().unwrap();
            let (receiver, outgoing) = client.take_receiver().unwrap();
            let client_task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
            let rpc = Arc::new(ZebraRpc::new(zebra_url).await.unwrap());
            let submitter = Arc::new(DualSubmit::primary_only(Arc::clone(&rpc), "unused", None));
            let metrics = Arc::new(SidecarMetrics::default());
            let chain_view = ZebraChainView::new(ZebraChainViewConfig::default());
            let gate = Arc::new(TokioMutex::new(SubmitGate::new(
                Default::default(),
                Arc::clone(&chain_view),
            )));
            let handler_task = spawn_relay_block_handler(
                receiver,
                rpc,
                submitter,
                mode,
                false,
                buffer_config(8, 65536, Duration::from_secs(60)),
                Arc::clone(&metrics),
                Arc::new(EmptyMempool),
                Some(gate),
                Some(chain_view),
                unreadable_submit,
                BoundTaskLimits::default(),
            );
            Self {
                peer,
                peer_addr,
                client_addr,
                client_task,
                handler_task,
                metrics,
            }
        }

        async fn send(&self, raw: &[u8]) {
            use sovright_relay::{BlockChunker, Chunk, ChunkHeader, RelaySession};
            let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
            let chunker = BlockChunker::new(2, 1).unwrap();
            let session = RelaySession::new(self.peer_addr, "test", TEST_KEY);
            for segment in split_raw_block(hash, raw, 2048).unwrap() {
                for chunk in chunker.raw_block_segment_to_chunks(&segment).unwrap() {
                    let h = &chunk.header;
                    let mac = session.compute_hmac(
                        &h.block_hash,
                        h.chunk_id,
                        h.total_chunks,
                        h.payload_len,
                        &chunk.payload,
                    );
                    let header = ChunkHeader::new_raw_block_segment_authenticated(
                        &h.block_hash,
                        h.chunk_id,
                        h.total_chunks,
                        h.payload_len,
                        mac,
                    );
                    self.peer
                        .send_to(
                            &Chunk::new(header, chunk.payload).to_bytes(),
                            self.client_addr,
                        )
                        .await
                        .unwrap();
                }
            }
        }

        async fn wait_for(&self, what: &str, done: impl Fn(&SidecarMetrics) -> bool) {
            let settled = tokio::time::timeout(Duration::from_secs(5), async {
                while !done(&self.metrics) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await;
            assert!(settled.is_ok(), "{what} never happened");
        }

        fn stop(self) -> Arc<SidecarMetrics> {
            self.client_task.abort();
            self.handler_task.abort();
            self.metrics
        }
    }

    fn refused_as_unreadable(metrics: &SidecarMetrics) -> u64 {
        let index = BlockBodyError::Transaction { index: 0 }.kind_index();
        metrics.block_body_rejections[index].load(Ordering::Relaxed)
    }

    fn unreadable_block() -> Vec<u8> {
        let txs = zcash_pool_common::fixtures::mainnet_transactions();
        let mut unknown = 0x8000_0007u32.to_le_bytes().to_vec();
        unknown.extend_from_slice(&0x7a7a_7a7au32.to_le_bytes());
        unknown.resize(400, 0x5a);
        let mut raw = zcash_pool_common::fixtures::mainnet_serialized_header();
        raw.push(2);
        raw.extend_from_slice(&txs[0]);
        raw.extend_from_slice(&unknown);
        raw
    }

    #[tokio::test]
    async fn the_receive_task_refuses_an_unreadable_block_by_default() {
        let task = ReceiveTask::start("http://127.0.0.1:1", SubmitBlockMode::DryRun, None).await;

        task.send(&unreadable_block()).await;
        task.wait_for("the refusal", |metrics| refused_as_unreadable(metrics) == 1)
            .await;

        let metrics = task.stop();
        assert_eq!(metrics.submit_dry_run_candidates.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.block_body_unverified.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_receive_task_takes_an_unreadable_block_under_the_bypass() {
        let bypass = UnreadableSubmit::new(Duration::from_secs(5), 4);
        let task =
            ReceiveTask::start("http://127.0.0.1:1", SubmitBlockMode::DryRun, Some(bypass)).await;

        task.send(&unreadable_block()).await;
        task.wait_for("the dry run", |metrics| {
            metrics.submit_dry_run_candidates.load(Ordering::Relaxed) == 1
        })
        .await;

        let metrics = task.stop();
        assert_eq!(metrics.block_body_unverified.load(Ordering::Relaxed), 1);
        assert_eq!(refused_as_unreadable(&metrics), 0);
    }

    /// A Zebra that answers everything except this one body, which it never answers.
    async fn zebra_holding(held: String) -> (String, jsonrpsee::server::ServerHandle) {
        use jsonrpsee::server::{RpcModule, ServerBuilder};
        use jsonrpsee::types::ErrorObjectOwned;

        let mut module = RpcModule::new(held);
        module
            .register_async_method("submitblock", |params, held, _| async move {
                let (block_hex,): (String,) = params.parse()?;
                if block_hex == *held {
                    std::future::pending::<()>().await;
                }
                Ok::<Option<String>, ErrorObjectOwned>(None)
            })
            .unwrap();
        module
            .register_method("getblockheader", |_, _, _| {
                Err::<(), ErrorObjectOwned>(ErrorObjectOwned::owned(-5, "not found", None::<()>))
            })
            .unwrap();
        let server = ServerBuilder::default()
            .http_only()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (url, server.start(module))
    }

    /// The real receive task and real RPC client: while Zebra sits on the unverified
    /// body, the task reads the next block and gets it accepted.
    #[tokio::test]
    async fn the_receive_task_keeps_going_while_zebra_holds_an_unverified_body() {
        let held = unreadable_block();
        let (url, _zebra) = zebra_holding(hex::encode(&held)).await;
        let bypass = UnreadableSubmit::new(Duration::from_secs(30), 4);
        let task = ReceiveTask::start(&url, SubmitBlockMode::Live, Some(bypass)).await;

        task.send(&held).await;
        task.wait_for("the attempt", |metrics| {
            metrics.block_body_unverified.load(Ordering::Relaxed) == 1
        })
        .await;
        // Another header: a second body of this one would stop at the client, which is
        // the upstream limit and not what this shows.
        let txs = [parseable_transaction(9)];
        let mut valid = header_committing_to(&txs);
        valid.push(1);
        valid.extend_from_slice(&txs[0]);
        task.send(&valid).await;

        task.wait_for("the valid block", |metrics| {
            metrics.submit_successes.load(Ordering::Relaxed) == 1
        })
        .await;
        task.stop();
    }

    /// Attempts per block do not bound this, because each new header brings its own.
    #[tokio::test]
    async fn the_receive_task_runs_only_so_many_attempts_at_once() {
        let held = unreadable_block();
        let (url, _zebra) = zebra_holding(hex::encode(&held)).await;
        let bypass = UnreadableSubmit::new(Duration::from_secs(30), 1);
        let task = ReceiveTask::start(&url, SubmitBlockMode::Live, Some(bypass.clone())).await;
        let _running = Arc::clone(&bypass.running).acquire_owned().await.unwrap();

        task.send(&held).await;
        task.wait_for("the refusal", |metrics| {
            metrics
                .submit_gate_rejected_unverified_limit
                .load(Ordering::Relaxed)
                == 1
        })
        .await;

        let metrics = task.stop();
        assert_eq!(metrics.block_body_unverified.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_bypass_takes_its_limits_from_the_config_and_needs_the_gate() {
        let config = config::SubmitGateConfig {
            enabled: true,
            submit_unreadable_blocks: true,
            unreadable_attempts_per_block: 3,
            unreadable_submit_budget_secs: 7,
            ..Default::default()
        };

        let bypass = UnreadableSubmit::from_config(&config).expect("it is on");
        assert_eq!(bypass.budget, Duration::from_secs(7));
        assert_eq!(bypass.running.available_permits(), 3);

        for off in [
            config::SubmitGateConfig {
                enabled: false,
                ..config.clone()
            },
            config::SubmitGateConfig {
                submit_unreadable_blocks: false,
                ..config
            },
        ] {
            assert!(UnreadableSubmit::from_config(&off).is_none());
        }
    }

    #[test]
    fn the_bypass_has_its_own_metrics() {
        let metrics = SidecarMetrics::default();
        metrics.block_body_unverified.store(3, Ordering::Relaxed);
        metrics
            .unreadable_submit_enabled
            .store(true, Ordering::Relaxed);

        let text = metrics.render_prometheus_text();

        assert!(text.contains("sovright_relay_sidecar_relay_block_body_unverified_total 3\n"));
        assert!(text.contains("sovright_relay_sidecar_unreadable_block_submit_enabled 1\n"));
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

        let nonce = 9;
        let coinbase = parseable_transaction(1);
        let tx1 = parseable_transaction(2);
        let header = header_committing_to(&[coinbase.clone(), tx1.clone()]);
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

        let coinbase = parseable_transaction(1);
        let tx1 = parseable_transaction(2);
        let header = committed_header(0xcd, &[coinbase.clone(), tx1.clone()]);
        let nonce = 3;
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

        let coinbase = parseable_transaction(1);
        let tx1 = parseable_transaction(2);
        let header = committed_header(0xef, &[coinbase.clone(), tx1.clone()]);
        let nonce = 5;
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
        let nonce = 42;
        let coinbase_wtxid = make_wtxid(0x01);
        let tx1_wtxid = make_wtxid(0x02);
        let coinbase = parseable_transaction(1);
        let tx1 = parseable_transaction(2);
        let header = header_committing_to(&[coinbase.clone(), tx1.clone()]);
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
        // Leave five payload bytes after charging the two slots and map entry.
        let budget = std::mem::size_of::<([u8; 32], RawSegmentEntry)>()
            + 2 * std::mem::size_of::<Option<RawBlockSegment>>()
            + 5;
        let mut buffer = RawSegmentBuffer::new(buffer_config(8, budget, Duration::from_secs(60)));
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
        assert_eq!(classify_reconstruction_invalid("no such failure"), "other");
        assert_eq!(classify_reconstruction_invalid(""), "other");
    }

    /// The reconstructor verifies the header commitment, so this reason is now
    /// produced for real -- by a short-id collision or a stale mempool copy --
    /// and needs its own bucket instead of being swept into `other`.
    #[test]
    fn a_merkle_mismatch_gets_its_own_bucket() {
        let m = SidecarMetrics::default();
        record_compact_reconstruction_outcome(
            &Err(RelayBlockError::InvalidBlockBody(
                BlockBodyError::MerkleMismatch,
            )),
            &m,
        );
        assert_eq!(
            m.compact_reconstruction_invalids_merkle_mismatch
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            m.compact_reconstruction_invalids_other
                .load(Ordering::Relaxed),
            0,
            "a merkle mismatch must not also land in other"
        );
    }

    /// A repeated txid keeps the root, so nobody chasing short-id collisions from
    /// the mismatch counter should be sent after one.
    #[test]
    fn a_repeated_txid_gets_its_own_bucket_not_the_mismatch_one() {
        let m = SidecarMetrics::default();
        record_compact_reconstruction_outcome(
            &Err(RelayBlockError::InvalidBlockBody(
                BlockBodyError::DuplicateTxid { index: 6 },
            )),
            &m,
        );

        let text = m.render_prometheus_text();
        let invalids = "sovright_relay_sidecar_relay_compact_reconstruction_invalids_total";
        assert!(
            text.contains(&format!("{invalids}{{reason=\"duplicate_txid\"}} 1\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{invalids}{{reason=\"merkle_mismatch\"}} 0\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{invalids}{{reason=\"other\"}} 0\n")),
            "{text}"
        );
        assert_eq!(m.compact_reconstruction_invalids.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn other_body_failures_of_a_filled_block_land_in_other() {
        let m = SidecarMetrics::default();
        record_compact_reconstruction_outcome(
            &Err(RelayBlockError::InvalidBlockBody(
                BlockBodyError::Transaction { index: 2 },
            )),
            &m,
        );
        assert_eq!(
            m.compact_reconstruction_invalids_other
                .load(Ordering::Relaxed),
            1
        );
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
