//! Zakura native peers as an extra block source (`zakura-native` feature).
//!
//! A body fetched from a native peer takes the same `RelayBridge::forward_block`
//! path as a block from a legacy peer: the same checks, the same parse permits and
//! the same dedup ring, which every clone of the bridge shares. A native failure
//! never reaches the legacy peers, and `main` stops the source when they end.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sovright_relay::{MAX_BLOCK_BYTES, ZCASH_FULL_HEADER_SIZE, consensus_block_hash_display};
use sovright_zakura_native::native::{
    BlockHash, DeliveredCheck, FetchedBlock, NativeNetwork, NativeSource, NativeSourceConfig,
    NativeStats, SourceLimits,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::ZakuraNativeConfig;
use crate::error::{IngressError, Result};
use crate::event::EventSink;
use crate::hash::{inventory_hash_to_display, raw_hash_from_header};
use crate::relay_bridge::{ForwardMode, RelayBridge};
use crate::tx_cache::TxCache;
use crate::wire::Network;

/// The peer name native blocks carry in events.
pub const SOURCE: &str = "zakura-native";

/// Native blocks remembered as delivered: at most this many.
///
/// This and [`RECENT_WINDOW`] are starting values that match the bridge's default
/// dedup ring (64 entries, 30 s). They have not been tuned in production.
pub const RECENT_CAPACITY: usize = 64;

/// How long a native block stays remembered as delivered, counted from the bridge's
/// own record of it; see [`RECENT_CAPACITY`].
pub const RECENT_WINDOW: Duration = Duration::from_secs(30);

/// What the bridge did with native blocks.
#[derive(Debug, Default)]
pub struct ForwardStats {
    /// Sent to the relay.
    pub forwarded: AtomicU64,
    /// Already sent, from either source, within the dedup window.
    pub deduplicated: AtomicU64,
    /// Refused by the bridge's checks, or lost to a relay error.
    pub failed: AtomicU64,
}

/// Native blocks the bridge holds a forward record for, by the hash their
/// advertisement carried.
///
/// The bridge keys its dedup ring by the relay object hash of the header, which an
/// advertisement does not carry, so this maps the advertised hash to it. An entry
/// is written only from the bridge's record (see [`RelayBridge::forwarded_at`]) and
/// keeps the bridge's record time. It is never refreshed: a repeated advertisement
/// does not extend it. It counts only while the bridge still holds the same record,
/// so it never outlasts the bridge's own dedup window or capacity.
#[derive(Debug)]
pub(crate) struct RecentNativeBlocks {
    capacity: usize,
    window: Duration,
    /// Advertised hash, relay object hash, the bridge's record time.
    entries: VecDeque<(BlockHash, [u8; 32], Instant)>,
}

impl RecentNativeBlocks {
    pub(crate) fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            entries: VecDeque::new(),
        }
    }

    fn expire(&mut self, now: Instant) {
        let window = self.window;
        self.entries
            .retain(|(_, _, recorded_at)| now.saturating_duration_since(*recorded_at) <= window);
    }

    /// Remembers `hash`, unless it is already remembered: an existing entry keeps
    /// its time.
    pub(crate) fn record(
        &mut self,
        hash: BlockHash,
        relay_hash: [u8; 32],
        recorded_at: Instant,
        now: Instant,
    ) {
        self.expire(now);
        if self.capacity == 0 || self.entries.iter().any(|(entry, _, _)| *entry == hash) {
            return;
        }
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((hash, relay_hash, recorded_at));
    }

    /// The relay object hash remembered for `hash`, inside the window.
    pub(crate) fn relay_hash(&mut self, hash: &BlockHash, now: Instant) -> Option<[u8; 32]> {
        self.expire(now);
        self.entries
            .iter()
            .find(|(entry, _, _)| entry == hash)
            .map(|(_, relay_hash, _)| *relay_hash)
    }

    /// The bridge record time remembered for `hash`, inside the window.
    #[cfg(test)]
    pub(crate) fn recorded_at(&mut self, hash: &BlockHash, now: Instant) -> Option<Instant> {
        self.expire(now);
        self.entries
            .iter()
            .find(|(entry, _, _)| entry == hash)
            .map(|(_, _, recorded_at)| *recorded_at)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The fetcher's check: a native block counts as delivered while it is remembered
/// and the bridge still holds its forward record.
pub(crate) fn delivered_check(
    recent: Arc<Mutex<RecentNativeBlocks>>,
    relay: RelayBridge,
) -> DeliveredCheck {
    Arc::new(move |hash| {
        let Some(relay_hash) = lock(&recent).relay_hash(hash, Instant::now()) else {
            return false;
        };
        relay.forwarded_at(&relay_hash).is_some()
    })
}

/// A running native source and the task that forwards its blocks.
///
/// Dropping it aborts the fetcher and the forwarder but leaves the endpoint
/// running. [`Self::shutdown`] also waits for both and shuts the endpoint down; see
/// `NativeSource::shutdown` for what that does and does not stop.
pub struct NativeIngress {
    source: NativeSource,
    forwarder: AbortOnDrop,
    forward_stats: Arc<ForwardStats>,
}

impl NativeIngress {
    /// The native source's counters. A clone stays readable after shutdown.
    pub fn source_stats(&self) -> &Arc<NativeStats> {
        self.source.stats()
    }

    /// The forwarder's counters. A clone stays readable after shutdown.
    pub fn forward_stats(&self) -> &Arc<ForwardStats> {
        &self.forward_stats
    }

    /// Logs the counters, stops fetching and forwarding, and closes the native
    /// connections.
    pub async fn shutdown(mut self) {
        let source = self.source_stats();
        let forward = self.forward_stats();
        info!(
            adverts_received = source.adverts_received.load(Ordering::Relaxed),
            adverts_dropped = source.adverts_dropped.load(Ordering::Relaxed),
            adverts_coalesced = source.adverts_coalesced.load(Ordering::Relaxed),
            adverts_delivered = source.adverts_delivered.load(Ordering::Relaxed),
            adverts_source_busy = source.adverts_source_busy.load(Ordering::Relaxed),
            fetches_ok = source.fetches_ok.load(Ordering::Relaxed),
            fetches_failed = source.fetches_failed.load(Ordering::Relaxed),
            forwarded = forward.forwarded.load(Ordering::Relaxed),
            deduplicated = forward.deduplicated.load(Ordering::Relaxed),
            forward_failed = forward.failed.load(Ordering::Relaxed),
            "Stopping the Zakura native source"
        );
        self.source.shutdown().await;
        self.forwarder.0.abort();
        let _ = (&mut self.forwarder.0).await;
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts the native source and forwards what it fetches through `relay`.
///
/// `relay` is a clone of the bridge the legacy peers use, so both sources share its
/// checks and dedup state.
pub async fn start(
    config: &ZakuraNativeConfig,
    network: Network,
    relay: RelayBridge,
    tx_cache: Option<TxCache>,
    events: EventSink,
) -> Result<NativeIngress> {
    let recent = Arc::new(Mutex::new(RecentNativeBlocks::new(
        RECENT_CAPACITY,
        RECENT_WINDOW,
    )));
    let (source, fetched) = NativeSource::start(
        NativeSourceConfig {
            network: native_network(network),
            identity_dir: config.identity_dir.clone(),
            listen_addr: config.listen_addr,
            bootstrap_peers: config.bootstrap_peers.clone(),
            limits: SourceLimits {
                advert_queue: config.advert_queue,
                max_concurrent_fetches: config.max_concurrent_fetches,
                fetch_timeout: config.fetch_timeout,
                max_body_bytes: MAX_BLOCK_BYTES,
            },
        },
        delivered_check(Arc::clone(&recent), relay.clone()),
    )
    .await
    .map_err(|error| IngressError::ZakuraNative(error.to_string()))?;

    let forward_stats = Arc::new(ForwardStats::default());
    let forwarder = tokio::spawn(forward_fetched(
        fetched,
        relay,
        tx_cache,
        events,
        Arc::clone(&forward_stats),
        recent,
    ));
    Ok(NativeIngress {
        source,
        forwarder: AbortOnDrop(forwarder),
        forward_stats,
    })
}

fn native_network(network: Network) -> NativeNetwork {
    match network {
        Network::Mainnet => NativeNetwork::Mainnet,
        Network::Testnet => NativeNetwork::Testnet,
    }
}

/// Forwards each fetched block, one at a time, until the source closes.
///
/// After a successful forward, the block is remembered as delivered if the bridge
/// now holds a forward record for its header. The bridge writes that record only
/// for a validated copy whose send finished, its own or another source's, so a
/// refused body, a failed or cancelled send, and a body sent under the emergency
/// bypass leave nothing to remember, whatever mode the forward reported. The record
/// is the bridge's local state: it does not say a relay peer received the block or
/// a node accepted it.
///
/// The block's delivery is dropped only after that, so its hash never leaves the
/// source's in-progress set before it is remembered. A cancelled or panicking
/// forward drops the delivery without remembering anything.
///
/// Events are best effort, as for legacy peers: a write error is logged and the
/// block is still forwarded. Their hash fields mean what they mean for legacy
/// blocks (`peer.rs`): `hash` is the relay object hash, the join key between
/// the received and forwarded events, and `consensus_hash` is the chain's hash.
pub(crate) async fn forward_fetched(
    mut fetched: mpsc::Receiver<FetchedBlock>,
    relay: RelayBridge,
    tx_cache: Option<TxCache>,
    events: EventSink,
    stats: Arc<ForwardStats>,
    recent: Arc<Mutex<RecentNativeBlocks>>,
) {
    while let Some(block) = fetched.recv().await {
        let FetchedBlock {
            hash: advertised,
            source,
            bytes,
            delivery,
        } = block;
        let relay_hash = raw_hash_from_header(&bytes).ok();
        let hash = relay_hash
            .map(|raw| inventory_hash_to_display(&raw))
            .unwrap_or_default();
        let consensus_hash = bytes
            .get(..ZCASH_FULL_HEADER_SIZE)
            .map(consensus_block_hash_display)
            .unwrap_or_default();
        let size = bytes.len();
        log_event(events.p2p_block_received(SOURCE, &hash, &consensus_hash, size));

        match relay.forward_block(&bytes, tx_cache.as_ref()).await {
            Ok(forwarded) => {
                let counter = if forwarded.mode == ForwardMode::Deduplicated {
                    &stats.deduplicated
                } else {
                    &stats.forwarded
                };
                counter.fetch_add(1, Ordering::Relaxed);
                if let Some(relay_hash) = relay_hash
                    && let Some(recorded_at) = relay.forwarded_at(&relay_hash)
                {
                    lock(&recent).record(advertised, relay_hash, recorded_at, Instant::now());
                }
                log_event(events.p2p_relay_block_forwarded(
                    SOURCE,
                    &hash,
                    forwarded.bytes,
                    forwarded.tx_count,
                    forwarded.mode.as_str(),
                    forwarded.relay_objects,
                ));
            }
            Err(error) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                warn!(
                    %consensus_hash,
                    ?source,
                    %error,
                    "Zakura native block forward failed"
                );
                if let IngressError::InvalidBlockBody(rejection) = &error {
                    log_event(events.p2p_block_body_rejected(
                        SOURCE,
                        &hash,
                        &consensus_hash,
                        rejection,
                        size,
                    ));
                }
                log_event(events.p2p_peer_error(SOURCE, &format!("relay forward failed: {error}")));
            }
        }
        drop(delivery);
    }
}

fn log_event(written: Result<()>) {
    if let Err(error) = written {
        warn!(%error, "Failed to write a Zakura native block event");
    }
}
