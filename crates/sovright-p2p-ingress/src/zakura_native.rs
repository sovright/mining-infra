//! Zakura native peers as an extra block source (`zakura-native` feature).
//!
//! A body fetched from a native peer takes the same `RelayBridge::forward_block`
//! path as a block from a legacy peer: the same checks, the same parse permits and
//! the same dedup ring, which every clone of the bridge shares. A native failure
//! never reaches the legacy peers, and `main` stops the source when they end.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sovright_relay::{MAX_BLOCK_BYTES, ZCASH_FULL_HEADER_SIZE, consensus_block_hash_display};
use sovright_zakura_native::native::{
    FetchedBlock, NativeNetwork, NativeSource, NativeSourceConfig, NativeStats, SourceLimits,
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
/// checks and dedup state. The bridge keys that state by a header hash the
/// advertisement does not carry, so a block is fetched before the bridge can tell
/// it is a duplicate.
pub async fn start(
    config: &ZakuraNativeConfig,
    network: Network,
    relay: RelayBridge,
    tx_cache: Option<TxCache>,
    events: EventSink,
) -> Result<NativeIngress> {
    let (source, fetched) = NativeSource::start(NativeSourceConfig {
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
    })
    .await
    .map_err(|error| IngressError::ZakuraNative(error.to_string()))?;

    let forward_stats = Arc::new(ForwardStats::default());
    let forwarder = tokio::spawn(forward_fetched(
        fetched,
        relay,
        tx_cache,
        events,
        Arc::clone(&forward_stats),
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
/// Each block's delivery is dropped once its forward ends, however it ends; that
/// gives its body slot back and frees its hash and peer in the source.
///
/// Events are best effort, as for legacy peers: a write error is logged and the
/// block is still forwarded. Their hash fields mean what they mean for legacy
/// blocks (`peer.rs`): `hash` is the relay object hash, the join key between
/// the received and forwarded events, and `consensus_hash` is the chain's hash.
async fn forward_fetched(
    mut fetched: mpsc::Receiver<FetchedBlock>,
    relay: RelayBridge,
    tx_cache: Option<TxCache>,
    events: EventSink,
    stats: Arc<ForwardStats>,
) {
    while let Some(block) = fetched.recv().await {
        let FetchedBlock {
            source,
            bytes,
            delivery,
            ..
        } = block;
        let hash = raw_hash_from_header(&bytes)
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
