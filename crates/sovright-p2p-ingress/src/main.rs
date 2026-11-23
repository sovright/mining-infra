// Tests set environment variables, which edition 2024 marks `unsafe`; the
// shipped binary must contain no unsafe code.
#![cfg_attr(not(test), forbid(unsafe_code))]

#[cfg(test)]
mod attribution_tests;
mod block;
mod coinbase;
mod config;
mod crawler;
mod error;
mod event;
#[cfg(test)]
mod fee_fields_tests;
mod hash;
mod metrics;
mod observation;
mod peer;
#[cfg(test)]
mod peer_loop_tests;
mod relay_bridge;
mod submitblock_rpc;
mod tx_cache;
mod tx_feed;
mod wire;
mod wtxid;
#[cfg(feature = "zakura-native")]
mod zakura_native;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use config::{Config, is_accepted_peer_addr, seed_socket};
use crawler::{Crawler, PeerOutcome};
use error::Result;
use event::EventSink;
use relay_bridge::RelayBridge;
use tx_cache::{TxCache, TxCacheConfig};
use tx_feed::TxFeedClient;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    // Fails when the source is enabled in a build without the feature, on a network
    // other than mainnet, or with a bootstrap peer Zakura could not read.
    #[cfg_attr(not(feature = "zakura-native"), allow(unused_variables))]
    let zakura_native_config = config::zakura_native_from_env(config.network)?;
    let events = EventSink::for_network(config.event_log.clone(), config.network)?;
    let observer = config
        .observation
        .clone()
        .map(observation::Observer::start)
        .transpose()?;
    let relay = RelayBridge::from_config(&config, events.clone()).await?;
    let tx_cache = config.tx_cache_enabled.then(|| {
        TxCache::new(TxCacheConfig {
            max_entries: config.tx_cache_max_entries,
            max_bytes: config.tx_cache_max_bytes,
            max_tx_bytes: config.tx_cache_max_tx_bytes,
        })
    });
    let _submitblock_rpc = match config.submitblock_rpc.clone() {
        Some(rpc_config) => {
            let relay = relay.clone().ok_or_else(|| {
                error::IngressError::Config(
                    "submitblock RPC requires configured relay peers and auth key".to_string(),
                )
            })?;
            Some(submitblock_rpc::start_submitblock_rpc(rpc_config, relay, tx_cache.clone()).await?)
        }
        None => None,
    };
    // Starts in its own task: the legacy peers below do not wait for it.
    #[cfg(feature = "zakura-native")]
    let native = start_zakura_native(zakura_native_config, &events, &relay, &tx_cache)?;
    let tx_feed = config.tx_feed_addr.map(TxFeedClient::new);
    let peers = discover_peers(&config).await;
    let crawler = Crawler::new(&config, peers);
    // One for the process: every connection skips blocks another already got.
    let received_blocks = peer::ReceivedBlocks::new(peer::RECEIVED_BLOCKS_CAPACITY);

    info!(
        network = config.network.name(),
        advertised_version = config.network.protocol_version(),
        forwarding_min_peer_version = config.forwarding_min_peer_version(),
        peers = crawler.known_len(),
        max_peers = config.max_peers,
        crawler_enabled = config.crawler_enabled,
        rotation_enabled = config.rotation_enabled,
        tx_cache_enabled = tx_cache.is_some(),
        tx_feed_enabled = tx_feed.is_some(),
        relay_compact_from_tx_cache = config.relay_compact_from_tx_cache,
        relay_raw_fallback_with_tx_cache = config.relay_raw_fallback_with_tx_cache,
        "starting P2P ingress"
    );
    // The legacy peers run as before; their outcome is main's result, unless an
    // enabled native source fails first.
    let legacy = async {
        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        loop {
            reap_finished(&mut handles).await;

            while handles.len() < config.max_peers {
                let Some(peer) = crawler.next_peer() else {
                    break;
                };
                handles.push(spawn_peer(
                    peer,
                    config.clone(),
                    events.clone(),
                    relay.clone(),
                    tx_cache.clone(),
                    tx_feed.clone(),
                    crawler.clone(),
                    observer.clone(),
                    received_blocks.clone(),
                ));
            }

            match peer_loop_step(handles.len(), crawler.queue_len(), config.crawler_enabled) {
                PeerLoopStep::Exhausted => break,
                PeerLoopStep::DrainRunning => {
                    for handle in handles.drain(..) {
                        let _ = handle.await;
                    }
                    if crawler.queue_len() == 0 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        return Err(peers_exhausted(&crawler));
                    }
                    // Rotation requeued a peer that dropped. Retry it after the
                    // drain interval like any other queued peer.
                    warn!(
                        queued = crawler.queue_len(),
                        "all peer tasks ended, retrying requeued peers"
                    );
                }
                PeerLoopStep::Wait => {}
            }

            tokio::time::sleep(config.crawler_drain_interval).await;
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        Err::<(), _>(peers_exhausted(&crawler))
    };

    #[cfg(feature = "zakura-native")]
    if let Some(native) = native {
        return zakura_native::run_with_native(legacy, native).await;
    }
    legacy.await
}

/// Spawns the native source's start when it is configured, and returns at once.
///
/// A configuration without a relay is an error here. A start that fails or takes
/// longer than `zakura_native::START_TIMEOUT` is reported by the returned runner,
/// and `main` then ends with that error: the operator asked for the source.
#[cfg(feature = "zakura-native")]
fn start_zakura_native(
    native: Option<config::ZakuraNativeConfig>,
    events: &EventSink,
    relay: &Option<RelayBridge>,
    tx_cache: &Option<TxCache>,
) -> Result<Option<zakura_native::NativeRunner>> {
    let Some(native) = native else {
        return Ok(None);
    };
    let relay = relay.clone().ok_or_else(|| {
        error::IngressError::Config(
            "SOVRIGHT_P2P_ZAKURA_ENABLED requires configured relay peers and auth key".to_string(),
        )
    })?;
    let relay = relay.logging_block_events(events.clone(), zakura_native::SOURCE);
    let events = events.clone();
    let tx_cache = tx_cache.clone();
    info!(
        bootstrap_peers = native.bootstrap_peers.len(),
        advert_queue = native.advert_queue,
        max_concurrent_fetches = native.max_concurrent_fetches,
        "Starting the Zakura native source"
    );
    Ok(Some(zakura_native::NativeRunner::spawn(
        async move {
            // `zakura_native_from_env` refuses every network but mainnet.
            zakura_native::start(
                &native,
                sovright_zakura_native::native::NativeNetwork::Mainnet,
                relay,
                tx_cache,
                events,
            )
            .await
        },
        zakura_native::START_TIMEOUT,
    )))
}

/// Next step of the legacy peer loop, after it has filled its free peer slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerLoopStep {
    /// No peer task is running and no peer is queued.
    Exhausted,
    /// Crawler off and nothing queued: wait for the running peer tasks, which
    /// rotation may requeue when they end.
    DrainRunning,
    /// Sleep for the drain interval, then fill the free slots again.
    Wait,
}

/// A queued peer never ends the loop. With rotation on, `release_peer` requeues
/// a peer that dropped, so a static peer list keeps reconnecting to a node that
/// restarts. With rotation off the queue only shrinks, and the process still
/// exits once the configured peers are used up.
fn peer_loop_step(running: usize, queued: usize, crawler_enabled: bool) -> PeerLoopStep {
    if running == 0 && queued == 0 {
        PeerLoopStep::Exhausted
    } else if !crawler_enabled && queued == 0 {
        PeerLoopStep::DrainRunning
    } else {
        PeerLoopStep::Wait
    }
}

/// The ingress reaches this only when no peer task is left and none can be
/// started. That is a failure of the daemon's one job, so it must not look like
/// a successful run: under a process supervisor an exit status of 0 is reported
/// as a normal completion, which hides the outage from anything watching.
fn peers_exhausted(crawler: &Crawler) -> error::IngressError {
    error::IngressError::PeersExhausted(format!(
        "no peer connection remains out of {} known peers",
        crawler.known_len()
    ))
}

#[allow(clippy::too_many_arguments)]
fn spawn_peer(
    peer: SocketAddr,
    config: Config,
    events: EventSink,
    relay: Option<RelayBridge>,
    tx_cache: Option<TxCache>,
    tx_feed: Option<TxFeedClient>,
    crawler: Crawler,
    observer: Option<observation::Observer>,
    received_blocks: peer::ReceivedBlocks,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let peer_text = peer.to_string();
        let peer_runtime = config.peer_runtime;
        let peer_score_error = config.peer_score_error;
        let result = if peer_runtime.is_zero() {
            peer::run_peer(
                peer,
                config,
                events.clone(),
                relay,
                tx_cache,
                tx_feed,
                crawler.clone(),
                observer,
                received_blocks,
            )
            .await
        } else {
            match tokio::time::timeout(
                peer_runtime,
                peer::run_peer(
                    peer,
                    config,
                    events.clone(),
                    relay,
                    tx_cache,
                    tx_feed,
                    crawler.clone(),
                    observer,
                    received_blocks,
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    if let Err(error) = crawler.release_peer(peer, PeerOutcome::Rotated, &events) {
                        warn!(peer = %peer_text, %error, "failed to requeue rotated peer");
                    }
                    return;
                }
            }
        };
        let outcome = match result {
            Ok(()) => PeerOutcome::Rotated,
            Err(error) => {
                let _ = events.p2p_peer_error(&peer_text, &error.to_string());
                let _ = crawler.score_peer(peer, peer_score_error, "peer_error", &events);
                warn!(peer = %peer_text, %error, "peer task exited");
                PeerOutcome::Errored
            }
        };
        if let Err(error) = crawler.release_peer(peer, outcome, &events) {
            warn!(peer = %peer_text, %error, "failed to release peer");
        }
    })
}

async fn reap_finished(handles: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < handles.len() {
        if handles[index].is_finished() {
            let handle = handles.swap_remove(index);
            let _ = handle.await;
        } else {
            index += 1;
        }
    }
}

async fn discover_peers(config: &Config) -> Vec<SocketAddr> {
    let mut peers = HashSet::new();
    peers.extend(config.peers.iter().copied().filter(|peer| {
        is_accepted_peer_addr(peer, config.accept_nonstandard_ports, config.network)
    }));

    for seed in &config.seeds {
        match lookup_host(seed_socket(seed, config.network)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if is_accepted_peer_addr(&addr, config.accept_nonstandard_ports, config.network)
                    {
                        peers.insert(addr);
                    }
                }
            }
            Err(error) => warn!(%seed, %error, "failed to resolve DNS seed"),
        }
    }

    peers.into_iter().collect()
}
