mod block;
mod coinbase;
mod config;
mod crawler;
mod error;
mod event;
mod hash;
mod peer;
mod relay_bridge;
mod tx_cache;
mod tx_feed;
mod wire;
mod wtxid;

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
    let events = EventSink::new(config.event_log.clone())?;
    let relay = RelayBridge::from_config(&config).await?;
    let tx_cache = config.tx_cache_enabled.then(|| {
        TxCache::new(TxCacheConfig {
            max_entries: config.tx_cache_max_entries,
            max_bytes: config.tx_cache_max_bytes,
            max_tx_bytes: config.tx_cache_max_tx_bytes,
        })
    });
    let tx_feed = config.tx_feed_addr.map(TxFeedClient::new);
    let peers = discover_peers(&config).await;
    let crawler = Crawler::new(&config, peers);

    info!(
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
            ));
        }

        if handles.is_empty() && (!config.crawler_enabled || crawler.queue_len() == 0) {
            break;
        }

        if !config.crawler_enabled && crawler.queue_len() == 0 {
            for handle in handles {
                let _ = handle.await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            return Ok(());
        }

        tokio::time::sleep(config.crawler_drain_interval).await;
    }

    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(())
}

fn spawn_peer(
    peer: SocketAddr,
    config: Config,
    events: EventSink,
    relay: Option<RelayBridge>,
    tx_cache: Option<TxCache>,
    tx_feed: Option<TxFeedClient>,
    crawler: Crawler,
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
    peers.extend(
        config
            .peers
            .iter()
            .copied()
            .filter(|peer| is_accepted_peer_addr(peer, config.accept_nonstandard_ports)),
    );

    for seed in &config.seeds {
        match lookup_host(seed_socket(seed)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if is_accepted_peer_addr(&addr, config.accept_nonstandard_ports) {
                        peers.insert(addr);
                    }
                }
            }
            Err(error) => warn!(%seed, %error, "failed to resolve DNS seed"),
        }
    }

    peers.into_iter().collect()
}
