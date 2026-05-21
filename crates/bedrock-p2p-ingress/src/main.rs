mod config;
mod error;
mod event;
mod forge;
mod hash;
mod peer;
mod wire;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use config::{Config, seed_socket};
use error::Result;
use event::EventSink;
use forge::ForgeBridge;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let events = EventSink::new(config.event_log.clone())?;
    let forge = ForgeBridge::from_config(&config).await?;
    let peers = discover_peers(&config).await;

    info!(
        peers = peers.len(),
        max_peers = config.max_peers,
        "starting P2P ingress"
    );
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    for peer in peers.into_iter().take(config.max_peers) {
        let cfg = config.clone();
        let sink = events.clone();
        let bridge = forge.clone();
        handles.push(tokio::spawn(async move {
            let peer_text = peer.to_string();
            let result = if cfg.peer_runtime.is_zero() {
                peer::run_peer(peer, cfg, sink.clone(), bridge).await
            } else {
                match tokio::time::timeout(
                    cfg.peer_runtime,
                    peer::run_peer(peer, cfg, sink.clone(), bridge),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Ok(()),
                }
            };
            if let Err(error) = result {
                let _ = sink.p2p_peer_error(&peer_text, &error.to_string());
                warn!(peer = %peer_text, %error, "peer task exited");
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(())
}

async fn discover_peers(config: &Config) -> Vec<SocketAddr> {
    let mut peers = HashSet::new();
    peers.extend(config.peers.iter().copied());

    for seed in &config.seeds {
        match lookup_host(seed_socket(seed)).await {
            Ok(addrs) => {
                for addr in addrs {
                    peers.insert(addr);
                }
            }
            Err(error) => warn!(%seed, %error, "failed to resolve DNS seed"),
        }
    }

    peers.into_iter().collect()
}
