//! A fake Zakura native peer for tests.
//!
//! It runs the real `zakura-network` endpoint, but its behaviour is ours: it
//! advertises only when told to, serves what `serve` returns, and has no chain
//! state. Passing a test against it says nothing about compatibility with stock
//! zakurad.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tempfile::TempDir;
use tokio::time::timeout;
use tower::{Service, ServiceExt, util::BoxCloneService};
use zakura_chain::{
    block::{self, Block},
    serialization::ZcashDeserializeInto,
};
use zakura_network::{
    AdvertisedBlock, BoxError, InventoryResponse, Request, Response,
    zakura::{LegacyGossipAdapter, ZakuraEndpoint},
};

use crate::native::{
    Inbound, NativeNetwork, missing_or_nil, spawn_stateless_endpoint, stateless_config,
};

/// Chooses the block the fake peer returns for a requested hash.
pub type Serve = Arc<dyn Fn(&block::Hash) -> Option<Arc<Block>> + Send + Sync>;

/// Parses serialized block bytes.
pub fn block_from_bytes(bytes: &[u8]) -> Result<Arc<Block>, BoxError> {
    Ok(Arc::new(bytes.zcash_deserialize_into()?))
}

/// Serves `block` for its own hash and nothing else.
pub fn serve_block(block: Arc<Block>) -> Serve {
    Arc::new(move |hash| (*hash == block.hash()).then(|| Arc::clone(&block)))
}

/// Serves nothing: every request is answered missing.
pub fn serve_nothing() -> Serve {
    Arc::new(|_| None)
}

/// Serves `block` for its own hash while `enabled` is set, and nothing else.
pub fn serve_block_when(block: Arc<Block>, enabled: Arc<AtomicBool>) -> Serve {
    Arc::new(move |hash| {
        (enabled.load(Ordering::SeqCst) && *hash == block.hash()).then(|| Arc::clone(&block))
    })
}

/// Serves `block` for any requested hash: a misbehaving peer.
pub fn serve_for_any_hash(block: Arc<Block>) -> Serve {
    Arc::new(move |_| Some(Arc::clone(&block)))
}

/// A fake native peer on 127.0.0.1 with no bootstrap peers.
pub struct FakePeer {
    endpoint: ZakuraEndpoint,
    adverts: Arc<AtomicU64>,
    block_requests: Arc<AtomicU64>,
    _identity: TempDir,
}

impl FakePeer {
    /// Starts the fake peer.
    pub async fn spawn(network: NativeNetwork, serve: Serve) -> Result<Self, BoxError> {
        let identity = tempfile::tempdir()?;
        let listen: SocketAddr = "127.0.0.1:0".parse()?;
        let adverts = Arc::new(AtomicU64::new(0));
        let block_requests = Arc::new(AtomicU64::new(0));
        let endpoint = spawn_stateless_endpoint(
            &stateless_config(network.zakura(), identity.path().into(), listen, Vec::new()),
            inbound(serve, Arc::clone(&adverts), Arc::clone(&block_requests)),
        )
        .await?;
        Ok(Self {
            endpoint,
            adverts,
            block_requests,
            _identity: identity,
        })
    }

    /// The `node_id@ip:port` a source uses to dial this peer.
    pub async fn bootstrap_addr(&self) -> Result<String, BoxError> {
        let addr = self.endpoint.node_addr().await;
        let socket = addr
            .direct
            .iter()
            .find(|socket| socket.ip().is_loopback() && socket.port() != 0)
            .ok_or("the fake peer has no loopback address")?;
        Ok(format!("{}@{socket}", addr.id))
    }

    /// Waits until some peer has connected.
    pub async fn wait_for_peer(&self, within: Duration) -> Result<(), BoxError> {
        let mut peers = self.endpoint.supervisor().subscribe();
        timeout(within, async {
            while peers.borrow_and_update().is_empty() {
                peers.changed().await?;
            }
            Ok::<_, BoxError>(())
        })
        .await
        .map_err(|_| "no peer connected in time")?
    }

    /// Advertises `hash` to connected peers, and to peers that connect later.
    pub async fn advertise(&self, hash: block::Hash, size: usize) -> Result<(), BoxError> {
        LegacyGossipAdapter::new(self.endpoint.supervisor())
            .ready()
            .await?
            .call(Request::AdvertiseBlock(
                AdvertisedBlock::new(hash, size),
                None,
            ))
            .await?;
        Ok(())
    }

    /// Block advertisements this peer received from its peers.
    pub fn adverts_received(&self) -> u64 {
        self.adverts.load(Ordering::Relaxed)
    }

    /// Block requests this peer received, retries included.
    pub fn block_requests_received(&self) -> u64 {
        self.block_requests.load(Ordering::Relaxed)
    }

    /// The underlying endpoint.
    pub fn endpoint(&self) -> &ZakuraEndpoint {
        &self.endpoint
    }
}

fn inbound(serve: Serve, adverts: Arc<AtomicU64>, block_requests: Arc<AtomicU64>) -> Inbound {
    BoxCloneService::new(tower::service_fn(move |request: Request| {
        let serve = Arc::clone(&serve);
        let adverts = Arc::clone(&adverts);
        let block_requests = Arc::clone(&block_requests);
        async move {
            match request {
                Request::AdvertiseBlock(..) => {
                    adverts.fetch_add(1, Ordering::Relaxed);
                }
                Request::BlocksByHash(_) | Request::BlocksByHashFrom { .. } => {
                    block_requests.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
            let response = match &request {
                Request::BlocksByHash(hashes) | Request::BlocksByHashFrom { hashes, .. } => {
                    Response::Blocks(
                        hashes
                            .iter()
                            .map(|hash| match serve(hash) {
                                Some(block) => InventoryResponse::Available((block.into(), None)),
                                None => InventoryResponse::Missing(*hash),
                            })
                            .collect(),
                    )
                }
                _ => missing_or_nil(&request),
            };
            Ok::<_, BoxError>(response)
        }
    }))
}
