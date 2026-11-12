//! A stateless Zakura native peer: no header-sync driver and no chain database.
//!
//! Without a header-sync driver, `zakura-network` starts no block-sync reactor, so
//! the endpoint offers only discovery and legacy gossip. Over legacy gossip a peer
//! advertises new blocks by hash and serves their bodies on request.
//!
//! The endpoint is not limited to the configured peers: it dials them, but its
//! discovery also dials peers it learns of, and any peer may connect to it. Every
//! connected peer can advertise to it and can be asked for a body.

use std::{
    collections::HashSet,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use indexmap::IndexSet;
use tokio::{
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tower::{Service, ServiceExt, util::BoxCloneService};
use zakura_chain::{block, parameters::Network, serialization::ZcashSerialize};
use zakura_network::{
    BoxError, Config, InventoryResponse, P2pStack, PeerSource, Request, Response,
    zakura::{
        LegacyGossipSink, LegacyRequestAdapter, ZakuraConfig, ZakuraEndpoint,
        spawn_zakura_endpoint_with_services,
    },
};

/// A block hash in internal byte order. Its `Display` gives the usual reversed hex.
pub use zakura_chain::block::Hash as BlockHash;

/// The legacy-gossip inbound service an endpoint hands requests from peers to.
pub type Inbound = BoxCloneService<Request, Response, BoxError>;

/// A block advertisement received from a native peer.
#[derive(Clone, Debug)]
pub struct NativeAdvert {
    /// The advertised block hash.
    pub hash: block::Hash,
    /// The peer that advertised it.
    pub source: PeerSource,
}

/// Returns a config that runs only the native stack, with `bootstrap_peers` as its
/// bootstrap list.
///
/// `bootstrap_peers` replaces Zakura's built-in Mainnet list. Discovery may still
/// dial other peers, and inbound connections are accepted. `identity_dir` holds
/// the node key and the discovery sequence file.
pub fn stateless_config(
    network: Network,
    identity_dir: PathBuf,
    listen_addr: SocketAddr,
    bootstrap_peers: Vec<String>,
) -> Config {
    Config {
        network,
        p2p_stack: P2pStack::Zakura,
        identity_dir,
        zakura: ZakuraConfig {
            listen_addr: Some(listen_addr),
            bootstrap_peers,
            ..ZakuraConfig::default()
        },
        ..Config::default()
    }
}

/// Starts a native endpoint with no header-sync driver, answering peers through `inbound`.
pub async fn spawn_stateless_endpoint(
    config: &Config,
    inbound: Inbound,
) -> Result<ZakuraEndpoint, BoxError> {
    spawn_zakura_endpoint_with_services(
        config,
        move |supervisor, trace| {
            Arc::new(LegacyGossipSink::spawn_with_trace(
                inbound, supervisor, trace,
            )) as Arc<dyn zakura_network::zakura::Service>
        },
        None,
        Vec::new(),
    )
    .await?
    .ok_or_else(|| "the config does not run the native stack".into())
}

/// Returns an inbound service that passes native block advertisements to `adverts`.
///
/// It serves no inventory: block requests get a missing answer, and other requests
/// get `Nil`. A full `adverts` channel drops the advertisement and counts it in
/// `stats`.
///
/// A native advertisement is answered with an error even when it was queued. After
/// a successful answer the endpoint marks the hash seen for ten minutes, which
/// drops every later advertisement of it from any peer, and re-advertises the hash
/// to its other peers. This node cannot serve the block, and a failed fetch must
/// leave a later advertisement free to arrive. An instant error does neither: the
/// endpoint only logs it at debug level.
pub fn advert_inbound(adverts: mpsc::Sender<NativeAdvert>, stats: Arc<NativeStats>) -> Inbound {
    BoxCloneService::new(tower::service_fn(move |request: Request| {
        let adverts = adverts.clone();
        let stats = Arc::clone(&stats);
        async move {
            if let Request::AdvertiseBlock(advert, Some(source @ PeerSource::Zakura(_))) = &request
            {
                stats.adverts_received.fetch_add(1, Ordering::Relaxed);
                let queued = adverts.try_send(NativeAdvert {
                    hash: advert.hash,
                    source: source.clone(),
                });
                if queued.is_err() {
                    stats.adverts_dropped.fetch_add(1, Ordering::Relaxed);
                }
                return Err::<Response, BoxError>(ADVERT_NOT_SEEN.into());
            }
            Ok(missing_or_nil(&request))
        }
    }))
}

/// The error a native advertisement is answered with; see [`advert_inbound`].
pub const ADVERT_NOT_SEEN: &str =
    "advertisement taken without marking it seen: this node does not serve blocks";

/// Answers a block request with every hash missing, and anything else with `Nil`.
pub fn missing_or_nil(request: &Request) -> Response {
    match request {
        Request::BlocksByHash(hashes) | Request::BlocksByHashFrom { hashes, .. } => {
            Response::Blocks(
                hashes
                    .iter()
                    .copied()
                    .map(InventoryResponse::Missing)
                    .collect(),
            )
        }
        _ => Response::Nil,
    }
}

/// Fetches the advertised block and returns its serialized bytes.
///
/// `zakura-network` asks the advertising peer first and, if it answers missing or
/// fails, up to two other connected peers, inbound and discovered ones included. A
/// peer that answers missing is not penalised. A block that was not requested is
/// rejected and its sender disconnected; the hash check here repeats that check.
///
/// The response carries a decoded block, not the bytes the peer sent, so the bytes
/// returned here are a re-serialization.
pub async fn fetch_block(
    endpoint: &ZakuraEndpoint,
    advert: &NativeAdvert,
) -> Result<Vec<u8>, BoxError> {
    let mut requests = LegacyRequestAdapter::new(endpoint.supervisor());
    let response = requests
        .ready()
        .await?
        .call(Request::BlocksByHashFrom {
            hashes: IndexSet::from([advert.hash]),
            source: advert.source.clone(),
        })
        .await?;

    let Response::Blocks(blocks) = response else {
        return Err("the peer answered a block request with another response".into());
    };
    match blocks.into_iter().next() {
        Some(InventoryResponse::Available((block, _))) if block.hash() == advert.hash => {
            Ok(block.zcash_serialize_to_vec()?)
        }
        Some(InventoryResponse::Available((block, _))) => Err(format!(
            "the peer returned block {} for {}",
            block.hash(),
            advert.hash
        )
        .into()),
        Some(InventoryResponse::Missing(hash)) => {
            Err(format!("the peer is missing block {hash}").into())
        }
        None => Err("the peer returned no block".into()),
    }
}

/// Counts what the native source did.
#[derive(Debug, Default)]
pub struct NativeStats {
    /// Advertisements received from native peers.
    pub adverts_received: AtomicU64,
    /// Advertisements dropped because the queue was full.
    pub adverts_dropped: AtomicU64,
    /// Advertisements skipped because a fetch of the same hash was in flight.
    pub adverts_coalesced: AtomicU64,
    /// Fetches that returned the advertised block.
    pub fetches_ok: AtomicU64,
    /// Fetches that failed, timed out, or returned another block.
    pub fetches_failed: AtomicU64,
}

/// Bounds on the work the native source takes on.
#[derive(Clone, Copy, Debug)]
pub struct SourceLimits {
    /// Advertisements waiting for a fetch slot. Further ones are dropped.
    pub advert_queue: usize,
    /// Body requests running at once.
    pub max_concurrent_fetches: usize,
    /// Time allowed for one body request.
    pub fetch_timeout: Duration,
}

/// A block body fetched from a native peer.
#[derive(Clone, Debug)]
pub struct FetchedBlock {
    /// The advertised hash, which the body's own hash matched.
    pub hash: block::Hash,
    /// The peer that advertised and served the block.
    pub source: PeerSource,
    /// The serialized block.
    pub bytes: Vec<u8>,
}

/// Fetches advertised blocks and sends the bodies to `fetched`.
///
/// At most `limits.max_concurrent_fetches` fetches run at once, and one per hash:
/// an advertisement of a hash already in flight is skipped. One fetch asks the
/// advertising peer first and then other peers; see [`fetch_block`]. A hash leaves
/// the in-flight set when its fetch ends, whether it succeeded or not, so a failed
/// fetch does not block a later advertisement of the same hash. That also holds
/// after a success: a later advertisement fetches the block again, and only the
/// consumer's own dedup drops the copy. Each such copy costs a full body transfer.
/// `max_concurrent_fetches` bounds how many fetches run at once, not how many run
/// in total: nothing here limits how often one block is fetched again, because the
/// endpoint does not mark answered hashes seen (see [`advert_inbound`]). Returns
/// when `adverts` closes; the fetches still running are then aborted.
pub async fn run_fetcher<F, Fut>(
    mut adverts: mpsc::Receiver<NativeAdvert>,
    fetch: F,
    fetched: mpsc::Sender<FetchedBlock>,
    limits: SourceLimits,
    stats: Arc<NativeStats>,
) where
    F: Fn(NativeAdvert) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Vec<u8>, BoxError>> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(limits.max_concurrent_fetches));
    let in_flight = Arc::new(Mutex::new(HashSet::new()));
    let mut fetches = JoinSet::new();

    while let Some(advert) = adverts.recv().await {
        while fetches.try_join_next().is_some() {}

        if !lock(&in_flight).insert(advert.hash) {
            stats.adverts_coalesced.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("the fetch semaphore is never closed");

        let fetch = fetch.clone();
        let fetched = fetched.clone();
        let in_flight = Arc::clone(&in_flight);
        let stats = Arc::clone(&stats);
        fetches.spawn(async move {
            let hash = advert.hash;
            let source = advert.source.clone();
            match timeout(limits.fetch_timeout, fetch(advert)).await {
                Ok(Ok(bytes)) => {
                    stats.fetches_ok.fetch_add(1, Ordering::Relaxed);
                    let _ = fetched
                        .send(FetchedBlock {
                            hash,
                            source,
                            bytes,
                        })
                        .await;
                }
                Ok(Err(error)) => {
                    stats.fetches_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%hash, ?source, %error, "Zakura native block fetch failed");
                }
                Err(_) => {
                    stats.fetches_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%hash, ?source, "Zakura native block fetch timed out");
                }
            }
            lock(&in_flight).remove(&hash);
            drop(permit);
        });
    }
}

/// Nothing panics while holding these locks, but a poisoned one must not stop the
/// source either.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The Zcash network a native source joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeNetwork {
    /// Mainnet.
    Mainnet,
    /// The default public testnet.
    Testnet,
}

impl NativeNetwork {
    pub(crate) fn zakura(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::new_default_testnet(),
        }
    }
}

/// Settings for a native block source.
#[derive(Clone, Debug)]
pub struct NativeSourceConfig {
    /// The network to join.
    pub network: NativeNetwork,
    /// Holds the node key and discovery sequence file. Must not be a real node's
    /// identity directory.
    pub identity_dir: PathBuf,
    /// UDP address the endpoint binds.
    pub listen_addr: SocketAddr,
    /// The only peers dialed, as `node_id@ip:port`.
    pub bootstrap_peers: Vec<String>,
    /// Queue and concurrency bounds.
    pub limits: SourceLimits,
}

/// A running native block source: a stateless endpoint plus its fetcher.
///
/// Dropping it only aborts the fetcher. `ZakuraEndpoint` has no `Drop`, so the
/// endpoint keeps its connections and dial loops until [`Self::shutdown`] or the
/// end of the runtime.
pub struct NativeSource {
    endpoint: ZakuraEndpoint,
    stats: Arc<NativeStats>,
    fetcher: JoinHandle<()>,
}

impl NativeSource {
    /// Starts the endpoint and the fetcher. Fetched bodies arrive on the returned
    /// receiver.
    pub async fn start(
        config: NativeSourceConfig,
    ) -> Result<(Self, mpsc::Receiver<FetchedBlock>), BoxError> {
        let limits = config.limits;
        if limits.advert_queue == 0 || limits.max_concurrent_fetches == 0 {
            return Err("the advert queue and fetch concurrency must be at least 1".into());
        }
        let stats = Arc::new(NativeStats::default());
        let (advert_tx, advert_rx) = mpsc::channel(limits.advert_queue);
        let endpoint = spawn_stateless_endpoint(
            &stateless_config(
                config.network.zakura(),
                config.identity_dir,
                config.listen_addr,
                config.bootstrap_peers,
            ),
            advert_inbound(advert_tx, Arc::clone(&stats)),
        )
        .await?;

        let (fetched_tx, fetched_rx) = mpsc::channel(limits.max_concurrent_fetches);
        let fetch_endpoint = endpoint.clone();
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            move |advert: NativeAdvert| {
                let endpoint = fetch_endpoint.clone();
                async move { fetch_block(&endpoint, &advert).await }
            },
            fetched_tx,
            limits,
            Arc::clone(&stats),
        ));

        Ok((
            Self {
                endpoint,
                stats,
                fetcher,
            },
            fetched_rx,
        ))
    }

    /// The source's counters. They stay readable after [`Self::shutdown`].
    pub fn stats(&self) -> &Arc<NativeStats> {
        &self.stats
    }

    /// The underlying endpoint.
    pub fn endpoint(&self) -> &ZakuraEndpoint {
        &self.endpoint
    }

    /// Stops fetching, then shuts the endpoint down.
    ///
    /// The fetcher is aborted and awaited, which aborts the fetches in flight, so no
    /// fetch starts afterwards. `ZakuraEndpoint::shutdown` then stops the dial and
    /// discovery loops, closes every native connection and stops accepting new
    /// ones. Tasks that `zakura-network` spawns detached, such as the gossip sink's
    /// worker and the per-session readers, are not awaited: they end when their
    /// connection or their last input closes.
    pub async fn shutdown(mut self) {
        self.fetcher.abort();
        let _ = (&mut self.fetcher).await;
        self.endpoint.shutdown().await;
    }
}

impl Drop for NativeSource {
    fn drop(&mut self) {
        self.fetcher.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use tokio::sync::Notify;
    use zakura_network::zakura::ZakuraPeerId;

    use super::*;

    const STEP: Duration = Duration::from_secs(5);

    fn limits(advert_queue: usize, max_concurrent_fetches: usize) -> SourceLimits {
        SourceLimits {
            advert_queue,
            max_concurrent_fetches,
            fetch_timeout: Duration::from_secs(5),
        }
    }

    fn advert(byte: u8) -> NativeAdvert {
        NativeAdvert {
            hash: block::Hash([byte; 32]),
            source: PeerSource::Zakura(
                ZakuraPeerId::new([9u8; 32]).expect("32 bytes is a valid peer id"),
            ),
        }
    }

    async fn wait_for(counter: &AtomicU64, at_least: u64, what: &str) {
        timeout(STEP, async {
            while counter.load(Ordering::Relaxed) < at_least {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what} in time"));
    }

    #[tokio::test]
    async fn a_full_advert_queue_drops_and_counts() {
        let stats = Arc::new(NativeStats::default());
        let (tx, mut rx) = mpsc::channel(1);
        let mut inbound = advert_inbound(tx, Arc::clone(&stats));

        for byte in 1..=3 {
            let advert = advert(byte);
            let answer = inbound
                .ready()
                .await
                .expect("the inbound service is always ready")
                .call(Request::AdvertiseBlock(
                    advert.hash.into(),
                    Some(advert.source),
                ))
                .await
                .expect_err("a native advertisement is never marked seen");
            assert_eq!(answer.to_string(), ADVERT_NOT_SEEN);
        }

        assert_eq!(stats.adverts_received.load(Ordering::Relaxed), 3);
        assert_eq!(stats.adverts_dropped.load(Ordering::Relaxed), 2);
        assert_eq!(
            rx.try_recv().expect("one advert was queued").hash,
            advert(1).hash
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_hash_in_flight_is_fetched_once() {
        let stats = Arc::new(NativeStats::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let (advert_tx, advert_rx) = mpsc::channel(4);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(4);
        let fetch = {
            let calls = Arc::clone(&calls);
            let release = Arc::clone(&release);
            move |_advert: NativeAdvert| {
                let calls = Arc::clone(&calls);
                let release = Arc::clone(&release);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok::<_, BoxError>(vec![1, 2, 3])
                }
            }
        };
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            fetch,
            fetched_tx,
            limits(4, 4),
            Arc::clone(&stats),
        ));

        advert_tx
            .send(advert(1))
            .await
            .expect("the fetcher is running");
        advert_tx
            .send(advert(1))
            .await
            .expect("the fetcher is running");
        wait_for(
            &stats.adverts_coalesced,
            1,
            "the second advert is coalesced",
        )
        .await;
        release.notify_one();

        let fetched = timeout(STEP, fetched_rx.recv())
            .await
            .expect("the block is delivered in time")
            .expect("the fetched channel stays open");
        assert_eq!(fetched.bytes, vec![1, 2, 3]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fetcher.abort();
    }

    #[tokio::test]
    async fn a_failed_fetch_does_not_block_a_later_advert_of_the_same_hash() {
        let stats = Arc::new(NativeStats::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (advert_tx, advert_rx) = mpsc::channel(4);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(4);
        let fetch = {
            let calls = Arc::clone(&calls);
            move |_advert: NativeAdvert| {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        Err::<Vec<u8>, BoxError>("the peer is missing the block".into())
                    } else {
                        Ok(vec![4, 5, 6])
                    }
                }
            }
        };
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            fetch,
            fetched_tx,
            limits(4, 1),
            Arc::clone(&stats),
        ));

        advert_tx
            .send(advert(2))
            .await
            .expect("the fetcher is running");
        wait_for(&stats.fetches_failed, 1, "the first fetch fails").await;
        // The failed hash may still be leaving the in-flight set; resend until the
        // retry is accepted rather than coalesced.
        let fetched = timeout(STEP, async {
            loop {
                advert_tx
                    .send(advert(2))
                    .await
                    .expect("the fetcher is running");
                if let Ok(Some(block)) =
                    timeout(Duration::from_millis(100), fetched_rx.recv()).await
                {
                    return block;
                }
            }
        })
        .await
        .expect("the retry succeeds in time");
        assert_eq!(fetched.bytes, vec![4, 5, 6]);
        assert_eq!(stats.fetches_failed.load(Ordering::Relaxed), 1);
        // A resend still queued when the retry finished may start one more fetch.
        assert!(stats.fetches_ok.load(Ordering::Relaxed) >= 1);
        fetcher.abort();
    }
}
