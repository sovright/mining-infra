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
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
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
/// Every block advertisement is answered with an error, whatever its source, and
/// only one from an authenticated native peer is queued. After a successful answer
/// the endpoint marks the hash seen for ten minutes, which drops every later
/// advertisement of it from any peer, and re-advertises the hash to its other
/// peers. This node cannot serve the block, and a failed fetch must leave a later
/// advertisement free to arrive. An instant error does neither: the endpoint only
/// logs it at debug level.
///
/// In `zakura-network` 15.0.0 the gossip sink builds every advertisement with a
/// native source, so the other case is not expected; it is refused all the same.
pub fn advert_inbound(adverts: mpsc::Sender<NativeAdvert>, stats: Arc<NativeStats>) -> Inbound {
    BoxCloneService::new(tower::service_fn(move |request: Request| {
        let adverts = adverts.clone();
        let stats = Arc::clone(&stats);
        async move {
            let Request::AdvertiseBlock(advert, source) = &request else {
                return Ok(missing_or_nil(&request));
            };
            if let Some(source @ PeerSource::Zakura(_)) = source {
                stats.adverts_received.fetch_add(1, Ordering::Relaxed);
                let queued = adverts.try_send(NativeAdvert {
                    hash: advert.hash,
                    source: source.clone(),
                });
                if queued.is_err() {
                    stats.adverts_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err::<Response, BoxError>(ADVERT_NOT_SEEN.into())
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
/// returned here are a re-serialization. The decoded block and this serialization
/// both exist in memory before [`run_fetcher`] checks the size.
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
    /// Advertisements skipped because the same hash was being fetched or delivered.
    pub adverts_coalesced: AtomicU64,
    /// Advertisements skipped because their source already had a block in progress.
    pub adverts_source_busy: AtomicU64,
    /// Fetches that returned the advertised block within the size limit.
    pub fetches_ok: AtomicU64,
    /// Fetches that failed, timed out, returned another block, or returned a body
    /// over the size limit.
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
    /// The largest serialized body kept after a fetch. A larger one is dropped and
    /// counted as a failed fetch.
    pub max_body_bytes: usize,
}

impl SourceLimits {
    /// Bodies the source holds at once, counted from the start of their fetch until
    /// the consumer drops their [`Delivery`]: twice the fetch concurrency. That
    /// covers bodies being fetched, fetched bodies not yet taken from the channel,
    /// and the one the consumer is working on.
    pub fn body_slots(&self) -> usize {
        self.max_concurrent_fetches.saturating_mul(2)
    }
}

/// A block body fetched from a native peer.
#[derive(Debug)]
pub struct FetchedBlock {
    /// The advertised hash, which the body's own hash matched.
    pub hash: block::Hash,
    /// The peer that advertised the block. Another peer may have served it.
    pub source: PeerSource,
    /// The serialized block.
    pub bytes: Vec<u8>,
    /// This block's place in the source. Drop it once the block is dealt with.
    pub delivery: Delivery,
}

/// What a block in progress holds, from the decision to fetch it until it is dealt
/// with: its hash stays in flight, so a later advertisement of it is coalesced, and
/// its source counts as busy.
#[derive(Default)]
struct InProgress {
    hashes: HashSet<block::Hash>,
    sources: HashSet<PeerSource>,
}

/// Gives a block's in-progress entries back when dropped, however its fetch or its
/// delivery ends.
struct Reservation {
    in_progress: Arc<Mutex<InProgress>>,
    hash: block::Hash,
    source: PeerSource,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // This can run while unwinding, so a poisoned lock must not panic here.
        let mut in_progress = lock(&self.in_progress);
        in_progress.hashes.remove(&self.hash);
        in_progress.sources.remove(&self.source);
    }
}

/// A fetched block's place in the source: one body slot, its hash in flight and its
/// source busy.
///
/// Dropping it gives all three back, whether the consumer forwarded the block,
/// failed, was cancelled or panicked.
pub struct Delivery {
    reservation: Reservation,
    _slot: OwnedSemaphorePermit,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery")
            .field("hash", &self.reservation.hash)
            .finish_non_exhaustive()
    }
}

/// Fetches advertised blocks and sends the bodies to `fetched`.
///
/// Each advertisement is decided under one lock, in this order:
/// - its hash is in progress (being fetched, queued or with the consumer): skipped
///   as coalesced;
/// - its source already has a block in progress: skipped, so one peer holds at most
///   one body slot and one fetch at a time and its later advertisements wait on
///   nothing;
/// - otherwise it takes a body slot and then a fetch permit, waiting for them.
///
/// The fetch permit is held only while the request runs: the body then moves to
/// `fetched` with its [`Delivery`], which holds the body slot. At most
/// `limits.max_concurrent_fetches` fetches run at once, and at most
/// [`SourceLimits::body_slots`] bodies exist at once, so `fetched` needs no more
/// room than that and sending to it never waits for the consumer.
///
/// While every slot or permit is taken, this loop waits and the advertisement queue
/// fills; further advertisements are dropped at the queue. One peer cannot cause
/// that alone, but many peer identities can.
///
/// A failed fetch frees its hash and its source at once, so a later advertisement
/// fetches again. So does a delivery the consumer drops after a successful fetch:
/// nothing here records delivered blocks, so a later advertisement of one fetches
/// it again. Returns when `adverts` closes; the fetches still running are then
/// aborted.
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
    let fetch_permits = Arc::new(Semaphore::new(limits.max_concurrent_fetches));
    let body_slots = Arc::new(Semaphore::new(limits.body_slots()));
    let in_progress = Arc::new(Mutex::new(InProgress::default()));
    let mut fetches = JoinSet::new();

    while let Some(advert) = adverts.recv().await {
        while fetches.try_join_next().is_some() {}

        let reservation = {
            let mut entries = lock(&in_progress);
            if entries.hashes.contains(&advert.hash) {
                stats.adverts_coalesced.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if entries.sources.contains(&advert.source) {
                stats.adverts_source_busy.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            entries.hashes.insert(advert.hash);
            entries.sources.insert(advert.source.clone());
            Reservation {
                in_progress: Arc::clone(&in_progress),
                hash: advert.hash,
                source: advert.source.clone(),
            }
        };
        let slot = Arc::clone(&body_slots)
            .acquire_owned()
            .await
            .expect("the body slots are never closed");
        let permit = Arc::clone(&fetch_permits)
            .acquire_owned()
            .await
            .expect("the fetch permits are never closed");

        let fetch = fetch.clone();
        let fetched = fetched.clone();
        let stats = Arc::clone(&stats);
        fetches.spawn(async move {
            let hash = advert.hash;
            let source = advert.source.clone();
            let outcome = timeout(limits.fetch_timeout, fetch(advert)).await;
            drop(permit);
            match outcome {
                Ok(Ok(bytes)) if bytes.len() > limits.max_body_bytes => {
                    stats.fetches_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        %hash,
                        ?source,
                        bytes = bytes.len(),
                        max_body_bytes = limits.max_body_bytes,
                        "Zakura native block body over the size limit"
                    );
                }
                Ok(Ok(bytes)) => {
                    stats.fetches_ok.fetch_add(1, Ordering::Relaxed);
                    // Never waits: `fetched` has room for every body slot. If the
                    // consumer is gone, the block and its delivery drop here.
                    let _ = fetched
                        .send(FetchedBlock {
                            hash,
                            source,
                            bytes,
                            delivery: Delivery {
                                reservation,
                                _slot: slot,
                            },
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
    /// Peers dialed at start, as `node_id@ip:port`. They are not the only peers:
    /// discovery may dial others and any peer may connect; see the module docs.
    pub bootstrap_peers: Vec<String>,
    /// Queue, concurrency and size bounds.
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
        if limits.max_body_bytes == 0 {
            return Err("the body size limit must be at least 1 byte".into());
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

        let (fetched_tx, fetched_rx) = mpsc::channel(limits.body_slots());
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
            max_body_bytes: 2_000_000,
        }
    }

    fn peer(byte: u8) -> PeerSource {
        PeerSource::Zakura(ZakuraPeerId::new([byte; 32]).expect("32 bytes is a valid peer id"))
    }

    fn advert(byte: u8) -> NativeAdvert {
        advert_from(byte, 9)
    }

    fn advert_from(byte: u8, source: u8) -> NativeAdvert {
        NativeAdvert {
            hash: block::Hash([byte; 32]),
            source: peer(source),
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

    async fn wait_for_calls(calls: &AtomicUsize, at_least: usize, what: &str) {
        timeout(STEP, async {
            while calls.load(Ordering::SeqCst) < at_least {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what} in time"));
    }

    /// Gives the fetcher time to act on what it was sent, for a check that it did
    /// not start something.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    async fn advertise(inbound: &mut Inbound, request: Request) -> BoxError {
        inbound
            .ready()
            .await
            .expect("the inbound service is always ready")
            .call(request)
            .await
            .expect_err("a block advertisement is never marked seen")
    }

    /// A fetch that counts its calls and returns `bytes`.
    fn counting_fetch(
        calls: Arc<AtomicUsize>,
        bytes: Vec<u8>,
    ) -> impl Fn(NativeAdvert) -> std::future::Ready<Result<Vec<u8>, BoxError>> + Clone {
        move |_advert: NativeAdvert| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(bytes.clone()))
        }
    }

    #[tokio::test]
    async fn a_full_advert_queue_drops_and_counts() {
        let stats = Arc::new(NativeStats::default());
        let (tx, mut rx) = mpsc::channel(1);
        let mut inbound = advert_inbound(tx, Arc::clone(&stats));

        for byte in 1..=3 {
            let advert = advert(byte);
            let answer = advertise(
                &mut inbound,
                Request::AdvertiseBlock(advert.hash.into(), Some(advert.source)),
            )
            .await;
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

    /// Review finding 3: an advertisement without a native source gets the same
    /// error, never the success answer, and is not queued.
    #[tokio::test]
    async fn a_non_native_or_unsourced_advert_is_refused_and_not_queued() {
        let stats = Arc::new(NativeStats::default());
        let (tx, mut rx) = mpsc::channel(4);
        let mut inbound = advert_inbound(tx, Arc::clone(&stats));
        let hash = block::Hash([7; 32]);
        let legacy = PeerSource::LegacySocket("127.0.0.1:8233".parse().unwrap());

        for source in [None, Some(legacy)] {
            let answer =
                advertise(&mut inbound, Request::AdvertiseBlock(hash.into(), source)).await;
            assert_eq!(answer.to_string(), ADVERT_NOT_SEEN);
        }

        assert!(rx.try_recv().is_err(), "nothing was queued");
        assert_eq!(stats.adverts_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.adverts_dropped.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_hash_in_flight_is_fetched_once() {
        let stats = Arc::new(NativeStats::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let (advert_tx, advert_rx) = mpsc::channel(4);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(8);
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

        advert_tx.send(advert_from(1, 1)).await.unwrap();
        advert_tx.send(advert_from(1, 2)).await.unwrap();
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

        advert_tx.send(advert(2)).await.unwrap();
        wait_for(&stats.fetches_failed, 1, "the first fetch fails").await;
        // The failed hash may still be leaving the in-progress set; resend until the
        // retry is accepted rather than coalesced.
        let fetched = timeout(STEP, async {
            loop {
                advert_tx.send(advert(2)).await.unwrap();
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
        assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 1);
        fetcher.abort();
    }

    /// Review finding 2: a source whose fetch hangs holds one fetch and one body
    /// slot. Its further advertisements are skipped at once, even with the queue
    /// full of them, and another source's advertisement is fetched meanwhile.
    #[tokio::test]
    async fn a_busy_source_holds_one_fetch_and_does_not_hold_back_others() {
        let stats = Arc::new(NativeStats::default());
        let started = Arc::new(Mutex::new(Vec::new()));
        let (advert_tx, advert_rx) = mpsc::channel(8);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(8);
        let fetch = {
            let started = Arc::clone(&started);
            move |advert: NativeAdvert| {
                lock(&started).push(advert.source.clone());
                let hangs = advert.source == peer(1);
                async move {
                    if hangs {
                        std::future::pending::<()>().await;
                    }
                    Ok::<_, BoxError>(vec![8])
                }
            }
        };
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            fetch,
            fetched_tx,
            limits(8, 2),
            Arc::clone(&stats),
        ));

        advert_tx.send(advert_from(1, 1)).await.unwrap();
        for byte in 2..=8 {
            advert_tx.send(advert_from(byte, 1)).await.unwrap();
        }
        advert_tx.send(advert_from(20, 2)).await.unwrap();

        let other = timeout(STEP, fetched_rx.recv())
            .await
            .expect("the other source's block arrives in time")
            .expect("the fetched channel stays open");
        assert_eq!(other.source, peer(2));
        assert_eq!(stats.adverts_source_busy.load(Ordering::Relaxed), 7);
        assert_eq!(
            lock(&started)
                .iter()
                .filter(|source| **source == peer(1))
                .count(),
            1,
            "one fetch for the busy source"
        );
        fetcher.abort();
    }

    /// Review finding 4: a fetched body waiting for the consumer holds a body slot,
    /// not a fetch permit. With one permit and two slots, a second fetch runs while
    /// the first body waits; a third waits for a slot, and starts once the consumer
    /// drops a body.
    #[tokio::test]
    async fn a_slow_consumer_holds_body_slots_not_fetch_permits() {
        let stats = Arc::new(NativeStats::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (advert_tx, advert_rx) = mpsc::channel(8);
        let limits = limits(8, 1);
        assert_eq!(limits.body_slots(), 2);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(limits.body_slots());
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            counting_fetch(Arc::clone(&calls), vec![1]),
            fetched_tx,
            limits,
            Arc::clone(&stats),
        ));

        for byte in 1..=3 {
            advert_tx.send(advert_from(byte, byte)).await.unwrap();
        }
        wait_for(&stats.fetches_ok, 2, "two fetches finish").await;
        settle().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the third waits for a slot"
        );

        let first = fetched_rx.recv().await.expect("a body is waiting");
        drop(first);
        wait_for_calls(&calls, 3, "the third fetch starts once a slot is free").await;
        fetcher.abort();
    }

    /// A body over the size limit is dropped as a failed fetch, and frees its hash.
    #[tokio::test]
    async fn an_oversized_body_is_dropped_as_a_failed_fetch() {
        let stats = Arc::new(NativeStats::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (advert_tx, advert_rx) = mpsc::channel(4);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(4);
        let limits = SourceLimits {
            max_body_bytes: 3,
            ..limits(4, 1)
        };
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            counting_fetch(Arc::clone(&calls), vec![0; 4]),
            fetched_tx,
            limits,
            Arc::clone(&stats),
        ));

        advert_tx.send(advert(5)).await.unwrap();
        wait_for(&stats.fetches_failed, 1, "the oversized fetch fails").await;
        advert_tx.send(advert(5)).await.unwrap();
        wait_for(&stats.fetches_failed, 2, "the hash is fetched again").await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 0);
        assert!(fetched_rx.try_recv().is_err(), "no body was delivered");
        fetcher.abort();
    }

    /// A delivery dropped without a record, as after a failed or cancelled
    /// forward, frees the hash and the source: the next advertisement fetches.
    #[tokio::test]
    async fn a_delivery_dropped_without_a_record_frees_its_hash_and_source() {
        let stats = Arc::new(NativeStats::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (advert_tx, advert_rx) = mpsc::channel(4);
        let (fetched_tx, mut fetched_rx) = mpsc::channel(4);
        let fetcher = tokio::spawn(run_fetcher(
            advert_rx,
            counting_fetch(Arc::clone(&calls), vec![1]),
            fetched_tx,
            limits(4, 1),
            Arc::clone(&stats),
        ));

        advert_tx.send(advert_from(4, 1)).await.unwrap();
        let block = timeout(STEP, fetched_rx.recv()).await.unwrap().unwrap();
        drop(block);
        advert_tx.send(advert_from(4, 1)).await.unwrap();
        let again = timeout(STEP, fetched_rx.recv()).await.unwrap().unwrap();
        assert_eq!(again.hash, advert(4).hash);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(stats.adverts_source_busy.load(Ordering::Relaxed), 0);
        fetcher.abort();
    }
}
