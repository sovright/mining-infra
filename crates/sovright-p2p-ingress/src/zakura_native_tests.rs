//! Native peer → ingress → relay node → sidecar, all on loopback.
//!
//! The fake native peers run the published `zakura-network` endpoint, but their
//! behaviour is ours (`sovright_zakura_native::test_support`). Nothing here is
//! evidence of compatibility with stock zakurad.
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use sovright_relay::test_support::raw_block;
use zcash_pool_common::fixtures;

use sovright_relay::RelayPayload;
use sovright_relay_sidecar::submit::{
    SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitBlockStatus, SubmitFuture,
    handle_relay_compact_block,
};
use sovright_zakura_native::native::{BlockHash, DeliveryProbe, FetchedBlock, NativeNetwork};
use sovright_zakura_native::test_support::{
    FakePeer, Serve, block_from_bytes, serve_block, serve_block_when, serve_for_any_hash,
    serve_nothing,
};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use super::block_body_tests::{
    Harness, bypass_harness, compact_blocks_of, eventually, fill_send_channel, good_and_bad,
    harness, hash_of, in_flight, unreadable_block,
};
use super::nu7_fixture::Nu7Fixture;
use super::nu7_transport_tests::{BridgeMode, LoopbackRelay};
use super::*;
use crate::config::ZakuraNativeConfig;
use crate::wire::Network;
use crate::zakura_native::{
    self, ForwardStats, NativeIngress, RECENT_CAPACITY, RECENT_WINDOW, RecentNativeBlocks,
    delivered_check, forward_fetched,
};

/// Upper bound for each step that waits on the network.
const STEP: Duration = Duration::from_secs(20);
/// The per-fetch limit the tests give the source.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

const PLAIN_RELAY: BridgeMode = BridgeMode {
    compact_from_tx_cache: false,
    skeleton_first: false,
};

/// Records every block it is asked to submit, and accepts it.
#[derive(Default)]
struct CapturingSubmit {
    submitted: Mutex<Vec<String>>,
}

impl SubmitBlock for CapturingSubmit {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        self.submitted.lock().unwrap().push(block_hex.to_owned());
        Box::pin(async { Ok(None) })
    }
}

/// The ingress side of a test: its native source, dialing only `peers`.
struct Ingress {
    native: NativeIngress,
    _identity: TempDir,
}

impl Ingress {
    async fn start(relay: &RelayBridge, peers: &[&FakePeer]) -> Self {
        Self::start_with_events(relay, peers, EventSink::new(None).unwrap()).await
    }

    async fn start_with_events(
        relay: &RelayBridge,
        peers: &[&FakePeer],
        events: EventSink,
    ) -> Self {
        let mut bootstrap_peers = Vec::new();
        for peer in peers {
            bootstrap_peers.push(
                timeout(STEP, peer.bootstrap_addr())
                    .await
                    .expect("the fake peer reports its address in time")
                    .expect("the fake peer listens on loopback"),
            );
        }
        let identity = tempfile::tempdir().expect("a temporary identity directory");
        let config = ZakuraNativeConfig {
            bootstrap_peers,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            identity_dir: PathBuf::from(identity.path()),
            advert_queue: 8,
            max_concurrent_fetches: 2,
            fetch_timeout: FETCH_TIMEOUT,
        };
        let native = zakura_native::start(&config, Network::Testnet, relay.clone(), None, events)
            .await
            .expect("the native source starts");
        for peer in peers {
            peer.wait_for_peer(STEP)
                .await
                .expect("the ingress connects to the fake peer in time");
        }
        Self {
            native,
            _identity: identity,
        }
    }
}

async fn fake_peer(serve: Serve) -> FakePeer {
    FakePeer::spawn(NativeNetwork::Testnet, serve)
        .await
        .expect("the fake peer starts")
}

async fn wait_for(counter: &AtomicU64, at_least: u64, what: &str) {
    timeout(STEP, async {
        while counter.load(Ordering::Relaxed) < at_least {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} within {STEP:?}"));
}

/// The native events named `name` in the event log. A line still being written
/// is skipped; the next read sees it whole.
fn native_events(log: &Path, name: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["event"] == name && event["peer"] == zakura_native::SOURCE)
        .collect()
}

/// The first native event named `name`, waiting for it to be written.
async fn wait_for_event(log: &Path, name: &str) -> serde_json::Value {
    timeout(STEP, async {
        loop {
            if let Some(event) = native_events(log, name).into_iter().next() {
                return event;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("a native {name} event within {STEP:?}"))
}

/// The first acceptance test: a native peer's NU7 block reaches `submitblock` with
/// the fixture's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_nu7_block_reaches_submitblock_with_the_fixture_bytes() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let mut relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let peer = fake_peer(serve_block(Arc::clone(&block))).await;
    let ingress = Ingress::start(&relay.bridge, &[&peer]).await;

    peer.advertise(block.hash(), raw.len())
        .await
        .expect("the fake peer advertises the fixture");
    wait_for(
        &ingress.native.forward_stats().forwarded,
        1,
        "the native block is forwarded",
    )
    .await;

    let mut compact = None;
    let received = relay
        .receive(|payload| {
            if let RelayPayload::CompactBlock(block) = payload {
                compact = Some(block);
            }
            compact.is_some()
        })
        .await;
    assert!(received, "the relay receiver gets the compact block");
    let compact = compact.unwrap();

    let submitter = CapturingSubmit::default();
    let outcome = handle_relay_compact_block(&submitter, &compact, SubmitBlockMode::Live)
        .await
        .expect("the sidecar rebuilds and submits the block");
    let SubmissionOutcome::Submitted { candidate, status } = outcome else {
        panic!("expected a submission, got {outcome:?}");
    };
    assert_eq!(status, SubmitBlockStatus::Accepted);
    let submitted = submitter.submitted.lock().unwrap().clone();
    assert_eq!(submitted.len(), 1, "one submitblock call");
    assert_eq!(hex::decode(&submitted[0]).unwrap(), raw, "submitted bytes");
    assert_eq!(hex::decode(&candidate.block_hex).unwrap(), raw);

    let stats = ingress.native.source_stats();
    assert_eq!(stats.adverts_received.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fetches_failed.load(Ordering::Relaxed), 0);

    // The other direction of the shared dedup state: a legacy copy that arrives
    // after the native one is not sent again.
    let legacy = relay.bridge.forward_block(&raw, None).await.unwrap();
    assert_eq!(legacy.mode, ForwardMode::Deduplicated);

    timeout(STEP, ingress.native.shutdown())
        .await
        .expect("the native tasks stop in time");
    relay.stop().await;
}

/// Native block events fill `hash` and `consensus_hash` the way legacy block events
/// do. `hash` is the relay object hash, the join key between the received and
/// forwarded events; `consensus_hash` is the chain's hash. The expected values are
/// the expressions the legacy event tests in `peer.rs` assert, plus the consensus
/// hash the fixture records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_block_events_fill_the_hash_fields_like_legacy_events() {
    let fixture = Nu7Fixture::load();
    let raw = fixture.raw.clone();
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let peer = fake_peer(serve_block(Arc::clone(&block))).await;
    let log_dir = tempfile::tempdir().expect("a temporary event directory");
    let log = log_dir.path().join("events.jsonl");
    let events = EventSink::new(Some(log.clone())).expect("the event log opens");
    let ingress = Ingress::start_with_events(&relay.bridge, &[&peer], events).await;

    peer.advertise(block.hash(), raw.len())
        .await
        .expect("the fake peer advertises the fixture");
    let forwarded = wait_for_event(&log, "p2p_relay_block_forwarded").await;
    let received = native_events(&log, "p2p_block_received");
    let [received] = received.as_slice() else {
        panic!("expected one native p2p_block_received event, got {received:?}");
    };

    let relay_object_hash = crate::hash::display_hash_from_header(&raw).unwrap();
    assert_eq!(received["hash"], relay_object_hash.as_str());
    assert_eq!(forwarded["hash"], relay_object_hash.as_str());
    assert_eq!(
        received["consensus_hash"],
        sovright_relay::consensus_block_hash_display(
            &raw[..sovright_relay::ZCASH_FULL_HEADER_SIZE]
        )
    );
    assert_eq!(received["consensus_hash"], fixture.consensus_hash());
    assert_ne!(relay_object_hash, fixture.consensus_hash());

    timeout(STEP, ingress.native.shutdown())
        .await
        .expect("the native tasks stop in time");
    relay.stop().await;
}

/// A block a legacy peer already forwarded is fetched from the native peer, but the
/// shared dedup state keeps it from being sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_forwarded_from_a_legacy_peer_is_deduplicated_on_the_native_path() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let legacy = relay.bridge.forward_block(&raw, None).await.unwrap();
    assert_eq!(legacy.mode, ForwardMode::CompactBlock);

    let peer = fake_peer(serve_block(Arc::clone(&block))).await;
    let ingress = Ingress::start(&relay.bridge, &[&peer]).await;
    peer.advertise(block.hash(), raw.len())
        .await
        .expect("the fake peer advertises the fixture");

    let forward = ingress.native.forward_stats();
    wait_for(&forward.deduplicated, 1, "the native copy is deduplicated").await;
    assert_eq!(forward.forwarded.load(Ordering::Relaxed), 0);
    assert_eq!(forward.failed.load(Ordering::Relaxed), 0);
    let stats = ingress.native.source_stats();
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fetches_failed.load(Ordering::Relaxed), 0);

    ingress.native.shutdown().await;
    relay.stop().await;
}

/// A peer that answers with a block other than the one requested gets nothing
/// forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_with_another_hash_is_not_forwarded() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let peer = fake_peer(serve_for_any_hash(block)).await;
    let ingress = Ingress::start(&relay.bridge, &[&peer]).await;

    let started = Instant::now();
    peer.advertise(BlockHash([0x22; 32]), raw.len())
        .await
        .expect("the fake peer advertises a hash it cannot serve honestly");
    let stats = ingress.native.source_stats();
    wait_for(&stats.fetches_failed, 1, "the fetch fails").await;
    // An answer, not the fetch timeout, ended the fetch.
    assert!(started.elapsed() < FETCH_TIMEOUT);
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 0);
    let forward = ingress.native.forward_stats();
    assert_eq!(forward.forwarded.load(Ordering::Relaxed), 0);
    assert_eq!(forward.failed.load(Ordering::Relaxed), 0);
    // The fixture the peer sent did not go out: a legacy copy of it is still new.
    let legacy = relay.bridge.forward_block(&raw, None).await.unwrap();
    assert_eq!(legacy.mode, ForwardMode::CompactBlock);

    ingress.native.shutdown().await;
    relay.stop().await;
}

/// After every connected peer answered missing, a later advertisement of the same
/// hash is still taken and fetched. The ingress also does not pass either
/// advertisement on to its other peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_fetch_leaves_a_later_advert_of_the_hash_free() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let first = fake_peer(serve_nothing()).await;
    let serving = Arc::new(AtomicBool::new(false));
    let second = fake_peer(serve_block_when(Arc::clone(&block), Arc::clone(&serving))).await;
    let ingress = Ingress::start(&relay.bridge, &[&first, &second]).await;

    first
        .advertise(block.hash(), raw.len())
        .await
        .expect("the first peer advertises the fixture");
    let stats = ingress.native.source_stats();
    wait_for(&stats.fetches_failed, 1, "the fetch fails at both peers").await;
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 0);

    serving.store(true, Ordering::SeqCst);
    second
        .advertise(block.hash(), raw.len())
        .await
        .expect("the second peer advertises the fixture");
    wait_for(
        &ingress.native.forward_stats().forwarded,
        1,
        "the second advert is fetched and forwarded",
    )
    .await;
    assert_eq!(stats.adverts_received.load(Ordering::Relaxed), 2);
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 1);
    assert_eq!(
        first.adverts_received(),
        0,
        "nothing passed on to the first peer"
    );
    assert_eq!(
        second.adverts_received(),
        0,
        "nothing passed on to the second peer"
    );

    ingress.native.shutdown().await;
    relay.stop().await;
}

/// One connection carries adverts the ingress answers with an error, two fetches
/// that fail and then one that succeeds. The connection stays up throughout: the
/// error answers neither close it nor stop later adverts on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_connection_survives_error_answers_and_failed_fetches() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let peer = fake_peer(serve_block(Arc::clone(&block))).await;
    let ingress = Ingress::start(&relay.bridge, &[&peer]).await;

    // Every registration and deregistration republishes the peer set, so a
    // disconnect or a reconnect of the same peer marks this receiver changed.
    let supervisor = peer.endpoint().supervisor();
    let connected = supervisor.registered_ids().await;
    assert_eq!(
        connected.len(),
        1,
        "the ingress is the fake peer's only peer"
    );
    let mut peer_set = supervisor.subscribe();
    peer_set.borrow_and_update();

    let stats = ingress.native.source_stats();
    for (failed, byte) in [(1, 0x31), (2, 0x32)] {
        peer.advertise(BlockHash([byte; 32]), raw.len())
            .await
            .expect("the fake peer advertises a hash it does not have");
        wait_for(
            &stats.fetches_failed,
            failed,
            "the fetch of a missing block fails",
        )
        .await;
    }
    peer.advertise(block.hash(), raw.len())
        .await
        .expect("the fake peer advertises the fixture");
    wait_for(
        &ingress.native.forward_stats().forwarded,
        1,
        "the fixture is fetched and forwarded",
    )
    .await;

    assert_eq!(stats.adverts_received.load(Ordering::Relaxed), 3);
    assert_eq!(stats.adverts_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(stats.fetches_failed.load(Ordering::Relaxed), 2);
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 1);
    assert!(peer.block_requests_received() >= 3);
    assert!(
        !peer_set
            .has_changed()
            .expect("the fake peer's supervisor is alive"),
        "no disconnect and no reconnect"
    );
    assert_eq!(supervisor.registered_ids().await, connected);
    assert_eq!(peer.adverts_received(), 0, "nothing was passed back");

    ingress.native.shutdown().await;
    relay.stop().await;
}

/// After `shutdown`, with the runtime still running, the native connection closes
/// and is not redialed, a later advert reaches nothing, and no block request
/// starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_shutdown_no_advert_is_taken_and_no_request_starts() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let peer = fake_peer(serve_block(Arc::clone(&block))).await;
    let ingress = Ingress::start(&relay.bridge, &[&peer]).await;
    let source = Arc::clone(ingress.native.source_stats());
    let forward = Arc::clone(ingress.native.forward_stats());
    let supervisor = peer.endpoint().supervisor();

    timeout(STEP, ingress.native.shutdown())
        .await
        .expect("the native source shuts down in time");
    timeout(STEP, async {
        let mut peers = supervisor.subscribe();
        while !peers.borrow_and_update().is_empty() {
            peers
                .changed()
                .await
                .expect("the fake peer's supervisor is alive");
        }
    })
    .await
    .expect("the ingress connection closes in time");

    // A short-lived bootstrap connection is redialed after 1 s, then 2 s; waiting
    // 3 s gives a redial the time to happen.
    sleep(Duration::from_secs(3)).await;
    assert!(
        supervisor.registered_ids().await.is_empty(),
        "the ingress did not redial"
    );

    peer.advertise(block.hash(), raw.len())
        .await
        .expect("the fake peer advertises the fixture");
    sleep(Duration::from_secs(1)).await;
    assert_eq!(source.adverts_received.load(Ordering::Relaxed), 0);
    assert_eq!(source.fetches_ok.load(Ordering::Relaxed), 0);
    assert_eq!(source.fetches_failed.load(Ordering::Relaxed), 0);
    assert_eq!(peer.block_requests_received(), 0);
    assert_eq!(forward.forwarded.load(Ordering::Relaxed), 0);
    let legacy = relay.bridge.forward_block(&raw, None).await.unwrap();
    assert_eq!(legacy.mode, ForwardMode::CompactBlock, "nothing went out");

    relay.stop().await;
}

// ---- Review of #143: delivered-block record ----

/// The native forwarder on its own, fed the way the fetcher feeds it, in front of
/// a bridge from the block body tests: no network.
struct Forwarder {
    blocks: mpsc::Sender<FetchedBlock>,
    task: tokio::task::JoinHandle<()>,
    stats: Arc<ForwardStats>,
    recent: Arc<Mutex<RecentNativeBlocks>>,
    probe: DeliveryProbe,
}

impl Forwarder {
    fn start(bridge: &RelayBridge) -> Self {
        let (blocks, fetched) = mpsc::channel(4);
        let stats = Arc::new(ForwardStats::default());
        let recent = Arc::new(Mutex::new(RecentNativeBlocks::new(
            RECENT_CAPACITY,
            RECENT_WINDOW,
        )));
        let task = tokio::spawn(forward_fetched(
            fetched,
            bridge.clone(),
            None,
            EventSink::new(None).unwrap(),
            Arc::clone(&stats),
            Arc::clone(&recent),
        ));
        Self {
            blocks,
            task,
            stats,
            recent,
            probe: DeliveryProbe::new(),
        }
    }

    /// Hands `raw` over as a fetched block under its consensus hash, and returns
    /// that hash.
    async fn send(&self, raw: &[u8]) -> BlockHash {
        let hash = BlockHash(sovright_relay::consensus_block_hash(
            &raw[..sovright_relay::ZCASH_FULL_HEADER_SIZE],
        ));
        self.blocks
            .send(self.probe.fetched(hash, raw.to_vec()))
            .await
            .expect("the forwarder is running");
        hash
    }

    /// Waits until the forwarder dropped the block's delivery.
    async fn released(&self, hash: &BlockHash) {
        eventually(|| !self.probe.in_progress(hash)).await;
    }

    /// The fetcher's view: is `hash` delivered?
    fn delivered(&self, bridge: &RelayBridge, hash: &BlockHash) -> bool {
        delivered_check(Arc::clone(&self.recent), bridge.clone())(hash)
    }

    fn recorded_at(&self, hash: &BlockHash) -> Option<Instant> {
        self.recent
            .lock()
            .unwrap()
            .recorded_at(hash, Instant::now())
    }
}

/// A bad body and then the good one under the same header: only the good one is
/// remembered, and only once the bridge recorded it. When the forwarder has
/// released a block, it is already remembered if it ever will be.
#[tokio::test]
async fn a_bad_copy_then_the_good_one_is_remembered_only_after_the_good_one() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    let forwarder = Forwarder::start(&harness.bridge);

    let hash = forwarder.send(&bad).await;
    wait_for(&forwarder.stats.failed, 1, "the bad copy is refused").await;
    forwarder.released(&hash).await;
    assert!(!forwarder.delivered(&harness.bridge, &hash));
    assert!(harness.bridge.forwarded_at(&hash_of(&bad)).is_none());

    assert_eq!(forwarder.send(&good).await, hash);
    wait_for(&forwarder.stats.forwarded, 1, "the good copy goes out").await;
    forwarder.released(&hash).await;
    assert!(forwarder.delivered(&harness.bridge, &hash));
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    forwarder.task.abort();
}

/// A send the relay channel refuses leaves no bridge record, so nothing is
/// remembered and the next advertisement would fetch again.
#[tokio::test]
async fn a_failed_relay_send_is_not_remembered() {
    let (good, _) = good_and_bad();
    let Harness {
        bridge, outgoing, ..
    } = harness();
    drop(outgoing);
    let forwarder = Forwarder::start(&bridge);

    let hash = forwarder.send(&good).await;
    wait_for(&forwarder.stats.failed, 1, "the send fails").await;
    forwarder.released(&hash).await;
    assert!(bridge.forwarded_at(&hash_of(&good)).is_none());
    assert!(!forwarder.delivered(&bridge, &hash));
    assert!(forwarder.recorded_at(&hash).is_none());
    forwarder.task.abort();
}

/// A forward cancelled while its send waits leaves no record anywhere, and frees
/// the block both in the source and in the bridge.
#[tokio::test]
async fn a_cancelled_forward_is_not_remembered_and_frees_the_block() {
    let (good, _) = good_and_bad();
    let harness = harness();
    fill_send_channel(&harness.bridge).await;
    let mut forwarder = Forwarder::start(&harness.bridge);

    let hash = forwarder.send(&good).await;
    eventually(|| in_flight(&harness.bridge, &hash_of(&good))).await;
    forwarder.task.abort();
    let ended = (&mut forwarder.task).await;
    assert!(ended.unwrap_err().is_cancelled());

    assert!(!forwarder.probe.in_progress(&hash));
    assert!(!in_flight(&harness.bridge, &hash_of(&good)));
    assert!(harness.bridge.forwarded_at(&hash_of(&good)).is_none());
    assert!(forwarder.recorded_at(&hash).is_none());
}

/// Under the emergency bypass an unreadable body goes out unverified, and the
/// bridge reports a repeat of the same bytes as `Deduplicated`. Neither leaves a
/// bridge record, so neither is remembered: the mode alone is not the test.
#[tokio::test]
async fn an_unverified_forward_and_its_deduplicated_repeat_are_not_remembered() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_harness();
    let forwarder = Forwarder::start(&harness.bridge);

    let hash = forwarder.send(&raw).await;
    wait_for(
        &forwarder.stats.forwarded,
        1,
        "the unverified body goes out",
    )
    .await;
    forwarder.released(&hash).await;
    assert!(!forwarder.delivered(&harness.bridge, &hash));

    forwarder.send(&raw).await;
    wait_for(
        &forwarder.stats.deduplicated,
        1,
        "the repeat is reported as deduplicated",
    )
    .await;
    forwarder.released(&hash).await;
    assert!(!forwarder.delivered(&harness.bridge, &hash));
    assert!(harness.bridge.forwarded_at(&hash_of(&raw)).is_none());
    assert!(forwarder.recorded_at(&hash).is_none());
    assert!(!harness.sent().is_empty(), "the first copy did go out");
    forwarder.task.abort();
}

/// A block the legacy path forwarded first is remembered with the bridge's own
/// record time, not the time the native copy arrived.
#[tokio::test]
async fn a_block_the_legacy_path_forwarded_keeps_the_bridges_record_time() {
    let (good, _) = good_and_bad();
    let harness = harness();
    let legacy = harness.bridge.forward_block(&good, None).await.unwrap();
    assert_eq!(legacy.mode, ForwardMode::CompactBlock);
    let bridge_time = harness.bridge.forwarded_at(&hash_of(&good)).unwrap();
    let forwarder = Forwarder::start(&harness.bridge);

    sleep(Duration::from_millis(20)).await;
    let hash = forwarder.send(&good).await;
    wait_for(
        &forwarder.stats.deduplicated,
        1,
        "the native copy is deduplicated",
    )
    .await;
    forwarder.released(&hash).await;
    assert_eq!(forwarder.recorded_at(&hash), Some(bridge_time));
    assert!(forwarder.delivered(&harness.bridge, &hash));
    forwarder.task.abort();
}

/// The native record counts only while the bridge holds its own: it does not
/// outlast a shorter bridge window, nor a bridge record pushed out by capacity.
#[tokio::test]
async fn a_remembered_block_does_not_outlast_the_bridges_record() {
    let (good, _) = good_and_bad();
    let other = raw_block(
        &fixtures::mainnet_serialized_header(),
        &fixtures::mainnet_transactions(),
    );

    let mut short = harness();
    short.bridge.recent_forwarded = Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
        64,
        Duration::from_secs(1),
    )));
    let forwarder = Forwarder::start(&short.bridge);
    let hash = forwarder.send(&good).await;
    wait_for(&forwarder.stats.forwarded, 1, "the block goes out").await;
    forwarder.released(&hash).await;
    assert!(forwarder.delivered(&short.bridge, &hash));
    sleep(Duration::from_millis(1200)).await;
    assert!(short.bridge.forwarded_at(&hash_of(&good)).is_none());
    assert!(
        forwarder.recorded_at(&hash).is_some(),
        "the native entry is inside its own window"
    );
    assert!(!forwarder.delivered(&short.bridge, &hash));
    forwarder.task.abort();

    let mut small = harness();
    small.bridge.recent_forwarded = Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
        1,
        Duration::from_secs(30),
    )));
    let forwarder = Forwarder::start(&small.bridge);
    let hash = forwarder.send(&good).await;
    wait_for(&forwarder.stats.forwarded, 1, "the block goes out").await;
    forwarder.released(&hash).await;
    assert!(forwarder.delivered(&small.bridge, &hash));
    small.bridge.forward_block(&other, None).await.unwrap();
    assert!(small.bridge.forwarded_at(&hash_of(&other)).is_some());
    assert!(small.bridge.forwarded_at(&hash_of(&good)).is_none());
    assert!(!forwarder.delivered(&small.bridge, &hash));
    small.sent();
    forwarder.task.abort();
}

#[test]
fn the_recent_record_is_bounded_and_never_refreshed() {
    let start = Instant::now();
    let mut recent = RecentNativeBlocks::new(2, Duration::from_secs(30));
    let first = BlockHash([1; 32]);
    recent.record(first, [1; 32], start, start);
    // A repeat does not move the record time.
    recent.record(first, [1; 32], start + Duration::from_secs(10), start);
    assert_eq!(recent.recorded_at(&first, start), Some(start));
    // Counted from the record time, whatever the time of the repeat.
    assert_eq!(
        recent.relay_hash(&first, start + Duration::from_secs(31)),
        None
    );

    let mut recent = RecentNativeBlocks::new(2, Duration::from_secs(30));
    for byte in 1..=3 {
        recent.record(BlockHash([byte; 32]), [byte; 32], start, start);
    }
    assert_eq!(recent.relay_hash(&BlockHash([1; 32]), start), None);
    assert_eq!(recent.relay_hash(&BlockHash([3; 32]), start), Some([3; 32]));
}

/// End to end: once a native block is forwarded, another peer's advertisement of
/// it is skipped as delivered, without a second fetch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivered_block_is_not_fetched_again_for_another_peer() {
    let raw = Nu7Fixture::load().raw;
    let block = block_from_bytes(&raw).expect("the fixture is a valid serialized block");
    let relay = LoopbackRelay::start(PLAIN_RELAY).await;
    let first = fake_peer(serve_block(Arc::clone(&block))).await;
    let second = fake_peer(serve_block(Arc::clone(&block))).await;
    let ingress = Ingress::start(&relay.bridge, &[&first, &second]).await;

    first
        .advertise(block.hash(), raw.len())
        .await
        .expect("the first peer advertises the fixture");
    wait_for(
        &ingress.native.forward_stats().forwarded,
        1,
        "the block is forwarded",
    )
    .await;
    let stats = ingress.native.source_stats();
    second
        .advertise(block.hash(), raw.len())
        .await
        .expect("the second peer advertises the fixture");
    wait_for(
        &stats.adverts_delivered,
        1,
        "the second advert is skipped as delivered",
    )
    .await;
    assert_eq!(stats.fetches_ok.load(Ordering::Relaxed), 1);
    assert_eq!(second.block_requests_received(), 0);

    ingress.native.shutdown().await;
    relay.stop().await;
}
