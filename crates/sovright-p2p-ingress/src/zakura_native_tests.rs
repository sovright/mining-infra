//! Native peer → ingress → relay node → sidecar, all on loopback.
//!
//! The fake native peers run the published `zakura-network` endpoint, but their
//! behaviour is ours (`sovright_zakura_native::test_support`). Nothing here is
//! evidence of compatibility with stock zakurad.
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use sovright_relay::RelayPayload;
use sovright_relay_sidecar::submit::{
    SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitBlockStatus, SubmitFuture,
    handle_relay_compact_block,
};
use sovright_zakura_native::native::{BlockHash, NativeNetwork};
use sovright_zakura_native::test_support::{
    FakePeer, Serve, block_from_bytes, serve_block, serve_block_when, serve_for_any_hash,
    serve_nothing,
};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

use super::nu7_fixture::Nu7Fixture;
use super::nu7_transport_tests::{BridgeMode, LoopbackRelay};
use super::*;
use crate::config::ZakuraNativeConfig;
use crate::wire::Network;
use crate::zakura_native::{self, NativeIngress};

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
        let native = zakura_native::start(
            &config,
            Network::Testnet,
            relay.clone(),
            None,
            EventSink::new(None).unwrap(),
        )
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
