//! Loopback test over the real Zakura native protocol, below the bounded fetcher.
//!
//! Both ends run the published `zakura-network` endpoint code on 127.0.0.1, with
//! no header-sync driver and no chain database. The fake peer is our own code
//! (`test_support`), so this test is no evidence of compatibility with stock
//! zakurad.
#![cfg(all(feature = "zakura-native", feature = "test-support"))]

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use serde_json::Value;
use sovright_zakura_native::{
    native::{
        NativeAdvert, NativeNetwork, NativeStats, advert_inbound, fetch_block,
        spawn_stateless_endpoint, stateless_config,
    },
    test_support::{FakePeer, block_from_bytes, serve_block},
};
use tokio::{sync::mpsc, time::timeout};
use zakura_chain::{
    block::{self, Block},
    parameters::Network,
    serialization::ZcashDeserializeInto,
};
use zakura_network::PeerSource;

const FIXTURE_HEX: &str =
    include_str!("../../sovright-p2p-ingress/tests/fixtures/testnet_nu7_4465026.hex");
const FIXTURE_META: &str =
    include_str!("../../sovright-p2p-ingress/tests/fixtures/testnet_nu7_4465026.json");

/// Upper bound for each step that waits on the network.
const STEP: Duration = Duration::from_secs(20);
/// A request for a block the peer lacks may be retried at that peer, which can take
/// up to the client's 30 s request timeout.
const MISSING_STEP: Duration = Duration::from_secs(70);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_advert_and_fetch_preserve_the_nu7_fixture_bytes() {
    let fixture = hex::decode(FIXTURE_HEX.trim()).expect("the fixture is hex");
    let meta: Value = serde_json::from_str(FIXTURE_META).expect("the fixture metadata is JSON");
    let block = block_from_bytes(&fixture).expect("the fixture is a valid serialized block");
    assert_eq!(block.hash().to_string(), meta["hash"].as_str().unwrap());

    let peer = FakePeer::spawn(NativeNetwork::Testnet, serve_block(Arc::clone(&block)))
        .await
        .expect("the fake peer starts");
    let bootstrap = timeout(STEP, peer.bootstrap_addr())
        .await
        .expect("the fake peer reports its address in time")
        .expect("the fake peer listens on loopback");

    let stats = Arc::new(NativeStats::default());
    let (advert_tx, mut adverts) = mpsc::channel::<NativeAdvert>(8);
    let identity = tempfile::tempdir().expect("a temporary identity directory");
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("a valid loopback address");
    let ingress = spawn_stateless_endpoint(
        &stateless_config(
            Network::new_default_testnet(),
            identity.path().into(),
            listen,
            vec![bootstrap],
        ),
        advert_inbound(advert_tx, Arc::clone(&stats)),
    )
    .await
    .expect("the ingress endpoint starts");

    // Stateless: no header-sync driver was passed, so no block-sync reactor runs.
    assert!(ingress.block_sync().is_none());
    assert!(peer.endpoint().block_sync().is_none());

    peer.wait_for_peer(STEP)
        .await
        .expect("the ingress connects to the fake peer in time");
    peer.advertise(block.hash(), fixture.len())
        .await
        .expect("the fake peer advertises the fixture");

    let advert = timeout(STEP, adverts.recv())
        .await
        .expect("the advertisement arrives in time")
        .expect("the advert channel stays open");
    assert_eq!(advert.hash, block.hash());
    assert!(matches!(advert.source, PeerSource::Zakura(_)));
    assert_eq!(stats.adverts_received.load(Ordering::Relaxed), 1);

    let fetched = timeout(STEP, fetch_block(&ingress, &advert))
        .await
        .expect("the body arrives in time")
        .expect("the fake peer serves the advertised block");
    let fetched_block: Block = fetched
        .zcash_deserialize_into()
        .expect("the fetched bytes are a valid serialized block");
    assert_eq!(fetched_block.hash(), advert.hash);
    assert_eq!(fetched, fixture, "re-serialized bytes equal the fixture");

    // Failure path, bounded in time: a hash the fake peer lacks.
    let unknown = NativeAdvert {
        hash: block::Hash([0x11; 32]),
        source: advert.source.clone(),
    };
    let missing = timeout(MISSING_STEP, fetch_block(&ingress, &unknown))
        .await
        .expect("a missing block is answered in time");
    assert!(missing.is_err(), "an unknown hash is not served");

    // Close, bounded in time: the fake peer drops the ingress, and the ingress
    // supervisor sees its peer set change.
    let mut ingress_peers = ingress.supervisor().subscribe();
    ingress_peers.borrow_and_update();
    let supervisor = peer.endpoint().supervisor();
    for id in supervisor.registered_ids().await {
        assert!(supervisor.disconnect_peer(&id).await);
    }
    timeout(STEP, ingress_peers.changed())
        .await
        .expect("the ingress sees the close in time")
        .expect("the ingress supervisor outlives the test");
}
