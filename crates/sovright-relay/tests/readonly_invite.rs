//! End-to-end coverage for the external read-only invitee path.
//!
//! An invitee holds a `ReceiveOnly` key and announces nothing, so the only
//! thing that registers and refreshes its relay session is the client run
//! loop's periodic authenticated keepalive. If that keepalive ever stops
//! covering the no-announcement case, an invite silently becomes a session
//! that expires after `session_timeout` and delivers zero blocks -- so this
//! is pinned by test rather than left to inspection.

use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{AuthKey, ClientConfig, KeyRole, RelayClient, RelayConfig, RelayNode};

async fn start_node(keys: Vec<AuthKey>) -> (Arc<RelayNode>, std::net::SocketAddr) {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(keys);
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    (Arc::new(node), addr)
}

/// A receive-only client that never announces still registers a relay
/// session, purely from the run loop's keepalive.
#[tokio::test]
async fn receive_only_client_registers_session_without_announcing() {
    let invitee_key = [0x7au8; 32];
    let (node, node_addr) = start_node(vec![
        AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly),
    ])
    .await;

    let node_clone = Arc::clone(&node);
    let node_handle = tokio::spawn(async move { node_clone.run().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = ClientConfig::new(vec![node_addr], invitee_key)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();

    // Drive the real run loop. Nothing is ever queued for announcement, so a
    // session can only appear via the keepalive tick.
    let client_handle = tokio::spawn(async move { client.run().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(
        metrics.auth_failures, 0,
        "keepalive from a valid invitee key must authenticate"
    );
    assert_eq!(
        metrics.sessions_created, 1,
        "a non-announcing receive-only client must still register one session"
    );
    assert!(
        metrics
            .sessions_created_by_key
            .iter()
            .any(|(id, count)| id == "invitee" && *count == 1),
        "session must be attributed to the invitee key, got {:?}",
        metrics.sessions_created_by_key
    );

    node.stop();
    client_handle.abort();
    let _ = node_handle.await;
}

/// A client whose key is not authorized registers nothing and is counted as
/// an auth failure -- the property that makes open internet exposure safe.
#[tokio::test]
async fn unauthorized_client_keepalive_registers_no_session() {
    let invitee_key = [0x7au8; 32];
    let wrong_key = [0x11u8; 32];
    let (node, node_addr) = start_node(vec![
        AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly),
    ])
    .await;

    let node_clone = Arc::clone(&node);
    let node_handle = tokio::spawn(async move { node_clone.run().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = ClientConfig::new(vec![node_addr], wrong_key)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();

    let client_handle = tokio::spawn(async move { client.run().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(
        metrics.sessions_created, 0,
        "an unauthorized keepalive must not create a session"
    );
    assert!(
        metrics.auth_failures > 0,
        "an unauthorized keepalive must count as an auth failure"
    );

    node.stop();
    client_handle.abort();
    let _ = node_handle.await;
}

/// An unauthenticated flood from the open internet is rate limited before it
/// can force a trial-verify HMAC scan, and it does not prevent a legitimate
/// invitee from authenticating. This is the property that makes exposing the
/// relay on 0.0.0.0/0 defensible.
#[tokio::test]
async fn unauthenticated_flood_is_rate_limited_and_does_not_block_a_real_invitee() {
    use sovright_relay::{Chunk, ChunkHeader, RelaySession};
    use tokio::net::UdpSocket;

    let invitee_key = [0x7au8; 32];
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![
            AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly),
        ])
        .with_unauth_rate_limit(5.0, 20.0);
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let node_addr = node.local_addr().unwrap();

    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);
    let node_handle = tokio::spawn(async move { node_clone.run().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Flood from a single source with garbage-keyed keepalives. Each one that
    // gets through costs a full trial-verify scan; the limiter should drop
    // the overwhelming majority.
    let flooder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bogus = RelaySession::new("0.0.0.0:0".parse().unwrap(), "bogus", [0x11u8; 32]);
    let hmac = bogus.compute_hmac(&[0u8; 32], 0, 0, 0, &[]);
    let bogus_chunk = Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new());
    let bogus_bytes = bogus_chunk.to_bytes();

    const FLOOD: usize = 200;
    for _ in 0..FLOOD {
        flooder.send_to(&bogus_bytes, node_addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(
        metrics.sessions_created, 0,
        "a flood with an unauthorized key must never create a session"
    );
    assert!(
        metrics.unauth_rate_limited > 0,
        "the flood must be rate limited, got {:?}",
        metrics.unauth_rate_limited
    );
    // The limiter is the point: only a small fraction should have reached the
    // expensive trial-verify path (burst 20, refilling at 5/sec).
    assert!(
        metrics.auth_failures < FLOOD as u64 / 2,
        "most of the flood should be dropped before trial-verify, but {} reached it",
        metrics.auth_failures
    );

    // A legitimate invitee, from a different source address, still gets in.
    let client_config = ClientConfig::new(vec![node_addr], invitee_key)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();
    let client_handle = tokio::spawn(async move { client.run().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(
        metrics.sessions_created, 1,
        "a legitimate invitee must still authenticate while a flood is in progress"
    );

    node.stop();
    client_handle.abort();
    let _ = node_handle.await;
}
