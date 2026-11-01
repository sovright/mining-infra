//! #130 PR B: the bound raw path on a real node and real clients over UDP loopback. What a
//! node does with the candidate format, with keys, sessions and PoW as they are. The format
//! is a candidate, and these tests are no specification of it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{
    AuthKey, BlockSender, BoundBlock, BoundForwardConfig, BoundRawConfig, BoundUsed, Chunk,
    ChunkHeader, ClientConfig, KeyRole, PowValidator, RejectAllValidator, RelayClient, RelayConfig,
    RelayNode, RelaySession, StubPowValidator, body_frames, is_bound, sealed_body, sealed_frame,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

const KEY: [u8; 32] = [0x42; 32];
const OTHER_KEY: [u8; 32] = [0x43; 32];
const WAIT: Duration = Duration::from_secs(10);

async fn start_node<V>(validator: V, keys: Vec<AuthKey>) -> (Arc<RelayNode<V>>, SocketAddr)
where
    V: PowValidator + Send + Sync + 'static,
{
    start_node_with(validator, keys, Default::default()).await
}

async fn start_node_with<V>(
    validator: V,
    keys: Vec<AuthKey>,
    bound: BoundForwardConfig,
) -> (Arc<RelayNode<V>>, SocketAddr)
where
    V: PowValidator + Send + Sync + 'static,
{
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(keys)
        .with_fec(10, 3)
        .with_bound_raw(bound);
    start_config(config, validator).await
}

async fn start_config<V>(config: RelayConfig, validator: V) -> (Arc<RelayNode<V>>, SocketAddr)
where
    V: PowValidator + Send + Sync + 'static,
{
    let mut node = RelayNode::with_validator(config, validator).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let running = Arc::clone(&node);
    tokio::spawn(async move { running.run().await });
    (node, addr)
}

fn fleet() -> Vec<AuthKey> {
    vec![AuthKey::new("fleet", KEY)]
}

fn config(node: SocketAddr, key: [u8; 32]) -> ClientConfig {
    ClientConfig::new(vec![node], key)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true)
        .with_fec(10, 3)
}

async fn start_receiver(node: SocketAddr, key: [u8; 32]) -> Receiver<BoundBlock> {
    let mut client =
        RelayClient::new(config(node, key).with_bound_raw(BoundRawConfig::default())).unwrap();
    client.bind().await.unwrap();
    let (mut receiver, outgoing) = client.take_receiver().unwrap();
    let blocks = receiver.take_bound_blocks().unwrap();
    tokio::spawn(async move {
        let _keep = receiver;
        client.run_with_outgoing(outgoing).await
    });
    blocks
}

async fn start_sender(node: SocketAddr, key: [u8; 32]) -> BlockSender {
    let mut client = RelayClient::new(config(node, key)).unwrap();
    client.bind().await.unwrap();
    let sender = client.sender();
    tokio::spawn(async move { client.run().await });
    sender
}

async fn sessions_reach<V>(node: &RelayNode<V>, count: usize)
where
    V: PowValidator + Send + Sync + 'static,
{
    timeout(WAIT, async {
        while node.session_count().await < count {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the sessions never came");
}

/// A socket that only watches: a real session by its keepalive, and every datagram it gets.
struct Watcher(UdpSocket);

impl Watcher {
    async fn start(node: SocketAddr, key: [u8; 32]) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = RelaySession::new("0.0.0.0:0".parse().unwrap(), "watcher", key);
        let hmac = session.compute_hmac(&[0; 32], 0, 0, 0, &[]);
        let keepalive = Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new());
        socket.send_to(&keepalive.to_bytes(), node).await.unwrap();
        Self(socket)
    }

    async fn next(&self) -> Vec<u8> {
        let mut buf = vec![0; 2048];
        let (len, _) = timeout(WAIT, self.0.recv_from(&mut buf))
            .await
            .expect("a datagram")
            .unwrap();
        buf.truncate(len);
        buf
    }
}

/// Everything sent so far has been handled: the node reads one socket in order, and it
/// counts a packet as it starts on it, so a later packet counted means the earlier ones
/// are done.
async fn node_has_handled<V>(node: &RelayNode<V>, addr: SocketAddr, socket: &UdpSocket)
where
    V: PowValidator + Send + Sync + 'static,
{
    let before = node.metrics().snapshot().packets_received;
    socket.send_to(b"not a chunk", addr).await.unwrap();
    socket.send_to(b"not a chunk", addr).await.unwrap();
    timeout(WAIT, async {
        while node.metrics().snapshot().packets_received < before + 2 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the node stopped reading");
}

fn the_block() -> Vec<u8> {
    fixtures::mainnet_raw_block()
}

async fn next_block(blocks: &mut Receiver<BoundBlock>) -> BoundBlock {
    timeout(WAIT, blocks.recv())
        .await
        .expect("a block crosses the relay")
        .expect("the channel stays open")
}

async fn send_all(socket: &UdpSocket, to: SocketAddr, datagrams: &[Vec<u8>]) {
    for datagram in datagrams {
        socket.send_to(datagram, to).await.unwrap();
        tokio::task::yield_now().await;
    }
}

/// Each receiver's key is its own and neither is the sender's, so each forward had to be
/// sealed for that session.
#[tokio::test]
async fn each_session_gets_the_block_under_its_own_key() {
    let keys = vec![
        AuthKey::new("sender", KEY),
        AuthKey::new("alice", OTHER_KEY),
        AuthKey::new("bob", [0x44; 32]),
    ];
    let (node, addr) = start_node(StubPowValidator, keys).await;
    let mut alice = start_receiver(addr, OTHER_KEY).await;
    let mut bob = start_receiver(addr, [0x44; 32]).await;
    sessions_reach(&node, 2).await;
    let sender = start_sender(addr, KEY).await;

    let raw = the_block();
    sender
        .send_bound_raw_block(Arc::new(raw.clone()))
        .await
        .unwrap();

    assert_eq!(next_block(&mut alice).await.raw(), raw);
    assert_eq!(next_block(&mut bob).await.raw(), raw);
}

/// The same rule as the legacy path: a receive-only key's content goes nowhere.
#[tokio::test]
async fn a_receive_only_key_is_not_fanned_out() {
    let keys = vec![
        AuthKey::new("fleet", KEY),
        AuthKey::new("invitee", OTHER_KEY).with_role(KeyRole::ReceiveOnly),
    ];
    let (node, addr) = start_node(StubPowValidator, keys).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_all(
        &socket,
        addr,
        &sealed_body(&the_block(), &OTHER_KEY).unwrap(),
    )
    .await;
    node_has_handled(&node, addr, &socket).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(metrics.packets_forwarded, 0);
}

#[tokio::test]
async fn a_header_that_fails_its_pow_check_goes_no_further() {
    let (node, addr) = start_node(RejectAllValidator, fleet()).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_all(&socket, addr, &sealed_body(&the_block(), &KEY).unwrap()).await;
    node_has_handled(&node, addr, &socket).await;

    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
}

/// A later segment proves nothing until its segment 0 has. Sent last here, and the whole
/// body then goes on.
#[tokio::test]
async fn segments_wait_for_their_segment_zero() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let raw = the_block();
    let frames = body_frames(&raw).unwrap();
    assert!(frames.len() > 1);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for frame in frames[1..].iter().rev() {
        send_all(&socket, addr, &sealed_frame(frame, &KEY).unwrap()).await;
    }
    node_has_handled(&node, addr, &socket).await;
    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);

    send_all(&socket, addr, &sealed_frame(&frames[0], &KEY).unwrap()).await;

    assert_eq!(next_block(&mut blocks).await.raw(), raw);
}

/// One session's repeat goes nowhere. Another session's copy crosses, because a node
/// cannot know that a receiver gave a body back and needs it again.
#[tokio::test]
async fn a_session_sends_an_object_on_once_and_another_may_send_it_again() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let datagrams = sealed_body(&the_block(), &KEY).unwrap();

    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_all(&first, addr, &datagrams).await;
    send_all(&first, addr, &datagrams).await;
    node_has_handled(&node, addr, &first).await;
    let once = node.metrics().snapshot().packets_forwarded as usize;
    assert_eq!(once, datagrams.len(), "to the watcher, and only the once");

    send_all(&second, addr, &datagrams).await;
    node_has_handled(&node, addr, &first).await;

    // To the watcher, and to the first sender, which has a session now.
    let forwarded = node.metrics().snapshot().packets_forwarded as usize;
    assert_eq!(forwarded, once + 2 * datagrams.len());
}

/// Sent exactly `k` of each object, the node sends all `n` on.
#[tokio::test]
async fn a_lost_chunk_is_back_for_the_next_hop() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let raw = the_block();
    let frames = body_frames(&raw).unwrap();
    let first = sealed_frame(&frames[0], &KEY).unwrap();
    assert_eq!(first.len(), 13);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_all(&socket, addr, &first[..10]).await;

    for sent in first {
        assert_eq!(
            watcher.next().await,
            sent,
            "the same datagram, the same key"
        );
    }
}

/// The frame's own check, on a node. Its chunks are all honest about the object.
#[tokio::test]
async fn a_forged_frame_stops_at_the_node() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let frames = body_frames(&the_block()).unwrap();
    let mut forged = frames[0].clone();
    *forged.last_mut().unwrap() ^= 0x01;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_all(&socket, addr, &sealed_frame(&forged, &KEY).unwrap()).await;
    node_has_handled(&node, addr, &socket).await;

    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
}

#[tokio::test]
async fn a_datagram_under_an_unknown_key_makes_no_session() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let datagrams = sealed_body(&the_block(), &OTHER_KEY).unwrap();
    assert!(is_bound(&datagrams[0]));
    send_all(&socket, addr, &datagrams[..3]).await;
    node_has_handled(&node, addr, &socket).await;

    assert_eq!(node.session_count().await, 0);
    assert!(node.metrics().snapshot().auth_failures > 0);
}

/// A key taken away takes its path with it: the session goes, and with it what the node
/// held for that session, and the old key opens nothing.
#[tokio::test]
async fn a_revoked_key_loses_its_way_through() {
    let keys = vec![AuthKey::new("fleet", KEY), AuthKey::new("gone", OTHER_KEY)];
    let (node, addr) = start_node(StubPowValidator, keys).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let datagrams = sealed_body(&the_block(), &OTHER_KEY).unwrap();
    send_all(&socket, addr, &datagrams[..3]).await;
    sessions_reach(&node, 2).await;

    node.apply_active_keys(fleet()).await;
    assert_eq!(node.session_count().await, 1);

    send_all(&socket, addr, &datagrams[3..]).await;
    node_has_handled(&node, addr, &socket).await;

    assert_eq!(node.session_count().await, 1);
    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
}

/// Turning it off is a rollback, and needs nothing else: v4 is dropped at decode again.
#[tokio::test]
async fn a_node_without_the_path_drops_it_at_decode() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(fleet())
        .with_fec(10, 3);
    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let running = Arc::clone(&node);
    tokio::spawn(async move { running.run().await });
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_all(&socket, addr, &sealed_body(&the_block(), &KEY).unwrap()).await;
    node_has_handled(&node, addr, &socket).await;

    assert_eq!(node.session_count().await, 1, "no session came of it");
    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
}

// Resends, through a real node. What a node sends on is read off the wire, so a sending that
// stopped early and one that never stopped both show.

/// A socket with a session, sending sealed datagrams as a client would.
async fn raw_session<V>(node: &RelayNode<V>, addr: SocketAddr, datagrams: &[Vec<u8>]) -> UdpSocket
where
    V: PowValidator + Send + Sync + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for datagram in datagrams {
        socket.send_to(datagram, addr).await.unwrap();
    }
    node_has_handled(node, addr, &socket).await;
    socket
}

async fn send_again<V>(node: &RelayNode<V>, addr: SocketAddr, socket: &UdpSocket, data: &[Vec<u8>])
where
    V: PowValidator + Send + Sync + 'static,
{
    for datagram in data {
        socket.send_to(datagram, addr).await.unwrap();
    }
    node_has_handled(node, addr, socket).await;
}

/// How many of `wanted` the watcher gets until it has seen every one of `last`.
async fn count_until_all_of(watcher: &Watcher, wanted: &[Vec<u8>], last: &[Vec<u8>]) -> usize {
    let (mut seen, mut left) = (0, last.len());
    while left > 0 {
        let datagram = watcher.next().await;
        seen += usize::from(wanted.contains(&datagram));
        left -= usize::from(last.contains(&datagram));
    }
    seen
}

fn resends_at_once(max_resends: u32) -> BoundForwardConfig {
    BoundForwardConfig {
        resend_after: Duration::ZERO,
        max_resends,
        ..Default::default()
    }
}

/// However often a session sends one object, the node sends it on as often as it allows.
#[tokio::test]
async fn a_session_resending_for_ever_gets_only_what_the_node_allows() {
    let (node, addr) = start_node_with(StubPowValidator, fleet(), resends_at_once(1)).await;
    let watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let (body, marker) = (
        sealed_body(&[7u8; 5000], &KEY).unwrap(),
        sealed_body(&[9u8; 5000], &KEY).unwrap(),
    );

    let socket = raw_session(&node, addr, &body).await;
    for _ in 0..8 {
        send_again(&node, addr, &socket, &body).await;
    }
    send_again(&node, addr, &socket, &marker).await;

    let seen = count_until_all_of(&watcher, &body, &marker).await;
    assert_eq!(seen, 2 * body.len());
}

/// The same connection gets a second send, which is what recovery on it rests on.
#[tokio::test]
async fn a_session_gets_its_resend() {
    let (node, addr) = start_node_with(StubPowValidator, fleet(), resends_at_once(2)).await;
    let watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let body = sealed_body(&[7u8; 5000], &KEY).unwrap();

    let socket = raw_session(&node, addr, &body).await;
    for _ in 0..body.len() {
        watcher.next().await;
    }
    send_again(&node, addr, &socket, &body).await;

    let again = watcher.next().await;
    assert!(body.contains(&again));
}

/// With the research values a burst and a copy of it right behind are one send.
#[tokio::test]
async fn a_copy_right_behind_a_send_goes_no_further_with_the_research_values() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let (body, marker) = (
        sealed_body(&[7u8; 5000], &KEY).unwrap(),
        sealed_body(&[9u8; 5000], &KEY).unwrap(),
    );

    let socket = raw_session(&node, addr, &body).await;
    send_again(&node, addr, &socket, &body).await;
    send_again(&node, addr, &socket, &marker).await;

    let seen = count_until_all_of(&watcher, &body, &marker).await;
    assert_eq!(seen, body.len());
}

// The node's shared limit, on real sessions. Each socket is a session.

fn small_pool() -> BoundForwardConfig {
    let mut config = BoundForwardConfig::default();
    config.pool.max_sessions = 6;
    config.pool.max_objects = 8;
    config.pool.max_spare_objects = 2;
    config
}

/// Open objects on `sessions` sockets, each stopping one chunk in.
async fn fill_from<V>(node: &RelayNode<V>, addr: SocketAddr, sessions: u8) -> Vec<UdpSocket>
where
    V: PowValidator + Send + Sync + 'static,
{
    let mut sockets = Vec::new();
    for session in 0..sessions {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for object in 0..8u8 {
            let body = sealed_body(&[session.wrapping_mul(16) ^ object; 5000], &KEY).unwrap();
            socket.send_to(&body[0], addr).await.unwrap();
        }
        node_has_handled(node, addr, &socket).await;
        sockets.push(socket);
    }
    sockets
}

#[tokio::test]
async fn sessions_together_cannot_pass_the_nodes_limit() {
    let (node, addr) = start_node_with(StubPowValidator, fleet(), small_pool()).await;
    let config = small_pool();

    let _sockets = fill_from(&node, addr, 12).await;

    let usage = node.bound_usage().unwrap();
    assert!(usage.pool.objects <= config.pool.max_objects, "{usage:?}");
    assert!(
        usage.pool.held_bytes <= config.pool.max_held_bytes,
        "{usage:?}"
    );
    assert_eq!(usage.peers, config.pool.max_sessions);
    assert!(usage.datagrams_without_a_place > 0, "{usage:?}");
    assert!(node.session_count().await >= usage.peers);
}

/// The research values, with every session at its own limit: far more than the pool holds,
/// on as many sessions as it takes. What was 2.25 MiB a session with nothing over them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_research_pool_holds_however_many_sessions_fill_it() {
    // New sources are rate limited ahead of all this, and that is not what is under test.
    let relay = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(fleet())
        .with_fec(10, 3)
        .with_unauth_rate_limit(100_000.0, 100_000.0)
        .with_bound_raw(Default::default());
    let (node, addr) = start_config(relay, StubPowValidator).await;
    let config = BoundForwardConfig::default();

    let mut sockets = Vec::new();
    for session in 0..80u32 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for object in 0..32u32 {
            let mut raw = vec![0u8; 9000];
            raw[..4].copy_from_slice(&session.to_le_bytes());
            raw[4..8].copy_from_slice(&object.to_le_bytes());
            let body = sealed_body(&raw, &KEY).unwrap();
            socket.send_to(&body[0], addr).await.unwrap();
        }
        node_has_handled(&node, addr, &socket).await;
        sockets.push(socket);
    }

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.peers, 80);
    assert!(usage.pool.objects <= config.pool.max_objects, "{usage:?}");
    assert!(
        usage.pool.held_bytes <= config.pool.max_held_bytes,
        "{usage:?}"
    );
    assert!(
        usage.pool.held_bytes > config.pool.max_held_bytes / 2,
        "the sessions were meant to press on the limit: {usage:?}"
    );
}

/// A session with little held keeps going while others have filled the pool, which is what
/// separate budgets used to give and a plain shared one would take away.
#[tokio::test]
async fn a_full_pool_leaves_a_quiet_session_its_share() {
    let (node, addr) = start_node_with(StubPowValidator, fleet(), small_pool()).await;
    let watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let body = sealed_body(&[0xee; 5000], &KEY).unwrap();
    let quiet = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    quiet.send_to(&body[0], addr).await.unwrap();
    node_has_handled(&node, addr, &quiet).await;

    let _sockets = fill_from(&node, addr, 5).await;
    assert_eq!(
        node.bound_usage().unwrap().pool.objects,
        small_pool().pool.max_objects
    );

    send_again(&node, addr, &quiet, &body[1..]).await;

    let first = watcher.next().await;
    assert!(body.contains(&first));
}

/// Eviction by key is the node's own, and reaches the pool at once.
#[tokio::test]
async fn revoked_sessions_give_the_pool_back() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let _sockets = fill_from(&node, addr, 6).await;
    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.peers, 6);
    assert!(usage.pool.held_bytes > 0);

    node.apply_active_keys(Vec::new()).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.pool, BoundUsed::default());
    assert_eq!(usage.peers, 0);
}

/// Sessions that fall silent reach the pool by the node's own cleanup, which runs on a timer
/// of its own.
#[tokio::test]
async fn sessions_that_time_out_give_the_pool_back() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(fleet())
        .with_fec(10, 3)
        .with_timeouts(Duration::from_millis(50), Duration::from_secs(30))
        .with_bound_raw(Default::default());
    let (node, addr) = start_config(config, StubPowValidator).await;
    let _sockets = fill_from(&node, addr, 3).await;
    assert_eq!(node.bound_usage().unwrap().peers, 3);

    timeout(Duration::from_secs(30), async {
        while node.bound_usage().unwrap().pool != BoundUsed::default() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the pool never came back");
    assert_eq!(node.bound_usage().unwrap().peers, 0);
}

/// Every place taken by sessions that keep theirs stops a new session here, as `max_sessions`
/// does on the legacy path. It comes back when one goes.
#[tokio::test]
async fn known_gap_a_full_session_table_turns_a_new_session_away() {
    let (node, addr) = start_node_with(StubPowValidator, fleet(), small_pool()).await;
    let _sockets = fill_from(&node, addr, 6).await;

    let body = sealed_body(&[0xee; 5000], &KEY).unwrap();
    let late = raw_session(&node, addr, &body).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.peers, small_pool().pool.max_sessions);
    assert!(
        usage.datagrams_without_a_place >= body.len() as u64,
        "{usage:?}"
    );
    drop(late);
}
