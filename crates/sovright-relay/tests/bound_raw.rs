//! #130 PR B: the bound raw path on a real node and real clients over UDP loopback. What a
//! node does with the candidate format, with keys, sessions and PoW as they are. The format
//! is a candidate, and these tests are no specification of it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sovright_relay::{
    AuthKey, BOUND_HELLO_ACK, BlockSender, BoundBlock, BoundForwardConfig, BoundRawConfig,
    BoundUsed, Chunk, ChunkHeader, ClientConfig, EquihashPowValidator, KeyRole,
    MAX_BODIES_PER_KEY_PER_BLOCK, PowResult, PowValidator, RELEASE_LEFTOVER, RejectAllValidator,
    RelayClient, RelayConfig, RelayNode, RelaySession, StubPowValidator, ZCASH_FULL_HEADER_SIZE,
    body_frames, bound_hello, is_bound, reassemble_raw_block, sealed_body, sealed_frame,
    split_raw_block, zcash_block_hash,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::error::Elapsed;
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

const KEY: [u8; 32] = [0x42; 32];
const OTHER_KEY: [u8; 32] = [0x43; 32];
const WAIT: Duration = Duration::from_secs(10);
/// Long enough for a wait that should still be waiting to have stopped if it were wrong. A
/// wait that is right is held by a gate or by what never came, so this can only be too short.
const STILL_WAITING: Duration = Duration::from_millis(200);

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

fn keepalive_bytes(key: [u8; 32]) -> Vec<u8> {
    let session = RelaySession::new("0.0.0.0:0".parse().unwrap(), "watcher", key);
    let hmac = session.compute_hmac(&[0; 32], 0, 0, 0, &[]);
    Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new()).to_bytes()
}

fn is_hello_ack(datagram: &[u8]) -> bool {
    !is_bound(datagram)
        && Chunk::from_bytes(datagram).is_ok_and(|chunk| chunk.header.block_hash == BOUND_HELLO_ACK)
}

/// A socket that only watches: a real session by its keepalive and its bound hello, and every
/// datagram it gets.
struct Watcher(UdpSocket);

impl Watcher {
    async fn start(node: SocketAddr, key: [u8; 32]) -> Self {
        let watcher = Self::legacy(node, key).await;
        watcher
            .0
            .send_to(&bound_hello(&key, true), node)
            .await
            .unwrap();
        assert!(
            is_hello_ack(&watcher.next().await),
            "the node did not answer the hello"
        );
        watcher
    }

    /// A session that never says it takes bound objects, as one from before the bound path.
    async fn legacy(node: SocketAddr, key: [u8; 32]) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(&keepalive_bytes(key), node).await.unwrap();
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

/// Packets the node has started on.
fn received<V>(node: &RelayNode<V>) -> u64
where
    V: PowValidator + Send + Sync + 'static,
{
    node.metrics().snapshot().packets_received
}

/// How many times the node will have finished with each of `datagrams` from `from` once
/// they are all done. Read before sending, and it holds for repeats too.
fn once_finished<'a, V>(
    node: &RelayNode<V>,
    from: SocketAddr,
    datagrams: impl IntoIterator<Item = &'a Vec<u8>>,
) -> HashMap<&'a [u8], u64>
where
    V: PowValidator + Send + Sync + 'static,
{
    let mut wanted = HashMap::new();
    for datagram in datagrams {
        *wanted
            .entry(datagram.as_slice())
            .or_insert_with(|| node.times_finished(from, datagram)) += 1;
    }
    wanted
}

/// The node has finished with exactly these datagrams from `from`, whatever came in what
/// order and whatever else reached it. UDP promises neither order nor arrival, so one that
/// never gets there runs this out, and no test passes on it.
async fn finished_within<V>(
    node: &RelayNode<V>,
    from: SocketAddr,
    wanted: &HashMap<&[u8], u64>,
    wait: Duration,
) -> Result<(), Elapsed>
where
    V: PowValidator + Send + Sync + 'static,
{
    timeout(wait, async {
        while !all_finished(node, from, wanted) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
}

/// Whether [`finished_within`] would be done. This one needs no timer, so it can be asked with
/// the gate shut.
fn all_finished<V>(node: &RelayNode<V>, from: SocketAddr, wanted: &HashMap<&[u8], u64>) -> bool
where
    V: PowValidator + Send + Sync + 'static,
{
    let mut left = wanted.iter();
    left.all(|(datagram, times)| node.times_finished(from, datagram) >= *times)
}

fn the_block() -> Vec<u8> {
    fixtures::mainnet_raw_block()
}

/// Where a header's time is.
const HEADER_TIME: std::ops::Range<usize> = 100..104;

/// `raw` with the time of [`the_block`]'s header, so neither looks old next to the other.
/// See `sovright_relay::ANCHOR_HEADER_WINDOW`.
fn dated_as_the_block(mut raw: Vec<u8>) -> Vec<u8> {
    raw[HEADER_TIME].copy_from_slice(&the_block()[HEADER_TIME]);
    raw
}

fn header_time(header: &[u8]) -> u32 {
    u32::from_le_bytes(header[HEADER_TIME].try_into().unwrap())
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

/// A node with the path on, and receivers from before it, which never send a hello. A legacy
/// client still gets the whole block the legacy way, and a bare legacy session gets not one
/// bound datagram, while a receiver with the path gets the bound copy of the same block.
#[tokio::test]
async fn a_legacy_receiver_gets_the_block_and_nothing_bound() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let old = Watcher::legacy(addr, KEY).await;
    let mut legacy_client = RelayClient::new(config(addr, KEY)).unwrap();
    legacy_client.bind().await.unwrap();
    let (mut legacy, outgoing) = legacy_client.take_receiver().unwrap();
    tokio::spawn(async move { legacy_client.run_with_outgoing(outgoing).await });
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 3).await;
    let sender = start_sender(addr, KEY).await;
    let raw = the_block();
    let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
    let segments = split_raw_block(hash, &raw, 10 * 1124 - 4).unwrap();

    for segment in segments.clone() {
        sender.send_raw_block_segment(segment).await.unwrap();
    }
    let send = sender.send_bound_raw_block(Arc::new(raw.clone()));
    timeout(WAIT, send).await.unwrap().unwrap();

    assert_eq!(next_block(&mut blocks).await.raw(), raw);
    let mut got = Vec::new();
    while got.len() < segments.len() {
        let segment = timeout(WAIT, legacy.recv_raw_block_segment()).await;
        got.push(segment.expect("the legacy client got the block").unwrap());
    }
    assert_eq!(reassemble_raw_block(&got).unwrap(), raw);
    let mut buf = vec![0; 2048];
    while let Ok(read) = timeout(STILL_WAITING, old.0.recv_from(&mut buf)).await {
        let datagram = &buf[..read.unwrap().0];
        assert!(!is_bound(datagram), "a legacy session got a bound datagram");
    }
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

    raw_session(&node, addr, &sealed_body(&the_block(), &OTHER_KEY).unwrap()).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(metrics.packets_forwarded, 0);
}

fn keys_with_an_invitee() -> Vec<AuthKey> {
    vec![
        AuthKey::new("fleet", KEY),
        AuthKey::new("invitee", OTHER_KEY).with_role(KeyRole::ReceiveOnly),
    ]
}

/// Later segments of a Full session wait for segment 0. The same segment 0 under a
/// receive-only key sends nothing on, and leaves them waiting for the Full session's own.
#[tokio::test]
async fn a_receive_only_session_cannot_spend_what_a_full_session_left_waiting() {
    let (node, addr) = start_node(StubPowValidator, keys_with_an_invitee()).await;
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let raw = the_block();
    let frames = body_frames(&raw).unwrap();
    let (first, later) = frames.split_first().unwrap();
    let later: Vec<Vec<u8>> = later
        .iter()
        .flat_map(|frame| sealed_frame(frame, &KEY).unwrap())
        .collect();

    let full = raw_session(&node, addr, &later).await;
    raw_session(&node, addr, &sealed_frame(first, &OTHER_KEY).unwrap()).await;
    send_again(&node, addr, &full, &sealed_frame(first, &KEY).unwrap()).await;

    assert_eq!(next_block(&mut blocks).await.raw(), raw);
}

/// What a receive-only key sends is authenticated and counted, and it takes up nothing
/// other sessions share.
#[tokio::test]
async fn a_receive_only_session_holds_nothing_on_the_node() {
    let (node, addr) = start_node(StubPowValidator, keys_with_an_invitee()).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let datagrams = sealed_body(&the_block(), &OTHER_KEY).unwrap();

    raw_session(&node, addr, &datagrams).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.pool, BoundUsed::default());
    assert_eq!(usage.peers, 0);
    assert_eq!(usage.objects_sent_on, 0);
    let metrics = node.metrics().snapshot();
    assert_eq!(metrics.packets_forwarded, 0);
    assert_eq!(metrics.receive_only_chunks_dropped, datagrams.len() as u64);
}

/// The MAC is checked the same as it was: a forged chunk from a session under a
/// receive-only key is an invalid chunk, not one more dropped chunk.
#[tokio::test]
async fn a_forged_chunk_from_a_receive_only_session_is_refused() {
    let (node, addr) = start_node(StubPowValidator, keys_with_an_invitee()).await;
    let raw = the_block();
    let sealed = sealed_body(&raw, &OTHER_KEY).unwrap();
    let socket = raw_session(&node, addr, &sealed[..1]).await;
    let dropped = node.metrics().snapshot().receive_only_chunks_dropped;

    send_again(&node, addr, &socket, &sealed_body(&raw, &KEY).unwrap()[..1]).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(metrics.invalid_chunks, 1);
    assert_eq!(metrics.receive_only_chunks_dropped, dropped);
}

/// That direction is the point of the role, and it is not what changes here.
#[tokio::test]
async fn a_receive_only_session_still_gets_what_a_full_session_sends() {
    let (node, addr) = start_node(StubPowValidator, keys_with_an_invitee()).await;
    let mut blocks = start_receiver(addr, OTHER_KEY).await;
    sessions_reach(&node, 1).await;
    let raw = the_block();

    raw_session(&node, addr, &sealed_body(&raw, &KEY).unwrap()).await;

    assert_eq!(next_block(&mut blocks).await.raw(), raw);
}

/// Nine chunks of a body, thirty-nine objects that stop at a chunk, and its tenth chunk: the
/// node's places for a session are full and the body is the oldest on its shelf. It goes
/// on, and the node is still there for the next one.
#[tokio::test]
async fn a_full_table_and_shelf_cost_a_real_node_nothing() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let raw = dated_as_the_block(vec![200u8; 5000]);
    let sealed = sealed_body(&raw, &KEY).unwrap();
    let crowd: Vec<Vec<u8>> = (0..39u8)
        .map(|fill| sealed_body(&[fill; 5000], &KEY).unwrap().swap_remove(0))
        .collect();

    let socket = raw_session(&node, addr, &sealed[..9]).await;
    send_again(&node, addr, &socket, &crowd).await;
    send_again(&node, addr, &socket, &sealed[9..10]).await;

    assert_eq!(next_block(&mut blocks).await.raw(), raw);
    let next = the_block();
    send_again(&node, addr, &socket, &sealed_body(&next, &KEY).unwrap()).await;
    assert_eq!(next_block(&mut blocks).await.raw(), next);
}

#[tokio::test]
async fn a_header_that_fails_its_pow_check_goes_no_further() {
    let (node, addr) = start_node(RejectAllValidator, fleet()).await;
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;

    raw_session(&node, addr, &sealed_body(&the_block(), &KEY).unwrap()).await;

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

    let later: Vec<Vec<u8>> = frames[1..]
        .iter()
        .rev()
        .flat_map(|frame| sealed_frame(frame, &KEY).unwrap())
        .collect();
    let socket = raw_session(&node, addr, &later).await;
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

    let first = raw_session(&node, addr, &datagrams).await;
    send_again(&node, addr, &first, &datagrams).await;
    let once = node.metrics().snapshot().packets_forwarded as usize;
    assert_eq!(once, datagrams.len(), "to the watcher, and only the once");

    raw_session(&node, addr, &datagrams).await;

    // To the watcher again. The first sender has a session now, but it never said it takes
    // bound objects, so it gets none.
    let forwarded = node.metrics().snapshot().packets_forwarded as usize;
    assert_eq!(forwarded, once + datagrams.len());
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

    raw_session(&node, addr, &sealed_frame(&forged, &KEY).unwrap()).await;

    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
}

#[tokio::test]
async fn a_datagram_under_an_unknown_key_makes_no_session() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;

    let datagrams = sealed_body(&the_block(), &OTHER_KEY).unwrap();
    assert!(is_bound(&datagrams[0]));
    raw_session(&node, addr, &datagrams[..3]).await;

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

    send_again(&node, addr, &socket, &datagrams[3..]).await;

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
    let watcher = Watcher::legacy(addr, KEY).await;
    sessions_reach(&node, 1).await;
    watcher
        .0
        .send_to(&bound_hello(&KEY, true), addr)
        .await
        .unwrap();

    raw_session(&node, addr, &sealed_body(&the_block(), &KEY).unwrap()).await;

    assert_eq!(node.session_count().await, 1, "no session came of it");
    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
    let mut buf = [0; 2048];
    let answer = timeout(STILL_WAITING, watcher.0.recv_from(&mut buf)).await;
    assert!(answer.is_err(), "a node without the path answered a hello");
}

/// Stops a node inside its PoW check until it is told to go on, so a test knows which packet
/// the node is on.
///
/// This holds a worker of the runtime, synchronously. While it does, nothing may be asked of
/// the runtime that needs that worker: a new socket's readiness, or a timer, comes from a
/// worker polling the driver. If this one was the one, nobody is, and a test waiting on it
/// never opens the gate. So with the gate shut a test does only what needs no runtime: it
/// sends on a [`PlainSocket`], looks at counters and waits at [`reaches_gate`]. These tests run
/// on one worker, so that anything else fails every time and not once in a while.
///
/// A gate left shut gives up in the end. That frees the worker, and the node gets over it and
/// goes on, so the stop could pass unseen. So the gate says it gave up, and the test hears it.
struct Gate {
    reached: UnboundedSender<AtGate>,
    open: Mutex<std::sync::mpsc::Receiver<()>>,
}

/// What a [`Gate`] tells its test.
#[derive(Debug, PartialEq)]
enum AtGate {
    Reached,
    GaveUp,
}

impl PowValidator for Gate {
    fn validate(&self, _header: &[u8]) -> PowResult {
        // A test that went wrong has dropped its end, and that lets the node go as well.
        let _ = self.reached.send(AtGate::Reached);
        let open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        match open.recv_timeout(WAIT) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => PowResult::Valid,
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.reached.send(AtGate::GaveUp);
                panic!("the test did not open the gate")
            }
        }
    }
}

/// A socket that sends with the runtime held: a send here returns by itself, with nothing to
/// wait for from a driver. The tokio one is the same socket, for all that needs waiting.
struct PlainSocket(std::net::UdpSocket);

impl PlainSocket {
    fn bind() -> (Self, UdpSocket) {
        let plain = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        plain.set_nonblocking(true).unwrap();
        let socket = UdpSocket::from_std(plain.try_clone().unwrap()).unwrap();
        (Self(plain), socket)
    }

    fn send(&self, to: SocketAddr, datagrams: &[Vec<u8>]) {
        for datagram in datagrams {
            self.0.send_to(datagram, to).unwrap();
        }
    }
}

/// A keepalive to send with the gate shut, on a socket bound before it was.
fn keepalive_ready() -> (PlainSocket, Vec<u8>) {
    let (plain, _) = PlainSocket::bind();
    (plain, keepalive_bytes(KEY))
}

/// What a test that is stuck can say of how far the node got. The node holds the bound path's
/// lock at the gate, so this reads nothing behind it: `bound_usage` here would stick as well.
fn progress<V>(node: &RelayNode<V>) -> String
where
    V: PowValidator + Send + Sync + 'static,
{
    let metrics = node.metrics().snapshot();
    format!(
        "{} packets received, {} forwarded, {} invalid chunks",
        metrics.packets_received, metrics.packets_forwarded, metrics.invalid_chunks
    )
}

/// Waits for the node to reach the gate, no longer than any other wait here. `stage` says
/// which arrival this was meant to be.
async fn reaches_gate<V>(at_gate: &mut UnboundedReceiver<AtGate>, node: &RelayNode<V>, stage: &str)
where
    V: PowValidator + Send + Sync + 'static,
{
    match timeout(WAIT, at_gate.recv()).await {
        Ok(Some(AtGate::Reached)) => {}
        Ok(Some(AtGate::GaveUp)) => {
            panic!(
                "{stage}: the gate gave up with the test away, {}",
                progress(node)
            )
        }
        Ok(None) => panic!("{stage}: the gate is gone, {}", progress(node)),
        Err(_) => panic!(
            "{stage}: no arrival at the gate in {WAIT:?}, {}",
            progress(node)
        ),
    }
}

fn gated() -> (Gate, UnboundedReceiver<AtGate>, std::sync::mpsc::Sender<()>) {
    let (reached, at_gate) = unbounded_channel();
    let (open, gate) = std::sync::mpsc::channel();
    let gate = Gate {
        reached,
        open: Mutex::new(gate),
    };
    (gate, at_gate, open)
}

fn sealed(fill: u8) -> Vec<Vec<u8>> {
    sealed_body(&[fill; 5000], &KEY).unwrap()
}

/// The node is held on its twentieth packet with nine more behind it, and the old wait, two
/// more packets counted, would be back all the same: packets already queued gave it its two. A
/// test that looked then for something not sent on would have passed with the packets that
/// matter still unread. The wait these tests use holds on until those packets are finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn two_more_packets_counted_can_leave_the_rest_unread() {
    let (gate, mut at_gate, open) = gated();
    let (node, addr) = start_node(gate, fleet()).await;
    let (plain, socket) = PlainSocket::bind();
    let from = socket.local_addr().unwrap();
    let (first, second, third) = (sealed(1), sealed(2), sealed(3));
    let wanted = once_finished(&node, from, second[..10].iter().chain(&third[..9]));

    send_all(&socket, addr, &first[..10]).await;
    reaches_gate(&mut at_gate, &node, "the first body's segment 0").await;
    assert_eq!(received(&node), 10);
    plain.send(addr, &second[..10]);
    plain.send(addr, &third[..9]);
    plain.send(addr, &[b"not a chunk".to_vec(), b"not a chunk".to_vec()]);
    let old_wait_ends_at = received(&node) + 2;

    open.send(()).unwrap();
    reaches_gate(&mut at_gate, &node, "the second body's segment 0").await;

    assert!(received(&node) >= old_wait_ends_at, "the old wait is over");
    assert_eq!(received(&node), 20, "and 11 of what was sent still unread");
    assert_eq!(node.times_finished(from, &second[8]), 1);
    assert_eq!(
        node.times_finished(from, &second[9]),
        0,
        "started, not done"
    );
    assert!(
        !all_finished(&node, from, &wanted),
        "the node has not been let on"
    );

    open.send(()).unwrap();
    let finished = finished_within(&node, from, &wanted, WAIT).await;
    assert!(
        finished.is_ok(),
        "the packets behind the gate never finished: {}",
        progress(&node)
    );
    assert_eq!(at_gate.try_recv().ok(), None, "no gate gave up at the end");
    assert_eq!(node.times_finished(from, &third[8]), 1);
    assert_eq!(node.bound_usage().unwrap().pool.objects, 1);
}

/// A test sends two packets, and a keepalive it knows nothing of takes the place of one in the
/// count. The count says done with the second one still unread, and one of them a repeat of
/// something already finished. Waiting for the packets themselves is not fooled by either.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_keepalive_can_fill_a_count_and_not_this_wait() {
    let (gate, mut at_gate, open) = gated();
    let (node, addr) = start_node(gate, fleet()).await;
    let (plain, socket) = PlainSocket::bind();
    let (watcher, keepalive) = keepalive_ready();
    let from = socket.local_addr().unwrap();
    let (first, second, third) = (sealed(1), sealed(2), sealed(3));
    let repeated = third[0].clone();
    send_again(&node, addr, &socket, std::slice::from_ref(&repeated)).await;
    send_again(&node, addr, &socket, &second[..9]).await;

    send_all(&socket, addr, &first[..10]).await;
    reaches_gate(&mut at_gate, &node, "the first body's segment 0").await;
    let (held_on, sent) = (second[9].clone(), [second[9].clone(), repeated.clone()]);
    let count_met_at = received(&node) + sent.len() as u64;
    let wanted = once_finished(&node, from, &sent);
    assert_eq!(wanted[repeated.as_slice()], 2);

    watcher.send(addr, std::slice::from_ref(&keepalive));
    plain.send(addr, &sent);
    open.send(()).unwrap();
    reaches_gate(&mut at_gate, &node, "the second body, behind the keepalive").await;

    assert_eq!(received(&node), count_met_at, "the count says done");
    assert_eq!(
        node.session_count().await,
        2,
        "the keepalive was one of them"
    );
    assert_eq!(node.times_finished(from, &held_on), 0);
    assert_eq!(
        node.times_finished(from, &repeated),
        1,
        "the first copy only"
    );
    assert!(
        !all_finished(&node, from, &wanted),
        "those two are not finished"
    );

    open.send(()).unwrap();
    let finished = finished_within(&node, from, &wanted, WAIT).await;
    assert!(
        finished.is_ok(),
        "the two packets behind the gate never finished: {}",
        progress(&node)
    );
    assert_eq!(at_gate.try_recv().ok(), None, "no gate gave up at the end");
}

/// The node gets over a gate that gave up, so without this nobody would know it had.
#[test]
fn a_gate_that_gives_up_tells_its_test() {
    let (gate, mut at_gate, open) = gated();
    let held = std::thread::spawn(move || gate.validate(&[]));

    assert_eq!(at_gate.blocking_recv(), Some(AtGate::Reached));
    assert_eq!(at_gate.blocking_recv(), Some(AtGate::GaveUp));

    assert!(held.join().is_err(), "and the node's worker is let go");
    drop(open);
}

/// A test that goes wrong with the gate shut must not leave the node stopped behind it.
#[test]
fn a_gate_lets_the_node_go_when_its_test_has_gone() {
    let (gate, mut at_gate, open) = gated();
    let held = std::thread::spawn(move || [gate.validate(&[]), gate.validate(&[])]);
    at_gate.blocking_recv().unwrap();

    // One was inside when the test left, and one comes after it.
    drop((at_gate, open));

    let results = held.join().unwrap();
    assert!(
        results
            .iter()
            .all(|result| matches!(result, PowResult::Valid))
    );
}

/// One that never came runs the wait out, and so does the same bytes from another socket.
#[tokio::test]
async fn a_packet_that_never_came_runs_the_wait_out() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let body = sealed(1);
    let socket = raw_session(&node, addr, &body[..1]).await;
    let from = socket.local_addr().unwrap();
    let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();

    let never_sent = once_finished(&node, from, &body[1..2]);
    let lost = finished_within(&node, from, &never_sent, STILL_WAITING).await;
    assert!(lost.is_err());

    let other_source = once_finished(&node, elsewhere, &body[..1]);
    let lost = finished_within(&node, elsewhere, &other_source, STILL_WAITING).await;
    assert!(lost.is_err());

    let repeat = once_finished(&node, from, &body[..1]);
    let lost = finished_within(&node, from, &repeat, STILL_WAITING).await;
    assert!(lost.is_err(), "it has to finish again");
}

// Resends, through a real node. What a node sends on is read off the wire, so a sending that
// stopped early and one that never stopped both show.

/// A socket with a session, sending sealed datagrams as a client would.
async fn raw_session<V>(node: &RelayNode<V>, addr: SocketAddr, datagrams: &[Vec<u8>]) -> UdpSocket
where
    V: PowValidator + Send + Sync + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_again(node, addr, &socket, datagrams).await;
    socket
}

async fn send_again<V>(node: &RelayNode<V>, addr: SocketAddr, socket: &UdpSocket, data: &[Vec<u8>])
where
    V: PowValidator + Send + Sync + 'static,
{
    let from = socket.local_addr().unwrap();
    let wanted = once_finished(node, from, data);
    for datagram in data {
        socket.send_to(datagram, addr).await.unwrap();
    }
    finished_within(node, from, &wanted, WAIT)
        .await
        .expect("the node did not finish with everything sent");
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
        let firsts: Vec<Vec<u8>> = (0..8u8)
            .map(|object| {
                let fill = session.wrapping_mul(16) ^ object;
                sealed_body(&[fill; 5000], &KEY).unwrap().swap_remove(0)
            })
            .collect();
        sockets.push(raw_session(node, addr, &firsts).await);
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
    // No key can fill the pool alone, so it takes several.
    let key_of = |session: u32| [session as u8 % 8 + 1; 32];
    let keys = (0..8)
        .map(|at| AuthKey::new(format!("key{at}"), key_of(at)))
        .collect();
    let config = BoundForwardConfig::default();
    let (node, addr) = start_config(relay_for(keys, config), StubPowValidator).await;

    let mut sockets = Vec::new();
    for session in 0..80u32 {
        let firsts: Vec<Vec<u8>> = (0..32u32)
            .map(|object| {
                let mut raw = vec![0u8; 9000];
                raw[..4].copy_from_slice(&session.to_le_bytes());
                raw[4..8].copy_from_slice(&object.to_le_bytes());
                sealed_body(&raw, &key_of(session)).unwrap().swap_remove(0)
            })
            .collect();
        sockets.push(raw_session(&node, addr, &firsts).await);
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
    let quiet = raw_session(&node, addr, &body[..1]).await;

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

fn three_sessions_a_key() -> BoundForwardConfig {
    let mut config = BoundForwardConfig::default();
    config.key_budget.max_sessions = 3;
    config
}

/// A source port costs nothing, so one key on many of them is still one key.
#[tokio::test]
async fn one_key_on_many_real_ports_stops_at_its_limit() {
    let (node, addr) = start_node_with(StubPowValidator, fleet(), three_sessions_a_key()).await;

    let _sockets = fill_from(&node, addr, 6).await;

    assert_eq!(node.bound_usage().unwrap().peers, 3);
    assert_eq!(node.session_count().await, 3);
}

#[tokio::test]
async fn another_key_gets_through_a_real_node_when_one_key_is_at_its_limit() {
    let mut limits = three_sessions_a_key();
    limits.pool.max_sessions = 4;
    let keys = vec![AuthKey::new("fleet", KEY), AuthKey::new("alice", OTHER_KEY)];
    let (node, addr) = start_config(relay_for(keys, limits), StubPowValidator).await;
    let _sockets = fill_from(&node, addr, 6).await;

    let body = sealed_body(&[0xee; 5000], &OTHER_KEY).unwrap();
    let _alice = raw_session(&node, addr, &body).await;

    assert_eq!(node.bound_usage().unwrap().objects_released, 1);
}

/// A ReceiveOnly key never reaches the pool, and its sessions still take places in the
/// node's table.
#[tokio::test]
async fn a_receive_only_key_on_many_ports_stops_at_its_limit() {
    let keys = vec![AuthKey::new("invitee", OTHER_KEY).with_role(KeyRole::ReceiveOnly)];
    let (node, addr) = start_node_with(StubPowValidator, keys, three_sessions_a_key()).await;
    let body = sealed_body(&[0xee; 5000], &OTHER_KEY).unwrap();

    let mut sockets = Vec::new();
    for _ in 0..6 {
        sockets.push(raw_session(&node, addr, &body[..1]).await);
    }

    assert_eq!(node.session_count().await, 3);
}

/// About 200 KB declared in one datagram, on the shape no sender uses. It does not start a
/// session, so it reserves nothing.
#[tokio::test]
async fn a_shape_no_sender_uses_makes_no_session() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let large = chunk_proof::object::encode(3, 256, 227, &vec![1; 195_000]).unwrap();
    let datagram = chunk_proof::datagram::seal(
        &KEY,
        &large.shape,
        &large.object_id,
        0,
        &large.proofs[0],
        &large.shards[0],
    );

    let _socket = raw_session(&node, addr, &[datagram]).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.peers, 0);
    assert_eq!(usage.pool, BoundUsed::default());
}

/// With a key at each of its limits, across its ports.
#[tokio::test]
async fn one_key_on_many_real_ports_stays_inside_its_budget() {
    let mut limits = three_sessions_a_key();
    limits.key_budget.max_objects = 4;
    limits.key_budget.max_spare_objects = 2;
    let (node, addr) = start_node_with(StubPowValidator, fleet(), limits).await;

    let _sockets = fill_from(&node, addr, 6).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.pool.sessions, 3);
    assert_eq!(usage.pool.objects, 4);
    assert_eq!(usage.pool.spare_objects, 2);
}

/// One object past both the table and the shelf: that one is refused, and the body that was
/// here loses nothing and goes on.
#[tokio::test]
async fn a_full_shelf_on_a_real_node_refuses_the_next_object_and_keeps_the_body() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let raw = vec![200u8; 5000];
    let sealed = sealed_body(&raw, &KEY).unwrap();
    let crowd: Vec<Vec<u8>> = (0..40u8)
        .map(|fill| sealed_body(&[fill; 5000], &KEY).unwrap().swap_remove(0))
        .collect();

    let socket = raw_session(&node, addr, &sealed[..9]).await;
    send_again(&node, addr, &socket, &crowd).await;

    assert_eq!(
        node.bound_usage().unwrap().arrivals.refused_for_objects,
        1,
        "the one past both"
    );
    send_again(&node, addr, &socket, &sealed[9..10]).await;
    assert_eq!(next_block(&mut blocks).await.raw(), raw);
}

fn relay_for(keys: Vec<AuthKey>, limits: BoundForwardConfig) -> RelayConfig {
    // New sources are rate limited ahead of all this, and that is not what is under test.
    RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(keys)
        .with_fec(10, 3)
        .with_unauth_rate_limit(100_000.0, 100_000.0)
        .with_bound_raw(limits)
}

/// A key at its limit that is revoked leaves nothing, and when it comes back it has all of
/// its places again.
#[tokio::test]
async fn a_revoked_key_gives_all_of_its_limit_back() {
    let relay = relay_for(fleet(), three_sessions_a_key());
    let (node, addr) = start_config(relay, StubPowValidator).await;
    let _first = fill_from(&node, addr, 6).await;
    assert_eq!(node.bound_usage().unwrap().peers, 3);

    node.apply_active_keys(Vec::new()).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.pool, BoundUsed::default());
    assert_eq!(usage.peers, 0);
    assert_eq!(node.session_count().await, 0);

    node.apply_active_keys(fleet()).await;
    let _again = fill_from(&node, addr, 6).await;
    assert_eq!(node.bound_usage().unwrap().peers, 3);
    assert_eq!(node.session_count().await, 3);
}

/// The only place a key has, held by a session that falls silent. Once the node's own cleanup
/// has been round, another session of that key gets it.
#[tokio::test]
async fn a_session_that_times_out_gives_its_key_room_back() {
    let mut limits = BoundForwardConfig::default();
    limits.key_budget.max_sessions = 1;
    let relay = relay_for(fleet(), limits)
        .with_timeouts(Duration::from_millis(500), Duration::from_secs(30));
    let (node, addr) = start_config(relay, StubPowValidator).await;
    let _silent = fill_from(&node, addr, 1).await;
    let body = sealed_body(&[0xee; 5000], &KEY).unwrap();
    let late = raw_session(&node, addr, &body).await;
    assert_eq!(node.bound_usage().unwrap().objects_released, 0);

    timeout(Duration::from_secs(30), async {
        while node.bound_usage().unwrap().pool != BoundUsed::default() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the place never came back");

    send_again(&node, addr, &late, &body).await;
    assert_eq!(node.bound_usage().unwrap().objects_released, 1);
}

/// Real headers from genesis on, each with its real proof of work. The node has no way to
/// tell how old they are, so each opens an anchor. See the plan's recent parent decision.
fn old_headers() -> Vec<Vec<u8>> {
    let listed: Vec<serde_json::Value> =
        serde_json::from_str(fixtures::EQUIHASH_MAINNET_HEADERS).unwrap();
    listed
        .iter()
        .map(|entry| hex::decode(entry["header"].as_str().unwrap()).unwrap())
        .collect()
}

fn on_a_header(header: &[u8], length: usize) -> Vec<u8> {
    let mut raw = header.to_vec();
    raw.resize(length, 7);
    raw
}

/// The review's finding, with what it takes to carry it out: real old headers, through the
/// real check. A body in flight goes on with its anchor.
#[tokio::test]
async fn old_headers_cannot_take_an_active_bodys_anchor() {
    let limits = BoundForwardConfig {
        max_anchors: 4,
        max_anchors_per_key: 2,
        ..Default::default()
    };
    let keys = vec![AuthKey::new("fleet", KEY), AuthKey::new("alice", OTHER_KEY)];
    let (node, addr) = start_config(relay_for(keys, limits), EquihashPowValidator).await;
    let raw = on_a_header(&fixtures::mainnet_serialized_header(), 12_000);
    let frames = body_frames(&raw).unwrap();
    let first = sealed_frame(&frames[0], &KEY).unwrap();
    let later = sealed_frame(&frames[1], &KEY).unwrap();
    let honest = raw_session(&node, addr, &first).await;
    assert_eq!(node.bound_usage().unwrap().objects_released, 1);

    // Those older than the honest header: one newer would rightly make it old.
    let honest_time = header_time(&raw);
    let older: Vec<_> = old_headers()
        .into_iter()
        .filter(|header| header_time(header) < honest_time)
        .collect();
    let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for header in &older {
        let sealed = sealed_body(&on_a_header(header, 5000), &OTHER_KEY).unwrap();
        send_again(&node, addr, &flood, &sealed).await;
    }
    let sent = node.bound_usage().unwrap().objects_released;

    send_again(&node, addr, &honest, &later).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, sent + 1, "{usage:?}");
    assert_eq!(usage.objects_waiting_for_segment_0, 0);
    assert_eq!(usage.anchors_refused_for_age, older.len() as u64);
    assert_eq!(usage.pow_refused + usage.pow_indeterminate, 0);
}

/// Real headers with real PoW, the newest first: every older one is refused for its age
/// before its PoW check. This was a known gap: the check said nothing of a header's age.
/// A node that has seen nothing newer still takes an old header; see
/// `sovright_relay::ANCHOR_HEADER_WINDOW`.
#[tokio::test]
async fn an_old_header_opens_no_anchor_once_a_newer_one_has() {
    let (node, addr) = start_node(EquihashPowValidator, fleet()).await;
    let mut headers = old_headers();
    headers.sort_by_key(|header| std::cmp::Reverse(header_time(header)));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for header in &headers {
        let sealed = sealed_body(&on_a_header(header, 5000), &KEY).unwrap();
        send_again(&node, addr, &socket, &sealed).await;
    }

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.anchors, 1);
    assert_eq!(usage.anchors_refused_for_age, headers.len() as u64 - 1);
}

/// Headers that came in the order they were made: each newer one ages out the one before,
/// so old headers sent first cannot hold the table once a newer one passes.
#[tokio::test]
async fn a_newer_header_clears_what_older_ones_hold_at_a_real_node() {
    let (node, addr) = start_node(EquihashPowValidator, fleet()).await;
    let mut headers = old_headers();
    headers.sort_by_key(|header| header_time(header));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for header in &headers {
        let sealed = sealed_body(&on_a_header(header, 5000), &KEY).unwrap();
        send_again(&node, addr, &socket, &sealed).await;
    }

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, headers.len() as u64);
    assert_eq!(usage.anchors, 1);
}

/// A block's bodies: no key can take more than its share of them, and over all keys no
/// more than the block has.
#[tokio::test]
async fn a_block_takes_only_so_many_bodies_at_a_real_node() {
    let keys = vec![
        AuthKey::new("fleet", KEY),
        AuthKey::new("alice", OTHER_KEY),
        AuthKey::new("bob", [0x44; 32]),
    ];
    let (node, addr) = start_node(StubPowValidator, keys).await;
    let limit = BoundForwardConfig::default().max_bodies_per_block;
    assert_eq!(limit, 2 * MAX_BODIES_PER_KEY_PER_BLOCK);
    let body = |mark: usize, key: &[u8; 32]| {
        let mut raw = vec![1u8; 5000];
        raw[4000] = mark as u8;
        sealed_body(&raw, key).unwrap()
    };
    let (fleet, alice) = (
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    );

    for mark in 0..=MAX_BODIES_PER_KEY_PER_BLOCK {
        send_again(&node, addr, &fleet, &body(mark, &KEY)).await;
    }
    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, MAX_BODIES_PER_KEY_PER_BLOCK as u64);
    assert_eq!(usage.anchors_refused_for_key_bodies, 1);
    for mark in 10..10 + MAX_BODIES_PER_KEY_PER_BLOCK {
        send_again(&node, addr, &alice, &body(mark, &OTHER_KEY)).await;
    }
    raw_session(&node, addr, &body(20, &[0x44; 32])).await;

    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, limit as u64);
    assert_eq!(usage.anchors_refused_for_bodies, 1);
}

/// A receiver that refused a body says so to its relay, and the place the body held in its
/// block is free for the right one. The refused body stays out for a while.
#[tokio::test]
async fn a_receivers_refusal_frees_the_place_a_forged_body_held() {
    let limits = BoundForwardConfig {
        max_bodies_per_block: 1,
        ..Default::default()
    };
    let (node, addr) = start_config(relay_for(fleet(), limits), StubPowValidator).await;
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let honest = the_block();
    let mut forged = honest.clone();
    *forged.last_mut().unwrap() ^= 1;
    let sender = raw_session(&node, addr, &sealed_body(&forged, &KEY).unwrap()).await;
    let got = next_block(&mut blocks).await;
    assert_eq!(got.raw(), forged);
    send_again(&node, addr, &sender, &sealed_body(&honest, &KEY).unwrap()).await;
    assert_eq!(node.bound_usage().unwrap().anchors_refused_for_bodies, 1);

    assert_eq!(got.refuse(), 1, "one relay took the word");
    timeout(WAIT, async {
        while node.bound_usage().unwrap().anchors_released == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the relay never freed the place");

    raw_session(&node, addr, &sealed_body(&forged, &KEY).unwrap()).await;
    assert_eq!(node.bound_usage().unwrap().anchors_refused_as_released, 1);
    raw_session(&node, addr, &sealed_body(&honest, &KEY).unwrap()).await;
    assert_eq!(next_block(&mut blocks).await.raw(), honest);
}

/// A body is named by its block hash and its id, so whoever refuses it can say which.
#[tokio::test]
async fn a_bound_block_names_its_body() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let mut blocks = start_receiver(addr, KEY).await;
    sessions_reach(&node, 1).await;
    let raw = the_block();
    let mut other = raw.clone();
    *other.last_mut().unwrap() ^= 1;

    raw_session(&node, addr, &sealed_body(&raw, &KEY).unwrap()).await;
    let first = next_block(&mut blocks).await;
    raw_session(&node, addr, &sealed_body(&other, &KEY).unwrap()).await;
    let second = next_block(&mut blocks).await;

    assert_eq!(first.block_hash(), second.block_hash());
    assert_ne!(first.body_id(), second.body_id());
}

/// Revoking a key does not take back what its anchors prove, or free what they hold. A key
/// that comes back answers for them until they lapse, and then it has its share again.
#[tokio::test]
async fn a_revoked_key_answers_for_its_anchors_until_they_lapse() {
    let limits = BoundForwardConfig {
        max_anchors_per_key: 1,
        anchor_ttl: Duration::from_secs(2),
        ..Default::default()
    };
    let (node, addr) = start_config(relay_for(fleet(), limits), StubPowValidator).await;
    let body = |fill: u8| sealed_body(&dated_as_the_block(vec![fill; 5000]), &KEY).unwrap();
    let socket = raw_session(&node, addr, &body(1)).await;
    send_again(&node, addr, &socket, &body(2)).await;
    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, 1);
    assert_eq!(usage.anchors_refused_for_room, 1);

    node.apply_active_keys(Vec::new()).await;
    assert_eq!(node.bound_usage().unwrap().anchors, 1, "it stays");
    node.apply_active_keys(fleet()).await;

    let again = raw_session(&node, addr, &body(3)).await;
    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, 1, "the key still pays: {usage:?}");
    assert_eq!(usage.anchors_refused_for_room, 2);

    timeout(WAIT, async {
        while node.bound_usage().unwrap().objects_released < 2 {
            send_again(&node, addr, &again, &body(3)).await;
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the key never had its share again");
}

/// Everything `socket` gets until nothing more comes for a while.
async fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let mut buf = vec![0; 2048];
    while let Ok(received) = timeout(STILL_WAITING, socket.recv_from(&mut buf)).await {
        let (len, _) = received.unwrap();
        got.push(buf[..len].to_vec());
    }
    got
}

/// With nobody to send to nothing went, so nothing is recorded, and the next copy crosses
/// as soon as somebody is there, however soon it comes.
#[tokio::test]
async fn a_send_with_no_peer_records_nothing() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let body = sealed_body(&[7u8; 5000], &KEY).unwrap();
    let socket = raw_session(&node, addr, &body).await;
    let usage = node.bound_usage().unwrap();
    assert_eq!(usage.objects_released, 1);
    assert_eq!(usage.objects_sent_on, 0);

    let watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 2).await;
    // Past what counts as left over from the decode, and well inside `resend_after`, which
    // would hold back a copy of an object that had been sent.
    sleep(RELEASE_LEFTOVER).await;
    send_again(&node, addr, &socket, &body).await;

    assert!(body.contains(&watcher.next().await));
    assert_eq!(node.bound_usage().unwrap().objects_sent_on, 1);
}

/// Objects that waited for their segment 0 go to everyone but the session they came from,
/// even though the datagram that let them go came from another one.
#[tokio::test]
async fn an_object_never_goes_back_to_the_session_it_came_from() {
    let (node, addr) = start_node(StubPowValidator, fleet()).await;
    let raw = the_block();
    let frames = body_frames(&raw).unwrap();
    let first = sealed_frame(&frames[0], &KEY).unwrap();
    let later: Vec<Vec<u8>> = frames[1..]
        .iter()
        .flat_map(|frame| sealed_frame(frame, &KEY).unwrap())
        .collect();
    let a = Watcher::start(addr, KEY).await;
    let b = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 2).await;

    send_again(&node, addr, &a.0, &later).await;
    send_again(&node, addr, &b.0, &first).await;

    let (to_a, to_b) = (drain(&a.0).await, drain(&b.0).await);
    assert!(to_a.iter().all(|datagram| !later.contains(datagram)));
    assert!(first.iter().all(|datagram| to_a.contains(datagram)));
    assert!(to_b.iter().all(|datagram| !first.contains(datagram)));
    assert!(later.iter().all(|datagram| to_b.contains(datagram)));
}
