//! #130 PR B: the bound raw path on a real node and real clients over UDP loopback. What a
//! node does with the candidate format, with keys, sessions and PoW as they are. The format
//! is a candidate, and these tests are no specification of it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sovright_relay::{
    AuthKey, BlockSender, BoundBlock, BoundForwardConfig, BoundRawConfig, BoundUsed, Chunk,
    ChunkHeader, ClientConfig, KeyRole, PowResult, PowValidator, RejectAllValidator, RelayClient,
    RelayConfig, RelayNode, RelaySession, StubPowValidator, body_frames, is_bound, sealed_body,
    sealed_frame,
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
    let done = || {
        let mut left = wanted.iter();
        left.all(|(datagram, times)| node.times_finished(from, datagram) >= *times)
    };
    timeout(wait, async {
        while !done() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
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
    let raw = vec![200u8; 5000];
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
    let _watcher = Watcher::start(addr, KEY).await;
    sessions_reach(&node, 1).await;

    raw_session(&node, addr, &sealed_body(&the_block(), &KEY).unwrap()).await;

    assert_eq!(node.session_count().await, 1, "no session came of it");
    assert_eq!(node.metrics().snapshot().packets_forwarded, 0);
}

/// Stops a node inside its PoW check until it is told to go on, so a test knows which packet
/// the node is on.
struct Gate {
    reached: UnboundedSender<()>,
    open: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl PowValidator for Gate {
    fn validate(&self, _header: &[u8]) -> PowResult {
        self.reached.send(()).unwrap();
        self.open.lock().unwrap().recv().unwrap();
        PowResult::Valid
    }
}

/// How these tests used to wait: two more packets counted, read after everything was sent.
async fn two_more_packets_counted<V>(node: &RelayNode<V>, addr: SocketAddr, socket: &UdpSocket)
where
    V: PowValidator + Send + Sync + 'static,
{
    let before = received(node);
    socket.send_to(b"not a chunk", addr).await.unwrap();
    socket.send_to(b"not a chunk", addr).await.unwrap();
    timeout(WAIT, async {
        while received(node) < before + 2 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the node stopped reading");
}

fn gated() -> (Gate, UnboundedReceiver<()>, std::sync::mpsc::Sender<()>) {
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

/// The node is held on its twentieth packet with nine more behind it, and the old wait comes
/// back all the same: packets already queued gave it its two. A test that looked then for
/// something not sent on would have passed with the packets that matter still unread. The
/// wait these tests use holds on until those packets are finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_more_packets_counted_can_leave_the_rest_unread() {
    let (gate, mut at_gate, open) = gated();
    let (node, addr) = start_node(gate, fleet()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let from = socket.local_addr().unwrap();
    let (first, second, third) = (sealed(1), sealed(2), sealed(3));
    let wanted = once_finished(&node, from, second[..10].iter().chain(&third[..9]));

    send_all(&socket, addr, &first[..10]).await;
    at_gate.recv().await.unwrap();
    assert_eq!(received(&node), 10);
    send_all(&socket, addr, &second[..10]).await;
    send_all(&socket, addr, &third[..9]).await;

    tokio::join!(two_more_packets_counted(&node, addr, &socket), async {
        open.send(()).unwrap();
        at_gate.recv().await.unwrap();
    });
    assert_eq!(received(&node), 20, "and 11 of what was sent still unread");
    assert_eq!(node.times_finished(from, &second[8]), 1);
    assert_eq!(
        node.times_finished(from, &second[9]),
        0,
        "started, not done"
    );

    let mut waiting = Box::pin(finished_within(&node, from, &wanted, WAIT));
    let held = timeout(STILL_WAITING, &mut waiting).await;
    assert!(held.is_err(), "the node has not been let on");

    open.send(()).unwrap();
    waiting.await.unwrap();
    assert_eq!(node.times_finished(from, &third[8]), 1);
    assert_eq!(node.bound_usage().unwrap().pool.objects, 1);
}

/// A test sends two packets, and a keepalive it knows nothing of takes the place of one in the
/// count. The count says done with the second one still unread, and one of them a repeat of
/// something already finished. Waiting for the packets themselves is not fooled by either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keepalive_can_fill_a_count_and_not_this_wait() {
    let (gate, mut at_gate, open) = gated();
    let (node, addr) = start_node(gate, fleet()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let from = socket.local_addr().unwrap();
    let (first, second, third) = (sealed(1), sealed(2), sealed(3));
    let repeated = third[0].clone();
    send_again(&node, addr, &socket, std::slice::from_ref(&repeated)).await;
    send_again(&node, addr, &socket, &second[..9]).await;

    send_all(&socket, addr, &first[..10]).await;
    at_gate.recv().await.unwrap();
    let (held_on, sent) = (second[9].clone(), [second[9].clone(), repeated.clone()]);
    let count_met_at = received(&node) + sent.len() as u64;
    let wanted = once_finished(&node, from, &sent);
    assert_eq!(wanted[repeated.as_slice()], 2);

    let _keepalive = Watcher::start(addr, KEY).await;
    send_all(&socket, addr, &sent).await;
    open.send(()).unwrap();
    at_gate.recv().await.unwrap();

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
    let mut waiting = Box::pin(finished_within(&node, from, &wanted, WAIT));
    let held = timeout(STILL_WAITING, &mut waiting).await;
    assert!(held.is_err(), "those two are not finished");

    open.send(()).unwrap();
    waiting.await.unwrap();
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
        let firsts: Vec<Vec<u8>> = (0..32u32)
            .map(|object| {
                let mut raw = vec![0u8; 9000];
                raw[..4].copy_from_slice(&session.to_le_bytes());
                raw[4..8].copy_from_slice(&object.to_le_bytes());
                sealed_body(&raw, &KEY).unwrap().swap_remove(0)
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
