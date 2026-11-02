//! The bound send on a real client and real sockets, with a plain socket as the relay. A send
//! is paced so it lasts, and what a test looks at happens while it is under way, so an order
//! is read from the datagrams and needs no fixed wait. A datagram a socket took says nothing
//! of whether it arrived, and neither does anything here.
use std::sync::atomic::AtomicBool;

use tokio::task::JoinHandle;
use tokio::time::{timeout, timeout_at};

use super::*;
use crate::ChunkHeader;
use crate::relay::{MAX_BODY_BYTES, SEGMENT_BYTES, sealed_body};
use crate::segmented_block::split_raw_block;
use crate::transport::RelaySession;

const KEY: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(10);
/// What an answer that needs nothing to happen first gets.
const AT_ONCE: Duration = Duration::from_secs(2);
/// The pause after each bound datagram here, which makes a body of three segments last about
/// three quarters of a second.
const PAUSE: Duration = Duration::from_millis(20);
/// An address an IPv4 socket has to refuse.
const REFUSED: &str = "[::1]:9";

/// A plain socket in a relay's place, and what came to it.
struct Relay {
    socket: UdpSocket,
    bound: Vec<Vec<u8>>,
    legacy: usize,
    keepalives: usize,
}

impl Relay {
    async fn bind() -> Self {
        Self {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            bound: Vec::new(),
            legacy: 0,
            keepalives: 0,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    async fn read_until(&mut self, done: impl Fn(&Self) -> bool) {
        let mut datagram = [0u8; 2048];
        let deadline = tokio::time::Instant::now() + WAIT;
        while !done(self) {
            let read = timeout_at(deadline, self.socket.recv_from(&mut datagram));
            let (length, _) = read.await.expect("it never came").unwrap();
            let datagram = &datagram[..length];
            if bound_raw::is_bound(datagram) {
                self.bound.push(datagram.to_vec());
            } else if Chunk::from_bytes(datagram).unwrap().header.msg_type == MessageType::Keepalive
            {
                self.keepalives += 1;
            } else {
                self.legacy += 1;
            }
        }
    }

    async fn send_to(&self, client: SocketAddr, datagrams: &[Vec<u8>]) {
        for datagram in datagrams {
            self.socket.send_to(datagram, client).await.unwrap();
        }
    }
}

struct Client {
    sender: BlockSender,
    addr: SocketAddr,
    receiver: BlockReceiver,
    running: Arc<AtomicBool>,
    task: JoinHandle<Result<(), TransportError>>,
}

impl Client {
    fn sending(&self, raw: &Arc<Vec<u8>>) -> JoinHandle<Result<(), TransportError>> {
        let (sender, raw) = (self.sender.clone(), Arc::clone(raw));
        tokio::spawn(async move { sender.send_bound_raw_block(raw).await })
    }

    async fn takes_a_block(&mut self, relay: &Relay, mark: u8) {
        relay.send_to(self.addr, &wire(&segment(mark))).await;
        let taken = timeout(WAIT, self.receiver.recv_raw_block_segment());
        taken.await.expect("the client took nothing").unwrap();
    }

    /// One send going out and a full queue behind it.
    async fn full_up(
        &self,
        relay: &mut Relay,
        raw: &Arc<Vec<u8>>,
    ) -> Vec<JoinHandle<Result<(), TransportError>>> {
        let mut sends = vec![self.sending(raw)];
        relay.read_until(|relay| !relay.bound.is_empty()).await;
        sends.extend((0..BOUND_SENDS_WAITING).map(|_| self.sending(raw)));
        queue_holds(&self.sender, BOUND_SENDS_WAITING).await;
        sends
    }
}

async fn answer(send: JoinHandle<Result<(), TransportError>>) -> Result<(), TransportError> {
    let answer = timeout(WAIT, send).await;
    answer.expect("the answer never came").unwrap()
}

/// Until `waiting` sends are in the queue.
async fn queue_holds(sender: &BlockSender, waiting: usize) {
    let room = BOUND_SENDS_WAITING - waiting;
    let holds = async {
        while sender.bound_tx.capacity() > room {
            tokio::task::yield_now().await;
        }
    };
    timeout(WAIT, holds)
        .await
        .expect("the queue never held them");
}

fn config(relays: &[SocketAddr]) -> ClientConfig {
    ClientConfig::new(relays.to_vec(), KEY)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true)
        .with_fec(10, 3)
        .with_bound_send_pacing(1, PAUSE)
}

async fn start(config: ClientConfig, keepalive_every: Duration) -> Client {
    let mut client = RelayClient::new(config).unwrap();
    client.keepalive_every = keepalive_every;
    client.bind().await.unwrap();
    let (sender, addr) = (client.sender(), client.local_addr().unwrap());
    let running = Arc::clone(&client.running);
    let (receiver, outgoing) = client.take_receiver().unwrap();
    let task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
    Client {
        sender,
        addr,
        receiver,
        running,
        task,
    }
}

/// A body of `segments` segments, and the datagrams it goes out in.
fn body(segments: usize, fill: u8) -> (Arc<Vec<u8>>, Vec<Vec<u8>>) {
    let raw = vec![fill; segments * SEGMENT_BYTES as usize];
    let datagrams = sealed_body(&raw, &KEY).unwrap();
    (Arc::new(raw), datagrams)
}

fn segment(mark: u8) -> RawBlockSegment {
    split_raw_block([mark; 32], &[0xcd; 9000], 11_236)
        .unwrap()
        .remove(0)
}

/// What a relay sends a client for `segment`.
fn wire(segment: &RawBlockSegment) -> Vec<Vec<u8>> {
    let session = RelaySession::new("0.0.0.0:0".parse().unwrap(), "test", KEY);
    let chunker = BlockChunker::new(10, 3).unwrap();
    let chunks = chunker.raw_block_segment_to_chunks(segment).unwrap();
    chunks
        .into_iter()
        .map(|chunk| {
            let h = &chunk.header;
            let mac = session.compute_hmac(
                &h.block_hash,
                h.chunk_id,
                h.total_chunks,
                h.payload_len,
                &chunk.payload,
            );
            let header = ChunkHeader::new_raw_block_segment_authenticated(
                &h.block_hash,
                h.chunk_id,
                h.total_chunks,
                h.payload_len,
                mac,
            );
            Chunk::new(header, chunk.payload).to_bytes()
        })
        .collect()
}

#[tokio::test]
async fn a_bound_send_leaves_the_client_receiving() {
    let mut relay = Relay::bind().await;
    let mut client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let (raw, datagrams) = body(3, 1);
    let send = client.sending(&raw);

    relay.read_until(|relay| !relay.bound.is_empty()).await;
    client.takes_a_block(&relay, 1).await;

    let sent = client.sender.sends().sent;
    assert!((sent as usize) < datagrams.len(), "{sent} sent already");
    answer(send).await.unwrap();
}

#[tokio::test]
async fn a_bound_send_does_not_stop_the_keepalives() {
    let mut relay = Relay::bind().await;
    let client = start(config(&[relay.addr()]), Duration::from_millis(50)).await;
    let (raw, datagrams) = body(3, 1);
    let send = client.sending(&raw);

    relay.read_until(|relay| !relay.bound.is_empty()).await;
    let before = relay.keepalives;
    let total = datagrams.len();
    relay.read_until(|relay| relay.bound.len() == total).await;

    let during = relay.keepalives - before;
    assert!(during >= 3, "{during} keepalives during the send");
    answer(send).await.unwrap();
}

#[tokio::test]
async fn a_bound_send_does_not_hold_a_legacy_send_back() {
    let mut relay = Relay::bind().await;
    let client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let (raw, datagrams) = body(3, 1);
    let send = client.sending(&raw);

    relay.read_until(|relay| !relay.bound.is_empty()).await;
    let legacy = segment(1);
    let chunks = wire(&legacy).len();
    client.sender.send_raw_block_segment(legacy).await.unwrap();
    relay.read_until(|relay| relay.legacy == chunks).await;

    assert!(relay.bound.len() < datagrams.len(), "legacy came last");
    answer(send).await.unwrap();
}

/// Block after block on the bound path, with legacy going out and coming in alongside. This
/// is steady traffic on a clean loopback, with no delay or loss.
#[tokio::test]
async fn a_run_of_bound_sends_leaves_legacy_and_receiving_going() {
    let mut relay = Relay::bind().await;
    let mut client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let chunks = wire(&segment(0)).len();

    for round in 0..4u8 {
        let (raw, datagrams) = body(2, round + 1);
        let sent_before = relay.bound.len();
        let send = client.sending(&raw);
        relay
            .read_until(|relay| relay.bound.len() > sent_before)
            .await;

        client.takes_a_block(&relay, round + 1).await;
        let legacy = segment(100 + round);
        client.sender.send_raw_block_segment(legacy).await.unwrap();
        let wanted = chunks * (usize::from(round) + 1);
        relay.read_until(|relay| relay.legacy == wanted).await;

        let of_this_send = relay.bound.len() - sent_before;
        assert!(of_this_send < datagrams.len(), "round {round}");
        let total = sent_before + datagrams.len();
        relay.read_until(|relay| relay.bound.len() == total).await;
        answer(send).await.unwrap();
    }
}

#[tokio::test]
async fn bound_sends_go_one_at_a_time() {
    let mut relay = Relay::bind().await;
    let client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let ((first, of_first), (second, of_second)) = (body(1, 1), body(1, 2));

    let sends = [client.sending(&first), client.sending(&second)];
    let total = of_first.len() + of_second.len();
    relay.read_until(|relay| relay.bound.len() == total).await;

    let starts_with_first = of_first.contains(&relay.bound[0]);
    let changes_at = relay
        .bound
        .iter()
        .position(|datagram| of_first.contains(datagram) != starts_with_first);
    assert_eq!(changes_at, Some(of_first.len()), "they are interleaved");
    for send in sends {
        answer(send).await.unwrap();
    }
}

/// With no client running nothing takes from the queue, so this is the queue alone.
#[tokio::test]
async fn a_full_bound_queue_says_so_at_once() {
    let relay = Relay::bind().await;
    let client = RelayClient::new(config(&[relay.addr()])).unwrap();
    let (raw, _) = body(1, 1);
    let sender = client.sender();
    let waiting: Vec<_> = (0..BOUND_SENDS_WAITING)
        .map(|_| {
            let (sender, raw) = (sender.clone(), Arc::clone(&raw));
            tokio::spawn(async move { sender.send_bound_raw_block(raw).await })
        })
        .collect();
    queue_holds(&sender, BOUND_SENDS_WAITING).await;

    let refused = timeout(AT_ONCE, sender.send_bound_raw_block(raw)).await;

    assert!(refused.expect("the queue held it up").is_err());
    waiting.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn a_full_bound_queue_stops_nothing_else() {
    let mut relay = Relay::bind().await;
    let mut client = start(config(&[relay.addr()]), Duration::from_millis(50)).await;
    let (raw, datagrams) = body(1, 1);
    let sends = client.full_up(&mut relay, &raw).await;

    let refused = timeout(AT_ONCE, client.sender.send_bound_raw_block(raw)).await;
    assert!(refused.expect("the queue held it up").is_err());

    let keepalives = relay.keepalives;
    client.takes_a_block(&relay, 1).await;
    let legacy = segment(2);
    let chunks = wire(&legacy).len();
    client.sender.send_raw_block_segment(legacy).await.unwrap();
    relay
        .read_until(|relay| relay.legacy == chunks && relay.keepalives > keepalives)
        .await;

    let all = (BOUND_SENDS_WAITING + 1) * datagrams.len();
    assert!(relay.bound.len() < all, "everything else came last");
    for send in sends {
        answer(send).await.unwrap();
    }
}

#[tokio::test]
async fn a_body_that_does_not_fit_comes_back_as_an_error() {
    let relay = Relay::bind().await;
    let client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let raw = Arc::new(vec![1u8; MAX_BODY_BYTES as usize + 1]);
    assert!(sealed_body(&raw, &KEY).is_none());

    let error = answer(client.sending(&raw)).await.unwrap_err();

    assert!(matches!(error, TransportError::InvalidChunk(_)), "{error}");
}

#[tokio::test]
async fn a_socket_that_refuses_comes_back_as_an_error() {
    let client = start(config(&[REFUSED.parse().unwrap()]), KEEPALIVE_INTERVAL).await;
    let (raw, _) = body(1, 1);

    let error = answer(client.sending(&raw)).await.unwrap_err();

    assert!(matches!(error, TransportError::Io(_)), "{error}");
    assert_eq!(client.sender.sends().errors, 1);
}

/// One relay refusing costs the others nothing, and a body one relay took can still get
/// through. Legacy stops at the first error instead, and that did not change.
#[tokio::test]
async fn one_relay_that_took_it_all_is_enough() {
    let mut relay = Relay::bind().await;
    let relays = [REFUSED.parse().unwrap(), relay.addr()];
    let client = start(config(&relays), KEEPALIVE_INTERVAL).await;
    let (raw, datagrams) = body(1, 1);
    let send = client.sending(&raw);

    let total = datagrams.len();
    relay.read_until(|relay| relay.bound.len() == total).await;

    answer(send).await.unwrap();
    assert_eq!(client.sender.sends().errors, 1);
}

/// A client that goes takes its queue with it, and each caller hears it did.
#[tokio::test]
async fn a_client_that_goes_fails_what_it_held() {
    for stops in [false, true] {
        let mut relay = Relay::bind().await;
        let client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
        let (raw, _) = body(3, 1);
        let sends = client.full_up(&mut relay, &raw).await;

        if stops {
            client.running.store(false, Ordering::SeqCst);
            let wake = [b"anything".to_vec()];
            relay.send_to(client.addr, &wake).await;
        } else {
            client.task.abort();
        }

        for send in sends {
            let answer = timeout(AT_ONCE, send).await.expect("a caller hangs");
            assert!(answer.unwrap().is_err());
        }
        let late = timeout(AT_ONCE, client.sender.send_bound_raw_block(raw));
        assert!(late.await.expect("a late caller hangs").is_err());
    }
}

/// A send that reaches the queue as the queue goes is held by nobody who can answer it. Here
/// the test holds it, which comes to the same for the caller.
#[tokio::test]
async fn a_queue_that_goes_answers_for_what_it_held() {
    let relay = Relay::bind().await;
    let mut client = RelayClient::new(config(&[relay.addr()])).unwrap();
    let mut queue = client.take_bound_sends().unwrap();
    let sender = client.sender();
    let (raw, _) = body(1, 1);
    let send = tokio::spawn(async move { sender.send_bound_raw_block(raw).await });
    let held = queue.recv().await.unwrap();

    drop(queue);

    let answer = timeout(AT_ONCE, send).await.expect("the caller hangs");
    assert!(answer.unwrap().is_err());
    drop(held);
}

/// A block on its way is worth more than a repeat saved: the send does not depend on who asked.
#[tokio::test]
async fn a_caller_that_stops_waiting_leaves_the_send_going() {
    let mut relay = Relay::bind().await;
    let client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let (raw, datagrams) = body(2, 1);

    let gives_up = client.sending(&raw);
    relay.read_until(|relay| !relay.bound.is_empty()).await;

    gives_up.abort();
    assert!(gives_up.await.unwrap_err().is_cancelled());

    let total = datagrams.len();
    relay.read_until(|relay| relay.bound.len() == total).await;
}

#[tokio::test]
async fn a_caller_that_stops_waiting_leaves_its_place_in_the_queue() {
    let mut relay = Relay::bind().await;
    let client = start(config(&[relay.addr()]), KEEPALIVE_INTERVAL).await;
    let ((first, of_first), (second, of_second)) = (body(1, 1), body(1, 2));
    let going = client.sending(&first);
    relay.read_until(|relay| !relay.bound.is_empty()).await;
    let gives_up = client.sending(&second);
    queue_holds(&client.sender, 1).await;

    gives_up.abort();
    assert!(gives_up.await.unwrap_err().is_cancelled());

    let total = of_first.len() + of_second.len();
    relay.read_until(|relay| relay.bound.len() == total).await;
    answer(going).await.unwrap();
}

/// On the one thread this test has, the loop gets nothing while something else holds it.
#[tokio::test]
async fn encoding_a_body_leaves_the_loop_free() {
    let relay = Relay::bind().await;
    let raw = Arc::new(vec![1u8; MAX_BODY_BYTES as usize]);
    let started = Instant::now();
    sealed_body(&raw, &KEY).unwrap();
    let encoding = started.elapsed();

    let paced = ClientConfig::new(vec![relay.addr()], KEY)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true)
        .with_fec(10, 3);
    let client = start(paced, KEEPALIVE_INTERVAL).await;
    let send = client.sending(&raw);

    let (mut longest, mut last) = (Duration::ZERO, Instant::now());
    while !send.is_finished() {
        tokio::task::yield_now().await;
        longest = longest.max(last.elapsed());
        last = Instant::now();
    }

    assert!(longest < encoding / 2, "{longest:?} of {encoding:?}");
}
