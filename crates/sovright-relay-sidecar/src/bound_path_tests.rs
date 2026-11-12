//! #130 PR B on the real path: a real node, a real client over UDP loopback, the sidecar's
//! real receive task, its real gate and the real RPC client. The only stand-in is Zebra.
//! It takes or refuses bodies as a test tells it to, so it stands in for an answer and
//! says nothing about what a node would decide. Nothing here has been near a real node.
//!
//! The ways through are told apart by what each test sends. Tests of a legacy receiver
//! say so in their name, and what they show is that it was left as it was.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;

use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};
use sovright_relay::test_support::{
    committed_header, parseable_transaction, parseable_transaction_with_script, raw_block,
};
use sovright_relay::{
    AuthKey, BOUND_SEND_BURST_DELAY, BOUND_SEND_BURST_PACKETS, BlockSender, BoundForwardConfig,
    BoundNodeUsage, BoundProbe, ClientConfig, MetricsSnapshot, RelayClient, RelayConfig, RelayNode,
    StubPowValidator, TransportError, body_frames, consensus_block_hash_display, sealed_body,
    sealed_frame, split_raw_block,
};
use sovright_relay_sidecar::chain_view::ZebraChainViewConfig;
use sovright_relay_sidecar::submit::build_raw_block_submission_candidate;
use sovright_relay_sidecar::submit_gate::{
    CandidateMeta, DEFAULT_STRICT_BODIES_PER_BLOCK, GateConfig, ParentObservation, RejectReason,
};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

use super::*;

const KEY: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(20);

/// What this stand-in was told, and what it was asked.
#[derive(Default)]
struct Zebra {
    refuse: Mutex<HashSet<String>>,
    candidates: Mutex<HashSet<String>>,
    has: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
    /// Every `submitblock` ends in an error, as when the node is restarting.
    down: AtomicBool,
    /// Permits for `submitblock`, if a test is holding it back.
    hold: Mutex<Option<Arc<Semaphore>>>,
    held: AtomicU64,
    /// Every `submitblock` as it came in, held or not.
    arrivals: Mutex<Vec<String>>,
    /// The same for `getblockheader`.
    hold_lookups: Mutex<Option<Arc<Semaphore>>>,
    lookups_held: AtomicU64,
}

impl Zebra {
    fn refuse(&self, raw: &[u8]) {
        self.refuse.lock().unwrap().insert(hex::encode(raw));
    }

    /// It has this block already, by some other way.
    fn has_already(&self, raw: &[u8]) {
        self.has.lock().unwrap().insert(display_hash(raw));
    }

    fn stop_refusing(&self) {
        self.refuse.lock().unwrap().clear();
    }

    fn knows_of(&self, raw: &[u8]) {
        self.candidates.lock().unwrap().insert(display_hash(raw));
    }

    fn go_down(&self) {
        self.down.store(true, Ordering::Relaxed);
    }

    fn come_back(&self) {
        self.down.store(false, Ordering::Relaxed);
    }

    fn hold(&self) -> Arc<Semaphore> {
        let permits = Arc::new(Semaphore::new(0));
        *self.hold.lock().unwrap() = Some(Arc::clone(&permits));
        permits
    }

    /// Calls from here on go straight through. Those held stay held.
    fn stop_holding(&self) {
        *self.hold.lock().unwrap() = None;
    }

    fn hold_lookups(&self) -> Arc<Semaphore> {
        let permits = Arc::new(Semaphore::new(0));
        *self.hold_lookups.lock().unwrap() = Some(Arc::clone(&permits));
        permits
    }

    fn stop_holding_lookups(&self) {
        *self.hold_lookups.lock().unwrap() = None;
    }

    /// Calls that have come in and are being held back.
    fn waiting(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    /// Calls that have reached this stand-in for this block, answered or not.
    fn arrivals_for(&self, raw: &[u8]) -> usize {
        let wanted = hex::encode(raw);
        let arrivals = self.arrivals.lock().unwrap();
        arrivals.iter().filter(|call| **call == wanted).count()
    }

    fn calls_for(&self, raw: &[u8]) -> usize {
        let wanted = hex::encode(raw);
        let calls = self.calls.lock().unwrap();
        calls.iter().filter(|call| **call == wanted).count()
    }

    fn calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn took(&self, raw: &[u8]) -> bool {
        self.has.lock().unwrap().contains(&hex::encode(raw))
    }

    fn submitted(&self, block_hex: String) -> Result<Option<String>, ErrorObjectOwned> {
        let hash = hex::decode(&block_hex)
            .ok()
            .map(|raw| display_hash(&raw))
            .unwrap_or_default();
        self.calls.lock().unwrap().push(block_hex.clone());
        if self.down.load(Ordering::Relaxed) {
            return Err(ErrorObjectOwned::owned(-32000, "not ready", None::<()>));
        }
        if self.refuse.lock().unwrap().contains(&block_hex) {
            return Ok(Some("rejected".to_string()));
        }
        let mut has = self.has.lock().unwrap();
        if has.contains(&hash) {
            return Ok(Some("duplicate".to_string()));
        }
        has.insert(hash);
        has.insert(block_hex);
        Ok(None)
    }

    fn header(&self, hash: &str) -> Result<Value, ErrorObjectOwned> {
        let known = !self.candidates.lock().unwrap().contains(hash)
            || self.has.lock().unwrap().contains(hash);
        if !known {
            return Err(ErrorObjectOwned::owned(-5, "not found", None::<()>));
        }
        Ok(json!({ "hash": hash, "height": 100, "confirmations": 1 }))
    }
}

fn display_hash(raw: &[u8]) -> String {
    consensus_block_hash_display(&raw[..ZCASH_FULL_HEADER_SIZE])
}

async fn start_zebra() -> (Arc<Zebra>, String, ServerHandle) {
    let zebra = Arc::new(Zebra::default());
    let mut module = RpcModule::new(Arc::clone(&zebra));
    module
        .register_async_method("submitblock", |params, zebra, _| async move {
            let (block_hex,): (String,) = params.parse()?;
            zebra.arrivals.lock().unwrap().push(block_hex.clone());
            let hold = zebra.hold.lock().unwrap().clone();
            if let Some(hold) = hold {
                zebra.held.fetch_add(1, Ordering::Relaxed);
                hold.acquire().await.expect("never closed").forget();
            }
            zebra.submitted(block_hex)
        })
        .unwrap();
    module
        .register_async_method("getblockheader", |params, zebra, _| async move {
            let (hash, _): (String, bool) = params.parse()?;
            let hold = zebra.hold_lookups.lock().unwrap().clone();
            if let Some(hold) = hold {
                zebra.lookups_held.fetch_add(1, Ordering::Relaxed);
                hold.acquire().await.expect("never closed").forget();
            }
            zebra.header(&hash)
        })
        .unwrap();
    let server = ServerBuilder::default()
        .http_only()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    (zebra, url, server.start(module))
}

type Sessions<'a> = Pin<Box<dyn Future<Output = usize> + Send + 'a>>;

trait LiveNode: Send + Sync {
    fn halt(&self);
    fn sessions(&self) -> Sessions<'_>;
    fn view(&self) -> NodeView;
}

/// What a node reports of itself.
struct NodeView {
    metrics: MetricsSnapshot,
    usage: Option<BoundNodeUsage>,
    recv_buffer: Option<usize>,
}

impl<V: sovright_relay::PowValidator + Send + Sync> LiveNode for RelayNode<V> {
    fn halt(&self) {
        self.stop();
    }

    fn sessions(&self) -> Sessions<'_> {
        Box::pin(self.session_count())
    }

    fn view(&self) -> NodeView {
        NodeView {
            metrics: self.metrics().snapshot(),
            usage: self.bound_usage(),
            recv_buffer: self.recv_buffer_bytes(),
        }
    }
}

struct Node {
    node: Arc<dyn LiveNode>,
    addr: SocketAddr,
    task: JoinHandle<Result<(), TransportError>>,
}

impl Node {
    async fn start<V>(mut node: RelayNode<V>) -> Self
    where
        V: sovright_relay::PowValidator + Send + Sync + 'static,
    {
        node.bind().await.unwrap();
        let addr = node.local_addr().unwrap();
        let node = Arc::new(node);
        let running = Arc::clone(&node);
        let task = tokio::spawn(async move { running.run().await });
        Self { node, addr, task }
    }

    /// A receiver has a session once its first keepalive arrived, and a block sent before
    /// that has nowhere to go.
    async fn has_a_receiver(&self) {
        let waited = timeout(WAIT, async {
            while self.node.sessions().await == 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "the receiver never got a session");
    }
}

fn node_config(bound: bool) -> RelayConfig {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
        .with_fec(10, 3);
    if bound {
        config.with_bound_raw(Default::default())
    } else {
        config
    }
}

/// A real node checking Equihash, so only the real header gets through it.
async fn equihash_node(bound: bool) -> Node {
    Node::start(RelayNode::new(node_config(bound)).unwrap()).await
}

/// The real node with PoW stubbed, because the tests that need many blocks have one real
/// header between them.
async fn stub_pow_node(bound: bool) -> Node {
    Node::start(RelayNode::with_validator(node_config(bound), StubPowValidator).unwrap()).await
}

/// A node that takes a resend as soon as it comes, so a test need not wait out the time
/// that tells a resend from what is left of a send.
fn resends_at_once() -> BoundForwardConfig {
    BoundForwardConfig {
        resend_after: Duration::ZERO,
        ..Default::default()
    }
}

async fn resending_equihash_node() -> Node {
    let config = node_config(false).with_bound_raw(resends_at_once());
    Node::start(RelayNode::new(config).unwrap()).await
}

async fn stub_pow_node_with(bound: BoundForwardConfig) -> Node {
    let config = node_config(false).with_bound_raw(bound);
    Node::start(RelayNode::with_validator(config, StubPowValidator).unwrap()).await
}

fn client_config(node: SocketAddr) -> ClientConfig {
    ClientConfig::new(vec![node], KEY)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true)
        .with_fec(10, 3)
        .with_send_pacing(32, Duration::from_micros(200))
}

async fn start_sender(node: SocketAddr) -> (BlockSender, JoinHandle<Result<(), TransportError>>) {
    start_sender_with(client_config(node)).await
}

async fn start_sender_with(
    config: ClientConfig,
) -> (BlockSender, JoinHandle<Result<(), TransportError>>) {
    let mut client = RelayClient::new(config).unwrap();
    client.bind().await.unwrap();
    let sender = client.sender();
    let task = tokio::spawn(async move { client.run().await });
    (sender, task)
}

/// The sidecar's side, end to end.
struct Sidecar {
    zebra: Arc<Zebra>,
    client_addr: SocketAddr,
    recv_buffer: Option<usize>,
    client_task: JoinHandle<Result<(), TransportError>>,
    handler_task: JoinHandle<()>,
    metrics: Arc<SidecarMetrics>,
    probe: Option<BoundProbe>,
    gate: Option<Arc<TokioMutex<SubmitGate<Arc<ZebraChainView>>>>>,
    _zebra_server: ServerHandle,
}

async fn start_sidecar(node: SocketAddr, bound: Option<BoundRawConfig>) -> Sidecar {
    start_sidecar_with(node, bound, None).await
}

async fn start_sidecar_with(
    node: SocketAddr,
    bound: Option<BoundRawConfig>,
    unreadable: Option<UnreadableSubmit>,
) -> Sidecar {
    let options = SidecarOptions {
        bound,
        unreadable,
        ..Default::default()
    };
    start_sidecar_from(node, options).await
}

/// How a sidecar here differs from a sidecar with its defaults and its gate on.
struct SidecarOptions {
    bound: Option<BoundRawConfig>,
    unreadable: Option<UnreadableSubmit>,
    limits: BoundTaskLimits,
    gate: bool,
    raw_ttl: Duration,
}

impl Default for SidecarOptions {
    fn default() -> Self {
        Self {
            bound: Some(Default::default()),
            unreadable: None,
            limits: Default::default(),
            gate: true,
            raw_ttl: Duration::from_secs(120),
        }
    }
}

/// One block at a time, for tests of what waits behind it.
fn one_task_at_a_time() -> BoundTaskLimits {
    BoundTaskLimits {
        running: 1,
        ..Default::default()
    }
}

async fn start_sidecar_from(node: SocketAddr, options: SidecarOptions) -> Sidecar {
    let SidecarOptions {
        bound,
        unreadable,
        limits,
        gate,
        raw_ttl,
    } = options;
    let (zebra, url, zebra_server) = start_zebra().await;
    let mut config = client_config(node);
    config.bound_raw = bound;
    let mut client = RelayClient::new(config).unwrap();
    client.bind().await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let recv_buffer = client.recv_buffer_bytes();
    let (receiver, outgoing) = client.take_receiver().unwrap();
    let probe = receiver.bound_probe();
    let client_task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
    let rpc = Arc::new(ZebraRpc::new(&url).await.unwrap());
    let submitter = Arc::new(DualSubmit::primary_only(Arc::clone(&rpc), "unused", None));
    let metrics = Arc::new(SidecarMetrics::default());
    let chain_view = ZebraChainView::new(ZebraChainViewConfig::default());
    chain_view.set_tip_height(100);
    let gate = gate.then(|| {
        Arc::new(TokioMutex::new(SubmitGate::new(
            // As the sidecar runs it with the bound raw switch on.
            GateConfig {
                enabled: true,
                competing_bodies: true,
                ..GateConfig::default()
            },
            Arc::clone(&chain_view),
        )))
    });
    let chain_view = gate.is_some().then_some(chain_view);
    let handler_task = spawn_relay_block_handler(
        receiver,
        rpc,
        submitter,
        SubmitBlockMode::Live,
        false,
        RawSegmentBufferConfig::new(128, 64 * 1024 * 1024, raw_ttl).unwrap(),
        Arc::clone(&metrics),
        Arc::new(EmptyMempool),
        gate.clone(),
        chain_view,
        unreadable,
        limits,
    );
    Sidecar {
        zebra,
        client_addr,
        recv_buffer,
        client_task,
        handler_task,
        metrics,
        probe,
        gate,
        _zebra_server: zebra_server,
    }
}

impl Sidecar {
    fn probe(&self) -> &BoundProbe {
        self.probe.as_ref().expect("the bound path is on")
    }

    fn gate(&self) -> &TokioMutex<SubmitGate<Arc<ZebraChainView>>> {
        self.gate.as_ref().expect("the gate is on")
    }

    /// Whether the gate has these bytes at Zebra, by what it says to a candidate as the real
    /// path puts one to it. For a block Zebra does not have: a repeat reads the same. A no costs
    /// that block one attempt, and a yes costs nothing.
    async fn gate_has_at_zebra(&self, raw: &[u8]) -> bool {
        let candidate = build_raw_block_submission_candidate(raw, None).unwrap();
        let header = &raw[..ZCASH_FULL_HEADER_SIZE];
        let parent = ParentObservation {
            parent_hash: CandidateMeta::parent_hash_from_header(header).unwrap(),
            height: 100,
            confirmations: Some(1),
        };
        let meta =
            CandidateMeta::from_header_bytes(header, candidate.block_hash.clone(), Some(&parent))
                .unwrap();
        let answer = self
            .gate()
            .lock()
            .await
            .reserve_strict_now(&candidate, &meta, false);
        match answer {
            Ok(_slot) => false,
            Err(RejectReason::DuplicateSubmit) => true,
            Err(reason) => panic!("the gate said {reason:?}"),
        }
    }

    async fn gate_lets_go_of(&self, raw: &[u8]) {
        let waited = timeout(WAIT, async {
            while self.gate_has_at_zebra(raw).await {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "gave up waiting for the gate to let go");
    }

    async fn gate_knows(&self, raw: &[u8]) -> bool {
        let hash = hex::encode(zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]));
        self.gate().lock().await.knows(&hash)
    }

    async fn gate_learns_of(&self, raw: &[u8]) {
        let waited = timeout(WAIT, async {
            while !self.gate_knows(raw).await {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "gave up waiting for the gate to learn");
    }

    /// Waits until the gate has turned this many copies away as bodies Zebra refused.
    async fn turned_away_as_refused(&self, copies: u64) {
        let metrics = Arc::clone(&self.metrics);
        until("the gate to turn a refused body away", move || {
            metrics
                .submit_gate_rejected_refused_body
                .load(Ordering::Relaxed)
                >= copies
        })
        .await;
    }

    fn turned_away_as_repeats(&self) -> u64 {
        let turned_away = &self.metrics.submit_gate_rejected_duplicate;
        turned_away.load(Ordering::Relaxed)
    }

    /// With a channel of one place: a block at Zebra, a block in the channel, and this
    /// many more waiting in the client. A small block is one segment, and a block that was
    /// put together has an owner for its copy as well.
    async fn is_full_with_waiting(&self, waiting: usize) {
        let probe = self.probe().clone();
        let owners = 2 * 2 + waiting;
        until("the blocks to be owned", move || {
            let ledger = probe.ledger();
            ledger.held + ledger.in_flight >= owners
        })
        .await;
    }

    /// Nothing is owned and no reservation is left.
    async fn ledger_settled(&self) {
        let probe = self.probe().clone();
        until("the ledger to let go", move || {
            let ledger = probe.ledger();
            ledger.reserved_bytes == 0 && ledger.live_owners == 0
        })
        .await;
    }

    /// That, and the chunk budget too, sessions apart.
    async fn settled(&self) {
        self.ledger_settled().await;
        let probe = self.probe().clone();
        until("every byte to come back", move || {
            let used = probe.used();
            used == sovright_relay::BoundUsed {
                sessions: used.sessions,
                ..Default::default()
            }
        })
        .await;
    }
}

async fn until(what: &str, done: impl Fn() -> bool) {
    let waited = timeout(WAIT, async {
        while !done() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "gave up waiting for {what}");
}

fn the_real_block() -> Vec<u8> {
    fixtures::mainnet_raw_block()
}

/// Block 3470793 with a byte changed where no txid covers it, so the strict reader cannot
/// tell it from the real one. Only the stand-in, told to, refuses it.
fn another_body_of_the_real_header() -> Vec<u8> {
    let header = fixtures::mainnet_serialized_header();
    let mut txs = fixtures::mainnet_transactions();
    txs[2][70] ^= 0x01;
    let other = raw_block(&header, &txs);
    assert_ne!(other, the_real_block());
    assert_eq!(
        sovright_relay::validate_block_body(&other),
        Ok(txs.len()),
        "the strict reader must pass it, or this is not the case under test"
    );
    other
}

/// A block of its own, for a test that needs several. Only a stubbed node passes it.
fn synthetic_block(fill: u8) -> Vec<u8> {
    let txs = vec![
        parseable_transaction(u32::from(fill) * 2),
        parseable_transaction(u32::from(fill) * 2 + 1),
    ];
    raw_block(&committed_header(fill, &txs), &txs)
}

/// The same, large enough to take several segments.
fn large_block(fill: u8) -> Vec<u8> {
    let txs: Vec<Vec<u8>> = (0..16)
        .map(|at| parseable_transaction_with_script(at + u32::from(fill), 4096))
        .collect();
    raw_block(&committed_header(fill, &txs), &txs)
}

/// As [`large_block`], dated as block `1` is. A node refuses a header far older than the
/// newest it has seen, and a synthetic header's time is its fill.
fn large_block_dated_as_the_first(fill: u8) -> Vec<u8> {
    let txs: Vec<Vec<u8>> = (0..16)
        .map(|at| parseable_transaction_with_script(at + u32::from(fill), 4096))
        .collect();
    let mut header = committed_header(fill, &txs);
    header[100..104].copy_from_slice(&[1; 4]);
    raw_block(&header, &txs)
}

async fn send_legacy(sender: &BlockSender, raw: &[u8]) {
    let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
    for segment in split_raw_block(hash, raw, 10 * 1124 - 4).unwrap() {
        sender.send_raw_block_segment(segment).await.unwrap();
    }
}

/// A block by the legacy way, sent after everything under test. Packets stay in order on
/// loopback and each task handles them in turn, so anything that was going to cross has
/// crossed once this reaches Zebra. That is how a test shows something did not arrive,
/// with the path shown to be working and no wait to guess at.
async fn behind_a_marker(sender: &BlockSender, sidecar: &Sidecar) {
    let marker = synthetic_block(200);
    sidecar.zebra.knows_of(&marker);
    send_legacy(sender, &marker).await;
    let zebra = Arc::clone(&sidecar.zebra);
    until("the marker", move || zebra.took(&marker)).await;
}

async fn send_bound(sender: &BlockSender, raw: &[u8]) {
    sender
        .send_bound_raw_block(Arc::new(raw.to_vec()))
        .await
        .unwrap();
}

async fn send_each(socket: &UdpSocket, to: SocketAddr, datagrams: &[Vec<u8>]) {
    for datagram in datagrams {
        socket.send_to(datagram, to).await.unwrap();
        tokio::task::yield_now().await;
    }
}

/// This frame's payload swapped for other bytes under the same metadata, root and proof.
/// Its chunks are honest about the object, so only the frame's own check can stop it.
fn forged_frame(frame: &[u8]) -> Vec<u8> {
    let mut forged = frame.to_vec();
    *forged.last_mut().unwrap() ^= 0x01;
    forged
}

fn stop(node: Node, tasks: impl IntoIterator<Item = JoinHandle<Result<(), TransportError>>>) {
    node.node.halt();
    node.task.abort();
    for task in tasks {
        task.abort();
    }
}

// Forged and interleaved.

/// One sender with the key, on the real node with Equihash: chunks of the real body, of
/// another body of its header, and of a forged frame, all in among each other.
#[tokio::test]
async fn forged_and_interleaved_chunks_do_not_mix_up_the_real_body() {
    let (real, other) = (the_real_block(), another_body_of_the_real_header());
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.refuse(&other);
    node.has_a_receiver().await;

    let frames = body_frames(&real).unwrap();
    assert!(frames.len() > 1, "the mix needs more than one segment");
    let forged = sealed_frame(&forged_frame(&frames[frames.len() - 1]), &KEY).unwrap();
    let streams = [
        sealed_body(&other, &KEY).unwrap(),
        sealed_body(&real, &KEY).unwrap(),
        forged,
    ];
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let longest = streams.iter().map(Vec::len).max().unwrap();
    for at in 0..longest {
        for stream in &streams {
            if let Some(datagram) = stream.get(at) {
                socket.send_to(datagram, node.addr).await.unwrap();
            }
        }
        tokio::task::yield_now().await;
    }

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the real body", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&real), 1);
    assert_eq!(
        sidecar
            .metrics
            .raw_segment_reassembly_failures
            .load(Ordering::Relaxed),
        0,
        "no set came out with a segment of another body"
    );
    stop(node, [sidecar.client_task]);
}

/// The forged frame sent straight to the client, past the node: the client's own check
/// stops it. The real frame goes through after it, in the same place.
#[tokio::test]
async fn a_forged_frame_sent_straight_to_the_client_takes_nothing_from_the_real_one() {
    let real = the_real_block();
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);

    let frames = body_frames(&real).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for frame in &frames {
        let forged = sealed_frame(&forged_frame(frame), &KEY).unwrap();
        send_each(&socket, sidecar.client_addr, &forged).await;
    }
    let body = sealed_body(&real, &KEY).unwrap();
    send_each(&socket, sidecar.client_addr, &body).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the real body", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls(), 1, "no forged set ever got that far");
    stop(node, [sidecar.client_task]);
}

// A bad body, then the right one.

/// A body Zebra refuses, then the real one, end to end. This is the block a legacy receiver
/// loses: see the test below, and `known_gap_a_forged_segment_costs_the_block_on_a_real_relay`.
#[tokio::test]
async fn a_bad_body_then_the_right_one_recovers_through_the_real_sidecar_path() {
    let (real, bad) = (the_real_block(), another_body_of_the_real_header());
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.refuse(&bad);
    node.has_a_receiver().await;
    let (first, first_task) = start_sender(node.addr).await;
    let (second, second_task) = start_sender(node.addr).await;

    send_bound(&first, &bad).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = bad.clone();
    until("the refusal", move || zebra.calls_for(&wanted) == 1).await;
    assert!(!sidecar.zebra.took(&bad));

    send_bound(&second, &real).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the real body", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&real), 1);
    sidecar.ledger_settled().await;
    stop(node, [sidecar.client_task, first_task, second_task]);
}

/// The same two bodies by the legacy way, on the same binaries. The refused body takes the
/// client's record, so the real one never reaches the gate. Sending both formats changes
/// nothing for a receiver without the bound path. This test is not a behaviour to keep.
#[tokio::test]
async fn known_gap_a_legacy_receiver_still_loses_the_right_body_after_a_bad_one() {
    let (real, bad) = (the_real_block(), another_body_of_the_real_header());
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, None).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.refuse(&bad);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_dual(&sender, &bad, true).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = bad.clone();
    until("the refusal", move || zebra.calls_for(&wanted) == 1).await;

    send_dual(&sender, &real, true).await;
    behind_a_marker(&sender, &sidecar).await;

    assert_eq!(sidecar.zebra.calls_for(&real), 0, "the client dropped it");
    stop(node, [sidecar.client_task, sender_task]);
}

/// Two senders with one honest body: one submission, and the record stays closed.
#[tokio::test]
async fn two_copies_of_a_block_reach_zebra_once() {
    let real = the_real_block();
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    node.has_a_receiver().await;
    let (first, first_task) = start_sender(node.addr).await;
    let (second, second_task) = start_sender(node.addr).await;

    send_bound(&first, &real).await;
    send_bound(&second, &real).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the block", move || zebra.took(&wanted)).await;
    sidecar.settled().await;
    assert_eq!(sidecar.zebra.calls_for(&real), 1);
    let ledger = sidecar.probe().ledger();
    let segments = body_frames(&real).unwrap().len();
    assert_eq!(
        ledger.completed,
        segments + 1,
        "it and its copy are finished with"
    );
    assert_eq!(ledger.released, 0);
    stop(node, [sidecar.client_task, first_task, second_task]);
}

/// A copy of a body Zebra refused is turned away, at the relay or at the gate. The receiver
/// tells its relays of the refusal, and a relay then keeps the body out for a while; a copy
/// that crossed before that word arrived meets the gate's own memory of the refusal.
async fn a_refused_copy_is_turned_away(node: &Node, sidecar: &Sidecar) {
    let live = Arc::clone(&node.node);
    let metrics = Arc::clone(&sidecar.metrics);
    until("the refused body to be turned away", move || {
        let at_the_relay = live
            .view()
            .usage
            .is_some_and(|usage| usage.anchors_refused_as_released > 0);
        let at_the_gate = metrics
            .submit_gate_rejected_refused_body
            .load(Ordering::Relaxed)
            > 0;
        at_the_relay || at_the_gate
    })
    .await;
}

/// Review item 1 on #134: a body Zebra refused is remembered for the dedup window, so a later
/// copy of the same bytes, here from another connection, is turned away instead of spending a
/// Zebra call. The relays are told too, so most copies stop there. For the sender's own connection, see
/// `the_same_connection_cannot_send_a_refused_body_again`.
#[tokio::test]
async fn another_connection_cannot_send_a_refused_body_again() {
    let real = the_real_block();
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.refuse(&real);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    let (again, again_task) = start_sender(node.addr).await;

    send_bound(&sender, &real).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the refusal", move || zebra.calls_for(&wanted) == 1).await;
    sidecar.ledger_settled().await;
    sidecar.zebra.stop_refusing();

    send_bound(&again, &real).await;

    a_refused_copy_is_turned_away(&node, &sidecar).await;
    assert_eq!(sidecar.zebra.calls_for(&real), 1);
    assert!(!sidecar.zebra.took(&real));
    stop(node, [sidecar.client_task, sender_task, again_task]);
}

/// The same bytes on the same connection, after a refusal, are turned away.
#[tokio::test]
async fn the_same_connection_cannot_send_a_refused_body_again() {
    let real = the_real_block();
    let node = resending_equihash_node().await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.refuse(&real);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &real).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the refusal", move || zebra.calls_for(&wanted) == 1).await;
    sidecar.ledger_settled().await;
    sidecar.zebra.stop_refusing();

    send_bound(&sender, &real).await;

    a_refused_copy_is_turned_away(&node, &sidecar).await;
    assert_eq!(sidecar.zebra.calls_for(&real), 1);
    assert!(!sidecar.zebra.took(&real));
    stop(node, [sidecar.client_task, sender_task]);
}

/// The same bytes on the same connection, after Zebra could not answer at all.
#[tokio::test]
async fn the_same_connection_can_send_a_body_again_after_a_zebra_error() {
    let real = the_real_block();
    let node = resending_equihash_node().await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.go_down();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &real).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the error", move || zebra.calls_for(&wanted) == 1).await;
    sidecar.ledger_settled().await;
    sidecar.zebra.come_back();

    send_bound(&sender, &real).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the block", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&real), 2);
    stop(node, [sidecar.client_task, sender_task]);
}

/// The same bytes on the same connection, after the layer below evicted an unfinished set.
/// Through the node, unlike `an_evicted_body_lets_go_and_can_come_again`. The unfinished set
/// goes only once it is quiet (review item 4 on #134), so the next block waits that long.
#[tokio::test]
async fn the_same_connection_can_send_an_evicted_body_again() {
    let node = stub_pow_node_with(resends_at_once()).await;
    let (evicted, next) = (large_block(1), large_block_dated_as_the_first(2));
    let mut config = BoundRawConfig::default();
    config.stack.buffer.max_sets = 1;
    config.stack.buffer.max_sets_per_block = 1;
    config.look_every = Duration::from_millis(10);
    let sidecar = start_sidecar(node.addr, Some(config)).await;
    sidecar.zebra.knows_of(&evicted);
    sidecar.zebra.knows_of(&next);
    node.has_a_receiver().await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let frames = body_frames(&evicted).unwrap();
    send_each(&socket, node.addr, &sealed_frame(&frames[0], &KEY).unwrap()).await;
    let probe = sidecar.probe().clone();
    until("the first segment to be owned", move || {
        probe.ledger().reserved_bytes > 0
    })
    .await;

    send_each(&socket, node.addr, &sealed_body(&next, &KEY).unwrap()).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = next.clone();
    until("the next block", move || zebra.took(&wanted)).await;
    sidecar.ledger_settled().await;

    send_each(&socket, node.addr, &sealed_body(&evicted, &KEY).unwrap()).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = evicted.clone();
    until("the evicted body", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&evicted), 1);
    stop(node, [sidecar.client_task]);
}

/// Block 3470793 with a byte changed where no txid covers it. `mark` tells them apart.
fn body_marked(mark: u8) -> Vec<u8> {
    let header = fixtures::mainnet_serialized_header();
    let mut txs = fixtures::mainnet_transactions();
    txs[2][70] ^= mark;
    raw_block(&header, &txs)
}

/// The tested case: three other bodies go first, each refused once, and the right one still
/// reaches Zebra. That rests on the gate's budgets, on room to reassemble and on a copy of the
/// right body arriving, so it is no promise. At the limit it does not reach Zebra, and
/// `known_gap_bodies_can_use_up_the_limit_before_the_real_one_comes` shows that.
#[tokio::test]
async fn the_right_body_gets_its_turn_behind_fewer_bodies_than_the_limit() {
    let real = the_real_block();
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    let others: Vec<Vec<u8>> = (1..=3).map(body_marked).collect();
    assert_eq!(others.len() + 1, DEFAULT_STRICT_BODIES_PER_BLOCK);
    for other in &others {
        sidecar.zebra.refuse(other);
    }
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    for other in &others {
        send_bound(&sender, other).await;
        let zebra = Arc::clone(&sidecar.zebra);
        let wanted = other.clone();
        until("the refusal", move || zebra.calls_for(&wanted) == 1).await;
    }
    send_bound(&sender, &real).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the block", move || zebra.took(&wanted)).await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// A receiver's count of copies stops the next one for a while, and that while ends: after
/// an outage longer than the repeat budget, a later copy still gets through. The node allows
/// more here, so the receiver's limit is the one under test.
#[tokio::test]
async fn an_outage_past_the_repeat_budget_does_not_silence_the_body() {
    const RELEASED_TTL: Duration = Duration::from_secs(2);
    let raw = synthetic_block(1);
    let node = stub_pow_node_with(BoundForwardConfig {
        max_resends: 8,
        ..resends_at_once()
    })
    .await;
    let mut config = BoundRawConfig::default();
    config.stack.ledger.repeat_budget = 1;
    config.stack.ledger.released_ttl = RELEASED_TTL;
    config.look_every = Duration::from_millis(10);
    let sidecar = start_sidecar(node.addr, Some(config)).await;
    sidecar.zebra.knows_of(&raw);
    sidecar.zebra.go_down();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    for attempt in 1..=2 {
        send_bound(&sender, &raw).await;
        let zebra = Arc::clone(&sidecar.zebra);
        let wanted = raw.clone();
        until("the error", move || zebra.calls_for(&wanted) == attempt).await;
        sidecar.ledger_settled().await;
    }
    send_bound(&sender, &raw).await;
    sidecar.zebra.come_back();
    behind_a_marker(&sender, &sidecar).await;
    assert_eq!(sidecar.zebra.calls_for(&raw), 2, "past the repeat budget");

    let records_end = std::time::Instant::now() + RELEASED_TTL;
    until("the records to end", move || {
        std::time::Instant::now() >= records_end
    })
    .await;
    send_bound(&sender, &raw).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = raw.clone();
    until("the block", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&raw), 3);
    stop(node, [sidecar.client_task, sender_task]);
}

/// A real header over a body the strict reader stops in, the case the bypass is for.
fn unreadable_block() -> Vec<u8> {
    let mut unknown_layout = 0x8000_0007u32.to_le_bytes().to_vec();
    unknown_layout.extend_from_slice(&0x7a7a_7a7au32.to_le_bytes());
    unknown_layout.resize(400, 0x5a);
    let mut block = fixtures::mainnet_serialized_header();
    block.push(2);
    block.extend_from_slice(&fixtures::mainnet_transactions()[0]);
    block.extend_from_slice(&unknown_layout);
    block
}

/// Off, as it is unless a sidecar is told otherwise: the reader's answer stands and nothing
/// goes to Zebra, on this path as on the others.
#[tokio::test]
async fn an_unreadable_bound_body_stops_at_the_reader_with_the_bypass_off() {
    let block = unreadable_block();
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&block);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &block).await;
    behind_a_marker(&sender, &sidecar).await;

    assert_eq!(sidecar.zebra.calls_for(&block), 0);
    stop(node, [sidecar.client_task, sender_task]);
}

/// On: the one way an unread body reaches Zebra. It goes byte for byte, once, and a copy on
/// the same connection stops at the gate. The block is given back whichever way the attempt
/// goes, because that attempt runs on a task of its own and its answer comes later, so the
/// copy is read again and costs a repeat.
#[tokio::test]
async fn an_unreadable_bound_body_reaches_zebra_once_by_the_bypass() {
    let block = unreadable_block();
    let node = stub_pow_node_with(resends_at_once()).await;
    let bypass = UnreadableSubmit::new(Duration::from_secs(5), 4);
    let sidecar = start_sidecar_with(node.addr, Some(Default::default()), Some(bypass)).await;
    sidecar.zebra.knows_of(&block);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &block).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = block.clone();
    until("the block", move || zebra.took(&wanted)).await;
    sidecar.ledger_settled().await;

    send_bound(&sender, &block).await;
    behind_a_marker(&sender, &sidecar).await;

    assert_eq!(sidecar.zebra.calls_for(&block), 1);
    stop(node, [sidecar.client_task, sender_task]);
}

/// Zebra refuses this copy and turns out to have the block. No copy is wanted now, so it
/// is finished with, and nothing can bring it back.
#[tokio::test]
async fn a_block_zebra_turns_out_to_have_is_finished_with() {
    let real = the_real_block();
    let node = equihash_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&real);
    sidecar.zebra.refuse(&real);
    sidecar.zebra.has_already(&real);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &real).await;

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = real.clone();
    until("the refusal", move || zebra.calls_for(&wanted) == 1).await;
    sidecar.ledger_settled().await;
    let ledger = sidecar.probe().ledger();
    assert_eq!(ledger.completed, body_frames(&real).unwrap().len() + 1);
    assert_eq!(ledger.released, 0);
    stop(node, [sidecar.client_task, sender_task]);
}

// The channel, and what it leaves.

/// One place in the channel and a Zebra that does not answer: the first block is at Zebra,
/// the second in the channel, and the rest wait in the client with their owners. Nothing is
/// lost, every block reaches Zebra once, and everything comes back.
#[tokio::test]
async fn a_full_channel_loses_nothing_and_every_block_goes_through_once() {
    let node = stub_pow_node(true).await;
    let config = BoundRawConfig {
        channel_blocks: 1,
        ..Default::default()
    };
    let options = SidecarOptions {
        bound: Some(config),
        limits: one_task_at_a_time(),
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let blocks: Vec<Vec<u8>> = (1..=4).map(synthetic_block).collect();
    for block in &blocks {
        sidecar.zebra.knows_of(block);
    }
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    for block in &blocks {
        send_bound(&sender, block).await;
    }
    sidecar.is_full_with_waiting(blocks.len() - 2).await;
    assert_eq!(
        sidecar.zebra.calls(),
        0,
        "Zebra is holding its first answer"
    );

    permits.add_permits(blocks.len());

    for block in &blocks {
        let zebra = Arc::clone(&sidecar.zebra);
        let wanted = block.clone();
        until("the block", move || zebra.took(&wanted)).await;
        assert_eq!(sidecar.zebra.calls_for(block), 1);
    }
    sidecar.settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// A consumer gone with a block in its hands, one in the channel and more waiting.
/// Everything comes back, and the client goes on without the bound path.
#[tokio::test]
async fn a_closed_channel_gives_every_reservation_back() {
    let node = stub_pow_node(true).await;
    let config = BoundRawConfig {
        channel_blocks: 1,
        ..Default::default()
    };
    let options = SidecarOptions {
        bound: Some(config),
        limits: one_task_at_a_time(),
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let blocks: Vec<Vec<u8>> = (1..=3).map(synthetic_block).collect();
    for block in &blocks {
        sidecar.zebra.knows_of(block);
    }
    let _held = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    for block in &blocks {
        send_bound(&sender, block).await;
    }
    sidecar.is_full_with_waiting(blocks.len() - 2).await;

    sidecar.handler_task.abort();

    sidecar.settled().await;
    let probe = sidecar.probe().clone();
    assert_eq!(probe.ledger().held, 0);
    assert!(!sidecar.client_task.is_finished(), "the client carries on");
    stop(node, [sidecar.client_task, sender_task]);
}

/// The client's task cancelled with a block at Zebra, one in the channel and one waiting.
/// The one at Zebra ends as usual. The receive task stops with its client, so the one in
/// the channel may go with it, and the one waiting does. Nothing stays counted either way.
#[tokio::test]
async fn a_cancelled_client_leaves_nothing_counted() {
    let node = stub_pow_node(true).await;
    let config = BoundRawConfig {
        channel_blocks: 1,
        ..Default::default()
    };
    let options = SidecarOptions {
        bound: Some(config),
        limits: one_task_at_a_time(),
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let blocks: Vec<Vec<u8>> = (1..=3).map(synthetic_block).collect();
    for block in &blocks {
        sidecar.zebra.knows_of(block);
    }
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    for block in &blocks {
        send_bound(&sender, block).await;
    }
    sidecar.is_full_with_waiting(blocks.len() - 2).await;

    let owned = sidecar.probe().ledger().reserved_bytes;
    sidecar.client_task.abort();
    let probe = sidecar.probe().clone();
    until("the waiting block to let go", move || {
        probe.ledger().reserved_bytes < owned
    })
    .await;

    permits.add_permits(blocks.len());
    sidecar.settled().await;
    assert!(sidecar.zebra.took(&blocks[0]), "the one at Zebra");
    assert!(
        !sidecar.zebra.took(&blocks[2]),
        "the one still in the client"
    );
    stop(node, [sender_task]);
}

/// Room below runs out while a block is at Zebra: what arrives next is refused for room,
/// keeps on the shelf decoded, and goes through by itself once the owner has gone. No
/// second copy is sent.
#[tokio::test]
async fn a_refusal_for_room_is_taken_back_up_with_no_second_copy() {
    let node = stub_pow_node(true).await;
    let (first, second) = (synthetic_block(1), synthetic_block(2));
    let mut config = BoundRawConfig::default();
    // Room for one block's owners and its copy, and not for two blocks.
    config.stack.ledger.max_reserved_bytes = first.len() * 5 / 2;
    config.stack.ledger.transit = Default::default();
    config.look_every = Duration::from_millis(10);
    let sidecar = start_sidecar(node.addr, Some(config)).await;
    sidecar.zebra.knows_of(&first);
    sidecar.zebra.knows_of(&second);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &first).await;
    let probe = sidecar.probe().clone();
    let size = first.len();
    until("the first to be owned", move || {
        probe.ledger().reserved_bytes >= size
    })
    .await;
    let zebra = Arc::clone(&sidecar.zebra);
    until("the first to be at Zebra", move || zebra.waiting() == 1).await;
    send_bound(&sender, &second).await;
    let probe = sidecar.probe().clone();
    until("the second to be on the shelf", move || {
        probe.used().spare_objects > 0
    })
    .await;

    permits.add_permits(2);

    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = second.clone();
    until("the second block", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&first), 1);
    assert_eq!(sidecar.zebra.calls_for(&second), 1);
    sidecar.settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// Part of a body, and nothing more of it: the buffer's time ends it and its reservations
/// come back, and a whole copy goes through after that.
#[tokio::test]
async fn an_unfinished_body_expires_and_a_copy_goes_through() {
    let node = stub_pow_node(true).await;
    let block = large_block(1);
    let frames = body_frames(&block).unwrap();
    assert!(frames.len() > 1, "this needs a body of several segments");
    let mut config = BoundRawConfig::default();
    config.stack.buffer.ttl = Duration::from_millis(300);
    config.stack.assembler.assembly_ttl = Duration::from_millis(300);
    config.look_every = Duration::from_millis(10);
    let sidecar = start_sidecar(node.addr, Some(config)).await;
    sidecar.zebra.knows_of(&block);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first = sealed_frame(&frames[0], &KEY).unwrap();
    send_each(&socket, sidecar.client_addr, &first).await;
    let probe = sidecar.probe().clone();
    until("the first segment to be owned", move || {
        probe.ledger().reserved_bytes > 0
    })
    .await;

    sidecar.settled().await;

    let body = sealed_body(&block, &KEY).unwrap();
    send_each(&socket, sidecar.client_addr, &body).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = block.clone();
    until("the block", move || zebra.took(&wanted)).await;
    stop(node, [sidecar.client_task]);
}

/// One set at a time below: a body that is not finished gives way to the next, gives its
/// reservations back, and can come again whole.
#[tokio::test]
async fn an_evicted_body_lets_go_and_can_come_again() {
    let node = stub_pow_node(true).await;
    let (evicted, next) = (large_block(1), large_block_dated_as_the_first(2));
    let mut config = BoundRawConfig::default();
    config.stack.buffer.max_sets = 1;
    config.stack.buffer.max_sets_per_block = 1;
    config.look_every = Duration::from_millis(10);
    let sidecar = start_sidecar(node.addr, Some(config)).await;
    sidecar.zebra.knows_of(&evicted);
    sidecar.zebra.knows_of(&next);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let frames = body_frames(&evicted).unwrap();
    let first = sealed_frame(&frames[0], &KEY).unwrap();
    send_each(&socket, sidecar.client_addr, &first).await;
    let probe = sidecar.probe().clone();
    until("the first segment to be owned", move || {
        probe.ledger().reserved_bytes > 0
    })
    .await;

    let body = sealed_body(&next, &KEY).unwrap();
    send_each(&socket, sidecar.client_addr, &body).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = next.clone();
    until("the next block", move || zebra.took(&wanted)).await;
    sidecar.ledger_settled().await;

    let body = sealed_body(&evicted, &KEY).unwrap();
    send_each(&socket, sidecar.client_addr, &body).await;
    let zebra = Arc::clone(&sidecar.zebra);
    let wanted = evicted.clone();
    until("the evicted body", move || zebra.took(&wanted)).await;
    assert_eq!(sidecar.zebra.calls_for(&evicted), 1);
    stop(node, [sidecar.client_task]);
}

/// A body close to the largest there is, with the research values as they stand. The fixture
/// is a few segments, so this is the one test of those values at the size they are for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_of_nearly_the_largest_size_crosses_with_the_research_values() {
    let block = a_block_of_nearly_the_largest_size();
    let frames = body_frames(&block).unwrap();
    assert!(frames.len() > 190, "{} segments", frames.len());
    cross_and_report(block).await;
}

fn a_block_of_nearly_the_largest_size() -> Vec<u8> {
    let txs: Vec<Vec<u8>> = (0..470)
        .map(|at| parseable_transaction_with_script(at, 4096))
        .collect();
    raw_block(&committed_header(7, &txs), &txs)
}

/// The same way across for the block the repository has, so the cost of how it is sent can be
/// read at the size most blocks are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_of_the_usual_size_is_timed_the_same_way() {
    cross_and_report(the_real_block()).await;
}

/// What a dual sender costs its legacy copy: an ingress sends the two side by side, and the
/// bound copy has a task of its own, so this should say little. A legacy receiver, because
/// that is who gets it. This reports and asserts nothing, and the CI job reads the numbers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run by the bound path diagnostic job"]
async fn a_dual_send_reports_how_long_the_legacy_copy_waits() {
    let blocks = [
        ("usual", the_real_block()),
        ("largest", a_block_of_nearly_the_largest_size()),
    ];
    for (name, block) in blocks {
        let alone = legacy_copy_reaches_zebra(&block, false).await;
        let beside_bound = legacy_copy_reaches_zebra(&block, true).await;
        println!("{name}: legacy alone {alone:?}, legacy beside a bound copy {beside_bound:?}");
    }
}

async fn legacy_copy_reaches_zebra(block: &[u8], beside_bound: bool) -> Option<Duration> {
    let (forward, burst, gap) = crossing_case();
    let node = stub_pow_node_with(forward).await;
    let sidecar = start_sidecar(node.addr, None).await;
    sidecar.zebra.knows_of(block);
    node.has_a_receiver().await;
    let config = client_config(node.addr)
        .with_send_pacing(0, Duration::ZERO)
        .with_bound_send_pacing(burst, gap);
    let (sender, sender_task) = start_sender_with(config).await;

    let started = std::time::Instant::now();
    let bound = async {
        if beside_bound {
            send_bound(&sender, block).await;
        }
    };
    let reaches_zebra = async {
        let mut taken = None;
        while taken.is_none() && started.elapsed() < WAIT {
            if sidecar.zebra.took(block) {
                taken = Some(started.elapsed());
            }
            sleep(Duration::from_millis(1)).await;
        }
        taken
    };
    let (_, (), taken) = tokio::join!(send_legacy(&sender, block), bound, reaches_zebra);

    stop(node, [sidecar.client_task, sender_task]);
    taken
}

/// How a body is sent and taken in. Unset is what a real sender and relay do with their
/// defaults, with no send pacing configured. The others are for the comparison the CI job
/// runs, to show what each part does alone. `before` is the sender of the test as it was.
fn crossing_case() -> (BoundForwardConfig, usize, Duration) {
    let queued = BoundForwardConfig::default();
    let unqueued = BoundForwardConfig {
        max_queued_datagrams: 0,
        ..queued
    };
    let paced = (BOUND_SEND_BURST_PACKETS, BOUND_SEND_BURST_DELAY);
    let (node, (burst, gap)) = match std::env::var("BOUND_PATH_CASE").as_deref() {
        Ok("before") => (unqueued, (32, Duration::from_micros(200))),
        Ok("drain-only") => (queued, (0, Duration::ZERO)),
        Ok("pacing-only") => (unqueued, paced),
        _ => (queued, paced),
    };
    (node, burst, gap)
}

async fn cross_and_report(block: Vec<u8>) {
    let (forward, burst, gap) = crossing_case();
    let node = stub_pow_node_with(forward).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    sidecar.zebra.knows_of(&block);
    node.has_a_receiver().await;
    let config = client_config(node.addr)
        .with_send_pacing(0, Duration::ZERO)
        .with_bound_send_pacing(burst, gap);
    let (sender, sender_task) = start_sender_with(config).await;
    let watch = PathWatch {
        node: &node,
        sidecar: &sidecar,
        sender: &sender,
        segments: body_frames(&block).unwrap().len(),
        datagrams: sealed_body(&block, &KEY).unwrap().len(),
        udp_before: kernel_udp_errors(),
        backlog_before: kernel_backlog_drops(),
    };

    // Side by side, as the send takes as long as it takes and the report is of that time.
    let sent = timeout(WAIT, sender.send_bound_raw_block(Arc::new(block.clone())));
    let (sent, ()) = tokio::join!(sent, watch.wait_for_the_block(&block));
    sent.expect("the send never ended").unwrap();
    assert_eq!(sidecar.zebra.calls_for(&block), 1);
    sidecar.ledger_settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

// What a run of that body came to, hop by hop, because it has failed on Linux with nothing to
// say why. This changes nothing about the run. A counter says what one side saw, so a gap
// between two of them is no proof of loss: a datagram can still be queued or being worked on.
// What says a socket lost something is the kernel's count for that socket, on Linux only.

/// A socket's line of a `/proc/net/udp` table: bytes waiting to be read, and what the kernel
/// dropped for it since it opened.
fn udp_table_line(table: &str, port: u16) -> Option<(u64, u64)> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (_, local_port) = fields.get(1)?.split_once(':')?;
        if u16::from_str_radix(local_port, 16).ok()? != port {
            return None;
        }
        let (_, queued) = fields.get(4)?.split_once(':')?;
        let queued = u64::from_str_radix(queued, 16).ok()?;
        Some((queued, fields.last()?.parse().ok()?))
    })
}

fn kernel_socket(port: u16) -> Option<(u64, u64)> {
    udp_table_line(&std::fs::read_to_string("/proc/net/udp").ok()?, port)
}

/// The UDP error counters of the whole machine, so every test running now is in them.
fn kernel_udp_errors() -> Option<Vec<(String, u64)>> {
    let table = std::fs::read_to_string("/proc/net/snmp").ok()?;
    let mut udp = table.lines().filter(|line| line.starts_with("Udp:"));
    let (names, values) = (udp.next()?, udp.next()?);
    let pairs = names.split_whitespace().zip(values.split_whitespace());
    Some(
        pairs
            .filter(|(name, _)| name.ends_with("Errors"))
            .filter_map(|(name, value)| Some((name.to_string(), value.parse().ok()?)))
            .collect(),
    )
}

/// Packets dropped in the queue ahead of every socket, for the whole machine. Loopback traffic
/// passes through it, and a drop here shows in no socket's count.
fn kernel_backlog_drops() -> Option<u64> {
    let table = std::fs::read_to_string("/proc/net/softnet_stat").ok()?;
    table
        .lines()
        .map(|line| u64::from_str_radix(line.split_whitespace().nth(1)?, 16).ok())
        .sum()
}

fn kernel_limit(name: &str) -> String {
    std::fs::read_to_string(format!("/proc/sys/net/core/{name}")).map_or_else(
        |_| "not available".to_string(),
        |value| value.trim().to_string(),
    )
}

struct PathWatch<'a> {
    node: &'a Node,
    sidecar: &'a Sidecar,
    sender: &'a BlockSender,
    segments: usize,
    datagrams: usize,
    udp_before: Option<Vec<(String, u64)>>,
    backlog_before: Option<u64>,
}

impl PathWatch<'_> {
    /// One line of the timeline. Whether these still move tells a slow run from a stopped one.
    fn line(&self, at: Duration) -> String {
        let view = self.node.node.view();
        let usage = view.usage.unwrap_or_default();
        let client = self.sidecar.probe().progress();
        let (node_queue, node_drops) = kernel_socket(self.node.addr.port()).unzip();
        let (client_queue, client_drops) = kernel_socket(self.sidecar.client_addr.port()).unzip();
        format!(
            "{at:>7.1?} sent {} | node took {} queued {node_queue:?} dropped {node_drops:?} \
             decoded {} forwarded {} | client took {} queued {client_queue:?} \
             dropped {client_drops:?} decoded {} held {} blocks {}",
            self.sender.sends().sent,
            usage.arrivals.datagrams,
            usage.arrivals.decoded,
            view.metrics.packets_forwarded,
            client.arrivals.datagrams,
            client.arrivals.decoded,
            client.handoffs.segments_held,
            client.handoffs.blocks_to_consumer,
        )
    }

    fn report(
        &self,
        timeline: &[String],
        sender_done: Option<Duration>,
        taken: Option<Duration>,
    ) -> String {
        let view = self.node.node.view();
        let metrics = &view.metrics;
        let usage = view.usage.unwrap_or_default();
        let probe = self.sidecar.probe();
        let zebra = &self.sidecar.zebra;
        format!(
            "case: {case}\n\
             expected: {segments} segments, {datagrams} datagrams from the sender\n\
             timing: sender done {sender_done:?}, block taken {taken:?}\n\
             scope: since each socket or node started. Counters are read one at a time, so no \
             line is a single instant. `sent` is what a socket took. Sizes the system reports \
             for a receive buffer on Linux are twice the usable size.\n\
             limits: rmem_max {rmem_max} rmem_default {rmem_default} \
             netdev_max_backlog {backlog}\n\
             machine-wide UDP errors, every running test included: before {before:?} \
             after {after:?}\n\
             machine-wide drops ahead of every socket: before {backlog_before:?} \
             after {backlog_after:?}\n\
             \nsender to node\n\
             sender socket: {sends:?}\n\
             node socket: granted {node_buffer:?}, queued and dropped {node_socket:?}\n\
             node, every packet: received {received} invalid {invalid} auth failures {auth} \
             rate limited {limited} receive errors {receive_errors}\n\
             node, this path: {arrivals:?}\n\
             node queue, in microseconds: {ingress:?}\n\
             node frames: rejected {frames} pow refused {pow} pow indeterminate {unsure} \
             pushed out waiting for segment 0 {pushed}\n\
             \nnode to client\n\
             node sent on: objects {objects} packets {forwarded} send errors {send_errors} \
             no peer {no_peer} no pool place {no_place}\n\
             client socket: granted {client_buffer:?}, queued and dropped {client_socket:?}\n\
             client, this path: {client_arrivals:?}\n\
             client hand-over: {handoffs:?}\n\
             \nstill open at this point\n\
             node: {pool:?}, waiting for segment 0 {waiting}\n\
             client: {used:?}\n\
             ledger: {ledger:?}\n\
             zebra: calls {calls} held back {held}\n\
             \ntimeline\n{timeline}",
            case = std::env::var("BOUND_PATH_CASE").unwrap_or_else(|_| "defaults".to_string()),
            segments = self.segments,
            datagrams = self.datagrams,
            rmem_max = kernel_limit("rmem_max"),
            rmem_default = kernel_limit("rmem_default"),
            backlog = kernel_limit("netdev_max_backlog"),
            before = self.udp_before,
            after = kernel_udp_errors(),
            backlog_before = self.backlog_before,
            backlog_after = kernel_backlog_drops(),
            sends = self.sender.sends(),
            node_buffer = view.recv_buffer,
            node_socket = kernel_socket(self.node.addr.port()),
            received = metrics.packets_received,
            invalid = metrics.invalid_chunks,
            auth = metrics.auth_failures,
            limited = metrics.unauth_rate_limited,
            receive_errors = metrics.socket_receive_errors,
            arrivals = usage.arrivals,
            ingress = usage.ingress,
            frames = usage.frames_rejected,
            pow = usage.pow_refused,
            unsure = usage.pow_indeterminate,
            pushed = usage.waiting_pushed_out,
            objects = usage.objects_sent_on,
            forwarded = metrics.packets_forwarded,
            send_errors = metrics.packet_send_errors,
            no_peer = metrics.forward_no_peer_chunks,
            no_place = usage.datagrams_without_a_place,
            client_buffer = self.sidecar.recv_buffer,
            client_socket = kernel_socket(self.sidecar.client_addr.port()),
            client_arrivals = probe.progress().arrivals,
            handoffs = probe.progress().handoffs,
            pool = usage.pool,
            waiting = usage.objects_waiting_for_segment_0,
            used = probe.used(),
            ledger = probe.ledger(),
            calls = zebra.calls(),
            held = zebra.waiting(),
            timeline = timeline.join("\n"),
        )
    }

    /// `until` for the block, with the same wait, and a report of how far it got.
    async fn wait_for_the_block(&self, raw: &[u8]) {
        let started = std::time::Instant::now();
        let mut timeline = Vec::new();
        let mut sender_done = None;
        while started.elapsed() < WAIT {
            if self.sidecar.zebra.took(raw) {
                let taken = started.elapsed();
                timeline.push(self.line(taken));
                println!("{}", self.report(&timeline, sender_done, Some(taken)));
                return;
            }
            if sender_done.is_none() && self.sender.sends().sent as usize >= self.datagrams {
                sender_done = Some(started.elapsed());
            }
            if started.elapsed() >= Duration::from_secs(timeline.len() as u64) {
                timeline.push(self.line(started.elapsed()));
            }
            sleep(Duration::from_millis(5)).await;
        }
        timeline.push(self.line(started.elapsed()));
        panic!(
            "gave up waiting for the block\n{}",
            self.report(&timeline, sender_done, None)
        );
    }
}

#[test]
fn a_socket_is_found_in_the_kernels_table_by_its_port() {
    let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   \
                 uid  timeout inode ref pointer drops\n\
                 123: 0100007F:1F90 00000000:0000 07 00000000:00000A00 00:00000000 00000000 \
                 1000 0 4242 2 0000000000000000 37\n";

    assert_eq!(udp_table_line(table, 0x1f90), Some((0xa00, 37)));
    assert_eq!(udp_table_line(table, 0x1f91), None);
}

// Consecutive honest traffic.

/// A small table of what was decoded and few normal places. Blocks come one after the
/// other, and behind each one the last parity of everything before it, as a slower path
/// would bring it. With the old rule the leftovers filled the normal places.
#[tokio::test]
async fn leftovers_never_stop_the_next_honest_block() {
    let node = stub_pow_node(true).await;
    let mut config = BoundRawConfig::default();
    config.stack.max_carried = 2;
    config.stack.budget.max_objects = 4;
    let sidecar = start_sidecar(node.addr, Some(config)).await;
    let blocks: Vec<Vec<u8>> = (1..=12).map(synthetic_block).collect();
    for block in &blocks {
        sidecar.zebra.knows_of(block);
    }

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (at, block) in blocks.iter().enumerate() {
        let body = sealed_body(block, &KEY).unwrap();
        assert_eq!(body.len(), 13, "one segment, one object");
        let (needed, leftover) = body.split_at(10);
        send_each(&socket, sidecar.client_addr, needed).await;
        let zebra = Arc::clone(&sidecar.zebra);
        let wanted = block.clone();
        until("the block", move || zebra.took(&wanted)).await;
        // Everything so far, late. All but the newest are forgotten by now.
        for earlier in &blocks[..at] {
            let late = sealed_body(earlier, &KEY).unwrap();
            send_each(&socket, sidecar.client_addr, &late[12..]).await;
        }
        send_each(&socket, sidecar.client_addr, leftover).await;
    }

    for block in &blocks {
        assert_eq!(sidecar.zebra.calls_for(block), 1);
    }
    stop(node, [sidecar.client_task]);
}

// What each side of a mixed network gets, in one build with the bound path off on the old
// side. This is a quick check and no evidence about an old release: for that, see
// `research/real-binaries/matrix.py`, which runs builds of the real tags as processes.

// Zebra's time is not the receive task's. A block at Zebra, in its parent lookup or in its
// submit, leaves everything else this task does alone. Each of these holds Zebra's answer, so
// what they look at happens while it is held, and no wait stands in for that.

/// Until this many `submitblock` calls have come in, with Zebra holding them.
async fn held_at_zebra(sidecar: &Sidecar, count: u64) {
    let zebra = Arc::clone(&sidecar.zebra);
    until("the calls to be at Zebra", move || zebra.waiting() == count).await;
}

async fn zebra_took(sidecar: &Sidecar, raw: &[u8]) {
    let (zebra, wanted) = (Arc::clone(&sidecar.zebra), raw.to_vec());
    until("the block to reach Zebra", move || zebra.took(&wanted)).await;
}

/// Until this many whole blocks have reached the receive task, by any way.
async fn blocks_complete(sidecar: &Sidecar, count: u64) {
    let metrics = Arc::clone(&sidecar.metrics);
    until("the blocks to complete", move || {
        metrics.raw_segment_sets_completed.load(Ordering::Relaxed) == count
    })
    .await;
}

/// A part of a legacy block, which asks nothing of Zebra. Payloads are handled in the order they
/// came, so once this is in so is everything sent ahead of it, with Zebra holding what it likes.
async fn behind_a_part(sender: &BlockSender, sidecar: &Sidecar) {
    let part = large_block(240);
    let hash = zcash_block_hash(&part[..ZCASH_FULL_HEADER_SIZE]);
    let first = split_raw_block(hash, &part, 10 * 1124 - 4)
        .unwrap()
        .remove(0);
    sender.send_raw_block_segment(first).await.unwrap();
    let metrics = Arc::clone(&sidecar.metrics);
    until("the part to be buffered", move || {
        metrics
            .raw_segment_incomplete_blocks
            .load(Ordering::Relaxed)
            == 1
    })
    .await;
}

/// The header of [`synthetic_block`] over other transactions: its hash, and none of its bytes.
fn other_bytes_of_synthetic_block(fill: u8) -> Vec<u8> {
    let txs = vec![
        parseable_transaction(u32::from(fill) * 2),
        parseable_transaction(u32::from(fill) * 2 + 1),
    ];
    let others = vec![parseable_transaction(u32::from(fill) * 2 + 100)];
    raw_block(&committed_header(fill, &txs), &others)
}

/// [`synthetic_block`], in its compact form with every transaction in it.
fn compact_of_synthetic_block(fill: u8) -> CompactBlock {
    let txs = vec![
        parseable_transaction(u32::from(fill) * 2),
        parseable_transaction(u32::from(fill) * 2 + 1),
    ];
    let prefilled = txs.iter().map(|tx| sovright_relay::PrefilledTx {
        index: 0,
        tx_data: tx.clone(),
    });
    CompactBlock::new(
        committed_header(fill, &txs),
        0,
        Vec::new(),
        prefilled.collect(),
    )
}

#[tokio::test]
async fn a_held_zebra_call_lets_a_different_block_through() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let (held, next) = (synthetic_block(1), synthetic_block(2));
    sidecar.zebra.knows_of(&held);
    sidecar.zebra.knows_of(&next);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &held).await;
    held_at_zebra(&sidecar, 1).await;
    send_bound(&sender, &next).await;

    held_at_zebra(&sidecar, 2).await;
    permits.add_permits(2);
    zebra_took(&sidecar, &held).await;
    zebra_took(&sidecar, &next).await;
    sidecar.settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

#[tokio::test]
async fn a_held_zebra_call_lets_legacy_traffic_through() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let (held, legacy) = (synthetic_block(1), synthetic_block(2));
    sidecar.zebra.knows_of(&held);
    sidecar.zebra.knows_of(&legacy);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &held).await;
    held_at_zebra(&sidecar, 1).await;
    send_legacy(&sender, &legacy).await;

    held_at_zebra(&sidecar, 2).await;
    permits.add_permits(2);
    zebra_took(&sidecar, &held).await;
    zebra_took(&sidecar, &legacy).await;
    sidecar.settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// Part of a legacy block comes in and its time runs out, all with a call at Zebra.
#[tokio::test]
async fn a_held_zebra_call_lets_cleanup_run() {
    let node = stub_pow_node(true).await;
    let options = SidecarOptions {
        raw_ttl: Duration::from_millis(200),
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let (held, part) = (synthetic_block(1), large_block(2));
    sidecar.zebra.knows_of(&held);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &held).await;
    held_at_zebra(&sidecar, 1).await;

    let hash = zcash_block_hash(&part[..ZCASH_FULL_HEADER_SIZE]);
    let mut segments = split_raw_block(hash, &part, 10 * 1124 - 4).unwrap();
    assert!(segments.len() > 1, "this needs part of a block");
    let first = segments.remove(0);
    sender.send_raw_block_segment(first).await.unwrap();
    let metrics = Arc::clone(&sidecar.metrics);
    until("the part to be buffered", move || {
        metrics
            .raw_segment_incomplete_blocks
            .load(Ordering::Relaxed)
            == 1
    })
    .await;

    let metrics = Arc::clone(&sidecar.metrics);
    until("the part to expire", move || {
        metrics
            .raw_segment_incomplete_blocks
            .load(Ordering::Relaxed)
            == 0
    })
    .await;
    assert_eq!(sidecar.zebra.waiting(), 1, "the call is still held");
    permits.add_permits(1);
    zebra_took(&sidecar, &held).await;
    stop(node, [sidecar.client_task, sender_task]);
}

#[tokio::test]
async fn a_held_parent_lookup_lets_a_different_block_through() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let (held, next) = (synthetic_block(1), synthetic_block(2));
    sidecar.zebra.knows_of(&held);
    sidecar.zebra.knows_of(&next);
    let permits = sidecar.zebra.hold_lookups();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    send_bound(&sender, &held).await;
    let zebra = Arc::clone(&sidecar.zebra);
    until("the first lookup", move || {
        zebra.lookups_held.load(Ordering::Relaxed) == 1
    })
    .await;
    send_bound(&sender, &next).await;

    let zebra = Arc::clone(&sidecar.zebra);
    until("the second lookup", move || {
        zebra.lookups_held.load(Ordering::Relaxed) == 2
    })
    .await;
    permits.add_permits(8);
    zebra_took(&sidecar, &held).await;
    zebra_took(&sidecar, &next).await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// Every task is at Zebra. More blocks wait where they waited before, in the channel, with
/// none of them started. This task goes on with parts of legacy blocks, which ask nothing of
/// Zebra, so it goes round many times with those blocks there to take. Then a whole legacy block
/// gets through, nothing waits for a place, and nothing is lost.
#[tokio::test]
async fn full_tasks_stop_nothing_else_and_lose_nothing() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let running = BoundTaskLimits::default().running;
    let blocks: Vec<Vec<u8>> = (1..=running as u8 + 2).map(synthetic_block).collect();
    let legacy = synthetic_block(100);
    for block in blocks.iter().chain([&legacy]) {
        sidecar.zebra.knows_of(block);
    }
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    for block in &blocks[..running] {
        send_bound(&sender, block).await;
    }
    held_at_zebra(&sidecar, running as u64).await;
    let owned = sidecar.probe().ledger().held + sidecar.probe().ledger().in_flight;
    for block in &blocks[running..] {
        send_bound(&sender, block).await;
    }
    let probe = sidecar.probe().clone();
    until("the rest to be whole", move || {
        probe.ledger().held + probe.ledger().in_flight > owned + 1
    })
    .await;

    const PARTS: usize = 16;
    for fill in 0..PARTS {
        let part = large_block(40 + fill as u8);
        let hash = zcash_block_hash(&part[..ZCASH_FULL_HEADER_SIZE]);
        let first = split_raw_block(hash, &part, 10 * 1124 - 4)
            .unwrap()
            .remove(0);
        sender.send_raw_block_segment(first).await.unwrap();
    }
    let metrics = Arc::clone(&sidecar.metrics);
    until("the parts to be taken in", move || {
        metrics
            .raw_segment_incomplete_blocks
            .load(Ordering::Relaxed)
            == PARTS
    })
    .await;
    assert_eq!(
        sidecar.zebra.waiting(),
        running as u64,
        "none past the limit"
    );

    send_legacy(&sender, &legacy).await;
    held_at_zebra(&sidecar, running as u64 + 1).await;

    permits.add_permits(blocks.len() + 1);
    for block in blocks.iter().chain([&legacy]) {
        zebra_took(&sidecar, block).await;
        assert_eq!(sidecar.zebra.calls_for(block), 1);
    }
    sidecar.ledger_settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// What cancels the receive task cancels what it started, and the block it was at Zebra with
/// is free to come again: the gate's slot is gone, its reservation is back, and nothing says
/// the block is dealt with. No receive task is left here to take it, so what shows it going
/// through is `a_task_past_its_budget_gives_way_to_a_copy`.
#[tokio::test]
async fn a_cancelled_handler_leaves_the_body_free_to_come_again() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    let _held = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &block).await;
    held_at_zebra(&sidecar, 1).await;
    assert!(sidecar.gate_has_at_zebra(&block).await, "the slot is taken");

    sidecar.handler_task.abort();

    sidecar.settled().await;
    sidecar.gate_lets_go_of(&block).await;
    assert_eq!(sidecar.probe().ledger().completed, 0);
    assert!(!sidecar.gate_knows(&block).await);
    stop(node, [sidecar.client_task, sender_task]);
}

/// What cancels the receive task cancels what it started, and each block goes back.
#[tokio::test]
async fn a_cancelled_handler_gives_back_what_its_tasks_held() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let blocks: Vec<Vec<u8>> = (1..=2).map(synthetic_block).collect();
    for block in &blocks {
        sidecar.zebra.knows_of(block);
    }
    let _held = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    for block in &blocks {
        send_bound(&sender, block).await;
    }
    held_at_zebra(&sidecar, 2).await;

    sidecar.handler_task.abort();

    sidecar.settled().await;
    assert!(!sidecar.client_task.is_finished(), "the client carries on");
    stop(node, [sidecar.client_task, sender_task]);
}

/// A task out of time lets go of everything: the block, so a copy can come, and the gate, so
/// that copy is no repeat of a call in progress.
#[tokio::test]
async fn a_task_past_its_budget_gives_way_to_a_copy() {
    let node = stub_pow_node_with(resends_at_once()).await;
    let options = SidecarOptions {
        limits: BoundTaskLimits {
            budget: Duration::from_millis(200),
            ..Default::default()
        },
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    let _held = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &block).await;
    held_at_zebra(&sidecar, 1).await;

    sidecar.ledger_settled().await;
    sidecar.gate_lets_go_of(&block).await;
    assert_eq!(sidecar.probe().ledger().completed, 0);
    sidecar.zebra.stop_holding();
    send_bound(&sender, &block).await;

    zebra_took(&sidecar, &block).await;
    sidecar.gate_learns_of(&block).await;
    assert_eq!(sidecar.zebra.arrivals_for(&block), 2);
    sidecar.settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// The client goes, and the receive task ends with it, with a call Zebra never answers. A found
/// block gets its time at Zebra first, up to its budget.
#[tokio::test]
async fn a_client_that_goes_ends_the_handler_within_the_budget() {
    let node = stub_pow_node(true).await;
    let options = SidecarOptions {
        limits: BoundTaskLimits {
            budget: Duration::from_millis(200),
            ..Default::default()
        },
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    let _held = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &block).await;
    held_at_zebra(&sidecar, 1).await;

    sidecar.client_task.abort();

    let finished = timeout(WAIT, sidecar.handler_task).await;
    assert!(finished.is_ok(), "the handler is still waiting");
    stop(node, [sender_task]);
}

/// Out of time at its parent lookup, before the gate has heard of it. There is no slot to let
/// go of yet, and everything else goes as it does at Zebra.
#[tokio::test]
async fn a_task_out_of_time_at_its_parent_lookup_gives_way_too() {
    let node = stub_pow_node_with(resends_at_once()).await;
    let options = SidecarOptions {
        limits: BoundTaskLimits {
            budget: Duration::from_millis(200),
            ..Default::default()
        },
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    let _held = sidecar.zebra.hold_lookups();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &block).await;
    let zebra = Arc::clone(&sidecar.zebra);
    until("the lookup", move || {
        zebra.lookups_held.load(Ordering::Relaxed) == 1
    })
    .await;

    sidecar.ledger_settled().await;
    assert_eq!(sidecar.probe().ledger().completed, 0);
    sidecar.zebra.stop_holding_lookups();
    send_bound(&sender, &block).await;

    zebra_took(&sidecar, &block).await;
    assert_eq!(sidecar.zebra.calls_for(&block), 1);
    sidecar.settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// Dual: the same body by both ways, the bound copy at Zebra when the legacy one is whole. It
/// waits, and with Zebra's answer it has nothing to do. Zebra hears of the block once.
#[tokio::test]
async fn a_legacy_copy_during_a_bound_task_waits_and_is_then_a_repeat() {
    for gate in [true, false] {
        let node = stub_pow_node(true).await;
        let options = SidecarOptions {
            gate,
            ..Default::default()
        };
        let sidecar = start_sidecar_from(node.addr, options).await;
        let block = synthetic_block(1);
        sidecar.zebra.knows_of(&block);
        let permits = sidecar.zebra.hold();
        node.has_a_receiver().await;
        let (sender, sender_task) = start_sender(node.addr).await;
        send_bound(&sender, &block).await;
        held_at_zebra(&sidecar, 1).await;

        send_legacy(&sender, &block).await;
        blocks_complete(&sidecar, 2).await;
        permits.add_permits(2);

        zebra_took(&sidecar, &block).await;
        behind_a_marker(&sender, &sidecar).await;
        assert_eq!(sidecar.zebra.calls_for(&block), 1, "gate {gate}");
        sidecar.settled().await;
        stop(node, [sidecar.client_task, sender_task]);
    }
}

/// The same, and Zebra could not answer the bound copy. The legacy copy was held for this: it
/// is the retry, and nothing else was going to be.
#[tokio::test]
async fn a_legacy_copy_during_a_bound_task_goes_when_that_task_fails() {
    for gate in [true, false] {
        let node = stub_pow_node(true).await;
        let options = SidecarOptions {
            gate,
            ..Default::default()
        };
        let sidecar = start_sidecar_from(node.addr, options).await;
        let block = synthetic_block(1);
        sidecar.zebra.knows_of(&block);
        sidecar.zebra.go_down();
        let permits = sidecar.zebra.hold();
        node.has_a_receiver().await;
        let (sender, sender_task) = start_sender(node.addr).await;
        send_bound(&sender, &block).await;
        held_at_zebra(&sidecar, 1).await;
        send_legacy(&sender, &block).await;
        blocks_complete(&sidecar, 2).await;

        permits.add_permits(1);
        let (zebra, wanted) = (Arc::clone(&sidecar.zebra), block.clone());
        until("the error", move || zebra.calls_for(&wanted) == 1).await;
        sidecar.zebra.come_back();
        held_at_zebra(&sidecar, 2).await;
        permits.add_permits(1);

        zebra_took(&sidecar, &block).await;
        assert_eq!(sidecar.zebra.calls_for(&block), 2, "gate {gate}");
        sidecar.ledger_settled().await;
        stop(node, [sidecar.client_task, sender_task]);
    }
}

/// Until the receive task has buffered a part of a legacy block, which asks nothing of Zebra.
async fn takes_a_part(sender: &BlockSender, sidecar: &Sidecar, fill: u8, incomplete: usize) {
    let part = large_block(fill);
    let hash = zcash_block_hash(&part[..ZCASH_FULL_HEADER_SIZE]);
    let first = split_raw_block(hash, &part, 10 * 1124 - 4)
        .unwrap()
        .remove(0);
    sender.send_raw_block_segment(first).await.unwrap();
    let metrics = Arc::clone(&sidecar.metrics);
    until("the part to be buffered", move || {
        metrics
            .raw_segment_incomplete_blocks
            .load(Ordering::Relaxed)
            == incomplete
    })
    .await;
}

/// The held-copy stall. Zebra fails the bound copy and then sits on every call. The copy held
/// for it is the retry, and it waits at Zebra on a task of its own: the receive task goes on
/// with other payloads, and another bound block gets to Zebra beside it. Before, the retry ran
/// here, and this task waited on Zebra with it.
#[tokio::test]
async fn the_held_copy_stall_stops_nothing_else() {
    for by in [CopyBy::Legacy, CopyBy::Compact] {
        let node = stub_pow_node(true).await;
        let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
        let (block, next) = (synthetic_block(1), synthetic_block(2));
        sidecar.zebra.knows_of(&block);
        sidecar.zebra.knows_of(&next);
        sidecar.zebra.go_down();
        let permits = sidecar.zebra.hold();
        node.has_a_receiver().await;
        let (sender, sender_task) = start_sender(node.addr).await;
        send_bound(&sender, &block).await;
        held_at_zebra(&sidecar, 1).await;
        match by {
            CopyBy::Legacy => send_legacy(&sender, &block).await,
            CopyBy::Compact => sender.send(compact_of_synthetic_block(1)).await.unwrap(),
        }
        takes_a_part(&sender, &sidecar, 240, 1).await;
        assert_eq!(
            sidecar.zebra.arrivals_for(&block),
            1,
            "{by:?}: the copy waits"
        );

        permits.add_permits(1);
        let (zebra, wanted) = (Arc::clone(&sidecar.zebra), block.clone());
        until("the error", move || zebra.calls_for(&wanted) == 1).await;
        sidecar.zebra.come_back();
        held_at_zebra(&sidecar, 2).await;
        assert_eq!(sidecar.zebra.arrivals_for(&block), 2, "{by:?}: the retry");

        takes_a_part(&sender, &sidecar, 241, 2).await;
        send_bound(&sender, &next).await;
        held_at_zebra(&sidecar, 3).await;
        assert_eq!(sidecar.zebra.arrivals_for(&next), 1, "{by:?}");

        permits.add_permits(2);
        zebra_took(&sidecar, &block).await;
        zebra_took(&sidecar, &next).await;
        assert_eq!(sidecar.zebra.calls_for(&block), 2, "{by:?}");
        sidecar.ledger_settled().await;
        stop(node, [sidecar.client_task, sender_task]);
    }
}

/// Another bound copy of the body at Zebra. The block's owner keeps it out, and nothing here
/// has to.
#[tokio::test]
async fn a_second_bound_copy_during_a_task_does_not_reach_zebra() {
    let node = stub_pow_node_with(resends_at_once()).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &block).await;
    held_at_zebra(&sidecar, 1).await;

    send_bound(&sender, &block).await;
    permits.add_permits(2);

    zebra_took(&sidecar, &block).await;
    behind_a_marker(&sender, &sidecar).await;
    assert_eq!(sidecar.zebra.arrivals_for(&block), 1);
    stop(node, [sidecar.client_task, sender_task]);
}

/// Copies of the bytes at Zebra with no shared room at all, by each way there is. The gate would
/// turn them away, and with it off they would be second calls, so they wait all the same. One is
/// all a retry needs, so the other takes no place: Zebra hears of these bytes once more and no
/// more than that.
#[tokio::test]
async fn bytes_at_zebra_wait_with_no_shared_room() {
    for gate in [true, false] {
        let node = stub_pow_node(true).await;
        let options = SidecarOptions {
            gate,
            limits: BoundTaskLimits {
                held: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let sidecar = start_sidecar_from(node.addr, options).await;
        let block = synthetic_block(1);
        sidecar.zebra.knows_of(&block);
        sidecar.zebra.go_down();
        let permits = sidecar.zebra.hold();
        node.has_a_receiver().await;
        let (sender, sender_task) = start_sender(node.addr).await;
        send_bound(&sender, &block).await;
        held_at_zebra(&sidecar, 1).await;

        send_legacy(&sender, &block).await;
        sender.send(compact_of_synthetic_block(1)).await.unwrap();
        behind_a_part(&sender, &sidecar).await;
        assert_eq!(sidecar.zebra.arrivals_for(&block), 1, "gate {gate}");
        assert_eq!(sidecar.turned_away_as_repeats(), 0, "gate {gate}");

        permits.add_permits(1);
        let (zebra, wanted) = (Arc::clone(&sidecar.zebra), block.clone());
        until("the error", move || zebra.calls_for(&wanted) == 1).await;
        sidecar.zebra.come_back();
        held_at_zebra(&sidecar, 2).await;
        sidecar.zebra.stop_holding();
        permits.add_permits(1);

        zebra_took(&sidecar, &block).await;
        behind_a_marker(&sender, &sidecar).await;
        assert_eq!(sidecar.zebra.calls_for(&block), 2, "gate {gate}");
        assert_eq!(sidecar.turned_away_as_repeats(), 0, "gate {gate}");
        sidecar.ledger_settled().await;
        stop(node, [sidecar.client_task, sender_task]);
    }
}

/// What fills the shared room is what a block can lose nothing by. A copy of other bytes with
/// no room goes on as it came: the gate lets a different body run beside the one at Zebra, so
/// it is tried now, on a task of its own and inside the gate's limits, and not turned away.
#[tokio::test]
async fn a_different_body_with_no_room_goes_on_beside_the_task() {
    let node = stub_pow_node(true).await;
    let options = SidecarOptions {
        limits: BoundTaskLimits {
            held: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let (first, second) = (the_real_block(), body_marked(1));
    sidecar.zebra.knows_of(&first);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &first).await;
    held_at_zebra(&sidecar, 1).await;

    send_legacy(&sender, &second).await;

    held_at_zebra(&sidecar, 2).await;
    assert_eq!(sidecar.zebra.arrivals_for(&second), 1);
    assert_eq!(sidecar.turned_away_as_repeats(), 0);
    permits.add_permits(2);
    zebra_took(&sidecar, &first).await;
    stop(node, [sidecar.client_task, sender_task]);
}

#[derive(Clone, Copy, Debug)]
enum CopyBy {
    Legacy,
    Compact,
}

#[derive(Clone, Copy, Debug)]
enum TaskEnds {
    Refused,
    OutOfTime,
}

/// The whole of it on the real receive task, gate on. A, B and C at Zebra, the shared room full
/// of other bytes under B's and C's hashes, and only then a copy of A. A fails. The copy is all
/// that is left of A here, so it has to be still here, and has to get to Zebra, and then the block
/// is closed everywhere: the gate has Zebra's word, a later copy by the other way is a repeat,
/// and nothing stays owned.
async fn a_copy_behind_a_full_room(by: CopyBy, ends: TaskEnds) {
    let node = stub_pow_node(true).await;
    let budget = match ends {
        TaskEnds::Refused => BoundTaskLimits::default().budget,
        TaskEnds::OutOfTime => Duration::from_secs(1),
    };
    let options = SidecarOptions {
        limits: BoundTaskLimits {
            held: 2,
            budget,
            ..Default::default()
        },
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let blocks: Vec<Vec<u8>> = (1..=3).map(synthetic_block).collect();
    let block = &blocks[0];
    for each in &blocks {
        sidecar.zebra.knows_of(each);
    }
    sidecar.zebra.refuse(block);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    for (at, each) in (1..).zip(&blocks) {
        send_bound(&sender, each).await;
        held_at_zebra(&sidecar, at).await;
    }

    send_legacy(&sender, &other_bytes_of_synthetic_block(2)).await;
    send_legacy(&sender, &other_bytes_of_synthetic_block(3)).await;
    blocks_complete(&sidecar, 5).await;
    match by {
        CopyBy::Legacy => send_legacy(&sender, block).await,
        CopyBy::Compact => sender.send(compact_of_synthetic_block(1)).await.unwrap(),
    }
    behind_a_part(&sender, &sidecar).await;
    assert_eq!(sidecar.zebra.arrivals_for(block), 1, "it waits");

    if let TaskEnds::Refused = ends {
        permits.add_permits(blocks.len());
        let (zebra, wanted) = (Arc::clone(&sidecar.zebra), block.clone());
        until("the refusal", move || zebra.calls_for(&wanted) == 1).await;
        // Review item 1 on #134: the copy is the bytes Zebra just refused, so the gate turns
        // it away without another call, and nothing stays owned.
        sidecar.turned_away_as_refused(1).await;
        assert_eq!(sidecar.zebra.arrivals_for(block), 1);
        sidecar.zebra.stop_holding();
        permits.add_permits(blocks.len() + 1);
        sidecar.ledger_settled().await;
        stop(node, [sidecar.client_task, sender_task]);
        return;
    }
    held_at_zebra(&sidecar, blocks.len() as u64 + 1).await;
    sidecar.zebra.stop_refusing();
    sidecar.zebra.stop_holding();
    permits.add_permits(blocks.len() + 1);

    zebra_took(&sidecar, block).await;
    sidecar.gate_learns_of(block).await;
    assert_eq!(sidecar.zebra.arrivals_for(block), 2);
    assert_eq!(sidecar.turned_away_as_repeats(), 0);
    match by {
        CopyBy::Legacy => sender.send(compact_of_synthetic_block(1)).await.unwrap(),
        CopyBy::Compact => send_legacy(&sender, block).await,
    }
    behind_a_marker(&sender, &sidecar).await;
    assert_eq!(
        sidecar.zebra.arrivals_for(block),
        2,
        "a later copy is a repeat"
    );
    sidecar.ledger_settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

#[tokio::test]
async fn a_legacy_copy_behind_a_full_room_is_turned_away_after_a_refusal() {
    a_copy_behind_a_full_room(CopyBy::Legacy, TaskEnds::Refused).await;
}

#[tokio::test]
async fn a_legacy_copy_behind_a_full_room_is_the_retry_after_the_budget() {
    a_copy_behind_a_full_room(CopyBy::Legacy, TaskEnds::OutOfTime).await;
}

#[tokio::test]
async fn a_compact_copy_behind_a_full_room_is_turned_away_after_a_refusal() {
    a_copy_behind_a_full_room(CopyBy::Compact, TaskEnds::Refused).await;
}

#[tokio::test]
async fn a_compact_copy_behind_a_full_room_is_the_retry_after_the_budget() {
    a_copy_behind_a_full_room(CopyBy::Compact, TaskEnds::OutOfTime).await;
}

/// A copy waits for every task on its block, not the first to end. Two bodies of one block at
/// Zebra, one ends with an error, and the copy of it stays where it is while the other runs.
#[tokio::test]
async fn a_held_copy_waits_for_every_task_on_its_block() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let (first, second, marker) = (the_real_block(), body_marked(1), synthetic_block(200));
    for block in [&first, &second, &marker] {
        sidecar.zebra.knows_of(block);
    }
    sidecar.zebra.go_down();
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &first).await;
    held_at_zebra(&sidecar, 1).await;
    send_bound(&sender, &second).await;
    held_at_zebra(&sidecar, 2).await;
    send_legacy(&sender, &first).await;
    blocks_complete(&sidecar, 3).await;

    permits.add_permits(1);
    let (zebra, wanted) = (Arc::clone(&sidecar.zebra), first.clone());
    until("the error", move || zebra.calls_for(&wanted) == 1).await;
    send_legacy(&sender, &marker).await;
    held_at_zebra(&sidecar, 3).await;

    assert_eq!(sidecar.zebra.arrivals_for(&first), 1, "it is still held");
    assert_eq!(sidecar.zebra.arrivals_for(&marker), 1);
    sidecar.zebra.come_back();
    permits.add_permits(3);
    zebra_took(&sidecar, &marker).await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// The other way round. The legacy copy got there first, and the bound one stops at the record
/// with no task and no call, with the gate off as well.
#[tokio::test]
async fn a_copy_after_a_block_reached_zebra_is_a_repeat_and_takes_no_task() {
    let node = stub_pow_node(true).await;
    let options = SidecarOptions {
        gate: false,
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_legacy(&sender, &block).await;
    zebra_took(&sidecar, &block).await;

    send_bound(&sender, &block).await;
    blocks_complete(&sidecar, 2).await;
    behind_a_marker(&sender, &sidecar).await;

    assert_eq!(sidecar.zebra.arrivals_for(&block), 1);
    sidecar.ledger_settled().await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// The compact way, where nothing but this record stops a second submit with the gate off.
#[tokio::test]
async fn a_compact_copy_during_a_bound_task_waits_and_is_then_a_repeat() {
    let node = stub_pow_node(true).await;
    let options = SidecarOptions {
        gate: false,
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let block = synthetic_block(1);
    sidecar.zebra.knows_of(&block);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_bound(&sender, &block).await;
    held_at_zebra(&sidecar, 1).await;

    sender.send(compact_of_synthetic_block(1)).await.unwrap();
    let marker = synthetic_block(200);
    sidecar.zebra.knows_of(&marker);
    send_legacy(&sender, &marker).await;
    held_at_zebra(&sidecar, 2).await;
    assert_eq!(sidecar.zebra.calls(), 0);
    permits.add_permits(2);

    zebra_took(&sidecar, &block).await;
    let metrics = Arc::clone(&sidecar.metrics);
    until("the compact copy to be a repeat", move || {
        metrics.full_block_deduplicated.load(Ordering::Relaxed) == 1
    })
    .await;
    assert_eq!(sidecar.zebra.calls(), 2, "the block and the marker");
    stop(node, [sidecar.client_task, sender_task]);
}

/// A key of its own for each sender, beside the fleet's.
fn sender_key(at: u8) -> [u8; 32] {
    [0x50 + at; 32]
}

/// A stubbed node that also takes `senders` keys of their own: a node lets one key hold only
/// a few bodies of a block, so a test of many bodies at once needs many keys.
async fn stub_pow_node_for(senders: u8) -> Node {
    let mut keys = vec![AuthKey::new("fleet", KEY)];
    keys.extend((0..senders).map(|at| AuthKey::new(format!("sender-{at}"), sender_key(at))));
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(keys)
        .with_fec(10, 3)
        .with_bound_raw(Default::default());
    Node::start(RelayNode::with_validator(config, StubPowValidator).unwrap()).await
}

/// Different bodies of one block may run side by side, as any of them may be the block, and the
/// gate's limits hold all the same. The last one finds them spent and never reaches Zebra. Each
/// body comes from a key of its own, as the node lets one key hold only a few of a block.
#[tokio::test]
async fn bodies_of_one_block_run_side_by_side_inside_the_gate_limits() {
    let limit = DEFAULT_STRICT_BODIES_PER_BLOCK as u64;
    let node = stub_pow_node_for(limit as u8 + 1).await;
    let options = SidecarOptions {
        limits: BoundTaskLimits {
            running: 8,
            ..Default::default()
        },
        ..Default::default()
    };
    let sidecar = start_sidecar_from(node.addr, options).await;
    let bodies: Vec<Vec<u8>> = (1..=limit as u8 + 1).map(body_marked).collect();
    for body in &bodies {
        sidecar.zebra.knows_of(body);
        sidecar.zebra.refuse(body);
    }
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let mut tasks = Vec::new();
    for (at, body) in bodies.iter().enumerate() {
        let key = sender_key(at as u8);
        let config = ClientConfig::new(vec![node.addr], key)
            .with_bind_addr("127.0.0.1:0".parse().unwrap())
            .with_auth_required(true)
            .with_fec(10, 3)
            .with_send_pacing(32, Duration::from_micros(200));
        let (sender, task) = start_sender_with(config).await;
        send_bound(&sender, body).await;
        tasks.push(task);
    }
    held_at_zebra(&sidecar, limit).await;
    permits.add_permits(bodies.len());
    sidecar.ledger_settled().await;

    assert_eq!(sidecar.zebra.calls(), limit as usize);
    tasks.push(sidecar.client_task);
    stop(node, tasks);
}

/// Known gap, and left as it is: the legacy paths still run on this task, so a held legacy call
/// holds the bound path up, though what it started goes on.
#[tokio::test]
async fn known_gap_a_held_legacy_zebra_call_still_stops_this_task() {
    let node = stub_pow_node(true).await;
    let sidecar = start_sidecar(node.addr, Some(Default::default())).await;
    let (legacy, next) = (synthetic_block(1), synthetic_block(2));
    sidecar.zebra.knows_of(&legacy);
    sidecar.zebra.knows_of(&next);
    let permits = sidecar.zebra.hold();
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;
    send_legacy(&sender, &legacy).await;
    held_at_zebra(&sidecar, 1).await;

    send_bound(&sender, &next).await;
    let probe = sidecar.probe().clone();
    until("the block to be whole", move || {
        probe.ledger().reserved_bytes > 0
    })
    .await;
    assert_eq!(sidecar.zebra.waiting(), 1, "it waits for this task");

    permits.add_permits(2);
    zebra_took(&sidecar, &next).await;
    stop(node, [sidecar.client_task, sender_task]);
}

/// Both copies. The bound one is refused at the sender when no relay has answered its hello,
/// and the legacy one goes all the same.
async fn send_dual(sender: &BlockSender, raw: &[u8], bound_answered: bool) {
    let ((), bound) = tokio::join!(
        send_legacy(sender, raw),
        sender.send_bound_raw_block(Arc::new(raw.to_vec()))
    );
    assert_eq!(bound.is_ok(), bound_answered, "{bound:?}");
}

/// How many times the block reached Zebra. A stubbed node, so a marker can follow it.
/// The receive task picks at random between what is ready, so the marker shows only what
/// the client has seen. If the block was to get through it has an owner by then, or a
/// legacy set behind it, and the test waits for that.
async fn mixed(node_bound: bool, receiver_bound: bool, send: Wire) -> usize {
    let real = the_real_block();
    let node = stub_pow_node(node_bound).await;
    let bound = receiver_bound.then(BoundRawConfig::default);
    let sidecar = start_sidecar(node.addr, bound).await;
    sidecar.zebra.knows_of(&real);
    node.has_a_receiver().await;
    let (sender, sender_task) = start_sender(node.addr).await;

    // A legacy relay never answers the bound hello, so the sender keeps its bound copy back
    // rather than send what that relay would drop.
    match send {
        Wire::Legacy => send_legacy(&sender, &real).await,
        Wire::Dual => send_dual(&sender, &real, node_bound).await,
        Wire::Bound if node_bound => send_bound(&sender, &real).await,
        Wire::Bound => {
            let refused = sender.send_bound_raw_block(Arc::new(real.clone())).await;
            assert!(
                matches!(refused, Err(TransportError::ConnectionRefused(_))),
                "{refused:?}"
            );
        }
    }
    behind_a_marker(&sender, &sidecar).await;

    let arrives = match send {
        Wire::Legacy | Wire::Dual => true,
        Wire::Bound => node_bound && receiver_bound,
    };
    if arrives {
        let zebra = Arc::clone(&sidecar.zebra);
        let wanted = real.clone();
        until("the block", move || zebra.took(&wanted)).await;
        sidecar_is_done(&sidecar).await;
    } else if let Some(probe) = &sidecar.probe {
        let ledger = probe.ledger();
        let records = ledger.in_flight + ledger.held + ledger.released + ledger.completed;
        assert_eq!(records, 0, "not one object got through");
    }
    let calls = sidecar.zebra.calls_for(&real);
    stop(node, [sidecar.client_task, sender_task]);
    calls
}

/// The other copy has been dealt with too, however that went.
async fn sidecar_is_done(sidecar: &Sidecar) {
    if sidecar.probe.is_some() {
        sidecar.ledger_settled().await;
    }
}

#[derive(Clone, Copy, Debug)]
enum Wire {
    Legacy,
    Dual,
    Bound,
}

#[tokio::test]
async fn legacy_sender_new_hop_new_receiver() {
    assert_eq!(mixed(true, true, Wire::Legacy).await, 1);
}

#[tokio::test]
async fn legacy_sender_legacy_hop_legacy_receiver() {
    assert_eq!(mixed(false, false, Wire::Legacy).await, 1);
}

#[tokio::test]
async fn legacy_sender_new_hop_legacy_receiver() {
    assert_eq!(mixed(true, false, Wire::Legacy).await, 1);
}

#[tokio::test]
async fn legacy_sender_legacy_hop_new_receiver() {
    assert_eq!(mixed(false, true, Wire::Legacy).await, 1);
}

#[tokio::test]
async fn dual_sender_legacy_hop_legacy_receiver_gets_the_legacy_copy() {
    assert_eq!(mixed(false, false, Wire::Dual).await, 1);
}

#[tokio::test]
async fn dual_sender_legacy_hop_new_receiver_gets_the_legacy_copy() {
    assert_eq!(mixed(false, true, Wire::Dual).await, 1);
}

#[tokio::test]
async fn dual_sender_new_hop_legacy_receiver_gets_the_legacy_copy() {
    assert_eq!(mixed(true, false, Wire::Dual).await, 1);
}

#[tokio::test]
async fn dual_sender_new_hop_new_receiver_reaches_zebra_once() {
    assert_eq!(mixed(true, true, Wire::Dual).await, 1);
}

#[tokio::test]
async fn bound_sender_new_hop_new_receiver() {
    assert_eq!(mixed(true, true, Wire::Bound).await, 1);
}

/// Bound only is not something a mixed network can run on: this is what rollback is
/// protecting against, and why dual sending comes first.
#[tokio::test]
async fn bound_sender_legacy_hop_delivers_nothing() {
    assert_eq!(mixed(false, true, Wire::Bound).await, 0);
}

#[tokio::test]
async fn bound_sender_new_hop_legacy_receiver_delivers_nothing() {
    assert_eq!(mixed(true, false, Wire::Bound).await, 0);
}

#[tokio::test]
async fn bound_sender_legacy_hop_legacy_receiver_delivers_nothing() {
    assert_eq!(mixed(false, false, Wire::Bound).await, 0);
}

/// The relay turns away bodies past what the gate would take, so neither runs out first.
#[test]
fn the_relay_and_the_gate_take_as_many_bodies_for_a_block() {
    assert_eq!(
        sovright_relay::BoundForwardConfig::default().max_bodies_per_block,
        DEFAULT_STRICT_BODIES_PER_BLOCK
    );
}
