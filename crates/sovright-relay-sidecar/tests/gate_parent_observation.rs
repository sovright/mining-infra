//! The gated submit path end to end, against a local JSON-RPC server standing
//! in for Zebra: the real `ZebraRpc` client, `ZebraChainView::
//! observe_candidate_parent`, both gated handlers and the gate, in live mode
//! with a submitter that only counts calls.
//!
//! The parent is mainnet block 3470793: its real header, and Zebra's display
//! hash for it. The candidate is a synthetic child whose header names that
//! block as its parent. "Submitted" here means the counting submitter was
//! called; no node accepts anything in these tests.
//!
//! The polled tip is set one below the parent, the state the gate sees when
//! Zebra has accepted the parent but the 5 s tip poll has not run since.

use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};
use sovright_relay::test_support::{commit_header, parseable_transaction, raw_block};
use sovright_relay::{CompactBlock, PrefilledTx, consensus_block_hash, zcash_block_hash};
use sovright_relay_sidecar::chain_view::{ZebraChainView, ZebraChainViewConfig};
use sovright_relay_sidecar::rpc::ZebraRpc;
use sovright_relay_sidecar::submit::{
    SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitFuture,
    handle_relay_compact_block_with_gate, handle_relay_raw_block_with_gate,
};
use sovright_relay_sidecar::submit_gate::{ChainView, GateConfig, RejectReason, SubmitGate};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use zcash_pool_common::fixtures::{MAINNET_BLOCK_3470793_HASH_DISPLAY, mainnet_serialized_header};

const PARENT_HEIGHT: u64 = 3_470_793;
const EVIDENCE_LOG: &str = "submit gate: upper bound passed on parent best-chain evidence";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Block 3470793's consensus hash in header (internal) byte order: what a
/// child header carries at `[4..36]`.
fn parent_hash() -> [u8; 32] {
    consensus_block_hash(&mainnet_serialized_header())
}

/// Block 3470793's own parent, in Zebra's display order. A real block hash
/// that is not the one queried.
fn grandparent_display() -> String {
    let header = mainnet_serialized_header();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&header[4..36]);
    bytes.reverse();
    hex::encode(bytes)
}

fn child_tx() -> Vec<u8> {
    parseable_transaction(1)
}

fn child_header() -> Vec<u8> {
    let mut header = vec![0xab; 1487];
    header[4..36].copy_from_slice(&parent_hash());
    commit_header(&mut header, &[child_tx()]);
    header
}

fn child_compact() -> CompactBlock {
    CompactBlock::new(
        child_header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: child_tx(),
        }],
    )
}

fn child_raw() -> Vec<u8> {
    raw_block(&child_header(), &[child_tx()])
}

/// A verbose `getblockheader` result in Zebra's shape. The sidecar reads
/// `hash`, `height` and `confirmations`; the other fields are there so the
/// deserializer sees a realistic object.
fn header_result(hash: &str, confirmations: Option<i64>) -> Value {
    let mut result = json!({
        "hash": hash,
        "height": PARENT_HEIGHT,
        "version": 4,
        "merkleroot": "00".repeat(32),
        "blockcommitments": "00".repeat(32),
        "finalsaplingroot": "00".repeat(32),
        "time": 1_761_000_000,
        "nonce": "00".repeat(32),
        "solution": "00".repeat(1344),
        "bits": "1c0168fd",
        "difficulty": 1.0,
        "previousblockhash": grandparent_display(),
    });
    if let Some(confirmations) = confirmations {
        result["confirmations"] = json!(confirmations);
    }
    result
}

// ---------------------------------------------------------------------------
// Local stand-in for Zebra
// ---------------------------------------------------------------------------

enum HeaderReply {
    Result(Value),
    Error(i32, &'static str),
}

struct MockZebra {
    reply: HeaderReply,
    requests: Mutex<Vec<Value>>,
}

impl MockZebra {
    fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}

/// Serve `getblockheader` with a fixed reply and record every request's
/// params. Returns the client the sidecar would use against it.
async fn start_mock_zebra(reply: HeaderReply) -> (Arc<MockZebra>, ZebraRpc, ServerHandle) {
    let zebra = Arc::new(MockZebra {
        reply,
        requests: Mutex::new(Vec::new()),
    });
    let mut module = RpcModule::new(Arc::clone(&zebra));
    module
        .register_method("getblockheader", |params, zebra, _| {
            let params: Value = params.parse()?;
            zebra.requests.lock().unwrap().push(params);
            match &zebra.reply {
                HeaderReply::Result(result) => Ok(result.clone()),
                HeaderReply::Error(code, message) => {
                    Err(ErrorObjectOwned::owned(*code, *message, None::<()>))
                }
            }
        })
        .unwrap();
    let server = ServerBuilder::default()
        .http_only()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    let handle = server.start(module);
    let rpc = ZebraRpc::new(&url).await.unwrap();
    (zebra, rpc, handle)
}

fn queried_with_parent() -> Vec<Value> {
    vec![json!([MAINNET_BLOCK_3470793_HASH_DISPLAY, true])]
}

// ---------------------------------------------------------------------------
// Gate, submitter and log capture
// ---------------------------------------------------------------------------

struct CountingSubmitter {
    calls: AtomicUsize,
}

impl CountingSubmitter {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SubmitBlock for CountingSubmitter {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(None) })
    }
}

/// A chain view whose polled tip is one below the parent.
fn stale_view() -> Arc<ZebraChainView> {
    let view = ZebraChainView::new(ZebraChainViewConfig::default());
    view.set_tip_height(PARENT_HEIGHT - 1);
    view
}

fn gate_over(view: &Arc<ZebraChainView>) -> SubmitGate<Arc<ZebraChainView>> {
    SubmitGate::new(
        GateConfig {
            enabled: true,
            allowed_below: 3,
            dedup_window: Duration::from_secs(60),
            dedup_capacity: 8,
            unreadable_attempts_per_block: 4,
            ..GateConfig::default()
        },
        Arc::clone(view),
    )
}

/// Records each tracing event's message.
#[derive(Clone, Default)]
struct CapturedEvents(Arc<Mutex<Vec<String>>>);

impl CapturedEvents {
    fn count(&self, message: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|m| *m == message)
            .count()
    }
}

#[derive(Default)]
struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedEvents {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0);
    }
}

/// Capture events on this thread for the rest of the test. `#[tokio::test]`
/// runs on one thread, so the lookup and the gate log here.
fn capture() -> (CapturedEvents, tracing::subscriber::DefaultGuard) {
    let events = CapturedEvents::default();
    let guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(events.clone()));
    (events, guard)
}

async fn run_compact(
    rpc: &ZebraRpc,
    view: &Arc<ZebraChainView>,
    gate: &mut SubmitGate<Arc<ZebraChainView>>,
    submitter: &CountingSubmitter,
) -> SubmissionOutcome {
    let compact = child_compact();
    let parent = view.observe_candidate_parent(rpc, &compact.header).await;
    handle_relay_compact_block_with_gate(
        submitter,
        &compact,
        SubmitBlockMode::Live,
        gate,
        parent.as_ref(),
    )
    .await
    .unwrap()
}

async fn run_raw(
    rpc: &ZebraRpc,
    view: &Arc<ZebraChainView>,
    gate: &mut SubmitGate<Arc<ZebraChainView>>,
    submitter: &CountingSubmitter,
) -> SubmissionOutcome {
    let raw = child_raw();
    let parent = view.observe_candidate_parent(rpc, &raw).await;
    handle_relay_raw_block_with_gate(
        submitter,
        &raw,
        Some(zcash_block_hash(&raw[..1487])),
        SubmitBlockMode::Live,
        gate,
        parent.as_ref(),
    )
    .await
    .unwrap()
}

fn assert_rejected(outcome: &SubmissionOutcome, expected: RejectReason) {
    assert!(
        matches!(outcome, SubmissionOutcome::GateRejected { reason, .. } if *reason == expected),
        "expected GateRejected({expected:?}), got {outcome:?}",
    );
}

// ---------------------------------------------------------------------------
// Stale polled tip, parent on the best chain: accepted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stale_tip_compact_with_best_chain_parent_is_submitted() {
    let (events, _guard) = capture();
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        Some(1),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert!(
        matches!(outcome, SubmissionOutcome::Submitted { .. }),
        "{outcome:?}"
    );
    assert_eq!(submitter.calls(), 1);
    assert_eq!(zebra.requests(), queried_with_parent());
    assert!(view.parent_known(&parent_hash()));
    assert_eq!(events.count(EVIDENCE_LOG), 1);
}

#[tokio::test]
async fn stale_tip_raw_with_best_chain_parent_is_submitted() {
    let (events, _guard) = capture();
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        Some(1),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_raw(&rpc, &view, &mut gate, &submitter).await;

    assert!(
        matches!(outcome, SubmissionOutcome::Submitted { .. }),
        "{outcome:?}"
    );
    assert_eq!(submitter.calls(), 1);
    assert_eq!(zebra.requests(), queried_with_parent());
    assert!(view.parent_known(&parent_hash()));
    assert_eq!(events.count(EVIDENCE_LOG), 1);
}

/// Zebra writes lowercase hex; the comparison does not depend on it.
#[tokio::test]
async fn uppercase_response_hash_still_matches_the_query() {
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        &MAINNET_BLOCK_3470793_HASH_DISPLAY.to_uppercase(),
        Some(1),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_raw(&rpc, &view, &mut gate, &submitter).await;

    assert!(
        matches!(outcome, SubmissionOutcome::Submitted { .. }),
        "{outcome:?}"
    );
    assert_eq!(submitter.calls(), 1);
    assert_eq!(zebra.requests(), queried_with_parent());
}

/// The evidence line is written only once the gate has accepted: a repeat of
/// the same candidate is a dedup reject and logs nothing more.
#[tokio::test]
async fn evidence_is_logged_only_for_an_accept() {
    let (events, _guard) = capture();
    let (_zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        Some(1),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let first = run_compact(&rpc, &view, &mut gate, &submitter).await;
    let second = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert!(
        matches!(first, SubmissionOutcome::Submitted { .. }),
        "{first:?}"
    );
    assert_rejected(&second, RejectReason::DuplicateSubmit);
    assert_eq!(submitter.calls(), 1);
    assert_eq!(events.count(EVIDENCE_LOG), 1);
}

/// With a current tip the window passes on its own and no evidence is logged.
#[tokio::test]
async fn current_tip_needs_no_evidence() {
    let (events, _guard) = capture();
    let (_zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        Some(1),
    )))
    .await;
    let view = stale_view();
    view.set_tip_height(PARENT_HEIGHT);
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert!(
        matches!(outcome, SubmissionOutcome::Submitted { .. }),
        "{outcome:?}"
    );
    assert_eq!(submitter.calls(), 1);
    assert_eq!(events.count(EVIDENCE_LOG), 0);
}

// ---------------------------------------------------------------------------
// Stale polled tip without best-chain evidence: today's rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_confirmations_keeps_the_polled_upper_bound() {
    let (events, _guard) = capture();
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        None,
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert_rejected(&outcome, RejectReason::OutOfHeightWindow);
    assert_eq!(submitter.calls(), 0);
    assert_eq!(zebra.requests(), queried_with_parent());
    assert!(view.parent_known(&parent_hash()));
    assert_eq!(events.count(EVIDENCE_LOG), 0);
}

/// `-1`: the parent left the best chain between Zebra's header and depth reads.
#[tokio::test]
async fn off_best_chain_confirmations_keeps_the_polled_upper_bound() {
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        Some(-1),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_raw(&rpc, &view, &mut gate, &submitter).await;

    assert_rejected(&outcome, RejectReason::OutOfHeightWindow);
    assert_eq!(submitter.calls(), 0);
    assert_eq!(zebra.requests(), queried_with_parent());
    assert!(view.parent_known(&parent_hash()));
}

// ---------------------------------------------------------------------------
// No usable observation: the parent is never cached and never submitted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn response_for_another_block_is_not_an_observation() {
    let (events, _guard) = capture();
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        &grandparent_display(),
        Some(1),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert_rejected(&outcome, RejectReason::UnknownParent);
    assert_eq!(submitter.calls(), 0);
    assert_eq!(zebra.requests(), queried_with_parent());
    assert!(!view.parent_known(&parent_hash()));
    assert_eq!(
        events.count("ZebraChainView: parent lookup answered for another block"),
        1
    );
}

#[tokio::test]
async fn unknown_parent_is_rejected_and_not_cached() {
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Error(-5, "Block not found")).await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_raw(&rpc, &view, &mut gate, &submitter).await;

    assert_rejected(&outcome, RejectReason::UnknownParent);
    assert_eq!(submitter.calls(), 0);
    assert_eq!(zebra.requests(), queried_with_parent());
    assert!(!view.parent_known(&parent_hash()));
}

/// A parent cached by an earlier lookup but not found now: the candidate
/// falls back to height 1, as before, and the lower bound rejects it.
#[tokio::test]
async fn unknown_but_cached_parent_falls_back_to_height_one() {
    let (zebra, rpc, _server) = start_mock_zebra(HeaderReply::Error(-5, "Block not found")).await;
    let view = stale_view();
    view.admit_parent(parent_hash());
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert_rejected(&outcome, RejectReason::OutOfHeightWindow);
    assert_eq!(submitter.calls(), 0);
    assert_eq!(zebra.requests(), queried_with_parent());
}

/// Nothing listens on the port, so there are no request params to check.
#[tokio::test]
async fn refused_connection_is_rejected_and_not_cached() {
    let (events, _guard) = capture();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let rpc = ZebraRpc::new(&format!("http://127.0.0.1:{port}"))
        .await
        .unwrap();
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();

    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;

    assert_rejected(&outcome, RejectReason::UnknownParent);
    assert_eq!(submitter.calls(), 0);
    assert!(!view.parent_known(&parent_hash()));
    assert_eq!(events.count("ZebraChainView: parent lookup failed"), 1);
}

// ---------------------------------------------------------------------------
// The window follows Zebra's tip at the lookup, not just the polled one
// ---------------------------------------------------------------------------

/// Run the compact child against a parent Zebra reports with `confirmations`,
/// while the polled tip is one below the parent.
async fn compact_with_parent_confirmations(
    confirmations: i64,
) -> (SubmissionOutcome, usize, CapturedEvents) {
    let (events, _guard) = capture();
    let (_zebra, rpc, _server) = start_mock_zebra(HeaderReply::Result(header_result(
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        Some(confirmations),
    )))
    .await;
    let view = stale_view();
    let mut gate = gate_over(&view);
    let submitter = CountingSubmitter::new();
    let outcome = run_compact(&rpc, &view, &mut gate, &submitter).await;
    (outcome, submitter.calls(), events)
}

/// Zebra is 100 blocks past the parent: the child is a deep fork block. The
/// window against Zebra's tip (parent + 101 - 1) is [3_470_890, 3_470_894].
#[tokio::test]
async fn deep_fork_child_is_rejected_against_zebras_tip() {
    let (outcome, calls, events) = compact_with_parent_confirmations(101).await;

    assert_rejected(&outcome, RejectReason::OutOfHeightWindow);
    assert_eq!(calls, 0);
    assert_eq!(events.count(EVIDENCE_LOG), 0);
}

/// Confirmations 5 put Zebra's tip at parent + 4, so the child sits exactly
/// on the lower bound (tip - 3).
#[tokio::test]
async fn child_at_the_observed_lower_bound_is_submitted() {
    let (outcome, calls, events) = compact_with_parent_confirmations(5).await;

    assert!(
        matches!(outcome, SubmissionOutcome::Submitted { .. }),
        "{outcome:?}"
    );
    assert_eq!(calls, 1);
    assert_eq!(events.count(EVIDENCE_LOG), 1);
}

/// Confirmations 6: the lower bound is one above the child.
#[tokio::test]
async fn child_one_below_the_observed_lower_bound_is_rejected() {
    let (outcome, calls, events) = compact_with_parent_confirmations(6).await;

    assert_rejected(&outcome, RejectReason::OutOfHeightWindow);
    assert_eq!(calls, 0);
    assert_eq!(events.count(EVIDENCE_LOG), 0);
}
