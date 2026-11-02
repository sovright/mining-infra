//! Block body validation at the sidecar boundary (#130), on the real mainnet
//! block 3470793. A counting Zebra stands in for the node: it accepts only the
//! genuine block, so a call count of zero means the candidate never reached it.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use sovright_relay::test_support::{
    committed_header, parseable_transaction, parseable_transaction_with_script, raw_block,
};
use sovright_relay::{
    AuthDigest, BlockBodyError, CompactBlock, MAX_BLOCK_BYTES, MempoolProvider, PrefilledTx,
    ShortId, TxId, WtxId, ZCASH_FULL_HEADER_SIZE, zcash_block_hash,
};
use sovright_relay_sidecar::dual_submit::DualSubmit;
use sovright_relay_sidecar::rpc::{ZEBRA_RPC_REQUEST_TIMEOUT, ZebraRpc};
use sovright_relay_sidecar::submit::{
    BlockKnownFuture, RelayBlockError, SubmissionCandidate, SubmissionOutcome, SubmitBlock,
    SubmitBlockMode, SubmitBlockStatus, SubmitFuture, UnverifiedLimits,
    build_raw_block_submission_candidate, build_submission_candidate, handle_relay_compact_block,
    handle_relay_compact_block_with_gate, handle_relay_compact_block_with_mempool,
    handle_relay_raw_block, handle_relay_raw_block_with_gate, submit_unverified_raw_block,
    unreadable_body, validate_then_gate_compact_block, validate_then_gate_raw_block,
};
use sovright_relay_sidecar::submit_gate::{
    CandidateMeta, ChainView, GateConfig, ParentObservation, RejectReason, SubmitGate,
};
use tokio::time::timeout;
use zcash_pool_common::fixtures;

struct Zebra {
    genuine_hex: String,
    calls: AtomicUsize,
}

impl Zebra {
    fn new() -> Self {
        Self {
            genuine_hex: hex::encode(fixtures::mainnet_raw_block()),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SubmitBlock for Zebra {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let accepted = block_hex == self.genuine_hex;
        Box::pin(async move { Ok((!accepted).then(|| "rejected".to_string())) })
    }
}

struct View;

impl ChainView for View {
    fn tip_height(&self) -> u64 {
        100
    }

    fn parent_known(&self, _parent_hash: &[u8; 32]) -> bool {
        true
    }
}

fn gate() -> SubmitGate<View> {
    SubmitGate::new(
        GateConfig {
            enabled: true,
            ..GateConfig::default()
        },
        View,
    )
}

fn parent() -> ParentObservation {
    let header = fixtures::mainnet_serialized_header();
    ParentObservation {
        parent_hash: CandidateMeta::parent_hash_from_header(&header).unwrap(),
        height: 100,
        confirmations: Some(1),
    }
}

fn compact(txs: &[Vec<u8>]) -> CompactBlock {
    CompactBlock::new(
        fixtures::mainnet_serialized_header(),
        0,
        Vec::new(),
        txs.iter()
            .map(|tx| PrefilledTx {
                index: 0,
                tx_data: tx.clone(),
            })
            .collect(),
    )
}

fn raw(count: &[u8], txs: &[Vec<u8>]) -> Vec<u8> {
    let mut block = fixtures::mainnet_serialized_header();
    block.extend_from_slice(count);
    txs.iter().for_each(|tx| block.extend_from_slice(tx));
    block
}

/// Block 3470793 with transaction 3 changed: it still parses, its txid moves.
fn bad_transactions() -> Vec<Vec<u8>> {
    let mut txs = fixtures::mainnet_transactions();
    txs[3][60] ^= 0x01;
    txs
}

fn block_hash() -> [u8; 32] {
    zcash_block_hash(&fixtures::mainnet_serialized_header())
}

fn assert_body_rejected(
    outcome: Result<SubmissionOutcome, RelayBlockError>,
    expected: BlockBodyError,
) {
    match outcome {
        Err(RelayBlockError::InvalidBlockBody(error)) => assert_eq!(error, expected),
        Err(other) => panic!("expected {expected:?}, got {other}"),
        Ok(_) => panic!("expected {expected:?}, the candidate was accepted"),
    }
}

fn assert_submitted(outcome: Result<SubmissionOutcome, RelayBlockError>) {
    match outcome {
        Ok(SubmissionOutcome::Submitted { status, .. }) => {
            assert_eq!(status, SubmitBlockStatus::Accepted)
        }
        Ok(SubmissionOutcome::GateRejected { reason, .. }) => {
            panic!("gate rejected the good body: {reason:?}")
        }
        Ok(_) => panic!("the good body was not submitted"),
        Err(error) => panic!("the good body failed: {error}"),
    }
}

#[tokio::test]
async fn gated_compact_bad_body_does_not_block_the_good_one() {
    let zebra = Zebra::new();
    let mut gate = gate();
    let parent = parent();
    let mode = SubmitBlockMode::Live;

    let bad = handle_relay_compact_block_with_gate(
        &zebra,
        &compact(&bad_transactions()),
        mode,
        &mut gate,
        Some(&parent),
    )
    .await;
    assert_body_rejected(bad, BlockBodyError::MerkleMismatch);
    assert_eq!(zebra.calls(), 0);

    let good = compact(&fixtures::mainnet_transactions());
    let outcome =
        handle_relay_compact_block_with_gate(&zebra, &good, mode, &mut gate, Some(&parent)).await;
    assert_submitted(outcome);
    assert_eq!(zebra.calls(), 1);

    // The gate still dedups the genuine block.
    let repeat =
        handle_relay_compact_block_with_gate(&zebra, &good, mode, &mut gate, Some(&parent)).await;
    assert!(matches!(
        repeat,
        Ok(SubmissionOutcome::GateRejected {
            reason: RejectReason::DuplicateSubmit,
            ..
        })
    ));
    assert_eq!(zebra.calls(), 1);
}

#[tokio::test]
async fn gated_raw_bad_body_does_not_block_the_good_one() {
    let zebra = Zebra::new();
    let mut gate = gate();
    let parent = parent();
    let mode = SubmitBlockMode::Live;
    let hash = Some(block_hash());

    let bad = raw(&[7], &bad_transactions());
    let outcome =
        handle_relay_raw_block_with_gate(&zebra, &bad, hash, mode, &mut gate, Some(&parent)).await;
    assert_body_rejected(outcome, BlockBodyError::MerkleMismatch);
    assert_eq!(zebra.calls(), 0);

    let good = fixtures::mainnet_raw_block();
    let outcome =
        handle_relay_raw_block_with_gate(&zebra, &good, hash, mode, &mut gate, Some(&parent)).await;
    assert_submitted(outcome);
    assert_eq!(zebra.calls(), 1);
}

#[tokio::test]
async fn ungated_bad_bodies_never_reach_zebra() {
    let zebra = Zebra::new();
    let mode = SubmitBlockMode::Live;
    let bad_txs = bad_transactions();

    let outcome = handle_relay_compact_block(&zebra, &compact(&bad_txs), mode).await;
    assert_body_rejected(outcome, BlockBodyError::MerkleMismatch);
    let outcome =
        handle_relay_raw_block(&zebra, &raw(&[7], &bad_txs), Some(block_hash()), mode).await;
    assert_body_rejected(outcome, BlockBodyError::MerkleMismatch);
    assert_eq!(zebra.calls(), 0);

    let good = compact(&fixtures::mainnet_transactions());
    assert_submitted(handle_relay_compact_block(&zebra, &good, mode).await);
    let good = fixtures::mainnet_raw_block();
    assert_submitted(handle_relay_raw_block(&zebra, &good, Some(block_hash()), mode).await);
    assert_eq!(zebra.calls(), 2);
}

#[test]
fn valid_blocks_keep_their_bytes_on_every_path() {
    let genuine = hex::encode(fixtures::mainnet_raw_block());
    let txs = fixtures::mainnet_transactions();

    let from_compact = build_submission_candidate(&compact(&txs)).unwrap();
    assert_eq!(from_compact.block_hex, genuine);
    assert_eq!(from_compact.tx_count, txs.len());

    let from_raw =
        build_raw_block_submission_candidate(&fixtures::mainnet_raw_block(), Some(block_hash()))
            .unwrap();
    assert_eq!(from_raw.block_hex, genuine);
    assert_eq!(from_raw.tx_count, txs.len());
}

/// A one-transaction block that serializes to exactly `block_bytes`.
fn block_of_size(block_bytes: usize) -> (Vec<u8>, Vec<u8>) {
    let overhead = parseable_transaction_with_script(0, 65_536).len() - 65_536;
    let script_bytes = block_bytes - ZCASH_FULL_HEADER_SIZE - 1 - overhead;
    let tx = parseable_transaction_with_script(0, script_bytes);
    (committed_header(0xcd, std::slice::from_ref(&tx)), tx)
}

/// The compact and raw paths must agree at the edge of the limit: the compact
/// candidate serializes the transaction count too.
#[test]
fn both_paths_limit_the_serialized_block() {
    for block_bytes in [MAX_BLOCK_BYTES, MAX_BLOCK_BYTES + 1] {
        let (header, tx) = block_of_size(block_bytes);
        let raw = raw_block(&header, std::slice::from_ref(&tx));
        assert_eq!(raw.len(), block_bytes);
        let compact = CompactBlock::new(
            header,
            0,
            Vec::new(),
            vec![PrefilledTx {
                index: 0,
                tx_data: tx,
            }],
        );

        let from_compact = build_submission_candidate(&compact);
        let from_raw = build_raw_block_submission_candidate(&raw, None);
        if block_bytes > MAX_BLOCK_BYTES {
            let refused = |outcome: Result<SubmissionCandidate, RelayBlockError>| {
                matches!(
                    outcome,
                    Err(RelayBlockError::InvalidBlockBody(BlockBodyError::TooLarge { bytes }))
                        if bytes == block_bytes
                )
            };
            assert!(refused(from_compact), "compact path, {block_bytes} bytes");
            assert!(refused(from_raw), "raw path, {block_bytes} bytes");
        } else {
            let (from_compact, from_raw) = (from_compact.unwrap(), from_raw.unwrap());
            assert_eq!(from_compact.block_hex, from_raw.block_hex);
            assert_eq!(from_compact.block_bytes, block_bytes);
        }
    }
}

#[tokio::test]
async fn malformed_raw_blocks_never_reach_zebra() {
    let txs = fixtures::mainnet_transactions();
    let genuine = fixtures::mainnet_raw_block();
    let mut trailing = genuine.clone();
    trailing.push(0);
    let cases = [
        (raw(&[0xfd, 7, 0], &txs), BlockBodyError::InvalidCount),
        (trailing, BlockBodyError::TrailingBytes { bytes: 1 }),
        (
            genuine[..genuine.len() - 1].to_vec(),
            BlockBodyError::Transaction { index: 6 },
        ),
        (
            genuine[..genuine.len() / 2].to_vec(),
            BlockBodyError::Transaction { index: 4 },
        ),
        (raw(&[8], &txs), BlockBodyError::Transaction { index: 7 }),
        (raw(&[6], &txs), BlockBodyError::MerkleMismatch),
    ];
    for (block, expected) in cases {
        let zebra = Zebra::new();
        let outcome =
            handle_relay_raw_block(&zebra, &block, Some(block_hash()), SubmitBlockMode::Live).await;
        assert_body_rejected(outcome, expected);
        assert_eq!(zebra.calls(), 0);
    }
}

#[tokio::test]
async fn a_repeated_final_transaction_never_reaches_zebra() {
    let mut txs = fixtures::mainnet_transactions();
    txs.push(txs[6].clone());
    let expected = BlockBodyError::DuplicateTxid { index: 7 };
    let zebra = Zebra::new();
    let mode = SubmitBlockMode::Live;

    let outcome = handle_relay_compact_block(&zebra, &compact(&txs), mode).await;
    assert_body_rejected(outcome, expected);
    let outcome = handle_relay_raw_block(&zebra, &raw(&[8], &txs), Some(block_hash()), mode).await;
    assert_body_rejected(outcome, expected);
    assert_eq!(zebra.calls(), 0);
}

/// Joined, these slices are the genuine block; they must still be refused.
#[tokio::test]
async fn compact_slices_must_keep_their_boundaries() {
    let txs = fixtures::mainnet_transactions();
    let zebra = Zebra::new();
    let mode = SubmitBlockMode::Live;

    let mut two_in_one = txs.clone();
    let second = two_in_one.remove(3);
    two_in_one[2].extend_from_slice(&second);
    assert_eq!(
        build_submission_candidate(&compact(&two_in_one)).unwrap_err(),
        RelayBlockError::InvalidBlockBody(BlockBodyError::TransactionBoundary { index: 2 })
    );

    let mut extra_byte = txs.clone();
    extra_byte[3].push(0);
    let outcome = handle_relay_compact_block(&zebra, &compact(&extra_byte), mode).await;
    assert_body_rejected(outcome, BlockBodyError::TransactionBoundary { index: 3 });

    let mut shifted = txs.clone();
    let tail = shifted[3].split_off(20);
    shifted[4].splice(0..0, tail);
    assert_eq!(
        hex::decode(hex::encode(raw(&[7], &shifted))).unwrap(),
        fixtures::mainnet_raw_block(),
        "the joined bytes are the genuine block"
    );
    let outcome = handle_relay_compact_block(&zebra, &compact(&shifted), mode).await;
    assert_body_rejected(outcome, BlockBodyError::Transaction { index: 3 });
    assert_eq!(zebra.calls(), 0);
}

struct Mempool(HashMap<WtxId, Vec<u8>>);

impl MempoolProvider for Mempool {
    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>> {
        self.0.get(wtxid).cloned()
    }

    fn get_wtxids(&self) -> Vec<WtxId> {
        self.0.keys().copied().collect()
    }
}

fn wtxid(seed: u8) -> WtxId {
    WtxId::new(
        TxId::from_bytes([seed; 32]),
        AuthDigest::from_bytes([seed; 32]),
    )
}

/// Short-ID compact block for 3470793: the coinbase prefilled, `slots` naming
/// transactions by index.
fn short_id_block(slots: &[usize]) -> (CompactBlock, Mempool) {
    let txs = fixtures::mainnet_transactions();
    let header = fixtures::mainnet_serialized_header();
    let hash = zcash_block_hash(&header);
    let short_ids = slots
        .iter()
        .map(|slot| ShortId::compute(&wtxid(*slot as u8), &hash, 0))
        .collect();
    let mempool = slots
        .iter()
        .map(|slot| (wtxid(*slot as u8), txs[*slot].clone()))
        .collect();
    let prefilled = vec![PrefilledTx {
        index: 0,
        tx_data: txs[0].clone(),
    }];
    (
        CompactBlock::new(header, 0, short_ids, prefilled),
        Mempool(mempool),
    )
}

#[tokio::test]
async fn the_short_id_path_refuses_a_repeated_final_transaction() {
    let mode = SubmitBlockMode::Live;

    // Positive control: the same path submits the genuine block.
    let zebra = Zebra::new();
    let (genuine, mempool) = short_id_block(&[1, 2, 3, 4, 5, 6]);
    let outcome = handle_relay_compact_block_with_mempool(&zebra, &genuine, mode, &mempool).await;
    assert_submitted(outcome);
    assert_eq!(zebra.calls(), 1);

    let zebra = Zebra::new();
    let (repeated, mempool) = short_id_block(&[1, 2, 3, 4, 5, 6, 6]);
    let outcome = handle_relay_compact_block_with_mempool(&zebra, &repeated, mode, &mempool).await;
    assert_body_rejected(outcome, BlockBodyError::DuplicateTxid { index: 7 });
    assert_eq!(zebra.calls(), 0);
}

/// Every short id resolves and the root matches the header it was built for, but
/// a slot holds a transaction the reader cannot read. The merkle check alone
/// used to pass this straight to the node.
#[tokio::test]
async fn the_short_id_path_refuses_a_slot_that_does_not_parse() {
    let garbage = vec![0xff; 40];
    let txs = [parseable_transaction(1), garbage.clone()];
    let header = committed_header(0xcd, &txs);
    let hash = zcash_block_hash(&header);
    let compact = CompactBlock::new(
        header,
        0,
        vec![ShortId::compute(&wtxid(1), &hash, 0)],
        vec![PrefilledTx {
            index: 0,
            tx_data: txs[0].clone(),
        }],
    );
    let mempool = Mempool([(wtxid(1), garbage)].into_iter().collect());
    let zebra = Zebra::new();

    let outcome =
        handle_relay_compact_block_with_mempool(&zebra, &compact, SubmitBlockMode::Live, &mempool)
            .await;

    assert_body_rejected(outcome, BlockBodyError::Transaction { index: 1 });
    assert_eq!(zebra.calls(), 0);
}

/// Refused before either costly step: the lookup, a Zebra round trip, is never
/// made, and the gate lock, held here by someone else, is never needed.
#[tokio::test]
async fn a_bad_gated_body_costs_no_parent_lookup_and_no_gate_lock() {
    let zebra = Zebra::new();
    let gate = tokio::sync::Mutex::new(gate());
    let _held = gate.lock().await;
    let lookups = AtomicUsize::new(0);
    let look_up = || async {
        lookups.fetch_add(1, Ordering::SeqCst);
        Some(parent())
    };
    let mode = SubmitBlockMode::Live;
    let limit = Duration::from_secs(30);
    let bad_compact = compact(&bad_transactions());
    let bad_raw = raw(&[7], &bad_transactions());

    let from_compact = timeout(
        limit,
        validate_then_gate_compact_block(&zebra, &bad_compact, mode, &gate, look_up),
    )
    .await
    .expect("a bad compact body must not wait for the gate");
    let from_raw = timeout(
        limit,
        validate_then_gate_raw_block(&zebra, &bad_raw, Some(block_hash()), mode, &gate, look_up),
    )
    .await
    .expect("a bad raw body must not wait for the gate");

    assert_body_rejected(from_compact, BlockBodyError::MerkleMismatch);
    assert_body_rejected(from_raw, BlockBodyError::MerkleMismatch);
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert_eq!(zebra.calls(), 0);
}

/// The other side of that test: a good body does make the lookup, once, and goes
/// on through the gate.
#[tokio::test]
async fn a_good_gated_body_looks_up_its_parent_once_and_is_submitted() {
    let mode = SubmitBlockMode::Live;
    let lookups = AtomicUsize::new(0);
    let look_up = || async {
        lookups.fetch_add(1, Ordering::SeqCst);
        Some(parent())
    };

    let zebra = Zebra::new();
    let gated = tokio::sync::Mutex::new(gate());
    let good = compact(&fixtures::mainnet_transactions());
    let outcome = validate_then_gate_compact_block(&zebra, &good, mode, &gated, look_up).await;
    assert_submitted(outcome);
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert_eq!(zebra.calls(), 1);

    let zebra = Zebra::new();
    let gated = tokio::sync::Mutex::new(gate());
    let good = fixtures::mainnet_raw_block();
    let outcome =
        validate_then_gate_raw_block(&zebra, &good, Some(block_hash()), mode, &gated, look_up)
            .await;
    assert_submitted(outcome);
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    assert_eq!(zebra.calls(), 1);
}

/// With a good body the lock is needed, so the wait is real: this is what makes
/// the bad body's clean return above a statement about order.
#[tokio::test]
async fn a_good_gated_body_waits_for_the_gate_lock() {
    let zebra = Zebra::new();
    let gate = tokio::sync::Mutex::new(gate());
    let held = gate.lock().await;
    let good = compact(&fixtures::mainnet_transactions());
    let mode = SubmitBlockMode::Live;
    let submit =
        validate_then_gate_compact_block(&zebra, &good, mode, &gate, || async { Some(parent()) });
    tokio::pin!(submit);

    tokio::select! {
        biased;
        _ = &mut submit => panic!("it went through a held gate"),
        () = tokio::task::yield_now() => {}
    }
    assert_eq!(zebra.calls(), 0);

    drop(held);
    assert_submitted(submit.await);
    assert_eq!(zebra.calls(), 1);
}

/// The tests above exercise the helpers. This pins that the receive loop uses
/// them: it has no gate lock or parent lookup of its own to put back in front of
/// validation.
#[test]
fn the_receive_loop_validates_before_the_lookup_and_the_lock() {
    let src = include_str!("../src/main.rs");

    assert_eq!(src.matches("validate_then_gate_compact_block(").count(), 1);
    assert_eq!(src.matches("validate_then_gate_raw_block(").count(), 1);
    assert!(!src.contains("gate.lock()"), "main.rs takes the gate lock");
    assert!(!src.contains("handle_relay_compact_block_with_gate"));
    assert!(!src.contains("handle_relay_raw_block_with_gate"));
}

/// `EmptyTransactions` is a body refusal on the raw path too, so it reaches the
/// body metric under its own label.
#[tokio::test]
async fn an_empty_raw_block_is_a_body_refusal() {
    let empty = raw(&[0], &[]);
    let zebra = Zebra::new();

    let outcome = handle_relay_raw_block(&zebra, &empty, None, SubmitBlockMode::Live).await;

    assert_body_rejected(outcome, BlockBodyError::EmptyTransactions);
    assert_eq!(zebra.calls(), 0);
}

/// One reply from Zebra.
#[derive(Clone, Copy, Debug)]
enum Reply {
    Accept,
    Duplicate,
    Reject,
    RpcError,
    Timeout,
}

/// Zebra answering from a script, and accepting once the script runs out.
struct ScriptedZebra {
    replies: Mutex<VecDeque<Reply>>,
    submitted: Mutex<Vec<String>>,
}

impl ScriptedZebra {
    fn new(replies: &[Reply]) -> Self {
        Self {
            replies: Mutex::new(replies.iter().copied().collect()),
            submitted: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.submitted.lock().unwrap().len()
    }
}

impl SubmitBlock for ScriptedZebra {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        self.submitted.lock().unwrap().push(block_hex.to_owned());
        let reply = self.replies.lock().unwrap().pop_front();
        Box::pin(async move {
            match reply.unwrap_or(Reply::Accept) {
                Reply::Accept => Ok(None),
                Reply::Duplicate => Ok(Some("duplicate".to_string())),
                Reply::Reject => Ok(Some("rejected".to_string())),
                Reply::RpcError => Err("connection refused".into()),
                Reply::Timeout => Err("request timed out".into()),
            }
        })
    }
}

/// A transaction in a layout the reader does not know. `last` tells bodies apart.
fn unknown_layout_transaction(last: u8) -> Vec<u8> {
    let mut tx = 0x8000_0007u32.to_le_bytes().to_vec();
    tx.extend_from_slice(&0x7a7a_7a7au32.to_le_bytes());
    tx.resize(400, 0x5a);
    tx[399] = last;
    tx
}

/// A real header and proof of work over a body the reader stops in.
fn unreadable_block(last: u8) -> Vec<u8> {
    let txs = fixtures::mainnet_transactions();
    raw(&[2], &[txs[0].clone(), unknown_layout_transaction(last)])
}

const UNREADABLE: BlockBodyError = BlockBodyError::Transaction { index: 1 };

const BUDGET: Duration = Duration::from_secs(5);

/// What the receive task does: the strict path first, then the bypass if it may apply.
async fn submit_body<S: SubmitBlock + Sync>(
    zebra: &S,
    block: &[u8],
    hash: [u8; 32],
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<SubmitGate<View>>,
    limits: UnverifiedLimits<'_>,
) -> Result<SubmissionOutcome, RelayBlockError> {
    let parent = || async { Some(parent()) };
    let strict = validate_then_gate_raw_block(zebra, block, Some(hash), mode, gate, parent).await;
    match unreadable_body(&strict) {
        Some(error) => {
            submit_unverified_raw_block(zebra, block, error, mode, gate, limits, parent).await
        }
        None => strict,
    }
}

async fn submit_with_bypass<S: SubmitBlock + Sync>(
    zebra: &S,
    block: &[u8],
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<SubmitGate<View>>,
    bypassed: &AtomicU64,
) -> Result<SubmissionOutcome, RelayBlockError> {
    let limits = UnverifiedLimits {
        budget: BUDGET,
        bypassed,
    };
    submit_body(zebra, block, block_hash(), mode, gate, limits).await
}

fn assert_gate_rejected(
    outcome: Result<SubmissionOutcome, RelayBlockError>,
    expected: RejectReason,
) {
    match outcome {
        Ok(SubmissionOutcome::GateRejected { reason, .. }) => assert_eq!(reason, expected),
        Ok(_) => panic!("expected {expected:?}, the candidate went through"),
        Err(error) => panic!("expected {expected:?}, got {error}"),
    }
}

/// The sidecar decides for itself: the same bytes are refused with its switch off,
/// whatever the sender did, and sent byte for byte with it on.
#[tokio::test]
async fn an_unreadable_raw_body_reaches_zebra_only_with_the_bypass() {
    let block = unreadable_block(1);
    let zebra = ScriptedZebra::new(&[]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);

    let refused = validate_then_gate_raw_block(
        &zebra,
        &block,
        Some(block_hash()),
        SubmitBlockMode::Live,
        &gate,
        || async { Some(parent()) },
    )
    .await;
    assert_body_rejected(refused, UNREADABLE);
    assert_eq!(zebra.calls(), 0);

    let outcome = submit_with_bypass(&zebra, &block, SubmitBlockMode::Live, &gate, &bypassed).await;

    match outcome {
        Ok(SubmissionOutcome::Submitted { candidate, status }) => {
            assert_eq!(status, SubmitBlockStatus::Accepted);
            assert_eq!(candidate.unverified, Some(UNREADABLE));
        }
        _ => panic!("the block did not reach Zebra"),
    }
    assert_eq!(*zebra.submitted.lock().unwrap(), [hex::encode(&block)]);
    assert_eq!(bypassed.load(Ordering::Relaxed), 1);
}

/// Each of these is a finding about the body, so the bypass does not apply.
#[tokio::test]
async fn the_bypass_covers_only_a_transaction_that_does_not_parse() {
    let txs = fixtures::mainnet_transactions();
    let mut trailing = fixtures::mainnet_raw_block();
    trailing.push(0);
    let mut repeated = txs.clone();
    repeated.push(txs[6].clone());
    let cases = [
        (trailing, BlockBodyError::TrailingBytes { bytes: 1 }),
        (
            raw(&[7], &bad_transactions()),
            BlockBodyError::MerkleMismatch,
        ),
        (
            raw(&[8], &repeated),
            BlockBodyError::DuplicateTxid { index: 7 },
        ),
        (
            raw(
                &[4],
                &[
                    txs[0].clone(),
                    txs[1].clone(),
                    txs[1].clone(),
                    unknown_layout_transaction(1),
                ],
            ),
            BlockBodyError::DuplicateTxid { index: 2 },
        ),
        (raw(&[0xfd, 7, 0], &txs), BlockBodyError::InvalidCount),
    ];
    for (block, expected) in cases {
        let zebra = ScriptedZebra::new(&[]);
        let gate = tokio::sync::Mutex::new(gate());
        let bypassed = AtomicU64::new(0);

        let outcome =
            submit_with_bypass(&zebra, &block, SubmitBlockMode::Live, &gate, &bypassed).await;

        assert_body_rejected(outcome, expected);
        assert_eq!(zebra.calls(), 0);
        assert_eq!(bypassed.load(Ordering::Relaxed), 0);
    }
}

/// The relay's checks are not relied on: a changed nonce leaves the hash metadata
/// for the sender to compute, and the solution no longer verifies.
#[tokio::test]
async fn a_header_with_no_real_proof_of_work_gets_no_bypass() {
    let mut block = unreadable_block(1);
    block[108] ^= 0x01;
    let hash = zcash_block_hash(&block[..sovright_relay::ZCASH_FULL_HEADER_SIZE]);
    let zebra = ScriptedZebra::new(&[]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);

    let limits = UnverifiedLimits {
        budget: BUDGET,
        bypassed: &bypassed,
    };
    let outcome = submit_body(&zebra, &block, hash, SubmitBlockMode::Live, &gate, limits).await;

    assert_body_rejected(outcome, UNREADABLE);
    assert_eq!(zebra.calls(), 0);
}

/// Whether the block is recorded depends on Zebra alone. Only an answer that it has
/// the block settles it; anything else leaves the next copy free to try.
#[tokio::test]
async fn an_unverified_block_is_recorded_only_once_zebra_has_it() {
    for (reply, settled) in [
        (Reply::Accept, true),
        (Reply::Duplicate, true),
        (Reply::Reject, false),
        (Reply::RpcError, false),
        (Reply::Timeout, false),
    ] {
        let block = unreadable_block(1);
        let zebra = ScriptedZebra::new(&[reply]);
        let gate = tokio::sync::Mutex::new(gate());
        let bypassed = AtomicU64::new(0);
        let mode = SubmitBlockMode::Live;

        let first = submit_with_bypass(&zebra, &block, mode, &gate, &bypassed).await;
        let second = submit_with_bypass(&zebra, &block, mode, &gate, &bypassed).await;

        assert_eq!(first.is_ok(), settled, "{reply:?}");
        if settled {
            assert_gate_rejected(second, RejectReason::DuplicateSubmit);
            assert_eq!(zebra.calls(), 1, "{reply:?}");
        } else {
            assert_submitted(second);
            assert_eq!(zebra.calls(), 2, "{reply:?}");
        }
    }
}

/// A dry run has no verdict, so it must not stop the real body in staging either.
#[tokio::test]
async fn an_unverified_dry_run_records_nothing() {
    let zebra = ScriptedZebra::new(&[]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let forged = unreadable_block(1);

    let outcome =
        submit_with_bypass(&zebra, &forged, SubmitBlockMode::DryRun, &gate, &bypassed).await;
    assert!(matches!(outcome, Ok(SubmissionOutcome::DryRun(_))));
    assert_eq!(zebra.calls(), 0);

    let real = validate_then_gate_raw_block(
        &zebra,
        &fixtures::mainnet_raw_block(),
        Some(block_hash()),
        SubmitBlockMode::Live,
        &gate,
        || async { Some(parent()) },
    )
    .await;
    assert_submitted(real);
}

async fn use_up_attempts(
    zebra: &ScriptedZebra,
    gate: &tokio::sync::Mutex<SubmitGate<View>>,
    bypassed: &AtomicU64,
    attempts: usize,
) {
    for last in 0..attempts {
        let block = unreadable_block(last as u8);
        let mode = SubmitBlockMode::Live;
        let outcome = submit_with_bypass(zebra, &block, mode, gate, bypassed).await;
        assert!(matches!(outcome, Err(RelayBlockError::SubmitRejected(..))));
    }
}

fn attempt_budget() -> usize {
    GateConfig::default().unreadable_attempts_per_block
}

/// Inside the budget a real unreadable body still reaches Zebra behind forged ones.
#[tokio::test]
async fn the_real_unreadable_body_is_tried_while_attempts_last() {
    let spare = attempt_budget() - 1;
    let zebra = ScriptedZebra::new(&vec![Reply::Reject; spare]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    use_up_attempts(&zebra, &gate, &bypassed, spare).await;
    let real = unreadable_block(0xff);

    let outcome = submit_with_bypass(&zebra, &real, SubmitBlockMode::Live, &gate, &bypassed).await;

    assert_submitted(outcome);
    assert_eq!(
        zebra.submitted.lock().unwrap().last().unwrap(),
        &hex::encode(&real)
    );
}

/// The limit stops recovery here. Forged bodies under a real header use up the
/// attempts, and the real unreadable body never reaches Zebra in this window. A
/// failed attempt counts too. No budget guarantees recovery from that.
#[tokio::test]
async fn known_gap_forged_bodies_can_use_up_the_attempts_before_the_real_one() {
    let budget = attempt_budget();
    let zebra = ScriptedZebra::new(&vec![Reply::Reject; budget]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    use_up_attempts(&zebra, &gate, &bypassed, budget).await;

    let real = unreadable_block(0xff);
    let outcome = submit_with_bypass(&zebra, &real, SubmitBlockMode::Live, &gate, &bypassed).await;

    assert_gate_rejected(outcome, RejectReason::UnverifiedLimit);
    assert_eq!(zebra.calls(), budget);
    assert_eq!(bypassed.load(Ordering::Relaxed) as usize, budget);
}

/// The limit is on bodies nothing could check, so a block that validates is outside it.
#[tokio::test]
async fn used_attempts_do_not_touch_a_block_that_validates() {
    let budget = attempt_budget();
    let zebra = ScriptedZebra::new(&vec![Reply::Reject; budget]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    use_up_attempts(&zebra, &gate, &bypassed, budget).await;

    let real = validate_then_gate_raw_block(
        &zebra,
        &fixtures::mainnet_raw_block(),
        Some(block_hash()),
        SubmitBlockMode::Live,
        &gate,
        || async { Some(parent()) },
    )
    .await;

    assert_submitted(real);
}

/// The relay's limit, applied here too: a testnet minimum-difficulty block has a real
/// solution and meets its target, and is outside what the bypass covers.
#[tokio::test]
async fn the_bypass_refuses_a_testnet_minimum_difficulty_block() {
    let mut block = fixtures::testnet_genesis_serialized_header();
    block.push(1);
    block.extend_from_slice(&unknown_layout_transaction(1));
    let hash = zcash_block_hash(&block[..sovright_relay::ZCASH_FULL_HEADER_SIZE]);
    let zebra = ScriptedZebra::new(&[]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);

    let limits = UnverifiedLimits {
        budget: BUDGET,
        bypassed: &bypassed,
    };
    let outcome = submit_body(&zebra, &block, hash, SubmitBlockMode::Live, &gate, limits).await;

    assert_body_rejected(outcome, BlockBodyError::Transaction { index: 0 });
    assert_eq!(zebra.calls(), 0);
}

/// Bad then good: Zebra's refusal leaves nothing behind, so the real body goes in.
#[tokio::test]
async fn a_forged_body_does_not_stop_the_real_block_at_the_gate() {
    let zebra = ScriptedZebra::new(&[Reply::Reject]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;

    let forged = submit_with_bypass(&zebra, &unreadable_block(1), mode, &gate, &bypassed).await;
    assert!(matches!(forged, Err(RelayBlockError::SubmitRejected(..))));

    let real = validate_then_gate_raw_block(
        &zebra,
        &fixtures::mainnet_raw_block(),
        Some(block_hash()),
        mode,
        &gate,
        || async { Some(parent()) },
    )
    .await;

    assert_submitted(real);
    assert_eq!(zebra.calls(), 2);
}

/// Good then bad: a validated block is recorded as before, so nothing unverified
/// goes to Zebra after it.
#[tokio::test]
async fn a_validated_block_stops_an_unverified_copy_at_the_gate() {
    let zebra = ScriptedZebra::new(&[]);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;
    let real = validate_then_gate_raw_block(
        &zebra,
        &fixtures::mainnet_raw_block(),
        Some(block_hash()),
        mode,
        &gate,
        || async { Some(parent()) },
    )
    .await;
    assert_submitted(real);

    let copy = submit_with_bypass(&zebra, &unreadable_block(1), mode, &gate, &bypassed).await;

    assert_gate_rejected(copy, RejectReason::DuplicateSubmit);
    assert_eq!(zebra.calls(), 1);
    assert_eq!(bypassed.load(Ordering::Relaxed), 0);
}

/// Zebra sits on every call until released, or on one body only if `only` is set.
struct HeldZebra {
    release: tokio::sync::Semaphore,
    calls: AtomicUsize,
    only: Option<String>,
}

impl HeldZebra {
    fn new(only: Option<&[u8]>) -> Self {
        Self {
            release: tokio::sync::Semaphore::new(0),
            calls: AtomicUsize::new(0),
            only: only.map(hex::encode),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    async fn reached(&self, calls: usize) {
        while self.calls() < calls {
            tokio::task::yield_now().await;
        }
    }
}

impl SubmitBlock for HeldZebra {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let held = self.only.as_deref().is_none_or(|only| only == block_hex);
        Box::pin(async move {
            if held {
                self.release.acquire().await.unwrap().forget();
            }
            Ok(None)
        })
    }
}

/// The same bytes wait for the answer already on its way, so Zebra is asked once.
#[tokio::test]
async fn concurrent_copies_of_an_unverified_body_reach_zebra_once() {
    let block = unreadable_block(1);
    let zebra = HeldZebra::new(None);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;
    let second = async {
        zebra.reached(1).await;
        let outcome = submit_with_bypass(&zebra, &block, mode, &gate, &bypassed).await;
        zebra.release.add_permits(1);
        outcome
    };

    let (first, second) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            submit_with_bypass(&zebra, &block, mode, &gate, &bypassed),
            second,
        )
    })
    .await
    .expect("the second copy does not wait for Zebra");

    assert_submitted(first);
    assert_gate_rejected(second, RejectReason::DuplicateSubmit);
    assert_eq!(zebra.calls(), 1);
}

/// Another body of the same block does not wait: it may be the real one, and the first
/// may never be answered. Zebra's acceptance is what settles the block.
#[tokio::test]
async fn a_different_body_of_the_block_does_not_wait_for_the_first() {
    let forged = unreadable_block(1);
    let real = unreadable_block(2);
    let zebra = HeldZebra::new(Some(&forged));
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;
    let held = submit_with_bypass(&zebra, &forged, mode, &gate, &bypassed);
    let second = async {
        zebra.reached(1).await;
        let outcome = submit_with_bypass(&zebra, &real, mode, &gate, &bypassed).await;
        zebra.release.add_permits(1);
        outcome
    };

    let (first, second) = timeout(Duration::from_secs(5), async { tokio::join!(held, second) })
        .await
        .expect("the real body does not wait for the forged one");

    assert_submitted(first);
    assert_submitted(second);
    assert_eq!(zebra.calls(), 2);
}

/// While Zebra sits on an unverified body the gate is free, so a block from another
/// header is submitted and answered with that call still open.
#[tokio::test]
async fn a_valid_block_does_not_wait_for_an_unverified_zebra_call() {
    let unverified = unreadable_block(1);
    let txs = [parseable_transaction(9)];
    let other = raw_block(&committed_header(0x11, &txs), &txs);
    let other_header = &other[..sovright_relay::ZCASH_FULL_HEADER_SIZE];
    let other_parent = ParentObservation {
        parent_hash: CandidateMeta::parent_hash_from_header(other_header).unwrap(),
        height: 100,
        confirmations: Some(1),
    };
    let zebra = HeldZebra::new(Some(&unverified));
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;
    let valid = async {
        zebra.reached(1).await;
        let outcome = validate_then_gate_raw_block(
            &zebra,
            &other,
            Some(zcash_block_hash(other_header)),
            mode,
            &gate,
            || async { Some(other_parent.clone()) },
        )
        .await;
        assert_eq!(zebra.calls(), 2, "it reached Zebra");
        zebra.release.add_permits(1);
        outcome
    };

    let (first, second) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            submit_with_bypass(&zebra, &unverified, mode, &gate, &bypassed),
            valid,
        )
    })
    .await
    .expect("the valid block does not wait for the unverified call");

    assert_submitted(first);
    assert_submitted(second);
}

/// Zebra rejects at once and the lookup after it never ends. Both are inside one budget.
struct StalledLookupZebra;

impl SubmitBlock for StalledLookupZebra {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async { Ok(Some("rejected".to_string())) })
    }

    fn block_known<'a>(&'a self, _block_hash_hex: &'a str) -> BlockKnownFuture<'a> {
        Box::pin(std::future::pending())
    }
}

async fn submit_within<S: SubmitBlock + Sync>(
    zebra: &S,
    gate: &tokio::sync::Mutex<SubmitGate<View>>,
    budget: Duration,
    bypassed: &AtomicU64,
) -> Result<SubmissionOutcome, RelayBlockError> {
    let limits = UnverifiedLimits { budget, bypassed };
    let block = unreadable_block(1);
    submit_body(
        zebra,
        &block,
        block_hash(),
        SubmitBlockMode::Live,
        gate,
        limits,
    )
    .await
}

/// One budget covers the whole attempt, whichever call it ends in, and neither leaves
/// a record: the next copy goes to Zebra.
#[tokio::test]
async fn the_budget_ends_an_attempt_in_either_rpc_and_records_nothing() {
    let budget = Duration::from_millis(50);
    let held = HeldZebra::new(None);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);

    let attempts = async {
        [
            submit_within(&held, &gate, budget, &bypassed).await,
            submit_within(&StalledLookupZebra, &gate, budget, &bypassed).await,
        ]
    };
    let outcomes = timeout(Duration::from_secs(5), attempts)
        .await
        .expect("the budget ended both attempts");
    for outcome in outcomes {
        assert!(matches!(outcome, Err(RelayBlockError::SubmitFailed(_))));
    }

    let zebra = ScriptedZebra::new(&[]);
    assert_submitted(
        submit_with_bypass(
            &zebra,
            &unreadable_block(1),
            SubmitBlockMode::Live,
            &gate,
            &bypassed,
        )
        .await,
    );
    assert_eq!(zebra.calls(), 1);
}

/// A task dropped at Zebra leaves nothing behind but the attempt it used.
#[tokio::test]
async fn cancelling_an_attempt_records_nothing_and_frees_its_body() {
    let block = unreadable_block(1);
    let held = HeldZebra::new(None);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;

    {
        let attempt = submit_with_bypass(&held, &block, mode, &gate, &bypassed);
        tokio::pin!(attempt);
        tokio::select! {
            _ = &mut attempt => panic!("Zebra never answers"),
            () = held.reached(1) => {}
        }
    }

    let zebra = ScriptedZebra::new(&[]);
    assert_submitted(submit_with_bypass(&zebra, &block, mode, &gate, &bypassed).await);
    assert_eq!(zebra.calls(), 1);
}

/// A Zebra that accepts the connection and never answers, for the real RPC client.
async fn silent_zebra() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (url, server)
}

/// The real client under the real wrapper, so each call's bound is shown on the path
/// the sidecar uses, under a budget too long to be what ended it.
#[tokio::test]
async fn an_unanswered_zebra_call_ends_at_the_rpc_timeout() {
    let (url, server) = silent_zebra().await;
    let rpc = ZebraRpc::with_request_timeout(&url, Duration::from_millis(100))
        .await
        .unwrap();
    let zebra = DualSubmit::primary_only(std::sync::Arc::new(rpc), "unused", None);
    let gate = tokio::sync::Mutex::new(gate());
    let bypassed = AtomicU64::new(0);
    let mode = SubmitBlockMode::Live;
    let block = unreadable_block(1);

    let outcome = timeout(
        Duration::from_secs(5),
        submit_with_bypass(&zebra, &block, mode, &gate, &bypassed),
    )
    .await
    .expect("the client's timeout ended the call");

    assert!(matches!(outcome, Err(RelayBlockError::SubmitFailed(_))));
    let hash = "ab".repeat(32);
    let lookup = timeout(Duration::from_secs(5), zebra.block_known(&hash)).await;
    assert_eq!(lookup.expect("the same bound covers the lookup"), None);
    server.abort();
}

#[test]
fn the_real_client_is_bounded_at_thirty_seconds() {
    assert_eq!(ZEBRA_RPC_REQUEST_TIMEOUT, Duration::from_secs(30));
}

// ---------------------------------------------------------------------------
// #130 PR B characterization. A `known_gap_` test pins what the code does today:
// it passes because the gap is open, and is not a behaviour to preserve.
// ---------------------------------------------------------------------------

/// Block 3470793 with a byte of transaction 2 changed where no txid covers it, so
/// every txid and the merkle root hold and the strict reader cannot tell it from
/// the genuine block. `Zebra` above refuses it only because the bytes differ: that
/// stands in for a refusal and says nothing about what a node would decide.
fn transactions_the_stand_in_refuses() -> Vec<Vec<u8>> {
    let header = fixtures::mainnet_serialized_header();
    let genuine = fixtures::mainnet_transactions();
    let mut txs = genuine.clone();
    txs[2][70] ^= 0x01;
    assert_ne!(txs[2], genuine[2]);
    assert_eq!(
        sovright_relay::txid_from_tx_bytes(&txs[2]),
        sovright_relay::txid_from_tx_bytes(&genuine[2]),
        "the change must leave the txid alone"
    );
    assert_eq!(raw_block(&header, &genuine), fixtures::mainnet_raw_block());
    assert_eq!(
        sovright_relay::validate_block_body(&raw_block(&header, &txs)),
        Ok(txs.len()),
        "the first body must pass the strict reader, or this is not the case under test"
    );
    txs
}

fn assert_refused_by_the_stand_in(outcome: Result<SubmissionOutcome, RelayBlockError>) {
    assert!(
        matches!(outcome, Err(RelayBlockError::SubmitRejected(..))),
        "expected the stand-in's refusal, got {outcome:?}"
    );
}

/// A body Zebra refuses leaves the block open, so the real one still gets its turn.
#[tokio::test]
async fn a_refused_raw_body_leaves_the_gate_open_for_the_real_block() {
    let mode = SubmitBlockMode::Live;
    let look_up = || async { Some(parent()) };
    let hash = Some(block_hash());
    let header = fixtures::mainnet_serialized_header();
    let refused = raw_block(&header, &transactions_the_stand_in_refuses());
    let real = fixtures::mainnet_raw_block();

    let zebra = Zebra::new();
    let gated = tokio::sync::Mutex::new(gate());
    let first = validate_then_gate_raw_block(&zebra, &refused, hash, mode, &gated, look_up).await;
    assert_refused_by_the_stand_in(first);
    assert_eq!(zebra.calls(), 1);

    let second = validate_then_gate_raw_block(&zebra, &real, hash, mode, &gated, look_up).await;
    assert_submitted(second);
    assert_eq!(zebra.calls(), 2);

    // Zebra has it now, so that closes the block, for this body and any other.
    let third = validate_then_gate_raw_block(&zebra, &refused, hash, mode, &gated, look_up).await;
    assert_gate_rejected(third, RejectReason::DuplicateSubmit);
    assert_eq!(zebra.calls(), 2);
}

#[tokio::test]
async fn a_refused_compact_body_leaves_the_gate_open_for_the_real_block() {
    let mode = SubmitBlockMode::Live;
    let look_up = || async { Some(parent()) };
    let refused = compact(&transactions_the_stand_in_refuses());
    let real = compact(&fixtures::mainnet_transactions());

    let zebra = Zebra::new();
    let gated = tokio::sync::Mutex::new(gate());
    let first = validate_then_gate_compact_block(&zebra, &refused, mode, &gated, look_up).await;
    assert_refused_by_the_stand_in(first);
    assert_eq!(zebra.calls(), 1);

    let second = validate_then_gate_compact_block(&zebra, &real, mode, &gated, look_up).await;
    assert_submitted(second);
    assert_eq!(zebra.calls(), 2);
}

/// With the gate off the sidecar builds no gate at all, so nothing was recorded.
#[tokio::test]
async fn gate_off_a_refused_raw_body_does_not_stop_the_real_block() {
    let mode = SubmitBlockMode::Live;
    let hash = Some(block_hash());
    let header = fixtures::mainnet_serialized_header();
    let refused = raw_block(&header, &transactions_the_stand_in_refuses());

    let zebra = Zebra::new();
    let first = handle_relay_raw_block(&zebra, &refused, hash, mode).await;
    assert_refused_by_the_stand_in(first);
    assert_eq!(zebra.calls(), 1);

    let real = fixtures::mainnet_raw_block();
    assert_submitted(handle_relay_raw_block(&zebra, &real, hash, mode).await);
    assert_eq!(zebra.calls(), 2);
}

// ---------------------------------------------------------------------------
// #130 PR B: the gate on the real submit path. Only Zebra's answer closes a block, and
// the gate lock is not held while Zebra thinks. The stand-ins here answer as they are
// told to, which says nothing about what a node would decide.
// ---------------------------------------------------------------------------

/// Another body of the real header that the strict reader passes, told apart by `mark`.
fn strict_body(mark: u8) -> Vec<u8> {
    let header = fixtures::mainnet_serialized_header();
    let mut txs = fixtures::mainnet_transactions();
    txs[2][70] ^= mark;
    let body = raw_block(&header, &txs);
    assert_eq!(
        sovright_relay::validate_block_body(&body),
        Ok(txs.len()),
        "the strict reader must pass it, or this is not the case under test"
    );
    body
}

/// Every call waits for a permit.
struct PausedZebra {
    entered: AtomicUsize,
    permits: tokio::sync::Semaphore,
}

impl PausedZebra {
    fn new() -> Self {
        Self {
            entered: AtomicUsize::new(0),
            permits: tokio::sync::Semaphore::new(0),
        }
    }

    async fn calls_reach(&self, count: usize) {
        while self.entered.load(Ordering::SeqCst) < count {
            tokio::task::yield_now().await;
        }
    }
}

impl SubmitBlock for PausedZebra {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.permits.acquire().await.expect("never closed").forget();
            Ok(None)
        })
    }
}

/// Refuses every copy, and has the block.
struct LosingRaceZebra;

impl SubmitBlock for LosingRaceZebra {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async move { Ok(Some("rejected".to_string())) })
    }

    fn block_known<'a>(
        &'a self,
        _block_hash_hex: &'a str,
    ) -> sovright_relay_sidecar::submit::BlockKnownFuture<'a> {
        Box::pin(async move { Some(true) })
    }
}

fn gate_with(attempts: usize, bodies: usize) -> tokio::sync::Mutex<SubmitGate<View>> {
    tokio::sync::Mutex::new(SubmitGate::new(
        GateConfig {
            enabled: true,
            strict_attempts_per_block: attempts,
            strict_bodies_per_block: bodies,
            ..GateConfig::default()
        },
        View,
    ))
}

const LIVE: SubmitBlockMode = SubmitBlockMode::Live;

/// Two bodies of one block at Zebra at once. With the gate held through the call the
/// second would never get there, and this would time out.
#[tokio::test]
async fn a_body_at_zebra_stops_no_other_body() {
    let (zebra, gated) = (PausedZebra::new(), tokio::sync::Mutex::new(gate()));
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };
    let (real, other) = (fixtures::mainnet_raw_block(), strict_body(1));

    let both = async {
        tokio::join!(
            validate_then_gate_raw_block(&zebra, &other, hash, LIVE, &gated, look_up),
            validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up),
            async {
                zebra.calls_reach(2).await;
                zebra.permits.add_permits(2);
            },
        )
    };
    let (first, second, ()) = timeout(Duration::from_secs(5), both)
        .await
        .expect("the gate is not held through the call");

    assert_submitted(first);
    assert_submitted(second);
}

#[tokio::test]
async fn the_same_bytes_wait_for_the_answer_at_zebra() {
    let (zebra, gated) = (PausedZebra::new(), tokio::sync::Mutex::new(gate()));
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };
    let real = fixtures::mainnet_raw_block();

    let first = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up);
    let second = async {
        zebra.calls_reach(1).await;
        let copy = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
        zebra.permits.add_permits(1);
        copy
    };
    let (first, second) = tokio::join!(first, second);

    assert_submitted(first);
    assert_gate_rejected(second, RejectReason::DuplicateSubmit);
    assert_eq!(zebra.entered.load(Ordering::SeqCst), 1);
}

/// A caller that goes away in the middle of the call leaves nothing behind it.
#[tokio::test]
async fn a_cancelled_call_leaves_the_block_open() {
    let (zebra, gated) = (PausedZebra::new(), tokio::sync::Mutex::new(gate()));
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };
    let real = fixtures::mainnet_raw_block();
    {
        let first = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up);
        tokio::pin!(first);
        tokio::select! {
            _ = &mut first => panic!("nothing has answered it"),
            () = zebra.calls_reach(1) => {}
        }
    }

    zebra.permits.add_permits(1);
    let again = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;

    assert_submitted(again);
}

#[tokio::test]
async fn a_failed_call_records_nothing() {
    for reply in [Reply::RpcError, Reply::Timeout, Reply::Reject] {
        let zebra = ScriptedZebra::new(&[reply]);
        let gated = tokio::sync::Mutex::new(gate());
        let hash = Some(block_hash());
        let look_up = || async { Some(parent()) };
        let real = fixtures::mainnet_raw_block();

        let first = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
        assert!(first.is_err(), "{reply:?}");

        let again = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
        assert_submitted(again);
    }
}

/// `duplicate`, and a refusal of a block Zebra turns out to have, both say it has it.
#[tokio::test]
async fn what_zebra_says_it_has_closes_the_block_whichever_way_it_says_it() {
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };
    let real = fixtures::mainnet_raw_block();

    let zebra = ScriptedZebra::new(&[Reply::Duplicate]);
    let gated = tokio::sync::Mutex::new(gate());
    let first = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
    assert!(first.is_ok());
    let next = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
    assert_gate_rejected(next, RejectReason::DuplicateSubmit);

    let zebra = LosingRaceZebra;
    let gated = tokio::sync::Mutex::new(gate());
    let first = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
    assert!(matches!(
        first,
        Err(RelayBlockError::SubmitRejected(
            _,
            sovright_relay_sidecar::submit::SubmitRejectionClass::RaceLost
        ))
    ));
    let next = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
    assert_gate_rejected(next, RejectReason::DuplicateSubmit);
}

/// A dry run says nothing about Zebra, so it never stops a live candidate.
#[tokio::test]
async fn a_dry_run_leaves_no_mark_on_a_live_candidate() {
    let zebra = Zebra::new();
    let gated = tokio::sync::Mutex::new(gate());
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };
    let real = fixtures::mainnet_raw_block();
    let dry = SubmitBlockMode::DryRun;

    let first = validate_then_gate_raw_block(&zebra, &real, hash, dry, &gated, look_up).await;
    assert!(matches!(first, Ok(SubmissionOutcome::DryRun(_))));
    let again = validate_then_gate_raw_block(&zebra, &real, hash, dry, &gated, look_up).await;
    assert_gate_rejected(again, RejectReason::DuplicateSubmit);
    assert_eq!(zebra.calls(), 0);

    let live = validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
    assert_submitted(live);
}

/// A repeat of one body spends calls and no bodies, and what spends the limit stays spent
/// when Zebra refuses, so a body sent over and over has a ceiling.
#[tokio::test]
async fn a_repeat_spends_a_call_and_no_body() {
    let zebra = ScriptedZebra::new(&[Reply::Reject, Reply::Reject]);
    let gated = gate_with(2, 1);
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };
    let bad = strict_body(1);

    for _ in 0..2 {
        let refused = validate_then_gate_raw_block(&zebra, &bad, hash, LIVE, &gated, look_up).await;
        assert!(matches!(refused, Err(RelayBlockError::SubmitRejected(..))));
    }
    let third = validate_then_gate_raw_block(&zebra, &bad, hash, LIVE, &gated, look_up).await;
    assert_gate_rejected(third, RejectReason::StrictLimit);
    assert_eq!(zebra.calls(), 2);
}

/// What stays open, and what no value of the limit takes away: anyone holding a real
/// header can spend it with bodies the strict reader passes, and the real body is then
/// refused until the window ends.
#[tokio::test]
async fn known_gap_bodies_can_use_up_the_limit_before_the_real_one_comes() {
    let zebra = ScriptedZebra::new(&[Reply::Reject, Reply::Reject]);
    let gated = gate_with(8, 2);
    let hash = Some(block_hash());
    let look_up = || async { Some(parent()) };

    for mark in [1, 2] {
        let body = strict_body(mark);
        let refused =
            validate_then_gate_raw_block(&zebra, &body, hash, LIVE, &gated, look_up).await;
        assert!(matches!(refused, Err(RelayBlockError::SubmitRejected(..))));
    }

    let real = fixtures::mainnet_raw_block();
    let turned_away =
        validate_then_gate_raw_block(&zebra, &real, hash, LIVE, &gated, look_up).await;
    assert_gate_rejected(turned_away, RejectReason::StrictLimit);
    assert_eq!(zebra.calls(), 2);
}
