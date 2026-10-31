//! Block body validation at the sidecar boundary (#130), on the real mainnet
//! block 3470793. A counting Zebra stands in for the node: it accepts only the
//! genuine block, so a call count of zero means the candidate never reached it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use sovright_relay::test_support::{
    committed_header, parseable_transaction_with_script, raw_block,
};
use sovright_relay::{
    AuthDigest, BlockBodyError, CompactBlock, MAX_BLOCK_BYTES, MempoolProvider, PrefilledTx,
    ShortId, TxId, WtxId, ZCASH_FULL_HEADER_SIZE, zcash_block_hash,
};
use sovright_relay_sidecar::submit::{
    RelayBlockError, SubmissionCandidate, SubmissionOutcome, SubmitBlock, SubmitBlockMode,
    SubmitBlockStatus, SubmitFuture, build_raw_block_submission_candidate,
    build_submission_candidate, handle_relay_compact_block, handle_relay_compact_block_with_gate,
    handle_relay_compact_block_with_mempool, handle_relay_raw_block,
    handle_relay_raw_block_with_gate,
};
use sovright_relay_sidecar::submit_gate::{
    CandidateMeta, ChainView, GateConfig, ParentObservation, RejectReason, SubmitGate,
};
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
    let last = txs[6].len();
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
        (
            raw(&[6], &txs),
            BlockBodyError::TrailingBytes { bytes: last },
        ),
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
    assert!(
        matches!(
            &outcome,
            Err(RelayBlockError::ReconstructionInvalid { reason })
                if reason.contains("merkle root mismatch")
        ),
        "got {:?}",
        outcome.map(|_| "a candidate")
    );
    assert_eq!(zebra.calls(), 0);
}
