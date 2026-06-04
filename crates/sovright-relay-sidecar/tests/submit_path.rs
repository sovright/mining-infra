use std::sync::atomic::{AtomicUsize, Ordering};

use sovright_relay::{CompactBlock, PrefilledTx, ShortId, zcash_block_hash};
use sovright_relay_sidecar::submit::{
    RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitBlockStatus,
    SubmitFuture, build_raw_block_submission_candidate, build_submission_candidate,
    handle_relay_compact_block, handle_relay_raw_block,
};

struct CountingSubmitter {
    calls: AtomicUsize,
    result: Option<String>,
}

impl CountingSubmitter {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            result: None,
        }
    }

    fn with_result(result: impl Into<String>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            result: Some(result.into()),
        }
    }
}

impl SubmitBlock for CountingSubmitter {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(self.result.clone()) })
    }
}

fn header() -> Vec<u8> {
    vec![0xab; 1487]
}

fn raw_block_hash(raw_block: &[u8]) -> [u8; 32] {
    zcash_block_hash(&raw_block[..1487])
}

fn raw_block() -> Vec<u8> {
    let mut block = header();
    block.push(1);
    block.extend_from_slice(&[0x01, 0x02, 0x03]);
    block
}

#[test]
fn candidate_rejects_header_only_compact_block() {
    let compact = CompactBlock::new(header(), 0, vec![], vec![]);

    let err = build_submission_candidate(&compact).unwrap_err();

    assert_eq!(err, RelayBlockError::EmptyTransactions);
}

#[test]
fn candidate_rejects_missing_short_id_transactions() {
    let compact = CompactBlock::new(
        header(),
        0,
        vec![ShortId::from_bytes([1, 2, 3, 4, 5, 6])],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    );

    let err = build_submission_candidate(&compact).unwrap_err();

    assert_eq!(err, RelayBlockError::MissingTransactions { short_ids: 1 });
}

#[test]
fn candidate_serializes_contiguous_prefilled_transactions() {
    let compact = CompactBlock::new(
        header(),
        0,
        vec![],
        vec![
            PrefilledTx {
                index: 0,
                tx_data: vec![0x01, 0x02],
            },
            PrefilledTx {
                index: 0,
                tx_data: vec![0x03],
            },
        ],
    );

    let candidate = build_submission_candidate(&compact).unwrap();

    assert_eq!(candidate.tx_count, 2);
    assert_eq!(candidate.block_bytes, 1487 + 1 + 3);
    assert!(candidate.block_hex.ends_with("02010203"));
}

#[tokio::test]
async fn dry_run_does_not_submit_to_zebra() {
    let submitter = CountingSubmitter::new();
    let compact = CompactBlock::new(
        header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    );

    let outcome = handle_relay_compact_block(&submitter, &compact, SubmitBlockMode::DryRun)
        .await
        .unwrap();

    assert!(matches!(outcome, SubmissionOutcome::DryRun(_)));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn live_mode_submits_candidate_to_zebra() {
    let submitter = CountingSubmitter::new();
    let compact = CompactBlock::new(
        header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    );

    let outcome = handle_relay_compact_block(&submitter, &compact, SubmitBlockMode::Live)
        .await
        .unwrap();

    assert!(matches!(
        outcome,
        SubmissionOutcome::Submitted {
            status: SubmitBlockStatus::Accepted,
            ..
        }
    ));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn live_mode_treats_duplicate_submitblock_as_idempotent() {
    let submitter = CountingSubmitter::with_result("duplicate");
    let compact = CompactBlock::new(
        header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    );

    let outcome = handle_relay_compact_block(&submitter, &compact, SubmitBlockMode::Live)
        .await
        .unwrap();

    assert!(matches!(
        outcome,
        SubmissionOutcome::Submitted {
            status: SubmitBlockStatus::Duplicate,
            ..
        }
    ));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn live_mode_rejects_non_duplicate_submitblock_reason() {
    let submitter = CountingSubmitter::with_result("bad-cb-amount");
    let compact = CompactBlock::new(
        header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    );

    let err = handle_relay_compact_block(&submitter, &compact, SubmitBlockMode::Live)
        .await
        .unwrap_err();

    assert_eq!(
        err,
        RelayBlockError::SubmitRejected("bad-cb-amount".to_string())
    );
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn raw_block_candidate_uses_complete_raw_bytes() {
    let raw_block = raw_block();
    let expected_hash = raw_block_hash(&raw_block);

    let candidate = build_raw_block_submission_candidate(&raw_block, Some(expected_hash)).unwrap();

    assert_eq!(candidate.tx_count, 1);
    assert_eq!(candidate.block_bytes, raw_block.len());
    assert_eq!(candidate.block_hex, hex::encode(&raw_block));
    assert_eq!(candidate.block_hash, hex::encode(expected_hash));
}

#[test]
fn raw_block_candidate_rejects_hash_mismatch() {
    let raw_block = raw_block();

    let err = build_raw_block_submission_candidate(&raw_block, Some([0x55; 32])).unwrap_err();

    assert_eq!(err, RelayBlockError::RawBlockHashMismatch);
}

#[tokio::test]
async fn dry_run_raw_block_does_not_submit_to_zebra() {
    let submitter = CountingSubmitter::new();
    let raw_block = raw_block();
    let expected_hash = raw_block_hash(&raw_block);

    let outcome = handle_relay_raw_block(
        &submitter,
        &raw_block,
        Some(expected_hash),
        SubmitBlockMode::DryRun,
    )
    .await
    .unwrap();

    assert!(matches!(outcome, SubmissionOutcome::DryRun(_)));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}
