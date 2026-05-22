use std::sync::atomic::{AtomicUsize, Ordering};

use bedrock_forge::{CompactBlock, PrefilledTx, ShortId};
use forge_sidecar::submit::{
    RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitFuture,
    build_submission_candidate, handle_relay_compact_block,
};

struct CountingSubmitter {
    calls: AtomicUsize,
}

impl CountingSubmitter {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl SubmitBlock for CountingSubmitter {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(None) })
    }
}

fn header() -> Vec<u8> {
    vec![0xab; 1487]
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
                index: 1,
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

    assert!(matches!(outcome, SubmissionOutcome::Submitted { .. }));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);
}
