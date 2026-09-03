use std::sync::atomic::{AtomicUsize, Ordering};

use sovright_relay::{CompactBlock, PrefilledTx, ShortId, zcash_block_hash};
use sovright_relay_sidecar::submit::{
    BlockKnownFuture, RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode,
    SubmitBlockStatus, SubmitFuture, SubmitRejectionClass, build_raw_block_submission_candidate,
    build_submission_candidate, handle_relay_compact_block, handle_relay_raw_block,
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

    // The default SubmitBlock::block_known returns None for test doubles, so a
    // rejection they produce is Unknown rather than misattributed to a race.
    assert_eq!(
        err,
        RelayBlockError::SubmitRejected("bad-cb-amount".to_string(), SubmitRejectionClass::Unknown)
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

// ---------------------------------------------------------------------------
// Gated wrappers (handle_relay_*_with_gate)
// ---------------------------------------------------------------------------

use sovright_relay_sidecar::submit::{
    handle_relay_compact_block_with_gate, handle_relay_raw_block_with_gate,
};
use sovright_relay_sidecar::submit_gate::{ChainView, GateConfig, RejectReason, SubmitGate};

struct AlwaysKnownChain {
    tip: u64,
}

impl ChainView for AlwaysKnownChain {
    fn tip_height(&self) -> u64 {
        self.tip
    }
    fn parent_known(&self, _parent_hash: &[u8; 32]) -> bool {
        true
    }
}

struct UnknownParentChain {
    tip: u64,
}

impl ChainView for UnknownParentChain {
    fn tip_height(&self) -> u64 {
        self.tip
    }
    fn parent_known(&self, _parent_hash: &[u8; 32]) -> bool {
        false
    }
}

fn compact_with_prefilled_one() -> CompactBlock {
    CompactBlock::new(
        header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    )
}

fn enabled_gate_config() -> GateConfig {
    GateConfig {
        enabled: true,
        allowed_below: 3,
        dedup_window: std::time::Duration::from_secs(60),
        dedup_capacity: 8,
    }
}

#[tokio::test]
async fn gated_compact_dry_run_accepts_when_gate_accepts() {
    let submitter = CountingSubmitter::new();
    let compact = compact_with_prefilled_one();
    let candidate = build_submission_candidate(&compact).unwrap();
    // candidate.block_hash is derived from the (all-zero parent) header,
    // so the gate at tip = candidate_height accepts.
    let chain = AlwaysKnownChain { tip: 100 };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);
    let parent_height = 99;

    let outcome = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::DryRun,
        &mut gate,
        parent_height,
    )
    .await
    .unwrap();

    let candidate_hash = candidate.block_hash;
    assert!(
        matches!(outcome, SubmissionOutcome::DryRun(ref c) if c.block_hash == candidate_hash),
        "gate-accepted dry-run must surface a DryRun outcome"
    );
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gated_compact_rejects_unknown_parent() {
    let submitter = CountingSubmitter::new();
    let compact = compact_with_prefilled_one();
    let chain = UnknownParentChain { tip: 100 };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    let outcome = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::Live,
        &mut gate,
        99,
    )
    .await
    .unwrap();

    assert!(
        matches!(
            outcome,
            SubmissionOutcome::GateRejected {
                reason: RejectReason::UnknownParent,
                ..
            }
        ),
        "unknown parent must surface GateRejected",
    );
    assert_eq!(
        submitter.calls.load(Ordering::SeqCst),
        0,
        "gate-rejected blocks must never call submit_block",
    );
}

#[tokio::test]
async fn gated_compact_rejects_out_of_window_height() {
    let submitter = CountingSubmitter::new();
    let compact = compact_with_prefilled_one();
    // tip = 1000, allowed_below = 3, so candidate height = parent + 1 = 996
    // (parent = 995) is below the window of [997, 1001].
    let chain = AlwaysKnownChain { tip: 1000 };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    let outcome = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::Live,
        &mut gate,
        995,
    )
    .await
    .unwrap();

    assert!(matches!(
        outcome,
        SubmissionOutcome::GateRejected {
            reason: RejectReason::OutOfHeightWindow,
            ..
        }
    ));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gated_compact_dedups_repeat_submissions() {
    let submitter = CountingSubmitter::new();
    let compact = compact_with_prefilled_one();
    let chain = AlwaysKnownChain { tip: 100 };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    let first = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::DryRun,
        &mut gate,
        99,
    )
    .await
    .unwrap();
    assert!(matches!(first, SubmissionOutcome::DryRun(_)));

    let second = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::DryRun,
        &mut gate,
        99,
    )
    .await
    .unwrap();
    assert!(matches!(
        second,
        SubmissionOutcome::GateRejected {
            reason: RejectReason::DuplicateSubmit,
            ..
        }
    ));
}

#[tokio::test]
async fn gated_compact_disabled_gate_accepts() {
    let submitter = CountingSubmitter::new();
    let compact = compact_with_prefilled_one();
    let chain = UnknownParentChain { tip: 100 }; // would reject if gate enabled
    let mut gate = SubmitGate::new(
        GateConfig {
            enabled: false,
            ..enabled_gate_config()
        },
        chain,
    );

    let outcome = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::DryRun,
        &mut gate,
        99,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SubmissionOutcome::DryRun(_)));
}

#[tokio::test]
async fn gated_raw_block_dry_run_accepts_when_gate_accepts() {
    let submitter = CountingSubmitter::new();
    let raw = raw_block();
    let expected_hash = raw_block_hash(&raw);
    let chain = AlwaysKnownChain { tip: 100 };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    let outcome = handle_relay_raw_block_with_gate(
        &submitter,
        &raw,
        Some(expected_hash),
        SubmitBlockMode::DryRun,
        &mut gate,
        99,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SubmissionOutcome::DryRun(_)));
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

// --- rejection classification ---------------------------------------------
//
// In a four-relay mesh every sidecar races to submit the same block and the
// losers get a rejection back. Zebra returns the same opaque "rejected" string
// for that as for a genuinely invalid block -- verified against 24h of
// production logs on two relays (520 and 336 rejections, every one
// reason=rejected). Without this split the rejection counter cannot support a
// threshold: the relay that loses the most races looks the most broken.

struct ClassifyingSubmitter {
    known: Option<bool>,
}

impl SubmitBlock for ClassifyingSubmitter {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async move { Ok(Some("rejected".to_string())) })
    }

    fn block_known<'a>(&'a self, _block_hash_hex: &'a str) -> BlockKnownFuture<'a> {
        let known = self.known;
        Box::pin(async move { known })
    }
}

async fn classify_with(known: Option<bool>) -> SubmitRejectionClass {
    let submitter = ClassifyingSubmitter { known };
    let compact = CompactBlock::new(
        header(),
        0,
        vec![],
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0x01],
        }],
    );
    match handle_relay_compact_block(&submitter, &compact, SubmitBlockMode::Live)
        .await
        .unwrap_err()
    {
        RelayBlockError::SubmitRejected(_, class) => class,
        other => panic!("expected SubmitRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn rejection_of_a_block_zebra_already_has_is_a_lost_race() {
    assert_eq!(
        classify_with(Some(true)).await,
        SubmitRejectionClass::RaceLost
    );
}

#[tokio::test]
async fn rejection_of_a_block_zebra_does_not_have_is_invalid() {
    assert_eq!(
        classify_with(Some(false)).await,
        SubmitRejectionClass::Invalid
    );
}

#[tokio::test]
async fn rejection_is_unknown_when_the_lookup_fails() {
    // Never guess. An unattributable rejection must not be silently counted as
    // a race loss, or a real outage hides inside the expected-noise bucket.
    assert_eq!(classify_with(None).await, SubmitRejectionClass::Unknown);
}

#[test]
fn rejection_class_strings_are_stable() {
    // These become Prometheus label values; renaming one silently breaks alerts.
    assert_eq!(SubmitRejectionClass::RaceLost.as_str(), "race_lost");
    assert_eq!(SubmitRejectionClass::Invalid.as_str(), "invalid");
    assert_eq!(SubmitRejectionClass::Unknown.as_str(), "unknown");
}

// --- every submit path classifies its rejections -------------------------
//
// Rejection classification was added in #88 but wired into only ONE of the five
// places that call submit_block. The raw-segment path -- which carries almost
// all traffic -- was not among them, so on 2026-09-03 the fleet showed 119
// rejections, every single one labelled `unknown`, with race_lost and invalid
// both at zero. The labels existed and classified nothing.

#[test]
fn no_submit_path_classifies_by_hand() {
    // A per-call-site classification is what let four of five paths be missed.
    // Every site must go through the one shared helper.
    let src = include_str!("../src/submit.rs");

    assert!(
        !src.contains("classify_submitblock_result(result)?"),
        "a submit path is classifying without the block_known lookup"
    );
    assert_eq!(
        src.matches("classify_submitblock_outcome(result, submitter")
            .count(),
        5,
        "expected all five submit_block call sites to use the shared classifier"
    );
}

#[tokio::test]
async fn the_raw_block_path_classifies_a_rejection() {
    // The path that carries the traffic, and the one that was missed.
    let submitter = ClassifyingSubmitter { known: Some(true) };
    let raw = raw_block();

    let err = handle_relay_raw_block(&submitter, &raw, None, SubmitBlockMode::Live)
        .await
        .unwrap_err();

    match err {
        RelayBlockError::SubmitRejected(_, class) => {
            assert_eq!(class, SubmitRejectionClass::RaceLost);
        }
        other => panic!("expected SubmitRejected, got {other:?}"),
    }
}
