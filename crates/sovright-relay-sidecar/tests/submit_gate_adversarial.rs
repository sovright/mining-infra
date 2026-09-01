//! Adversarial fixtures for the submit safety gate.
//!
//! Drives the gate against intentionally malformed or stale candidates to
//! prove the gate's per-cause rejection logic catches everything we care
//! about. Sister to `submit_path.rs` (which covers the happy paths and the
//! benign rejection variants); this file targets the failure modes the
//! Phase 3 cutover plan calls out by name:
//!
//! 1. Block with invalid PoW (mutated nonce → candidate hash diverges from
//!    the `CandidateMeta.block_hash_hex`).
//! 2. Block whose parent is unknown to our local zebra.
//! 3. Block above the height window (would-be reorg from far above tip).
//! 4. Block below the height window (stale fork attempt).
//! 5. Block already submitted within the dedup window.
//! 6. Block at u64::MAX parent height (cannot compute height = parent + 1).
//!
//! Each fixture passes if the gate produces the exact expected
//! `RejectReason`. Any false negative (gate accepts a block from this suite)
//! is a Phase 3 blocker — the staging service is allowed to ship only after
//! every fixture rejects with the right reason.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sovright_relay::{CompactBlock, PrefilledTx, ShortId};
use sovright_relay_sidecar::submit::{
    SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitFuture,
    handle_relay_compact_block_with_gate,
};
use sovright_relay_sidecar::submit_gate::{
    CandidateMeta, ChainView, GateConfig, RejectReason, SubmitGate,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A submitter that records every call and never errors. Used to assert
/// that gate-rejected paths NEVER reach the upstream RPC.
struct NeverSubmitsSubmitter {
    calls: AtomicUsize,
}

impl NeverSubmitsSubmitter {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl SubmitBlock for NeverSubmitsSubmitter {
    fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(None) })
    }
}

struct ConfigurableChain {
    tip: u64,
    known_parent: Option<[u8; 32]>,
}

impl ChainView for ConfigurableChain {
    fn tip_height(&self) -> u64 {
        self.tip
    }
    fn parent_known(&self, parent_hash: &[u8; 32]) -> bool {
        match self.known_parent {
            Some(known) => &known == parent_hash,
            None => false,
        }
    }
}

fn header_bytes() -> Vec<u8> {
    // 1487 bytes matches the existing submit_path fixtures so the
    // candidate-build path is identical.
    vec![0xab; 1487]
}

fn header_bytes_with_parent(parent: [u8; 32]) -> Vec<u8> {
    let mut h = header_bytes();
    h[4..36].copy_from_slice(&parent);
    h
}

fn compact_one_prefilled(header: Vec<u8>) -> CompactBlock {
    CompactBlock::new(
        header,
        0,
        Vec::<ShortId>::new(),
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
        dedup_window: Duration::from_secs(60),
        dedup_capacity: 8,
    }
}

// ---------------------------------------------------------------------------
// 1. PoW recheck — mutated candidate hash
//
// The gate compares the candidate's reported block_hash against the meta's
// block_hash_hex. When they diverge (e.g. a mutated nonce post-construction),
// the gate must reject with HeaderMutated. This proves the gate catches
// candidates whose hash was tampered between construction and gate.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_header_mutation_rejects_mutated_candidate_hash() {
    let submitter = NeverSubmitsSubmitter::new();
    let parent = [7u8; 32];
    let compact = compact_one_prefilled(header_bytes_with_parent(parent));

    // The candidate hash diverges from what `from_header_bytes` would
    // compute. We construct CandidateMeta directly with a mismatched
    // block_hash_hex by intercepting the candidate produced by the gate
    // wrapper's internal extraction. The most natural way to do this in a
    // black-box test is to use the gate API directly.
    let candidate = sovright_relay_sidecar::submit::build_submission_candidate(&compact).unwrap();
    let meta = CandidateMeta {
        height: 101,
        parent_hash: parent,
        block_hash_hex: "different_hash_string".to_string(),
    };
    let chain = ConfigurableChain {
        tip: 100,
        known_parent: Some(parent),
    };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    let decision = gate.apply_now(&candidate, &meta);

    assert_eq!(
        decision,
        sovright_relay_sidecar::submit_gate::GateDecision::Reject(RejectReason::HeaderMutated),
        "mutated candidate hash must trip HeaderMutated",
    );
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// 2. Unknown parent
//
// The chain view does not know the parent hash. The gate must reject before
// any submit_block call. This is the most common false-positive risk during
// a reorg: a relay-delivered block whose parent we haven't yet received via
// our own P2P would be a leak signal upstream.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_unknown_parent_rejects_and_never_submits() {
    let submitter = NeverSubmitsSubmitter::new();
    let compact = compact_one_prefilled(header_bytes());
    let chain = ConfigurableChain {
        tip: 100,
        known_parent: None,
    };
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
        "unknown parent must trip UnknownParent",
    );
    assert_eq!(
        submitter.calls.load(Ordering::SeqCst),
        0,
        "gate-rejected blocks must never reach submitblock",
    );
}

// ---------------------------------------------------------------------------
// 3. Block above the height window — far future reorg attempt
//
// candidate_height = parent_height + 1. With parent_height = 1000 and tip =
// 100, the candidate is at height 1001, which is 901 blocks above the
// permitted upper bound (tip + 1 = 101). The gate must reject with
// OutOfHeightWindow.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_far_future_height_rejects() {
    let submitter = NeverSubmitsSubmitter::new();
    let parent = [3u8; 32];
    let compact = compact_one_prefilled(header_bytes_with_parent(parent));
    let chain = ConfigurableChain {
        tip: 100,
        known_parent: Some(parent),
    };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    // parent_height = 1000 → candidate_height = 1001, but tip = 100.
    let outcome = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::Live,
        &mut gate,
        1000,
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

// ---------------------------------------------------------------------------
// 4. Block below the height window — stale fork attempt
//
// The deepest reorg the gate tolerates is `allowed_below`. With
// allowed_below=3 and tip=1000, a candidate at height 996 (parent 995) is
// out of window by exactly one block.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_stale_fork_rejects() {
    let submitter = NeverSubmitsSubmitter::new();
    let parent = [3u8; 32];
    let compact = compact_one_prefilled(header_bytes_with_parent(parent));
    let chain = ConfigurableChain {
        tip: 1000,
        known_parent: Some(parent),
    };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    // tip=1000, allowed_below=3 → window [997, 1001].
    // parent_height=995 → candidate=996, one block below the window.
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

// ---------------------------------------------------------------------------
// 5. Duplicate submission within the dedup window
//
// Same compact block, two back-to-back gate calls. The first accepts and
// records; the second must reject with DuplicateSubmit.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_dedup_window_rejects_repeat() {
    let submitter = NeverSubmitsSubmitter::new();
    let parent = [3u8; 32];
    let compact = compact_one_prefilled(header_bytes_with_parent(parent));
    let chain = ConfigurableChain {
        tip: 100,
        known_parent: Some(parent),
    };
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
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// 6. Parent height overflow
//
// CandidateMeta::from_header_bytes returns None when parent_height = u64::MAX
// because the candidate height (parent + 1) would overflow. The wrapper
// surfaces this as a ReconstructionInvalid error so the staging service can
// log + count without thinking it's a successful submission.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_parent_height_max_returns_reconstruction_invalid() {
    let submitter = NeverSubmitsSubmitter::new();
    let parent = [3u8; 32];
    let compact = compact_one_prefilled(header_bytes_with_parent(parent));
    let chain = ConfigurableChain {
        tip: u64::MAX,
        known_parent: Some(parent),
    };
    let mut gate = SubmitGate::new(enabled_gate_config(), chain);

    let result = handle_relay_compact_block_with_gate(
        &submitter,
        &compact,
        SubmitBlockMode::DryRun,
        &mut gate,
        u64::MAX,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(sovright_relay_sidecar::submit::RelayBlockError::ReconstructionInvalid { .. })
        ),
        "parent height = u64::MAX must surface ReconstructionInvalid, not a successful submission",
    );
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// 7. Disabled gate is a passthrough even for an adversarial input
//
// Sanity check: a disabled gate must accept everything, even an unknown
// parent. This is what makes shadow-mode safe: turning the gate off must
// never change observable submit_block behavior.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_disabled_gate_accepts_unknown_parent() {
    let submitter = NeverSubmitsSubmitter::new();
    let compact = compact_one_prefilled(header_bytes());
    let chain = ConfigurableChain {
        tip: 100,
        known_parent: None,
    };
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

    assert!(
        matches!(outcome, SubmissionOutcome::DryRun(_)),
        "disabled gate must accept even adversarial input",
    );
}
