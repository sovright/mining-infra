//! Safety gate for relay-received block submissions.
//!
//! Sits between `build_submission_candidate` and the live `submit_block` call.
//! The gate exists so that a relay-reassembled block — which arrived via a
//! third-party transport, not via the local Zcash P2P set — cannot reach the
//! upstream `submitblock` RPC unless it passes a series of cheap local checks.
//!
//! Today the sidecar gates submission only behind `enable_submitblock`. Once
//! that flag is on, every reassembled candidate is forwarded to the upstream
//! RPC. This module adds a per-candidate decision in front of that step so a
//! malformed, stale, or already-submitted block is rejected without hitting
//! the upstream node.
//!
//! The gate is intentionally cheap. The expensive validation (full block
//! verification, transaction script execution) is upstream's job — sending a
//! block to `submitblock` is what *triggers* that validation. The gate's
//! purpose is to skip submissions where we already know upstream will reject,
//! so we don't waste an upstream slot and so our metrics stay clean.
//!
//! Decisions:
//!
//! - **Header mutation** — confirm the candidate's header still hashes to the
//!   block hash recorded when it was built, i.e. nothing mutated it between
//!   construction and here. This was named `pow_recheck` and documented as
//!   re-verifying the Equihash solution and compact-target, but it never did
//!   either: the code is a hash comparison. Renamed 2026-09-01 to say what it
//!   is. Real proof-of-work — Equihash solution AND hash-to-target — is
//!   verified in `sovright-relay::transport::pow` before a block reaches the
//!   mesh, so it is not repeated here.
//! - **Parent-known** — confirm the parent block hash exists in our local
//!   zebra. If we don't have the parent, upstream will reject anyway, and
//!   forwarding the block tells an attacker we don't know about it.
//! - **Height window** — confirm the block height is within
//!   `tip - allowed_below ..= tip + 1`. Submitting an old reorg attempt or a
//!   far-future block is wasteful and noisy.
//! - **Hash dedup** — confirm we have not already submitted this exact block
//!   hash within the dedup window. Two reassembly paths can produce the same
//!   block in close succession; the first wins.
//!
//! All four decisions are independent and emit distinct rejection variants
//! so metrics can attribute the cause precisely.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::submit::SubmissionCandidate;

/// Local view of the chain that the gate needs in order to decide.
///
/// The gate consumes this through a small trait so tests can pass a mock and
/// production code can pass a thin wrapper around the existing `ZebraRpc`.
pub trait ChainView: Send + Sync {
    /// Current local tip height (best-known on the local zebra).
    fn tip_height(&self) -> u64;
    /// Whether the given block hash is known to the local zebra.
    fn parent_known(&self, parent_hash: &[u8; 32]) -> bool;
}

/// Configuration for the safety gate. Disabled gates short-circuit to accept.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Master switch. Default false. The gate must be explicitly enabled.
    pub enabled: bool,
    /// Allowed block heights below the local tip. Default 3.
    /// Reasonable values: 0 (only the next block), 3 (one-deep reorg
    /// tolerance), 6 (full short reorg tolerance).
    pub allowed_below: u64,
    /// Dedup window. Default 5 minutes.
    pub dedup_window: Duration,
    /// Maximum entries to retain in the dedup ring. Bounded so a flood does
    /// not exhaust memory. Default 256.
    pub dedup_capacity: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_below: 3,
            dedup_window: Duration::from_secs(300),
            dedup_capacity: 256,
        }
    }
}

/// Why the gate rejected a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Header failed integrity check between candidate construction and gate.
    HeaderMutated,
    /// Parent block is not known locally.
    UnknownParent,
    /// Block height is outside the configured window.
    OutOfHeightWindow,
    /// Block hash was already accepted by the gate within the dedup window.
    DuplicateSubmit,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::HeaderMutated => "header_mutated",
            RejectReason::UnknownParent => "unknown_parent",
            RejectReason::OutOfHeightWindow => "out_of_height_window",
            RejectReason::DuplicateSubmit => "duplicate_submit",
        }
    }
}

/// Decision returned by the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    Accept,
    Reject(RejectReason),
}

/// Bounded ring of recent submissions. Cheap to maintain, cheap to query.
#[derive(Debug)]
struct DedupRing {
    capacity: usize,
    window: Duration,
    entries: VecDeque<(String, Instant)>,
}

impl DedupRing {
    fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    fn contains(&mut self, hash: &str, now: Instant) -> bool {
        self.evict_expired(now);
        self.entries.iter().any(|(h, _)| h == hash)
    }

    fn record(&mut self, hash: String, now: Instant) {
        self.evict_expired(now);
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((hash, now));
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some((_, ts)) = self.entries.front() {
            if now.duration_since(*ts) > self.window {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

/// The gate. Apply to a candidate before invoking `submit_block`.
pub struct SubmitGate<V: ChainView> {
    config: GateConfig,
    chain: V,
    dedup: DedupRing,
}

impl<V: ChainView> SubmitGate<V> {
    pub fn new(config: GateConfig, chain: V) -> Self {
        let dedup = DedupRing::new(config.dedup_capacity, config.dedup_window);
        Self {
            config,
            chain,
            dedup,
        }
    }

    /// Evaluate a candidate against the gate. The metadata is everything the
    /// gate needs that is not directly on `SubmissionCandidate` (parent hash,
    /// block height, header-bytes for PoW recheck).
    ///
    /// Use `apply_now` in production. `apply_at` is for deterministic tests.
    pub fn apply_now(
        &mut self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
    ) -> GateDecision {
        self.apply_at(candidate, meta, Instant::now())
    }

    pub fn apply_at(
        &mut self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
        now: Instant,
    ) -> GateDecision {
        if !self.config.enabled {
            return GateDecision::Accept;
        }

        // (1) Header mutation — the candidate's header must still hash to the
        //     block hash recorded at construction. This is a mutation guard, not
        //     a PoW check; PoW is verified in the transport before the block
        //     enters the mesh.
        if !meta.header_hash_matches(&candidate.block_hash) {
            return GateDecision::Reject(RejectReason::HeaderMutated);
        }

        // (2) Parent-known
        if !self.chain.parent_known(&meta.parent_hash) {
            return GateDecision::Reject(RejectReason::UnknownParent);
        }

        // (3) Height window
        let tip = self.chain.tip_height();
        let lower = tip.saturating_sub(self.config.allowed_below);
        let upper = tip.saturating_add(1);
        if meta.height < lower || meta.height > upper {
            return GateDecision::Reject(RejectReason::OutOfHeightWindow);
        }

        // (4) Hash dedup — and record on accept
        if self.dedup.contains(&candidate.block_hash, now) {
            return GateDecision::Reject(RejectReason::DuplicateSubmit);
        }
        self.dedup.record(candidate.block_hash.clone(), now);

        GateDecision::Accept
    }
}

/// Auxiliary data the gate needs to evaluate a candidate.
///
/// The fields are split out from `SubmissionCandidate` so this module can
/// stay focused on the gate logic and not duplicate header parsing that lives
/// in `crate::compact` and `crate::submit`.
#[derive(Debug, Clone)]
pub struct CandidateMeta {
    /// Height of the candidate block.
    pub height: u64,
    /// Parent block hash (big-endian).
    pub parent_hash: [u8; 32],
    /// Hex-encoded block hash. Must equal `candidate.block_hash` after the
    /// candidate is constructed. Tracked separately so the gate can detect
    /// mutation.
    pub block_hash_hex: String,
}

impl CandidateMeta {
    fn header_hash_matches(&self, candidate_hash: &str) -> bool {
        self.block_hash_hex == candidate_hash
    }

    /// Extract the parent hash from a serialized Zcash block header.
    ///
    /// Zcash header layout (consensus byte order):
    ///   - `[0..4]`   version          (u32 LE)
    ///   - `[4..36]`  prev_hash        (32 bytes, internal byte order)
    ///   - `[36..68]` merkle_root      (32 bytes)
    ///   - `[68..100]` hash_block_commitments
    ///   - `[100..104]` time
    ///   - `[104..108]` bits
    ///   - `[108..140]` nonce
    ///   - `[140..]`  Equihash solution (variable length)
    ///
    /// Returns `None` if the header is shorter than the fixed pre-solution
    /// prefix (140 bytes).
    pub fn parent_hash_from_header(header: &[u8]) -> Option<[u8; 32]> {
        if header.len() < 36 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&header[4..36]);
        Some(out)
    }

    /// Build a `CandidateMeta` from a serialized header plus the candidate
    /// block hash hex plus the parent's height (resolved by the caller via
    /// `chain_view.get_block_header(parent_hash)` or pre-cached lookup).
    pub fn from_header_bytes(
        header: &[u8],
        block_hash_hex: String,
        parent_height: u64,
    ) -> Option<Self> {
        let parent_hash = Self::parent_hash_from_header(header)?;
        Some(Self {
            // Candidate height is parent height + 1, the standard linkage.
            height: parent_height.checked_add(1)?,
            parent_hash,
            block_hash_hex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChainStub {
        tip: u64,
        known_parents: Vec<[u8; 32]>,
    }

    impl ChainView for ChainStub {
        fn tip_height(&self) -> u64 {
            self.tip
        }
        fn parent_known(&self, parent_hash: &[u8; 32]) -> bool {
            self.known_parents.iter().any(|p| p == parent_hash)
        }
    }

    fn candidate(hash: &str) -> SubmissionCandidate {
        SubmissionCandidate {
            block_hash: hash.to_string(),
            consensus_block_hash: hash.to_string(),
            block_hex: "ff".to_string(),
            tx_count: 1,
            block_bytes: 1,
        }
    }

    fn meta(height: u64, parent: [u8; 32], hash: &str) -> CandidateMeta {
        CandidateMeta {
            height,
            parent_hash: parent,
            block_hash_hex: hash.to_string(),
        }
    }

    fn chain(tip: u64, parents: Vec<[u8; 32]>) -> ChainStub {
        ChainStub {
            tip,
            known_parents: parents,
        }
    }

    fn enabled_config() -> GateConfig {
        GateConfig {
            enabled: true,
            allowed_below: 3,
            dedup_window: Duration::from_secs(60),
            dedup_capacity: 8,
        }
    }

    #[test]
    fn disabled_gate_accepts_everything() {
        let mut g = SubmitGate::new(
            GateConfig {
                enabled: false,
                ..enabled_config()
            },
            chain(1000, vec![]),
        );
        let c = candidate("aa");
        let m = meta(2000, [1u8; 32], "aa");
        assert_eq!(g.apply_now(&c, &m), GateDecision::Accept);
    }

    #[test]
    fn accepts_well_formed_candidate() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("bb");
        let m = meta(1001, parent, "bb");
        assert_eq!(g.apply_now(&c, &m), GateDecision::Accept);
    }

    #[test]
    fn rejects_mutated_candidate() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("expected");
        let m = meta(1001, parent, "different");
        assert_eq!(
            g.apply_now(&c, &m),
            GateDecision::Reject(RejectReason::HeaderMutated),
        );
    }

    #[test]
    fn rejects_unknown_parent() {
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![]));
        let c = candidate("cc");
        let m = meta(1001, [9u8; 32], "cc");
        assert_eq!(
            g.apply_now(&c, &m),
            GateDecision::Reject(RejectReason::UnknownParent),
        );
    }

    #[test]
    fn rejects_too_low_height() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("dd");
        let m = meta(996, parent, "dd"); // tip - 4
        assert_eq!(
            g.apply_now(&c, &m),
            GateDecision::Reject(RejectReason::OutOfHeightWindow),
        );
    }

    #[test]
    fn rejects_far_future_height() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("ee");
        let m = meta(1002, parent, "ee");
        assert_eq!(
            g.apply_now(&c, &m),
            GateDecision::Reject(RejectReason::OutOfHeightWindow),
        );
    }

    #[test]
    fn dedups_same_hash_within_window() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("ff");
        let m = meta(1001, parent, "ff");
        let t0 = Instant::now();
        assert_eq!(g.apply_at(&c, &m, t0), GateDecision::Accept);
        assert_eq!(
            g.apply_at(&c, &m, t0 + Duration::from_secs(10)),
            GateDecision::Reject(RejectReason::DuplicateSubmit),
        );
    }

    #[test]
    fn dedup_expires_after_window() {
        let parent = [7u8; 32];
        let mut cfg = enabled_config();
        cfg.dedup_window = Duration::from_secs(30);
        let mut g = SubmitGate::new(cfg, chain(1000, vec![parent]));
        let c = candidate("0a");
        let m = meta(1001, parent, "0a");
        let t0 = Instant::now();
        assert_eq!(g.apply_at(&c, &m, t0), GateDecision::Accept);
        assert_eq!(
            g.apply_at(&c, &m, t0 + Duration::from_secs(31)),
            GateDecision::Accept,
        );
    }

    #[test]
    fn parent_hash_from_header_extracts_offset_4_to_36() {
        // Build a minimal header with a recognizable prev_hash.
        let mut header = vec![0u8; 140];
        // Version
        header[0..4].copy_from_slice(&4u32.to_le_bytes());
        // Parent (32 bytes of ascending values 1..=32)
        for i in 0..32 {
            header[4 + i] = (i + 1) as u8;
        }
        let parent = CandidateMeta::parent_hash_from_header(&header).expect("parent slice");
        for (i, b) in parent.iter().enumerate() {
            assert_eq!(*b, (i + 1) as u8);
        }
    }

    #[test]
    fn parent_hash_from_header_handles_short_header() {
        let header = vec![0u8; 10];
        assert!(CandidateMeta::parent_hash_from_header(&header).is_none());
    }

    #[test]
    fn from_header_bytes_constructs_meta_at_parent_plus_one() {
        let mut header = vec![0u8; 140];
        for i in 0..32 {
            header[4 + i] = (i + 1) as u8;
        }
        let meta =
            CandidateMeta::from_header_bytes(&header, "abc".into(), 100).expect("well-formed");
        assert_eq!(meta.height, 101);
        assert_eq!(meta.parent_hash[0], 1);
        assert_eq!(meta.parent_hash[31], 32);
        assert_eq!(meta.block_hash_hex, "abc");
    }

    #[test]
    fn from_header_bytes_rejects_parent_height_overflow() {
        let mut header = vec![0u8; 140];
        for i in 0..32 {
            header[4 + i] = (i + 1) as u8;
        }
        assert!(
            CandidateMeta::from_header_bytes(&header, "ff".into(), u64::MAX).is_none(),
            "u64::MAX parent height has no successor",
        );
    }

    #[test]
    fn dedup_capacity_bounds_memory() {
        let parent = [7u8; 32];
        let mut cfg = enabled_config();
        cfg.dedup_capacity = 2;
        let mut g = SubmitGate::new(cfg, chain(1000, vec![parent]));
        let t0 = Instant::now();
        for tag in ["a", "b", "c", "d"] {
            let c = candidate(tag);
            let m = meta(1001, parent, tag);
            assert_eq!(g.apply_at(&c, &m, t0), GateDecision::Accept);
        }
        // After three additions over a capacity-2 ring, the very first
        // entry must have been evicted and is accepted again.
        let first = candidate("a");
        let first_m = meta(1001, parent, "a");
        assert_eq!(g.apply_at(&first, &first_m, t0), GateDecision::Accept);
    }
}
