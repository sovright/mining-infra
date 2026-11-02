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
//!   far-future block is wasteful and noisy. `tip` is polled and can lag the
//!   node, so when the candidate's own parent lookup reports the node's tip
//!   (see [`CandidateMeta::observed_tip`]), the window uses the higher of the
//!   two.
//! - **Hash dedup** — confirm we have not already submitted this exact block
//!   hash within the dedup window. Two reassembly paths can produce the same
//!   block in close succession; the first wins.
//!
//! All four decisions are independent and emit distinct rejection variants
//! so metrics can attribute the cause precisely.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

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
    /// Unverified attempts per block in a dedup window. Default 4.
    pub unreadable_attempts_per_block: usize,
    /// #130 competing-body gate. Default false, which keeps the legacy gate exactly:
    /// the dedup mark is written when a candidate passes, and the gate lock is held
    /// across the Zebra call. When true, only Zebra's answer closes a block (so a body
    /// Zebra refuses cannot hide the real one), the lock is released for the Zebra
    /// call, and the limits below apply. The bound raw path turns this on.
    pub competing_bodies: bool,
    /// With `competing_bodies`: different bodies of one block that may get a definitive
    /// answer from Zebra in a dedup window, counting those at Zebra now. Repeats of a
    /// body and calls that failed in transit are not counted.
    pub strict_bodies_per_block: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_below: 3,
            dedup_window: Duration::from_secs(300),
            dedup_capacity: 256,
            unreadable_attempts_per_block: DEFAULT_UNREADABLE_ATTEMPTS_PER_BLOCK,
            competing_bodies: false,
            strict_bodies_per_block: DEFAULT_STRICT_BODIES_PER_BLOCK,
        }
    }
}

/// How many unverified candidates one block can send to Zebra in a dedup window by
/// default. Each holds the gate through a Zebra call, so there has to be a limit. Four
/// leaves room for the real body behind three others or a few failed calls. Anyone
/// holding a real header can still use all of it.
pub const DEFAULT_UNREADABLE_ATTEMPTS_PER_BLOCK: usize = 4;

/// Different bodies of one block the competing-body gate sends Zebra in a dedup window.
/// Only distinct bodies that got an answer count: a resent body Zebra refused is turned
/// away without a call, an accepted one closes the block, and a call that failed in
/// transit gives its place back. A body that passes the strict reader matches the
/// header's Merkle root, so a second such body is rare; four leaves room for the real
/// one behind a few that Zebra refuses. Research value for #130, not a decided setting.
pub const DEFAULT_STRICT_BODIES_PER_BLOCK: usize = 4;

/// Why the gate rejected a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Header failed integrity check between candidate construction and gate.
    HeaderMutated,
    /// Parent block is not known locally.
    UnknownParent,
    /// Block height is outside the configured window.
    OutOfHeightWindow,
    /// Zebra has this block by what it said within the dedup window, or these same bytes
    /// are with it now.
    DuplicateSubmit,
    /// This block has used up its unverified attempts for the dedup window.
    UnverifiedLimit,
    /// This block has used up its bodies for the dedup window.
    StrictLimit,
    /// Zebra refused these exact bytes for this block within the dedup window.
    RefusedBody,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::HeaderMutated => "header_mutated",
            RejectReason::UnknownParent => "unknown_parent",
            RejectReason::OutOfHeightWindow => "out_of_height_window",
            RejectReason::DuplicateSubmit => "duplicate_submit",
            RejectReason::UnverifiedLimit => "unverified_limit",
            RejectReason::StrictLimit => "strict_limit",
            RejectReason::RefusedBody => "refused_body",
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

    fn count(&mut self, hash: &str, now: Instant) -> usize {
        self.evict_expired(now);
        self.entries.iter().filter(|(h, _)| h == hash).count()
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

/// Exact bodies waiting on Zebra without the gate lock, with the block each is for and
/// whether the strict reader passed it.
type UnverifiedBodies = Arc<Mutex<HashMap<[u8; 32], InFlight>>>;

#[derive(Debug, Clone)]
struct InFlight {
    block_hash: String,
    strict: bool,
}

/// One body at Zebra. The gate lock is not held through that call, so this
/// keeps a concurrent copy of the same bytes out instead. Ending it any way, by an
/// answer, an error, a timeout or cancellation, lets the next copy try.
pub struct UnverifiedSlot {
    in_flight: UnverifiedBodies,
    /// `None` for a slot that holds nothing at Zebra, such as a dry run's.
    body: Option<[u8; 32]>,
}

impl Drop for UnverifiedSlot {
    fn drop(&mut self) {
        let Some(body) = self.body else {
            return;
        };
        // This can run while unwinding, so a poisoned lock must not panic here.
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&body);
    }
}

/// What Zebra said of a body the competing-body gate reserved, for
/// [`SubmitGate::record_strict_answer_now`]. A call that failed in transit, timed out
/// or was cancelled is not an answer, and records nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictAnswer {
    /// Zebra has the block: it took this body, already had the block, or refused this
    /// copy and turned out to have it.
    Known,
    /// Zebra refused these bytes and does not have the block, or could not say.
    Refused,
    /// Zebra answered without taking or refusing the block, such as `inconclusive`.
    Undecided,
}

/// The gate. Apply to a candidate before invoking `submit_block`.
pub struct SubmitGate<V: ChainView> {
    config: GateConfig,
    chain: V,
    dedup: DedupRing,
    unverified_attempts: DedupRing,
    unverified_in_flight: UnverifiedBodies,
    /// Competing-body gate: dry runs' own marks, by block and body, which a live run
    /// never reads.
    dry_seen: DedupRing,
    /// Competing-body gate: one entry per distinct body that got an answer, by block.
    strict_bodies: DedupRing,
    /// Competing-body gate: the same bodies, by block and body.
    strict_answered: DedupRing,
    /// Competing-body gate: bodies Zebra refused, by block and body.
    strict_refused: DedupRing,
}

impl<V: ChainView> SubmitGate<V> {
    /// `config.dedup_capacity` must be at least 1; config loading rejects 0, and a gate
    /// built from 0 here keeps one entry rather than none.
    pub fn new(config: GateConfig, chain: V) -> Self {
        let capacity = config.dedup_capacity.max(1);
        let ring = || DedupRing::new(capacity, config.dedup_window);
        Self {
            dedup: ring(),
            unverified_attempts: ring(),
            unverified_in_flight: UnverifiedBodies::default(),
            dry_seen: ring(),
            strict_bodies: ring(),
            strict_answered: ring(),
            strict_refused: ring(),
            config,
            chain,
        }
    }

    /// Whether this gate runs the #130 competing-body rules. Callers pick the submit
    /// path from this: the legacy one holds the gate across the Zebra call.
    pub fn competing_bodies(&self) -> bool {
        self.config.competing_bodies
    }

    /// Evaluate a candidate against the gate. The metadata is everything the
    /// gate needs that is not directly on `SubmissionCandidate` (parent hash,
    /// block height, header-bytes for PoW recheck).
    ///
    /// On the legacy gate an accepted candidate is recorded here, so the first copy
    /// wins. On the competing-body gate this records nothing: only Zebra can say a body
    /// is the block, so only [`Self::record_strict_answer_now`] closes it.
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
        if let Some(reason) = self.chain_rejection(candidate, meta) {
            return GateDecision::Reject(reason);
        }

        // (4) Hash dedup. The legacy gate records on accept.
        if self.dedup.contains(&candidate.block_hash, now) {
            return GateDecision::Reject(RejectReason::DuplicateSubmit);
        }
        if !self.config.competing_bodies {
            self.dedup.record(candidate.block_hash.clone(), now);
        }

        // Only accepted candidates are logged, so each line is a block the
        // polled window alone would have rejected.
        let polled_tip = self.chain.tip_height();
        if meta.height > polled_tip.saturating_add(1) {
            tracing::info!(
                consensus_block_hash = %candidate.consensus_block_hash,
                height = meta.height,
                polled_tip,
                observed_tip = ?meta.observed_tip,
                parent_confirmations = ?meta.parent_confirmations,
                "submit gate: upper bound passed on parent best-chain evidence"
            );
        }
        GateDecision::Accept
    }

    /// The competing-body gate's [`Self::apply_at`] for a candidate the strict reader
    /// passed, reserving its place at Zebra. The caller lets go of the gate for the
    /// Zebra call and reports the answer with [`Self::record_strict_answer_now`]. A
    /// different body of the block may run alongside this one, and the same bytes wait
    /// for this answer.
    ///
    /// A dry run has no answer, so it reads and writes only its own marks, by block and
    /// body: it never closes a block for a live run, and never spends a live budget.
    pub fn reserve_strict_now(
        &mut self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
        dry_run: bool,
    ) -> Result<UnverifiedSlot, RejectReason> {
        self.reserve_strict_at(candidate, meta, dry_run, Instant::now())
    }

    pub fn reserve_strict_at(
        &mut self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
        dry_run: bool,
        now: Instant,
    ) -> Result<UnverifiedSlot, RejectReason> {
        debug_assert!(
            self.config.competing_bodies,
            "the legacy gate has no strict reservation"
        );
        if let GateDecision::Reject(reason) = self.apply_at(candidate, meta, now) {
            return Err(reason);
        }
        let hash = &candidate.block_hash;
        let body = body_digest(candidate);
        let key = body_key(hash, &body);
        if dry_run {
            if self.config.enabled {
                if self.dry_seen.contains(&key, now) {
                    return Err(RejectReason::DuplicateSubmit);
                }
                self.dry_seen.record(key, now);
            }
            return Ok(UnverifiedSlot {
                in_flight: Arc::clone(&self.unverified_in_flight),
                body: None,
            });
        }
        if self.config.enabled && self.strict_refused.contains(&key, now) {
            return Err(RejectReason::RefusedBody);
        }
        let mut in_flight = self
            .unverified_in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if in_flight.contains_key(&body) {
            return Err(RejectReason::DuplicateSubmit);
        }
        if self.config.enabled && !self.strict_answered.contains(&key, now) {
            let at_zebra = in_flight
                .values()
                .filter(|entry| entry.strict && entry.block_hash == *hash)
                .count();
            let answered = self.strict_bodies.count(hash, now);
            if answered + at_zebra >= self.config.strict_bodies_per_block {
                return Err(RejectReason::StrictLimit);
            }
        }
        in_flight.insert(
            body,
            InFlight {
                block_hash: hash.clone(),
                strict: true,
            },
        );
        Ok(UnverifiedSlot {
            in_flight: Arc::clone(&self.unverified_in_flight),
            body: Some(body),
        })
    }

    /// Record what Zebra said of a body reserved by [`Self::reserve_strict_now`]. Call
    /// it before dropping the slot, so a copy of the same bytes cannot slip in between.
    pub fn record_strict_answer_now(
        &mut self,
        candidate: &SubmissionCandidate,
        answer: StrictAnswer,
    ) {
        self.record_strict_answer_at(candidate, answer, Instant::now());
    }

    pub fn record_strict_answer_at(
        &mut self,
        candidate: &SubmissionCandidate,
        answer: StrictAnswer,
        now: Instant,
    ) {
        let hash = &candidate.block_hash;
        if answer == StrictAnswer::Known {
            self.dedup.record(hash.clone(), now);
            return;
        }
        let key = body_key(hash, &body_digest(candidate));
        if !self.strict_answered.contains(&key, now) {
            self.strict_answered.record(key.clone(), now);
            self.strict_bodies.record(hash.clone(), now);
        }
        if answer == StrictAnswer::Refused && !self.strict_refused.contains(&key, now) {
            self.strict_refused.record(key, now);
        }
    }

    /// Whether Zebra has said it has this block, within the dedup window. Only the
    /// competing-body gate can say: the legacy gate marks a block when a candidate
    /// passes, not when Zebra has it, so it always answers `false`.
    pub fn knows(&mut self, block_hash: &str) -> bool {
        self.config.competing_bodies && self.dedup.contains(block_hash, Instant::now())
    }

    /// [`Self::apply_at`] for a candidate the strict reader could not read. Only
    /// Zebra can say whether this body is the block, so this reserves an attempt and
    /// records nothing: a forged body must not hide the real one. The caller then lets
    /// go of the gate for the Zebra call, and calls [`Self::record_submitted_now`] if
    /// Zebra has the block. A different body of the same block may run alongside this
    /// one, since it may be the real one; the same bytes wait for this answer.
    pub fn reserve_unverified_now(
        &mut self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
    ) -> Result<UnverifiedSlot, RejectReason> {
        self.reserve_unverified_at(candidate, meta, Instant::now())
    }

    pub fn reserve_unverified_at(
        &mut self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
        now: Instant,
    ) -> Result<UnverifiedSlot, RejectReason> {
        if self.config.enabled {
            if let Some(reason) = self.chain_rejection(candidate, meta) {
                return Err(reason);
            }
            if self.dedup.contains(&candidate.block_hash, now) {
                return Err(RejectReason::DuplicateSubmit);
            }
        }
        let body: [u8; 32] = Sha256::digest(candidate.block_hex.as_bytes()).into();
        let mut in_flight = self
            .unverified_in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if in_flight.contains_key(&body) {
            return Err(RejectReason::DuplicateSubmit);
        }
        if self.config.enabled {
            let attempts = self.unverified_attempts.count(&candidate.block_hash, now);
            if attempts >= self.config.unreadable_attempts_per_block {
                return Err(RejectReason::UnverifiedLimit);
            }
            self.unverified_attempts
                .record(candidate.block_hash.clone(), now);
        }
        in_flight.insert(
            body,
            InFlight {
                block_hash: candidate.block_hash.clone(),
                strict: false,
            },
        );
        Ok(UnverifiedSlot {
            in_flight: Arc::clone(&self.unverified_in_flight),
            body: Some(body),
        })
    }

    /// Zebra took this block or already had it, so later copies are duplicates.
    pub fn record_submitted_now(&mut self, candidate: &SubmissionCandidate) {
        self.record_submitted_at(candidate, Instant::now());
    }

    pub fn record_submitted_at(&mut self, candidate: &SubmissionCandidate, now: Instant) {
        self.dedup.record(candidate.block_hash.clone(), now);
    }

    fn chain_rejection(
        &self,
        candidate: &SubmissionCandidate,
        meta: &CandidateMeta,
    ) -> Option<RejectReason> {
        // (1) Header mutation — the candidate's header must still hash to the
        //     block hash recorded at construction. This is a mutation guard, not
        //     a PoW check; PoW is verified in the transport before the block
        //     enters the mesh.
        if !meta.header_hash_matches(&candidate.block_hash) {
            return Some(RejectReason::HeaderMutated);
        }

        // (2) Parent-known
        if !self.chain.parent_known(&meta.parent_hash) {
            return Some(RejectReason::UnknownParent);
        }

        // (3) Height window. The tip is polled and can lag behind the node,
        //     for longer while the poll's RPC is failing. When the candidate's
        //     parent lookup reported the node's tip at that read, both bounds
        //     use the higher of the two; a polled tip that is higher (say,
        //     stale after a reorg that lowered the height) keeps its window.
        let polled_tip = self.chain.tip_height();
        let tip = meta
            .observed_tip
            .map_or(polled_tip, |observed| observed.max(polled_tip));
        let lower = tip.saturating_sub(self.config.allowed_below);
        let upper = tip.saturating_add(1);
        if meta.height < lower || meta.height > upper {
            return Some(RejectReason::OutOfHeightWindow);
        }
        None
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
    /// The node's tip at the candidate's own parent lookup:
    /// `parent height + confirmations - 1`, when that lookup placed the parent
    /// on the node's best chain (`confirmations >= 1`). `None` otherwise. The
    /// gate's window uses the higher of this and the polled tip.
    pub observed_tip: Option<u64>,
    /// `confirmations` from the same lookup, kept for the gate's log.
    pub parent_confirmations: Option<i64>,
}

/// What the local node reported about a candidate's parent, from the
/// `getblockheader` lookup made for that candidate.
///
/// By convention production code gets one only from
/// `ZebraChainView::observe_parent`, which has already checked that the
/// response is for `parent_hash`; the fields are public so tests can build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentObservation {
    /// The parent hash that was queried, in header byte order.
    pub parent_hash: [u8; 32],
    /// The parent's height, from the same response.
    pub height: u64,
    /// `confirmations` from the same response: `depth + 1` on the best chain,
    /// `-1` off it, `None` if the node did not report it.
    pub confirmations: Option<i64>,
}

/// Why a `CandidateMeta` could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateMetaError {
    /// The header is shorter than its parent-hash field.
    HeaderTooShort,
    /// The parent height has no successor.
    ParentHeightOverflow,
    /// The observation was made for a different parent than the header's.
    ObservationForOtherParent,
    /// `parent height + confirmations - 1` does not fit: the lookup cannot be
    /// turned into a tip, and the polled tip is not a safe stand-in for it.
    ObservedTipOverflow,
}

impl CandidateMetaError {
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateMetaError::HeaderTooShort => "header too short",
            CandidateMetaError::ParentHeightOverflow => "parent height overflow",
            CandidateMetaError::ObservationForOtherParent => {
                "parent observation is for a different parent"
            }
            CandidateMetaError::ObservedTipOverflow => "observed tip overflow",
        }
    }
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

    /// Build a `CandidateMeta` from a serialized header, the candidate block
    /// hash hex, and the lookup of the header's parent
    /// (`ZebraChainView::observe_candidate_parent`).
    ///
    /// The candidate height is the observed parent height + 1. Without an
    /// observation (the lookup failed or the parent is unknown) the parent
    /// height is taken as 0, as before, so the gate rejects the candidate.
    /// The observed tip comes from the same observation, and only when it
    /// placed the parent on the best chain; missing, zero or negative
    /// confirmations leave the gate on the polled tip.
    pub fn from_header_bytes(
        header: &[u8],
        block_hash_hex: String,
        parent: Option<&ParentObservation>,
    ) -> Result<Self, CandidateMetaError> {
        let parent_hash =
            Self::parent_hash_from_header(header).ok_or(CandidateMetaError::HeaderTooShort)?;
        let (parent_height, parent_confirmations) = match parent {
            Some(observed) if observed.parent_hash != parent_hash => {
                return Err(CandidateMetaError::ObservationForOtherParent);
            }
            Some(observed) => (observed.height, observed.confirmations),
            None => (0, None),
        };
        // Candidate height is parent height + 1, the standard linkage.
        let height = parent_height
            .checked_add(1)
            .ok_or(CandidateMetaError::ParentHeightOverflow)?;
        let observed_tip = match parent_confirmations {
            Some(confirmations) if confirmations >= 1 => Some(
                u64::try_from(confirmations - 1)
                    .ok()
                    .and_then(|depth| parent_height.checked_add(depth))
                    .ok_or(CandidateMetaError::ObservedTipOverflow)?,
            ),
            _ => None,
        };
        Ok(Self {
            height,
            parent_hash,
            block_hash_hex,
            observed_tip,
            parent_confirmations,
        })
    }
}

/// A candidate's exact bytes, for telling copies of a block apart.
fn body_digest(candidate: &SubmissionCandidate) -> [u8; 32] {
    Sha256::digest(candidate.block_hex.as_bytes()).into()
}

fn body_key(block_hash: &str, body: &[u8; 32]) -> String {
    format!("{block_hash}:{}", hex::encode(body))
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

    /// An attempt counts whatever Zebra answered, and ends with the dedup window.
    #[test]
    fn unverified_attempts_refresh_when_the_window_ends_and_not_before() {
        let window = Duration::from_secs(300);
        let mut gate = SubmitGate::new(
            GateConfig {
                dedup_window: window,
                unreadable_attempts_per_block: 2,
                ..enabled_config()
            },
            chain(100, vec![[1u8; 32]]),
        );
        let candidate = candidate("aa");
        let meta = meta(100, [1u8; 32], "aa");
        let start = Instant::now();
        assert!(gate.reserve_unverified_at(&candidate, &meta, start).is_ok());
        assert!(gate.reserve_unverified_at(&candidate, &meta, start).is_ok());

        assert_eq!(
            gate.reserve_unverified_at(&candidate, &meta, start + window)
                .err(),
            Some(RejectReason::UnverifiedLimit)
        );
        let later = start + window + Duration::from_millis(1);
        assert!(gate.reserve_unverified_at(&candidate, &meta, later).is_ok());
    }

    fn candidate(hash: &str) -> SubmissionCandidate {
        SubmissionCandidate {
            block_hash: hash.to_string(),
            consensus_block_hash: hash.to_string(),
            unverified: None,
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
            observed_tip: None,
            parent_confirmations: None,
        }
    }

    fn header_with_parent(parent: [u8; 32]) -> Vec<u8> {
        let mut header = vec![0u8; 140];
        header[4..36].copy_from_slice(&parent);
        header
    }

    fn observed(parent: [u8; 32], height: u64, confirmations: Option<i64>) -> ParentObservation {
        ParentObservation {
            parent_hash: parent,
            height,
            confirmations,
        }
    }

    /// A candidate at `height` whose parent lookup reported `confirmations`,
    /// built the way production builds it.
    fn meta_with_parent_confirmations(
        height: u64,
        parent: [u8; 32],
        hash: &str,
        confirmations: i64,
    ) -> CandidateMeta {
        CandidateMeta::from_header_bytes(
            &header_with_parent(parent),
            hash.to_string(),
            Some(&observed(parent, height - 1, Some(confirmations))),
        )
        .unwrap()
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
            unreadable_attempts_per_block: DEFAULT_UNREADABLE_ATTEMPTS_PER_BLOCK,
            competing_bodies: false,
            strict_bodies_per_block: DEFAULT_STRICT_BODIES_PER_BLOCK,
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

    /// The polled tip still says 1000 after the node accepted 1001; the next
    /// block, 1002, has a parent the node reported at its tip.
    #[test]
    fn stale_polled_tip_accepts_next_block_with_best_chain_parent() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("1a");
        assert_eq!(
            g.apply_now(&c, &meta_with_parent_confirmations(1002, parent, "1a", 1)),
            GateDecision::Accept,
        );
    }

    #[test]
    fn stale_polled_tip_rejects_next_block_without_evidence() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("1b");
        assert_eq!(
            g.apply_now(&c, &meta(1002, parent, "1b")),
            GateDecision::Reject(RejectReason::OutOfHeightWindow),
        );
    }

    /// The polled tip is stuck at 1000 while Zebra is at 1200: a parent at
    /// 1100 with 101 confirmations makes 1101 a 100-deep fork child. Against
    /// Zebra's tip the window is [1197, 1201].
    #[test]
    fn deep_fork_child_is_rejected_against_the_observed_tip() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("2a");
        assert_eq!(
            g.apply_now(&c, &meta_with_parent_confirmations(1101, parent, "2a", 101)),
            GateDecision::Reject(RejectReason::OutOfHeightWindow),
        );
    }

    /// Confirmations 5 put the observed tip at 1104: the window is
    /// [1101, 1105] and 1101 sits on its lower bound.
    #[test]
    fn candidate_at_the_observed_lower_bound_is_accepted() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("2b");
        assert_eq!(
            g.apply_now(&c, &meta_with_parent_confirmations(1101, parent, "2b", 5)),
            GateDecision::Accept,
        );
    }

    /// Confirmations 6: the window is [1102, 1106], one above 1101.
    #[test]
    fn candidate_one_below_the_observed_lower_bound_is_rejected() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("2c");
        assert_eq!(
            g.apply_now(&c, &meta_with_parent_confirmations(1101, parent, "2c", 6)),
            GateDecision::Reject(RejectReason::OutOfHeightWindow),
        );
    }

    #[test]
    fn best_chain_evidence_does_not_relax_lower_bound() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("1c");
        // Parent 990 with confirmations 11: the observed tip is 1000, and
        // candidate 991 is below the window [997, 1001].
        assert_eq!(
            g.apply_now(&c, &meta_with_parent_confirmations(991, parent, "1c", 11)),
            GateDecision::Reject(RejectReason::OutOfHeightWindow),
        );
    }

    /// The polled tip (1000) is above the observed tip (995), as after a reorg
    /// that lowered the height. The higher, polled tip keeps the window, so
    /// 996 is rejected as before; this is a known limit.
    #[test]
    fn higher_polled_tip_keeps_its_window() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("2d");
        assert_eq!(
            g.apply_now(&c, &meta_with_parent_confirmations(996, parent, "2d", 1)),
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

    /// The competing-body gate records nothing on accept: only Zebra's answer that it
    /// has the block closes it.
    #[test]
    fn competing_gate_dedups_only_what_zebra_has() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(competing_config(), chain(1000, vec![parent]));
        let c = candidate("ff");
        let m = meta(1001, parent, "ff");
        let t0 = Instant::now();
        assert_eq!(g.apply_at(&c, &m, t0), GateDecision::Accept);
        assert_eq!(
            g.apply_at(&c, &m, t0 + Duration::from_secs(5)),
            GateDecision::Accept,
            "nothing is recorded until Zebra has answered"
        );
        assert!(!g.knows(&c.block_hash));
        g.record_strict_answer_at(&c, StrictAnswer::Known, t0);
        assert!(g.knows(&c.block_hash));
        assert_eq!(
            g.apply_at(&c, &m, t0 + Duration::from_secs(10)),
            GateDecision::Reject(RejectReason::DuplicateSubmit),
        );
    }

    /// The legacy gate's mark is made on accept, not by Zebra, so it never claims Zebra
    /// has a block.
    #[test]
    fn the_legacy_gate_never_says_zebra_has_a_block() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(enabled_config(), chain(1000, vec![parent]));
        let c = candidate("ff");
        assert_eq!(
            g.apply_at(&c, &meta(1001, parent, "ff"), Instant::now()),
            GateDecision::Accept
        );
        assert!(!g.knows(&c.block_hash));
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
        let mut parent = [0u8; 32];
        for (i, b) in parent.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let header = header_with_parent(parent);
        let meta = CandidateMeta::from_header_bytes(
            &header,
            "abc".into(),
            Some(&observed(parent, 100, Some(1))),
        )
        .expect("well-formed");
        assert_eq!(meta.height, 101);
        assert_eq!(meta.parent_hash[0], 1);
        assert_eq!(meta.parent_hash[31], 32);
        assert_eq!(meta.block_hash_hex, "abc");
        assert_eq!(meta.observed_tip, Some(100));
        assert_eq!(meta.parent_confirmations, Some(1));
    }

    #[test]
    fn from_header_bytes_without_observation_keeps_height_one() {
        let header = header_with_parent([5u8; 32]);
        let meta = CandidateMeta::from_header_bytes(&header, "ab".into(), None).unwrap();
        assert_eq!(meta.height, 1);
        assert_eq!(meta.observed_tip, None);
    }

    #[test]
    fn from_header_bytes_refuses_observation_for_other_parent() {
        let header = header_with_parent([5u8; 32]);
        assert_eq!(
            CandidateMeta::from_header_bytes(
                &header,
                "ab".into(),
                Some(&observed([6u8; 32], 100, Some(1))),
            )
            .unwrap_err(),
            CandidateMetaError::ObservationForOtherParent,
        );
    }

    #[test]
    fn from_header_bytes_rejects_parent_height_overflow() {
        let parent = [5u8; 32];
        assert_eq!(
            CandidateMeta::from_header_bytes(
                &header_with_parent(parent),
                "ff".into(),
                Some(&observed(parent, u64::MAX, Some(1))),
            )
            .unwrap_err(),
            CandidateMetaError::ParentHeightOverflow,
            "u64::MAX parent height has no successor",
        );
    }

    #[test]
    fn from_header_bytes_rejects_short_header() {
        assert_eq!(
            CandidateMeta::from_header_bytes(&[0u8; 35], "ff".into(), None).unwrap_err(),
            CandidateMetaError::HeaderTooShort,
        );
    }

    /// Only a lookup that placed the parent on the best chain gives a tip;
    /// anything else leaves the gate on the polled tip.
    #[test]
    fn only_positive_confirmations_give_an_observed_tip() {
        let parent = [5u8; 32];
        for (confirmations, expected) in [
            (Some(1), Some(100)),
            (Some(11), Some(110)),
            (Some(0), None),
            (Some(-1), None),
            (None, None),
        ] {
            let meta = CandidateMeta::from_header_bytes(
                &header_with_parent(parent),
                "ab".into(),
                Some(&observed(parent, 100, confirmations)),
            )
            .unwrap();
            assert_eq!(meta.observed_tip, expected, "{confirmations:?}");
        }
    }

    /// A tip that cannot be computed is not replaced by the polled one: the
    /// candidate's metadata is refused.
    #[test]
    fn from_header_bytes_refuses_an_observed_tip_that_overflows() {
        let parent = [5u8; 32];
        assert_eq!(
            CandidateMeta::from_header_bytes(
                &header_with_parent(parent),
                "ff".into(),
                Some(&observed(parent, u64::MAX - 1, Some(3))),
            )
            .unwrap_err(),
            CandidateMetaError::ObservedTipOverflow,
        );
    }

    fn competing_config() -> GateConfig {
        GateConfig {
            competing_bodies: true,
            ..enabled_config()
        }
    }

    fn body_of(mark: usize) -> SubmissionCandidate {
        SubmissionCandidate {
            block_hex: format!("{mark:02x}"),
            ..candidate("cc")
        }
    }

    /// Review item 1 on #134: one body replayed past any count must not lock out the valid
    /// body. Zebra's refusal is remembered, so the replay never reaches Zebra again, and it
    /// spends one place, not one per copy.
    #[test]
    fn a_replayed_refused_body_spends_one_place_and_no_calls() {
        let parent = [7u8; 32];
        let config = competing_config();
        let mut g = SubmitGate::new(config.clone(), chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let (forged, real) = (body_of(1), body_of(2));
        let start = Instant::now();

        let slot = g.reserve_strict_at(&forged, &m, false, start).unwrap();
        g.record_strict_answer_at(&forged, StrictAnswer::Refused, start);
        drop(slot);
        for _ in 0..32 {
            assert_eq!(
                g.reserve_strict_at(&forged, &m, false, start).err(),
                Some(RejectReason::RefusedBody),
                "a refused body is turned away without a Zebra call"
            );
        }

        assert!(g.reserve_strict_at(&real, &m, false, start).is_ok());
    }

    /// Calls that fail in transit, time out or are cancelled are not answers, so they give
    /// their place back and the same bytes can try again, however many times.
    #[test]
    fn transient_failures_spend_nothing() {
        let parent = [7u8; 32];
        let config = competing_config();
        let mut g = SubmitGate::new(config.clone(), chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        for _ in 0..(4 * config.strict_bodies_per_block) {
            for mark in 0..config.strict_bodies_per_block {
                // Reserved, then dropped with no answer recorded.
                drop(
                    g.reserve_strict_at(&body_of(mark), &m, false, start)
                        .unwrap(),
                );
            }
        }
        let real = body_of(config.strict_bodies_per_block + 1);
        assert!(g.reserve_strict_at(&real, &m, false, start).is_ok());
    }

    /// A body already answered without a refusal costs nothing more when it comes again.
    #[test]
    fn a_repeat_of_an_answered_body_is_free() {
        let parent = [7u8; 32];
        let mut config = competing_config();
        config.strict_bodies_per_block = 1;
        let mut g = SubmitGate::new(config, chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        let body = body_of(1);
        for _ in 0..8 {
            let slot = g.reserve_strict_at(&body, &m, false, start).unwrap();
            g.record_strict_answer_at(&body, StrictAnswer::Undecided, start);
            drop(slot);
        }
        assert_eq!(
            g.reserve_strict_at(&body_of(2), &m, false, start).err(),
            Some(RejectReason::StrictLimit),
            "the one place is spent by the one body"
        );
    }

    /// The same bytes wait for the call at Zebra; a different body may run alongside.
    #[test]
    fn an_identical_copy_in_flight_waits_and_a_different_one_runs() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(competing_config(), chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        let slot = g.reserve_strict_at(&body_of(1), &m, false, start).unwrap();
        assert_eq!(
            g.reserve_strict_at(&body_of(1), &m, false, start).err(),
            Some(RejectReason::DuplicateSubmit)
        );
        assert!(g.reserve_strict_at(&body_of(2), &m, false, start).is_ok());
        drop(slot);
        assert!(g.reserve_strict_at(&body_of(1), &m, false, start).is_ok());
    }

    /// Distinct bodies at Zebra or answered count against the block, and come back with
    /// the window.
    #[test]
    fn a_spent_body_limit_ends_with_its_window() {
        let parent = [7u8; 32];
        let config = competing_config();
        let mut g = SubmitGate::new(config.clone(), chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        for mark in 0..config.strict_bodies_per_block {
            let slot = g
                .reserve_strict_at(&body_of(mark), &m, false, start)
                .unwrap();
            g.record_strict_answer_at(&body_of(mark), StrictAnswer::Refused, start);
            drop(slot);
        }
        let next = body_of(config.strict_bodies_per_block);
        assert_eq!(
            g.reserve_strict_at(&next, &m, false, start).err(),
            Some(RejectReason::StrictLimit)
        );

        let later = start + config.dedup_window + Duration::from_millis(1);
        assert!(g.reserve_strict_at(&next, &m, false, later).is_ok());
        assert!(
            g.reserve_strict_at(&body_of(0), &m, false, later).is_ok(),
            "a refusal is forgotten with its window"
        );
    }

    /// Bodies still at Zebra hold their places too.
    #[test]
    fn bodies_at_zebra_count_against_the_block() {
        let parent = [7u8; 32];
        let config = competing_config();
        let mut g = SubmitGate::new(config.clone(), chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        let slots: Vec<_> = (0..config.strict_bodies_per_block)
            .map(|mark| {
                g.reserve_strict_at(&body_of(mark), &m, false, start)
                    .unwrap()
            })
            .collect();
        let next = body_of(config.strict_bodies_per_block);
        assert_eq!(
            g.reserve_strict_at(&next, &m, false, start).err(),
            Some(RejectReason::StrictLimit)
        );
        drop(slots);
        assert!(g.reserve_strict_at(&next, &m, false, start).is_ok());
    }

    /// Review item 10 on #134: a dry run's marks are its own. A forged dry-run body does not
    /// make the real one a duplicate, and dry runs spend nothing a live run needs.
    #[test]
    fn dry_runs_are_isolated() {
        let parent = [7u8; 32];
        let mut config = competing_config();
        config.strict_bodies_per_block = 1;
        let mut g = SubmitGate::new(config, chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        let (forged, real) = (body_of(1), body_of(2));

        assert!(g.reserve_strict_at(&forged, &m, true, start).is_ok());
        assert_eq!(
            g.reserve_strict_at(&forged, &m, true, start).err(),
            Some(RejectReason::DuplicateSubmit),
            "the same dry-run body is seen once"
        );
        assert!(
            g.reserve_strict_at(&real, &m, true, start).is_ok(),
            "another body of the header is not a duplicate"
        );
        let slot = g.reserve_strict_at(&forged, &m, false, start);
        assert!(slot.is_ok(), "dry runs spend no live place");
        assert!(!g.knows(&forged.block_hash));
    }

    /// A dry run holds nothing at Zebra, so ending it cannot free a live copy's place.
    #[test]
    fn a_dry_run_slot_does_not_free_a_live_one() {
        let parent = [7u8; 32];
        let mut g = SubmitGate::new(competing_config(), chain(1000, vec![parent]));
        let m = meta(1001, parent, "cc");
        let start = Instant::now();
        let live = g.reserve_strict_at(&body_of(1), &m, false, start).unwrap();
        drop(g.reserve_strict_at(&body_of(1), &m, true, start).unwrap());
        assert_eq!(
            g.reserve_strict_at(&body_of(1), &m, false, start).err(),
            Some(RejectReason::DuplicateSubmit)
        );
        drop(live);
    }

    /// Review item 9 on #134: a capacity of 0 must not make a gate that remembers nothing.
    #[test]
    fn a_zero_dedup_capacity_still_remembers() {
        let parent = [7u8; 32];
        let mut cfg = enabled_config();
        cfg.dedup_capacity = 0;
        let mut g = SubmitGate::new(cfg, chain(1000, vec![parent]));
        let c = candidate("ff");
        let m = meta(1001, parent, "ff");
        let t0 = Instant::now();
        assert_eq!(g.apply_at(&c, &m, t0), GateDecision::Accept);
        assert_eq!(
            g.apply_at(&c, &m, t0),
            GateDecision::Reject(RejectReason::DuplicateSubmit)
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
