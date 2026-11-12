//! Guarded relay-block submission support.
//!
//! This module is intentionally conservative: compact blocks with missing
//! transaction data are not submit candidates, and dry-run mode never calls
//! Zebra `submitblock`.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sovright_relay::{
    BlockBodyError, BlockHash, CompactBlock, CompactBlockReconstructor, EquihashPowValidator,
    GetBlockTxn, MempoolProvider, PowResult, PowValidator, ReconstructionResult, ShortId, WtxId,
    ZCASH_FULL_HEADER_SIZE, consensus_block_hash_display, validate_block_body,
    validate_block_transactions, zcash_block_hash,
};

use crate::rpc::ZebraRpc;

/// Future returned by submitblock implementations.
pub type BlockKnownFuture<'a> = Pin<Box<dyn Future<Output = Option<bool>> + Send + 'a>>;

pub type SubmitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, Box<dyn Error + Send + Sync>>> + Send + 'a>>;

/// Minimal submitblock interface for testing and for the Zebra RPC client.
pub trait SubmitBlock {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a>;

    /// Does the node already have this block?
    ///
    /// Used only to classify a rejection. In a multi-relay mesh every sidecar
    /// races to submit the same block and the losers get a rejection back, so
    /// the rejection counter alone cannot distinguish "we lost the race" from
    /// "this block is invalid" -- and Zebra returns the same opaque
    /// `"rejected"` string for both (verified against 24h of production logs
    /// on two relays: 520 and 336 rejections, every one `reason=rejected`).
    ///
    /// `Some(true)` known, `Some(false)` unknown to the node, `None` could not
    /// be determined. Defaults to `None` so test doubles need no change.
    fn block_known<'a>(&'a self, _block_hash_hex: &'a str) -> BlockKnownFuture<'a> {
        Box::pin(async { None })
    }
}

/// Lets an `Arc<T>` stand in for the submitter anywhere a `&dyn SubmitBlock` is
/// needed, so a shared RPC client can be wrapped (see `dual_submit`) without
/// every handler taking ownership.
impl<T: SubmitBlock + Send + Sync + ?Sized> SubmitBlock for std::sync::Arc<T> {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        (**self).submit_block(block_hex)
    }

    fn block_known<'a>(&'a self, block_hash_hex: &'a str) -> BlockKnownFuture<'a> {
        (**self).block_known(block_hash_hex)
    }
}

impl SubmitBlock for ZebraRpc {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async move { ZebraRpc::submit_block(self, block_hex).await })
    }

    fn block_known<'a>(&'a self, block_hash_hex: &'a str) -> BlockKnownFuture<'a> {
        Box::pin(async move {
            // get_block_header already maps Zebra's -5 / "not found" to Ok(None),
            // so a clean negative is distinguishable from an RPC failure.
            match ZebraRpc::get_block_header(self, block_hash_hex).await {
                Ok(Some(_)) => Some(true),
                Ok(None) => Some(false),
                Err(_) => None,
            }
        })
    }
}

/// How a `submitblock` rejection should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitRejectionClass {
    /// Zebra already had the block: another sidecar in the mesh won the race.
    /// Structural, expected, and not a defect.
    RaceLost,
    /// Zebra rejected the block and does not have it. This is the one that matters.
    Invalid,
    /// The follow-up lookup failed, so the rejection cannot be attributed.
    Unknown,
    /// Zebra answered `inconclusive`: it could not decide the block yet, for example
    /// because it does not extend the best chain. Not a finding against the body.
    Inconclusive,
}

impl SubmitRejectionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            SubmitRejectionClass::RaceLost => "race_lost",
            SubmitRejectionClass::Invalid => "invalid",
            SubmitRejectionClass::Unknown => "unknown",
            SubmitRejectionClass::Inconclusive => "inconclusive",
        }
    }

    /// Classify from the "does the node already have it" answer.
    pub fn from_block_known(block_known: Option<bool>) -> Self {
        match block_known {
            Some(true) => SubmitRejectionClass::RaceLost,
            Some(false) => SubmitRejectionClass::Invalid,
            None => SubmitRejectionClass::Unknown,
        }
    }
}

/// Runtime submit mode for relay-received compact blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitBlockMode {
    /// Build and log a candidate but do not call `submitblock`.
    DryRun,
    /// Submit candidates to Zebra.
    Live,
}

/// Fully serialized block candidate that is safe to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionCandidate {
    /// Relay internal BLAKE2b object id (NOT the consensus block hash).
    pub block_hash: String,
    /// Zcash consensus block hash in DISPLAY order, matching Zebra/getblockhash
    /// and the P2P-ingress `hash` field. Lets submit outcomes be cross-referenced
    /// with ingress receipts and the first-to-Zebra win attribution pipeline.
    pub consensus_block_hash: String,
    pub block_hex: String,
    /// 0 for an unverified candidate, whose transactions could not all be read.
    pub tx_count: usize,
    pub block_bytes: usize,
    /// Why this sidecar could not read the body, if it is going to Zebra anyway
    /// under the emergency bypass. The Merkle and duplicate checks have not run.
    pub unverified: Option<BlockBodyError>,
}

/// Outcome from handling one relay-received compact block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionOutcome {
    DryRun(SubmissionCandidate),
    NeedsTransactions {
        request: GetBlockTxn,
        missing_indexes: usize,
        missing_wtxids: usize,
        unresolved_short_ids: usize,
    },
    Submitted {
        candidate: SubmissionCandidate,
        status: SubmitBlockStatus,
    },
    /// The safety gate rejected the candidate before reaching the submit RPC.
    /// `reason` attributes the cause so per-cause metrics can be wired up.
    GateRejected {
        candidate: SubmissionCandidate,
        reason: crate::submit_gate::RejectReason,
    },
}

impl SubmissionOutcome {
    /// The Zcash consensus block hash of a successfully reconstructed candidate
    /// (DryRun / Submitted / GateRejected). `None` for `NeedsTransactions`,
    /// which did not reconstruct a block. Used to log the compact-block relay
    /// arrival so the observatory can time the fast path (not just the
    /// raw-segment fallback).
    pub fn candidate_consensus_hash(&self) -> Option<&str> {
        match self {
            SubmissionOutcome::DryRun(candidate)
            | SubmissionOutcome::Submitted { candidate, .. }
            | SubmissionOutcome::GateRejected { candidate, .. } => {
                Some(candidate.consensus_block_hash.as_str())
            }
            SubmissionOutcome::NeedsTransactions { .. } => None,
        }
    }
}

/// Classified Zebra `submitblock` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitBlockStatus {
    Accepted,
    Duplicate,
}

impl SubmitBlockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SubmitBlockStatus::Accepted => "accepted",
            SubmitBlockStatus::Duplicate => "duplicate",
        }
    }
}

/// Errors that prevent a relay block from being submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayBlockError {
    EmptyTransactions,
    MissingTransactions {
        short_ids: usize,
    },
    ReconstructionIncomplete {
        block_hash: BlockHash,
        missing_indexes: Vec<usize>,
        missing_wtxids: Vec<WtxId>,
        unresolved_short_ids: Vec<ShortId>,
    },
    ReconstructionInvalid {
        reason: String,
    },
    NonContiguousPrefilledTx {
        expected: u16,
        actual: u16,
    },
    TooManyTransactions {
        count: usize,
    },
    RawBlockTooShort {
        bytes: usize,
    },
    RawBlockHashMismatch,
    InvalidBlockBody(BlockBodyError),
    SubmitFailed(String),
    SubmitRejected(String, SubmitRejectionClass),
}

impl fmt::Display for RelayBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayBlockError::EmptyTransactions => {
                write!(f, "compact block has no prefilled transactions")
            }
            RelayBlockError::MissingTransactions { short_ids } => {
                write!(
                    f,
                    "compact block is missing {short_ids} short-id transactions"
                )
            }
            RelayBlockError::ReconstructionIncomplete {
                block_hash: _,
                missing_indexes,
                missing_wtxids,
                unresolved_short_ids,
            } => write!(
                f,
                "compact block reconstruction incomplete: missing_indexes={} missing_wtxids={} unresolved_short_ids={}",
                missing_indexes.len(),
                missing_wtxids.len(),
                unresolved_short_ids.len(),
            ),
            RelayBlockError::ReconstructionInvalid { reason } => {
                write!(f, "compact block reconstruction invalid: {reason}")
            }
            RelayBlockError::NonContiguousPrefilledTx { expected, actual } => write!(
                f,
                "prefilled transaction index {actual} is not contiguous at expected index {expected}"
            ),
            RelayBlockError::TooManyTransactions { count } => {
                write!(f, "transaction count {count} exceeds compactSize u64")
            }
            RelayBlockError::RawBlockTooShort { bytes } => {
                write!(f, "raw block too short for Zcash header: {bytes} bytes")
            }
            RelayBlockError::RawBlockHashMismatch => {
                write!(f, "raw block header hash does not match relay metadata")
            }
            RelayBlockError::InvalidBlockBody(error) => write!(f, "invalid block body: {error}"),
            RelayBlockError::SubmitFailed(error) => write!(f, "submitblock RPC failed: {error}"),
            RelayBlockError::SubmitRejected(reason, class) => {
                write!(f, "submitblock rejected: {reason} ({})", class.as_str())
            }
        }
    }
}

impl Error for RelayBlockError {}

impl RelayBlockError {
    /// Build a `getblocktxn` request for compact reconstruction misses.
    pub fn missing_transaction_request(&self) -> Option<GetBlockTxn> {
        match self {
            RelayBlockError::ReconstructionIncomplete {
                block_hash,
                missing_indexes,
                ..
            } => GetBlockTxn::from_missing_indexes(*block_hash, missing_indexes).ok(),
            _ => None,
        }
    }
}

/// Build a full serialized block from a compact block when all transactions are prefilled.
pub fn build_submission_candidate(
    compact: &CompactBlock,
) -> Result<SubmissionCandidate, RelayBlockError> {
    if !compact.short_ids.is_empty() {
        return Err(RelayBlockError::MissingTransactions {
            short_ids: compact.short_ids.len(),
        });
    }
    if compact.prefilled_txs.is_empty() {
        return Err(RelayBlockError::EmptyTransactions);
    }

    let txs = &compact.prefilled_txs;
    let mut next_position = 0usize;
    for (expected, tx) in txs.iter().enumerate() {
        if expected > u16::MAX as usize {
            return Err(RelayBlockError::TooManyTransactions { count: txs.len() });
        }
        let expected = expected as u16;
        let position = next_position
            .checked_add(tx.index as usize)
            .ok_or(RelayBlockError::TooManyTransactions { count: txs.len() })?;
        if position > u16::MAX as usize {
            return Err(RelayBlockError::TooManyTransactions { count: txs.len() });
        }
        let position = position as u16;
        if position != expected {
            return Err(RelayBlockError::NonContiguousPrefilledTx {
                expected,
                actual: position,
            });
        }
        next_position = position as usize + 1;
    }

    // Each slice, not the joined block: shifted boundaries can join into valid
    // bytes that this compact block did not actually carry.
    let tx_count =
        validate_block_transactions(&compact.header, txs.iter().map(|tx| tx.tx_data.as_slice()))
            .map_err(RelayBlockError::InvalidBlockBody)?;

    let mut block = Vec::with_capacity(
        compact.header.len()
            + compact_size_len(txs.len())
            + txs.iter().map(|tx| tx.tx_data.len()).sum::<usize>(),
    );
    block.extend_from_slice(&compact.header);
    encode_compact_size(txs.len(), &mut block)?;
    for tx in txs {
        block.extend_from_slice(&tx.tx_data);
    }

    Ok(SubmissionCandidate {
        block_hash: compact.header_hash().to_string(),
        consensus_block_hash: consensus_block_hash_display(&compact.header),
        block_hex: hex::encode(&block),
        tx_count,
        block_bytes: block.len(),
        unverified: None,
    })
}

/// Build a full serialized block from a compact block using a mempool provider
/// for short-id transactions.
pub fn build_submission_candidate_with_mempool<M: MempoolProvider>(
    compact: &CompactBlock,
    mempool: &M,
) -> Result<SubmissionCandidate, RelayBlockError> {
    if compact.short_ids.is_empty() {
        return build_submission_candidate(compact);
    }

    let mut reconstructor = CompactBlockReconstructor::new(mempool);
    let header_hash = zcash_block_hash(&compact.header);
    reconstructor.prepare(&header_hash, compact.nonce);

    match reconstructor.reconstruct(compact) {
        ReconstructionResult::Complete { transactions } => {
            build_submission_candidate_from_transactions(&compact.header, &transactions)
        }
        ReconstructionResult::Incomplete {
            partial,
            missing_wtxids,
            unresolved_short_ids,
        } => Err(RelayBlockError::ReconstructionIncomplete {
            block_hash: compact.header_hash(),
            missing_indexes: partial
                .iter()
                .enumerate()
                .filter_map(|(index, tx)| tx.is_none().then_some(index))
                .collect(),
            missing_wtxids,
            unresolved_short_ids,
        }),
        ReconstructionResult::Invalid { reason } => {
            Err(RelayBlockError::ReconstructionInvalid { reason })
        }
        ReconstructionResult::InvalidBody(error) => Err(RelayBlockError::InvalidBlockBody(error)),
    }
}

/// Serialize transactions the reconstructor already validated against `header`.
/// Its one call is on `ReconstructionResult::Complete`, which is why it stays
/// private: nothing else may reach a candidate without that check.
fn build_submission_candidate_from_transactions(
    header: &[u8],
    transactions: &[Vec<u8>],
) -> Result<SubmissionCandidate, RelayBlockError> {
    if transactions.is_empty() {
        return Err(RelayBlockError::EmptyTransactions);
    }
    let mut block = Vec::with_capacity(
        header.len()
            + compact_size_len(transactions.len())
            + transactions.iter().map(Vec::len).sum::<usize>(),
    );
    block.extend_from_slice(header);
    encode_compact_size(transactions.len(), &mut block)?;
    for tx in transactions {
        block.extend_from_slice(tx);
    }

    Ok(SubmissionCandidate {
        block_hash: hex::encode(zcash_block_hash(header)),
        consensus_block_hash: consensus_block_hash_display(header),
        block_hex: hex::encode(&block),
        tx_count: transactions.len(),
        block_bytes: block.len(),
        unverified: None,
    })
}

/// Build a submit candidate from a complete raw serialized block.
pub fn build_raw_block_submission_candidate(
    raw_block: &[u8],
    expected_block_hash: Option<[u8; 32]>,
) -> Result<SubmissionCandidate, RelayBlockError> {
    let header =
        raw_block
            .get(..ZCASH_FULL_HEADER_SIZE)
            .ok_or(RelayBlockError::RawBlockTooShort {
                bytes: raw_block.len(),
            })?;
    let block_hash = raw_block_header_hash(header);
    if let Some(expected) = expected_block_hash
        && expected != block_hash
    {
        return Err(RelayBlockError::RawBlockHashMismatch);
    }

    let tx_count = validate_block_body(raw_block).map_err(RelayBlockError::InvalidBlockBody)?;

    Ok(SubmissionCandidate {
        block_hash: hex::encode(block_hash),
        consensus_block_hash: consensus_block_hash_display(header),
        block_hex: hex::encode(raw_block),
        tx_count,
        block_bytes: raw_block.len(),
        unverified: None,
    })
}

/// A raw block this sidecar could not read, for the emergency bypass. Nothing here
/// says the body belongs to its header, so the header has to show a real proof of
/// work. The relay's checks are not relied on, and neither is what the sender saw.
///
/// The cost of the Equihash check has not been measured. It is the relay node's
/// check, so it covers the mainnet target range on either network: a testnet
/// minimum-difficulty block is refused here as it is at the first relay.
fn unverified_raw_candidate(
    raw_block: &[u8],
    error: BlockBodyError,
) -> Result<SubmissionCandidate, RelayBlockError> {
    let header = raw_block_header(raw_block)?;
    if EquihashPowValidator.validate(header) != PowResult::Valid {
        return Err(RelayBlockError::InvalidBlockBody(error));
    }
    Ok(SubmissionCandidate {
        block_hash: hex::encode(raw_block_header_hash(header)),
        consensus_block_hash: consensus_block_hash_display(header),
        block_hex: hex::encode(raw_block),
        tx_count: 0,
        block_bytes: raw_block.len(),
        unverified: Some(error),
    })
}

/// Handle one relay compact block under the configured submit mode.
pub async fn handle_relay_compact_block<S: SubmitBlock + Sync>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
) -> Result<SubmissionOutcome, RelayBlockError> {
    let candidate = build_submission_candidate(compact)?;
    match mode {
        SubmitBlockMode::DryRun => Ok(SubmissionOutcome::DryRun(candidate)),
        SubmitBlockMode::Live => {
            let result = submitter
                .submit_block(&candidate.block_hex)
                .await
                .map_err(|error| RelayBlockError::SubmitFailed(error.to_string()))?;
            let status =
                classify_submitblock_outcome(result, submitter, &candidate.consensus_block_hash)
                    .await?;
            Ok(SubmissionOutcome::Submitted { candidate, status })
        }
    }
}

/// Handle one relay compact block, allowing short-id reconstruction from a
/// provided mempool before applying the submit mode.
pub async fn handle_relay_compact_block_with_mempool<S, M>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
    mempool: &M,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    M: MempoolProvider,
{
    let candidate = match build_submission_candidate_with_mempool(compact, mempool) {
        Ok(candidate) => candidate,
        Err(error @ RelayBlockError::ReconstructionIncomplete { .. }) => {
            let request = error.missing_transaction_request().ok_or_else(|| {
                RelayBlockError::ReconstructionInvalid {
                    reason: "failed to build getblocktxn request from missing indexes".to_owned(),
                }
            })?;
            if let RelayBlockError::ReconstructionIncomplete {
                missing_indexes,
                missing_wtxids,
                unresolved_short_ids,
                ..
            } = error
            {
                return Ok(SubmissionOutcome::NeedsTransactions {
                    request,
                    missing_indexes: missing_indexes.len(),
                    missing_wtxids: missing_wtxids.len(),
                    unresolved_short_ids: unresolved_short_ids.len(),
                });
            }
            unreachable!("matched ReconstructionIncomplete above")
        }
        Err(error) => return Err(error),
    };
    match mode {
        SubmitBlockMode::DryRun => Ok(SubmissionOutcome::DryRun(candidate)),
        SubmitBlockMode::Live => {
            let result = submitter
                .submit_block(&candidate.block_hex)
                .await
                .map_err(|error| RelayBlockError::SubmitFailed(error.to_string()))?;
            let status =
                classify_submitblock_outcome(result, submitter, &candidate.consensus_block_hash)
                    .await?;
            Ok(SubmissionOutcome::Submitted { candidate, status })
        }
    }
}

/// Handle one relay raw block under the configured submit mode.
pub async fn handle_relay_raw_block<S: SubmitBlock + Sync>(
    submitter: &S,
    raw_block: &[u8],
    expected_block_hash: Option<[u8; 32]>,
    mode: SubmitBlockMode,
) -> Result<SubmissionOutcome, RelayBlockError> {
    let candidate = build_raw_block_submission_candidate(raw_block, expected_block_hash)?;
    match mode {
        SubmitBlockMode::DryRun => Ok(SubmissionOutcome::DryRun(candidate)),
        SubmitBlockMode::Live => {
            let result = submitter
                .submit_block(&candidate.block_hex)
                .await
                .map_err(|error| RelayBlockError::SubmitFailed(error.to_string()))?;
            let status =
                classify_submitblock_outcome(result, submitter, &candidate.consensus_block_hash)
                    .await?;
            Ok(SubmissionOutcome::Submitted { candidate, status })
        }
    }
}

/// Handle one relay compact block, evaluating the safety gate against the
/// reassembled candidate before any submit_block call.
///
/// The gate runs *before* `mode` is inspected, so a gate rejection in DryRun
/// mode also short-circuits with `GateRejected`. That lets the staging service
/// exercise the gate's decision logic on every candidate without ever calling
/// `submit_block`.
///
/// `parent` is the lookup of the header's parent
/// (`ZebraChainView::observe_candidate_parent`), `None` if it failed.
pub async fn handle_relay_compact_block_with_gate<S, V>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
    gate: &mut crate::submit_gate::SubmitGate<V>,
    parent: Option<&crate::submit_gate::ParentObservation>,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let candidate = build_submission_candidate(compact)?;
    submit_through_gate(submitter, candidate, &compact.header, mode, gate, parent).await
}

/// Handle one relay raw block, evaluating the safety gate against the
/// reassembled candidate before any submit_block call.
///
/// `parent` is the lookup of the header's parent
/// (`ZebraChainView::observe_candidate_parent`), `None` if it failed.
pub async fn handle_relay_raw_block_with_gate<S, V>(
    submitter: &S,
    raw_block: &[u8],
    expected_block_hash: Option<[u8; 32]>,
    mode: SubmitBlockMode,
    gate: &mut crate::submit_gate::SubmitGate<V>,
    parent: Option<&crate::submit_gate::ParentObservation>,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let candidate = build_raw_block_submission_candidate(raw_block, expected_block_hash)?;
    let header = raw_block_header(raw_block)?;
    submit_through_gate(submitter, candidate, header, mode, gate, parent).await
}

/// [`handle_relay_compact_block_with_gate`], validating the candidate first: a
/// bad body costs neither the parent lookup, which is a Zebra round trip, nor a
/// wait for the gate lock while a good copy may be queued behind it.
pub async fn validate_then_gate_compact_block<S, V, L, F>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<crate::submit_gate::SubmitGate<V>>,
    look_up_parent: L,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
    L: FnOnce() -> F,
    F: Future<Output = Option<crate::submit_gate::ParentObservation>>,
{
    let candidate = build_submission_candidate(compact)?;
    let parent = look_up_parent().await;
    gate_and_submit(
        submitter,
        candidate,
        &compact.header,
        mode,
        gate,
        parent.as_ref(),
    )
    .await
}

/// [`validate_then_gate_compact_block`] for a reassembled raw block.
pub async fn validate_then_gate_raw_block<S, V, L, F>(
    submitter: &S,
    raw_block: &[u8],
    expected_block_hash: Option<[u8; 32]>,
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<crate::submit_gate::SubmitGate<V>>,
    look_up_parent: L,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
    L: FnOnce() -> F,
    F: Future<Output = Option<crate::submit_gate::ParentObservation>>,
{
    let candidate = build_raw_block_submission_candidate(raw_block, expected_block_hash)?;
    let header = raw_block_header(raw_block)?;
    let parent = look_up_parent().await;
    gate_and_submit(submitter, candidate, header, mode, gate, parent.as_ref()).await
}

/// The legacy gate holds its lock across the Zebra call and marks the block when the
/// candidate passes, as it always has. The competing-body gate holds it only to reserve
/// and to record.
async fn gate_and_submit<S, V>(
    submitter: &S,
    candidate: SubmissionCandidate,
    header: &[u8],
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<crate::submit_gate::SubmitGate<V>>,
    parent: Option<&crate::submit_gate::ParentObservation>,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let mut held = gate.lock().await;
    if !held.competing_bodies() {
        return submit_through_gate(submitter, candidate, header, mode, &mut held, parent).await;
    }
    drop(held);
    let meta = candidate_meta(&candidate, header, parent)?;
    submit_without_the_gate_lock(submitter, candidate, &meta, mode, gate).await
}

/// Raw blocks carry the full header at the start. The gate metadata needs its
/// prev_hash.
fn raw_block_header(raw_block: &[u8]) -> Result<&[u8], RelayBlockError> {
    raw_block
        .get(..ZCASH_FULL_HEADER_SIZE)
        .ok_or_else(|| RelayBlockError::ReconstructionInvalid {
            reason: format!(
                "raw block shorter than the {} byte header prefix",
                ZCASH_FULL_HEADER_SIZE
            ),
        })
}

fn candidate_meta(
    candidate: &SubmissionCandidate,
    header: &[u8],
    parent: Option<&crate::submit_gate::ParentObservation>,
) -> Result<crate::submit_gate::CandidateMeta, RelayBlockError> {
    crate::submit_gate::CandidateMeta::from_header_bytes(
        header,
        candidate.block_hash.clone(),
        parent,
    )
    .map_err(candidate_meta_error)
}

/// A reserved candidate to Zebra, and what it said: the gate's answer for it, `None` if
/// the call failed in transit, and the result.
async fn ask_zebra<S>(
    submitter: &S,
    candidate: &SubmissionCandidate,
) -> (
    Option<crate::submit_gate::StrictAnswer>,
    Result<SubmitBlockStatus, RelayBlockError>,
)
where
    S: SubmitBlock + Sync,
{
    use crate::submit_gate::StrictAnswer;
    let result = match submitter.submit_block(&candidate.block_hex).await {
        Ok(result) => result,
        Err(error) => return (None, Err(RelayBlockError::SubmitFailed(error.to_string()))),
    };
    let status =
        classify_submitblock_outcome(result, submitter, &candidate.consensus_block_hash).await;
    let answer = match &status {
        Ok(_) | Err(RelayBlockError::SubmitRejected(_, SubmitRejectionClass::RaceLost)) => {
            StrictAnswer::Known
        }
        Err(RelayBlockError::SubmitRejected(_, SubmitRejectionClass::Inconclusive)) => {
            StrictAnswer::Undecided
        }
        Err(RelayBlockError::SubmitRejected(..)) => StrictAnswer::Refused,
        // Classification only ever ends in a status or a rejection.
        Err(_) => return (None, status),
    };
    (Some(answer), status)
}

/// The competing-body gate, held only to reserve and to record, so a slow Zebra call
/// stops no one. Only Zebra's answer is recorded: a call that fails in transit, times out
/// or is cancelled records nothing, and gives the body's place back.
async fn submit_without_the_gate_lock<S, V>(
    submitter: &S,
    candidate: SubmissionCandidate,
    meta: &crate::submit_gate::CandidateMeta,
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<crate::submit_gate::SubmitGate<V>>,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let dry_run = mode == SubmitBlockMode::DryRun;
    let reservation = gate
        .lock()
        .await
        .reserve_strict_now(&candidate, meta, dry_run);
    let slot = match reservation {
        Ok(slot) => slot,
        Err(reason) => return Ok(SubmissionOutcome::GateRejected { candidate, reason }),
    };
    if dry_run {
        return Ok(SubmissionOutcome::DryRun(candidate));
    }
    let (answer, status) = ask_zebra(submitter, &candidate).await;
    if let Some(answer) = answer {
        gate.lock()
            .await
            .record_strict_answer_now(&candidate, answer);
    }
    drop(slot);
    Ok(SubmissionOutcome::Submitted {
        status: status?,
        candidate,
    })
}

/// [`submit_without_the_gate_lock`] for a caller that has the gate to itself.
async fn submit_holding_the_competing_gate<S, V>(
    submitter: &S,
    candidate: SubmissionCandidate,
    meta: &crate::submit_gate::CandidateMeta,
    mode: SubmitBlockMode,
    gate: &mut crate::submit_gate::SubmitGate<V>,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let dry_run = mode == SubmitBlockMode::DryRun;
    let slot = match gate.reserve_strict_now(&candidate, meta, dry_run) {
        Ok(slot) => slot,
        Err(reason) => return Ok(SubmissionOutcome::GateRejected { candidate, reason }),
    };
    if dry_run {
        return Ok(SubmissionOutcome::DryRun(candidate));
    }
    let (answer, status) = ask_zebra(submitter, &candidate).await;
    if let Some(answer) = answer {
        gate.record_strict_answer_now(&candidate, answer);
    }
    drop(slot);
    Ok(SubmissionOutcome::Submitted {
        status: status?,
        candidate,
    })
}

/// Run a validated candidate through the legacy gate and, if it passes, the mode. The
/// caller holds the gate across the Zebra call.
async fn submit_through_gate<S, V>(
    submitter: &S,
    candidate: SubmissionCandidate,
    header: &[u8],
    mode: SubmitBlockMode,
    gate: &mut crate::submit_gate::SubmitGate<V>,
    parent: Option<&crate::submit_gate::ParentObservation>,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let meta = candidate_meta(&candidate, header, parent)?;
    if gate.competing_bodies() {
        return submit_holding_the_competing_gate(submitter, candidate, &meta, mode, gate).await;
    }

    match gate.apply_now(&candidate, &meta) {
        crate::submit_gate::GateDecision::Accept => {}
        crate::submit_gate::GateDecision::Reject(reason) => {
            return Ok(SubmissionOutcome::GateRejected { candidate, reason });
        }
    }

    match mode {
        SubmitBlockMode::DryRun => Ok(SubmissionOutcome::DryRun(candidate)),
        SubmitBlockMode::Live => {
            let result = submitter
                .submit_block(&candidate.block_hex)
                .await
                .map_err(|error| RelayBlockError::SubmitFailed(error.to_string()))?;
            let status =
                classify_submitblock_outcome(result, submitter, &candidate.consensus_block_hash)
                    .await?;
            Ok(SubmissionOutcome::Submitted { candidate, status })
        }
    }
}

/// Whether this outcome means Zebra has the block, even though this body was not what
/// took it there: the gate turned away a block Zebra has told it about, or Zebra refused
/// this copy and turned out to have the block.
pub async fn zebra_has_the_block<V>(
    outcome: &Result<SubmissionOutcome, RelayBlockError>,
    gate: Option<&tokio::sync::Mutex<crate::submit_gate::SubmitGate<V>>>,
) -> bool
where
    V: crate::submit_gate::ChainView,
{
    match (outcome, gate) {
        (
            Ok(SubmissionOutcome::GateRejected {
                candidate,
                reason: crate::submit_gate::RejectReason::DuplicateSubmit,
            }),
            Some(gate),
        ) => gate.lock().await.knows(&candidate.block_hash),
        (Err(RelayBlockError::SubmitRejected(_, SubmitRejectionClass::RaceLost)), _) => true,
        _ => false,
    }
}

/// True when Zebra said this body is wrong, now or within the gate's memory of it. Only
/// then may the relays be told to free the place the body holds for a rival body of its
/// block: a transport failure, an `inconclusive` or a lost race says nothing against it.
pub fn zebra_refused_the_body(outcome: &Result<SubmissionOutcome, RelayBlockError>) -> bool {
    matches!(
        outcome,
        Err(RelayBlockError::SubmitRejected(
            _,
            SubmitRejectionClass::Invalid | SubmitRejectionClass::Unknown
        )) | Ok(SubmissionOutcome::GateRejected {
            reason: crate::submit_gate::RejectReason::RefusedBody,
            ..
        })
    )
}

/// The refusal the emergency bypass may override, if this is one. A transaction that
/// did not parse is the only one: anything else is a finding about the body.
pub fn unreadable_body(
    outcome: &Result<SubmissionOutcome, RelayBlockError>,
) -> Option<BlockBodyError> {
    match outcome {
        Err(RelayBlockError::InvalidBlockBody(error @ BlockBodyError::Transaction { .. })) => {
            Some(*error)
        }
        _ => None,
    }
}

/// What bounds one emergency bypass attempt, and where it is counted.
#[derive(Clone, Copy)]
pub struct UnverifiedLimits<'a> {
    /// Time for the attempt's async waits together: the parent lookup, the gate,
    /// `submitblock` and the lookup after a rejection, so separate RPC timeouts cannot
    /// add up. It is not a wall-clock limit on the attempt: a timer cannot interrupt
    /// the synchronous Equihash check, which can run past it.
    pub budget: Duration,
    pub bypassed: &'a AtomicU64,
}

/// The emergency bypass, for a raw block the strict path refused as
/// [`unreadable_body`]. Zebra is the only validator of these bytes.
///
/// The gate lock is held only to reserve an attempt and to record the result, so a
/// candidate waiting on Zebra holds up nothing else. The block is recorded only once
/// Zebra has it. A dry run has no verdict, and a rejection, an RPC error, a timeout or
/// cancellation says nothing about the real body, so none of them may hide it.
pub async fn submit_unverified_raw_block<S, V, L, F>(
    submitter: &S,
    raw_block: &[u8],
    error: BlockBodyError,
    mode: SubmitBlockMode,
    gate: &tokio::sync::Mutex<crate::submit_gate::SubmitGate<V>>,
    limits: UnverifiedLimits<'_>,
    look_up_parent: L,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
    L: FnOnce() -> F,
    F: Future<Output = Option<crate::submit_gate::ParentObservation>>,
{
    let attempt = async {
        let candidate = unverified_raw_candidate(raw_block, error)?;
        let header = raw_block_header(raw_block)?;
        let parent = look_up_parent().await;
        let meta = crate::submit_gate::CandidateMeta::from_header_bytes(
            header,
            candidate.block_hash.clone(),
            parent.as_ref(),
        )
        .map_err(candidate_meta_error)?;

        let reservation = gate.lock().await.reserve_unverified_now(&candidate, &meta);
        let slot = match reservation {
            Ok(slot) => slot,
            Err(reason) => return Ok(SubmissionOutcome::GateRejected { candidate, reason }),
        };
        limits.bypassed.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            consensus_block_hash = %candidate.consensus_block_hash,
            reason = candidate.unverified.map(|error| error.label()),
            block_bytes = candidate.block_bytes,
            checks_run = "size,header,proof_of_work",
            checks_skipped = "merkle,duplicate_txid",
            "Sending Zebra a block body without the Merkle and duplicate checks"
        );

        match mode {
            SubmitBlockMode::DryRun => Ok(SubmissionOutcome::DryRun(candidate)),
            SubmitBlockMode::Live => {
                let result = submitter
                    .submit_block(&candidate.block_hex)
                    .await
                    .map_err(|error| RelayBlockError::SubmitFailed(error.to_string()))?;
                let hash = &candidate.consensus_block_hash;
                let status = classify_submitblock_outcome(result, submitter, hash).await?;
                gate.lock().await.record_submitted_now(&candidate);
                drop(slot);
                Ok(SubmissionOutcome::Submitted { candidate, status })
            }
        }
    };
    tokio::time::timeout(limits.budget, attempt)
        .await
        .unwrap_or_else(|_| {
            Err(RelayBlockError::SubmitFailed(format!(
                "unverified submission exceeded its {:?} budget",
                limits.budget
            )))
        })
}

/// A gated candidate whose `CandidateMeta` could not be built never reaches
/// the gate or `submit_block`; each cause keeps its own reason text.
fn candidate_meta_error(error: crate::submit_gate::CandidateMetaError) -> RelayBlockError {
    RelayBlockError::ReconstructionInvalid {
        reason: format!("candidate meta extraction failed: {}", error.as_str()),
    }
}

/// Submit-result classification WITH the follow-up lookup, for every submit path.
///
/// There were five places that called `submit_block`. When rejection classification
/// was added in #88 only one of them was wired up, so the other four -- including
/// the raw-segment path, which carries almost all traffic -- left the class at
/// `Unknown`. The result was 119 rejections fleet-wide on 2026-09-03, every one
/// labelled `unknown` and none classified: a feature that shipped, looked
/// healthy, and told us nothing.
///
/// Keeping this in one place is the point. A per-call-site version is what
/// allowed four of five paths to be missed.
async fn classify_submitblock_outcome<S: SubmitBlock + ?Sized>(
    result: Option<String>,
    submitter: &S,
    consensus_block_hash: &str,
) -> Result<SubmitBlockStatus, RelayBlockError> {
    match classify_submitblock_result(result) {
        Ok(status) => Ok(status),
        // BIP 22: Zebra could not decide. Nothing is wrong with the body, so it is not
        // counted as invalid. "duplicate-inconclusive" means Zebra has the block, which the
        // lookup below reports as a lost race.
        Err(RelayBlockError::SubmitRejected(reason, _)) if reason == "inconclusive" => Err(
            RelayBlockError::SubmitRejected(reason, SubmitRejectionClass::Inconclusive),
        ),
        Err(RelayBlockError::SubmitRejected(reason, _)) => {
            // One extra RPC, only on the rejection path.
            let known = submitter.block_known(consensus_block_hash).await;
            Err(RelayBlockError::SubmitRejected(
                reason,
                SubmitRejectionClass::from_block_known(known),
            ))
        }
        Err(other) => Err(other),
    }
}

fn classify_submitblock_result(
    result: Option<String>,
) -> Result<SubmitBlockStatus, RelayBlockError> {
    match result.as_deref() {
        None => Ok(SubmitBlockStatus::Accepted),
        Some("duplicate") => Ok(SubmitBlockStatus::Duplicate),
        // Class is filled in by the caller, which still has the block hash;
        // this function only decides accepted / duplicate / rejected.
        Some(reason) => Err(RelayBlockError::SubmitRejected(
            reason.to_owned(),
            SubmitRejectionClass::Unknown,
        )),
    }
}

/// Length in bytes of `count` once CompactSize-encoded.
///
/// Asks the shared encoder rather than restating its boundaries, so this
/// cannot drift away from what `encode_compact_size` actually writes. Used
/// only to pre-size buffers.
fn compact_size_len(count: usize) -> usize {
    zcash_pool_common::encode_compact_size(count as u64).1
}

/// Append a CompactSize-encoded count to `out`.
///
/// Delegates to `zcash_pool_common::write_compact_size`, the workspace's single
/// implementation of this encoding. The signature and the `TooManyTransactions`
/// error are preserved: on a target where `usize` does not fit in `u64` the
/// conversion fails and nothing is written to `out`, exactly as before.
fn encode_compact_size(count: usize, out: &mut Vec<u8>) -> Result<(), RelayBlockError> {
    let value = u64::try_from(count).map_err(|_| RelayBlockError::TooManyTransactions { count })?;
    zcash_pool_common::write_compact_size(value, out);
    Ok(())
}

fn raw_block_header_hash(header: &[u8]) -> [u8; 32] {
    zcash_block_hash(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovright_relay::test_support::parseable_transaction;
    use sovright_relay::{
        AuthDigest, CompactBlock, PrefilledTx, ShortId, TestMempool, TxId, WtxId,
    };

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[test]
    fn submission_candidate_decodes_differential_prefilled_indices() {
        use sovright_relay::test_support::{committed_header, parseable_transaction, raw_block};
        let txs: Vec<Vec<u8>> = (1..=3).map(parseable_transaction).collect();
        let header = committed_header(0xab, &txs);
        let compact = CompactBlock::new(
            header.clone(),
            0,
            Vec::new(),
            txs.iter()
                .map(|tx| PrefilledTx {
                    index: 0,
                    tx_data: tx.clone(),
                })
                .collect(),
        );

        let candidate = build_submission_candidate(&compact).unwrap();
        let block = hex::decode(&candidate.block_hex).unwrap();

        let expected = raw_block(&header, &txs);

        assert_eq!(candidate.tx_count, 3);
        assert_eq!(candidate.block_bytes, expected.len());
        assert_eq!(block, expected);
    }

    #[test]
    fn submission_candidate_rejects_legacy_absolute_prefilled_indices() {
        let compact = CompactBlock::new(
            vec![0xab; 2189],
            0,
            Vec::new(),
            vec![
                PrefilledTx {
                    index: 0,
                    tx_data: vec![0x01],
                },
                PrefilledTx {
                    index: 1,
                    tx_data: vec![0x02],
                },
            ],
        );

        let err = build_submission_candidate(&compact).unwrap_err();

        assert_eq!(
            err,
            RelayBlockError::NonContiguousPrefilledTx {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn candidate_consensus_hash_returns_reconstructed_hash() {
        let candidate = SubmissionCandidate {
            block_hash: "internal-id".to_string(),
            consensus_block_hash: "00abcdef".to_string(),
            unverified: None,
            block_hex: "00".to_string(),
            tx_count: 1,
            block_bytes: 1,
        };
        assert_eq!(
            SubmissionOutcome::DryRun(candidate).candidate_consensus_hash(),
            Some("00abcdef"),
        );
    }

    #[test]
    fn submission_candidate_reconstructs_short_ids_from_mempool() {
        let nonce = 42;
        let coinbase = parseable_transaction(1);
        let tx1 = parseable_transaction(2);
        let tx1_wtxid = make_wtxid(0x11);
        // Reconstruction verifies the header's merkle commitment, so the test
        // header has to actually commit to these two transactions. An arbitrary
        // filler header would now (correctly) be rejected before this path is
        // reached, and the test would prove nothing about short-id resolution.
        let header = {
            let mut h = vec![0xcd; ZCASH_FULL_HEADER_SIZE];
            let txids: Vec<[u8; 32]> = [&coinbase, &tx1]
                .iter()
                .map(|t| sovright_relay::txid_from_tx_bytes(t))
                .collect();
            h[36..68].copy_from_slice(&sovright_relay::merkle_root(&txids).unwrap());
            h
        };
        let header_hash = zcash_block_hash(&header);
        let short_id = ShortId::compute(&tx1_wtxid, &header_hash, nonce);
        let compact = CompactBlock::new(
            header.clone(),
            nonce,
            vec![short_id],
            vec![PrefilledTx {
                index: 0,
                tx_data: coinbase.clone(),
            }],
        );
        let mut mempool = TestMempool::new();
        mempool.insert(tx1_wtxid, tx1.clone());

        let candidate = build_submission_candidate_with_mempool(&compact, &mempool).unwrap();
        let block = hex::decode(&candidate.block_hex).unwrap();

        let mut expected = header;
        expected.push(2);
        expected.extend_from_slice(&coinbase);
        expected.extend_from_slice(&tx1);
        assert_eq!(candidate.tx_count, 2);
        assert_eq!(candidate.block_bytes, expected.len());
        assert_eq!(block, expected);
    }

    #[test]
    fn submission_candidate_reports_incomplete_reconstruction() {
        let header = vec![0xef; 2189];
        let nonce = 7;
        let missing_wtxid = make_wtxid(0x21);
        let header_hash = zcash_block_hash(&header);
        let short_id = ShortId::compute(&missing_wtxid, &header_hash, nonce);
        let compact = CompactBlock::new(
            header,
            nonce,
            vec![short_id],
            vec![PrefilledTx {
                index: 0,
                tx_data: vec![0x01],
            }],
        );
        let mempool = TestMempool::new();

        let err = build_submission_candidate_with_mempool(&compact, &mempool).unwrap_err();

        assert_eq!(
            err,
            RelayBlockError::ReconstructionIncomplete {
                block_hash: compact.header_hash(),
                missing_indexes: vec![1],
                missing_wtxids: Vec::new(),
                unresolved_short_ids: vec![short_id],
            }
        );
    }

    #[test]
    fn incomplete_reconstruction_builds_getblocktxn_request() {
        let header = vec![0xef; 2189];
        let nonce = 7;
        let missing_wtxid = make_wtxid(0x21);
        let header_hash = zcash_block_hash(&header);
        let short_id = ShortId::compute(&missing_wtxid, &header_hash, nonce);
        let compact = CompactBlock::new(
            header,
            nonce,
            vec![short_id],
            vec![PrefilledTx {
                index: 0,
                tx_data: vec![0x01],
            }],
        );
        let mempool = TestMempool::new();

        let err = build_submission_candidate_with_mempool(&compact, &mempool).unwrap_err();

        let request = err
            .missing_transaction_request()
            .expect("incomplete reconstruction should produce getblocktxn");
        assert_eq!(request.block_hash, compact.header_hash());
        assert_eq!(request.indexes, vec![1]);
    }
}
