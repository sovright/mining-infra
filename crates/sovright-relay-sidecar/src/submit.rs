//! Guarded relay-block submission support.
//!
//! This module is intentionally conservative: compact blocks with missing
//! transaction data are not submit candidates, and dry-run mode never calls
//! Zebra `submitblock`.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use sovright_relay::{
    BlockHash, CompactBlock, CompactBlockReconstructor, GetBlockTxn, MempoolProvider,
    ReconstructionResult, ShortId, WtxId, ZCASH_FULL_HEADER_SIZE, consensus_block_hash_display,
    zcash_block_hash,
};

use crate::rpc::ZebraRpc;

/// Future returned by submitblock implementations.
pub type SubmitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, Box<dyn Error + Send + Sync>>> + Send + 'a>>;

/// Minimal submitblock interface for testing and for the Zebra RPC client.
pub trait SubmitBlock {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a>;
}

impl SubmitBlock for ZebraRpc {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async move { ZebraRpc::submit_block(self, block_hex).await })
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
    pub tx_count: usize,
    pub block_bytes: usize,
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
    InvalidCompactSize,
    SubmitFailed(String),
    SubmitRejected(String),
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
            RelayBlockError::InvalidCompactSize => {
                write!(f, "invalid transaction count compactSize")
            }
            RelayBlockError::SubmitFailed(error) => write!(f, "submitblock RPC failed: {error}"),
            RelayBlockError::SubmitRejected(reason) => write!(f, "submitblock rejected: {reason}"),
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
        tx_count: txs.len(),
        block_bytes: block.len(),
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
    }
}

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

    let mut cursor = ZCASH_FULL_HEADER_SIZE;
    let tx_count = decode_compact_size(raw_block, &mut cursor)?;
    if tx_count == 0 {
        return Err(RelayBlockError::EmptyTransactions);
    }
    let tx_count = usize::try_from(tx_count)
        .map_err(|_| RelayBlockError::TooManyTransactions { count: usize::MAX })?;

    Ok(SubmissionCandidate {
        block_hash: hex::encode(block_hash),
        consensus_block_hash: consensus_block_hash_display(header),
        block_hex: hex::encode(raw_block),
        tx_count,
        block_bytes: raw_block.len(),
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
            let status = classify_submitblock_result(result)?;
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
            let status = classify_submitblock_result(result)?;
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
            let status = classify_submitblock_result(result)?;
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
pub async fn handle_relay_compact_block_with_gate<S, V>(
    submitter: &S,
    compact: &CompactBlock,
    mode: SubmitBlockMode,
    gate: &mut crate::submit_gate::SubmitGate<V>,
    parent_height: u64,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let candidate = build_submission_candidate(compact)?;
    let meta = crate::submit_gate::CandidateMeta::from_header_bytes(
        &compact.header,
        candidate.block_hash.clone(),
        parent_height,
    )
    .ok_or_else(|| RelayBlockError::ReconstructionInvalid {
        reason: "candidate meta extraction failed: header too short or parent height overflow"
            .to_owned(),
    })?;

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
            let status = classify_submitblock_result(result)?;
            Ok(SubmissionOutcome::Submitted { candidate, status })
        }
    }
}

/// Handle one relay raw block, evaluating the safety gate against the
/// reassembled candidate before any submit_block call.
pub async fn handle_relay_raw_block_with_gate<S, V>(
    submitter: &S,
    raw_block: &[u8],
    expected_block_hash: Option<[u8; 32]>,
    mode: SubmitBlockMode,
    gate: &mut crate::submit_gate::SubmitGate<V>,
    parent_height: u64,
) -> Result<SubmissionOutcome, RelayBlockError>
where
    S: SubmitBlock + Sync,
    V: crate::submit_gate::ChainView,
{
    let candidate = build_raw_block_submission_candidate(raw_block, expected_block_hash)?;

    // Raw blocks carry the full header at the start. Extract the prev_hash
    // from the first ZCASH_FULL_HEADER_SIZE bytes; the gate metadata needs it.
    let header = raw_block.get(..ZCASH_FULL_HEADER_SIZE).ok_or_else(|| {
        RelayBlockError::ReconstructionInvalid {
            reason: format!(
                "raw block shorter than the {} byte header prefix",
                ZCASH_FULL_HEADER_SIZE
            ),
        }
    })?;
    let meta = crate::submit_gate::CandidateMeta::from_header_bytes(
        header,
        candidate.block_hash.clone(),
        parent_height,
    )
    .ok_or_else(|| RelayBlockError::ReconstructionInvalid {
        reason: "candidate meta extraction failed: header too short or parent height overflow"
            .to_owned(),
    })?;

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
            let status = classify_submitblock_result(result)?;
            Ok(SubmissionOutcome::Submitted { candidate, status })
        }
    }
}

fn classify_submitblock_result(
    result: Option<String>,
) -> Result<SubmitBlockStatus, RelayBlockError> {
    match result.as_deref() {
        None => Ok(SubmitBlockStatus::Accepted),
        Some("duplicate") => Ok(SubmitBlockStatus::Duplicate),
        Some(reason) => Err(RelayBlockError::SubmitRejected(reason.to_owned())),
    }
}

fn compact_size_len(count: usize) -> usize {
    if count < 253 {
        1
    } else if u16::try_from(count).is_ok() {
        3
    } else if u32::try_from(count).is_ok() {
        5
    } else {
        9
    }
}

fn encode_compact_size(count: usize, out: &mut Vec<u8>) -> Result<(), RelayBlockError> {
    if count < 253 {
        out.push(count as u8);
    } else if let Ok(count) = u16::try_from(count) {
        out.push(0xfd);
        out.extend_from_slice(&count.to_le_bytes());
    } else if let Ok(count) = u32::try_from(count) {
        out.push(0xfe);
        out.extend_from_slice(&count.to_le_bytes());
    } else if let Ok(count) = u64::try_from(count) {
        out.push(0xff);
        out.extend_from_slice(&count.to_le_bytes());
    } else {
        return Err(RelayBlockError::TooManyTransactions { count });
    }
    Ok(())
}

fn decode_compact_size(input: &[u8], cursor: &mut usize) -> Result<u64, RelayBlockError> {
    let Some(tag) = input.get(*cursor).copied() else {
        return Err(RelayBlockError::InvalidCompactSize);
    };
    *cursor += 1;
    match tag {
        0x00..=0xfc => Ok(tag as u64),
        0xfd => {
            let bytes = input
                .get(*cursor..*cursor + 2)
                .ok_or(RelayBlockError::InvalidCompactSize)?;
            *cursor += 2;
            Ok(u16::from_le_bytes(bytes.try_into().unwrap()) as u64)
        }
        0xfe => {
            let bytes = input
                .get(*cursor..*cursor + 4)
                .ok_or(RelayBlockError::InvalidCompactSize)?;
            *cursor += 4;
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as u64)
        }
        0xff => {
            let bytes = input
                .get(*cursor..*cursor + 8)
                .ok_or(RelayBlockError::InvalidCompactSize)?;
            *cursor += 8;
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        }
    }
}

fn raw_block_header_hash(header: &[u8]) -> [u8; 32] {
    zcash_block_hash(header)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let header = vec![0xab; 2189];
        let compact = CompactBlock::new(
            header.clone(),
            0,
            Vec::new(),
            vec![
                PrefilledTx {
                    index: 0,
                    tx_data: vec![0x01],
                },
                PrefilledTx {
                    index: 0,
                    tx_data: vec![0x02, 0x03],
                },
                PrefilledTx {
                    index: 0,
                    tx_data: vec![0x04],
                },
            ],
        );

        let candidate = build_submission_candidate(&compact).unwrap();
        let block = hex::decode(&candidate.block_hex).unwrap();

        let mut expected = header;
        expected.push(3);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

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
        let header = vec![0xcd; 2189];
        let nonce = 42;
        let coinbase = vec![0x01, 0x02];
        let tx1 = vec![0x03, 0x04, 0x05];
        let tx1_wtxid = make_wtxid(0x11);
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
