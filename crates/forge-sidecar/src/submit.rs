//! Guarded relay-block submission support.
//!
//! This module is intentionally conservative: compact blocks with missing
//! transaction data are not submit candidates, and dry-run mode never calls
//! Zebra `submitblock`.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use bedrock_forge::CompactBlock;

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
    pub block_hash: String,
    pub block_hex: String,
    pub tx_count: usize,
    pub block_bytes: usize,
}

/// Outcome from handling one relay-received compact block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionOutcome {
    DryRun(SubmissionCandidate),
    Submitted {
        candidate: SubmissionCandidate,
        result: Option<String>,
    },
}

/// Errors that prevent a relay block from being submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayBlockError {
    EmptyTransactions,
    MissingTransactions { short_ids: usize },
    NonContiguousPrefilledTx { expected: u16, actual: u16 },
    TooManyTransactions { count: usize },
    SubmitFailed(String),
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
            RelayBlockError::NonContiguousPrefilledTx { expected, actual } => write!(
                f,
                "prefilled transaction index {actual} is not contiguous at expected index {expected}"
            ),
            RelayBlockError::TooManyTransactions { count } => {
                write!(f, "transaction count {count} exceeds compactSize u64")
            }
            RelayBlockError::SubmitFailed(error) => write!(f, "submitblock failed: {error}"),
        }
    }
}

impl Error for RelayBlockError {}

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

    let mut txs = compact.prefilled_txs.clone();
    txs.sort_by_key(|tx| tx.index);
    for (expected, tx) in txs.iter().enumerate() {
        if expected > u16::MAX as usize {
            return Err(RelayBlockError::TooManyTransactions { count: txs.len() });
        }
        let expected = expected as u16;
        if tx.index != expected {
            return Err(RelayBlockError::NonContiguousPrefilledTx {
                expected,
                actual: tx.index,
            });
        }
    }

    let mut block = Vec::with_capacity(
        compact.header.len()
            + compact_size_len(txs.len())
            + txs.iter().map(|tx| tx.tx_data.len()).sum::<usize>(),
    );
    block.extend_from_slice(&compact.header);
    encode_compact_size(txs.len(), &mut block)?;
    for tx in &txs {
        block.extend_from_slice(&tx.tx_data);
    }

    Ok(SubmissionCandidate {
        block_hash: compact.header_hash().to_string(),
        block_hex: hex::encode(&block),
        tx_count: txs.len(),
        block_bytes: block.len(),
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
            Ok(SubmissionOutcome::Submitted { candidate, result })
        }
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
