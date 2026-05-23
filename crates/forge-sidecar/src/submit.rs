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

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_forge::{CompactBlock, PrefilledTx};

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
}
