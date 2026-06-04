//! Error types for sovright-relay

use thiserror::Error;

use crate::types::ShortId;

/// Errors that can occur during compact block operations
#[derive(Error, Debug)]
pub enum CompactBlockError {
    /// Short ID collision detected (multiple wtxids map to same short ID)
    #[error("short ID collision detected: {0:?}")]
    ShortIdCollision(ShortId),

    /// Invalid prefilled transaction index
    #[error("invalid prefilled transaction index: {index} >= {tx_count}")]
    InvalidPrefilledIndex { index: usize, tx_count: usize },

    /// Compact block has wrong transaction count
    #[error("transaction count mismatch: expected {expected}, got {actual}")]
    TransactionCountMismatch { expected: usize, actual: usize },

    /// Block reconstruction failed after receiving blocktxn
    #[error("block reconstruction failed: still missing {missing_count} transactions")]
    ReconstructionFailed { missing_count: usize },

    /// Transaction index overflow for compact block requests
    #[error("transaction index overflow: {index}")]
    IndexOverflow { index: usize },

    /// Transaction indexes are not strictly increasing
    #[error("transaction indexes not strictly increasing: prev {prev}, current {current}")]
    InvalidIndexOrder { prev: usize, current: usize },
}
