//! FEC error types

use thiserror::Error;

/// Errors that can occur during FEC operations
#[derive(Error, Debug)]
pub enum FecError {
    /// Not enough shards to reconstruct data
    #[error("insufficient shards: need {required}, have {available}")]
    InsufficientShards { required: usize, available: usize },

    /// Invalid shard configuration
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Reed-Solomon encoding failed
    #[error("encoding failed: {0}")]
    EncodingFailed(String),

    /// Reed-Solomon decoding failed
    #[error("decoding failed: {0}")]
    DecodingFailed(String),

    /// Data too large for configured shard count
    #[error("data too large: {size} bytes exceeds max {max} bytes")]
    DataTooLarge { size: usize, max: usize },
}
