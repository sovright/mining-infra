//! Pool server error types

use thiserror::Error;
use zcash_equihash_validator::ValidationError;
use zcash_mining_protocol::ProtocolError;

#[derive(Error, Debug)]
pub enum PoolError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Unknown channel: {0}")]
    UnknownChannel(u32),

    #[error("Unknown job: {0}")]
    UnknownJob(u32),

    #[error("Stale share for job {0}")]
    StaleShare(u32),

    #[error("Duplicate share")]
    DuplicateShare,

    #[error("Channel send error")]
    ChannelSend,

    #[error("Operation timed out")]
    Timeout,

    #[error("Template provider error: {0}")]
    TemplateProvider(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Server shutdown")]
    Shutdown,
}

pub type Result<T> = std::result::Result<T, PoolError>;
