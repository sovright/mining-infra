//! Transport layer error types

use std::io;
use thiserror::Error;

use crate::fec::FecError;

/// Errors that can occur during relay transport
#[derive(Error, Debug)]
pub enum TransportError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// FEC error
    #[error("FEC error: {0}")]
    Fec(#[from] FecError),

    /// Invalid chunk received
    #[error("invalid chunk: {0}")]
    InvalidChunk(String),

    /// Authentication failed
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Session timeout
    #[error("session timeout")]
    Timeout,

    /// Block assembly incomplete
    #[error("block assembly incomplete: received {received}/{total} chunks")]
    IncompleteBlock { received: usize, total: usize },

    /// PoW validation failed
    #[error("PoW validation failed")]
    InvalidPow,

    /// Connection refused
    #[error("connection refused: {0}")]
    ConnectionRefused(String),
}
