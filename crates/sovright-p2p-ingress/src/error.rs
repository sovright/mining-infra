use std::io;

#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("wire error: {0}")]
    Wire(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("relay error: {0}")]
    Relay(String),
}

pub type Result<T> = std::result::Result<T, IngressError>;
