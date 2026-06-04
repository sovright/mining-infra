//! Zcash Mining Protocol for Stratum V2
//!
//! This crate defines the message types for Equihash mining:
//! - NewEquihashJob: Pool → Miner job distribution
//! - SubmitEquihashShare: Miner → Pool share submission
//! - Channel management messages

pub mod codec;
pub mod error;
pub mod messages;

pub use error::ProtocolError;
pub use messages::{NewEquihashJob, ShareResult, SubmitEquihashShare, SubmitSharesResponse};
