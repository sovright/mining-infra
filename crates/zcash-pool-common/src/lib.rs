//! Common types shared between pool server components
//!
//! This crate provides shared types used by both the pool server
//! and the JD server, avoiding circular dependencies.

pub mod compact_size;
pub mod payout;

pub use compact_size::{CompactSizeError, read_compact_size, write_compact_size};
pub use payout::{is_ephemeral_miner_id, MinerId, MinerStats, PayoutTracker, EPHEMERAL_MINER_PREFIX};
