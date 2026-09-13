//! Common types shared between pool server components
//!
//! This crate provides shared types used by both the pool server
//! and the JD server, avoiding circular dependencies.

pub mod block_hash;
pub mod compact_size;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
pub mod payout;

pub use block_hash::{
    BASE_HEADER_BYTES, BITS_OFFSET, SOLUTION_BYTES, SOLUTION_PREFIX_BYTES, ZCASH_FULL_HEADER_SIZE,
    consensus_block_hash, consensus_block_hash_parts,
};
pub use compact_size::{
    CompactSizeError, MAX_COMPACT_SIZE_LEN, encode_compact_size, read_compact_size,
    write_compact_size,
};
pub use payout::{
    EPHEMERAL_MINER_PREFIX, MAX_PERSISTED_WORKERS, MinerId, MinerStats, PayoutTracker,
    is_ephemeral_miner_id,
};
