//! Zcash block hash helpers.

use blake2b_simd::Params;

/// Compute the canonical Zcash block hash for a serialized block header.
///
/// Zcash uses BLAKE2b-256 with the `ZcashBlockHash` personalization for block
/// header IDs. The returned bytes are the raw consensus hash bytes, not the
/// reversed display form used by explorers.
pub fn zcash_block_hash(header: &[u8]) -> [u8; 32] {
    let hash = Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockHash\0\0")
        .hash(header);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}
