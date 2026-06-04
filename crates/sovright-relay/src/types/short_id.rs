//! Short transaction ID for compact block relay
//!
//! Per BIP 152, short IDs are 6-byte truncated SipHash values computed from
//! the wtxid using keys derived from the block header hash and a random nonce.

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

use super::WtxId;

/// 6-byte short transaction ID for compact block relay
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ShortId([u8; 6]);

impl ShortId {
    /// Create ShortId from raw bytes
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Compute short ID from wtxid using BIP 152 algorithm
    ///
    /// short_id = SipHash-2-4(k0, k1, wtxid)[0..6]
    /// where:
    ///   k0 = header_hash[0..8] as little-endian u64
    ///   k1 = header_hash[8..16] as little-endian u64 XOR nonce
    pub fn compute(wtxid: &WtxId, header_hash: &[u8; 32], nonce: u64) -> Self {
        let k0 = u64::from_le_bytes(header_hash[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(header_hash[8..16].try_into().unwrap()) ^ nonce;

        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(&wtxid.to_bytes());
        let hash = hasher.finish();

        let hash_bytes = hash.to_le_bytes();
        let mut short_id = [0u8; 6];
        short_id.copy_from_slice(&hash_bytes[0..6]);

        Self(short_id)
    }
}
