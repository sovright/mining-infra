//! Zcash block hash helpers.

use blake2b_simd::Params;
use sha2::{Digest, Sha256};

/// Compute the relay's internal BLAKE2b-256 block object id for a serialized
/// block header, using the `ZcashBlockHash` personalization.
///
/// NOTE: despite the personalization string, this is NOT the Zcash *consensus*
/// block hash. The consensus block id used by Zebra, explorers, and the P2P
/// network is the double-SHA256 of the header (see [`consensus_block_hash`]).
/// This BLAKE2b value is only the relay's internal object identifier for raw
/// segment dedup/reassembly and must not be used to cross-reference blocks with
/// Zebra or the P2P ingress.
pub fn zcash_block_hash(header: &[u8]) -> [u8; 32] {
    let hash = Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockHash\0\0")
        .hash(header);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Compute the Zcash *consensus* block hash (double-SHA256 of the serialized
/// block header) in internal byte order.
///
/// This is the block id Zebra and the P2P network use; explorers and
/// `getblockhash` display its byte reversal (see [`consensus_block_hash_display`]).
pub fn consensus_block_hash(header: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// The Zcash consensus block hash in DISPLAY (big-endian) hex, matching Zebra's
/// `getblockhash`, block explorers, and the P2P-ingress `hash` field. This is the
/// value to log so submit outcomes can be cross-referenced with ingress receipts.
pub fn consensus_block_hash_display(header: &[u8]) -> String {
    let mut bytes = consensus_block_hash(header);
    bytes.reverse();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_block_hash_is_double_sha256() {
        // sha256d(b"") known-answer vector.
        // sha256("")  = e3b0c442...b855
        // sha256(that)= 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let internal = consensus_block_hash(b"");
        assert_eq!(
            hex::encode(internal),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
        // Display form is the byte reversal.
        assert_eq!(
            consensus_block_hash_display(b""),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d"
        );
    }

    #[test]
    fn consensus_and_object_hashes_differ() {
        // The relay BLAKE2b object id must never be confused with the consensus
        // double-SHA256 id; they are different functions over the same bytes.
        let header = [0xab_u8; 1487];
        assert_ne!(zcash_block_hash(&header), consensus_block_hash(&header));
    }
}
