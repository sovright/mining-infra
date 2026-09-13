//! Zcash's consensus block hash, and the serialized header layout it covers.
//!
//! This is the one implementation of that rule. It lives here because
//! `zcash-pool-common` has no internal dependencies, so every crate that needs
//! the consensus hash -- the validator, the test miner, the relay -- can reach
//! it without a dependency cycle.
//!
//! Note what this module is NOT: the relay's BLAKE2b-256 digest personalised
//! `"ZcashBlockHash"` is an internal object id for raw-segment dedup and
//! compact-block short IDs, and is a different value over the same bytes. See
//! `sovright_relay::hash`.

use sha2::{Digest, Sha256};

use crate::compact_size::encode_compact_size;

/// Offset of `nBits` within the fixed header: version(4) prev(32) merkle(32)
/// commitments(32) time(4). Offset 100 is `time`; reading `nBits` there
/// silently rejects every real header.
pub const BITS_OFFSET: usize = 104;

/// The fixed part of a Zcash block header, before the solution.
pub const BASE_HEADER_BYTES: usize = 140;

/// `CompactSize(1344)` is three bytes: `0xfd 0x40 0x05`.
pub const SOLUTION_PREFIX_BYTES: usize = 3;

/// Equihash (200,9) solution size: 512 * 21 bits / 8.
pub const SOLUTION_BYTES: usize = 1344;

/// The full serialized header the P2P network and `submitblock` carry:
/// `header(140) || CompactSize(1344) || solution(1344)`.
pub const ZCASH_FULL_HEADER_SIZE: usize =
    BASE_HEADER_BYTES + SOLUTION_PREFIX_BYTES + SOLUTION_BYTES;

/// Zcash's proof-of-work hash: the double-SHA256 of the full serialized block
/// header, in internal byte order.
///
/// This is the value an nBits-derived target must be compared against, and the
/// block id Zebra reports; explorers display its byte reversal.
pub fn consensus_block_hash(serialized_header: &[u8]) -> [u8; 32] {
    finish_sha256d(Sha256::new().chain_update(serialized_header))
}

/// The same rule computed from the parts, without serializing them first.
///
/// Equals `consensus_block_hash(header || CompactSize(solution.len()) ||
/// solution)`. `parts_and_serialized_agree_across_compact_size_widths` covers
/// the 1-, 3- and 5-byte CompactSize prefixes; the 9-byte encoding is checked
/// separately, against literal bytes, in `compact_size`'s own tests.
///
/// This hashes what it is given and does not validate it: callers that require
/// a 140-byte header or a 1344-byte solution check those separately, so a
/// length bug surfaces as a length error rather than a silently wrong digest.
pub fn consensus_block_hash_parts(header: &[u8], solution: &[u8]) -> [u8; 32] {
    let (prefix, prefix_len) = encode_compact_size(solution.len() as u64);
    finish_sha256d(
        Sha256::new()
            .chain_update(header)
            .chain_update(&prefix[..prefix_len])
            .chain_update(solution),
    )
}

/// The single SHA256d core: finish the first pass, then hash that digest.
/// Both entry points above go through here, so they cannot drift apart.
fn finish_sha256d(first_pass: Sha256) -> [u8; 32] {
    Sha256::digest(first_pass.finalize()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact_size::{MAX_COMPACT_SIZE_LEN, write_compact_size};

    fn serialize(header: &[u8], solution: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(header.len() + MAX_COMPACT_SIZE_LEN + solution.len());
        out.extend_from_slice(header);
        write_compact_size(solution.len() as u64, &mut out);
        out.extend_from_slice(solution);
        out
    }

    /// The two entry points must agree wherever the CompactSize prefix changes
    /// width. The lengths below cover the 1-, 3- and 5-byte prefixes; the
    /// 9-byte encoding is checked separately against literal bytes, in
    /// `compact_size::tests::test_encoding_width_boundaries`. Disagreement here
    /// is exactly the drift this module exists to prevent.
    #[test]
    fn parts_and_serialized_agree_across_compact_size_widths() {
        let header = [0xab; BASE_HEADER_BYTES];
        for len in [0usize, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, SOLUTION_BYTES] {
            let solution = vec![0x5a; len];
            assert_eq!(
                consensus_block_hash_parts(&header, &solution),
                consensus_block_hash(&serialize(&header, &solution)),
                "the two entry points disagree at solution length {len}"
            );
        }
    }

    /// Pins the core itself, not only the agreement of its two callers: the
    /// sha256d known-answer vector for the empty input.
    ///
    /// sha256("")  = e3b0c442...b855
    /// sha256(that) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    #[test]
    fn consensus_block_hash_is_double_sha256() {
        assert_eq!(
            consensus_block_hash(b""),
            [
                0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
                0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
                0x5d, 0x4c, 0x94, 0x56,
            ]
        );
    }

    #[test]
    fn full_header_size_is_the_serialized_length() {
        assert_eq!(ZCASH_FULL_HEADER_SIZE, 1487);
    }
}
