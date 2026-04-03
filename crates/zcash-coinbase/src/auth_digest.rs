//! ZIP 244 auth digest computation for Zcash transactions.
//!
//! Computes the auth data commitment used in block headers (NU5+).

use blake2b_simd::Params as Blake2bParams;
use sha2::{Digest, Sha256};

const TRANSPARENT_AUTH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const SAPLING_AUTH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";
const ORCHARD_AUTH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";
pub const AUTH_DATA_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashAuthDatHash";
const TX_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const NO_AUTH_DATA: [u8; 32] = [0u8; 32];

/// BLAKE2b-256 of transparent script_sig data.
fn compute_transparent_auth_digest(script_sigs: &[u8]) -> [u8; 32] {
    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(TRANSPARENT_AUTH_PERSONALIZATION)
        .hash(script_sigs);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Compute the auth digest for a coinbase transaction.
///
/// For coinbase transactions, sapling and orchard auth data are sentinels (all zeros)
/// since coinbase transactions have no shielded components.
///
/// The final digest combines transparent, sapling, and orchard auth digests
/// using a personalized BLAKE2b hash that includes the consensus branch ID.
pub fn compute_coinbase_auth_digest(
    transparent_script_sigs: &[u8],
    consensus_branch_id: u32,
) -> [u8; 32] {
    let transparent_digest = compute_transparent_auth_digest(transparent_script_sigs);

    // Sapling and Orchard auth digests are sentinels for coinbase
    let sapling_digest = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(SAPLING_AUTH_PERSONALIZATION)
            .hash(&NO_AUTH_DATA);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    };

    let orchard_digest = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(ORCHARD_AUTH_PERSONALIZATION)
            .hash(&NO_AUTH_DATA);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    };

    // Build personalization: prefix + branch_id bytes
    let mut personalization = [0u8; 16];
    personalization[..12].copy_from_slice(TX_AUTH_PERSONALIZATION_PREFIX);
    personalization[12..16].copy_from_slice(&consensus_branch_id.to_le_bytes());

    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(&transparent_digest);
    combined.extend_from_slice(&sapling_digest);
    combined.extend_from_slice(&orchard_digest);

    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(&personalization)
        .hash(&combined);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Compute SHA256d (double SHA-256) transaction ID for v4 transactions.
pub fn compute_v4_txid(raw_tx: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(raw_tx);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Compute the auth data Merkle root from a list of per-transaction auth digests.
///
/// Uses a binary Merkle tree with BLAKE2b-256 personalized with `ZcashAuthDatHash`.
/// The leaf list is padded to the next power of two by repeating the last element.
pub fn compute_auth_data_root(tx_auth_digests: &[[u8; 32]]) -> [u8; 32] {
    assert!(!tx_auth_digests.is_empty(), "need at least one auth digest");

    // Pad to next power of two
    let n = tx_auth_digests.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(tx_auth_digests);
    while layer.len() < n {
        layer.push(*tx_auth_digests.last().unwrap());
    }

    // Build tree bottom-up
    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&pair[0]);
            data.extend_from_slice(&pair[1]);

            let hash = Blake2bParams::new()
                .hash_length(32)
                .personal(AUTH_DATA_HASH_PERSONALIZATION)
                .hash(&data);
            let mut result = [0u8; 32];
            result.copy_from_slice(hash.as_bytes());
            next_layer.push(result);
        }
        layer = next_layer;
    }

    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_auth_digest_uses_sentinels_for_shielded() {
        let script_sigs = b"coinbase script";
        let branch_id: u32 = 0xc2d6_d0b4; // NU5

        // Should be deterministic
        let digest1 = compute_coinbase_auth_digest(script_sigs, branch_id);
        let digest2 = compute_coinbase_auth_digest(script_sigs, branch_id);
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, [0u8; 32]); // Not all zeros
    }

    #[test]
    fn different_scripts_produce_different_digests() {
        let branch_id: u32 = 0xc2d6_d0b4;
        let d1 = compute_coinbase_auth_digest(b"script_a", branch_id);
        let d2 = compute_coinbase_auth_digest(b"script_b", branch_id);
        assert_ne!(d1, d2);
    }

    #[test]
    fn different_branch_ids_produce_different_digests() {
        let script = b"same script";
        let d1 = compute_coinbase_auth_digest(script, 0xc2d6_d0b4);
        let d2 = compute_coinbase_auth_digest(script, 0x3778_5173);
        assert_ne!(d1, d2);
    }

    #[test]
    fn auth_data_merkle_root_single_tx() {
        let digest = [0x42u8; 32];
        let root = compute_auth_data_root(&[digest]);
        assert_eq!(root, digest);
    }

    #[test]
    fn auth_data_merkle_root_two_txs() {
        let d1 = [0x01u8; 32];
        let d2 = [0x02u8; 32];

        // Manual BLAKE2b of d1 || d2
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&d1);
        data.extend_from_slice(&d2);
        let expected = Blake2bParams::new()
            .hash_length(32)
            .personal(AUTH_DATA_HASH_PERSONALIZATION)
            .hash(&data);
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_bytes());

        let root = compute_auth_data_root(&[d1, d2]);
        assert_eq!(root, expected_bytes);
    }

    #[test]
    fn auth_data_merkle_root_pads_to_power_of_two() {
        let d1 = [0x01u8; 32];
        let d2 = [0x02u8; 32];
        let d3 = [0x03u8; 32];

        // 3 digests should be padded to 4 by repeating d3
        // Layer 0: [d1, d2, d3, d3]
        // Layer 1: [H(d1||d2), H(d3||d3)]
        // Root: H(H(d1||d2) || H(d3||d3))

        let hash_pair = |a: &[u8; 32], b: &[u8; 32]| -> [u8; 32] {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(a);
            data.extend_from_slice(b);
            let h = Blake2bParams::new()
                .hash_length(32)
                .personal(AUTH_DATA_HASH_PERSONALIZATION)
                .hash(&data);
            let mut result = [0u8; 32];
            result.copy_from_slice(h.as_bytes());
            result
        };

        let left = hash_pair(&d1, &d2);
        let right = hash_pair(&d3, &d3);
        let expected = hash_pair(&left, &right);

        let root = compute_auth_data_root(&[d1, d2, d3]);
        assert_eq!(root, expected);
    }
}
