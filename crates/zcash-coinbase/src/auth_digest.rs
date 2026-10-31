//! The auth data Merkle root used in block commitments (NU5+).
//!
//! Per-transaction auth digests come from [`crate::digest`].

use blake2b_simd::Params as Blake2bParams;

/// BLAKE2b-256 personalization for auth data Merkle tree nodes (ZIP 244).
pub const AUTH_DATA_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashAuthDatHash";

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
