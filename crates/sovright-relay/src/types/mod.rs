//! Core types for Zcash transaction and block identifiers

mod block;
mod short_id;
mod txid;

pub use block::BlockHash;
pub use short_id::ShortId;
pub use txid::{TxId, WtxId, AuthDigest};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_from_bytes() {
        let bytes = [0u8; 32];
        let txid = TxId::from_bytes(bytes);
        assert_eq!(txid.as_bytes(), &bytes);
    }

    #[test]
    fn txid_from_hex() {
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let txid = TxId::from_hex(hex_str).unwrap();
        assert_eq!(txid.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn wtxid_combines_txid_and_auth_digest() {
        let txid = TxId::from_bytes([1u8; 32]);
        let auth = AuthDigest::from_bytes([2u8; 32]);
        let wtxid = WtxId::new(txid, auth);

        assert_eq!(wtxid.txid().as_bytes(), &[1u8; 32]);
        assert_eq!(wtxid.auth_digest().as_bytes(), &[2u8; 32]);
    }

    #[test]
    fn short_id_is_6_bytes() {
        let short_id = ShortId::from_bytes([1, 2, 3, 4, 5, 6]);
        assert_eq!(short_id.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn short_id_computes_from_wtxid_with_nonce() {
        // Per BIP 152: short_id = SipHash-2-4(k0, k1, wtxid)[0..6]
        // where k0 = block_header_hash[0..8], k1 = block_header_hash[8..16] XOR nonce
        let wtxid = WtxId::new(
            TxId::from_bytes([0xaa; 32]),
            AuthDigest::from_bytes([0xbb; 32]),
        );
        let header_hash = [0x11; 32];
        let nonce: u64 = 0x1234567890abcdef;

        let short_id = ShortId::compute(&wtxid, &header_hash, nonce);

        // Should produce consistent 6-byte result
        assert_eq!(short_id.as_bytes().len(), 6);

        // Same inputs should produce same output
        let short_id2 = ShortId::compute(&wtxid, &header_hash, nonce);
        assert_eq!(short_id, short_id2);
    }

    #[test]
    fn block_hash_from_bytes() {
        let bytes = [0xffu8; 32];
        let hash = BlockHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn block_hash_from_hex() {
        let hex_str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let hash = BlockHash::from_hex(hex_str).unwrap();
        assert_eq!(hash.as_bytes(), &[0xff; 32]);
    }
}
