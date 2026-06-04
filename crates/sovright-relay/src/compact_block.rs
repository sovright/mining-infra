//! Compact block message types for bandwidth-efficient block relay
//!
//! Implements BIP 152 compact block semantics adapted for Zcash.

use crate::types::{BlockHash, ShortId};

/// Prefilled transaction in a compact block
#[derive(Clone, Debug)]
pub struct PrefilledTx {
    /// Index in the block (differentially encoded in wire format)
    pub index: u16,
    /// Full transaction data (opaque bytes for now)
    pub tx_data: Vec<u8>,
}

/// Compact block message
#[derive(Clone, Debug)]
pub struct CompactBlock {
    /// Block header (2189 bytes for Zcash including Equihash solution)
    pub header: Vec<u8>,
    /// Random nonce for short ID calculation
    pub nonce: u64,
    /// Short transaction IDs
    pub short_ids: Vec<ShortId>,
    /// Prefilled transactions (always includes coinbase)
    pub prefilled_txs: Vec<PrefilledTx>,
}

impl CompactBlock {
    /// Create a new compact block
    pub fn new(
        header: Vec<u8>,
        nonce: u64,
        short_ids: Vec<ShortId>,
        prefilled_txs: Vec<PrefilledTx>,
    ) -> Self {
        Self {
            header,
            nonce,
            short_ids,
            prefilled_txs,
        }
    }

    /// Get the block header hash for short ID calculation
    ///
    /// Note: In production, this would compute double-SHA256 of header.
    /// For now we require it to be passed in.
    pub fn header_hash(&self) -> BlockHash {
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(&self.header);
        let second = Sha256::digest(first);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second);
        BlockHash::from_bytes(hash)
    }

    /// Total number of transactions in the original block
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled_txs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthDigest, TxId, WtxId};

    #[test]
    fn compact_block_construction() {
        let header = vec![0u8; 2189]; // Zcash header size
        let nonce = 0x123456789abcdef0u64;

        let wtxid = WtxId::new(
            TxId::from_bytes([0xaa; 32]),
            AuthDigest::from_bytes([0xbb; 32]),
        );
        let header_hash = [0u8; 32];
        let short_id = ShortId::compute(&wtxid, &header_hash, nonce);

        let prefilled = PrefilledTx {
            index: 0,
            tx_data: vec![0u8; 100], // Coinbase placeholder
        };

        let compact = CompactBlock::new(
            header,
            nonce,
            vec![short_id],
            vec![prefilled],
        );

        assert_eq!(compact.tx_count(), 2); // 1 short_id + 1 prefilled
        assert_eq!(compact.nonce, nonce);
    }

    #[test]
    fn prefilled_tx_includes_coinbase() {
        let compact = CompactBlock::new(
            vec![0u8; 2189],
            0,
            vec![],
            vec![PrefilledTx { index: 0, tx_data: vec![1, 2, 3] }],
        );

        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);
    }
}
