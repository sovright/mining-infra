//! Network message types for compact block protocol
//!
//! Implements the request/response messages needed for compact block relay.

use crate::error::CompactBlockError;
use crate::types::BlockHash;

/// Request for specific transactions from a block (getblocktxn)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBlockTxn {
    /// Hash of the block containing the transactions
    pub block_hash: BlockHash,
    /// Indices of requested transactions (differentially encoded)
    pub indexes: Vec<u16>,
}

impl GetBlockTxn {
    /// Create a new request
    pub fn new(block_hash: BlockHash, indexes: Vec<u16>) -> Self {
        Self { block_hash, indexes }
    }

    /// Create request for unresolved short IDs after reconstruction failure
    ///
    /// Converts absolute indexes to differential encoding.
    /// For example, [0, 5, 6, 10] becomes [0, 4, 0, 3] where each value
    /// is the offset from the previous position+1.
    pub fn from_missing_indexes(
        block_hash: BlockHash,
        missing: &[usize],
    ) -> Result<Self, CompactBlockError> {
        // Convert absolute indexes to differential encoding
        let mut indexes = Vec::with_capacity(missing.len());
        let mut prev = 0usize;

        for &idx in missing {
            if idx < prev {
                return Err(CompactBlockError::InvalidIndexOrder {
                    prev: prev.saturating_sub(1),
                    current: idx,
                });
            }
            let diff = idx.saturating_sub(prev);
            let diff_u16 = u16::try_from(diff)
                .map_err(|_| CompactBlockError::IndexOverflow { index: idx })?;
            indexes.push(diff_u16);
            prev = idx + 1;
        }

        Ok(Self { block_hash, indexes })
    }
}

/// Response with requested transactions (blocktxn)
#[derive(Clone, Debug)]
pub struct BlockTxn {
    /// Hash of the block
    pub block_hash: BlockHash,
    /// Requested transactions in order
    pub transactions: Vec<Vec<u8>>,
}

impl BlockTxn {
    /// Create a new response
    pub fn new(block_hash: BlockHash, transactions: Vec<Vec<u8>>) -> Self {
        Self {
            block_hash,
            transactions,
        }
    }
}

/// High-bandwidth mode announcement (sendcmpct)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendCmpct {
    /// Whether high-bandwidth mode is requested
    pub high_bandwidth: bool,
    /// Protocol version (1 for BIP 152)
    pub version: u64,
}

impl SendCmpct {
    /// Create announcement for high-bandwidth mode
    ///
    /// In high-bandwidth mode, compact blocks are sent immediately
    /// without waiting for a block announcement.
    pub fn high_bandwidth() -> Self {
        Self {
            high_bandwidth: true,
            version: 1,
        }
    }

    /// Create announcement for low-bandwidth mode
    ///
    /// In low-bandwidth mode, a block announcement is sent first,
    /// and compact blocks are only sent upon request.
    pub fn low_bandwidth() -> Self {
        Self {
            high_bandwidth: false,
            version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_block_txn_creation() {
        let hash = BlockHash::from_bytes([1u8; 32]);
        let indexes = vec![0, 5, 10];

        let msg = GetBlockTxn::new(hash, indexes.clone());

        assert_eq!(msg.block_hash, hash);
        assert_eq!(msg.indexes, indexes);
    }

    #[test]
    fn get_block_txn_from_missing_indexes() {
        let hash = BlockHash::from_bytes([1u8; 32]);
        // Missing transactions at positions 0, 5, 6, 10
        let missing = vec![0, 5, 6, 10];

        let msg = GetBlockTxn::from_missing_indexes(hash, &missing).unwrap();

        // Differential encoding: 0, 5-1=4, 6-6=0, 10-7=3
        assert_eq!(msg.indexes, vec![0, 4, 0, 3]);
    }

    #[test]
    fn get_block_txn_rejects_overflow() {
        let hash = BlockHash::from_bytes([1u8; 32]);
        let missing = vec![0, u16::MAX as usize + 2];

        let err = GetBlockTxn::from_missing_indexes(hash, &missing).unwrap_err();
        match err {
            CompactBlockError::IndexOverflow { .. } => {}
            _ => panic!("Expected IndexOverflow error"),
        }
    }

    #[test]
    fn get_block_txn_rejects_out_of_order() {
        let hash = BlockHash::from_bytes([1u8; 32]);
        let missing = vec![2, 1];

        let err = GetBlockTxn::from_missing_indexes(hash, &missing).unwrap_err();
        match err {
            CompactBlockError::InvalidIndexOrder { .. } => {}
            _ => panic!("Expected InvalidIndexOrder error"),
        }
    }

    #[test]
    fn block_txn_creation() {
        let hash = BlockHash::from_bytes([2u8; 32]);
        let txs = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let msg = BlockTxn::new(hash, txs.clone());

        assert_eq!(msg.block_hash, hash);
        assert_eq!(msg.transactions, txs);
    }

    #[test]
    fn send_cmpct_modes() {
        let high = SendCmpct::high_bandwidth();
        assert!(high.high_bandwidth);
        assert_eq!(high.version, 1);

        let low = SendCmpct::low_bandwidth();
        assert!(!low.high_bandwidth);
        assert_eq!(low.version, 1);
    }
}
