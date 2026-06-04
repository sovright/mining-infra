//! Mempool interface for compact block reconstruction
//!
//! Defines the trait that mempool implementations must satisfy
//! for compact block reconstruction to work.

use crate::types::WtxId;

/// Error type for mempool operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction not found in mempool
    TransactionNotFound(WtxId),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::TransactionNotFound(wtxid) => {
                write!(f, "transaction not found in mempool: {:?}", wtxid)
            }
        }
    }
}

impl std::error::Error for MempoolError {}

/// Trait for mempool implementations to support compact block reconstruction
pub trait MempoolProvider {
    /// Get all wtxids currently in mempool
    fn get_wtxids(&self) -> Vec<WtxId>;

    /// Get transaction data by wtxid
    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>>;

    /// Check if transaction exists in mempool
    fn contains(&self, wtxid: &WtxId) -> bool {
        self.get_tx_data(wtxid).is_some()
    }
}

/// In-memory mempool implementation for testing
#[derive(Default)]
pub struct TestMempool {
    transactions: std::collections::HashMap<WtxId, Vec<u8>>,
}

impl TestMempool {
    /// Create empty test mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Add transaction to mempool
    pub fn insert(&mut self, wtxid: WtxId, tx_data: Vec<u8>) {
        self.transactions.insert(wtxid, tx_data);
    }

    /// Number of transactions in mempool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl MempoolProvider for TestMempool {
    fn get_wtxids(&self) -> Vec<WtxId> {
        self.transactions.keys().copied().collect()
    }

    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>> {
        self.transactions.get(wtxid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthDigest, TxId};

    #[test]
    fn test_mempool_insert_and_retrieve() {
        let mut mempool = TestMempool::new();

        let wtxid = WtxId::new(
            TxId::from_bytes([1u8; 32]),
            AuthDigest::from_bytes([2u8; 32]),
        );
        let tx_data = vec![0xde, 0xad, 0xbe, 0xef];

        mempool.insert(wtxid, tx_data.clone());

        assert!(mempool.contains(&wtxid));
        assert_eq!(mempool.get_tx_data(&wtxid), Some(tx_data));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_get_wtxids() {
        let mut mempool = TestMempool::new();

        let wtxid1 = WtxId::new(
            TxId::from_bytes([1u8; 32]),
            AuthDigest::from_bytes([1u8; 32]),
        );
        let wtxid2 = WtxId::new(
            TxId::from_bytes([2u8; 32]),
            AuthDigest::from_bytes([2u8; 32]),
        );

        mempool.insert(wtxid1, vec![1]);
        mempool.insert(wtxid2, vec![2]);

        let wtxids = mempool.get_wtxids();
        assert_eq!(wtxids.len(), 2);
        assert!(wtxids.contains(&wtxid1));
        assert!(wtxids.contains(&wtxid2));
    }

    #[test]
    fn test_mempool_not_found() {
        let mempool = TestMempool::new();

        let wtxid = WtxId::new(
            TxId::from_bytes([99u8; 32]),
            AuthDigest::from_bytes([99u8; 32]),
        );

        assert!(!mempool.contains(&wtxid));
        assert_eq!(mempool.get_tx_data(&wtxid), None);
    }
}
