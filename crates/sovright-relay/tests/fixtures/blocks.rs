//! Block test fixtures

use sovright_relay::{BlockHash, TxId};

/// A test block with header and transactions
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TestBlock {
    /// Full block header (140 bytes + equihash solution)
    pub header: Vec<u8>,
    /// Block hash
    pub hash: BlockHash,
    /// Transactions (txid -> raw tx bytes)
    pub transactions: Vec<(TxId, Vec<u8>)>,
}

impl TestBlock {
    /// Create a new test block
    pub fn new(header: Vec<u8>, hash: BlockHash, transactions: Vec<(TxId, Vec<u8>)>) -> Self {
        Self {
            header,
            hash,
            transactions,
        }
    }

    /// Get total serialized size
    pub fn total_size(&self) -> usize {
        self.header.len() + self.transactions.iter().map(|(_, tx)| tx.len()).sum::<usize>()
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Create a synthetic test block with valid structure but fake PoW
pub fn create_synthetic_block(tx_count: usize, tx_size: usize) -> TestBlock {
    // Create fake header (140 bytes header + 3 bytes compactSize + 1344 bytes solution)
    let mut header = vec![0u8; 1487];
    // Version
    header[0..4].copy_from_slice(&4u32.to_le_bytes());
    // Set some distinguishing bytes
    header[4] = 0xAB;
    header[5] = 0xCD;

    // Create block hash from header
    let hash = BlockHash::from_bytes({
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&header[..140]);
        let first = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(&first);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    // Create synthetic transactions
    let mut transactions = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let mut tx_data = vec![0u8; tx_size];
        // Put index in first 4 bytes for uniqueness
        tx_data[0..4].copy_from_slice(&(i as u32).to_le_bytes());

        // Compute txid (double SHA256)
        let txid = TxId::from_bytes({
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&tx_data);
            let first = hasher.finalize();
            let mut hasher = Sha256::new();
            hasher.update(&first);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        });

        transactions.push((txid, tx_data));
    }

    TestBlock::new(header, hash, transactions)
}

/// Create a realistic testnet-like block
pub fn create_testnet_block() -> TestBlock {
    // Typical testnet block: ~50 transactions, ~300 bytes each
    create_synthetic_block(50, 300)
}

/// Create a large stress test block
#[allow(dead_code)]
pub fn create_large_block() -> TestBlock {
    // Large block: 2500 transactions, ~500 bytes each (~1.25 MB)
    create_synthetic_block(2500, 500)
}

/// Create a minimal block (coinbase only)
#[allow(dead_code)]
pub fn create_minimal_block() -> TestBlock {
    create_synthetic_block(1, 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_block_creation() {
        let block = create_synthetic_block(10, 250);
        assert_eq!(block.tx_count(), 10);
        assert_eq!(block.header.len(), 1487);
        // Header + 10 txs of 250 bytes
        assert_eq!(block.total_size(), 1487 + 10 * 250);
    }

    #[test]
    fn testnet_block_reasonable_size() {
        let block = create_testnet_block();
        assert!(block.tx_count() >= 10);
        assert!(block.total_size() > 10_000); // At least 10KB
    }
}
