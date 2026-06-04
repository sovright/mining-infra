//! Compact block construction from full blocks
//!
//! Builds CompactBlock messages from full block data and mempool state.

use crate::compact_block::{CompactBlock, PrefilledTx};
use crate::mempool::MempoolProvider;
use crate::types::{ShortId, WtxId};

/// Builder for constructing compact blocks
pub struct CompactBlockBuilder {
    header: Vec<u8>,
    nonce: u64,
    /// Transactions with their wtxids, in block order
    transactions: Vec<(WtxId, Vec<u8>)>,
}

impl CompactBlockBuilder {
    /// Create a new builder with block header and nonce
    pub fn new(header: Vec<u8>, nonce: u64) -> Self {
        Self {
            header,
            nonce,
            transactions: Vec::new(),
        }
    }

    /// Add a transaction (in block order, coinbase first)
    pub fn add_transaction(&mut self, wtxid: WtxId, tx_data: Vec<u8>) {
        self.transactions.push((wtxid, tx_data));
    }

    /// Build compact block, prefilling transactions not in peer's mempool
    ///
    /// Always prefills the coinbase transaction (index 0).
    /// Other transactions are prefilled if not in the provided mempool wtxids.
    pub fn build<M: MempoolProvider>(self, peer_mempool: &M) -> CompactBlock {
        let peer_wtxids: std::collections::HashSet<_> =
            peer_mempool.get_wtxids().into_iter().collect();

        let header_hash = self.compute_header_hash();

        let mut short_ids = Vec::new();
        let mut prefilled_txs = Vec::new();
        let mut last_prefilled_index: isize = -1;

        for (block_index, (wtxid, tx_data)) in self.transactions.into_iter().enumerate() {
            let is_coinbase = block_index == 0;
            let in_peer_mempool = peer_wtxids.contains(&wtxid);

            if is_coinbase || !in_peer_mempool {
                // Prefill this transaction
                // Index is differentially encoded relative to last prefilled index
                let diff = (block_index as isize) - last_prefilled_index - 1;
                prefilled_txs.push(PrefilledTx {
                    index: diff as u16,
                    tx_data,
                });
                last_prefilled_index = block_index as isize;
            } else {
                // Use short ID
                short_ids.push(ShortId::compute(&wtxid, &header_hash, self.nonce));
            }
        }

        CompactBlock::new(self.header, self.nonce, short_ids, prefilled_txs)
    }

    /// Compute header hash for short ID calculation
    fn compute_header_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(&self.header);
        let second = Sha256::digest(first);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::TestMempool;
    use crate::types::{AuthDigest, TxId};

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[test]
    fn builder_always_prefills_coinbase() {
        let mut builder = CompactBlockBuilder::new(vec![0u8; 2189], 12345);

        let coinbase_wtxid = make_wtxid(0);
        builder.add_transaction(coinbase_wtxid, vec![1, 2, 3]);

        // Even if coinbase is "in mempool", it should be prefilled
        let mut mempool = TestMempool::new();
        mempool.insert(coinbase_wtxid, vec![1, 2, 3]);

        let compact = builder.build(&mempool);

        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);
        assert_eq!(compact.short_ids.len(), 0);
    }

    #[test]
    fn builder_uses_short_ids_for_mempool_txs() {
        let mut builder = CompactBlockBuilder::new(vec![0u8; 2189], 12345);

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);
        let tx2 = make_wtxid(2);

        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);
        builder.add_transaction(tx2, vec![12]);

        // tx1 is in mempool, tx2 is not
        let mut mempool = TestMempool::new();
        mempool.insert(tx1, vec![11]);

        let compact = builder.build(&mempool);

        // Coinbase + tx2 prefilled, tx1 as short_id
        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.short_ids.len(), 1);
    }

    #[test]
    fn builder_prefills_missing_txs() {
        let mut builder = CompactBlockBuilder::new(vec![0u8; 2189], 12345);

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);

        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);

        // Empty mempool - everything should be prefilled
        let mempool = TestMempool::new();

        let compact = builder.build(&mempool);

        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.short_ids.len(), 0);
    }
}
