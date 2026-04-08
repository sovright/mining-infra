//! Compact block reconstruction from mempool
//!
//! Reconstructs full blocks from compact block messages using local mempool.

use std::collections::HashMap;

use crate::compact_block::CompactBlock;
use crate::mempool::MempoolProvider;
use crate::types::{ShortId, WtxId};

/// Result of compact block reconstruction
#[derive(Debug)]
pub enum ReconstructionResult {
    /// Successfully reconstructed all transactions
    Complete {
        /// Transactions in block order
        transactions: Vec<Vec<u8>>,
    },
    /// Invalid compact block (malformed or inconsistent)
    Invalid {
        /// Human-readable reason
        reason: String,
    },
    /// Missing some transactions - need to request them
    Incomplete {
        /// Transactions we have (Some) and missing (None), in block order
        partial: Vec<Option<Vec<u8>>>,
        /// WtxIds of missing transactions (if identifiable)
        missing_wtxids: Vec<WtxId>,
        /// Short IDs we couldn't resolve
        unresolved_short_ids: Vec<ShortId>,
    },
}

/// Reconstructs full blocks from compact block messages
pub struct CompactBlockReconstructor<'a, M: MempoolProvider> {
    mempool: &'a M,
    /// Short ID to wtxid mapping computed from mempool
    short_id_map: HashMap<ShortId, Option<WtxId>>,
}

impl<'a, M: MempoolProvider> CompactBlockReconstructor<'a, M> {
    /// Create a new reconstructor with the given mempool
    pub fn new(mempool: &'a M) -> Self {
        Self {
            mempool,
            short_id_map: HashMap::new(),
        }
    }

    /// Precompute short ID mappings for a specific compact block
    pub fn prepare(&mut self, header_hash: &[u8; 32], nonce: u64) {
        self.short_id_map.clear();

        for wtxid in self.mempool.get_wtxids() {
            let short_id = ShortId::compute(&wtxid, header_hash, nonce);
            match self.short_id_map.get_mut(&short_id) {
                Some(entry) => {
                    // Collision: mark as unresolved so we request missing
                    *entry = None;
                }
                None => {
                    self.short_id_map.insert(short_id, Some(wtxid));
                }
            }
        }
    }

    /// Attempt to reconstruct a block from a compact block message
    pub fn reconstruct(&self, compact: &CompactBlock) -> ReconstructionResult {
        let total_tx_count = compact.tx_count();
        let mut transactions: Vec<Option<Vec<u8>>> = vec![None; total_tx_count];
        let mut missing_wtxids = Vec::new();
        let mut unresolved_short_ids = Vec::new();

        // First, fill in prefilled transactions
        let mut cumulative_offset = 0usize;

        for prefilled in &compact.prefilled_txs {
            // Differentially decoded index
            let position = cumulative_offset + prefilled.index as usize;
            if position < total_tx_count {
                if transactions[position].is_some() {
                    return ReconstructionResult::Invalid {
                        reason: format!("duplicate prefilled position {}", position),
                    };
                }
                transactions[position] = Some(prefilled.tx_data.clone());
                cumulative_offset = position + 1;
            } else {
                return ReconstructionResult::Invalid {
                    reason: format!(
                        "prefilled index {} out of bounds for {} txs",
                        position, total_tx_count
                    ),
                };
            }
        }

        // Then, resolve short IDs to transactions
        let mut short_id_iter = compact.short_ids.iter();
        for tx_slot in &mut transactions {
            if tx_slot.is_some() {
                // Already filled by prefilled
                continue;
            }

            let Some(&short_id) = short_id_iter.next() else {
                return ReconstructionResult::Invalid {
                    reason: "not enough short IDs for available slots".into(),
                };
            };

            match self.short_id_map.get(&short_id) {
                Some(Some(wtxid)) => {
                    if let Some(tx_data) = self.mempool.get_tx_data(wtxid) {
                        *tx_slot = Some(tx_data);
                    } else {
                        // In mempool when we computed map, but removed since
                        missing_wtxids.push(*wtxid);
                    }
                }
                Some(None) | None => {
                    // Collision or not in our mempool
                    unresolved_short_ids.push(short_id);
                }
            }
        }

        if short_id_iter.next().is_some() {
            return ReconstructionResult::Invalid {
                reason: "too many short IDs for available slots".into(),
            };
        }

        // Check if reconstruction is complete
        if transactions.iter().all(|t| t.is_some()) {
            ReconstructionResult::Complete {
                transactions: transactions.into_iter().map(|t| t.unwrap()).collect(),
            }
        } else {
            ReconstructionResult::Incomplete {
                partial: transactions,
                missing_wtxids,
                unresolved_short_ids,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CompactBlockBuilder;
    use crate::compact_block::CompactBlock;
    use crate::mempool::TestMempool;
    use crate::types::{AuthDigest, ShortId, TxId};

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[test]
    fn reconstruct_complete_block() {
        // Sender side: build compact block
        let header = vec![0u8; 2189];
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);
        let tx2 = make_wtxid(2);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);
        builder.add_transaction(tx2, vec![12]);

        // Sender's view of receiver's mempool (has tx1 and tx2)
        let mut sender_view = TestMempool::new();
        sender_view.insert(tx1, vec![11]);
        sender_view.insert(tx2, vec![12]);

        let compact = builder.build(&sender_view);

        // Receiver side: reconstruct
        let mut receiver_mempool = TestMempool::new();
        receiver_mempool.insert(tx1, vec![11]);
        receiver_mempool.insert(tx2, vec![12]);

        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);

        // Use same header hash computation as builder
        let header_hash = {
            use sha2::{Digest, Sha256};
            let first = Sha256::digest(&header);
            let second = Sha256::digest(first);
            let mut h = [0u8; 32];
            h.copy_from_slice(&second);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions.len(), 3);
                assert_eq!(transactions[0], vec![10]); // coinbase
                assert_eq!(transactions[1], vec![11]); // tx1
                assert_eq!(transactions[2], vec![12]); // tx2
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("Unexpected invalid reconstruction: {}", reason);
            }
            ReconstructionResult::Incomplete { .. } => {
                panic!("Expected complete reconstruction");
            }
        }
    }

    #[test]
    fn reconstruct_incomplete_block() {
        let header = vec![0u8; 2189];
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);

        // Sender thinks receiver has tx1
        let mut sender_view = TestMempool::new();
        sender_view.insert(tx1, vec![11]);

        let compact = builder.build(&sender_view);

        // But receiver's mempool is empty!
        let receiver_mempool = TestMempool::new();

        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
        let header_hash = {
            use sha2::{Digest, Sha256};
            let first = Sha256::digest(&header);
            let second = Sha256::digest(first);
            let mut h = [0u8; 32];
            h.copy_from_slice(&second);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Incomplete { unresolved_short_ids, .. } => {
                assert_eq!(unresolved_short_ids.len(), 1);
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("Unexpected invalid reconstruction: {}", reason);
            }
            ReconstructionResult::Complete { .. } => {
                panic!("Expected incomplete reconstruction");
            }
        }
    }

    #[test]
    fn reconstruct_marks_collision_unresolved() {
        let mempool = TestMempool::new();
        let mut reconstructor = CompactBlockReconstructor::new(&mempool);

        let short_id = ShortId::from_bytes([1, 2, 3, 4, 5, 6]);
        reconstructor.short_id_map.insert(short_id, None);

        let compact = CompactBlock::new(vec![0u8; 2189], 0, vec![short_id], vec![]);

        let result = reconstructor.reconstruct(&compact);
        match result {
            ReconstructionResult::Incomplete { unresolved_short_ids, .. } => {
                assert_eq!(unresolved_short_ids, vec![short_id]);
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("Unexpected invalid reconstruction: {}", reason);
            }
            ReconstructionResult::Complete { .. } => {
                panic!("Expected unresolved short ID due to collision");
            }
        }
    }

    #[test]
    fn reconstruct_coinbase_only_block() {
        let header = vec![0u8; 2189];
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);

        // No transactions in mempool (only coinbase, which is prefilled)
        let sender_view = TestMempool::new();
        let compact = builder.build(&sender_view);

        let receiver_mempool = TestMempool::new();
        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);

        let header_hash = {
            use sha2::{Digest, Sha256};
            let first = Sha256::digest(&header);
            let second = Sha256::digest(first);
            let mut h = [0u8; 32];
            h.copy_from_slice(&second);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions.len(), 1);
                assert_eq!(transactions[0], vec![10]); // coinbase only
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("Unexpected invalid reconstruction: {}", reason);
            }
            ReconstructionResult::Incomplete { .. } => {
                panic!("Expected complete reconstruction");
            }
        }
    }

    #[test]
    fn reconstruct_large_block() {
        let header = vec![0u8; 2189];
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![0; 100]);

        let mut sender_view = TestMempool::new();
        let mut receiver_mempool = TestMempool::new();

        for i in 1u8..=200 {
            let wtxid = make_wtxid(i);
            let tx_data = vec![i; 100];
            builder.add_transaction(wtxid, tx_data.clone());
            sender_view.insert(wtxid, tx_data.clone());
            receiver_mempool.insert(wtxid, tx_data);
        }

        let compact = builder.build(&sender_view);

        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);

        let header_hash = {
            use sha2::{Digest, Sha256};
            let first = Sha256::digest(&header);
            let second = Sha256::digest(first);
            let mut h = [0u8; 32];
            h.copy_from_slice(&second);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions.len(), 201); // coinbase + 200
                assert_eq!(transactions[0], vec![0; 100]); // coinbase
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("Unexpected invalid reconstruction: {}", reason);
            }
            ReconstructionResult::Incomplete { .. } => {
                panic!("Expected complete reconstruction");
            }
        }
    }

    #[test]
    fn reconstruct_empty_block() {
        let mempool = TestMempool::new();
        let mut reconstructor = CompactBlockReconstructor::new(&mempool);

        let header = vec![0u8; 2189];
        let nonce = 0u64;

        let header_hash = {
            use sha2::{Digest, Sha256};
            let first = Sha256::digest(&header);
            let second = Sha256::digest(first);
            let mut h = [0u8; 32];
            h.copy_from_slice(&second);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let compact = CompactBlock::new(vec![0u8; 2189], 0, vec![], vec![]);

        let result = reconstructor.reconstruct(&compact);
        match result {
            ReconstructionResult::Complete { transactions } => {
                assert!(transactions.is_empty());
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("Unexpected invalid reconstruction: {}", reason);
            }
            ReconstructionResult::Incomplete { .. } => {
                panic!("Expected complete reconstruction");
            }
        }
    }
}
