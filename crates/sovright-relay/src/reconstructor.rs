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
            let filled: Vec<Vec<u8>> = transactions.into_iter().map(|t| t.unwrap()).collect();
            // Every slot being filled means only that reconstruction ran out of
            // holes. A 6-byte short id is not a commitment: it can collide, and
            // our mempool copy of a transaction can differ from the one the
            // miner actually included. The header's merkle root IS the
            // commitment, so it is the only thing that can promise this is the
            // block the header describes.
            //
            // Without this the sidecar submitted unverified assemblies and let
            // Zebra be the validator, which rejected them -- spending the fast
            // path's entire latency advantage to learn something knowable
            // locally. Returning Invalid falls back to getblocktxn / raw block.
            if !crate::merkle::transactions_match_merkle_root(&compact.header, &filled) {
                // Emit enough to identify the offending slot offline. The block
                // is on-chain moments later, so logging the consensus hash plus
                // our own per-slot txids makes the failure joinable against
                // `getblock <hash> 1`: whichever index disagrees is the
                // transaction we substituted, and the counter alone can never
                // say which one that was.
                //
                // Prefilled slots are excluded: their bytes come from the
                // compact block itself, so they cannot be the substitution.
                let prefilled_positions = prefilled_positions(compact);
                let expected = crate::merkle::header_merkle_root(&compact.header)
                    .map(|root| crate::merkle::display_hex(&root))
                    .unwrap_or_else(|| "short-header".to_string());
                let txids: Vec<[u8; 32]> = filled
                    .iter()
                    .map(|tx| crate::merkle::txid_from_tx_bytes(tx))
                    .collect();
                let computed = crate::merkle::merkle_root(&txids)
                    .map(|root| crate::merkle::display_hex(&root))
                    .unwrap_or_else(|| "no-transactions".to_string());
                tracing::warn!(
                    consensus_block_hash =
                        %crate::consensus_block_hash_display(&compact.header),
                    expected_merkle_root = %expected,
                    computed_merkle_root = %computed,
                    tx_count = filled.len(),
                    prefilled_count = prefilled_positions.len(),
                    mempool_slots = %crate::merkle::mempool_slot_digest(
                        &filled,
                        &prefilled_positions,
                    ),
                    "Reconstruction merkle mismatch; slots listed are mempool-resolved"
                );
                return ReconstructionResult::Invalid {
                    reason: "merkle root mismatch".into(),
                };
            }
            ReconstructionResult::Complete {
                transactions: filled,
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

/// Block indexes a compact block prefills, decoding BIP-152 differential
/// indexes the same way `reconstruct` does.
///
/// Kept beside the decoder it mirrors: if one changes, the diagnostic that
/// names the guilty slot must change with it, or it will point at the wrong
/// transaction.
fn prefilled_positions(compact: &CompactBlock) -> Vec<usize> {
    let mut positions = Vec::with_capacity(compact.prefilled_txs.len());
    let mut cumulative_offset = 0usize;
    for prefilled in &compact.prefilled_txs {
        let position = cumulative_offset + prefilled.index as usize;
        positions.push(position);
        cumulative_offset = position + 1;
    }
    positions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CompactBlockBuilder;
    use crate::compact_block::{CompactBlock, PrefilledTx};
    use crate::mempool::TestMempool;
    use crate::types::{AuthDigest, ShortId, TxId};

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    /// A synthetic header that actually commits to `txs`.
    ///
    /// Reconstruction now verifies the merkle root, so a test using an
    /// all-zero header would only ever prove that the check rejects garbage.
    /// Committing properly keeps these tests about slot filling, which is what
    /// they are for; real headers and real ZIP-244 txids are covered by the
    /// mainnet block fixture in `crate::merkle`.
    fn header_committing_to(txs: &[Vec<u8>]) -> Vec<u8> {
        let mut header = vec![0u8; 2189];
        let txids: Vec<[u8; 32]> = txs
            .iter()
            .map(|t| crate::merkle::txid_from_tx_bytes(t))
            .collect();
        let root = crate::merkle::merkle_root(&txids).expect("tests commit to >=1 tx");
        header[36..68].copy_from_slice(&root);
        header
    }

    #[test]
    fn reconstruct_complete_block() {
        // Sender side: build compact block
        let header = header_committing_to(&[vec![10], vec![11], vec![12]]);
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

        let header_hash = crate::zcash_block_hash(&header);
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
        let header_hash = crate::zcash_block_hash(&header);
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Incomplete {
                unresolved_short_ids,
                ..
            } => {
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
            ReconstructionResult::Incomplete {
                unresolved_short_ids,
                ..
            } => {
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
        let header = header_committing_to(&[vec![10]]);
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);

        // No transactions in mempool (only coinbase, which is prefilled)
        let sender_view = TestMempool::new();
        let compact = builder.build(&sender_view);

        let receiver_mempool = TestMempool::new();
        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);

        let header_hash = crate::zcash_block_hash(&header);
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
        let mut block_txs: Vec<Vec<u8>> = vec![vec![0; 100]];
        block_txs.extend((1u8..=200).map(|i| vec![i; 100]));
        let header = header_committing_to(&block_txs);
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

        let header_hash = crate::zcash_block_hash(&header);
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

        let header_hash = crate::zcash_block_hash(&header);
        reconstructor.prepare(&header_hash, nonce);

        let compact = CompactBlock::new(vec![0u8; 2189], 0, vec![], vec![]);

        // A zero-transaction block cannot exist on mainnet -- every block has a
        // coinbase -- and nothing commits to it, so there is no root to check
        // against. This used to reconstruct "successfully" into an empty block;
        // it is now rejected rather than handed to submit.
        match reconstructor.reconstruct(&compact) {
            ReconstructionResult::Invalid { reason } => {
                assert_eq!(reason, "merkle root mismatch");
            }
            other => panic!("expected a zero-transaction block to be invalid: {other:?}"),
        }
    }

    /// The defect this check exists for: every slot fills, but one transaction
    /// is not the one the header commits to. Before the merkle check this
    /// returned Complete and the sidecar submitted it to Zebra, which rejected
    /// it as invalid ~0.5s later -- after the fast path's advantage was spent.
    #[test]
    fn reconstruct_rejects_a_substituted_transaction() {
        let nonce = 12345u64;
        let header = header_committing_to(&[vec![10], vec![11]]);

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);

        let mut sender_view = TestMempool::new();
        sender_view.insert(tx1, vec![11]);
        let compact = builder.build(&sender_view);

        // The receiver holds a DIFFERENT transaction under the same wtxid --
        // what a short-id collision or a stale mempool copy looks like.
        let mut receiver_mempool = TestMempool::new();
        receiver_mempool.insert(tx1, vec![99]);

        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
        let header_hash = crate::zcash_block_hash(&header);
        reconstructor.prepare(&header_hash, nonce);

        match reconstructor.reconstruct(&compact) {
            ReconstructionResult::Invalid { reason } => {
                assert_eq!(reason, "merkle root mismatch");
            }
            other => panic!("expected a substituted transaction to be invalid: {other:?}"),
        }
    }

    /// The diagnostic names a guilty slot by index, so its decoding of the
    /// BIP-152 differential prefill indexes must agree with `reconstruct`'s.
    /// If these drift apart the log points at an innocent transaction, which is
    /// worse than no log at all.
    #[test]
    fn prefilled_positions_matches_the_decoder() {
        // Differential indexes [0, 1, 0] decode to absolute positions [0, 2, 3].
        let compact = CompactBlock::new(
            vec![0u8; 2189],
            0,
            vec![],
            vec![
                PrefilledTx {
                    index: 0,
                    tx_data: vec![1],
                },
                PrefilledTx {
                    index: 1,
                    tx_data: vec![2],
                },
                PrefilledTx {
                    index: 0,
                    tx_data: vec![3],
                },
            ],
        );
        assert_eq!(prefilled_positions(&compact), vec![0, 2, 3]);
    }

    /// Cross-check against the real decoder rather than against my arithmetic:
    /// every position the helper reports must be a slot `reconstruct` actually
    /// filled from the compact block, not from the mempool.
    #[test]
    fn reported_prefilled_positions_are_the_slots_reconstruct_prefills() {
        let nonce = 7u64;
        let coinbase_data = vec![0xc0];
        let mempool_data = vec![0xa1];
        let trailing_data = vec![0xa2];
        let header = header_committing_to(&[
            coinbase_data.clone(),
            mempool_data.clone(),
            trailing_data.clone(),
        ]);

        let mempool_wtxid = make_wtxid(9);
        let mut receiver = TestMempool::new();
        receiver.insert(mempool_wtxid, mempool_data.clone());
        let short_id = ShortId::compute(&mempool_wtxid, &crate::zcash_block_hash(&header), nonce);

        // Slots 0 and 2 prefilled (differential 0 then 1), slot 1 short-id'd.
        let compact = CompactBlock::new(
            header.clone(),
            nonce,
            vec![short_id],
            vec![
                PrefilledTx {
                    index: 0,
                    tx_data: coinbase_data.clone(),
                },
                PrefilledTx {
                    index: 1,
                    tx_data: trailing_data.clone(),
                },
            ],
        );

        assert_eq!(prefilled_positions(&compact), vec![0, 2]);

        let mut reconstructor = CompactBlockReconstructor::new(&receiver);
        reconstructor.prepare(&crate::zcash_block_hash(&header), nonce);
        match reconstructor.reconstruct(&compact) {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(
                    transactions[0], coinbase_data,
                    "slot 0 came from the prefill"
                );
                assert_eq!(
                    transactions[1], mempool_data,
                    "slot 1 came from the mempool"
                );
                assert_eq!(
                    transactions[2], trailing_data,
                    "slot 2 came from the prefill"
                );
            }
            other => panic!("expected a complete reconstruction: {other:?}"),
        }
    }
}
