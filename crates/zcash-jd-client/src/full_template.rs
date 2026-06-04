//! Full template construction for JD Client
//!
//! This module provides the `FullTemplateBuilder` for constructing full template
//! jobs that include transaction selection. Unlike Coinbase-Only mode where the
//! pool provides transactions, Full-Template mode allows miners to select which
//! transactions to include in the block.

use crate::config::TxSelectionStrategy;
use crate::error::{JdClientError, Result};
use zcash_jd_server::messages::SetFullTemplateJob;

/// Builds full templates for job declaration
///
/// The `FullTemplateBuilder` is responsible for constructing `SetFullTemplateJob`
/// messages that include the miner's selected transactions. This is used when
/// the JD Client is operating in Full-Template mode.
pub struct FullTemplateBuilder {
    /// Transaction selection strategy
    strategy: TxSelectionStrategy,
}

impl FullTemplateBuilder {
    /// Create a new builder with the specified selection strategy
    pub fn new(strategy: TxSelectionStrategy) -> Self {
        Self { strategy }
    }

    /// Build a SetFullTemplateJob from template components
    ///
    /// # Arguments
    /// * `channel_id` - Channel for this job
    /// * `request_id` - Request identifier
    /// * `token` - Mining job token from server
    /// * `version` - Block version
    /// * `prev_hash` - Previous block hash
    /// * `merkle_root` - Merkle root of transactions
    /// * `block_commitments` - NU5+ block commitments
    /// * `coinbase_tx` - Constructed coinbase transaction
    /// * `time` - Block timestamp
    /// * `bits` - Difficulty target
    /// * `transactions` - List of (txid, tx_data) pairs
    #[allow(clippy::too_many_arguments)]
    pub fn build_job(
        &self,
        channel_id: u32,
        request_id: u32,
        token: Vec<u8>,
        version: u32,
        prev_hash: [u8; 32],
        merkle_root: [u8; 32],
        block_commitments: [u8; 32],
        coinbase_tx: Vec<u8>,
        time: u32,
        bits: u32,
        transactions: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<SetFullTemplateJob> {
        // Validate token
        if token.is_empty() {
            return Err(JdClientError::Protocol(
                "Empty mining job token".to_string(),
            ));
        }

        // Validate coinbase
        if coinbase_tx.is_empty() {
            return Err(JdClientError::Protocol(
                "Empty coinbase transaction".to_string(),
            ));
        }

        // Apply selection strategy
        let selected_txs = self.select_transactions(transactions);

        // Extract txids for compact format
        let tx_short_ids: Vec<[u8; 32]> = selected_txs.iter().map(|(txid, _)| *txid).collect();

        // For now, include all tx data (pool may not have them)
        // In future, could be smarter about which to include based on
        // pool mempool state or previous requests
        let tx_data: Vec<Vec<u8>> = selected_txs.iter().map(|(_, data)| data.clone()).collect();

        Ok(SetFullTemplateJob {
            channel_id,
            request_id,
            mining_job_token: token,
            version,
            prev_hash,
            merkle_root,
            block_commitments,
            coinbase_tx,
            time,
            bits,
            tx_short_ids,
            tx_data,
        })
    }

    /// Select transactions based on strategy
    fn select_transactions(
        &self,
        transactions: Vec<([u8; 32], Vec<u8>)>,
    ) -> Vec<([u8; 32], Vec<u8>)> {
        match self.strategy {
            TxSelectionStrategy::All => transactions,
            TxSelectionStrategy::ByFeeRate => {
                // For MVP, just return all transactions
                // Future enhancement: sort by fee rate and potentially filter
                // based on block size limits or minimum fee rate threshold
                transactions
            }
        }
    }

    /// Get the selection strategy
    pub fn strategy(&self) -> TxSelectionStrategy {
        self.strategy
    }

    /// Set a new selection strategy
    pub fn set_strategy(&mut self, strategy: TxSelectionStrategy) {
        self.strategy = strategy;
    }
}

impl Default for FullTemplateBuilder {
    fn default() -> Self {
        Self::new(TxSelectionStrategy::All)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_job_empty_transactions() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::All);

        let job = builder
            .build_job(
                1,                            // channel_id
                42,                           // request_id
                vec![0x01, 0x02, 0x03],       // token
                5,                            // version
                [0xaa; 32],                   // prev_hash
                [0xbb; 32],                   // merkle_root
                [0xcc; 32],                   // block_commitments
                vec![0x01, 0x00, 0x00, 0x00], // coinbase_tx
                1700000000,                   // time
                0x1d00ffff,                   // bits
                vec![],                       // no transactions
            )
            .unwrap();

        assert_eq!(job.channel_id, 1);
        assert_eq!(job.request_id, 42);
        assert_eq!(job.mining_job_token, vec![0x01, 0x02, 0x03]);
        assert_eq!(job.version, 5);
        assert_eq!(job.prev_hash, [0xaa; 32]);
        assert_eq!(job.merkle_root, [0xbb; 32]);
        assert_eq!(job.block_commitments, [0xcc; 32]);
        assert_eq!(job.time, 1700000000);
        assert_eq!(job.bits, 0x1d00ffff);
        assert!(job.tx_short_ids.is_empty());
        assert!(job.tx_data.is_empty());
    }

    #[test]
    fn test_build_job_with_transactions() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::All);

        let transactions = vec![
            ([0x11; 32], vec![0x01, 0x02, 0x03]),
            ([0x22; 32], vec![0x04, 0x05, 0x06]),
        ];

        let job = builder
            .build_job(
                1,
                42,
                vec![0x01],
                5,
                [0xaa; 32],
                [0xbb; 32],
                [0xcc; 32],
                vec![0x01],
                1700000000,
                0x1d00ffff,
                transactions,
            )
            .unwrap();

        assert_eq!(job.tx_short_ids.len(), 2);
        assert_eq!(job.tx_data.len(), 2);
        assert_eq!(job.tx_short_ids[0], [0x11; 32]);
        assert_eq!(job.tx_short_ids[1], [0x22; 32]);
        assert_eq!(job.tx_data[0], vec![0x01, 0x02, 0x03]);
        assert_eq!(job.tx_data[1], vec![0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_build_job_empty_token_error() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::All);

        let result = builder.build_job(
            1,
            42,
            vec![], // empty token
            5,
            [0xaa; 32],
            [0xbb; 32],
            [0xcc; 32],
            vec![0x01],
            1700000000,
            0x1d00ffff,
            vec![],
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, JdClientError::Protocol(_)));
    }

    #[test]
    fn test_build_job_empty_coinbase_error() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::All);

        let result = builder.build_job(
            1,
            42,
            vec![0x01],
            5,
            [0xaa; 32],
            [0xbb; 32],
            [0xcc; 32],
            vec![], // empty coinbase
            1700000000,
            0x1d00ffff,
            vec![],
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, JdClientError::Protocol(_)));
    }

    #[test]
    fn test_strategy_selection() {
        let builder_all = FullTemplateBuilder::new(TxSelectionStrategy::All);
        assert_eq!(builder_all.strategy(), TxSelectionStrategy::All);

        let builder_fee = FullTemplateBuilder::new(TxSelectionStrategy::ByFeeRate);
        assert_eq!(builder_fee.strategy(), TxSelectionStrategy::ByFeeRate);
    }

    #[test]
    fn test_set_strategy() {
        let mut builder = FullTemplateBuilder::new(TxSelectionStrategy::All);
        assert_eq!(builder.strategy(), TxSelectionStrategy::All);

        builder.set_strategy(TxSelectionStrategy::ByFeeRate);
        assert_eq!(builder.strategy(), TxSelectionStrategy::ByFeeRate);
    }

    #[test]
    fn test_default_builder() {
        let builder = FullTemplateBuilder::default();
        assert_eq!(builder.strategy(), TxSelectionStrategy::All);
    }

    #[test]
    fn test_select_transactions_all_strategy() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::All);

        let transactions = vec![
            ([0x11; 32], vec![0x01]),
            ([0x22; 32], vec![0x02]),
            ([0x33; 32], vec![0x03]),
        ];

        let selected = builder.select_transactions(transactions.clone());
        assert_eq!(selected.len(), 3);
        assert_eq!(selected, transactions);
    }

    #[test]
    fn test_select_transactions_by_fee_rate_strategy() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::ByFeeRate);

        let transactions = vec![([0x11; 32], vec![0x01]), ([0x22; 32], vec![0x02])];

        // For MVP, ByFeeRate just returns all transactions
        let selected = builder.select_transactions(transactions.clone());
        assert_eq!(selected.len(), 2);
        assert_eq!(selected, transactions);
    }

    #[test]
    fn test_build_job_preserves_transaction_order() {
        let builder = FullTemplateBuilder::new(TxSelectionStrategy::All);

        let transactions = vec![
            ([0x01; 32], vec![0xaa]),
            ([0x02; 32], vec![0xbb]),
            ([0x03; 32], vec![0xcc]),
            ([0x04; 32], vec![0xdd]),
        ];

        let job = builder
            .build_job(
                1,
                1,
                vec![0x01],
                5,
                [0x00; 32],
                [0x00; 32],
                [0x00; 32],
                vec![0x01],
                0,
                0,
                transactions,
            )
            .unwrap();

        // Verify order is preserved
        assert_eq!(job.tx_short_ids[0], [0x01; 32]);
        assert_eq!(job.tx_short_ids[1], [0x02; 32]);
        assert_eq!(job.tx_short_ids[2], [0x03; 32]);
        assert_eq!(job.tx_short_ids[3], [0x04; 32]);

        assert_eq!(job.tx_data[0], vec![0xaa]);
        assert_eq!(job.tx_data[1], vec![0xbb]);
        assert_eq!(job.tx_data[2], vec![0xcc]);
        assert_eq!(job.tx_data[3], vec![0xdd]);
    }
}
