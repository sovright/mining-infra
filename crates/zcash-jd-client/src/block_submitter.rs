//! Block submission to Zebra
//!
//! Submits found blocks to the local Zebra node via RPC.

use crate::error::{JdClientError, Result};
use tracing::{error, info};

/// Block submitter for Zebra RPC
pub struct BlockSubmitter {
    /// Zebra RPC URL
    zebra_url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl BlockSubmitter {
    /// Create a new block submitter
    pub fn new(zebra_url: String) -> Self {
        Self {
            zebra_url,
            client: reqwest::Client::new(),
        }
    }

    /// Submit a block to Zebra
    pub async fn submit_block(&self, block_hex: &str) -> Result<()> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "submitblock",
            "params": [block_hex]
        });

        let response = self
            .client
            .post(&self.zebra_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| JdClientError::BlockSubmissionFailed(e.to_string()))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| JdClientError::BlockSubmissionFailed(e.to_string()))?;

        if let Some(error) = result.get("error")
            && !error.is_null()
        {
            let error_msg = error.to_string();
            error!("Block submission failed: {}", error_msg);
            return Err(JdClientError::BlockSubmissionFailed(error_msg));
        }

        info!("Block submitted successfully to Zebra");
        Ok(())
    }

    /// Build block hex from components
    pub fn build_block_hex(
        header: &[u8; 140],
        solution: &[u8; 1344],
        coinbase_tx: &[u8],
        transactions: &[Vec<u8>],
    ) -> String {
        let mut block = Vec::new();

        // Header (140 bytes)
        block.extend_from_slice(header);

        // Equihash solution length (compactSize) + solution
        zcash_pool_common::write_compact_size(solution.len() as u64, &mut block);
        block.extend_from_slice(solution);

        // Transaction count (compactSize)
        let tx_count = 1 + transactions.len();
        zcash_pool_common::write_compact_size(tx_count as u64, &mut block);

        // Coinbase transaction
        block.extend_from_slice(coinbase_tx);

        // Other transactions
        for tx in transactions {
            block.extend_from_slice(tx);
        }

        hex::encode(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_submitter_creation() {
        let submitter = BlockSubmitter::new("http://127.0.0.1:8232".to_string());
        assert_eq!(submitter.zebra_url, "http://127.0.0.1:8232");
    }

    #[test]
    fn test_build_block_hex() {
        let header = [0xaa; 140];
        let solution = [0xbb; 1344];
        let coinbase_tx = vec![0x01; 100];
        let transactions: Vec<Vec<u8>> = vec![];

        let hex = BlockSubmitter::build_block_hex(&header, &solution, &coinbase_tx, &transactions);

        // header(140) + fd(1) + len(2) + solution(1344) + tx_count(1) + coinbase(100) = 1588 bytes = 3176 hex chars
        assert_eq!(hex.len(), 3176);
    }
}
