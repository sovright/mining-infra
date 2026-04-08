//! Test utilities for zcash-template-provider
//!
//! Provides `MockZebraRpc` (a fake RPC backend) and `TestTemplateFactory`
//! (a builder for valid `GetBlockTemplateResponse` values).
//!
//! Enable with the `test-support` feature flag for use in downstream crates.

use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::rpc::RpcProvider;
use crate::types::{DefaultRoots, GetBlockTemplateResponse, TemplateTransaction};

// ---------------------------------------------------------------------------
// MockZebraRpc
// ---------------------------------------------------------------------------

/// A mock implementation of [`RpcProvider`] that returns pre-queued responses.
pub struct MockZebraRpc {
    templates: Mutex<VecDeque<Result<GetBlockTemplateResponse>>>,
    submitted: Mutex<Vec<String>>,
}

impl MockZebraRpc {
    /// Create a new, empty mock.
    pub fn new() -> Self {
        Self {
            templates: Mutex::new(VecDeque::new()),
            submitted: Mutex::new(Vec::new()),
        }
    }

    /// Queue a successful template response.
    pub fn enqueue_template(&self, response: GetBlockTemplateResponse) {
        self.templates.lock().unwrap().push_back(Ok(response));
    }

    /// Queue an error response.
    pub fn enqueue_error(&self, err: Error) {
        self.templates.lock().unwrap().push_back(Err(err));
    }

    /// Return a snapshot of all submitted block hex strings.
    pub fn submitted_blocks(&self) -> Vec<String> {
        self.submitted.lock().unwrap().clone()
    }
}

impl Default for MockZebraRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RpcProvider for MockZebraRpc {
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse> {
        self.templates
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(Error::Rpc("no queued templates".into())))
    }

    async fn submit_block(&self, block_hex: &str) -> Result<Option<String>> {
        self.submitted.lock().unwrap().push(block_hex.to_string());
        Ok(None)
    }

    async fn get_best_block_hash(&self) -> Result<String> {
        Ok("0".repeat(64))
    }
}

// ---------------------------------------------------------------------------
// TestTemplateFactory
// ---------------------------------------------------------------------------

/// Builder for constructing valid [`GetBlockTemplateResponse`] values.
///
/// Defaults produce a template where `assemble_header()` yields a valid
/// 140-byte Equihash header.
pub struct TestTemplateFactory {
    height: u64,
    version: u32,
    time: u64,
    bits: String,
    prev_hash: String,
    merkle_root: String,
    chain_history_root: String,
    auth_data_root: String,
    block_commitments_hash: String,
    target: String,
    transactions: Vec<TemplateTransaction>,
    coinbase_hex: String,
}

impl Default for TestTemplateFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl TestTemplateFactory {
    /// Create a factory with sensible defaults.
    pub fn new() -> Self {
        // Minimal valid coinbase: a small transaction hex that decodes
        // correctly is not strictly required by assemble_header, but we
        // provide one so callers can exercise full-template paths.
        // This is a 60-byte (120 hex-char) minimal coinbase:
        //   version(4) + vin_count(1) + prev_out(32+4) + script_len(1) +
        //   script(4) + sequence(4) + vout_count(1) + value(8) +
        //   script_len(1) + script(1) + locktime(4) = 65 bytes
        let coinbase_hex = "05000000\
            01\
            0000000000000000000000000000000000000000000000000000000000000000ffffffff\
            0404ffffff\
            ffffffff\
            01\
            0000000000000000\
            0100\
            00000000"
            .to_string();

        Self {
            height: 1_000_000,
            version: 5,
            time: 1_700_000_000,
            bits: "2007ffff".to_string(),
            prev_hash: "0".repeat(64),
            merkle_root: "0".repeat(64),
            chain_history_root: "0".repeat(64),
            auth_data_root: "0".repeat(64),
            block_commitments_hash: "0".repeat(64),
            target: "0".repeat(64),
            transactions: Vec::new(),
            coinbase_hex,
        }
    }

    /// Set the block height.
    pub fn height(mut self, h: u64) -> Self {
        self.height = h;
        self
    }

    /// Set the previous block hash (64-char hex, display/big-endian order).
    pub fn prev_hash(mut self, h: &str) -> Self {
        self.prev_hash = h.to_string();
        self
    }

    /// Set the block timestamp.
    pub fn time(mut self, t: u64) -> Self {
        self.time = t;
        self
    }

    /// Set the transactions included in the template.
    pub fn with_transactions(mut self, txs: Vec<TemplateTransaction>) -> Self {
        self.transactions = txs;
        self
    }

    /// Build the `GetBlockTemplateResponse`.
    pub fn build(self) -> GetBlockTemplateResponse {
        GetBlockTemplateResponse {
            version: self.version,
            previous_block_hash: self.prev_hash,
            default_roots: DefaultRoots {
                merkle_root: self.merkle_root,
                chain_history_root: self.chain_history_root,
                auth_data_root: self.auth_data_root,
                block_commitments_hash: self.block_commitments_hash,
            },
            transactions: self.transactions,
            coinbase_txn: serde_json::json!({ "data": self.coinbase_hex }),
            target: self.target,
            height: self.height,
            bits: self.bits,
            cur_time: self.time,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::assemble_header;

    #[test]
    fn factory_produces_valid_header() {
        let template = TestTemplateFactory::new().build();
        let header = assemble_header(&template).expect("assemble_header should succeed");
        let bytes = header.serialize();
        assert_eq!(bytes.len(), 140, "Equihash header must be exactly 140 bytes");
    }

    #[test]
    fn factory_builder_methods() {
        let template = TestTemplateFactory::new()
            .height(2_000_000)
            .time(1_800_000_000)
            .build();

        assert_eq!(template.height, 2_000_000);
        assert_eq!(template.cur_time, 1_800_000_000);
    }

    #[tokio::test]
    async fn mock_rpc_returns_queued_templates() {
        let mock = MockZebraRpc::new();

        // Enqueue one success and one error
        mock.enqueue_template(TestTemplateFactory::new().height(100).build());
        mock.enqueue_error(Error::Rpc("simulated failure".into()));

        // First call should succeed
        let resp = mock.get_block_template().await;
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().height, 100);

        // Second call should return the queued error
        let resp = mock.get_block_template().await;
        assert!(resp.is_err());

        // Third call (queue empty) should also error
        let resp = mock.get_block_template().await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn mock_rpc_tracks_submitted_blocks() {
        let mock = MockZebraRpc::new();

        mock.submit_block("aabbccdd").await.unwrap();
        mock.submit_block("11223344").await.unwrap();

        let submitted = mock.submitted_blocks();
        assert_eq!(submitted, vec!["aabbccdd", "11223344"]);
    }
}
