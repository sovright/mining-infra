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
use crate::rpc::{RpcProvider, SubmitBlockResult, SubmitMode};
use crate::types::{
    DefaultRoots, GetBlockTemplateResponse, GetBlockchainInfoResponse, TemplateTransaction,
};

// ---------------------------------------------------------------------------
// MockZebraRpc
// ---------------------------------------------------------------------------

/// A mock implementation of [`RpcProvider`] that returns pre-queued responses.
pub struct MockZebraRpc {
    templates: Mutex<VecDeque<Result<GetBlockTemplateResponse>>>,
    blockchain_infos: Mutex<VecDeque<Result<GetBlockchainInfoResponse>>>,
    submitted: Mutex<Vec<String>>,
}

impl MockZebraRpc {
    /// Create a new, empty mock.
    pub fn new() -> Self {
        Self {
            templates: Mutex::new(VecDeque::new()),
            blockchain_infos: Mutex::new(VecDeque::new()),
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

    /// Queue a successful getblockchaininfo response.
    pub fn enqueue_blockchain_info(&self, next_block: &str) {
        self.blockchain_infos
            .lock()
            .unwrap()
            .push_back(Ok(GetBlockchainInfoResponse {
                consensus: crate::types::BlockchainInfoConsensus {
                    next_block: next_block.to_string(),
                },
            }));
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

    async fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResponse> {
        self.blockchain_infos
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                Ok(GetBlockchainInfoResponse {
                    consensus: crate::types::BlockchainInfoConsensus {
                        next_block: "c8e71055".to_string(),
                    },
                })
            })
    }

    async fn submit_block(
        &self,
        block_hex: &str,
        _mode: Option<SubmitMode>,
    ) -> Result<SubmitBlockResult> {
        self.submitted.lock().unwrap().push(block_hex.to_string());
        Ok(SubmitBlockResult::Accepted)
    }

    async fn get_best_block_hash(&self) -> Result<String> {
        Ok("0".repeat(64))
    }
}

/// Delegating impl so a test can pass `Box::new(mock.clone())` into a provider
/// and still inspect the same recorded state (e.g. `submitted_blocks()`) through
/// its retained `Arc` handle.
#[async_trait]
impl RpcProvider for std::sync::Arc<MockZebraRpc> {
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse> {
        (**self).get_block_template().await
    }

    async fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResponse> {
        (**self).get_blockchain_info().await
    }

    async fn submit_block(
        &self,
        block_hex: &str,
        mode: Option<SubmitMode>,
    ) -> Result<SubmitBlockResult> {
        (**self).submit_block(block_hex, mode).await
    }

    async fn get_best_block_hash(&self) -> Result<String> {
        (**self).get_best_block_hash().await
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

        // Every hash field is asymmetric, so a parser that forgets to reverse
        // produces a different value and the test notices. They are also mutually
        // distinct, so swapping two fields is caught as well.
        //
        // These defaults used to be "0".repeat(64). A reversed palindrome is
        // itself, which is why the whole suite stayed green through #103 -- the
        // byte-order defect that stopped the pool recognising any block it mined.
        // Do not reintroduce a symmetric default here. See #106.
        Self {
            height: 1_000_000,
            version: 5,
            time: 1_700_000_000,
            bits: "2007ffff".to_string(),
            prev_hash: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
            merkle_root: "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
                .to_string(),
            chain_history_root: "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
                .to_string(),
            auth_data_root: "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80"
                .to_string(),
            block_commitments_hash:
                "8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0".to_string(),
            // The big-endian expansion of mainnet nBits 0x1c00a48e: asymmetric, and a
            // real difficulty, so no test meets it by accident and flips `is_block`.
            target: "0000000000a48e00000000000000000000000000000000000000000000000000".to_string(),
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

    /// Set the block version (Zcash blocks use 4; ZIP 301 requires notify
    /// VERSION == 4).
    pub fn version(mut self, v: u32) -> Self {
        self.version = v;
        self
    }

    /// Set the merkle root (64-char hex, display/big-endian order).
    pub fn merkle_root(mut self, h: &str) -> Self {
        self.merkle_root = h.to_string();
        self
    }

    /// Set the block commitments hash (64-char hex, display/big-endian order).
    pub fn block_commitments_hash(mut self, h: &str) -> Self {
        self.block_commitments_hash = h.to_string();
        self
    }

    /// Set the chain history root (64-char hex, display/big-endian order).
    pub fn chain_history_root(mut self, h: &str) -> Self {
        self.chain_history_root = h.to_string();
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

    /// The factory's defaults must reach the header in internal byte order.
    ///
    /// Without this, the asymmetric defaults are inert: every other test built on
    /// the factory asserts something else, or compares parser output to parser
    /// output, so none of them would notice the bytes arriving reversed. Measured
    /// -- with `from_hex` stripped of its reversal, swapping the defaults from
    /// `"0".repeat(64)` to asymmetric values changed the failure count not at all
    /// until this test existed.
    ///
    /// Expectations are literals decoded with `hex::decode`, never with the
    /// parser under test, so they cannot share a bug with it. See #106.
    #[test]
    fn factory_defaults_land_in_internal_order() {
        let header = assemble_header(&TestTemplateFactory::new().build())
            .expect("assemble_header should succeed");

        let internal = |s: &str| -> [u8; 32] {
            hex::decode(s)
                .expect("literal hex")
                .try_into()
                .expect("32 bytes")
        };

        assert_eq!(
            header.prev_hash.0,
            internal("201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"),
            "prev_hash"
        );
        assert_eq!(
            header.merkle_root.0,
            internal("403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221"),
            "merkle_root"
        );
    }

    #[test]
    fn factory_produces_valid_header() {
        let template = TestTemplateFactory::new().build();
        let header = assemble_header(&template).expect("assemble_header should succeed");
        let bytes = header.serialize();
        assert_eq!(
            bytes.len(),
            140,
            "Equihash header must be exactly 140 bytes"
        );
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

        mock.submit_block("aabbccdd", None).await.unwrap();
        mock.submit_block("11223344", None).await.unwrap();

        let submitted = mock.submitted_blocks();
        assert_eq!(submitted, vec!["aabbccdd", "11223344"]);
    }
}
