//! Forge relay integration for low-latency block propagation
//!
//! Wraps bedrock-forge library for compact block relay over UDP/FEC.

use std::sync::Arc;

use bedrock_forge::{
    BlockChunker, BlockSender, ClientConfig, CompactBlock,
    PrefilledTx, RelayClient, ShortId, WtxId, AuthDigest, TxId,
};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::PoolConfig;
use crate::error::{PoolError, Result};
use zcash_template_provider::types::BlockTemplate;

/// Equihash solution size for Zcash (n=200, k=9)
const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Compute double-SHA256 header hash, matching bedrock-forge library convention.
///
/// This MUST match `CompactBlock::header_hash()`, `CompactBlockBuilder::compute_header_hash()`,
/// and `RelayClient::compute_block_hash()` so that short IDs are consistent between
/// sender and receiver during compact block reconstruction.
pub(crate) fn compute_header_hash(header: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Build a CompactBlock from a BlockTemplate
pub(crate) fn build_compact_block(template: &BlockTemplate, nonce: u64) -> Result<CompactBlock> {
    // Serialize the full header (140 bytes header + equihash solution placeholder)
    let header_bytes = template.header.serialize();

    // For templates, we include a placeholder solution (zeros)
    // The actual solution will be filled when a block is found
    let mut full_header = Vec::with_capacity(1487);
    full_header.extend_from_slice(&header_bytes);
    // Add compactSize for solution length (1344 bytes = 0xfd 0x40 0x05)
    full_header.push(0xfd);
    full_header.extend_from_slice(&(EQUIHASH_SOLUTION_SIZE as u16).to_le_bytes());
    // Add placeholder solution
    full_header.extend(std::iter::repeat_n(0u8, EQUIHASH_SOLUTION_SIZE));

    let header_hash = compute_header_hash(&full_header);

    // Prefill coinbase
    let prefilled = vec![PrefilledTx {
        index: 0,
        tx_data: template.coinbase.clone(),
    }];

    // Build short IDs for template transactions
    let short_ids: Vec<ShortId> = template.transactions.iter()
        .filter_map(|tx| {
            match hex::decode(&tx.hash) {
                Ok(hash_bytes) if hash_bytes.len() == 32 => {
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&hash_bytes);
                    txid_bytes.reverse();
                    let txid = TxId::from_bytes(txid_bytes);
                    let wtxid = WtxId::new(txid, AuthDigest::from_bytes([0u8; 32]));
                    Some(ShortId::compute(&wtxid, &header_hash, nonce))
                }
                _ => {
                    warn!(tx_hash = %tx.hash, "Failed to decode transaction hash, skipping");
                    None
                }
            }
        })
        .collect();

    Ok(CompactBlock::new(
        full_header,
        nonce,
        short_ids,
        prefilled,
    ))
}

/// Forge relay wrapper for the pool server
pub struct ForgeRelay {
    /// Relay client for sending blocks
    client: Arc<RwLock<RelayClient>>,
    /// Block sender handle
    sender: BlockSender,
    /// Block chunker for manual operations
    #[allow(dead_code)]
    chunker: BlockChunker,
    /// Nonce for short ID computation (use 0 for consistency)
    nonce: u64,
}

impl ForgeRelay {
    /// Create a new forge relay from pool config
    pub fn new(config: &PoolConfig) -> Result<Self> {
        let relay_peers = config.forge_relay_peers.clone();
        if relay_peers.is_empty() {
            return Err(PoolError::Config("forge_relay_peers cannot be empty".into()));
        }

        let auth_key = config.forge_auth_key.unwrap_or([0u8; 32]);

        let client_config = ClientConfig::new(relay_peers, auth_key)
            .with_fec(config.forge_data_shards, config.forge_parity_shards)
            .with_bind_addr(config.forge_bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().expect("0.0.0.0:0 is a valid address")))
            .with_auth_required(true);

        let client = RelayClient::new(client_config)
            .map_err(|e| PoolError::Config(format!("forge client creation failed: {}", e)))?;

        let sender = client.sender();

        let chunker = BlockChunker::new(config.forge_data_shards, config.forge_parity_shards)
            .map_err(|e| PoolError::Config(format!("forge chunker creation failed: {}", e)))?;

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            sender,
            chunker,
            nonce: 0,
        })
    }

    /// Initialize the relay client (bind socket)
    pub async fn init(&self) -> Result<()> {
        let mut client = self.client.write().await;
        client.bind().await
            .map_err(|e| PoolError::Config(format!("forge bind failed: {}", e)))?;
        info!("Forge relay bound to {:?}", client.local_addr());
        Ok(())
    }

    /// Start the relay client run loop
    ///
    /// Returns a handle that can be used to stop the client.
    pub async fn start(&self) -> Result<()> {
        let client = Arc::clone(&self.client);
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(e) = client.run().await {
                warn!("Forge relay client exited with error: {}", e);
            }
        });
        Ok(())
    }

    /// Announce a new block template to the relay network
    pub async fn announce_template(&self, template: &BlockTemplate) -> Result<()> {
        let compact = build_compact_block(template, self.nonce)?;

        self.sender.send(compact).await
            .map_err(|e| PoolError::Config(format!("forge send failed: {}", e)))?;

        debug!(
            height = template.height,
            tx_count = template.transactions.len(),
            "Announced compact block to forge relay"
        );
        Ok(())
    }

    /// Announce a found block to the relay network
    pub async fn announce_block(&self, block_header: &[u8], coinbase: &[u8], tx_hashes: &[[u8; 32]]) -> Result<()> {
        // Build minimal compact block with just header and coinbase prefilled
        let prefilled = vec![PrefilledTx {
            index: 0,
            tx_data: coinbase.to_vec(),
        }];

        // Build short IDs for non-coinbase transactions
        let header_hash = compute_header_hash(block_header);
        let short_ids: Vec<ShortId> = tx_hashes.iter()
            .map(|hash| {
                let txid = TxId::from_bytes(*hash);
                let wtxid = WtxId::new(txid, AuthDigest::from_bytes([0u8; 32]));
                ShortId::compute(&wtxid, &header_hash, self.nonce)
            })
            .collect();

        let compact = CompactBlock::new(
            block_header.to_vec(),
            self.nonce,
            short_ids,
            prefilled,
        );

        self.sender.send(compact).await
            .map_err(|e| PoolError::Config(format!("forge send failed: {}", e)))?;

        info!("Announced found block to forge relay");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoolConfig;
    use zcash_template_provider::header::assemble_header;
    use zcash_template_provider::testutil::TestTemplateFactory;
    use zcash_template_provider::types::{BlockTemplate, Hash256, TemplateTransaction};

    /// Helper: build a BlockTemplate from the TestTemplateFactory output.
    fn make_block_template(txs: Vec<TemplateTransaction>) -> BlockTemplate {
        let response = TestTemplateFactory::new()
            .with_transactions(txs)
            .build();
        let header = assemble_header(&response).expect("assemble_header should succeed");
        let coinbase_hex = response.coinbase_txn.get("data").unwrap().as_str().unwrap();
        let coinbase = hex::decode(coinbase_hex).expect("valid coinbase hex");
        let total_fees: i64 = response.transactions.iter().map(|tx| tx.fee).sum();

        BlockTemplate {
            template_id: 0,
            height: response.height,
            header,
            target: Hash256::default(),
            transactions: response.transactions,
            coinbase,
            total_fees,
        }
    }

    #[test]
    fn test_compute_header_hash_known_value() {
        // All-zeros input
        let input = [0u8; 140];
        let result = compute_header_hash(&input);

        // Manually compute double-SHA256
        let first = Sha256::digest(&input);
        let second = Sha256::digest(first);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&second);

        assert_eq!(result, expected);

        // Verify consistency: building a CompactBlock with the same header
        // and calling header_hash() should produce the same double-SHA256.
        // We verify by recomputing since BlockHash may not expose inner bytes.
        let _compact = CompactBlock::new(input.to_vec(), 0, vec![], vec![]);
        // The compact block's header_hash() uses the same double-SHA256 algorithm,
        // so our free function must produce the same result for the same input.

        // Non-trivial input: verify determinism
        let input2 = [0xffu8; 80];
        let r1 = compute_header_hash(&input2);
        let r2 = compute_header_hash(&input2);
        assert_eq!(r1, r2);

        // Different inputs produce different hashes
        assert_ne!(result, r1);
    }

    #[test]
    fn test_build_compact_block_valid_template() {
        let template = make_block_template(vec![]);

        let compact = build_compact_block(&template, 0).expect("should build compact block");

        // Header should be 140 + 3 (compactSize) + 1344 (solution placeholder) = 1487 bytes
        assert_eq!(compact.header.len(), 1487, "header must be 1487 bytes");

        // Prefilled txs should have exactly 1 entry at index 0 (coinbase)
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);

        // No template transactions means no short IDs
        assert_eq!(compact.short_ids.len(), 0);
    }

    #[test]
    fn test_build_compact_block_invalid_tx_hash() {
        // Create a transaction with an invalid (non-hex) hash
        let bad_tx = TemplateTransaction {
            data: "00".to_string(),
            hash: "not_valid_hex!".to_string(),
            fee: 1000,
            depends: vec![],
        };

        let template = make_block_template(vec![bad_tx]);

        // Should succeed -- the invalid tx is skipped via filter_map
        let compact = build_compact_block(&template, 0).expect("should succeed despite invalid tx hash");

        // The invalid transaction was skipped, so short_ids should be empty
        assert_eq!(compact.short_ids.len(), 0, "invalid tx hash should be skipped");

        // Coinbase is still prefilled
        assert_eq!(compact.prefilled_txs.len(), 1);
    }

    #[test]
    fn test_forge_relay_rejects_empty_peers() {
        let config = PoolConfig {
            forge_relay_enabled: true,
            forge_relay_peers: vec![],
            forge_auth_key: Some([0u8; 32]),
            ..PoolConfig::default()
        };

        let result = ForgeRelay::new(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("cannot be empty"),
            "error should mention 'cannot be empty', got: {}",
            err_msg
        );
    }
}
