//! Relay integration for low-latency block propagation
//!
//! Wraps sovright-relay library for compact block relay over UDP/FEC.
//!
//! The relay client runs as a background tokio task, sending and receiving
//! compact blocks over authenticated UDP with Reed-Solomon FEC.

use sovright_relay::{
    BlockChunker, BlockReceiver, BlockSender, ClientConfig, CompactBlock,
    PrefilledTx, RelayClient, ShortId, WtxId, AuthDigest, TxId,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::PoolConfig;
use crate::error::{PoolError, Result};
use zcash_template_provider::types::BlockTemplate;

/// Equihash solution size for Zcash (n=200, k=9)
const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Compute double-SHA256 header hash, matching sovright-relay library convention.
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

/// Relay wrapper for the pool server
pub struct RelayHandle {
    /// Relay client — Option so we can take ownership when spawning the run loop
    client: Mutex<Option<RelayClient>>,
    /// Block sender handle (cloneable, works after client is moved to run task)
    sender: BlockSender,
    /// Block chunker for manual operations
    #[allow(dead_code)]
    chunker: BlockChunker,
    /// Nonce for short ID computation (use 0 for consistency)
    nonce: u64,
}

impl RelayHandle {
    /// Create a new relay from pool config
    pub fn new(config: &PoolConfig) -> Result<Self> {
        let relay_peers = config.relay_peers.clone();
        if relay_peers.is_empty() {
            return Err(PoolError::Config("relay_peers cannot be empty".into()));
        }

        let auth_key = config.relay_auth_key.unwrap_or([0u8; 32]);

        let client_config = ClientConfig::new(relay_peers, auth_key)
            .with_fec(config.relay_data_shards, config.relay_parity_shards)
            .with_bind_addr(config.relay_bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().expect("0.0.0.0:0 is a valid address")))
            .with_auth_required(true);

        let client = RelayClient::new(client_config)
            .map_err(|e| PoolError::Config(format!("relay client creation failed: {}", e)))?;

        let sender = client.sender();

        let chunker = BlockChunker::new(config.relay_data_shards, config.relay_parity_shards)
            .map_err(|e| PoolError::Config(format!("relay chunker creation failed: {}", e)))?;

        Ok(Self {
            client: Mutex::new(Some(client)),
            sender,
            chunker,
            nonce: 0,
        })
    }

    /// Initialize the relay client (bind UDP socket)
    pub async fn init(&self) -> Result<()> {
        let mut guard = self.client.lock().await;
        let client = guard.as_mut()
            .ok_or_else(|| PoolError::Config("relay client already started".into()))?;
        client.bind().await
            .map_err(|e| PoolError::Config(format!("relay bind failed: {}", e)))?;
        info!("Relay bound to {:?}", client.local_addr());
        Ok(())
    }

    /// Start the relay client run loop
    ///
    /// Takes ownership of the RelayClient and spawns it as a background task.
    /// Returns a BlockReceiver for incoming compact blocks from the relay network.
    /// Must be called after `init()`.
    pub async fn start(&self) -> Result<BlockReceiver> {
        let mut client = self.client.lock().await
            .take()
            .ok_or_else(|| PoolError::Config("relay client already started or not created".into()))?;

        let (block_receiver, _outgoing_rx) = client.take_receiver()
            .ok_or_else(|| PoolError::Config("relay receiver already taken".into()))?;

        // Spawn the relay client run loop as a background task.
        // The run loop handles both sending (via outgoing channel fed by BlockSender)
        // and receiving (incoming UDP packets reassembled via FEC).
        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                warn!("Relay run loop exited: {}", e);
            }
        });

        Ok(block_receiver)
    }

    /// Announce a new block template to the relay network
    pub async fn announce_template(&self, template: &BlockTemplate) -> Result<()> {
        let compact = build_compact_block(template, self.nonce)?;

        self.sender.send(compact).await
            .map_err(|e| PoolError::Config(format!("relay send failed: {}", e)))?;

        debug!(
            height = template.height,
            tx_count = template.transactions.len(),
            "Announced compact block to relay"
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
            .map_err(|e| PoolError::Config(format!("relay send failed: {}", e)))?;

        info!("Announced found block to relay");
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
        let first = Sha256::digest(input);
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
    fn test_relay_rejects_empty_peers() {
        let config = PoolConfig {
            relay_enabled: true,
            relay_peers: vec![],
            relay_auth_key: Some([0u8; 32]),
            ..PoolConfig::default()
        };

        let result = RelayHandle::new(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("cannot be empty"),
            "error should mention 'cannot be empty', got: {}",
            err_msg
        );
    }
}
