//! Forge relay integration for low-latency block propagation
//!
//! Wraps bedrock-forge library for compact block relay over UDP/FEC.
//!
//! The relay client runs as a background tokio task, sending and receiving
//! compact blocks over authenticated UDP with Reed-Solomon FEC.

use std::sync::Arc;

use bedrock_forge::{
    BlockChunker, BlockReceiver, BlockSender, ClientConfig, CompactBlock,
    PrefilledTx, RelayClient, ShortId, WtxId, AuthDigest, TxId,
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::PoolConfig;
use crate::error::{PoolError, Result};
use zcash_template_provider::types::BlockTemplate;

/// Equihash solution size for Zcash (n=200, k=9)
const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Forge relay wrapper for the pool server
pub struct ForgeRelay {
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
            .with_bind_addr(config.forge_bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().expect("0.0.0.0:0 is a valid address")));

        let client = RelayClient::new(client_config)
            .map_err(|e| PoolError::Config(format!("forge client creation failed: {}", e)))?;

        let sender = client.sender();

        let chunker = BlockChunker::new(config.forge_data_shards, config.forge_parity_shards)
            .map_err(|e| PoolError::Config(format!("forge chunker creation failed: {}", e)))?;

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
            .ok_or_else(|| PoolError::Config("forge client already started".into()))?;
        client.bind().await
            .map_err(|e| PoolError::Config(format!("forge bind failed: {}", e)))?;
        info!("Forge relay bound to {:?}", client.local_addr());
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
            .ok_or_else(|| PoolError::Config("forge client already started or not created".into()))?;

        let (block_receiver, _outgoing_rx) = client.take_receiver()
            .ok_or_else(|| PoolError::Config("forge relay receiver already taken".into()))?;

        // Spawn the relay client run loop as a background task.
        // The run loop handles both sending (via outgoing channel fed by BlockSender)
        // and receiving (incoming UDP packets reassembled via FEC).
        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                warn!("Forge relay run loop exited: {}", e);
            }
        });

        Ok(block_receiver)
    }

    /// Announce a new block template to the relay network
    pub async fn announce_template(&self, template: &BlockTemplate) -> Result<()> {
        let compact = self.build_compact_block_from_template(template)?;

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
        let header_hash = self.compute_header_hash(block_header);
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

    /// Build a CompactBlock from a BlockTemplate
    fn build_compact_block_from_template(&self, template: &BlockTemplate) -> Result<CompactBlock> {
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

        let header_hash = self.compute_header_hash(&full_header);

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
                        Some(ShortId::compute(&wtxid, &header_hash, self.nonce))
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
            self.nonce,
            short_ids,
            prefilled,
        ))
    }

    /// Compute double-SHA256 header hash, matching bedrock-forge library convention.
    ///
    /// This MUST match `CompactBlock::header_hash()`, `CompactBlockBuilder::compute_header_hash()`,
    /// and `RelayClient::compute_block_hash()` so that short IDs are consistent between
    /// sender and receiver during compact block reconstruction.
    fn compute_header_hash(&self, header: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(header);
        let second = Sha256::digest(first);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second);
        result
    }
}
