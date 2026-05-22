use std::sync::Arc;

use bedrock_forge::{
    BlockChunker, BlockSender, ClientConfig, CompactBlock, RelayClient, TransportError,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::block::compact_block_from_raw_block;
use crate::config::Config;
use crate::error::{IngressError, Result};

#[derive(Clone)]
pub struct ForgeBridge {
    sender: BlockSender,
    data_shards: usize,
    parity_shards: usize,
}

impl ForgeBridge {
    pub async fn from_config(config: &Config) -> Result<Option<Self>> {
        let Some(auth_key) = config.relay_auth_key else {
            return Ok(None);
        };
        if config.relay_peers.is_empty() {
            return Ok(None);
        }

        let client_config = ClientConfig::new(config.relay_peers.clone(), auth_key)
            .with_bind_addr(config.relay_bind_addr)
            .with_auth_required(true);
        let data_shards = client_config.data_shards;
        let parity_shards = client_config.parity_shards;
        let mut client =
            RelayClient::new(client_config).map_err(|e| IngressError::Forge(e.to_string()))?;
        client
            .bind()
            .await
            .map_err(|e| IngressError::Forge(e.to_string()))?;
        let sender = client.sender();
        let client = Arc::new(RwLock::new(client));
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(error) = client.run().await {
                warn!(%error, "FORGE relay client exited");
            }
        });
        info!(peers = config.relay_peers.len(), "FORGE bridge enabled");
        Ok(Some(Self {
            sender,
            data_shards,
            parity_shards,
        }))
    }

    pub async fn forward_block(&self, block_payload: &[u8]) -> Result<ForwardedBlock> {
        let compact = compact_block_from_raw_block(block_payload)?;
        let tx_count = compact.prefilled_txs.len();
        self.preflight_chunks(&compact)?;
        self.sender
            .send(compact)
            .await
            .map_err(map_transport_error)?;
        Ok(ForwardedBlock {
            tx_count,
            bytes: block_payload.len(),
        })
    }

    fn preflight_chunks(&self, compact: &CompactBlock) -> Result<()> {
        let block_hash = compact.header_hash();
        let chunker = BlockChunker::new(self.data_shards, self.parity_shards)
            .map_err(|e| IngressError::Forge(e.to_string()))?;
        chunker
            .compact_block_to_chunks(compact, block_hash.as_bytes())
            .map(|_| ())
            .map_err(|e| IngressError::Forge(e.to_string()))
    }
}

pub struct ForwardedBlock {
    pub tx_count: usize,
    pub bytes: usize,
}

fn map_transport_error(error: TransportError) -> IngressError {
    IngressError::Forge(error.to_string())
}
