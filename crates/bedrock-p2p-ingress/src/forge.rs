use std::sync::Arc;

use bedrock_forge::{
    BlockSender, ClientConfig, CompactBlock, RelayClient, TransportError, ZCASH_FULL_HEADER_SIZE,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::Config;
use crate::error::{IngressError, Result};

#[derive(Clone)]
pub struct ForgeBridge {
    sender: BlockSender,
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
        Ok(Some(Self { sender }))
    }

    pub async fn forward_header_only(&self, block_payload: &[u8]) -> Result<()> {
        let header = block_payload
            .get(..ZCASH_FULL_HEADER_SIZE)
            .ok_or_else(|| {
                IngressError::Wire("block payload shorter than Zcash header".to_string())
            })?
            .to_vec();
        let compact = CompactBlock::new(header, 0, Vec::new(), Vec::new());
        self.sender.send(compact).await.map_err(map_transport_error)
    }
}

fn map_transport_error(error: TransportError) -> IngressError {
    IngressError::Forge(error.to_string())
}
