//! Forge relay client wrapper for sidecar

use bedrock_forge::{BlockSender, ClientConfig, CompactBlock, RelayClient};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Forge relay wrapper
pub struct ForgeRelay {
    client: Arc<RwLock<RelayClient>>,
    sender: BlockSender,
}

impl ForgeRelay {
    /// Create a new forge relay
    pub fn new(
        relay_peers: Vec<SocketAddr>,
        auth_key: [u8; 32],
        bind_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = ClientConfig::new(relay_peers, auth_key).with_bind_addr(bind_addr);
        let config = config.with_auth_required(true);

        let client = RelayClient::new(config)?;
        let sender = client.sender();

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            sender,
        })
    }

    /// Initialize the relay (bind socket)
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = self.client.write().await;
        client.bind().await?;
        info!(addr = ?client.local_addr(), "Forge relay bound");
        Ok(())
    }

    /// Start the relay run loop
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = Arc::clone(&self.client);
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(e) = client.run().await {
                warn!("Forge relay client exited with error: {}", e);
            }
        });
        Ok(())
    }

    /// Announce a compact block to the relay network
    pub async fn announce(
        &self,
        compact: CompactBlock,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sender.send(compact).await?;
        debug!("Announced compact block to forge relay");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_creation() {
        let peers = vec!["127.0.0.1:8333".parse().unwrap()];
        let auth_key = [0x42; 32];
        let bind_addr = "0.0.0.0:0".parse().unwrap();

        let relay = ForgeRelay::new(peers, auth_key, bind_addr);
        assert!(relay.is_ok());
    }
}
