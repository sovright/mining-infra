//! Relay client wrapper for sidecar

use sovright_relay::{BlockSender, ClientConfig, CompactBlock, RelayClient};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Relay client wrapper
pub struct RelayWrapper {
    client: Arc<RwLock<RelayClient>>,
    sender: BlockSender,
}

impl RelayWrapper {
    /// Create a new relay client
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
        info!(addr = ?client.local_addr(), "Relay client bound");
        Ok(())
    }

    /// Start the relay run loop
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = Arc::clone(&self.client);
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(e) = client.run().await {
                warn!("Relay client exited with error: {}", e);
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
        debug!("Announced compact block to relay network");
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

        let relay = RelayWrapper::new(peers, auth_key, bind_addr);
        assert!(relay.is_ok());
    }
}
