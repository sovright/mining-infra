//! Sovright relay client wrapper for sidecar

use sovright_relay::{BlockReceiver, BlockSender, ClientConfig, CompactBlock, RelayClient};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Sovright relay wrapper
pub struct RelayWrapper {
    client: Arc<RwLock<RelayClient>>,
    sender: BlockSender,
}

impl RelayWrapper {
    /// Create a new relay with explicit FEC profile.
    pub fn new_with_fec(
        relay_peers: Vec<SocketAddr>,
        auth_key: [u8; 32],
        bind_addr: SocketAddr,
        data_shards: usize,
        parity_shards: usize,
        send_burst_packets: usize,
        send_burst_delay: Duration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = ClientConfig::new(relay_peers, auth_key)
            .with_bind_addr(bind_addr)
            .with_fec(data_shards, parity_shards)
            .with_send_pacing(send_burst_packets, send_burst_delay);
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
        info!(addr = ?client.local_addr(), "Sovright relay bound");
        Ok(())
    }

    /// Start the relay run loop
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = Arc::clone(&self.client);
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(e) = client.run().await {
                warn!("Sovright relay client exited with error: {}", e);
            }
        });
        Ok(())
    }

    /// Start the relay run loop and return a receiver for relay-delivered blocks.
    pub async fn start_with_receiver(
        &self,
    ) -> Result<BlockReceiver, Box<dyn std::error::Error + Send + Sync>> {
        let (receiver, outgoing) = {
            let mut client = self.client.write().await;
            client
                .take_receiver()
                .ok_or("Sovright relay receiver already taken")?
        };

        let client = Arc::clone(&self.client);
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(e) = client.run_with_outgoing(outgoing).await {
                warn!("Sovright relay client exited with error: {}", e);
            }
        });

        Ok(receiver)
    }

    /// Announce a compact block to the relay network
    pub async fn announce(
        &self,
        compact: CompactBlock,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sender.send(compact).await?;
        debug!("Announced compact block to relay");
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

        let relay = RelayWrapper::new_with_fec(peers, auth_key, bind_addr, 10, 3, 0, Duration::ZERO);
        assert!(relay.is_ok());
    }

    #[tokio::test]
    async fn relay_starts_with_receiver() {
        let peers = vec!["127.0.0.1:8333".parse().unwrap()];
        let auth_key = [0x42; 32];
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let relay =
            RelayWrapper::new_with_fec(peers, auth_key, bind_addr, 10, 3, 0, Duration::ZERO).unwrap();
        relay.init().await.unwrap();

        let mut receiver = relay.start_with_receiver().await.unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv())
                .await
                .is_err()
        );
    }

    #[test]
    fn relay_rejects_invalid_fec_profile() {
        let peers = vec!["127.0.0.1:8333".parse().unwrap()];
        let auth_key = [0x42; 32];
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let relay = RelayWrapper::new_with_fec(peers, auth_key, bind_addr, 255, 2, 0, Duration::ZERO);

        assert!(relay.is_err());
    }
}
