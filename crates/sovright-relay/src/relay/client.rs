//! Relay client implementation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Sha256, Digest};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::compact_block::CompactBlock;
use crate::fec::FecError;
use crate::transport::{
    BlockAssembly, BlockChunker, Chunk, ChunkHeader, ClientConfig, MessageType, TransportError,
    MAX_TOTAL_CHUNKS,
};

const MAX_PENDING_BLOCKS_CLIENT: usize = 64;
const RECENT_DELIVERED_TTL: Duration = Duration::from_secs(120);

/// Handle for sending blocks through the relay client
#[derive(Clone)]
pub struct BlockSender {
    tx: mpsc::Sender<CompactBlock>,
}

impl BlockSender {
    /// Send a block to be relayed
    pub async fn send(&self, block: CompactBlock) -> Result<(), TransportError> {
        self.tx
            .send(block)
            .await
            .map_err(|_| TransportError::ConnectionRefused("channel closed".into()))
    }
}

/// Handle for receiving blocks from the relay
pub struct BlockReceiver {
    rx: mpsc::Receiver<CompactBlock>,
}

impl BlockReceiver {
    /// Receive the next block
    pub async fn recv(&mut self) -> Option<CompactBlock> {
        self.rx.recv().await
    }
}

/// Relay client for connecting to relay nodes
pub struct RelayClient {
    /// Configuration
    #[allow(dead_code)]
    config: ClientConfig,
    /// UDP socket
    socket: Option<Arc<UdpSocket>>,
    /// Block chunker
    #[allow(dead_code)]
    chunker: BlockChunker,
    /// Channel for outgoing blocks
    outgoing_tx: mpsc::Sender<CompactBlock>,
    outgoing_rx: Option<mpsc::Receiver<CompactBlock>>,
    /// Channel for delivering received blocks to user
    incoming_tx: Option<mpsc::Sender<CompactBlock>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayClient {
    /// Create a new relay client
    pub fn new(config: ClientConfig) -> Result<Self, FecError> {
        // Validate config first
        if let Err(e) = config.validate() {
            return Err(FecError::InvalidConfiguration(format!("config error: {}", e)));
        }

        let chunker = BlockChunker::new(config.data_shards, config.parity_shards)?;
        let (outgoing_tx, outgoing_rx) = mpsc::channel(16);

        Ok(Self {
            config,
            socket: None,
            chunker,
            outgoing_tx,
            outgoing_rx: Some(outgoing_rx),
            incoming_tx: None,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Bind the client socket
    pub async fn bind(&mut self) -> Result<(), TransportError> {
        let socket = UdpSocket::bind(self.config.bind_addr).await?;
        self.socket = Some(Arc::new(socket));
        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Get a sender handle for sending blocks
    pub fn sender(&self) -> BlockSender {
        BlockSender {
            tx: self.outgoing_tx.clone(),
        }
    }

    /// Take the receiver handle (can only be called once before run())
    ///
    /// Returns a BlockReceiver for receiving blocks from the relay.
    /// Also returns the outgoing channel receiver for the run loop to consume.
    pub fn take_receiver(&mut self) -> Option<(BlockReceiver, mpsc::Receiver<CompactBlock>)> {
        self.outgoing_rx.take().map(|outgoing| {
            let (incoming_tx, incoming_rx) = mpsc::channel(16);
            self.incoming_tx = Some(incoming_tx);
            (BlockReceiver { rx: incoming_rx }, outgoing)
        })
    }

    /// Check if client is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stop the client
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Run the client
    ///
    /// Handles both sending outgoing blocks and receiving incoming blocks.
    pub async fn run(&mut self) -> Result<(), TransportError> {
        let socket = self.socket.as_ref()
            .ok_or_else(|| TransportError::Io(
                std::io::Error::new(std::io::ErrorKind::NotConnected, "socket not bound")
            ))?
            .clone();

        let mut outgoing_rx = self.outgoing_rx.take()
            .ok_or_else(|| TransportError::Io(
                std::io::Error::other("receiver already taken")
            ))?;

        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        let mut recv_buf = vec![0u8; 2048];
        let mut pending_blocks: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();
        let mut recent_delivered: HashMap<[u8; 32], Instant> = HashMap::new();
        let mut cleanup_counter: u32 = 0;

        loop {
            if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }

            tokio::select! {
                // Handle outgoing blocks
                Some(block) = outgoing_rx.recv() => {
                    if let Err(e) = self.send_block_internal(&socket, &block).await {
                        warn!(error = ?e, "Error sending block");
                    }
                }

                // Handle incoming packets
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((len, _src)) => {
                            if let Ok(chunk) = Chunk::from_bytes(&recv_buf[..len]) {
                                self.handle_incoming_chunk(
                                    chunk,
                                    &mut pending_blocks,
                                    &mut recent_delivered,
                                ).await;
                            }
                        }
                        Err(e) => {
                            self.running.store(false, std::sync::atomic::Ordering::SeqCst);
                            return Err(TransportError::Io(e));
                        }
                    }
                }
            }

            // Periodic cleanup of stale pending blocks (every ~100 iterations)
            cleanup_counter += 1;
            if cleanup_counter >= 100 {
                cleanup_counter = 0;
                let timeout = self.config.recv_timeout;
                pending_blocks.retain(|_, (assembly, _)| !assembly.is_expired(timeout));
                recent_delivered.retain(|_, seen_at| seen_at.elapsed() <= RECENT_DELIVERED_TTL);
            }
        }

        Ok(())
    }

    /// Send a block to all relay nodes
    async fn send_block_internal(
        &self,
        socket: &UdpSocket,
        block: &CompactBlock,
    ) -> Result<(), TransportError> {
        let block_hash = self.compute_block_hash(block);

        // Convert to chunks (unauthenticated)
        let chunks = self.chunker.compact_block_to_chunks(block, &block_hash)?;

        // Create temporary session for HMAC computation
        use crate::transport::RelaySession;
        let session = RelaySession::new(
            "0.0.0.0:0".parse().unwrap(),
            self.config.auth_key,
        );

        // Send to all relay nodes
        for relay_addr in &self.config.relay_addrs {
            for chunk in &chunks {
                // Compute HMAC for this chunk
                let hmac = session.compute_hmac(
                    &chunk.header.block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    &chunk.payload,
                );

                // Create authenticated version 2 chunk
                let auth_header = ChunkHeader::new_block_authenticated(
                    &block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    hmac,
                );
                let auth_chunk = Chunk::new(auth_header, chunk.payload.clone());

                let data = auth_chunk.to_bytes();
                socket.send_to(&data, relay_addr).await?;
            }
        }

        debug!(
            block_hash = ?hex::encode(&block_hash[..8]),
            chunks = chunks.len(),
            "Sent authenticated block"
        );
        Ok(())
    }

    /// Compute block hash from header using double-SHA256, matching
    /// `CompactBlock::header_hash()` and `CompactBlockBuilder::compute_header_hash()`.
    fn compute_block_hash(&self, block: &CompactBlock) -> [u8; 32] {
        let first = Sha256::digest(&block.header);
        let second = Sha256::digest(first);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second);
        hash
    }

    /// Handle an incoming chunk
    async fn handle_incoming_chunk(
        &self,
        chunk: Chunk,
        pending: &mut HashMap<[u8; 32], (BlockAssembly, usize)>,
        recent_delivered: &mut HashMap<[u8; 32], Instant>,
    ) {
        let block_hash = chunk.header.block_hash;
        let total_chunks = chunk.header.total_chunks as usize;
        let chunk_id = chunk.header.chunk_id as usize;

        if recent_delivered
            .get(&block_hash)
            .is_some_and(|seen_at| seen_at.elapsed() <= RECENT_DELIVERED_TTL)
        {
            return;
        }

        // Validate chunk header
        if chunk.header.msg_type != MessageType::Block {
            return;
        }
        if total_chunks == 0 || chunk_id >= total_chunks {
            return; // Drop invalid chunk
        }
        if chunk.header.total_chunks > MAX_TOTAL_CHUNKS {
            return; // Drop invalid chunk
        }
        let expected_total = self.config.data_shards + self.config.parity_shards;
        if total_chunks != expected_total {
            return; // Drop mismatched FEC config chunks
        }

        // Enforce authentication if configured
        let auth_required = self.config.auth_required;
        if auth_required && chunk.header.version != 2 {
            return; // Drop unauthenticated chunk
        }
        if chunk.header.version == 2 {
            use crate::transport::RelaySession;
            let session = RelaySession::new("0.0.0.0:0".parse().unwrap(), self.config.auth_key);
            if !session.verify_hmac(
                &block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                &chunk.payload,
                &chunk.header.hmac,
            ) {
                return; // Drop failed auth
            }
        }

        // Get or create assembly
        if !pending.contains_key(&block_hash) && pending.len() >= MAX_PENDING_BLOCKS_CLIENT {
            return;
        }
        let (assembly, original_len) = pending
            .entry(block_hash)
            .or_insert_with(|| (BlockAssembly::new(block_hash, total_chunks), 0));

        // Drop duplicate chunk to avoid unnecessary work
        if let Some(existing) = assembly.chunks.get(chunk_id) {
            if existing.is_some() {
                return;
            }
        }
        // Add chunk
        assembly.add_chunk(chunk_id, chunk.payload);

        // Set original length estimate once we know shard size
        if *original_len == 0 {
            if let Some(shard) = assembly.chunks.iter().filter_map(|c| c.as_ref()).next() {
                *original_len = shard.len() * self.config.data_shards;
            }
        }

        // Try to reconstruct if we have enough chunks
        if assembly.can_reconstruct(self.config.data_shards) {
            // Extract chunks for decoding
            let shard_opts: Vec<Option<Vec<u8>>> = assembly.chunks.clone();

            // Estimate original length from first chunk if available
            let est_len = *original_len;

            if est_len > 0 {
                if let Ok(block) = self.chunker.chunks_to_compact_block(shard_opts, est_len) {
                    // Send to receiver
                    if let Some(tx) = &self.incoming_tx {
                        if tx.send(block).await.is_err() {
                            warn!("Failed to deliver reconstructed block (receiver dropped)");
                        }
                    }
                    recent_delivered.insert(block_hash, Instant::now());
                    // Remove from pending
                    pending.remove(&block_hash);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[test]
    fn client_creation() {
        let config = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32])
            .with_fec(2, 1);

        let client = RelayClient::new(config).unwrap();
        assert!(!client.is_running());
    }

    #[tokio::test]
    async fn client_bind() {
        let config = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32]);

        let mut client = RelayClient::new(config).unwrap();
        client.bind().await.unwrap();

        let addr = client.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn client_drops_unauthenticated_chunk() {
        let config = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32])
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();

        let (tx, mut rx) = mpsc::channel(1);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();

        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, 3, 4);
        let chunk = Chunk::new(header, vec![1, 2, 3, 4]);

        let mut recent_delivered = HashMap::new();
        client
            .handle_incoming_chunk(chunk, &mut pending, &mut recent_delivered)
            .await;

        assert!(pending.is_empty());
        let recv = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(recv.is_err() || recv.unwrap().is_none());
    }

    #[tokio::test]
    async fn client_drops_non_block_message() {
        let config = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32]);
        let client = RelayClient::new(config).unwrap();

        let (tx, mut rx) = mpsc::channel(1);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();

        let block_hash = [0xab; 32];
        let mut header = ChunkHeader::new_block(&block_hash, 0, 1, 4);
        header.msg_type = MessageType::Keepalive;
        let chunk = Chunk::new(header, vec![1, 2, 3, 4]);

        let mut recent_delivered = HashMap::new();
        client
            .handle_incoming_chunk(chunk, &mut pending, &mut recent_delivered)
            .await;

        assert!(pending.is_empty());
        let recv = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(recv.is_err() || recv.unwrap().is_none());
    }

    #[tokio::test]
    async fn client_drops_duplicate_chunks() {
        let config = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32])
            .with_fec(2, 1);
        let client = RelayClient::new(config).unwrap();

        let (tx, _rx) = mpsc::channel(1);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();

        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, 3, 4);
        let chunk = Chunk::new(header, vec![1, 2, 3, 4]);

        let mut assembly = BlockAssembly::new(block_hash, 3);
        assembly.add_chunk(0, vec![1, 2, 3, 4]);
        pending.insert(block_hash, (assembly, 0));

        let mut recent_delivered = HashMap::new();
        client
            .handle_incoming_chunk(chunk, &mut pending, &mut recent_delivered)
            .await;

        let (assembly, _) = pending.get(&block_hash).unwrap();
        assert_eq!(assembly.received_count(), 1);
    }
}
