//! Relay node server implementation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::fec::FecError;
use crate::transport::{
    BlockAssembly, BlockChunker, Chunk, ChunkHeader, EquihashPowValidator, MAX_TOTAL_CHUNKS,
    MessageType, PowResult, PowValidator, RelayConfig, RelaySession, TransportError,
};

use super::metrics::RelayMetrics;

/// Relay node server
///
/// Receives blocks from authenticated clients, validates PoW,
/// and forwards to other connected clients.
pub struct RelayNode<V: PowValidator = EquihashPowValidator> {
    /// Configuration
    config: RelayConfig,
    /// UDP socket (bound in Task 4's bind() method)
    socket: Option<Arc<UdpSocket>>,
    /// Active sessions (protected by RwLock for concurrent access)
    sessions: Arc<RwLock<HashMap<SocketAddr, RelaySession>>>,
    /// Block chunker for FEC encoding/decoding
    chunker: BlockChunker,
    /// PoW validator
    validator: V,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Metrics
    metrics: Arc<RelayMetrics>,
}

impl RelayNode<EquihashPowValidator> {
    /// Create a new relay node with default PoW validator
    pub fn new(config: RelayConfig) -> Result<Self, FecError> {
        Self::with_validator(config, EquihashPowValidator)
    }
}

impl<V: PowValidator> RelayNode<V> {
    /// Create a new relay node with custom PoW validator
    pub fn with_validator(config: RelayConfig, validator: V) -> Result<Self, FecError> {
        // Validate config first
        if let Err(e) = config.validate() {
            return Err(FecError::InvalidConfiguration(format!(
                "config error: {}",
                e
            )));
        }

        let chunker = BlockChunker::new_with_max_payload(
            config.data_shards,
            config.parity_shards,
            config.chunk_size,
        )?;

        Ok(Self {
            config,
            socket: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            chunker,
            validator,
            running: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(RelayMetrics::new()),
        })
    }

    /// Get the listen address from config
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Check if a key is authorized
    pub fn is_authorized(&self, key: &[u8; 32]) -> bool {
        self.config.authorized_keys.contains(key)
    }

    /// Get the number of active sessions
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Check if the node is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &RelayMetrics {
        &self.metrics
    }

    /// Bind the socket and prepare for running
    pub async fn bind(&mut self) -> Result<(), TransportError> {
        let domain = if self.config.listen_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(4 * 1024 * 1024)?;
        socket.bind(&self.config.listen_addr.into())?;

        let socket = UdpSocket::from_std(socket.into())?;
        self.socket = Some(Arc::new(socket));
        Ok(())
    }

    /// Get the actual bound address (useful when binding to port 0)
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Run the relay node
    ///
    /// This method runs until `stop()` is called or an error occurs.
    pub async fn run(&self) -> Result<(), TransportError> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not bound",
            ))
        })?;

        self.running.store(true, Ordering::SeqCst);

        let mut buf = vec![0u8; 2048];
        let mut cleanup_counter: u32 = 0;

        loop {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            let recv_result =
                tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await;

            match recv_result {
                Ok(Ok((len, src_addr))) => {
                    if let Err(e) = self.handle_packet(&buf[..len], src_addr).await {
                        debug!(peer = %src_addr, error = ?e, "Error handling packet");
                    }
                }
                Ok(Err(e)) => {
                    self.running.store(false, Ordering::SeqCst);
                    return Err(TransportError::Io(e));
                }
                Err(_) => {
                    // Timeout - continue
                }
            }

            // Periodic cleanup (every ~10 seconds with 100ms timeout)
            cleanup_counter += 1;
            if cleanup_counter >= 100 {
                cleanup_counter = 0;
                self.cleanup_expired_sessions().await;
            }
        }

        Ok(())
    }

    /// Remove expired sessions
    async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let timeout = self.config.session_timeout;
        let assembly_timeout: Duration = self.config.assembly_timeout;
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired(timeout));
        for session in sessions.values_mut() {
            session.cleanup_assemblies(assembly_timeout);
            session.cleanup_recent();
        }
        let expired = (before - sessions.len()) as u64;
        if expired > 0 {
            self.metrics.add_sessions_expired(expired);
        }
    }

    /// Estimate original serialized length based on shard size
    fn estimate_original_len(&self, assembly: &BlockAssembly) -> Option<usize> {
        let shard_size = assembly
            .chunks
            .iter()
            .filter_map(|c| c.as_ref())
            .map(|c| c.len())
            .next()?;
        Some(shard_size * self.config.data_shards)
    }

    /// Validate PoW once we can reconstruct serialized data
    fn validate_pow_from_assembly(&self, assembly: &BlockAssembly) -> Option<bool> {
        let est_len = self.estimate_original_len(assembly)?;
        let data = match self.chunker.decode_data(assembly.chunks.clone(), est_len) {
            Ok(data) => data,
            Err(_) => return None,
        };

        if data.len() < 4 {
            return None;
        }
        let header_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if header_len == 0 || data.len() < 4 + header_len {
            return None;
        }

        let header = &data[4..4 + header_len];
        match self.validator.validate(header) {
            PowResult::Valid => Some(true),
            PowResult::Invalid => Some(false),
            PowResult::Indeterminate => None,
        }
    }

    /// Forward chunks to all other sessions
    async fn forward_to_peers(
        &self,
        src_addr: SocketAddr,
        block_hash: &[u8; 32],
        total_chunks: u16,
        chunks: &[(u16, Vec<u8>)],
    ) -> Result<(), TransportError> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not bound",
            ))
        })?;

        let sessions = self.sessions.read().await;
        let mut outbound: Vec<(SocketAddr, Vec<Vec<u8>>)> = Vec::new();

        for (peer_addr, session) in sessions.iter() {
            // Don't forward back to sender
            if *peer_addr == src_addr {
                continue;
            }

            // Forward all available chunks and count them
            let mut payloads: Vec<Vec<u8>> = Vec::new();
            for (chunk_id, data) in chunks.iter() {
                let header = if self.config.auth_required() {
                    let hmac = session.compute_hmac(
                        block_hash,
                        *chunk_id,
                        total_chunks,
                        data.len() as u16,
                        data,
                    );
                    ChunkHeader::new_block_authenticated(
                        block_hash,
                        *chunk_id,
                        total_chunks,
                        data.len() as u16,
                        hmac,
                    )
                } else {
                    ChunkHeader::new_block(block_hash, *chunk_id, total_chunks, data.len() as u16)
                };
                let chunk = Chunk::new(header, data.clone());
                payloads.push(chunk.to_bytes());
            }
            if !payloads.is_empty() {
                outbound.push((*peer_addr, payloads));
            }
        }
        drop(sessions);

        for (peer_addr, payloads) in outbound {
            let mut chunks_sent: u64 = 0;
            for data in payloads {
                let _ = socket.send_to(&data, peer_addr).await;
                chunks_sent += 1;
            }
            if chunks_sent > 0 {
                self.metrics.inc_packets_forwarded(chunks_sent);
            }
        }

        Ok(())
    }

    /// Stop the relay node
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Process a chunk for an existing session
    fn process_chunk_for_session(
        &self,
        session: &mut RelaySession,
        chunk: &Chunk,
        block_hash: [u8; 32],
        chunk_id: usize,
        total_chunks: usize,
    ) -> Option<Vec<(u16, Vec<u8>)>> {
        if !session.mark_chunk_seen(block_hash, chunk.header.chunk_id) {
            return None;
        }
        let Some(assembly) = session.get_or_create_assembly(block_hash, total_chunks) else {
            self.metrics.inc_invalid_chunks();
            return None;
        };
        let is_new = assembly.chunks.get(chunk_id).is_none_or(|c| c.is_none());
        assembly.add_chunk(chunk_id, chunk.payload.clone());

        // PoW validation gate: we check PoW eagerly on each new chunk rather
        // than waiting until the full block is assembled.  This is intentional --
        // it lets the relay reject invalid streams early and avoid accumulating
        // (and forwarding) chunks for blocks that will never pass validation.
        // `validate_pow_from_assembly` may return `None` when there aren't enough
        // chunks yet to extract a header; in that case we keep the current
        // `pow_validated` state (false) and suppress forwarding until a future
        // chunk provides enough data to decide.
        if is_new && !assembly.pow_validated {
            if let Some(valid) = self.validate_pow_from_assembly(assembly) {
                assembly.pow_validated = valid;
            }
        }

        if !assembly.pow_validated {
            return None;
        }

        let mut ready = Vec::new();
        for (idx, payload) in assembly.chunks.iter().enumerate() {
            if let Some(data) = payload {
                if !assembly.forwarded[idx] {
                    assembly.forwarded[idx] = true;
                    ready.push((idx as u16, data.clone()));
                }
            }
        }

        if ready.is_empty() { None } else { Some(ready) }
    }

    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), TransportError> {
        self.metrics.inc_packets_received();

        let chunk = Chunk::from_bytes(data)?;

        if chunk.header.msg_type == MessageType::Keepalive {
            return self.handle_keepalive(src_addr, &chunk).await;
        }

        // Validate chunk type and counts
        if chunk.header.msg_type != MessageType::Block {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(format!(
                "unsupported message type: {:?}",
                chunk.header.msg_type
            )));
        }
        if chunk.header.total_chunks == 0 || chunk.header.total_chunks > MAX_TOTAL_CHUNKS {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(format!(
                "invalid total_chunks: {}",
                chunk.header.total_chunks
            )));
        }

        let expected_total = (self.config.data_shards + self.config.parity_shards) as u16;
        if chunk.header.total_chunks != expected_total {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(format!(
                "unexpected total_chunks: got {}, expected {}",
                chunk.header.total_chunks, expected_total
            )));
        }

        let block_hash = chunk.header.block_hash;
        let chunk_id = chunk.header.chunk_id as usize;
        let total_chunks = chunk.header.total_chunks as usize;

        if chunk_id >= total_chunks {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(format!(
                "chunk_id {} >= total_chunks {}",
                chunk_id, total_chunks
            )));
        }

        let chunks_to_forward = {
            let mut sessions = self.sessions.write().await;

            if let Some(session) = sessions.get_mut(&src_addr) {
                // Existing session - enforce auth if configured
                let auth_required = self.config.auth_required();
                if auth_required && chunk.header.version != 2 {
                    warn!(peer = %src_addr, "Auth required but received version 1 chunk");
                    self.metrics.inc_auth_failures();
                    return Err(TransportError::AuthenticationFailed);
                }
                if auth_required
                    && chunk.header.version == 2
                    && !session.verify_hmac(
                        &block_hash,
                        chunk.header.chunk_id,
                        chunk.header.total_chunks,
                        chunk.header.payload_len,
                        &chunk.payload,
                        &chunk.header.hmac,
                    )
                {
                    warn!(peer = %src_addr, "HMAC verification failed for existing session");
                    self.metrics.inc_auth_failures();
                    return Err(TransportError::AuthenticationFailed);
                }
                session.touch();
                self.process_chunk_for_session(session, &chunk, block_hash, chunk_id, total_chunks)
            } else {
                if sessions.len() >= self.config.max_sessions {
                    warn!(peer = %src_addr, max_sessions = self.config.max_sessions, "Relay session limit reached");
                    return Err(TransportError::ConnectionRefused(
                        "relay session limit reached".into(),
                    ));
                }

                // New session - authenticate
                if !self.config.auth_required() {
                    // No auth required
                    debug!(peer = %src_addr, "Creating unauthenticated session");
                    sessions.insert(src_addr, RelaySession::new(src_addr, [0u8; 32]));
                    self.metrics.inc_sessions_created();
                    let session = sessions.get_mut(&src_addr).unwrap();
                    self.process_chunk_for_session(
                        session,
                        &chunk,
                        block_hash,
                        chunk_id,
                        total_chunks,
                    )
                } else if chunk.header.version == 2 {
                    // Try each authorized key
                    let mut authenticated_key: Option<[u8; 32]> = None;
                    for key in &self.config.authorized_keys {
                        let temp_session = RelaySession::new(src_addr, *key);
                        if temp_session.verify_hmac(
                            &block_hash,
                            chunk.header.chunk_id,
                            chunk.header.total_chunks,
                            chunk.header.payload_len,
                            &chunk.payload,
                            &chunk.header.hmac,
                        ) {
                            authenticated_key = Some(*key);
                            break;
                        }
                    }

                    if let Some(key) = authenticated_key {
                        info!(peer = %src_addr, "Authenticated new session");
                        sessions.insert(src_addr, RelaySession::new(src_addr, key));
                        self.metrics.inc_sessions_created();
                        let session = sessions.get_mut(&src_addr).unwrap();
                        self.process_chunk_for_session(
                            session,
                            &chunk,
                            block_hash,
                            chunk_id,
                            total_chunks,
                        )
                    } else {
                        warn!(peer = %src_addr, "Authentication failed - no matching key");
                        self.metrics.inc_auth_failures();
                        return Err(TransportError::AuthenticationFailed);
                    }
                } else {
                    warn!(peer = %src_addr, "Auth required but received version 1 chunk");
                    self.metrics.inc_auth_failures();
                    return Err(TransportError::AuthenticationFailed);
                }
            }
        };

        if let Some(chunks_to_forward) = chunks_to_forward {
            self.forward_to_peers(
                src_addr,
                &block_hash,
                chunk.header.total_chunks,
                &chunks_to_forward,
            )
            .await?;
        }

        Ok(())
    }

    async fn handle_keepalive(
        &self,
        src_addr: SocketAddr,
        chunk: &Chunk,
    ) -> Result<(), TransportError> {
        if chunk.header.block_hash != [0u8; 32]
            || chunk.header.chunk_id != 0
            || chunk.header.total_chunks != 0
            || chunk.header.payload_len != 0
            || !chunk.payload.is_empty()
        {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(
                "invalid keepalive framing".into(),
            ));
        }

        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&src_addr) {
            let auth_required = self.config.auth_required();
            if auth_required && chunk.header.version != 2 {
                warn!(peer = %src_addr, "Auth required but received version 1 keepalive");
                self.metrics.inc_auth_failures();
                return Err(TransportError::AuthenticationFailed);
            }
            if auth_required
                && !session.verify_hmac(
                    &chunk.header.block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    &chunk.payload,
                    &chunk.header.hmac,
                )
            {
                warn!(peer = %src_addr, "HMAC verification failed for existing keepalive session");
                self.metrics.inc_auth_failures();
                return Err(TransportError::AuthenticationFailed);
            }
            session.touch();
            return Ok(());
        }

        if sessions.len() >= self.config.max_sessions {
            warn!(peer = %src_addr, max_sessions = self.config.max_sessions, "Relay session limit reached");
            return Err(TransportError::ConnectionRefused(
                "relay session limit reached".into(),
            ));
        }

        if !self.config.auth_required() {
            debug!(peer = %src_addr, "Creating unauthenticated keepalive session");
            sessions.insert(src_addr, RelaySession::new(src_addr, [0u8; 32]));
            self.metrics.inc_sessions_created();
            return Ok(());
        }

        if chunk.header.version != 2 {
            warn!(peer = %src_addr, "Auth required but received version 1 keepalive");
            self.metrics.inc_auth_failures();
            return Err(TransportError::AuthenticationFailed);
        }

        let mut authenticated_key: Option<[u8; 32]> = None;
        for key in &self.config.authorized_keys {
            let temp_session = RelaySession::new(src_addr, *key);
            if temp_session.verify_hmac(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                &chunk.payload,
                &chunk.header.hmac,
            ) {
                authenticated_key = Some(*key);
                break;
            }
        }

        if let Some(key) = authenticated_key {
            info!(peer = %src_addr, "Authenticated new keepalive session");
            sessions.insert(src_addr, RelaySession::new(src_addr, key));
            self.metrics.inc_sessions_created();
            Ok(())
        } else {
            warn!(peer = %src_addr, "Keepalive authentication failed - no matching key");
            self.metrics.inc_auth_failures();
            Err(TransportError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn relay_node_creation() {
        let config = RelayConfig::new("127.0.0.1:8333".parse().unwrap())
            .with_authorized_keys(vec![[0x42; 32]]);

        let node = RelayNode::new(config).unwrap();

        assert_eq!(node.listen_addr().port(), 8333);
        assert!(node.is_authorized(&[0x42; 32]));
        assert!(!node.is_authorized(&[0x00; 32]));
        assert!(!node.is_running());
    }

    #[tokio::test]
    async fn relay_node_session_count() {
        let config = RelayConfig::default().with_unauthenticated_peers_allowed(true);
        let node = RelayNode::new(config).unwrap();

        assert_eq!(node.session_count().await, 0);
    }

    #[test]
    fn relay_node_validates_config() {
        let mut config = RelayConfig::default();
        config.data_shards = 0; // Invalid

        let result = RelayNode::new(config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn relay_node_bind() {
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let mut node = RelayNode::new(config).unwrap();

        node.bind().await.unwrap();

        let addr = node.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn relay_node_stop() {
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let mut node = RelayNode::new(config).unwrap();
        node.bind().await.unwrap();

        // Start in background
        let node = Arc::new(node);
        let node_clone = Arc::clone(&node);

        let handle = tokio::spawn(async move { node_clone.run().await });

        // Give it time to start
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(node.is_running());

        // Stop it
        node.stop();

        // Wait for it to finish
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert!(!node.is_running());
    }

    #[tokio::test]
    async fn forward_uses_authenticated_chunks_when_required() {
        let auth_key = [0x42; 32];
        let config =
            RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![auth_key]);
        let mut node = RelayNode::new(config).unwrap();
        node.bind().await.unwrap();

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let sender_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(sender_addr, RelaySession::new(sender_addr, auth_key));
            sessions.insert(receiver_addr, RelaySession::new(receiver_addr, auth_key));
        }

        let block_hash = [0xab; 32];
        let chunks = vec![(0u16, vec![1u8; 10])];

        node.forward_to_peers(sender_addr, &block_hash, 1, &chunks)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let recv = timeout(Duration::from_millis(200), receiver.recv_from(&mut buf))
            .await
            .expect("timeout waiting for forwarded chunk")
            .unwrap();
        let (len, _) = recv;
        let parsed = Chunk::from_bytes(&buf[..len]).unwrap();

        assert_eq!(parsed.header.version, 2);
        let session = RelaySession::new(receiver_addr, auth_key);
        assert!(session.verify_hmac(
            &parsed.header.block_hash,
            parsed.header.chunk_id,
            parsed.header.total_chunks,
            parsed.header.payload_len,
            &parsed.payload,
            &parsed.header.hmac
        ));
    }

    #[tokio::test]
    async fn rejects_non_block_message() {
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let mut node = RelayNode::new(config).unwrap();
        node.bind().await.unwrap();

        let addr = node.local_addr().unwrap();
        let node = Arc::new(node);
        let node_clone = Arc::clone(&node);

        let handle = tokio::spawn(async move { node_clone.run().await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let block_hash = [0x11; 32];
        let mut header = ChunkHeader::new_block(&block_hash, 0, 13, 4);
        header.msg_type = MessageType::Keepalive;
        let chunk = Chunk::new(header, vec![1, 2, 3, 4]);
        socket.send_to(&chunk.to_bytes(), addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let metrics = node.metrics().snapshot();
        assert!(metrics.invalid_chunks > 0);

        node.stop();
        let _ = handle.await;
    }
}
