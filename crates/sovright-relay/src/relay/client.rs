//! Relay client implementation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::compact_block::CompactBlock;
use crate::fec::FecError;
use crate::segmented_block::RawBlockSegment;
use crate::transport::{
    BlockAssembly, BlockChunker, Chunk, ChunkHeader, ClientConfig, MAX_TOTAL_CHUNKS, MessageType,
    TransportError,
};

const MAX_PENDING_BLOCKS_CLIENT: usize = 64;
const RECENT_DELIVERED_TTL: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const KEEPALIVE_BLOCK_HASH: [u8; 32] = [0u8; 32];
const CLIENT_RECV_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Payload delivered through the relay client.
#[derive(Clone, Debug)]
pub enum RelayPayload {
    /// Compact block relay object.
    CompactBlock(CompactBlock),
    /// One segment of a raw serialized block.
    RawBlockSegment(RawBlockSegment),
    /// Compact-skeleton fast-path object: a `CompactBlock` (all-short_id form)
    /// sent first and redundantly ahead of the full compact block, routed to
    /// the receiver's skeleton fast path.
    CompactSkeleton(CompactBlock),
}

/// Handle for sending blocks through the relay client
#[derive(Clone)]
pub struct BlockSender {
    tx: mpsc::Sender<RelayPayload>,
}

impl BlockSender {
    /// Send a block to be relayed
    pub async fn send(&self, block: CompactBlock) -> Result<(), TransportError> {
        self.tx
            .send(RelayPayload::CompactBlock(block))
            .await
            .map_err(|_| TransportError::ConnectionRefused("channel closed".into()))
    }

    /// Send one raw block segment to be relayed.
    pub async fn send_raw_block_segment(
        &self,
        segment: RawBlockSegment,
    ) -> Result<(), TransportError> {
        self.tx
            .send(RelayPayload::RawBlockSegment(segment))
            .await
            .map_err(|_| TransportError::ConnectionRefused("channel closed".into()))
    }

    /// Send a compact skeleton to be relayed on the fast path.
    ///
    /// The skeleton is the reconstruction-critical `CompactBlock` (header +
    /// nonce + all-non-coinbase short_ids, coinbase prefilled). It is chunked
    /// under [`MessageType::CompactSkeleton`] with a heavier parity floor and a
    /// distinct relay object id, so it reassembles independently of, and ahead
    /// of, the full compact block that follows as the push fallback.
    pub async fn send_skeleton(&self, skeleton: CompactBlock) -> Result<(), TransportError> {
        self.tx
            .send(RelayPayload::CompactSkeleton(skeleton))
            .await
            .map_err(|_| TransportError::ConnectionRefused("channel closed".into()))
    }
}

/// Handle for receiving blocks from the relay
pub struct BlockReceiver {
    rx: mpsc::Receiver<RelayPayload>,
}

impl BlockReceiver {
    /// Receive the next block
    pub async fn recv(&mut self) -> Option<CompactBlock> {
        while let Some(payload) = self.rx.recv().await {
            if let RelayPayload::CompactBlock(block) = payload {
                return Some(block);
            }
        }
        None
    }

    /// Receive the next raw block segment.
    pub async fn recv_raw_block_segment(&mut self) -> Option<RawBlockSegment> {
        while let Some(payload) = self.rx.recv().await {
            if let RelayPayload::RawBlockSegment(segment) = payload {
                return Some(segment);
            }
        }
        None
    }

    /// Receive the next relay payload of any supported type.
    pub async fn recv_payload(&mut self) -> Option<RelayPayload> {
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
    outgoing_tx: mpsc::Sender<RelayPayload>,
    outgoing_rx: Option<mpsc::Receiver<RelayPayload>>,
    /// Channel for delivering received blocks to user
    incoming_tx: Option<mpsc::Sender<RelayPayload>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayClient {
    /// Create a new relay client
    pub fn new(config: ClientConfig) -> Result<Self, FecError> {
        // Validate config first
        if let Err(e) = config.validate() {
            return Err(FecError::InvalidConfiguration(format!(
                "config error: {}",
                e
            )));
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
        let domain = if self.config.bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(CLIENT_RECV_BUFFER_BYTES)?;
        socket.bind(&self.config.bind_addr.into())?;

        let socket = UdpSocket::from_std(socket.into())?;
        info!(
            local_addr = ?socket.local_addr().ok(),
            recv_buffer_bytes = CLIENT_RECV_BUFFER_BYTES,
            "Relay client socket bound"
        );
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
    pub fn take_receiver(&mut self) -> Option<(BlockReceiver, mpsc::Receiver<RelayPayload>)> {
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
        let outgoing_rx = self
            .outgoing_rx
            .take()
            .ok_or_else(|| TransportError::Io(std::io::Error::other("receiver already taken")))?;

        self.run_with_outgoing(outgoing_rx).await
    }

    /// Run the client using an outgoing queue returned by `take_receiver`.
    ///
    /// This lets callers receive relay-delivered blocks while the same client
    /// continues to process outgoing announcements.
    pub async fn run_with_outgoing(
        &mut self,
        mut outgoing_rx: mpsc::Receiver<RelayPayload>,
    ) -> Result<(), TransportError> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| {
                TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "socket not bound",
                ))
            })?
            .clone();

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let mut recv_buf = vec![0u8; 2048];
        let mut pending_blocks: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();
        let mut recent_delivered: HashMap<[u8; 32], Instant> = HashMap::new();
        let mut cleanup_counter: u32 = 0;
        let mut keepalive_interval = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }

            tokio::select! {
                // Register/refresh this client as a relay session, including
                // receive-only clients that have no block announcements to send.
                _ = keepalive_interval.tick() => {
                    if let Err(e) = self.send_keepalive_internal(&socket).await {
                        warn!(error = ?e, "Error sending relay keepalive");
                    }
                }

                // Handle outgoing blocks
                Some(payload) = outgoing_rx.recv() => {
                    if let Err(e) = self.send_payload_internal(socket.clone(), &payload).await {
                        warn!(error = ?e, "Error sending relay payload");
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

    /// Send an authenticated keepalive to all relay nodes.
    async fn send_keepalive_internal(&self, socket: &UdpSocket) -> Result<(), TransportError> {
        use crate::transport::RelaySession;

        let session =
            RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", self.config.auth_key);
        let payload: [u8; 0] = [];
        let hmac = session.compute_hmac(&KEEPALIVE_BLOCK_HASH, 0, 0, 0, &payload);
        let chunk = Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new());
        let data = chunk.to_bytes();

        for relay_addr in &self.config.relay_addrs {
            socket.send_to(&data, relay_addr).await?;
        }

        debug!("Sent relay keepalive");
        Ok(())
    }

    /// Send a payload to all relay nodes
    async fn send_payload_internal(
        &self,
        socket: Arc<UdpSocket>,
        payload: &RelayPayload,
    ) -> Result<(), TransportError> {
        match payload {
            RelayPayload::CompactBlock(block) => self.send_block_internal(socket, block).await,
            RelayPayload::RawBlockSegment(segment) => {
                self.send_raw_block_segment_internal(socket, segment).await
            }
            RelayPayload::CompactSkeleton(skeleton) => {
                self.send_skeleton_internal(socket, skeleton).await
            }
        }
    }

    /// Send a compact skeleton to all relay nodes on the fast path.
    ///
    /// The skeleton always uses the adaptive (v3) codec with the heavier
    /// skeleton parity floor, and is routed under a domain-separated object id
    /// so it does not collide with the full compact block of the same block.
    async fn send_skeleton_internal(
        &self,
        socket: Arc<UdpSocket>,
        skeleton: &CompactBlock,
    ) -> Result<(), TransportError> {
        let block_hash = self.compute_block_hash(skeleton);
        let object_hash = crate::segmented_block::skeleton_object_hash(block_hash);
        let chunks = self
            .chunker
            .compact_block_to_chunks_skeleton(skeleton, &object_hash)?;
        self.send_chunks_internal(socket, &object_hash, chunks, "compact skeleton")
            .await
    }

    /// Send a block to all relay nodes
    async fn send_block_internal(
        &self,
        socket: Arc<UdpSocket>,
        block: &CompactBlock,
    ) -> Result<(), TransportError> {
        let block_hash = self.compute_block_hash(block);

        // With adaptive FEC on, size the block to a handful of version-3 chunks
        // (falling back to the fixed v2 profile for oversized blocks). Otherwise
        // keep the fixed v2 behavior.
        let chunks = if self.config.adaptive_fec {
            self.chunker
                .compact_block_to_chunks_adaptive(block, &block_hash)?
        } else {
            self.chunker.compact_block_to_chunks(block, &block_hash)?
        };
        self.send_chunks_internal(socket, &block_hash, chunks, "compact block")
            .await
    }

    /// Send one raw block segment to all relay nodes.
    async fn send_raw_block_segment_internal(
        &self,
        socket: Arc<UdpSocket>,
        segment: &RawBlockSegment,
    ) -> Result<(), TransportError> {
        let object_hash =
            crate::segmented_block::segment_object_hash(segment.block_hash, segment.segment_index);
        let chunks = self.chunker.raw_block_segment_to_chunks(segment)?;
        self.send_chunks_internal(socket, &object_hash, chunks, "raw block segment")
            .await
    }

    async fn send_chunks_internal(
        &self,
        socket: Arc<UdpSocket>,
        object_hash: &[u8; 32],
        chunks: Vec<Chunk>,
        label: &str,
    ) -> Result<(), TransportError> {
        // Create temporary session for HMAC computation
        use crate::transport::RelaySession;
        let session =
            RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", self.config.auth_key);

        let mut payloads = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            // A nonzero data_shards marks a version-3 (adaptive) intermediate
            // chunk: authenticate it with the v3 HMAC (which covers data_shards)
            // and emit a v3 header. Otherwise fall back to the fixed v2 path.
            let auth_header = if chunk.header.data_shards > 0 {
                let hmac = session.compute_hmac_v3(
                    &chunk.header.block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    chunk.header.data_shards,
                    &chunk.payload,
                );
                match chunk.header.msg_type {
                    MessageType::Block => ChunkHeader::new_block_authenticated_v3(
                        &chunk.header.block_hash,
                        chunk.header.chunk_id,
                        chunk.header.total_chunks,
                        chunk.header.payload_len,
                        chunk.header.data_shards,
                        hmac,
                    ),
                    MessageType::RawBlockSegment => {
                        ChunkHeader::new_raw_block_segment_authenticated_v3(
                            &chunk.header.block_hash,
                            chunk.header.chunk_id,
                            chunk.header.total_chunks,
                            chunk.header.payload_len,
                            chunk.header.data_shards,
                            hmac,
                        )
                    }
                    MessageType::CompactSkeleton => {
                        ChunkHeader::new_compact_skeleton_authenticated_v3(
                            &chunk.header.block_hash,
                            chunk.header.chunk_id,
                            chunk.header.total_chunks,
                            chunk.header.payload_len,
                            chunk.header.data_shards,
                            hmac,
                        )
                    }
                    MessageType::Keepalive | MessageType::Auth => {
                        return Err(TransportError::InvalidChunk(
                            "unsupported outgoing chunk message type".into(),
                        ));
                    }
                }
            } else {
                let hmac = session.compute_hmac(
                    &chunk.header.block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    &chunk.payload,
                );
                match chunk.header.msg_type {
                    MessageType::Block => ChunkHeader::new_block_authenticated(
                        &chunk.header.block_hash,
                        chunk.header.chunk_id,
                        chunk.header.total_chunks,
                        chunk.header.payload_len,
                        hmac,
                    ),
                    MessageType::RawBlockSegment => {
                        ChunkHeader::new_raw_block_segment_authenticated(
                            &chunk.header.block_hash,
                            chunk.header.chunk_id,
                            chunk.header.total_chunks,
                            chunk.header.payload_len,
                            hmac,
                        )
                    }
                    MessageType::CompactSkeleton => {
                        ChunkHeader::new_compact_skeleton_authenticated(
                            &chunk.header.block_hash,
                            chunk.header.chunk_id,
                            chunk.header.total_chunks,
                            chunk.header.payload_len,
                            hmac,
                        )
                    }
                    MessageType::Keepalive | MessageType::Auth => {
                        return Err(TransportError::InvalidChunk(
                            "unsupported outgoing chunk message type".into(),
                        ));
                    }
                }
            };
            payloads.push(Chunk::new(auth_header, chunk.payload).to_bytes());
        }

        let payloads = Arc::new(payloads);
        let pacing = SendPacing::new(self.config.send_burst_packets, self.config.send_burst_delay);
        let mut tasks = tokio::task::JoinSet::new();
        for relay_addr in self.config.relay_addrs.iter().copied() {
            tasks.spawn(send_payloads_to_relay(
                socket.clone(),
                relay_addr,
                payloads.clone(),
                pacing,
            ));
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => {
                    return Err(TransportError::Io(std::io::Error::other(format!(
                        "relay send task failed: {error}"
                    ))));
                }
            }
        }

        debug!(
            object_hash = ?hex::encode(&object_hash[..8]),
            chunks = payloads.len(),
            label,
            "Sent authenticated relay payload"
        );
        Ok(())
    }

    /// Compute the Zcash block hash from the header, matching
    /// `CompactBlock::header_hash()` and `CompactBlockBuilder::compute_header_hash()`.
    fn compute_block_hash(&self, block: &CompactBlock) -> [u8; 32] {
        crate::zcash_block_hash(&block.header)
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
            log_raw_segment_chunk_drop(&chunk, "recently delivered");
            return;
        }

        // Validate chunk header
        if !matches!(
            chunk.header.msg_type,
            MessageType::Block | MessageType::RawBlockSegment | MessageType::CompactSkeleton
        ) {
            log_raw_segment_chunk_drop(&chunk, "unsupported message type");
            return;
        }
        if total_chunks == 0 || chunk_id >= total_chunks {
            log_raw_segment_chunk_drop(&chunk, "invalid chunk id or total chunks");
            return; // Drop invalid chunk
        }
        if chunk.header.total_chunks > MAX_TOTAL_CHUNKS {
            log_raw_segment_chunk_drop(&chunk, "too many chunks");
            return; // Drop invalid chunk
        }
        // Version-3 (adaptive) chunks carry a per-block data_shards count and a
        // per-block total, so only version-2 chunks must match the receiver's
        // fixed FEC profile. v3 totals are bounded by the MAX_TOTAL_CHUNKS check
        // above and the header's own `1 <= data_shards < total_chunks` guard.
        let is_v3 = chunk.header.version == 3;
        if !is_v3 {
            let expected_total = self.config.data_shards + self.config.parity_shards;
            if total_chunks != expected_total {
                log_raw_segment_chunk_drop(&chunk, "mismatched FEC profile");
                return; // Drop mismatched FEC config chunks
            }
        }

        // Enforce authentication if configured. Both v2 and v3 are authenticated.
        // Decode (`Chunk::from_bytes`) already restricts a wire-received
        // chunk's version to {2, 3} -- the unauthenticated, no-HMAC version-1
        // wire format has been removed entirely -- so this guard only matters
        // for hand-built `Chunk`s (e.g. in tests) that bypass decode.
        let auth_required = self.config.auth_required;
        if auth_required && chunk.header.version != 2 && chunk.header.version != 3 {
            log_raw_segment_chunk_drop(&chunk, "authentication required");
            return; // Drop unauthenticated chunk
        }
        {
            use crate::transport::RelaySession;
            let session =
                RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", self.config.auth_key);
            let authenticated = match chunk.header.version {
                2 => session.verify_hmac(
                    &block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    &chunk.payload,
                    &chunk.header.hmac,
                ),
                3 => session.verify_hmac_v3(
                    &block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    chunk.header.data_shards,
                    &chunk.payload,
                    &chunk.header.hmac,
                ),
                // Any other version is unreachable for wire-decoded chunks;
                // deny by default rather than assuming authenticated.
                _ => false,
            };
            if !authenticated {
                log_raw_segment_chunk_drop(&chunk, "authentication failed");
                return; // Drop failed auth
            }
        }

        // Get or create assembly
        if !pending.contains_key(&block_hash) && pending.len() >= MAX_PENDING_BLOCKS_CLIENT {
            log_raw_segment_chunk_drop(&chunk, "pending assembly limit reached");
            return;
        }
        let (assembly, original_len) = pending.entry(block_hash).or_insert_with(|| {
            (
                BlockAssembly::new_for_message(block_hash, total_chunks, chunk.header.msg_type),
                0,
            )
        });
        if assembly.total_chunks != total_chunks || assembly.msg_type != chunk.header.msg_type {
            log_raw_segment_chunk_drop(&chunk, "assembly metadata mismatch");
            return;
        }
        // Capture (or validate) the per-block adaptive shard count. v3 chunks
        // carry a nonzero data_shards; v2 carries 0 (fixed profile). All chunks
        // of one block must agree.
        if chunk.header.data_shards != 0 {
            if assembly.data_shards == 0 {
                assembly.data_shards = chunk.header.data_shards;
            } else if assembly.data_shards != chunk.header.data_shards {
                log_raw_segment_chunk_drop(&chunk, "data_shards mismatch");
                return;
            }
        }

        // Drop duplicate chunk to avoid unnecessary work
        if let Some(existing) = assembly.chunks.get(chunk_id)
            && existing.is_some()
        {
            log_raw_segment_chunk_drop(&chunk, "duplicate chunk");
            return;
        }
        // Add chunk
        let msg_type = chunk.header.msg_type;
        assembly.add_chunk(chunk_id, chunk.payload);
        if msg_type == MessageType::RawBlockSegment {
            let received_count = assembly.received_count();
            if received_count == 1
                || received_count == self.config.data_shards
                || received_count % 64 == 0
            {
                info!(
                    object_hash = %hex::encode(block_hash),
                    received_count,
                    total_chunks,
                    data_shards = self.config.data_shards,
                    "Relay raw segment object chunks buffered"
                );
            }
        }

        // Effective data-shard count: the per-block v3 value, or the fixed
        // configured profile for v2 chunks.
        let effective_data_shards = assembly.effective_data_shards(self.config.data_shards);

        // Set original length estimate once we know shard size
        if *original_len == 0
            && let Some(shard) = assembly.chunks.iter().filter_map(|c| c.as_ref()).next()
        {
            *original_len = shard.len() * effective_data_shards;
        }

        // Try to reconstruct if we have enough chunks
        if assembly.can_reconstruct(effective_data_shards) {
            // Extract chunks for decoding
            let shard_opts: Vec<Option<Vec<u8>>> = assembly.chunks.clone();

            // Estimate original length from first chunk if available
            let est_len = *original_len;

            if est_len > 0 {
                match self.decode_payload(msg_type, shard_opts, est_len, effective_data_shards) {
                    Some(payload) => {
                        if msg_type == MessageType::RawBlockSegment {
                            info!(
                                object_hash = %hex::encode(block_hash),
                                "Relay raw segment object reconstructed"
                            );
                        }
                        if let Some(tx) = &self.incoming_tx
                            && tx.send(payload).await.is_err()
                        {
                            warn!(
                                "Failed to deliver reconstructed relay payload (receiver dropped)"
                            );
                        }
                        recent_delivered.insert(block_hash, Instant::now());
                        pending.remove(&block_hash);
                    }
                    None if msg_type == MessageType::RawBlockSegment => {
                        warn!(
                            object_hash = %hex::encode(block_hash),
                            est_len,
                            "Relay raw segment object decode failed"
                        );
                    }
                    None => {}
                }
            }
        }
    }

    fn decode_payload(
        &self,
        msg_type: MessageType,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
        data_shards: usize,
    ) -> Option<RelayPayload> {
        // Decoding runs the Reed-Solomon codec of the per-block shape
        // (data_shards, total_chunks - data_shards). For v2 chunks this equals
        // the fixed configured profile; for v3 it is the adaptive per-block
        // shape carried in the header.
        match msg_type {
            MessageType::Block => self
                .chunker
                .chunks_to_compact_block_with_shards(chunks, original_len, data_shards)
                .ok()
                .map(RelayPayload::CompactBlock),
            MessageType::RawBlockSegment => self
                .chunker
                .chunks_to_raw_block_segment_with_shards(chunks, original_len, data_shards)
                .ok()
                .map(RelayPayload::RawBlockSegment),
            // A skeleton is a serialized CompactBlock; decode it identically but
            // deliver it as a distinct payload so the receiver routes it to the
            // skeleton fast path.
            MessageType::CompactSkeleton => self
                .chunker
                .chunks_to_compact_block_with_shards(chunks, original_len, data_shards)
                .ok()
                .map(RelayPayload::CompactSkeleton),
            MessageType::Keepalive | MessageType::Auth => None,
        }
    }
}

#[derive(Clone, Copy)]
struct SendPacing {
    burst_packets: usize,
    delay: Duration,
}

impl SendPacing {
    fn new(burst_packets: usize, delay: Duration) -> Self {
        Self {
            burst_packets,
            delay,
        }
    }

    fn should_delay(
        self,
        packet_idx: usize,
        packet_count: usize,
        sent_since_delay: &mut usize,
    ) -> bool {
        if self.burst_packets == 0 || self.delay.is_zero() {
            return false;
        }
        *sent_since_delay += 1;
        if *sent_since_delay < self.burst_packets || packet_idx + 1 >= packet_count {
            return false;
        }
        *sent_since_delay = 0;
        true
    }
}

async fn send_payloads_to_relay(
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    payloads: Arc<Vec<Vec<u8>>>,
    pacing: SendPacing,
) -> Result<(), TransportError> {
    let packet_count = payloads.len();
    let mut sent_since_delay = 0usize;
    for (idx, data) in payloads.iter().enumerate() {
        socket.send_to(data, relay_addr).await?;
        if pacing.should_delay(idx, packet_count, &mut sent_since_delay) {
            sleep(pacing.delay).await;
        }
    }
    Ok(())
}

fn log_raw_segment_chunk_drop(chunk: &Chunk, reason: &'static str) {
    if chunk.header.msg_type == MessageType::RawBlockSegment {
        warn!(
            object_hash = %hex::encode(chunk.header.block_hash),
            chunk_id = chunk.header.chunk_id,
            total_chunks = chunk.header.total_chunks,
            reason,
            "Dropping relay raw segment chunk"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[test]
    fn client_creation() {
        let config =
            ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32]).with_fec(2, 1);

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
    async fn client_runs_with_taken_block_receiver() {
        let config = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32]);
        let mut client = RelayClient::new(config).unwrap();
        client.bind().await.unwrap();

        let (_receiver, outgoing) = client
            .take_receiver()
            .expect("receiver should be available before run");

        let result = timeout(
            Duration::from_millis(50),
            client.run_with_outgoing(outgoing),
        )
        .await;
        assert!(
            result.is_err(),
            "client.run_with_outgoing() returned after take_receiver(): {result:?}"
        );
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
        let config =
            ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], [0x42; 32]).with_fec(2, 1);
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

    #[tokio::test]
    async fn client_reconstructs_authenticated_v3_compact_block() {
        // Receive-side v3: a small compact block encoded as adaptive v3 chunks,
        // authenticated with the v3 HMAC, must reassemble using the per-block
        // data_shards from the header and be delivered to the user.
        let auth_key = [0x42; 32];
        let config = ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], auth_key)
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();

        let (tx, mut rx) = mpsc::channel(4);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let compact = CompactBlock::new(vec![0xab; 2189], 0xdead_beef, Vec::new(), Vec::new());
        let block_hash = client.compute_block_hash(&compact);
        let chunks = client
            .chunker
            .compact_block_to_chunks_adaptive(&compact, &block_hash)
            .unwrap();
        assert!(chunks.iter().all(|c| c.header.version == 3));
        assert!(chunks.len() >= 3);

        let session =
            crate::transport::RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", auth_key);
        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();
        let mut recent_delivered = HashMap::new();
        for chunk in chunks {
            let hmac = session.compute_hmac_v3(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                chunk.header.data_shards,
                &chunk.payload,
            );
            let auth_header = ChunkHeader::new_block_authenticated_v3(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                chunk.header.data_shards,
                hmac,
            );
            client
                .handle_incoming_chunk(
                    Chunk::new(auth_header, chunk.payload),
                    &mut pending,
                    &mut recent_delivered,
                )
                .await;
        }

        let delivered = timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("v3 compact block should be delivered")
            .expect("channel open");
        match delivered {
            RelayPayload::CompactBlock(block) => {
                assert_eq!(block.nonce, 0xdead_beef);
                assert_eq!(block.header, vec![0xab; 2189]);
            }
            other => panic!("expected compact block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_reassembles_and_delivers_compact_skeleton() {
        // A skeleton encoded under MessageType::CompactSkeleton, routed by its
        // domain-separated object id, must reassemble and be delivered as a
        // distinct RelayPayload::CompactSkeleton (not a CompactBlock).
        let auth_key = [0x42; 32];
        let config = ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], auth_key)
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();

        let (tx, mut rx) = mpsc::channel(4);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let skeleton = CompactBlock::new(vec![0xab; 2189], 0xfeed, Vec::new(), Vec::new());
        let block_hash = client.compute_block_hash(&skeleton);
        let object_hash = crate::segmented_block::skeleton_object_hash(block_hash);
        let chunks = client
            .chunker
            .compact_block_to_chunks_skeleton(&skeleton, &object_hash)
            .unwrap();
        assert!(
            chunks
                .iter()
                .all(|c| c.header.msg_type == MessageType::CompactSkeleton)
        );
        assert!(chunks.iter().all(|c| c.header.version == 3));

        let session =
            crate::transport::RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", auth_key);
        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();
        let mut recent_delivered = HashMap::new();
        for chunk in chunks {
            let hmac = session.compute_hmac_v3(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                chunk.header.data_shards,
                &chunk.payload,
            );
            let auth_header = ChunkHeader::new_compact_skeleton_authenticated_v3(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                chunk.header.data_shards,
                hmac,
            );
            client
                .handle_incoming_chunk(
                    Chunk::new(auth_header, chunk.payload),
                    &mut pending,
                    &mut recent_delivered,
                )
                .await;
        }

        let delivered = timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("skeleton should be delivered")
            .expect("channel open");
        match delivered {
            RelayPayload::CompactSkeleton(block) => {
                assert_eq!(block.nonce, 0xfeed);
                assert_eq!(block.header, vec![0xab; 2189]);
            }
            other => panic!("expected compact skeleton, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_drops_v3_chunk_with_tampered_data_shards() {
        // A v3 chunk whose data_shards is altered after HMAC computation must
        // fail authentication (the v3 HMAC covers data_shards).
        let auth_key = [0x42; 32];
        let config = ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], auth_key)
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let compact = CompactBlock::new(vec![0xcd; 2189], 1, Vec::new(), Vec::new());
        let block_hash = client.compute_block_hash(&compact);
        let chunks = client
            .chunker
            .compact_block_to_chunks_adaptive(&compact, &block_hash)
            .unwrap();
        let session =
            crate::transport::RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", auth_key);

        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();
        let mut recent_delivered = HashMap::new();
        let chunk = &chunks[0];
        let hmac = session.compute_hmac_v3(
            &chunk.header.block_hash,
            chunk.header.chunk_id,
            chunk.header.total_chunks,
            chunk.header.payload_len,
            chunk.header.data_shards,
            &chunk.payload,
        );
        // Tamper: bump data_shards in the header but keep the HMAC over the old value.
        let tampered = ChunkHeader::new_block_authenticated_v3(
            &chunk.header.block_hash,
            chunk.header.chunk_id,
            chunk.header.total_chunks,
            chunk.header.payload_len,
            chunk.header.data_shards + 1,
            hmac,
        );
        client
            .handle_incoming_chunk(
                Chunk::new(tampered, chunk.payload.clone()),
                &mut pending,
                &mut recent_delivered,
            )
            .await;

        assert!(pending.is_empty(), "tampered v3 chunk must be dropped");
        let recv = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(recv.is_err() || recv.unwrap().is_none());
    }

    #[tokio::test]
    async fn client_tracks_raw_segment_assembly_type() {
        // Chunk verification always checks the HMAC for v2/v3 chunks
        // regardless of `auth_required` (see `handle_incoming_chunk`), so the
        // test chunk must carry a real HMAC computed with the client's
        // configured key -- there is no unauthenticated wire format any more
        // for a placeholder header to fall back to.
        let auth_key = [0x42; 32];
        let config =
            ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], auth_key).with_fec(2, 1);
        let client = RelayClient::new(config).unwrap();

        let (tx, _rx) = mpsc::channel(1);
        let mut client = client;
        client.incoming_tx = Some(tx);

        let mut pending: HashMap<[u8; 32], (BlockAssembly, usize)> = HashMap::new();

        let block_hash = [0xcd; 32];
        let payload = vec![1, 2, 3, 4];
        let session =
            crate::transport::RelaySession::new("0.0.0.0:0".parse().unwrap(), "client", auth_key);
        let hmac = session.compute_hmac(&block_hash, 0, 3, payload.len() as u16, &payload);
        let header = ChunkHeader::new_raw_block_segment_authenticated(&block_hash, 0, 3, 4, hmac);
        let chunk = Chunk::new(header, payload);

        let mut recent_delivered = HashMap::new();
        client
            .handle_incoming_chunk(chunk, &mut pending, &mut recent_delivered)
            .await;

        let (assembly, _) = pending.get(&block_hash).unwrap();
        assert_eq!(assembly.msg_type, MessageType::RawBlockSegment);
        assert_eq!(assembly.total_chunks, 3);
        assert_eq!(assembly.received_count(), 1);
    }

    #[tokio::test]
    async fn client_sends_paced_relay_copies_concurrently() {
        let relay_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addrs = vec![
            relay_one.local_addr().unwrap(),
            relay_two.local_addr().unwrap(),
        ];
        let config = ClientConfig::new(relay_addrs, [0x42; 32])
            .with_fec(2, 1)
            .with_send_pacing(1, Duration::from_millis(40));
        let client = RelayClient::new(config).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let block_hash = [0xee; 32];
        let chunks = (0..4)
            .map(|chunk_id| {
                Chunk::new(
                    ChunkHeader::new_block(&block_hash, chunk_id, 4, 4),
                    vec![chunk_id as u8; 4],
                )
            })
            .collect();

        let started = Instant::now();
        client
            .send_chunks_internal(Arc::new(socket), &block_hash, chunks, "test block")
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(220),
            "paced relay fanout should not serialize every relay copy; elapsed={elapsed:?}"
        );
    }

    #[test]
    fn send_pacing_delays_after_configured_bursts() {
        let pacing = SendPacing::new(3, Duration::from_millis(1));
        let mut sent_since_delay = 0;

        assert!(!pacing.should_delay(0, 7, &mut sent_since_delay));
        assert!(!pacing.should_delay(1, 7, &mut sent_since_delay));
        assert!(pacing.should_delay(2, 7, &mut sent_since_delay));
        assert_eq!(sent_since_delay, 0);
        assert!(!pacing.should_delay(3, 7, &mut sent_since_delay));
        assert!(!pacing.should_delay(4, 7, &mut sent_since_delay));
        assert!(pacing.should_delay(5, 7, &mut sent_since_delay));
        assert!(!pacing.should_delay(6, 7, &mut sent_since_delay));
    }

    #[test]
    fn send_pacing_disabled_with_zero_delay_or_burst() {
        for pacing in [
            SendPacing::new(0, Duration::from_millis(1)),
            SendPacing::new(3, Duration::ZERO),
        ] {
            let mut sent_since_delay = 0;
            assert!(!pacing.should_delay(0, 3, &mut sent_since_delay));
            assert!(!pacing.should_delay(1, 3, &mut sent_since_delay));
            assert!(!pacing.should_delay(2, 3, &mut sent_since_delay));
        }
    }
}
