//! Relay node server implementation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::fec::FecError;
use crate::segmented_block::{RawBlockSegment, segment_object_hash};
use crate::transport::{
    AuthKey, BlockAssembly, BlockChunker, Chunk, ChunkHeader, EquihashPowValidator,
    MAX_TOTAL_CHUNKS, MessageType, PowResult, PowValidator, RelayConfig, RelaySession,
    TransportError, ZCASH_FULL_HEADER_SIZE,
};

use super::ArrivalSink;
use super::metrics::RelayMetrics;

const MAX_VALIDATED_RAW_BLOCKS: usize = 4096;
const VALIDATED_RAW_BLOCK_TTL: Duration = Duration::from_secs(120);

/// Key-id sentinel bound to sessions admitted while auth is not required
/// (`allow_unauthenticated_peers`). Never a real configured key id, since
/// [`crate::transport::config`] identity labels are restricted to
/// `[A-Za-z0-9_-]{1,32}` and this sentinel is intentionally outside that
/// pattern's spirit by convention (still matches the charset, but reserved).
const UNAUTHENTICATED_KEY_ID: &str = "unauthenticated";

#[derive(Clone, Copy)]
struct ValidatedRawBlock {
    segment_count: u16,
    raw_block_len: u64,
    raw_block_digest: [u8; 32],
    validated_at: Instant,
}

impl ValidatedRawBlock {
    fn from_segment_zero(segment: &RawBlockSegment) -> Self {
        Self {
            segment_count: segment.segment_count,
            raw_block_len: segment.raw_block_len,
            raw_block_digest: segment.raw_block_digest,
            validated_at: Instant::now(),
        }
    }

    fn matches_segment(self, segment: &RawBlockSegment) -> bool {
        self.segment_count == segment.segment_count
            && self.raw_block_len == segment.raw_block_len
            && self.raw_block_digest == segment.raw_block_digest
    }
}

struct ReadyChunks {
    msg_type: MessageType,
    block_hash: [u8; 32],
    total_chunks: u16,
    /// Per-block FEC data-shard count (0 for v2, nonzero for adaptive v3).
    /// Carried so the forward path re-emits v3 chunks (with v3 HMAC) intact.
    data_shards: u16,
    chunks: Vec<(u16, Vec<u8>)>,
}

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
    /// Raw block metadata with validated segment-0 PoW, keyed by parent block hash
    validated_raw_blocks: Arc<Mutex<HashMap<[u8; 32], ValidatedRawBlock>>>,
    /// Optional per-block relay arrival logger (observatory timing source)
    arrival_sink: Option<ArrivalSink>,
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
            validated_raw_blocks: Arc::new(Mutex::new(HashMap::new())),
            arrival_sink: None,
        })
    }

    /// Attach (or clear) the per-block relay arrival logger. When set, the node
    /// appends a `relay_block_received` event (keyed by the Zcash consensus block
    /// hash) each time it reconstructs a PoW-valid raw block.
    pub fn with_arrival_sink(mut self, sink: Option<ArrivalSink>) -> Self {
        self.arrival_sink = sink;
        self
    }

    /// Get the listen address from config
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Check if a key is authorized
    pub fn is_authorized(&self, key: &[u8; 32]) -> bool {
        self.config.authorized_keys.iter().any(|k| &k.key == key)
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
                    self.metrics.inc_socket_receive_errors();
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
            let stats = session.cleanup_assemblies(assembly_timeout, self.config.data_shards);
            self.metrics
                .add_assembly_misses(stats.expired_incomplete, stats.expired_incomplete_near);
            session.cleanup_recent();
        }
        let expired = (before - sessions.len()) as u64;
        if expired > 0 {
            self.metrics.add_sessions_expired(expired);
        }
        self.cleanup_validated_raw_blocks();
    }

    /// Estimate original serialized length based on shard size.
    ///
    /// Uses the assembly's effective data-shard count: the per-block adaptive
    /// (v3) value when present, else the fixed configured profile.
    fn estimate_original_len(&self, assembly: &BlockAssembly) -> Option<usize> {
        let shard_size = assembly
            .chunks
            .iter()
            .filter_map(|c| c.as_ref())
            .map(|c| c.len())
            .next()?;
        Some(shard_size * assembly.effective_data_shards(self.config.data_shards))
    }

    /// Validate PoW once we can reconstruct serialized data
    fn validate_pow_from_assembly(
        &self,
        assembly: &BlockAssembly,
        msg_type: MessageType,
    ) -> Option<bool> {
        match msg_type {
            // A skeleton carries the full block header in its serialized
            // CompactBlock, so PoW validates exactly like a compact block.
            MessageType::Block | MessageType::CompactSkeleton => {
                self.validate_compact_block_pow(assembly)
            }
            MessageType::RawBlockSegment => self.validate_raw_block_segment(assembly),
            MessageType::Keepalive | MessageType::Auth => None,
        }
    }

    fn validate_compact_block_pow(&self, assembly: &BlockAssembly) -> Option<bool> {
        let est_len = self.estimate_original_len(assembly)?;
        let data_shards = assembly.effective_data_shards(self.config.data_shards);
        let data = match self.chunker.decode_data_with_shards(
            assembly.chunks.clone(),
            est_len,
            data_shards,
        ) {
            Ok(data) => data,
            Err(_) => return None,
        };

        if data.len() < 4 {
            return None;
        }
        let content_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if content_len < 4 || data.len() < 4 + content_len {
            return None;
        }

        let content = &data[4..4 + content_len];
        let header_len =
            u32::from_le_bytes([content[0], content[1], content[2], content[3]]) as usize;
        if header_len == 0 || content.len() < 4 + header_len {
            return None;
        }

        let header = &content[4..4 + header_len];
        match self.validator.validate(header) {
            PowResult::Valid => Some(true),
            PowResult::Invalid => Some(false),
            PowResult::Indeterminate => None,
        }
    }

    fn validate_raw_block_segment(&self, assembly: &BlockAssembly) -> Option<bool> {
        let segment = self.decode_raw_segment_from_assembly(assembly)?;
        let expected_object_hash = segment_object_hash(segment.block_hash, segment.segment_index);
        if expected_object_hash != assembly.block_hash {
            return Some(false);
        }

        if segment.segment_index != 0 {
            return Some(self.raw_segment_matches_validated_segment_zero(&segment));
        }

        if segment.payload.len() < ZCASH_FULL_HEADER_SIZE {
            return None;
        }
        let header = &segment.payload[..ZCASH_FULL_HEADER_SIZE];
        if raw_block_header_hash(header) != segment.block_hash {
            return Some(false);
        }

        match self.validator.validate(header) {
            PowResult::Valid => {
                self.record_validated_raw_block(&segment);
                // First moment this region's relay holds a PoW-valid block via
                // the relay path: log its consensus block hash so the observatory
                // can join it against native-P2P arrivals for the same block.
                if let Some(sink) = &self.arrival_sink {
                    sink.relay_block_received(&crate::hash::consensus_block_hash_display(header));
                }
                Some(true)
            }
            PowResult::Invalid => Some(false),
            PowResult::Indeterminate => None,
        }
    }

    fn decode_raw_segment_from_assembly(
        &self,
        assembly: &BlockAssembly,
    ) -> Option<RawBlockSegment> {
        let est_len = self.estimate_original_len(assembly)?;
        let data_shards = assembly.effective_data_shards(self.config.data_shards);
        self.chunker
            .chunks_to_raw_block_segment_with_shards(assembly.chunks.clone(), est_len, data_shards)
            .ok()
    }

    fn record_validated_raw_block(&self, segment_zero: &RawBlockSegment) {
        let mut validated = self
            .validated_raw_blocks
            .lock()
            .expect("validated raw block cache poisoned");
        cleanup_validated_raw_blocks_locked(&mut validated);
        if validated.len() >= MAX_VALIDATED_RAW_BLOCKS {
            evict_oldest_validated_raw_block(&mut validated);
        }
        validated.insert(
            segment_zero.block_hash,
            ValidatedRawBlock::from_segment_zero(segment_zero),
        );
    }

    fn raw_segment_matches_validated_segment_zero(&self, segment: &RawBlockSegment) -> bool {
        let mut validated = self
            .validated_raw_blocks
            .lock()
            .expect("validated raw block cache poisoned");
        cleanup_validated_raw_blocks_locked(&mut validated);
        validated
            .get(&segment.block_hash)
            .is_some_and(|entry| entry.matches_segment(segment))
    }

    fn cleanup_validated_raw_blocks(&self) {
        let mut validated = self
            .validated_raw_blocks
            .lock()
            .expect("validated raw block cache poisoned");
        cleanup_validated_raw_blocks_locked(&mut validated);
    }

    fn refresh_cached_raw_segment_assemblies(&self, session: &mut RelaySession) {
        let raw_segment_object_hashes: Vec<[u8; 32]> = session
            .pending_blocks
            .iter()
            .filter_map(|(object_hash, assembly)| {
                if assembly.msg_type == MessageType::RawBlockSegment && !assembly.pow_validated {
                    Some(*object_hash)
                } else {
                    None
                }
            })
            .collect();

        for object_hash in raw_segment_object_hashes {
            let should_forward = {
                let Some(assembly) = session.pending_blocks.get(&object_hash) else {
                    continue;
                };
                self.decode_raw_segment_from_assembly(assembly)
                    .is_some_and(|segment| {
                        segment.segment_index != 0
                            && self.raw_segment_matches_validated_segment_zero(&segment)
                    })
            };
            if should_forward && let Some(assembly) = session.pending_blocks.get_mut(&object_hash) {
                assembly.pow_validated = true;
                self.metrics.inc_raw_segment_cached_promotions();
            }
        }
    }

    fn collect_ready_chunks(&self, session: &mut RelaySession) -> Vec<ReadyChunks> {
        let mut ready_objects = Vec::new();
        for assembly in session.pending_blocks.values_mut() {
            if !assembly.pow_validated {
                continue;
            }

            let mut chunks = Vec::new();
            for (idx, payload) in assembly.chunks.iter().enumerate() {
                if let Some(data) = payload
                    && !assembly.forwarded[idx]
                {
                    assembly.forwarded[idx] = true;
                    chunks.push((idx as u16, data.clone()));
                }
            }

            if !chunks.is_empty() {
                ready_objects.push(ReadyChunks {
                    msg_type: assembly.msg_type,
                    block_hash: assembly.block_hash,
                    total_chunks: assembly.total_chunks as u16,
                    data_shards: assembly.data_shards,
                    chunks,
                });
            }
        }
        ready_objects
    }

    /// Forward chunks to all other sessions
    #[allow(clippy::too_many_arguments)]
    async fn forward_to_peers(
        &self,
        src_addr: SocketAddr,
        msg_type: MessageType,
        block_hash: &[u8; 32],
        total_chunks: u16,
        data_shards: u16,
        chunks: &[(u16, Vec<u8>)],
    ) -> Result<(), TransportError> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not bound",
            ))
        })?;

        let sessions = self.sessions.read().await;
        let mut outbound: Vec<(SocketAddr, String, Vec<Vec<u8>>)> = Vec::new();

        for (peer_addr, session) in sessions.iter() {
            // Don't forward back to sender
            if *peer_addr == src_addr {
                continue;
            }

            // Forward all available chunks and count them. Every forwarded
            // chunk is authenticated with the receiving peer's session key
            // (which is a real shared secret for authenticated sessions, or
            // the zero key for sessions admitted while auth is not required)
            // and re-emitted as a full v2/v3-shaped header -- there is no
            // unauthenticated, no-HMAC wire format any more. Version-3
            // (adaptive) objects (data_shards > 0) must be re-emitted as v3
            // chunks carrying the same per-block data_shards, authenticated
            // with the v3 HMAC that covers data_shards, so the next hop can
            // decode them.
            //
            // Per-key-identity hardening (PR-A): each session is bound to a
            // named auth key at admission time (`RelaySession::key_id`), and
            // every chunk forwarded to it is MAC'd with THAT session's own
            // key -- never a single global send key. For the fleet today,
            // every live session's bound key IS the fleet key, so this is
            // wire-identical to the old global-key broadcast; the moment an
            // invitee session is bound to its own key instead, its forwards
            // become independently verifiable/attributable without ever
            // sharing the fleet key with it. Payload bytes are shared across
            // sessions (`chunks` is built once by the caller); only the
            // header/HMAC differs per session.
            let mut payloads: Vec<Vec<u8>> = Vec::new();
            for (chunk_id, data) in chunks.iter() {
                let payload_len = data.len() as u16;
                let header = if data_shards > 0 {
                    let hmac = session.compute_hmac_v3(
                        block_hash,
                        *chunk_id,
                        total_chunks,
                        payload_len,
                        data_shards,
                        data,
                    );
                    authenticated_data_header_v3(
                        msg_type,
                        block_hash,
                        *chunk_id,
                        total_chunks,
                        payload_len,
                        data_shards,
                        hmac,
                    )?
                } else {
                    let hmac = session.compute_hmac(
                        block_hash,
                        *chunk_id,
                        total_chunks,
                        payload_len,
                        data,
                    );
                    authenticated_data_header(
                        msg_type,
                        block_hash,
                        *chunk_id,
                        total_chunks,
                        payload_len,
                        hmac,
                    )?
                };
                let chunk = Chunk::new(header, data.clone());
                payloads.push(chunk.to_bytes());
            }
            if !payloads.is_empty() {
                outbound.push((*peer_addr, session.key_id().to_string(), payloads));
            }
        }
        drop(sessions);

        if outbound.is_empty() && !chunks.is_empty() {
            self.metrics.inc_forward_no_peer_chunks(chunks.len() as u64);
        }

        let pacing = ForwardPacing::new(
            self.config.forward_burst_packets,
            self.config.forward_burst_delay,
        );
        for (peer_addr, key_id, payloads) in outbound {
            let mut chunks_sent: u64 = 0;
            let payload_count = payloads.len();
            let mut sent_since_delay = 0usize;
            for (idx, data) in payloads.into_iter().enumerate() {
                match socket.send_to(&data, peer_addr).await {
                    Ok(_) => chunks_sent += 1,
                    Err(error) => {
                        self.metrics.inc_packet_send_errors();
                        warn!(peer = %peer_addr, %error, "Failed to forward relay packet");
                    }
                }
                if pacing.should_delay(idx, payload_count, &mut sent_since_delay) {
                    sleep(pacing.delay).await;
                }
            }
            if chunks_sent > 0 {
                self.metrics.inc_packets_forwarded(chunks_sent);
                self.metrics
                    .inc_chunks_forwarded_for_key(&key_id, chunks_sent);
                match msg_type {
                    MessageType::Block => {
                        self.metrics.inc_compact_block_chunks_forwarded(chunks_sent)
                    }
                    MessageType::RawBlockSegment => {
                        self.metrics.inc_raw_segment_chunks_forwarded(chunks_sent)
                    }
                    // Skeleton chunk forwarding is not counted under a dedicated
                    // node metric (skeleton observability lives on the sidecar,
                    // which reports fast-path wins); forwarding still happens.
                    MessageType::CompactSkeleton => {}
                    MessageType::Keepalive | MessageType::Auth => {}
                }
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
    ) -> Vec<ReadyChunks> {
        if !session.mark_chunk_seen(block_hash, chunk.header.chunk_id) {
            if chunk.header.msg_type == MessageType::RawBlockSegment {
                self.metrics.inc_raw_segment_duplicate_chunks();
            }
            return Vec::new();
        }
        {
            let Some(assembly) = session.get_or_create_assembly_for_message(
                block_hash,
                total_chunks,
                chunk.header.msg_type,
            ) else {
                self.metrics.inc_invalid_chunks();
                return Vec::new();
            };
            if assembly.msg_type != chunk.header.msg_type || assembly.total_chunks != total_chunks {
                self.metrics.inc_invalid_chunks();
                return Vec::new();
            }
            // Capture (or validate) the per-block adaptive shard count carried by
            // version-3 chunks. v2 carries 0 (fixed profile); all chunks of one
            // object must agree.
            if chunk.header.data_shards != 0 {
                if assembly.data_shards == 0 {
                    assembly.data_shards = chunk.header.data_shards;
                } else if assembly.data_shards != chunk.header.data_shards {
                    self.metrics.inc_invalid_chunks();
                    return Vec::new();
                }
            }
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
                match self.validate_pow_from_assembly(assembly, chunk.header.msg_type) {
                    Some(valid) => {
                        if chunk.header.msg_type == MessageType::RawBlockSegment {
                            if valid {
                                self.metrics.inc_raw_segment_validation_successes();
                                self.metrics.record_reconstruct_latency_ms(
                                    assembly.started_at.elapsed().as_millis() as u64,
                                );
                            } else {
                                self.metrics.inc_raw_segment_validation_failures();
                            }
                        }
                        assembly.pow_validated = valid;
                    }
                    None => {
                        if chunk.header.msg_type == MessageType::RawBlockSegment {
                            self.metrics.inc_raw_segment_validation_deferred();
                        }
                    }
                }
            }
        }

        if chunk.header.msg_type == MessageType::RawBlockSegment {
            self.refresh_cached_raw_segment_assemblies(session);
        }

        self.collect_ready_chunks(session)
    }
}

#[derive(Clone, Copy)]
struct ForwardPacing {
    burst_packets: usize,
    delay: Duration,
}

impl ForwardPacing {
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

fn cleanup_validated_raw_blocks_locked(validated: &mut HashMap<[u8; 32], ValidatedRawBlock>) {
    validated.retain(|_, entry| entry.validated_at.elapsed() <= VALIDATED_RAW_BLOCK_TTL);
}

fn evict_oldest_validated_raw_block(validated: &mut HashMap<[u8; 32], ValidatedRawBlock>) {
    let Some(oldest) = validated
        .iter()
        .min_by_key(|(_, entry)| entry.validated_at)
        .map(|(block_hash, _)| *block_hash)
    else {
        return;
    };
    validated.remove(&oldest);
}

impl<V: PowValidator> RelayNode<V> {
    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), TransportError> {
        self.metrics.inc_packets_received();

        let chunk = Chunk::from_bytes(data)?;

        if chunk.header.msg_type == MessageType::Keepalive {
            return self.handle_keepalive(src_addr, &chunk).await;
        }

        // Validate chunk type and counts
        if !matches!(
            chunk.header.msg_type,
            MessageType::Block | MessageType::RawBlockSegment | MessageType::CompactSkeleton
        ) {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(format!(
                "unsupported message type: {:?}",
                chunk.header.msg_type
            )));
        }

        match chunk.header.msg_type {
            MessageType::Block => self.metrics.inc_compact_block_chunks_received(),
            MessageType::RawBlockSegment => self.metrics.inc_raw_segment_chunks_received(),
            // Not counted under a dedicated node metric; forwarded like a block.
            MessageType::CompactSkeleton => {}
            MessageType::Keepalive | MessageType::Auth => {}
        }
        if chunk.header.total_chunks == 0 || chunk.header.total_chunks > MAX_TOTAL_CHUNKS {
            self.metrics.inc_invalid_chunks();
            return Err(TransportError::InvalidChunk(format!(
                "invalid total_chunks: {}",
                chunk.header.total_chunks
            )));
        }

        // Version-3 (adaptive) chunks carry a per-block total_chunks; only
        // version-2 chunks must match this relay's fixed FEC profile. The
        // per-block total is still bounded by the MAX_TOTAL_CHUNKS check above
        // and the header's `1 <= data_shards < total_chunks` guard.
        if chunk.header.version != 3 {
            let expected_total = (self.config.data_shards + self.config.parity_shards) as u16;
            if chunk.header.total_chunks != expected_total {
                self.metrics.inc_invalid_chunks();
                return Err(TransportError::InvalidChunk(format!(
                    "unexpected total_chunks: got {}, expected {}",
                    chunk.header.total_chunks, expected_total
                )));
            }
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

        let chunks_to_forward: Vec<ReadyChunks> = {
            let mut sessions = self.sessions.write().await;

            if let Some(session) = sessions.get_mut(&src_addr) {
                // Existing session - enforce auth if configured. Decode already
                // restricts `chunk.header.version` to {2, 3} (the removed
                // version 1 is rejected in `Chunk::from_bytes`), so there is no
                // separate "unauthenticated wire format" case to gate here.
                let auth_required = self.config.auth_required();
                if auth_required && !verify_data_chunk_hmac(session, &chunk, &block_hash) {
                    warn!(peer = %src_addr, "HMAC verification failed for existing session");
                    self.metrics.inc_auth_failures();
                    return Err(TransportError::AuthenticationFailed);
                }
                session.touch();
                self.process_chunk_for_session(session, &chunk, block_hash, chunk_id, total_chunks)
            } else {
                if sessions.len() >= self.config.max_sessions {
                    self.metrics.inc_session_limit_rejections();
                    warn!(peer = %src_addr, max_sessions = self.config.max_sessions, "Relay session limit reached");
                    return Err(TransportError::ConnectionRefused(
                        "relay session limit reached".into(),
                    ));
                }

                // New session - authenticate
                if !self.config.auth_required() {
                    // No auth required
                    debug!(peer = %src_addr, "Creating unauthenticated session");
                    sessions.insert(
                        src_addr,
                        RelaySession::new(src_addr, UNAUTHENTICATED_KEY_ID, [0u8; 32]),
                    );
                    self.metrics.inc_sessions_created();
                    self.metrics
                        .inc_sessions_created_for_key(UNAUTHENTICATED_KEY_ID);
                    let session = sessions.get_mut(&src_addr).unwrap();
                    self.process_chunk_for_session(
                        session,
                        &chunk,
                        block_hash,
                        chunk_id,
                        total_chunks,
                    )
                } else {
                    // Decode already restricts `chunk.header.version` to {2, 3},
                    // so any well-formed chunk reaching here is v2 or v3 and can
                    // be checked against the authorized-key list.
                    let mut authenticated_key: Option<AuthKey> = None;
                    for key in &self.config.authorized_keys {
                        let temp_session = RelaySession::new(src_addr, key.id.clone(), key.key);
                        if verify_data_chunk_hmac(&temp_session, &chunk, &block_hash) {
                            authenticated_key = Some(key.clone());
                            break;
                        }
                    }

                    if let Some(key) = authenticated_key {
                        info!(peer = %src_addr, key_id = %key.id, "Authenticated new session");
                        sessions.insert(
                            src_addr,
                            RelaySession::new(src_addr, key.id.clone(), key.key),
                        );
                        self.metrics.inc_sessions_created();
                        self.metrics.inc_sessions_created_for_key(&key.id);
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
                }
            }
        };

        for ready in chunks_to_forward {
            self.forward_to_peers(
                src_addr,
                ready.msg_type,
                &ready.block_hash,
                ready.total_chunks,
                ready.data_shards,
                &ready.chunks,
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
                warn!(peer = %src_addr, "Auth required but received unsupported keepalive version");
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
            self.metrics.inc_session_limit_rejections();
            warn!(peer = %src_addr, max_sessions = self.config.max_sessions, "Relay session limit reached");
            return Err(TransportError::ConnectionRefused(
                "relay session limit reached".into(),
            ));
        }

        if !self.config.auth_required() {
            debug!(peer = %src_addr, "Creating unauthenticated keepalive session");
            sessions.insert(
                src_addr,
                RelaySession::new(src_addr, UNAUTHENTICATED_KEY_ID, [0u8; 32]),
            );
            self.metrics.inc_sessions_created();
            self.metrics
                .inc_sessions_created_for_key(UNAUTHENTICATED_KEY_ID);
            return Ok(());
        }

        if chunk.header.version != 2 {
            warn!(peer = %src_addr, "Auth required but received unsupported keepalive version");
            self.metrics.inc_auth_failures();
            return Err(TransportError::AuthenticationFailed);
        }

        let mut authenticated_key: Option<AuthKey> = None;
        for key in &self.config.authorized_keys {
            let temp_session = RelaySession::new(src_addr, key.id.clone(), key.key);
            if temp_session.verify_hmac(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                &chunk.payload,
                &chunk.header.hmac,
            ) {
                authenticated_key = Some(key.clone());
                break;
            }
        }

        if let Some(key) = authenticated_key {
            info!(peer = %src_addr, key_id = %key.id, "Authenticated new keepalive session");
            sessions.insert(
                src_addr,
                RelaySession::new(src_addr, key.id.clone(), key.key),
            );
            self.metrics.inc_sessions_created();
            self.metrics.inc_sessions_created_for_key(&key.id);
            Ok(())
        } else {
            warn!(peer = %src_addr, "Keepalive authentication failed - no matching key");
            self.metrics.inc_auth_failures();
            Err(TransportError::AuthenticationFailed)
        }
    }
}

fn authenticated_data_header(
    msg_type: MessageType,
    object_hash: &[u8; 32],
    chunk_id: u16,
    total_chunks: u16,
    payload_len: u16,
    hmac: [u8; 32],
) -> Result<ChunkHeader, TransportError> {
    match msg_type {
        MessageType::Block => Ok(ChunkHeader::new_block_authenticated(
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        )),
        MessageType::RawBlockSegment => Ok(ChunkHeader::new_raw_block_segment_authenticated(
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        )),
        MessageType::CompactSkeleton => Ok(ChunkHeader::new_compact_skeleton_authenticated(
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        )),
        MessageType::Keepalive | MessageType::Auth => Err(TransportError::InvalidChunk(
            "unsupported forwarded chunk message type".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn authenticated_data_header_v3(
    msg_type: MessageType,
    object_hash: &[u8; 32],
    chunk_id: u16,
    total_chunks: u16,
    payload_len: u16,
    data_shards: u16,
    hmac: [u8; 32],
) -> Result<ChunkHeader, TransportError> {
    match msg_type {
        MessageType::Block => Ok(ChunkHeader::new_block_authenticated_v3(
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        )),
        MessageType::RawBlockSegment => Ok(ChunkHeader::new_raw_block_segment_authenticated_v3(
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        )),
        MessageType::CompactSkeleton => Ok(ChunkHeader::new_compact_skeleton_authenticated_v3(
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        )),
        MessageType::Keepalive | MessageType::Auth => Err(TransportError::InvalidChunk(
            "unsupported forwarded chunk message type".into(),
        )),
    }
}

fn raw_block_header_hash(header: &[u8]) -> [u8; 32] {
    crate::zcash_block_hash(header)
}

/// Verify a data chunk's HMAC against `session`, selecting the v2 or v3 HMAC
/// coverage by header version. Version 1 (the removed, unauthenticated wire
/// format) can no longer reach this function: `Chunk::from_bytes` rejects it
/// during decode, so `chunk.header.version` is always 2 or 3 here.
fn verify_data_chunk_hmac(session: &RelaySession, chunk: &Chunk, block_hash: &[u8; 32]) -> bool {
    match chunk.header.version {
        2 => session.verify_hmac(
            block_hash,
            chunk.header.chunk_id,
            chunk.header.total_chunks,
            chunk.header.payload_len,
            &chunk.payload,
            &chunk.header.hmac,
        ),
        3 => session.verify_hmac_v3(
            block_hash,
            chunk.header.chunk_id,
            chunk.header.total_chunks,
            chunk.header.payload_len,
            chunk.header.data_shards,
            &chunk.payload,
            &chunk.header.hmac,
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompactBlock, MAX_PAYLOAD_SIZE, StubPowValidator, split_raw_block};
    use std::time::Duration;
    use tokio::time::timeout;

    #[derive(Clone)]
    struct HeaderPrefixValidator([u8; 4]);

    impl PowValidator for HeaderPrefixValidator {
        fn validate(&self, header: &[u8]) -> PowResult {
            if header.starts_with(&self.0) {
                PowResult::Valid
            } else {
                PowResult::Invalid
            }
        }
    }

    fn raw_segment_assembly<V: PowValidator>(
        node: &RelayNode<V>,
        segment: &RawBlockSegment,
    ) -> BlockAssembly {
        let object_hash = segment_object_hash(segment.block_hash, segment.segment_index);
        let chunks = node.chunker.raw_block_segment_to_chunks(segment).unwrap();
        let mut assembly =
            BlockAssembly::new_for_message(object_hash, chunks.len(), MessageType::RawBlockSegment);
        for chunk in chunks {
            assembly.add_chunk(chunk.header.chunk_id as usize, chunk.payload);
        }
        assembly
    }

    #[test]
    fn relay_node_creation() {
        let config = RelayConfig::new("127.0.0.1:8333".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", [0x42; 32])]);

        let node = RelayNode::new(config).unwrap();

        assert_eq!(node.listen_addr().port(), 8333);
        assert!(node.is_authorized(&[0x42; 32]));
        assert!(!node.is_authorized(&[0x00; 32]));
        assert!(!node.is_running());
    }

    #[tokio::test]
    async fn packet_matched_by_second_key_creates_session_attributed_to_that_key() {
        // Per-key-identity hardening (PR-A): with two named keys configured,
        // a session must be attributed to whichever key actually matched --
        // not always the first/fleet key.
        let alice_key = [0x11; 32];
        let bob_key = [0x22; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![
            AuthKey::new("alice", alice_key),
            AuthKey::new("bob", bob_key),
        ]);
        let mut node = RelayNode::new(config.clone()).unwrap();
        node.bind().await.unwrap();

        let src_addr: SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let block_hash = [0x9a; 32];
        let payload = vec![5u8; 10];
        let payload_len = payload.len() as u16;
        let total_chunks = (config.data_shards + config.parity_shards) as u16;
        let chunk_id = 0u16;

        // Build a chunk authenticated with bob's key (the SECOND configured
        // key), so the match loop must fall through past alice's key.
        let bob_session = RelaySession::new(src_addr, "bob", bob_key);
        let hmac =
            bob_session.compute_hmac(&block_hash, chunk_id, total_chunks, payload_len, &payload);
        let header = ChunkHeader::new_block_authenticated(
            &block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        );
        let chunk = Chunk::new(header, payload);

        node.handle_packet(&chunk.to_bytes(), src_addr)
            .await
            .unwrap();

        let sessions = node.sessions.read().await;
        let session = sessions.get(&src_addr).expect("session should be created");
        assert_eq!(session.key_id(), "bob");
    }

    #[tokio::test]
    async fn relay_node_session_count() {
        let config = RelayConfig::default().with_unauthenticated_peers_allowed(true);
        let node = RelayNode::new(config).unwrap();

        assert_eq!(node.session_count().await, 0);
    }

    #[test]
    fn relay_node_validates_config() {
        let config = RelayConfig {
            data_shards: 0,
            ..RelayConfig::default()
        };

        let result = RelayNode::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn pow_validation_extracts_header_after_content_length_prefix() {
        let marker = [0x04, 0x00, 0x00, 0x00];
        let mut compact_header = marker.to_vec();
        compact_header.resize(256, 0x42);
        let compact = CompactBlock::new(compact_header, 0, Vec::new(), Vec::new());
        let block_hash = compact.header_hash();
        let chunker = BlockChunker::new(10, 3).unwrap();
        let chunks = chunker
            .compact_block_to_chunks(&compact, block_hash.as_bytes())
            .unwrap();

        let mut assembly = BlockAssembly::new(*block_hash.as_bytes(), chunks.len());
        for chunk in chunks {
            assembly.add_chunk(chunk.header.chunk_id as usize, chunk.payload);
        }

        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let node = RelayNode::with_validator(config, HeaderPrefixValidator(marker)).unwrap();

        assert_eq!(
            node.validate_pow_from_assembly(&assembly, MessageType::Block),
            Some(true)
        );
    }

    #[test]
    fn raw_segment_validation_requires_valid_segment_zero_metadata() {
        let marker = [0x04, 0x00, 0x00, 0x00];
        let mut raw_block = marker.to_vec();
        raw_block.resize(ZCASH_FULL_HEADER_SIZE + 4096, 0xab);
        let block_hash = raw_block_header_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
        let segments = split_raw_block(block_hash, &raw_block, 2_000).unwrap();
        assert!(segments.len() > 1);

        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let node = RelayNode::with_validator(config, HeaderPrefixValidator(marker)).unwrap();

        let segment_one = raw_segment_assembly(&node, &segments[1]);
        assert_eq!(
            node.validate_pow_from_assembly(&segment_one, MessageType::RawBlockSegment),
            Some(false),
            "nonzero raw segments require a validated segment-zero cache entry"
        );

        let segment_zero = raw_segment_assembly(&node, &segments[0]);
        assert_eq!(
            node.validate_pow_from_assembly(&segment_zero, MessageType::RawBlockSegment),
            Some(true)
        );
        assert_eq!(
            node.validate_pow_from_assembly(&segment_one, MessageType::RawBlockSegment),
            Some(true),
            "matching nonzero raw segments are valid after segment zero validates"
        );

        let mut mismatched = segments[1].clone();
        mismatched.raw_block_digest[0] ^= 0xff;
        let mismatched = raw_segment_assembly(&node, &mismatched);
        assert_eq!(
            node.validate_pow_from_assembly(&mismatched, MessageType::RawBlockSegment),
            Some(false),
            "nonzero raw segment metadata must match the validated segment-zero metadata"
        );
    }

    #[test]
    fn raw_segment_validation_rejects_legacy_double_sha_block_hash() {
        use sha2::{Digest, Sha256};

        let mut raw_block = vec![0xab; ZCASH_FULL_HEADER_SIZE + 4096];
        raw_block[0] = 0x04;
        let header = &raw_block[..ZCASH_FULL_HEADER_SIZE];
        let zcash_hash = raw_block_header_hash(header);
        let legacy_hash = {
            let first = Sha256::digest(header);
            let second = Sha256::digest(first);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&second);
            hash
        };
        assert_ne!(zcash_hash, legacy_hash);

        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let node = RelayNode::with_validator(config, StubPowValidator).unwrap();

        let valid_segment = split_raw_block(zcash_hash, &raw_block, 2_000)
            .unwrap()
            .remove(0);
        let valid_assembly = raw_segment_assembly(&node, &valid_segment);
        assert_eq!(
            node.validate_pow_from_assembly(&valid_assembly, MessageType::RawBlockSegment),
            Some(true)
        );

        let legacy_segment = split_raw_block(legacy_hash, &raw_block, 2_000)
            .unwrap()
            .remove(0);
        let legacy_assembly = raw_segment_assembly(&node, &legacy_segment);
        assert_eq!(
            node.validate_pow_from_assembly(&legacy_assembly, MessageType::RawBlockSegment),
            Some(false),
            "raw segment metadata must use the canonical Zcash block hash"
        );
    }

    #[test]
    fn live_sized_raw_segments_validate_with_production_fec_budget() {
        let mut raw_block = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        raw_block.resize(335_940, 0xcd);
        raw_block[0] = 0x04;
        let block_hash = raw_block_header_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
        let segment_frame_bytes = 224 * MAX_PAYLOAD_SIZE - 4;
        let segments = split_raw_block(block_hash, &raw_block, segment_frame_bytes).unwrap();
        assert_eq!(segments.len(), 2);

        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true)
            .with_fec(224, 32);
        let node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        let mut session = RelaySession::new("127.0.0.1:12345".parse().unwrap(), "test", [0u8; 32]);
        let mut ready_objects = Vec::new();

        for segment in &segments {
            let chunks = node.chunker.raw_block_segment_to_chunks(segment).unwrap();
            assert_eq!(chunks.len(), 256);
            for chunk in &chunks {
                ready_objects.extend(node.process_chunk_for_session(
                    &mut session,
                    chunk,
                    chunk.header.block_hash,
                    chunk.header.chunk_id as usize,
                    chunk.header.total_chunks as usize,
                ));
            }
        }

        for segment in &segments {
            let object_hash = segment_object_hash(segment.block_hash, segment.segment_index);
            assert!(
                ready_objects
                    .iter()
                    .any(|ready| ready.block_hash == object_hash),
                "validated live-sized segment object should become forwardable"
            );
        }
        let metrics = node.metrics().snapshot();
        assert_eq!(
            metrics.raw_segment_validation_successes,
            segments.len() as u64
        );
        assert_eq!(metrics.raw_segment_validation_failures, 0);
    }

    #[test]
    fn validated_raw_block_emits_arrival_event_with_consensus_hash() {
        let mut raw_block = vec![0xab; ZCASH_FULL_HEADER_SIZE + 256];
        raw_block[0] = 0x04;
        let block_hash = raw_block_header_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
        let segments = split_raw_block(block_hash, &raw_block, 2_000).unwrap();

        let arrival_path = std::env::temp_dir().join(format!(
            "sovright-relay-arrival-node-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let node = RelayNode::with_validator(config, StubPowValidator)
            .unwrap()
            .with_arrival_sink(Some(ArrivalSink::new(&arrival_path).unwrap()));
        let mut session = RelaySession::new("127.0.0.1:12345".parse().unwrap(), "test", [0u8; 32]);

        for segment in &segments {
            let chunks = node.chunker.raw_block_segment_to_chunks(segment).unwrap();
            for chunk in &chunks {
                let _ = node.process_chunk_for_session(
                    &mut session,
                    chunk,
                    chunk.header.block_hash,
                    chunk.header.chunk_id as usize,
                    chunk.header.total_chunks as usize,
                );
            }
        }

        // The arrival log must carry the Zcash *consensus* hash (double-SHA256,
        // display), not the relay's internal object id.
        let expected =
            crate::hash::consensus_block_hash_display(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
        let contents = std::fs::read_to_string(&arrival_path).unwrap();
        assert!(
            contents.lines().any(|line| {
                line.contains("\"event\":\"relay_block_received\"") && line.contains(&expected)
            }),
            "expected relay_block_received with consensus hash {expected}, got:\n{contents}"
        );
        let _ = std::fs::remove_file(arrival_path);
    }

    #[test]
    fn raw_segment_zero_promotes_previously_buffered_nonzero_segments() {
        let mut raw_block = vec![0xab; ZCASH_FULL_HEADER_SIZE + 4096];
        raw_block[0] = 0x04;
        let block_hash = raw_block_header_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
        let segments = split_raw_block(block_hash, &raw_block, 2_000).unwrap();
        assert!(segments.len() > 1);

        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        let mut session = RelaySession::new("127.0.0.1:12345".parse().unwrap(), "test", [0u8; 32]);

        let segment_one_chunks = node
            .chunker
            .raw_block_segment_to_chunks(&segments[1])
            .unwrap();
        let segment_one_object_hash =
            segment_object_hash(segments[1].block_hash, segments[1].segment_index);
        for chunk in &segment_one_chunks {
            let ready = node.process_chunk_for_session(
                &mut session,
                chunk,
                chunk.header.block_hash,
                chunk.header.chunk_id as usize,
                chunk.header.total_chunks as usize,
            );
            assert!(
                ready.is_empty(),
                "nonzero segment should not forward before segment zero validates"
            );
        }

        let segment_zero_chunks = node
            .chunker
            .raw_block_segment_to_chunks(&segments[0])
            .unwrap();
        let segment_zero_object_hash =
            segment_object_hash(segments[0].block_hash, segments[0].segment_index);
        let mut ready_after_segment_zero = Vec::new();
        for chunk in &segment_zero_chunks {
            ready_after_segment_zero.extend(node.process_chunk_for_session(
                &mut session,
                chunk,
                chunk.header.block_hash,
                chunk.header.chunk_id as usize,
                chunk.header.total_chunks as usize,
            ));
        }

        assert!(
            ready_after_segment_zero
                .iter()
                .any(|ready| ready.block_hash == segment_zero_object_hash),
            "segment zero chunks should forward once validated"
        );
        assert!(
            ready_after_segment_zero
                .iter()
                .any(|ready| ready.block_hash == segment_one_object_hash),
            "previously buffered nonzero segment chunks should forward after segment zero validates"
        );
        let metrics = node.metrics().snapshot();
        assert_eq!(metrics.raw_segment_cached_promotions, 1);
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
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", auth_key)]);
        let mut node = RelayNode::new(config).unwrap();
        node.bind().await.unwrap();

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let sender_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                sender_addr,
                RelaySession::new(sender_addr, "test", auth_key),
            );
            sessions.insert(
                receiver_addr,
                RelaySession::new(receiver_addr, "test", auth_key),
            );
        }

        let block_hash = [0xab; 32];
        let chunks = vec![(0u16, vec![1u8; 10])];

        node.forward_to_peers(sender_addr, MessageType::Block, &block_hash, 1, 0, &chunks)
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
        let session = RelaySession::new(receiver_addr, "test", auth_key);
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
    async fn forward_macs_each_session_with_its_own_bound_key() {
        // Per-key-identity hardening (PR-A): forward_to_peers must MAC each
        // outbound chunk with the RECEIVING session's own bound key, not a
        // single global send key. Two sessions bound to different keys --
        // "fleet" (A) and "alice" (B, an invitee key) -- must each receive
        // chunks that verify under their own key and FAIL under the other's.
        let fleet_key = [0x42; 32];
        let alice_key = [0x77; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![
            AuthKey::new("fleet", fleet_key),
            AuthKey::new("alice", alice_key),
        ]);
        let mut node = RelayNode::new(config).unwrap();
        node.bind().await.unwrap();

        let fleet_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fleet_peer_addr = fleet_peer.local_addr().unwrap();
        let alice_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alice_peer_addr = alice_peer.local_addr().unwrap();
        let sender_addr: SocketAddr = "127.0.0.1:23456".parse().unwrap();

        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                sender_addr,
                RelaySession::new(sender_addr, "fleet", fleet_key),
            );
            sessions.insert(
                fleet_peer_addr,
                RelaySession::new(fleet_peer_addr, "fleet", fleet_key),
            );
            sessions.insert(
                alice_peer_addr,
                RelaySession::new(alice_peer_addr, "alice", alice_key),
            );
        }

        let block_hash = [0xcd; 32];
        let chunks = vec![(0u16, vec![9u8; 10])];

        node.forward_to_peers(sender_addr, MessageType::Block, &block_hash, 1, 0, &chunks)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];

        // The fleet-bound session receives a chunk MAC'd with the fleet key:
        // it verifies under fleet_key and fails under alice_key.
        let (len, _) = timeout(Duration::from_millis(200), fleet_peer.recv_from(&mut buf))
            .await
            .expect("timeout waiting for fleet forward")
            .unwrap();
        let parsed = Chunk::from_bytes(&buf[..len]).unwrap();
        let fleet_session = RelaySession::new(fleet_peer_addr, "fleet", fleet_key);
        let alice_session = RelaySession::new(fleet_peer_addr, "alice", alice_key);
        assert!(fleet_session.verify_hmac(
            &parsed.header.block_hash,
            parsed.header.chunk_id,
            parsed.header.total_chunks,
            parsed.header.payload_len,
            &parsed.payload,
            &parsed.header.hmac
        ));
        assert!(!alice_session.verify_hmac(
            &parsed.header.block_hash,
            parsed.header.chunk_id,
            parsed.header.total_chunks,
            parsed.header.payload_len,
            &parsed.payload,
            &parsed.header.hmac
        ));

        // The alice-bound (invitee) session receives a chunk MAC'd with
        // alice's own key: it verifies under alice_key and fails under
        // fleet_key -- the fleet key was never used toward this session.
        let (len, _) = timeout(Duration::from_millis(200), alice_peer.recv_from(&mut buf))
            .await
            .expect("timeout waiting for alice forward")
            .unwrap();
        let parsed = Chunk::from_bytes(&buf[..len]).unwrap();
        let alice_session = RelaySession::new(alice_peer_addr, "alice", alice_key);
        let fleet_session = RelaySession::new(alice_peer_addr, "fleet", fleet_key);
        assert!(alice_session.verify_hmac(
            &parsed.header.block_hash,
            parsed.header.chunk_id,
            parsed.header.total_chunks,
            parsed.header.payload_len,
            &parsed.payload,
            &parsed.header.hmac
        ));
        assert!(!fleet_session.verify_hmac(
            &parsed.header.block_hash,
            parsed.header.chunk_id,
            parsed.header.total_chunks,
            parsed.header.payload_len,
            &parsed.payload,
            &parsed.header.hmac
        ));
    }

    #[tokio::test]
    async fn forwards_v3_adaptive_chunks_preserving_data_shards() {
        // End-to-end mesh path for adaptive (v3) chunks: a small compact block
        // is encoded as v3, validated + collected by the session, then forwarded
        // to a peer. The forwarded datagram must remain v3, carry the same
        // per-block data_shards, and authenticate under the v3 HMAC.
        let auth_key = [0x42; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", auth_key)]);
        let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        node.bind().await.unwrap();

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                sender_addr,
                RelaySession::new(sender_addr, "test", auth_key),
            );
            sessions.insert(
                receiver_addr,
                RelaySession::new(receiver_addr, "test", auth_key),
            );
        }

        let compact = CompactBlock::new(vec![0xab; 2189], 0x1234, Vec::new(), Vec::new());
        let block_hash = *compact.header_hash().as_bytes();
        let chunks = node
            .chunker
            .compact_block_to_chunks_adaptive(&compact, &block_hash)
            .unwrap();
        assert!(chunks.iter().all(|c| c.header.version == 3));
        let data_shards = chunks[0].header.data_shards;
        assert!(data_shards > 0);

        let mut ready = Vec::new();
        {
            let mut sessions = node.sessions.write().await;
            let session = sessions.get_mut(&sender_addr).unwrap();
            for chunk in &chunks {
                ready.extend(node.process_chunk_for_session(
                    session,
                    chunk,
                    block_hash,
                    chunk.header.chunk_id as usize,
                    chunk.header.total_chunks as usize,
                ));
            }
        }
        let forwarded_total: usize = ready.iter().map(|r| r.chunks.len()).sum();
        assert_eq!(forwarded_total, chunks.len());
        assert!(ready.iter().all(|r| r.data_shards == data_shards));

        for r in &ready {
            node.forward_to_peers(
                sender_addr,
                r.msg_type,
                &r.block_hash,
                r.total_chunks,
                r.data_shards,
                &r.chunks,
            )
            .await
            .unwrap();
        }

        let verify_session = RelaySession::new(receiver_addr, "test", auth_key);
        let mut buf = vec![0u8; 2048];
        for _ in 0..chunks.len() {
            let (len, _) = timeout(Duration::from_millis(200), receiver.recv_from(&mut buf))
                .await
                .expect("timeout waiting for forwarded v3 chunk")
                .unwrap();
            let parsed = Chunk::from_bytes(&buf[..len]).unwrap();
            assert_eq!(parsed.header.version, 3);
            assert_eq!(parsed.header.data_shards, data_shards);
            assert!(verify_session.verify_hmac_v3(
                &parsed.header.block_hash,
                parsed.header.chunk_id,
                parsed.header.total_chunks,
                parsed.header.payload_len,
                parsed.header.data_shards,
                &parsed.payload,
                &parsed.header.hmac,
            ));
        }
    }

    #[tokio::test]
    async fn forwards_compact_skeleton_chunks_after_pow_validation() {
        // A CompactSkeleton is PoW-validated at the node exactly like a compact
        // block (it carries the header) and forwarded to peers as authenticated
        // v3 CompactSkeleton chunks under its own object id.
        let auth_key = [0x42; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", auth_key)]);
        let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        node.bind().await.unwrap();

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                sender_addr,
                RelaySession::new(sender_addr, "test", auth_key),
            );
            sessions.insert(
                receiver_addr,
                RelaySession::new(receiver_addr, "test", auth_key),
            );
        }

        let compact = CompactBlock::new(vec![0xab; 2189], 0xbeef, Vec::new(), Vec::new());
        let block_hash = *compact.header_hash().as_bytes();
        let object_hash = crate::segmented_block::skeleton_object_hash(block_hash);
        let chunks = node
            .chunker
            .compact_block_to_chunks_skeleton(&compact, &object_hash)
            .unwrap();
        assert!(
            chunks
                .iter()
                .all(|c| c.header.msg_type == MessageType::CompactSkeleton && c.header.version == 3)
        );
        let data_shards = chunks[0].header.data_shards;

        let mut ready = Vec::new();
        {
            let mut sessions = node.sessions.write().await;
            let session = sessions.get_mut(&sender_addr).unwrap();
            for chunk in &chunks {
                ready.extend(node.process_chunk_for_session(
                    session,
                    chunk,
                    object_hash,
                    chunk.header.chunk_id as usize,
                    chunk.header.total_chunks as usize,
                ));
            }
        }
        let forwarded_total: usize = ready.iter().map(|r| r.chunks.len()).sum();
        assert_eq!(forwarded_total, chunks.len(), "skeleton chunks forwardable");
        assert!(
            ready
                .iter()
                .all(|r| r.msg_type == MessageType::CompactSkeleton)
        );

        for r in &ready {
            node.forward_to_peers(
                sender_addr,
                r.msg_type,
                &r.block_hash,
                r.total_chunks,
                r.data_shards,
                &r.chunks,
            )
            .await
            .unwrap();
        }

        let verify_session = RelaySession::new(receiver_addr, "test", auth_key);
        let mut buf = vec![0u8; 2048];
        for _ in 0..chunks.len() {
            let (len, _) = timeout(Duration::from_millis(200), receiver.recv_from(&mut buf))
                .await
                .expect("timeout waiting for forwarded skeleton chunk")
                .unwrap();
            let parsed = Chunk::from_bytes(&buf[..len]).unwrap();
            assert_eq!(parsed.header.msg_type, MessageType::CompactSkeleton);
            assert_eq!(parsed.header.version, 3);
            assert_eq!(parsed.header.data_shards, data_shards);
            assert!(verify_session.verify_hmac_v3(
                &parsed.header.block_hash,
                parsed.header.chunk_id,
                parsed.header.total_chunks,
                parsed.header.payload_len,
                parsed.header.data_shards,
                &parsed.payload,
                &parsed.header.hmac,
            ));
        }
    }

    #[tokio::test]
    async fn forward_counts_chunks_without_eligible_receive_peers() {
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let mut node = RelayNode::new(config).unwrap();
        node.bind().await.unwrap();

        let sender_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                sender_addr,
                RelaySession::new(sender_addr, "test", [0u8; 32]),
            );
        }

        let block_hash = [0xab; 32];
        let chunks = vec![(0u16, vec![1u8; 10]), (1u16, vec![2u8; 10])];

        node.forward_to_peers(sender_addr, MessageType::Block, &block_hash, 2, 0, &chunks)
            .await
            .unwrap();

        let metrics = node.metrics().snapshot();
        assert_eq!(metrics.forward_no_peer_chunks, 2);
        assert_eq!(metrics.packets_forwarded, 0);
    }

    #[tokio::test]
    async fn keepalive_counts_session_limit_rejections() {
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true)
            .with_max_sessions(1);
        let node = RelayNode::new(config).unwrap();
        let existing_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let new_addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                existing_addr,
                RelaySession::new(existing_addr, "test", [0u8; 32]),
            );
        }

        let keepalive = Chunk::new(
            ChunkHeader::new_keepalive_authenticated([0u8; 32]),
            Vec::new(),
        );
        let result = node.handle_keepalive(new_addr, &keepalive).await;

        assert!(matches!(result, Err(TransportError::ConnectionRefused(_))));
        assert_eq!(node.metrics().snapshot().session_limit_rejections, 1);
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

    #[test]
    fn forward_pacing_delays_after_configured_bursts() {
        let pacing = ForwardPacing::new(3, Duration::from_millis(1));
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
    fn forward_pacing_disabled_with_zero_delay_or_burst() {
        for pacing in [
            ForwardPacing::new(0, Duration::from_millis(1)),
            ForwardPacing::new(3, Duration::ZERO),
        ] {
            let mut sent_since_delay = 0;
            assert!(!pacing.should_delay(0, 3, &mut sent_since_delay));
            assert!(!pacing.should_delay(1, 3, &mut sent_since_delay));
            assert!(!pacing.should_delay(2, 3, &mut sent_since_delay));
        }
    }
}
