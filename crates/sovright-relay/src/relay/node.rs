//! Relay node server implementation

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::RwLock as StdRwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chunk_proof::datagram::Verifier;
use chunk_proof::object::Profile;
use delivery_lease::segment_frame::SetKey;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::fec::FecError;
use crate::relay::ratelimit::UnauthRateLimiter;
use crate::segmented_block::{RawBlockSegment, segment_object_hash};
use crate::transport::{
    AuthKey, BlockAssembly, BlockChunker, Chunk, ChunkHeader, EquihashPowValidator, KeyRole,
    MAX_TOTAL_CHUNKS, MessageType, PowResult, PowValidator, RelayConfig, RelaySession,
    TransportError, ZCASH_FULL_HEADER_SIZE,
};

use super::bound_raw::{
    self, BoundForwarder, BoundNodeUsage, BoundStep, IngressQueue, LiveIngress, MAX_READ_BYTES,
    Outgoing,
};
use super::forwarding::ForwardOrder;
#[cfg(feature = "handled-log")]
use super::handled_log::HandledLog;
use super::metrics::RelayMetrics;
use super::{ArrivalSink, ReceiptObject};

/// A keepalive that says more than that a session is alive. See the note in `bound_raw`.
#[derive(Clone, Copy, Debug)]
enum Control {
    Hello(u16),
    Release(SetKey),
}

/// What a [`Control`] comes to once its session is known.
enum Answer {
    Ack(Vec<u8>),
    Release(SetKey),
}

const MAX_VALIDATED_RAW_BLOCKS: usize = 4096;
const VALIDATED_RAW_BLOCK_TTL: Duration = Duration::from_secs(120);

/// Key-id sentinel bound to sessions admitted while auth is not required
/// (`allow_unauthenticated_peers`). Authentication state is tracked
/// separately, so a configured key may safely use the same display label.
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
    /// Per-source rate limiter for traffic from sources with no established
    /// session. Guards the trial-verify HMAC scan, which is the CPU cost an
    /// internet-exposed relay pays to any sender. Established sessions are
    /// never consulted against it.
    unauth_limiter: UnauthRateLimiter,
    /// Live, hot-swappable authorized key set (hot-revocation, PR-B).
    ///
    /// Initialized from `config.authorized_keys` at construction. The receive
    /// (hot) path reads this -- never `config.authorized_keys` directly --
    /// by taking a short read lock, cloning the inner `Arc`, and releasing
    /// the lock before doing any HMAC/crypto work over the cloned key list.
    /// A reload task (spawned by the `relay-node` binary when
    /// `SOVRIGHT_RELAY_AUTH_KEYS_FILE` is set) is the only writer, via
    /// [`RelayNode::apply_active_keys`]. `std::sync::RwLock` is used rather
    /// than an async lock or an external crate (e.g. arc-swap, not present
    /// in this workspace's Cargo.lock) because critical sections here are
    /// always short, synchronous pointer operations.
    active_keys: StdRwLock<Arc<Vec<AuthKey>>>,
    /// The bound raw path, if the config asks for it. A plain lock: nothing here awaits
    /// while holding it.
    bound: Option<Mutex<BoundForwarder>>,
    ingress: LiveIngress,
    #[cfg(feature = "handled-log")]
    handled: Mutex<HandledLog>,
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

        let active_keys = StdRwLock::new(Arc::new(config.authorized_keys.clone()));
        let unauth_limiter = UnauthRateLimiter::new(
            config.unauth_rate_limit_per_sec,
            config.unauth_rate_limit_burst,
        );

        if config.bound_raw.is_some()
            && let Some(reason) = bound_raw::bound_raw_refused()
        {
            return Err(FecError::InvalidConfiguration(reason.to_string()));
        }
        let bound = config
            .bound_raw
            .map(BoundForwarder::new)
            .transpose()
            .map_err(|invalid| {
                FecError::InvalidConfiguration(format!("bound raw limits: {}", invalid.0))
            })?
            .map(Mutex::new);

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
            unauth_limiter,
            active_keys,
            bound,
            ingress: LiveIngress::default(),
            #[cfg(feature = "handled-log")]
            handled: Mutex::default(),
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
        self.active_keys().iter().any(|k| &k.key == key)
    }

    /// Read a cheap clone of the currently active authorized key set.
    ///
    /// Takes a short read lock on `active_keys`, clones the inner `Arc`, and
    /// releases the lock immediately -- callers iterate over the returned
    /// `Arc` without holding any lock across HMAC/crypto work.
    fn active_keys(&self) -> Arc<Vec<AuthKey>> {
        Arc::clone(&self.active_keys.read().expect("active_keys lock poisoned"))
    }

    /// Replace the active authorized key set (hot-revocation, PR-B) and evict
    /// every live session whose bound identity, key, or role has changed in
    /// the new set. Called by the `relay-node` binary's auth-keys reload task
    /// each time the on-disk keys file changes in a way that rebuilds the
    /// env-keys-union-file-keys active set.
    ///
    /// The caller is expected to have already validated `keys` (e.g. via
    /// `require_unique_key_ids`) and to have applied the fail-safe rule
    /// (never call this with a set that drops the permanent env/fleet keys)
    /// before invoking this method -- this method itself just swaps and
    /// evicts.
    pub async fn apply_active_keys(&self, keys: Vec<AuthKey>) {
        let keys = Arc::new(keys);
        {
            let mut guard = self.active_keys.write().expect("active_keys lock poisoned");
            *guard = Arc::clone(&keys);
        }
        self.evict_sessions_not_in(&keys).await;
    }

    /// Evict every live session without an exact authorization match in `keys`.
    ///
    /// Sessions admitted while auth was not required (bound to the
    /// [`UNAUTHENTICATED_KEY_ID`] sentinel) are never evicted by a key-set
    /// change -- they were never bound to a revocable key in the first
    /// place.
    async fn evict_sessions_not_in(&self, keys: &[AuthKey]) {
        let keep: HashMap<&str, &AuthKey> = keys.iter().map(|key| (key.id.as_str(), key)).collect();
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, session| {
            !session.is_authenticated()
                || keep
                    .get(session.key_id())
                    .is_some_and(|key| session.matches_authorization(key))
        });
        let evicted = before - sessions.len();
        if evicted > 0 {
            info!(evicted, "Evicted sessions bound to revoked auth keys");
        }
        self.tidy_bound(&sessions);
    }

    fn tidy_bound(&self, sessions: &HashMap<SocketAddr, RelaySession>) {
        if let Some(bound) = &self.bound {
            self.with_bound(bound, |forwarder| {
                forwarder.tidy(Instant::now(), |addr| sessions.contains_key(addr));
            });
        }
    }

    /// What this node holds on the bound path, if it has it.
    pub fn bound_usage(&self) -> Option<BoundNodeUsage> {
        let bound = self.bound.as_ref()?;
        let mut usage = self.with_bound(bound, |forwarder| forwarder.usage())?;
        usage.ingress = self.ingress.read();
        Some(usage)
    }

    /// A body named by its block hash and body id was refused downstream of this node, by
    /// whoever runs it beside its own Zebra: its anchor goes, and its segment 0 opens none for
    /// a while. Whether it had one. A receiver elsewhere says the same with
    /// [`bound_release`](super::bound_raw::bound_release).
    pub fn release_bound_body(&self, block_hash: [u8; 32], body_id: [u8; 32]) -> bool {
        let Some(bound) = self.bound.as_ref() else {
            return false;
        };
        let key = SetKey {
            block_hash,
            body_id,
        };
        let released = self.with_bound(bound, |forwarder| forwarder.release(key, Instant::now()));
        released.unwrap_or(false)
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

    /// The receive buffer the system gave this socket, which can differ from what `bind`
    /// asked for, with no error.
    pub fn recv_buffer_bytes(&self) -> Option<usize> {
        let socket = self.socket.as_ref()?;
        SockRef::from(&**socket).recv_buffer_size().ok()
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

        let mut buf = vec![0u8; MAX_READ_BYTES];
        let mut cleanup_counter: u32 = 0;
        // Bound objects are decoded and encoded again in this loop, and nothing reads the
        // socket meanwhile. So with the bound path on, the socket is emptied into this between
        // datagrams. In order, one at a time, as before. Off, this stays empty.
        let mut waiting = IngressQueue::new(self.config.bound_raw.as_ref());

        loop {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            if let Err(e) = self.empty_socket(socket, &mut buf, &mut waiting) {
                self.metrics.inc_socket_receive_errors();
                self.running.store(false, Ordering::SeqCst);
                return Err(TransportError::Io(e));
            }

            if let Some((datagram, src_addr)) = waiting.pop() {
                let started = Instant::now();
                self.take_packet(&datagram, src_addr).await;
                self.ingress.note_handled(started.elapsed());
                // Lets the runtime look at its sockets, or this one reads as empty.
                tokio::task::yield_now().await;
            } else {
                let recv_result =
                    tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf))
                        .await;

                match recv_result {
                    Ok(Ok((len, src_addr))) => self.take_packet(&buf[..len], src_addr).await,
                    Ok(Err(e)) => {
                        self.metrics.inc_socket_receive_errors();
                        self.running.store(false, Ordering::SeqCst);
                        return Err(TransportError::Io(e));
                    }
                    Err(_) => {
                        // Timeout - continue
                    }
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

    /// How many times this node has finished with exactly this datagram from `src`, as far
    /// as its bounded log goes.
    #[cfg(feature = "handled-log")]
    pub fn times_finished(&self, src: SocketAddr, datagram: &[u8]) -> u64 {
        self.handled.lock().unwrap().times(src, datagram)
    }

    /// One packet, from start to finish.
    async fn take_packet(&self, data: &[u8], src_addr: SocketAddr) {
        if let Err(e) = self.handle_packet(data, src_addr).await {
            debug!(peer = %src_addr, error = ?e, "Error handling packet");
        }
        #[cfg(feature = "handled-log")]
        self.handled.lock().unwrap().note(src_addr, data);
    }

    /// Move what the socket holds into `waiting`, as far as it has room. The rest stays in the
    /// socket.
    fn empty_socket(
        &self,
        socket: &UdpSocket,
        buf: &mut [u8],
        waiting: &mut IngressQueue,
    ) -> std::io::Result<()> {
        while waiting.has_room() {
            match socket.try_recv_from(buf) {
                Ok((len, src_addr)) => waiting.push(&buf[..len], src_addr),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        self.ingress.note_queue(waiting);
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
        self.tidy_bound(&sessions);
        let expired = (before - sessions.len()) as u64;
        drop(sessions);
        if expired > 0 {
            self.metrics.add_sessions_expired(expired);
        }
        self.cleanup_validated_raw_blocks();
        if let Some(bound) = &self.bound
            && let Err(error) = self.revive_bound(bound).await
        {
            debug!(?error, "Error sending revived bound objects");
        }
    }

    /// Spares a session had in full but no room to decode, tried again once something may
    /// have given room back: an object that went out, or a timer. Without this they would
    /// wait for their time to run out, room or not.
    async fn revive_bound(&self, bound: &Mutex<BoundForwarder>) -> Result<(), TransportError> {
        let objects = self.with_bound(bound, |forwarder| {
            forwarder.revive(Instant::now(), |header| self.validator.validate(header))
        });
        match objects {
            Some(objects) if !objects.is_empty() => self.forward_bound(bound, objects).await,
            _ => Ok(()),
        }
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

    #[cfg(test)]
    fn validate_pow_from_assembly(
        &self,
        assembly: &BlockAssembly,
        msg_type: MessageType,
    ) -> Option<bool> {
        self.validate_pow_with_identity(assembly, msg_type)
            .map(|(valid, _)| valid)
    }

    /// Validate PoW once we can reconstruct serialized data. A valid result
    /// also carries the consensus hash when an arrival sink will record it.
    fn validate_pow_with_identity(
        &self,
        assembly: &BlockAssembly,
        msg_type: MessageType,
    ) -> Option<(bool, Option<String>)> {
        match msg_type {
            // A skeleton carries the full block header in its serialized
            // CompactBlock, so PoW validates exactly like a compact block.
            MessageType::Block | MessageType::CompactSkeleton => {
                self.validate_compact_block_pow_with_identity(assembly)
            }
            MessageType::RawBlockSegment => self.validate_raw_block_segment_with_identity(assembly),
            MessageType::Keepalive | MessageType::Auth => None,
        }
    }

    fn validate_compact_block_pow_with_identity(
        &self,
        assembly: &BlockAssembly,
    ) -> Option<(bool, Option<String>)> {
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
            PowResult::Valid => Some((
                true,
                self.arrival_sink
                    .as_ref()
                    .map(|_| crate::hash::consensus_block_hash_display(header)),
            )),
            PowResult::Invalid => Some((false, None)),
            PowResult::Indeterminate => None,
        }
    }

    fn validate_raw_block_segment_with_identity(
        &self,
        assembly: &BlockAssembly,
    ) -> Option<(bool, Option<String>)> {
        let segment = self.decode_raw_segment_from_assembly(assembly)?;
        let expected_object_hash = segment_object_hash(segment.block_hash, segment.segment_index);
        if expected_object_hash != assembly.block_hash {
            return Some((false, None));
        }

        if segment.segment_index != 0 {
            return Some((
                self.raw_segment_matches_validated_segment_zero(&segment),
                None,
            ));
        }

        if segment.payload.len() < ZCASH_FULL_HEADER_SIZE {
            return None;
        }
        let header = &segment.payload[..ZCASH_FULL_HEADER_SIZE];
        if raw_block_header_hash(header) != segment.block_hash {
            return Some((false, None));
        }

        match self.validator.validate(header) {
            PowResult::Valid => {
                self.record_validated_raw_block(&segment);
                Some((
                    true,
                    self.arrival_sink
                        .as_ref()
                        .map(|_| crate::hash::consensus_block_hash_display(header)),
                ))
            }
            PowResult::Invalid => Some((false, None)),
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

        self.send_outbound(outbound, chunks.len(), msg_type)
            .await
            .map(drop)
    }

    /// Each bound object to every session that announced it takes them, but the one it came
    /// from, sealed with each session's own key. A session that never sent a bound hello is
    /// legacy and gets none: it would drop them. The datagram that released an object can be
    /// another session's, such as a segment 0 that let waiting objects go, so each object
    /// carries its origin.
    ///
    /// An object counts against its origin's sends only once every datagram of it went out
    /// to at least one peer. With no peer, or a socket that refused, nothing is recorded and
    /// the next copy can go.
    async fn forward_bound(
        &self,
        bound: &Mutex<BoundForwarder>,
        objects: Vec<Outgoing>,
    ) -> Result<(), TransportError> {
        for Outgoing { object, from } in objects {
            let shards = object.shards.len() as u64;
            let sessions = self.sessions.read().await;
            let outbound: Vec<(SocketAddr, String, Vec<Vec<u8>>)> = sessions
                .iter()
                .filter(|(peer_addr, session)| **peer_addr != from && session.receives_bound())
                .map(|(peer_addr, session)| {
                    let payloads = BoundForwarder::sealed(&session.auth_key(), &object);
                    (*peer_addr, session.key_id().to_string(), payloads)
                })
                .collect();
            drop(sessions);
            let sent = self
                .send_outbound(outbound, shards as usize, MessageType::RawBlockSegment)
                .await?;
            if sent.contains(&shards) {
                let id = object.object_id;
                self.with_bound(bound, |forwarder| forwarder.sent(from, id, Instant::now()));
            }
        }
        Ok(())
    }

    /// Sends each peer its payloads, paced, and says how many datagrams each peer's socket
    /// took, in the order of `outbound`.
    async fn send_outbound(
        &self,
        outbound: Vec<(SocketAddr, String, Vec<Vec<u8>>)>,
        chunks: usize,
        msg_type: MessageType,
    ) -> Result<Vec<u64>, TransportError> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not bound",
            ))
        })?;

        if outbound.is_empty() && chunks > 0 {
            self.metrics.inc_forward_no_peer_chunks(chunks as u64);
        }

        let pacing = ForwardPacing::new(
            self.config.forward_burst_packets,
            self.config.forward_burst_delay,
        );
        let packet_count: usize = outbound.iter().map(|(_, _, p)| p.len()).sum();
        let order = ForwardOrder::new(
            outbound.iter().map(|(_, _, p)| p.len()).collect(),
            self.config.forward_round_robin,
        );
        let mut sent = vec![0u64; outbound.len()];
        let mut sent_since_delay = 0usize;
        for (global_idx, (peer_idx, packet_idx)) in order.enumerate() {
            let (peer_addr, _, payloads) = &outbound[peer_idx];
            if !self.config.forward_round_robin && packet_idx == 0 {
                sent_since_delay = 0;
            }
            match socket.send_to(&payloads[packet_idx], peer_addr).await {
                Ok(_) => sent[peer_idx] += 1,
                Err(error) => {
                    self.metrics.inc_packet_send_errors();
                    warn!(peer = %peer_addr, %error, "Failed to forward relay packet");
                }
            }
            // One budget across ALL peers for round-robin; parallel per-peer
            // sleeps would silently multiply the configured egress burst rate.
            let (idx, count) = if self.config.forward_round_robin {
                (global_idx, packet_count)
            } else {
                (packet_idx, payloads.len())
            };
            if pacing.should_delay(idx, count, &mut sent_since_delay) {
                sleep(pacing.delay).await;
            }
        }
        for ((_, key_id, _), &chunks_sent) in outbound.iter().zip(&sent) {
            if chunks_sent > 0 {
                self.metrics.inc_packets_forwarded(chunks_sent);
                self.metrics
                    .inc_chunks_forwarded_for_key(key_id, chunks_sent);
                match msg_type {
                    MessageType::Block => {
                        self.metrics.inc_compact_block_chunks_forwarded(chunks_sent)
                    }
                    MessageType::RawBlockSegment => {
                        self.metrics.inc_raw_segment_chunks_forwarded(chunks_sent)
                    }
                    MessageType::CompactSkeleton | MessageType::Keepalive | MessageType::Auth => {}
                }
            }
        }

        Ok(sent)
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
        let mut arrival = None;
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
                let object_kind = match chunk.header.msg_type {
                    MessageType::RawBlockSegment => Some(ReceiptObject::RawSegment),
                    MessageType::Block => Some(ReceiptObject::Compact),
                    MessageType::CompactSkeleton => Some(ReceiptObject::CompactSkeleton),
                    MessageType::Keepalive | MessageType::Auth => None,
                };
                let validation = self
                    .validate_pow_with_identity(assembly, chunk.header.msg_type)
                    .map(|(valid, hash)| {
                        arrival = hash.zip(object_kind).map(|(hash, kind)| {
                            (hash, kind, assembly.started_at.elapsed().as_millis() as u64)
                        });
                        valid
                    });
                match validation {
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

        if let (Some(sink), Some((hash, object_kind, elapsed))) = (&self.arrival_sink, arrival) {
            sink.relay_header_received(
                &hash,
                object_kind,
                session.key_id(),
                match session.role() {
                    KeyRole::Full => "full",
                    KeyRole::ReceiveOnly => "receive_only",
                },
                session.is_authenticated(),
                elapsed,
            );
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
    /// Gate an unknown (sessionless) source before it can make the relay
    /// perform a trial-verify HMAC scan across every active key.
    ///
    /// Only reached when the source has no established session, so an
    /// authenticated peer never pays this check.
    fn admit_unknown_source(&self, src_addr: SocketAddr) -> Result<(), TransportError> {
        if self.unauth_limiter.allow(src_addr.ip()) {
            return Ok(());
        }
        self.metrics.inc_unauth_rate_limited();
        debug!(peer = %src_addr, "Unknown source rate limited before key trial-verify");
        Err(TransportError::ConnectionRefused(
            "unauthenticated source rate limited".into(),
        ))
    }

    /// The source of a bound datagram, by its session or by trying the active keys. Only
    /// a datagram that passes its checks makes a session.
    async fn bound_source(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
    ) -> Result<([u8; 32], KeyRole, String), TransportError> {
        if let Some(session) = self.sessions.read().await.get(&src_addr) {
            let id = session.key_id().to_string();
            return Ok((session.auth_key(), session.role(), id));
        }
        self.admit_unknown_source(src_addr)?;
        let keys = self.active_keys();
        let Some(key) = keys.iter().find(|key| {
            Verifier::new(key.key, Profile::BoundSegment)
                .verify(data)
                .is_ok()
        }) else {
            warn!(peer = %src_addr, "Authentication failed - no matching key");
            self.metrics.inc_auth_failures();
            return Err(TransportError::AuthenticationFailed);
        };
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= self.config.max_sessions {
            self.metrics.inc_session_limit_rejections();
            return Err(TransportError::ConnectionRefused(
                "relay session limit reached".into(),
            ));
        }
        // Whatever its role: a session of a ReceiveOnly key never reaches the pool's limits,
        // and it takes a place in this table all the same.
        let key_limit = self
            .config
            .bound_raw
            .map(|bound| bound.key_budget.max_sessions);
        let of_this_key = sessions.values().filter(|s| s.key_id() == key.id).count();
        if key_limit.is_some_and(|limit| of_this_key >= limit) {
            self.metrics.inc_session_limit_rejections();
            return Err(TransportError::ConnectionRefused(
                "relay session limit for this key reached".into(),
            ));
        }
        sessions.entry(src_addr).or_insert_with(|| {
            info!(peer = %src_addr, key_id = %key.id, role = ?key.role, "Authenticated new peer");
            self.metrics.inc_sessions_created();
            self.metrics.inc_sessions_created_for_key(&key.id);
            RelaySession::new_with_role(src_addr, key.id.clone(), key.key, key.role)
        });
        Ok((key.key, key.role, key.id.clone()))
    }

    async fn touch_session(&self, src_addr: SocketAddr) {
        if let Some(session) = self.sessions.write().await.get_mut(&src_addr) {
            session.touch();
        }
    }

    /// The one way to the forwarder. Its own steps drop the session a panic belongs to, and
    /// this is for one that got past them, with nobody to put it down to. Then nothing in it
    /// can be vouched for, so all of it goes, and `None` says so. A poisoned lock means the
    /// same. Only `work` is caught: a panic elsewhere in this loop still ends it.
    fn with_bound<T>(
        &self,
        bound: &Mutex<BoundForwarder>,
        work: impl FnOnce(&mut BoundForwarder) -> T,
    ) -> Option<T> {
        let mut forwarder = bound.lock().unwrap_or_else(|poisoned| {
            bound.clear_poison();
            let mut forwarder = poisoned.into_inner();
            forwarder.start_over();
            forwarder
        });
        match catch_unwind(AssertUnwindSafe(|| work(&mut forwarder))) {
            Ok(result) => Some(result),
            Err(_) => {
                forwarder.start_over();
                None
            }
        }
    }

    async fn handle_bound_packet(
        &self,
        bound: &Mutex<BoundForwarder>,
        data: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), TransportError> {
        let (key, role, key_id) = self.bound_source(data, src_addr).await?;
        // The same rule as the legacy path: a ReceiveOnly key's content is never fanned out.
        // So it stops at its MAC and the session's keepalive. Past here it would share the
        // pool, and its segment 0 would open the way for what Full sessions left waiting.
        if role == KeyRole::ReceiveOnly {
            if Verifier::new(key, Profile::BoundSegment)
                .verify(data)
                .is_err()
            {
                self.metrics.inc_invalid_chunks();
                return Err(TransportError::AuthenticationFailed);
            }
            self.touch_session(src_addr).await;
            self.metrics.inc_receive_only_chunks_dropped(1);
            self.metrics
                .inc_receive_only_chunks_dropped_for_key(&key_id, 1);
            return Ok(());
        }
        let step = self.with_bound(bound, |forwarder| {
            forwarder.take(src_addr, key, &key_id, data, Instant::now(), |header| {
                self.validator.validate(header)
            })
        });
        let objects = match step {
            None | Some(BoundStep::Lost) => return Ok(()),
            Some(BoundStep::Invalid) => {
                self.metrics.inc_invalid_chunks();
                return Err(TransportError::AuthenticationFailed);
            }
            Some(BoundStep::Forward(objects)) => objects,
        };
        self.touch_session(src_addr).await;
        if objects.is_empty() {
            return Ok(());
        }
        let relayed = objects.iter().map(|o| o.object.shards.len() as u64).sum();
        self.metrics.inc_chunks_relayed_from_key(&key_id, relayed);
        self.forward_bound(bound, objects).await?;
        // What went out gave its room back.
        self.revive_bound(bound).await
    }

    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), TransportError> {
        self.metrics.inc_packets_received();

        if let Some(bound) = &self.bound
            && bound_raw::is_bound(data)
        {
            return self.handle_bound_packet(bound, data, src_addr).await;
        }

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

        let (chunks_to_forward, source_role, source_key_id): (Vec<ReadyChunks>, KeyRole, String) = {
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
                let role = session.role();
                let key_id = session.key_id().to_string();
                let ready = self.process_chunk_for_session(
                    session,
                    &chunk,
                    block_hash,
                    chunk_id,
                    total_chunks,
                );
                (ready, role, key_id)
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
                        RelaySession::new_unauthenticated(src_addr, UNAUTHENTICATED_KEY_ID),
                    );
                    self.metrics.inc_sessions_created();
                    self.metrics
                        .inc_sessions_created_for_key(UNAUTHENTICATED_KEY_ID);
                    let session = sessions.get_mut(&src_addr).unwrap();
                    let ready = self.process_chunk_for_session(
                        session,
                        &chunk,
                        block_hash,
                        chunk_id,
                        total_chunks,
                    );
                    (ready, KeyRole::Full, UNAUTHENTICATED_KEY_ID.to_string())
                } else {
                    // Decode already restricts `chunk.header.version` to {2, 3},
                    // so any well-formed chunk reaching here is v2 or v3 and can
                    // be checked against the authorized-key list.
                    self.admit_unknown_source(src_addr)?;
                    let active_keys = self.active_keys();
                    let mut authenticated_key: Option<AuthKey> = None;
                    for key in active_keys.iter() {
                        let temp_session = RelaySession::new(src_addr, key.id.clone(), key.key);
                        if verify_data_chunk_hmac(&temp_session, &chunk, &block_hash) {
                            authenticated_key = Some(key.clone());
                            break;
                        }
                    }

                    if let Some(key) = authenticated_key {
                        info!(peer = %src_addr, key_id = %key.id, role = ?key.role, "Authenticated new session");
                        sessions.insert(
                            src_addr,
                            RelaySession::new_with_role(
                                src_addr,
                                key.id.clone(),
                                key.key,
                                key.role,
                            ),
                        );
                        self.metrics.inc_sessions_created();
                        self.metrics.inc_sessions_created_for_key(&key.id);
                        let session = sessions.get_mut(&src_addr).unwrap();
                        let ready = self.process_chunk_for_session(
                            session,
                            &chunk,
                            block_hash,
                            chunk_id,
                            total_chunks,
                        );
                        (ready, key.role, key.id.clone())
                    } else {
                        warn!(peer = %src_addr, "Authentication failed - no matching key");
                        self.metrics.inc_auth_failures();
                        return Err(TransportError::AuthenticationFailed);
                    }
                }
            }
        };

        // Role-scoped keys (the invitee-injection security gate): a session
        // bound to a ReceiveOnly key still authenticates and assembles its
        // chunks (so keepalives/assembly keep working and it keeps receiving
        // forwards originated by Full sessions -- that direction is handled
        // entirely by `forward_to_peers` iterating over destination sessions
        // below, unaffected by this check), but content IT authored is never
        // fanned out to other peers. Drop it here, after authentication,
        // instead of relaying it.
        if source_role == KeyRole::ReceiveOnly {
            let dropped: u64 = chunks_to_forward
                .iter()
                .map(|r| r.chunks.len() as u64)
                .sum();
            if dropped > 0 {
                self.metrics.inc_receive_only_chunks_dropped(dropped);
                self.metrics
                    .inc_receive_only_chunks_dropped_for_key(&source_key_id, dropped);
                debug!(
                    peer = %src_addr,
                    key_id = %source_key_id,
                    dropped,
                    "Dropping chunks authored by a ReceiveOnly-bound session (not relayed)"
                );
            }
            return Ok(());
        }

        // Only Full sessions reach this point (ReceiveOnly returned above), so
        // this counts content each Full key authored that the relay fans out.
        let relayed: u64 = chunks_to_forward
            .iter()
            .map(|r| r.chunks.len() as u64)
            .sum();
        if relayed > 0 {
            self.metrics
                .inc_chunks_relayed_from_key(&source_key_id, relayed);
        }

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

    /// A keepalive, or a bound hello, which is one with a marker and flags. A node without
    /// the bound path takes a hello for a keepalive it cannot read, as an old node does. With
    /// the path on, an authenticated hello sets what the session takes and is answered.
    async fn handle_keepalive(
        &self,
        src_addr: SocketAddr,
        chunk: &Chunk,
    ) -> Result<(), TransportError> {
        let control = self.bound.as_ref().and_then(|_| {
            let hello = bound_raw::hello_flags(chunk).map(Control::Hello);
            hello.or_else(|| bound_raw::released_body(chunk).map(Control::Release))
        });
        match self.admit_keepalive(src_addr, chunk, control).await? {
            Some(Answer::Ack(ack)) => {
                let Some(socket) = self.socket.as_ref() else {
                    return Ok(());
                };
                if let Err(error) = socket.send_to(&ack, src_addr).await {
                    self.metrics.inc_packet_send_errors();
                    warn!(peer = %src_addr, %error, "Failed to answer a bound hello");
                }
            }
            Some(Answer::Release(key)) => {
                if let Some(bound) = self.bound.as_ref() {
                    let released = self.with_bound(bound, |f| f.release(key, Instant::now()));
                    debug!(peer = %src_addr, ?released, "A receiver refused a bound body");
                }
            }
            None => {}
        }
        Ok(())
    }

    /// What a hello or a release says, on a session it authenticated. A release counts only
    /// from a key with the full role: a receive-only key may not take another key's anchor.
    fn take_control(session: &mut RelaySession, control: Option<Control>) -> Option<Answer> {
        let control = control?;
        if !session.is_authenticated() {
            return None;
        }
        match control {
            Control::Hello(flags) => {
                session.set_receives_bound(flags & bound_raw::HELLO_RECEIVES != 0);
                Some(Answer::Ack(bound_raw::bound_hello_ack(&session.auth_key())))
            }
            Control::Release(key) => {
                (session.role() == KeyRole::Full).then_some(Answer::Release(key))
            }
        }
    }

    async fn admit_keepalive(
        &self,
        src_addr: SocketAddr,
        chunk: &Chunk,
        control: Option<Control>,
    ) -> Result<Option<Answer>, TransportError> {
        if control.is_none()
            && (chunk.header.block_hash != [0u8; 32]
                || chunk.header.chunk_id != 0
                || chunk.header.total_chunks != 0
                || chunk.header.payload_len != 0
                || !chunk.payload.is_empty())
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
            return Ok(Self::take_control(session, control));
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
                RelaySession::new_unauthenticated(src_addr, UNAUTHENTICATED_KEY_ID),
            );
            self.metrics.inc_sessions_created();
            self.metrics
                .inc_sessions_created_for_key(UNAUTHENTICATED_KEY_ID);
            return Ok(None);
        }

        if chunk.header.version != 2 {
            warn!(peer = %src_addr, "Auth required but received unsupported keepalive version");
            self.metrics.inc_auth_failures();
            return Err(TransportError::AuthenticationFailed);
        }

        self.admit_unknown_source(src_addr)?;
        let active_keys = self.active_keys();
        let mut authenticated_key: Option<AuthKey> = None;
        for key in active_keys.iter() {
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
            info!(peer = %src_addr, key_id = %key.id, role = ?key.role, "Authenticated new keepalive session");
            let mut session =
                RelaySession::new_with_role(src_addr, key.id.clone(), key.key, key.role);
            let answer = Self::take_control(&mut session, control);
            sessions.insert(src_addr, session);
            self.metrics.inc_sessions_created();
            self.metrics.inc_sessions_created_for_key(&key.id);
            Ok(answer)
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
#[path = "known_gap_resource_node_tests.rs"]
mod known_gap_resource_tests;

#[cfg(test)]
mod tests {
    use super::super::bound_raw::Trip;
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

    /// Build an authenticated v2 wire chunk for `block_hash` bound to `key`.
    fn authenticated_wire_chunk(key: [u8; 32], block_hash: &[u8; 32], chunk: &Chunk) -> Vec<u8> {
        let session = RelaySession::new("127.0.0.1:1".parse().unwrap(), "hmac-only", key);
        let hmac = session.compute_hmac(
            block_hash,
            chunk.header.chunk_id,
            chunk.header.total_chunks,
            chunk.header.payload_len,
            &chunk.payload,
        );
        let header = ChunkHeader::new_block_authenticated(
            block_hash,
            chunk.header.chunk_id,
            chunk.header.total_chunks,
            chunk.header.payload_len,
            hmac,
        );
        Chunk::new(header, chunk.payload.clone()).to_bytes()
    }

    #[tokio::test]
    async fn receive_only_session_chunks_are_not_forwarded_but_full_session_chunks_are() {
        // THE SECURITY TEST (role-scoped keys): a chunk received from a
        // ReceiveOnly-bound session must NOT be fanned out to other peers,
        // while the identical content from a Full-bound session MUST be.
        // This is the hard gate before opening the relay to real external
        // invitees -- an invitee key must not be able to inject content the
        // mesh will relay.
        let fleet_key = [0x42; 32];
        let invitee_key = [0x77; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![
            AuthKey::new("fleet", fleet_key),
            AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly),
        ]);
        let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        node.bind().await.unwrap();

        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observer_addr = observer.local_addr().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                observer_addr,
                RelaySession::new(observer_addr, "fleet", fleet_key),
            );
        }

        let compact = CompactBlock::new(vec![0xab; 2189], 0x1111, Vec::new(), Vec::new());
        let block_hash = *compact.header_hash().as_bytes();
        let chunks = node
            .chunker
            .compact_block_to_chunks(&compact, &block_hash)
            .unwrap();

        // The invitee (ReceiveOnly) authors the block. Its own session must
        // be created and bound ReceiveOnly, and NOTHING must reach the
        // observer.
        let invitee_addr: SocketAddr = "127.0.0.1:20001".parse().unwrap();
        for chunk in &chunks {
            let wire = authenticated_wire_chunk(invitee_key, &block_hash, chunk);
            node.handle_packet(&wire, invitee_addr).await.unwrap();
        }

        {
            let sessions = node.sessions.read().await;
            let session = sessions
                .get(&invitee_addr)
                .expect("invitee session created");
            assert_eq!(session.role(), KeyRole::ReceiveOnly);
        }

        let mut buf = vec![0u8; 2048];
        let result = timeout(Duration::from_millis(150), observer.recv_from(&mut buf)).await;
        assert!(
            result.is_err(),
            "ReceiveOnly-authored chunks must NOT be forwarded to other peers"
        );
        assert!(
            node.metrics().snapshot().receive_only_chunks_dropped > 0,
            "dropped chunks must be counted"
        );

        // The fleet (Full) authors the IDENTICAL block content. It MUST be
        // forwarded to the observer.
        let fleet_addr: SocketAddr = "127.0.0.1:20002".parse().unwrap();
        for chunk in &chunks {
            let wire = authenticated_wire_chunk(fleet_key, &block_hash, chunk);
            node.handle_packet(&wire, fleet_addr).await.unwrap();
        }

        let (len, _) = timeout(Duration::from_millis(200), observer.recv_from(&mut buf))
            .await
            .expect("Full-authored chunks must be forwarded to other peers")
            .unwrap();
        assert!(len > 0);
    }

    #[tokio::test]
    async fn receive_only_session_still_receives_forwards_from_full_session() {
        // Direction unaffected: a session bound ReceiveOnly still RECEIVES
        // forwards originated by a Full session -- only content IT authors
        // is gated from fan-out.
        let fleet_key = [0x42; 32];
        let invitee_key = [0x77; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", fleet_key)]);
        let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        node.bind().await.unwrap();

        let invitee_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let invitee_addr = invitee_peer.local_addr().unwrap();
        let sender_addr: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                sender_addr,
                RelaySession::new(sender_addr, "fleet", fleet_key),
            );
            sessions.insert(
                invitee_addr,
                RelaySession::new_with_role(
                    invitee_addr,
                    "invitee",
                    invitee_key,
                    KeyRole::ReceiveOnly,
                ),
            );
        }

        let compact = CompactBlock::new(vec![0xab; 2189], 0x2222, Vec::new(), Vec::new());
        let block_hash = *compact.header_hash().as_bytes();
        let chunks = node
            .chunker
            .compact_block_to_chunks(&compact, &block_hash)
            .unwrap();

        for chunk in &chunks {
            let wire = authenticated_wire_chunk(fleet_key, &block_hash, chunk);
            node.handle_packet(&wire, sender_addr).await.unwrap();
        }

        let mut buf = vec![0u8; 2048];
        let (len, _) = timeout(Duration::from_millis(200), invitee_peer.recv_from(&mut buf))
            .await
            .expect("a ReceiveOnly session must still receive forwards from a Full session")
            .unwrap();
        assert!(len > 0);
    }

    #[tokio::test]
    async fn chunks_relayed_from_key_counts_what_each_full_key_authored() {
        // Inbound attribution: chunks a Full session sends that the relay
        // fans out are counted against the SOURCE key. A ReceiveOnly key's
        // dropped chunks are not counted here (they were never relayed).
        let pool_key = [0x42; 32];
        let fleet_key = [0x43; 32];
        let invitee_key = [0x77; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![
            AuthKey::new("pool", pool_key),
            AuthKey::new("fleet", fleet_key),
            AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly),
        ]);
        let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        node.bind().await.unwrap();

        // Exactly one destination, so everything relayed from "pool" lands
        // on "fleet" and the two directional counters must agree.
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observer_addr = observer.local_addr().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                observer_addr,
                RelaySession::new(observer_addr, "fleet", fleet_key),
            );
        }

        let compact = CompactBlock::new(vec![0xab; 2189], 0x3333, Vec::new(), Vec::new());
        let block_hash = *compact.header_hash().as_bytes();
        let chunks = node
            .chunker
            .compact_block_to_chunks(&compact, &block_hash)
            .unwrap();

        let invitee_addr: SocketAddr = "127.0.0.1:20011".parse().unwrap();
        for chunk in &chunks {
            let wire = authenticated_wire_chunk(invitee_key, &block_hash, chunk);
            node.handle_packet(&wire, invitee_addr).await.unwrap();
        }
        let pool_addr: SocketAddr = "127.0.0.1:20012".parse().unwrap();
        for chunk in &chunks {
            let wire = authenticated_wire_chunk(pool_key, &block_hash, chunk);
            node.handle_packet(&wire, pool_addr).await.unwrap();
        }
        // Resending the same chunks is deduplicated per session and must not
        // inflate the count.
        for chunk in &chunks {
            let wire = authenticated_wire_chunk(pool_key, &block_hash, chunk);
            node.handle_packet(&wire, pool_addr).await.unwrap();
        }

        let snapshot = node.metrics().snapshot();
        let relayed_from = |id: &str| {
            snapshot
                .chunks_relayed_from_key
                .iter()
                .find(|(k, _)| k == id)
                .map(|(_, v)| *v)
        };
        let forwarded_to_fleet = snapshot
            .chunks_forwarded_by_key
            .iter()
            .find(|(k, _)| k == "fleet")
            .map(|(_, v)| *v)
            .expect("observer received forwards");

        assert!(forwarded_to_fleet > 0);
        assert_eq!(relayed_from("pool"), Some(forwarded_to_fleet));
        assert_eq!(
            relayed_from("invitee"),
            None,
            "dropped chunks are not relayed"
        );
        assert_eq!(
            relayed_from("fleet"),
            None,
            "the destination authored nothing"
        );
    }

    #[tokio::test]
    async fn keepalive_from_receive_only_session_keeps_it_alive() {
        let invitee_key = [0x77; 32];
        let addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![
            AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly),
        ]);
        let node = RelayNode::new(config).unwrap();
        {
            let mut sessions = node.sessions.write().await;
            let mut session =
                RelaySession::new_with_role(addr, "invitee", invitee_key, KeyRole::ReceiveOnly);
            session.last_seen = Instant::now() - Duration::from_secs(200);
            sessions.insert(addr, session);
        }

        let hmac_session = RelaySession::new(addr, "invitee", invitee_key);
        let hmac = hmac_session.compute_hmac(&[0u8; 32], 0, 0, 0, &[]);
        let keepalive = Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new());

        node.handle_keepalive(addr, &keepalive).await.unwrap();

        let sessions = node.sessions.read().await;
        let session = sessions.get(&addr).expect("session retained");
        assert!(!session.is_expired(Duration::from_secs(60)));
        assert_eq!(session.role(), KeyRole::ReceiveOnly);
    }

    fn bound_node_config(keys: Vec<AuthKey>) -> RelayConfig {
        RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(keys)
            .with_fec(10, 3)
            .with_bound_raw(Default::default())
    }

    /// Only what passes the MAC keeps the session, as with a keepalive.
    #[tokio::test]
    async fn a_receive_only_session_is_kept_alive_by_its_chunks_and_not_by_forgeries() {
        let invitee_key = [0x77; 32];
        let addr: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let keys = vec![AuthKey::new("invitee", invitee_key).with_role(KeyRole::ReceiveOnly)];
        let node = RelayNode::new(bound_node_config(keys)).unwrap();
        {
            let mut session =
                RelaySession::new_with_role(addr, "invitee", invitee_key, KeyRole::ReceiveOnly);
            session.last_seen = Instant::now() - Duration::from_secs(200);
            node.sessions.write().await.insert(addr, session);
        }
        let expired = |sessions: &HashMap<SocketAddr, RelaySession>| {
            sessions[&addr].is_expired(Duration::from_secs(60))
        };

        let forged = bound_raw::sealed_body(&[1; 5000], &[0x78; 32]).unwrap();
        assert!(matches!(
            node.handle_packet(&forged[0], addr).await,
            Err(TransportError::AuthenticationFailed)
        ));
        assert!(expired(&*node.sessions.read().await));

        let sealed = bound_raw::sealed_body(&[1; 5000], &invitee_key).unwrap();
        node.handle_packet(&sealed[0], addr).await.unwrap();
        assert!(!expired(&*node.sessions.read().await));
    }

    async fn until(mut done: impl FnMut() -> bool) {
        timeout(Duration::from_secs(10), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("it never came");
    }

    /// A panic that no session can be held to, on the node's real loop. The path starts
    /// over and sessions stay. What the node counts and what it has yet to read are no part
    /// of the forwarder: the rest of this burst goes on, and it is enough for the object.
    #[tokio::test]
    async fn a_panic_outside_any_session_leaves_the_node_running() {
        let key = [0x42; 32];
        let keys = vec![AuthKey::new("fleet", key)];
        let mut node =
            RelayNode::with_validator(bound_node_config(keys), StubPowValidator).unwrap();
        node.bind().await.unwrap();
        let addr = node.local_addr().unwrap();
        let node = Arc::new(node);
        let running = Arc::clone(&node);
        let task = tokio::spawn(async move { running.run().await });
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sealed = bound_raw::sealed_body(&[1; 5000], &key).unwrap();

        socket.send_to(&sealed[0], addr).await.unwrap();
        until(|| node.bound_usage().unwrap().pool.objects == 1).await;
        let received = node.metrics().snapshot().packets_received;
        let handled = node.bound_usage().unwrap().ingress.handled;
        let bound = node.bound.as_ref().unwrap();
        bound.lock().unwrap().trips = vec![Trip::BetweenSteps];
        for datagram in &sealed[1..] {
            socket.send_to(datagram, addr).await.unwrap();
        }
        until(|| node.bound_usage().unwrap().objects_released == 1).await;

        assert!(!task.is_finished());
        assert!(node.is_running());
        assert!(!bound.is_poisoned());
        assert_eq!(node.session_count().await, 1);
        let usage = node.bound_usage().unwrap();
        assert_eq!(usage.panic_resets, 1);
        assert_eq!(usage.pool.objects, 0);
        assert!(usage.ingress.handled > handled);
        assert!(node.metrics().snapshot().packets_received > received);

        let session = RelaySession::new(addr, "fleet", key);
        let hmac = session.compute_hmac(&[0u8; 32], 0, 0, 0, &[]);
        let keepalive = Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new());
        let received = node.metrics().snapshot().packets_received;
        socket.send_to(&keepalive.to_bytes(), addr).await.unwrap();
        until(|| node.metrics().snapshot().packets_received > received).await;
    }

    /// A poisoned lock is no state to go on from.
    #[tokio::test]
    async fn a_poisoned_lock_starts_the_path_over() {
        let keys = vec![AuthKey::new("fleet", [0x42; 32])];
        let node = RelayNode::new(bound_node_config(keys)).unwrap();
        let bound = node.bound.as_ref().unwrap();
        let held_through_it = catch_unwind(AssertUnwindSafe(|| {
            let _forwarder = bound.lock().unwrap();
            panic!("stopped on purpose");
        }));
        assert!(held_through_it.is_err());
        assert!(bound.is_poisoned());

        let usage = node.bound_usage().unwrap();

        assert_eq!(usage.panic_resets, 1);
        assert!(!bound.is_poisoned());
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

    #[tokio::test]
    async fn apply_active_keys_evicts_sessions_bound_to_removed_keys() {
        // Hot-revocation, PR-B: a session bound to a key that has been
        // dropped from the active set must be evicted immediately when the
        // new set is applied -- it must not survive until the 300s idle
        // session timeout.
        let fleet_key = [0x42; 32];
        let alice_key = [0x77; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![
            AuthKey::new("fleet", fleet_key),
            AuthKey::new("alice", alice_key),
        ]);
        let node = RelayNode::new(config).unwrap();

        let fleet_addr: SocketAddr = "127.0.0.1:11111".parse().unwrap();
        let alice_addr: SocketAddr = "127.0.0.1:22222".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                fleet_addr,
                RelaySession::new(fleet_addr, "fleet", fleet_key),
            );
            sessions.insert(
                alice_addr,
                RelaySession::new(alice_addr, "alice", alice_key),
            );
        }

        // Alice's (file-sourced) key is revoked; only fleet remains active.
        node.apply_active_keys(vec![AuthKey::new("fleet", fleet_key)])
            .await;

        let sessions = node.sessions.read().await;
        assert!(
            sessions.contains_key(&fleet_addr),
            "session bound to a surviving key must not be evicted"
        );
        assert!(
            !sessions.contains_key(&alice_addr),
            "session bound to a revoked key must be evicted"
        );
    }

    fn authenticated_keepalive(key: [u8; 32]) -> Vec<u8> {
        let session = RelaySession::new("127.0.0.1:1".parse().unwrap(), "hmac-only", key);
        let hmac = session.compute_hmac(&[0u8; 32], 0, 0, 0, &[]);
        Chunk::new(ChunkHeader::new_keepalive_authenticated(hmac), Vec::new()).to_bytes()
    }

    #[tokio::test]
    async fn apply_active_keys_evicts_same_id_rotated_key() {
        let old_key = [0x11; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("alice", old_key)]);
        let node = RelayNode::new(config).unwrap();
        let addr: SocketAddr = "127.0.0.1:22222".parse().unwrap();
        node.handle_packet(&authenticated_keepalive(old_key), addr)
            .await
            .unwrap();
        assert_eq!(node.session_count().await, 1);

        node.apply_active_keys(vec![AuthKey::new("alice", [0x22; 32])])
            .await;

        assert_eq!(
            node.session_count().await,
            0,
            "rotated session must be evicted"
        );
    }

    async fn assert_role_change_evicts_session(old_role: KeyRole, new_role: KeyRole) {
        let key = [0x11; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("alice", key).with_role(old_role)]);
        let node = RelayNode::new(config).unwrap();
        let addr: SocketAddr = "127.0.0.1:22222".parse().unwrap();
        let keepalive = authenticated_keepalive(key);
        node.handle_packet(&keepalive, addr).await.unwrap();
        assert_eq!(node.session_count().await, 1);

        node.apply_active_keys(vec![AuthKey::new("alice", key).with_role(new_role)])
            .await;

        assert_eq!(
            node.session_count().await,
            0,
            "changed role must evict the session"
        );
        node.handle_packet(&keepalive, addr).await.unwrap();
        let sessions = node.sessions.read().await;
        assert_eq!(sessions.get(&addr).unwrap().role(), new_role);
        assert_eq!(node.metrics().snapshot().sessions_created, 2);
    }

    #[tokio::test]
    async fn apply_active_keys_evicts_demoted_session() {
        assert_role_change_evicts_session(KeyRole::Full, KeyRole::ReceiveOnly).await;
    }

    #[tokio::test]
    async fn apply_active_keys_evicts_promoted_session() {
        assert_role_change_evicts_session(KeyRole::ReceiveOnly, KeyRole::Full).await;
    }

    #[tokio::test]
    async fn apply_active_keys_preserves_unchanged_and_reordered_authorizations() {
        let keys = vec![
            AuthKey::new("fleet", [0x42; 32]),
            AuthKey::new("alice", [0x77; 32]).with_role(KeyRole::ReceiveOnly),
        ];
        let config =
            RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(keys.clone());
        let node = RelayNode::new(config).unwrap();
        let peers: [SocketAddr; 2] = [
            "127.0.0.1:11111".parse().unwrap(),
            "127.0.0.1:22222".parse().unwrap(),
        ];
        let last_seen = Instant::now() - Duration::from_secs(30);
        for (addr, key) in peers.iter().zip(&keys) {
            node.handle_packet(&authenticated_keepalive(key.key), *addr)
                .await
                .unwrap();
            let mut sessions = node.sessions.write().await;
            let session = sessions.get_mut(addr).unwrap();
            session.last_seen = last_seen;
            assert!(session.mark_chunk_seen([0xab; 32], 0));
        }

        node.apply_active_keys(keys.clone()).await;
        node.apply_active_keys(keys.into_iter().rev().collect())
            .await;

        let mut sessions = node.sessions.write().await;
        assert_eq!(sessions.len(), 2);
        for addr in peers {
            let session = sessions.get_mut(&addr).expect("unchanged session retained");
            assert_eq!(session.last_seen, last_seen);
            assert!(
                !session.mark_chunk_seen([0xab; 32], 0),
                "replay state retained"
            );
        }
        assert_eq!(node.metrics().snapshot().sessions_created, 2);
    }

    #[tokio::test]
    async fn apply_active_keys_rejects_rotated_session_traffic_and_admits_new_key() {
        let old_key = [0x11; 32];
        let new_key = [0x22; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("alice", old_key)]);
        let node = RelayNode::new(config).unwrap();
        let addr: SocketAddr = "127.0.0.1:22222".parse().unwrap();
        let old_keepalive = authenticated_keepalive(old_key);
        node.handle_packet(&old_keepalive, addr).await.unwrap();

        node.apply_active_keys(vec![AuthKey::new("alice", new_key)])
            .await;

        assert!(
            matches!(
                node.handle_packet(&old_keepalive, addr).await,
                Err(TransportError::AuthenticationFailed)
            ),
            "the old key must not keep its established session alive"
        );
        let block_hash = [0xab; 32];
        let chunk = Chunk::new(ChunkHeader::new_block(&block_hash, 0, 13, 4), vec![1; 4]);
        let old_data = authenticated_wire_chunk(old_key, &block_hash, &chunk);
        assert!(
            matches!(
                node.handle_packet(&old_data, addr).await,
                Err(TransportError::AuthenticationFailed)
            ),
            "the old key must not submit data after rotation"
        );
        assert_eq!(node.session_count().await, 0);
        assert_eq!(node.metrics().snapshot().auth_failures, 2);

        node.handle_packet(&authenticated_keepalive(new_key), addr)
            .await
            .unwrap();
        assert_eq!(node.session_count().await, 1);
        assert_eq!(node.metrics().snapshot().sessions_created, 2);
    }

    #[tokio::test]
    async fn authenticated_key_named_like_unauthenticated_sentinel_is_still_revoked() {
        let old_key = [0x31; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new(UNAUTHENTICATED_KEY_ID, old_key)]);
        let node = RelayNode::new(config).unwrap();
        let addr: SocketAddr = "127.0.0.1:31337".parse().unwrap();
        node.handle_packet(&authenticated_keepalive(old_key), addr)
            .await
            .unwrap();

        node.apply_active_keys(vec![AuthKey::new(UNAUTHENTICATED_KEY_ID, [0x32; 32])])
            .await;

        assert_eq!(node.session_count().await, 0);
    }

    #[tokio::test]
    async fn apply_active_keys_preserves_unauthenticated_sessions() {
        let config = RelayConfig::default().with_unauthenticated_peers_allowed(true);
        let node = RelayNode::new(config).unwrap();

        let addr: SocketAddr = "127.0.0.1:33333".parse().unwrap();
        {
            let mut sessions = node.sessions.write().await;
            sessions.insert(
                addr,
                RelaySession::new_unauthenticated(addr, UNAUTHENTICATED_KEY_ID),
            );
        }

        node.apply_active_keys(vec![]).await;

        let sessions = node.sessions.read().await;
        assert!(
            sessions.contains_key(&addr),
            "unauthenticated sessions are never evicted by a key-set change"
        );
    }

    #[tokio::test]
    async fn is_authorized_reflects_applied_active_keys() {
        let fleet_key = [0x42; 32];
        let new_key = [0x99; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", fleet_key)]);
        let node = RelayNode::new(config).unwrap();

        assert!(node.is_authorized(&fleet_key));
        assert!(!node.is_authorized(&new_key));

        node.apply_active_keys(vec![AuthKey::new("new", new_key)])
            .await;

        assert!(
            !node.is_authorized(&fleet_key),
            "revoked key must no longer authorize"
        );
        assert!(
            node.is_authorized(&new_key),
            "newly applied key must authorize"
        );
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
    #[tokio::test]
    async fn attribution_requires_authentication_and_records_immediate_peer() {
        let path =
            std::env::temp_dir().join(format!("relay-attribution-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let key = [0x42; 32];
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("pool", key)]);
        let mut node = RelayNode::with_validator(config, StubPowValidator)
            .unwrap()
            .with_arrival_sink(Some(ArrivalSink::new(&path).unwrap()));
        node.bind().await.unwrap();
        let mut raw = vec![0xab; ZCASH_FULL_HEADER_SIZE + 256];
        raw[0] = 4;
        let hash = raw_block_header_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
        let segments = split_raw_block(hash, &raw, 2_000).unwrap();
        let source = "127.0.0.1:12349".parse().unwrap();
        let signing = RelaySession::new(source, "pool", key);
        for segment in segments {
            for chunk in node.chunker.raw_block_segment_to_chunks(&segment).unwrap() {
                let h = &chunk.header;
                let mac = signing.compute_hmac(
                    &h.block_hash,
                    h.chunk_id,
                    h.total_chunks,
                    h.payload_len,
                    &chunk.payload,
                );
                let header = authenticated_data_header(
                    h.msg_type,
                    &h.block_hash,
                    h.chunk_id,
                    h.total_chunks,
                    h.payload_len,
                    mac,
                )
                .unwrap();
                let wire = Chunk::new(header, chunk.payload).to_bytes();
                let mut tampered = wire.clone();
                *tampered.last_mut().unwrap() ^= 1;
                assert!(node.handle_packet(&tampered, source).await.is_err());
                node.handle_packet(&wire, source).await.unwrap();
                // Retransmission must not create another arrival.
                node.handle_packet(&wire, source).await.unwrap();
            }
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r["source_key_id"], "pool");
        assert_eq!(r["source_role"], "full");
        assert_eq!(r["authenticated"], true);
        assert_eq!(r["stage"], "header_pow_validated");
        assert_eq!(
            r["hash"],
            crate::hash::consensus_block_hash_display(&raw[..ZCASH_FULL_HEADER_SIZE])
        );
        assert!(r.get("peer").is_none());
        assert_eq!(r["object_kind"], "raw_segment");
        std::fs::remove_file(path).unwrap();
    }

    /// Feed `chunks` (twice, modelling retransmission) through one session of a
    /// node with an arrival sink attached; return the parsed arrival records.
    fn arrival_records_for<V, F>(tag: &str, validator: V, make_chunks: F) -> Vec<serde_json::Value>
    where
        V: PowValidator + 'static,
        F: FnOnce(&BlockChunker) -> (Vec<Chunk>, [u8; 32]),
    {
        let path = std::env::temp_dir().join(format!(
            "relay-arrival-{tag}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_unauthenticated_peers_allowed(true);
        let node = RelayNode::with_validator(config, validator)
            .unwrap()
            .with_arrival_sink(Some(ArrivalSink::new(&path).unwrap()));
        let (chunks, object_hash) = make_chunks(&node.chunker);
        let mut session = RelaySession::new("127.0.0.1:12350".parse().unwrap(), "pool", [7u8; 32]);
        for _ in 0..2 {
            for chunk in &chunks {
                let _ = node.process_chunk_for_session(
                    &mut session,
                    chunk,
                    object_hash,
                    chunk.header.chunk_id as usize,
                    chunk.header.total_chunks as usize,
                );
            }
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        content
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }

    fn compact_v3_chunks(
        compact: &CompactBlock,
    ) -> impl FnOnce(&BlockChunker) -> (Vec<Chunk>, [u8; 32]) + '_ {
        move |chunker| {
            let block_hash = *compact.header_hash().as_bytes();
            let chunks = chunker
                .compact_block_to_chunks_adaptive(compact, &block_hash)
                .unwrap();
            (
                chunks,
                crate::segmented_block::compact_v3_object_hash(block_hash),
            )
        }
    }

    #[test]
    fn validated_compact_block_emits_one_attributed_receipt() {
        // Pool gateways send most blocks as compact blocks and fall back to raw
        // segments only for oversized ones. Receipts must cover compact blocks
        // too, or a pool's direct submissions are invisible to attribution.
        let header = vec![0xab; 2189];
        let compact = CompactBlock::new(header.clone(), 0x5151, Vec::new(), Vec::new());
        let records = arrival_records_for("compact", StubPowValidator, compact_v3_chunks(&compact));
        assert_eq!(records.len(), 1, "one receipt per object, got {records:?}");
        let r = &records[0];
        assert_eq!(r["stage"], "header_pow_validated");
        assert_eq!(r["object_kind"], "compact");
        assert_eq!(r["source_key_id"], "pool");
        assert_eq!(r["source_role"], "full");
        assert_eq!(
            r["hash"],
            crate::hash::consensus_block_hash_display(&header)
        );
    }

    #[test]
    fn validated_compact_skeleton_emits_attributed_receipt() {
        let header = vec![0xab; 2189];
        let compact = CompactBlock::new(header.clone(), 0x5252, Vec::new(), Vec::new());
        let records = arrival_records_for("skeleton", StubPowValidator, |chunker| {
            let block_hash = *compact.header_hash().as_bytes();
            let object_hash = crate::segmented_block::skeleton_object_hash(block_hash);
            let chunks = chunker
                .compact_block_to_chunks_skeleton(&compact, &object_hash)
                .unwrap();
            (chunks, object_hash)
        });
        assert_eq!(records.len(), 1, "one receipt per object, got {records:?}");
        assert_eq!(records[0]["object_kind"], "compact_skeleton");
        assert_eq!(
            records[0]["hash"],
            crate::hash::consensus_block_hash_display(&header)
        );
    }

    #[test]
    fn invalid_compact_block_emits_no_receipt() {
        let compact = CompactBlock::new(vec![0xab; 2189], 0x5353, Vec::new(), Vec::new());
        let records = arrival_records_for(
            "invalid",
            crate::RejectAllValidator,
            compact_v3_chunks(&compact),
        );
        assert!(
            records.is_empty(),
            "invalid PoW must not log a receipt: {records:?}"
        );
    }

    /// Real UDP loopback benchmark. Not a WAN or complete consensus-block
    /// benchmark: completion here means the final packet of one object batch.
    #[tokio::test]
    #[ignore = "operator benchmark; prints observed scheduling tradeoffs"]
    async fn benchmark_forward_scheduling() {
        for peers in [4usize, 8] {
            for round_robin in [false, true] {
                for trial in 0..3 {
                    let packets = 64usize;
                    let mut config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
                        .with_forward_pacing(16, Duration::from_millis(1))
                        .with_authorized_keys(vec![AuthKey::new("benchmark", [1; 32])]);
                    config.forward_round_robin = round_robin;
                    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
                    node.bind().await.unwrap();
                    let started = Instant::now();
                    let mut receivers = Vec::new();
                    for peer in 0..peers {
                        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        let addr = socket.local_addr().unwrap();
                        let key = [peer as u8 + 1; 32];
                        node.sessions
                            .write()
                            .await
                            .insert(addr, RelaySession::new(addr, format!("peer{peer}"), key));
                        receivers.push(tokio::spawn(async move {
                            let verifier = RelaySession::new(addr, "verify", key);
                            let mut first = None;
                            let mut last = 0u128;
                            let mut seen = std::collections::HashSet::new();
                            for _ in 0..packets {
                                let mut buf = [0u8; 2048];
                                let (n, _) =
                                    timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
                                        .await
                                        .unwrap()
                                        .unwrap();
                                let arrival = started.elapsed().as_micros();
                                first.get_or_insert(arrival);
                                last = arrival;
                                let c = Chunk::from_bytes(&buf[..n]).unwrap();
                                let h = &c.header;
                                assert!(verifier.verify_hmac(
                                    &h.block_hash,
                                    h.chunk_id,
                                    h.total_chunks,
                                    h.payload_len,
                                    &c.payload,
                                    &h.hmac
                                ));
                                assert!(seen.insert(h.chunk_id));
                            }
                            (first.unwrap(), last)
                        }));
                    }
                    let setup_us = started.elapsed().as_micros();
                    let chunks = (0..packets)
                        .map(|i| (i as u16, vec![i as u8; 512]))
                        .collect::<Vec<_>>();
                    node.forward_to_peers(
                        "127.0.0.1:1".parse().unwrap(),
                        MessageType::Block,
                        &[7; 32],
                        packets as u16,
                        0,
                        &chunks,
                    )
                    .await
                    .unwrap();
                    let mut times = Vec::new();
                    for r in receivers {
                        let (a, b) = r.await.unwrap();
                        times.push((a.saturating_sub(setup_us), b.saturating_sub(setup_us)));
                    }
                    assert_eq!(
                        node.metrics().snapshot().packets_forwarded,
                        (peers * packets) as u64
                    );
                    println!(
                        "BENCH {}",
                        serde_json::json!({"peers":peers,"packets_per_peer":packets,"round_robin":round_robin,"trial":trial,"first_packet_us":times.iter().map(|(a,_)|a).collect::<Vec<_>>(),"batch_complete_us":times.iter().map(|(_,b)|b).collect::<Vec<_>>() })
                    );
                }
            }
        }
    }
}
