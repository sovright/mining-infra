use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sovright_relay::{
    BlockBodyError, BlockChunker, BlockSender, ClientConfig, CompactBlock, EquihashPowValidator,
    MAX_BLOCK_BYTES, MAX_PAYLOAD_SIZE, PowResult, PowValidator, RawBlockSegment, RelayClient,
    TargetCheck, TransportError, ZCASH_FULL_HEADER_SIZE, consensus_block_hash_display,
    header_meets_stated_target, parse_block_body, split_raw_block, zcash_block_hash,
};
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, watch};
use tokio::task::JoinError;
use tokio::time::sleep;
use tracing::{info, warn};
use zcash_equihash_validator::Target;

use crate::block::{
    compact_block_from_parsed, compact_block_from_parsed_with_tx_cache,
    skeleton_compact_block_from_parsed,
};
use crate::coinbase::CoinbaseTelemetry;
use crate::config::{Config, DEFAULT_UNREADABLE_BODIES_PER_HEADER};
use crate::error::{IngressError, Result};
use crate::event::EventSink;
use crate::hash::inventory_hash_to_display;
use crate::metrics::{BlockBodyRejections, METRICS_WRITE_INTERVAL, spawn_metrics_textfile_writer};
use crate::tx_cache::TxCache;
use crate::wire::decode_compact_size;

const RELAY_LEN_PREFIX_BYTES: usize = 4;

/// Upper bound on the serialized compact-skeleton size worth sending as a
/// redundant, heavier-parity early copy ahead of the full compact block. The
/// skeleton is a strict duplicate of the reconstruction-critical data, so for a
/// large object the extra copy is pure overhead -- above this the full compact
/// block (the push fallback) is left to carry it alone. Typical Zcash compact
/// blocks are ~1.5-2.5 KB (the Equihash header dominates); this admits normal
/// blocks and skips oversized / cold-cache (large-prefill) ones.
const SKELETON_MAX_WIRE_BYTES: usize = 8 * 1024;

/// Block bodies prepared at once for P2P peers. A peer task waits for its own
/// delivery, so `max_peers` limits how many queue here and this limits how many
/// run, whatever the peers send.
const P2P_PARSE_PERMITS: usize = 1;

/// The same for the pool gateway. It has its own permits so that a found block
/// never queues behind peer traffic.
const POOL_PARSE_PERMITS: usize = 1;

/// How raw blocks leave this ingress. Every mode but `Legacy` is #130 PR B research.
///
/// The record of what was forwarded follows: `Legacy` keeps one per header, so the first
/// body this ingress passes stops every other body of that header. The others keep one
/// per body, up to a limit per header, because this ingress cannot tell which body is the
/// block: the strict reader can pass more than one, and only Zebra can choose.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RawWire {
    #[default]
    Legacy,
    /// Both formats. An old receiver takes the legacy copy, with everything that means.
    Dual,
    /// The bound format only, so a receiver or relay without it gets no raw block.
    Bound,
}

impl RawWire {
    fn keys_by_body(self) -> bool {
        self != Self::Legacy
    }
}

/// Bounded, time-windowed LRU of recently-forwarded block hashes. Used by
/// `RelayBridge::forward_block` to implement first-seen-wins dedup so the
/// same block being delivered by multiple P2P peers (the steady-state case)
/// is only encoded and broadcast once into the relay mesh.
#[derive(Debug)]
struct RecentForwardedHashes {
    capacity: usize,
    window: Duration,
    entries: std::collections::VecDeque<([u8; 32], std::time::Instant)>,
    /// Blocks being sent right now. Nothing is ever sent on these channels: a
    /// [`ForwardClaim`] removes its entry when it ends, and that closes the
    /// channel and wakes every copy waiting on it, however late they subscribed.
    in_flight: HashMap<[u8; 32], watch::Sender<()>>,
    /// Bodies a header has sent, or is sending, in the window. Only a record per body
    /// can go past one. A body counts once any copy of it has left, even with another
    /// copy still owed, and its own repeats cost it nothing.
    bodies_per_header: usize,
    /// Header, what the record is kept by, and when.
    sent_bodies: VecDeque<([u8; 32], [u8; 32], std::time::Instant)>,
    sending_bodies: HashMap<[u8; 32], [u8; 32]>,
}

/// One body forwarded without validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UnverifiedBody {
    header_hash: [u8; 32],
    digest: [u8; 32],
}

/// How far an unverified body has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnverifiedProgress {
    /// A slot holds it, and only that slot can end this.
    Sending,
    /// A copy left and another is owed. It keeps its place, as what left has gone, and
    /// its next delivery sends.
    Owed,
    /// Every copy went.
    Sent,
}

/// Bodies forwarded without validation. They never claim their header, or a forged
/// body would hide the real one. This only stops the same bytes going out twice
/// and bounds how many bodies one header can send, because each is a full raw send
/// that nothing has validated. Honest copies of a block are identical, so they use
/// one place; anyone holding a real header can use the rest.
#[derive(Debug)]
struct UnverifiedForwards {
    capacity: usize,
    window: Duration,
    per_header: usize,
    entries: VecDeque<(UnverifiedBody, std::time::Instant, UnverifiedProgress)>,
    /// Bodies a slot holds. Nothing is ever sent on these channels: the entry goes when
    /// the slot ends, and that wakes every copy waiting on it.
    sending: HashMap<UnverifiedBody, watch::Sender<()>>,
    /// See [`Self::waiting_for_copies`].
    wait_for_sending: bool,
}

/// What a body found when it asked to be forwarded unverified.
enum UnverifiedReservation {
    Reserved,
    /// It left before with a copy owed, and this is its next try. The place is its own.
    Owed,
    /// A copy is going now. How that ends says what this one does, so it waits. It is
    /// neither a refusal nor a repeat yet.
    Sending(watch::Receiver<()>),
    Repeat,
    HeaderFull,
}

impl Default for UnverifiedForwards {
    fn default() -> Self {
        Self::new(
            64,
            Duration::from_secs(30),
            DEFAULT_UNREADABLE_BODIES_PER_HEADER,
        )
    }
}

impl UnverifiedForwards {
    fn new(capacity: usize, window: Duration, per_header: usize) -> Self {
        Self {
            capacity,
            window,
            per_header,
            entries: VecDeque::new(),
            sending: HashMap::new(),
            wait_for_sending: false,
        }
    }

    /// A copy of a body still being sent waits for that send to end, and goes if it failed.
    /// Off, as `RawWire::Legacy` always had it, such a copy is a repeat and is dropped.
    fn waiting_for_copies(mut self, wait: bool) -> Self {
        self.wait_for_sending = wait;
        self
    }

    fn reserve(&mut self, body: UnverifiedBody, now: std::time::Instant) -> UnverifiedReservation {
        // Never expire an in-flight reservation: its drop guard still owns it.
        self.entries.retain(|(_, at, progress)| {
            *progress == UnverifiedProgress::Sending || now.duration_since(*at) <= self.window
        });
        let same_body = self.entries.iter_mut().find(|(entry, _, _)| *entry == body);
        if let Some((_, at, progress)) = same_body {
            return match *progress {
                UnverifiedProgress::Sent => UnverifiedReservation::Repeat,
                UnverifiedProgress::Sending if !self.wait_for_sending => {
                    UnverifiedReservation::Repeat
                }
                UnverifiedProgress::Sending => {
                    let sending = self.sending.entry(body);
                    let sending = sending.or_insert_with(|| watch::channel(()).0);
                    UnverifiedReservation::Sending(sending.subscribe())
                }
                UnverifiedProgress::Owed => {
                    (*at, *progress) = (now, UnverifiedProgress::Sending);
                    self.sending.insert(body, watch::channel(()).0);
                    UnverifiedReservation::Owed
                }
            };
        }
        let same_header = self
            .entries
            .iter()
            .filter(|(entry, _, _)| entry.header_hash == body.header_hash)
            .count();
        if same_header >= self.per_header {
            return UnverifiedReservation::HeaderFull;
        }
        if self.entries.len() >= self.capacity.max(self.per_header) {
            return UnverifiedReservation::HeaderFull;
        }
        self.entries
            .push_back((body, now, UnverifiedProgress::Sending));
        self.sending.insert(body, watch::channel(()).0);
        UnverifiedReservation::Reserved
    }

    fn sent(&self, body: &UnverifiedBody) -> bool {
        self.entries.iter().any(|(entry, at, progress)| {
            *entry == *body && *progress == UnverifiedProgress::Sent && at.elapsed() <= self.window
        })
    }

    fn settle(&mut self, body: &UnverifiedBody, settled: UnverifiedProgress) {
        let entry = self.entries.iter_mut().find(|(entry, _, _)| entry == body);
        if let Some((_, at, progress)) = entry {
            (*at, *progress) = (std::time::Instant::now(), settled);
        }
        self.sending.remove(body);
    }

    fn commit(&mut self, body: &UnverifiedBody) {
        self.settle(body, UnverifiedProgress::Sent);
    }

    fn release(&mut self, body: &UnverifiedBody) {
        self.entries.retain(|(entry, _, _)| entry != body);
        self.sending.remove(body);
    }
}

/// A body's place while it is sent. Ending it any way but [`Self::commit`] gives the
/// place back, so a failed send does not count against the header, unless a copy has
/// left. Then the body stays owed: it holds its place and can come again.
struct UnverifiedSlot {
    forwards: Arc<std::sync::Mutex<UnverifiedForwards>>,
    body: UnverifiedBody,
    /// A copy of this body has left, on this try or an earlier one.
    left: bool,
    sent: bool,
}

impl UnverifiedSlot {
    /// Says a copy left. True the first time for this body, which is the one to report.
    fn body_left(&mut self) -> bool {
        !std::mem::replace(&mut self.left, true)
    }

    fn commit(mut self) {
        self.forwards
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .commit(&self.body);
        self.sent = true;
    }
}

impl Drop for UnverifiedSlot {
    fn drop(&mut self) {
        if self.sent {
            return;
        }
        let mut forwards = self.forwards.lock().unwrap_or_else(PoisonError::into_inner);
        if self.left {
            forwards.settle(&self.body, UnverifiedProgress::Owed);
        } else {
            forwards.release(&self.body);
        }
    }
}

/// Where a block stands, by its header hash.
enum ForwardState {
    /// Not forwarded, and no validated copy is being sent.
    Open,
    /// A validated copy is being sent; the receiver closes when that ends.
    InFlight(watch::Receiver<()>),
    /// Forwarded within the dedup window.
    Forwarded,
}

impl RecentForwardedHashes {
    fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            entries: std::collections::VecDeque::with_capacity(capacity.max(1)),
            in_flight: HashMap::new(),
            bodies_per_header: usize::MAX,
            sent_bodies: VecDeque::new(),
            sending_bodies: HashMap::new(),
        }
    }

    fn with_bodies_per_header(mut self, limit: usize) -> Self {
        self.bodies_per_header = limit;
        self
    }

    /// The bodies of `header` other than `key`.
    fn bodies_of(&mut self, header: &[u8; 32], key: &[u8; 32], now: std::time::Instant) -> usize {
        let window = self.window;
        self.sent_bodies
            .retain(|(_, _, sent)| now.duration_since(*sent) <= window);
        let sent = self.sent_bodies.iter();
        let sent = sent.filter(|(h, body, _)| h == header && body != key);
        let sending = self.sending_bodies.iter();
        let sending = sending.filter(|(body, h)| *h == header && *body != key);
        sent.count() + sending.count()
    }

    fn body_left(&mut self, header: [u8; 32], key: [u8; 32], now: std::time::Instant) {
        self.sending_bodies.remove(&key);
        self.sent_bodies.retain(|(_, body, _)| *body != key);
        self.sent_bodies.push_back((header, key, now));
    }

    fn state(&mut self, hash: &[u8; 32], now: std::time::Instant) -> ForwardState {
        if self.contains(hash, now) {
            return ForwardState::Forwarded;
        }
        match self.in_flight.get(hash) {
            Some(sender) => ForwardState::InFlight(sender.subscribe()),
            None => ForwardState::Open,
        }
    }

    fn contains(&mut self, hash: &[u8; 32], now: std::time::Instant) -> bool {
        self.evict_expired(now);
        self.entries.iter().any(|(h, _)| h == hash)
    }

    fn record(&mut self, hash: [u8; 32], now: std::time::Instant) {
        self.evict_expired(now);
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((hash, now));
    }

    fn evict_expired(&mut self, now: std::time::Instant) {
        while let Some((_, ts)) = self.entries.front() {
            if now.duration_since(*ts) > self.window {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

/// The right to send a validated block. Ending it any way but [`Self::commit`]
/// -- a send error, a cancelled caller, a panic -- reopens the block, and a copy
/// waiting on it sends instead of being deduplicated against a send that failed.
struct ForwardClaim {
    recent_forwarded: Arc<std::sync::Mutex<RecentForwardedHashes>>,
    /// What the record is kept by: the header, or the header and body. See [`RawWire`].
    key: [u8; 32],
    header_hash: [u8; 32],
}

impl ForwardClaim {
    /// A copy has gone, so the body has its place under its header, whatever becomes of the
    /// rest of the send. It stays open for its next delivery until [`Self::commit`].
    fn body_left(&self) {
        if let Ok(mut recent) = self.recent_forwarded.lock() {
            recent.body_left(self.header_hash, self.key, std::time::Instant::now());
        }
    }

    /// The block went out, so later copies of it are duplicates. For a bound copy that means
    /// encoded and taken by the socket, and a legacy copy need only be queued. Neither says
    /// anything arrived.
    fn commit(self) {
        let now = std::time::Instant::now();
        if let Ok(mut recent) = self.recent_forwarded.lock() {
            recent.record(self.key, now);
            recent.body_left(self.header_hash, self.key, now);
        }
    }
}

impl Drop for ForwardClaim {
    fn drop(&mut self) {
        // Runs after `commit` too, so a woken copy finds the block recorded. This
        // can run while unwinding, so a poisoned lock must not panic here.
        let mut recent = self
            .recent_forwarded
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        recent.in_flight.remove(&self.key);
        recent.sending_bodies.remove(&self.key);
    }
}

#[derive(Clone)]
struct ParsePermits {
    p2p: Arc<Semaphore>,
    pool: Arc<Semaphore>,
}

impl ParsePermits {
    fn new() -> Self {
        Self {
            p2p: Arc::new(Semaphore::new(P2P_PARSE_PERMITS)),
            pool: Arc::new(Semaphore::new(POOL_PARSE_PERMITS)),
        }
    }
}

/// What a forward sends, built away from the async workers.
struct PreparedForward {
    tx_count: usize,
    objects: PreparedObjects,
}

enum PreparedObjects {
    PreviouslySent,
    /// An unverified copy of this very body is going now.
    BeingSent(watch::Receiver<()>),
    /// The compact block does not fit the current FEC budget.
    RawSegments(Vec<RawBlockSegment>),
    Compact {
        skeleton: Option<CompactBlock>,
        compact: CompactBlock,
        compact_wire_bytes: usize,
        raw_fallback: Option<Vec<RawBlockSegment>>,
    },
    /// A body the reader could not read, under the emergency bypass. The Merkle and
    /// duplicate checks have not run on it.
    Unverified {
        segments: Vec<RawBlockSegment>,
        error: BlockBodyError,
        slot: UnverifiedSlot,
    },
}

/// How block events name a block from the pool gateway.
pub const POOL_GATEWAY_SOURCE: &str = "pool_gateway";

/// Where block events are reported, and the source they name.
#[derive(Clone)]
struct BlockLog {
    events: EventSink,
    source: String,
}

#[derive(Clone)]
pub struct RelayBridge {
    sender: BlockSender,
    data_shards: usize,
    parity_shards: usize,
    /// FEC chunker cached at construction: building the RS(224,32) codec is
    /// ~100ms of matrix math, far too expensive for the per-block hot path.
    chunker: Arc<BlockChunker>,
    compact_from_tx_cache: bool,
    /// Send a compact skeleton first (and redundantly) ahead of the full
    /// compact block. Only acts when `compact_from_tx_cache` is also on and a
    /// tx cache is supplied to `forward_block`.
    skeleton_first: bool,
    raw_fallback_with_tx_cache: bool,
    raw_segment_send_rounds: usize,
    raw_segment_round_delay: Duration,
    raw_wire: RawWire,
    /// Shared dedup ring for first-seen-wins forward suppression. Cloned
    /// bridges share the same state via `Arc`.
    recent_forwarded: Arc<std::sync::Mutex<RecentForwardedHashes>>,
    parse_permits: ParsePermits,
    block_body_rejections: Arc<BlockBodyRejections>,
    /// The easiest target a peer's header may state. `from_config` always sets
    /// it; only tests on synthetic headers leave it out.
    peer_pow_limit: Option<Target>,
    block_log: Option<BlockLog>,
    /// The operator's emergency bypass: an unreadable body behind a header with a
    /// real proof of work goes out unverified.
    forward_unreadable_blocks: bool,
    unverified_forwards: Arc<std::sync::Mutex<UnverifiedForwards>>,
}

impl RelayBridge {
    pub async fn from_config(config: &Config, events: EventSink) -> Result<Option<Self>> {
        if config.relay_peers.is_empty() {
            // Relay bridging is simply not configured -- distinct from a
            // misconfiguration where peers are set but the auth key is
            // missing (see below).
            if config.metrics_textfile.is_some() {
                warn!("Metrics textfile configured without a relay bridge; nothing will write it");
            }
            return Ok(None);
        }
        let Some(auth_key) = config.relay_auth_key else {
            // PR-0 removed the unauthenticated, no-HMAC version-1 wire
            // format. Silently disabling the bridge here used to leave an
            // operator who configured relay peers but forgot the auth key
            // with a relay that quietly never sent anything; fail loud
            // instead so the misconfiguration is caught at startup.
            return Err(IngressError::Config(
                "relay auth key required; unauthenticated mode removed \
                 (set SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX)"
                    .to_string(),
            ));
        };

        let mut client = Self::new_client_for_config(config, auth_key)?;
        client
            .bind()
            .await
            .map_err(|e| IngressError::Relay(e.to_string()))?;
        let sender = client.sender();
        let client = Arc::new(RwLock::new(client));
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(error) = client.run().await {
                warn!(%error, "Sovright relay client exited");
            }
        });
        info!(
            peers = config.relay_peers.len(),
            data_shards = config.relay_data_shards,
            parity_shards = config.relay_parity_shards,
            raw_segment_send_rounds = config.relay_raw_segment_send_rounds,
            raw_segment_round_delay_millis = config.relay_raw_segment_round_delay_millis,
            "Relay bridge enabled"
        );
        let block_body_rejections = Arc::new(BlockBodyRejections::default());
        if config.relay_forward_unreadable_blocks {
            warn!(
                bodies_per_header = config.relay_unreadable_bodies_per_header,
                "Emergency bypass on: bodies the reader cannot read are forwarded without \
                 the Merkle and duplicate checks. Only blocks in the mainnet target range \
                 qualify"
            );
            block_body_rejections.set_unverified_forward_enabled();
        }
        if let Some(path) = &config.metrics_textfile {
            spawn_metrics_textfile_writer(
                Arc::clone(&block_body_rejections),
                path.clone(),
                METRICS_WRITE_INTERVAL,
            );
        }
        Ok(Some(Self {
            sender,
            data_shards: config.relay_data_shards,
            parity_shards: config.relay_parity_shards,
            chunker: Arc::new(
                BlockChunker::new(config.relay_data_shards, config.relay_parity_shards)
                    .map_err(|e| IngressError::Relay(e.to_string()))?,
            ),
            compact_from_tx_cache: config.relay_compact_from_tx_cache,
            skeleton_first: config.relay_skeleton_first,
            raw_fallback_with_tx_cache: config.relay_raw_fallback_with_tx_cache,
            raw_segment_send_rounds: config.relay_raw_segment_send_rounds,
            raw_segment_round_delay: Duration::from_millis(
                config.relay_raw_segment_round_delay_millis,
            ),
            recent_forwarded: Arc::new(std::sync::Mutex::new(
                RecentForwardedHashes::new(
                    config.relay_forward_dedup_capacity,
                    config.relay_forward_dedup_window,
                )
                .with_bodies_per_header(config.relay_bodies_per_header),
            )),
            raw_wire: config.relay_raw_wire,
            parse_permits: ParsePermits::new(),
            block_body_rejections,
            peer_pow_limit: Some(config.network.pow_limit()),
            block_log: Some(BlockLog {
                events,
                source: POOL_GATEWAY_SOURCE.to_owned(),
            }),
            forward_unreadable_blocks: config.relay_forward_unreadable_blocks,
            unverified_forwards: Arc::new(std::sync::Mutex::new(
                UnverifiedForwards::new(
                    config.relay_forward_dedup_capacity,
                    config.relay_forward_dedup_window,
                    config.relay_unreadable_bodies_per_header,
                )
                .waiting_for_copies(config.relay_raw_wire.keys_by_body()),
            )),
        }))
    }

    #[cfg(test)]
    fn new_for_config(config: &Config) -> Result<Self> {
        let auth_key = config
            .relay_auth_key
            .ok_or_else(|| IngressError::Relay("missing relay auth key".to_string()))?;
        let client = Self::new_client_for_config(config, auth_key)?;
        let sender = client.sender();
        Ok(Self {
            sender,
            data_shards: config.relay_data_shards,
            parity_shards: config.relay_parity_shards,
            chunker: Arc::new(
                BlockChunker::new(config.relay_data_shards, config.relay_parity_shards)
                    .map_err(|e| IngressError::Relay(e.to_string()))?,
            ),
            compact_from_tx_cache: config.relay_compact_from_tx_cache,
            skeleton_first: config.relay_skeleton_first,
            raw_fallback_with_tx_cache: config.relay_raw_fallback_with_tx_cache,
            raw_segment_send_rounds: config.relay_raw_segment_send_rounds,
            raw_segment_round_delay: Duration::from_millis(
                config.relay_raw_segment_round_delay_millis,
            ),
            recent_forwarded: Arc::new(std::sync::Mutex::new(
                RecentForwardedHashes::new(
                    config.relay_forward_dedup_capacity,
                    config.relay_forward_dedup_window,
                )
                .with_bodies_per_header(config.relay_bodies_per_header),
            )),
            raw_wire: config.relay_raw_wire,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        })
    }

    fn new_client_for_config(config: &Config, auth_key: [u8; 32]) -> Result<RelayClient> {
        let client_config = ClientConfig::new(config.relay_peers.clone(), auth_key)
            .with_bind_addr(config.relay_bind_addr)
            .with_fec(config.relay_data_shards, config.relay_parity_shards)
            .with_adaptive_fec(config.relay_adaptive_fec)
            .with_send_pacing(
                config.relay_send_burst_packets,
                Duration::from_micros(config.relay_send_burst_delay_micros),
            )
            .with_auth_required(true);
        RelayClient::new(client_config).map_err(|e| IngressError::Relay(e.to_string()))
    }

    /// This handle, naming `source` in its block events. The bridge as built names
    /// the pool gateway; each peer takes a handle of its own.
    pub fn logging_block_events(mut self, events: EventSink, source: &str) -> Self {
        self.block_log = Some(BlockLog {
            events,
            source: source.to_owned(),
        });
        self
    }

    #[cfg(test)]
    pub(crate) fn block_body_rejections(&self) -> &BlockBodyRejections {
        &self.block_body_rejections
    }

    /// Forward a block a P2P peer delivered.
    pub async fn forward_block(
        &self,
        block_payload: &[u8],
        tx_cache: Option<&TxCache>,
    ) -> Result<ForwardedBlock> {
        self.forward_with_permits(
            block_payload,
            tx_cache,
            &self.parse_permits.p2p,
            self.peer_pow_limit.as_ref(),
        )
        .await
    }

    /// Forward a block from the pool gateway, which checks the target itself.
    pub async fn forward_pool_block(
        &self,
        block_payload: &[u8],
        tx_cache: Option<&TxCache>,
    ) -> Result<ForwardedBlock> {
        self.forward_with_permits(block_payload, tx_cache, &self.parse_permits.pool, None)
            .await
    }

    async fn forward_with_permits(
        &self,
        block_payload: &[u8],
        tx_cache: Option<&TxCache>,
        permits: &Arc<Semaphore>,
        pow_limit: Option<&Target>,
    ) -> Result<ForwardedBlock> {
        let outcome = self
            .validate_and_forward(block_payload, tx_cache, permits, pow_limit)
            .await;
        if let Err(IngressError::InvalidBlockBody(error)) = &outcome {
            self.block_body_rejections.record(error);
        }
        outcome
    }

    async fn validate_and_forward(
        &self,
        block_payload: &[u8],
        tx_cache: Option<&TxCache>,
        permits: &Arc<Semaphore>,
        pow_limit: Option<&Target>,
    ) -> Result<ForwardedBlock> {
        // Before anything waits or copies the payload.
        if block_payload.len() > MAX_BLOCK_BYTES {
            return Err(IngressError::InvalidBlockBody(BlockBodyError::TooLarge {
                bytes: block_payload.len(),
            }));
        }
        let header =
            block_payload
                .get(..ZCASH_FULL_HEADER_SIZE)
                .ok_or(IngressError::InvalidBlockBody(
                    BlockBodyError::InvalidHeaderLength,
                ))?;

        // One hash, so a made-up header never reaches a parse permit. This is an
        // anti-garbage check, not proof of work: the sender picks nBits, the
        // solution is not verified, and a real header reused with another body
        // passes it.
        if let Some(pow_limit) = pow_limit
            && header_meets_stated_target(header, pow_limit) != TargetCheck::Met
        {
            return Err(IngressError::InvalidBlockBody(BlockBodyError::HeaderTarget));
        }

        // First-seen-wins dedup. Under steady state multiple Zcash P2P peers
        // deliver the same block within the same few hundred milliseconds.
        // Without this check each delivery re-encodes and re-broadcasts the
        // block into the relay mesh, multiplying mesh traffic for no benefit.
        // The decision is recorded on successful broadcast so a half-failed
        // forward can be retried by the next delivery.
        let header_hash = zcash_block_hash(header);
        let forward_key = self
            .forward_key(&header_hash, block_payload, permits)
            .await?;
        let deduplicated = || ForwardedBlock {
            tx_count: declared_tx_count(block_payload),
            bytes: 0,
            relay_objects: 0,
            mode: ForwardMode::Deduplicated,
        };

        // After the dedup check, so a known header costs no parsing and a bad copy
        // of one is skipped unsent; before any send, so a body that fails is
        // neither forwarded nor recorded and cannot hide a good copy.
        let (prepared, permit) = loop {
            if self.wait_for_forward(&forward_key).await {
                return Ok(deduplicated());
            }
            let permit = Arc::clone(permits)
                .acquire_owned()
                .await
                .expect("parse permits are never closed");
            // A copy ahead in the queue may have settled this block meanwhile.
            if matches!(self.forward_state(&forward_key), ForwardState::Open) {
                match self
                    .prepare_off_workers(block_payload, tx_cache, permit)
                    .await?
                {
                    (
                        PreparedForward {
                            objects: PreparedObjects::BeingSent(mut sending),
                            ..
                        },
                        permit,
                    ) => {
                        drop(permit);
                        let _ = sending.changed().await;
                    }
                    ready => break ready,
                }
            }
        };

        let prepared = match prepared {
            PreparedForward {
                objects: PreparedObjects::PreviouslySent,
                ..
            } => return Ok(deduplicated()),
            PreparedForward {
                tx_count,
                objects:
                    PreparedObjects::Unverified {
                        segments,
                        error,
                        mut slot,
                    },
            } => {
                drop(permit);
                let raw_wire_bytes = self.raw_segments_wire_bytes(&segments);
                // What this record bounds and reports is what left without its checks, so a
                // legacy copy counts then, whatever becomes of the bound one.
                let report = |slot: &mut UnverifiedSlot| {
                    if slot.body_left() {
                        self.log_unverified_forward(header, &error, block_payload.len());
                    }
                };
                let legacy = async {
                    let relay_objects = self.send_raw_block_segments(&segments).await?;
                    if relay_objects > 0 {
                        report(&mut slot);
                    }
                    Ok(relay_objects)
                };
                let relay_objects = self.with_bound_copy(block_payload, legacy).await?;
                report(&mut slot);
                slot.commit();
                return Ok(ForwardedBlock {
                    tx_count,
                    bytes: raw_wire_bytes,
                    relay_objects,
                    mode: ForwardMode::RawBlockSegmentsUnverified,
                });
            }
            other => other,
        };

        // Only a validated body claims the block, and a copy that lost the race
        // keeps what it prepared until the winner's send has really gone out. The
        // permit is given up with the first attempt: the next copy in the queue
        // then finds this claim, rather than an open block to parse again.
        let Some(claim) = self.claim_forward(forward_key, header_hash, permit).await? else {
            return Ok(deduplicated());
        };
        let legacy = async {
            let forwarded = self.send_prepared(prepared).await?;
            if forwarded.relay_objects > 0 {
                claim.body_left();
            }
            Ok(forwarded)
        };
        let forwarded = self.with_bound_copy(block_payload, legacy).await?;
        claim.commit();
        Ok(forwarded)
    }

    /// What a forward is deduplicated by. See [`RawWire`]. Hashing the body takes a parse
    /// permit and the blocking pool, as anything else that reads a whole body here does.
    async fn forward_key(
        &self,
        header_hash: &[u8; 32],
        block_payload: &[u8],
        permits: &Arc<Semaphore>,
    ) -> Result<[u8; 32]> {
        if !self.raw_wire.keys_by_body() {
            return Ok(*header_hash);
        }
        let permit = Arc::clone(permits)
            .acquire_owned()
            .await
            .expect("parse permits are never closed");
        let (block, header_hash) = (block_payload.to_vec(), *header_hash);
        let (key, _permit) = run_holding_permit(permit, move || {
            let mut digest = Sha256::new();
            digest.update(header_hash);
            digest.update(&block);
            <[u8; 32]>::from(digest.finalize())
        })
        .await
        .map_err(|error| IngressError::Relay(format!("body hash failed: {error}")))?;
        Ok(key)
    }

    /// Sends the legacy copy and the bound copy side by side. Neither waits for the other or
    /// stops it, so a bound copy that fails or takes its time leaves the legacy one alone, and
    /// a slow legacy copy cannot stop a bound one from being taken before a caller gives up.
    /// The result says whether both went, so a body whose bound copy failed stays open, and
    /// its next delivery sends both again, which repeats the legacy copy.
    async fn with_bound_copy<T>(
        &self,
        block_payload: &[u8],
        legacy: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let (legacy, bound) = tokio::join!(legacy, self.send_bound_copy(block_payload));
        let legacy = legacy?;
        bound?;
        Ok(legacy)
    }

    /// The bound copy of a body that is going out, if this ingress sends one, as far as this
    /// client can tell: see [`BlockSender::send_bound_raw_block`].
    async fn send_bound_copy(&self, block_payload: &[u8]) -> Result<()> {
        if self.raw_wire == RawWire::Legacy {
            return Ok(());
        }
        self.sender
            .send_bound_raw_block(Arc::new(block_payload.to_vec()))
            .await
            .map_err(map_transport_error)
    }

    /// Reported once a body has parsed, so nothing about the send can lose it, and
    /// on the blocking pool with the parse. Best effort: a validated block goes out
    /// whether or not this line does.
    fn log_coinbase(&self, header: &[u8], coinbase: &CoinbaseTelemetry) {
        let Some(log) = &self.block_log else {
            return;
        };
        let hash = inventory_hash_to_display(&zcash_block_hash(header));
        let consensus_hash = consensus_block_hash_display(header);
        if let Err(error) =
            log.events
                .p2p_block_coinbase(&log.source, &hash, &consensus_hash, coinbase)
        {
            warn!(%error, %consensus_hash, "Failed to write the coinbase event");
        }
    }

    /// The Merkle and duplicate checks did not run on this body; the size, header and
    /// proof-of-work checks did. Best effort, like the coinbase line, but the counter
    /// and the warning do not depend on the log.
    fn log_unverified_forward(&self, header: &[u8], error: &BlockBodyError, bytes: usize) {
        self.block_body_rejections.record_unverified_forward();
        let consensus_hash = consensus_block_hash_display(header);
        warn!(
            %consensus_hash,
            reason = error.label(),
            bytes,
            checks_run = "size,header,proof_of_work",
            checks_skipped = "merkle,duplicate_txid",
            "Forwarded a block body without the Merkle and duplicate checks"
        );
        let Some(log) = &self.block_log else {
            return;
        };
        let hash = inventory_hash_to_display(&zcash_block_hash(header));
        if let Err(write_error) = log.events.p2p_block_unverified_forwarded(
            &log.source,
            &hash,
            &consensus_hash,
            error,
            bytes,
        ) {
            warn!(%write_error, %consensus_hash, "Failed to write the unverified forward event");
        }
    }

    fn forward_state(&self, header_hash: &[u8; 32]) -> ForwardState {
        self.recent_forwarded
            .lock()
            .expect("recent_forwarded mutex poisoned")
            .state(header_hash, std::time::Instant::now())
    }

    /// Wait out any send of this block in progress. True if it was forwarded,
    /// false if it is open, as it is again after a send that did not finish.
    async fn wait_for_forward(&self, header_hash: &[u8; 32]) -> bool {
        loop {
            match self.forward_state(header_hash) {
                ForwardState::Open => return false,
                ForwardState::Forwarded => return true,
                ForwardState::InFlight(mut sending) => {
                    let _ = sending.changed().await;
                }
            }
        }
    }

    /// Claim a validated block, waiting out any send in progress without holding
    /// `permit`. `None` if it was forwarded, and an error if its header has sent all the
    /// bodies it may. That fails closed, so the real body can be the one turned away.
    async fn claim_forward(
        &self,
        forward_key: [u8; 32],
        header_hash: [u8; 32],
        permit: OwnedSemaphorePermit,
    ) -> Result<Option<ForwardClaim>> {
        let mut permit = Some(permit);
        loop {
            let state = {
                let mut recent = self
                    .recent_forwarded
                    .lock()
                    .expect("recent_forwarded mutex poisoned");
                let now = std::time::Instant::now();
                let state = recent.state(&forward_key, now);
                if matches!(state, ForwardState::Open) {
                    let others = recent.bodies_of(&header_hash, &forward_key, now);
                    if others >= recent.bodies_per_header {
                        return Err(IngressError::Relay(
                            "this header has sent all the bodies it may".to_string(),
                        ));
                    }
                    recent.in_flight.insert(forward_key, watch::channel(()).0);
                    recent.sending_bodies.insert(forward_key, header_hash);
                }
                state
            };
            drop(permit.take());
            match state {
                ForwardState::Open => {
                    return Ok(Some(ForwardClaim {
                        recent_forwarded: Arc::clone(&self.recent_forwarded),
                        key: forward_key,
                        header_hash,
                    }));
                }
                ForwardState::Forwarded => return Ok(None),
                ForwardState::InFlight(mut sending) => {
                    let _ = sending.changed().await;
                }
            }
        }
    }

    async fn prepare_off_workers(
        &self,
        block_payload: &[u8],
        tx_cache: Option<&TxCache>,
        permit: OwnedSemaphorePermit,
    ) -> Result<(PreparedForward, OwnedSemaphorePermit)> {
        let bridge = self.clone();
        let block = block_payload.to_vec();
        let tx_cache = tx_cache.cloned();
        let (prepared, permit) = run_holding_permit(permit, move || {
            bridge.prepare_forward(block, tx_cache.as_ref())
        })
        .await
        .map_err(|error| IngressError::Relay(format!("block preparation failed: {error}")))?;
        Ok((prepared?, permit))
    }

    /// Validate a block and build everything that will be sent for it. Everything
    /// is read from the parsed block, so it is what the reader checked.
    fn prepare_forward(
        &self,
        block: Vec<u8>,
        tx_cache: Option<&TxCache>,
    ) -> Result<PreparedForward> {
        // Hash on the bounded blocking pool, not a Tokio worker. A committed
        // identical body may be skipped; in-flight copies are never treated as sent.
        if self.forward_unreadable_blocks {
            let body = UnverifiedBody {
                header_hash: zcash_block_hash(&block[..ZCASH_FULL_HEADER_SIZE]),
                digest: Sha256::digest(&block).into(),
            };
            if self
                .unverified_forwards
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .sent(&body)
            {
                return Ok(PreparedForward {
                    tx_count: declared_tx_count(&block),
                    objects: PreparedObjects::PreviouslySent,
                });
            }
        }
        // Copied only under the bypass, the one case that needs the bytes after the
        // reader has failed.
        let fallback = self.forward_unreadable_blocks.then(|| block.clone());
        let parsed = match parse_block_body(block) {
            Ok(parsed) => parsed,
            Err(error) => return self.prepare_unreadable(error, fallback),
        };
        self.log_coinbase(parsed.header(), &CoinbaseTelemetry::of(parsed.coinbase()));
        let tx_cache = tx_cache.filter(|_| self.compact_from_tx_cache);
        let compact = match tx_cache {
            Some(tx_cache) => compact_block_from_parsed_with_tx_cache(&parsed, tx_cache)?,
            None => compact_block_from_parsed(&parsed)?,
        };
        let tx_count = compact.tx_count();
        let block_hash = *compact.header_hash().as_bytes();

        if let Err(error) = self.preflight_chunks(&compact) {
            let text = error.to_string();
            if text.contains("all-prefilled compact block too large") {
                let segments = self.raw_block_segments(block_hash, parsed.raw_block())?;
                return Ok(PreparedForward {
                    tx_count,
                    objects: PreparedObjects::RawSegments(segments),
                });
            }
            return Err(self.with_segment_plan(error, &compact, parsed.raw_block()));
        }
        // Skeleton fast path: emit the reconstruction-critical skeleton first
        // (and with heavier FEC parity) so a receiver that already holds the
        // block's transactions reconstructs and submits before the FEC'd compact
        // bodies arrive. The full compact block is the push fallback, so it is
        // ALWAYS sent afterward -- the skeleton never suppresses it. Only
        // meaningful with tx-cache compaction (short_id compact blocks).
        let skeleton = tx_cache
            .filter(|_| self.skeleton_first)
            .and_then(|tx_cache| {
                match skeleton_compact_block_from_parsed(&parsed, tx_cache) {
                    Ok(skeleton) => {
                        // Small-block guard: the skeleton is only worth an extra
                        // redundant, heavier-parity early copy when (a) it carries
                        // short_ids a receiver can resolve from its own mempool --
                        // an all-prefilled skeleton reconstructs from nothing, so
                        // it would only ever duplicate the full block -- and (b) it
                        // is small enough that the duplicate send is cheap. Oversized
                        // / cold-cache (large-prefill) blocks are left to the full
                        // compact block alone.
                        let skeleton_bytes = BlockChunker::serialize_compact_block(&skeleton).len();
                        (!skeleton.short_ids.is_empty()
                            && skeleton_bytes <= SKELETON_MAX_WIRE_BYTES)
                            .then_some(skeleton)
                    }
                    Err(error) => {
                        warn!(%error, "Failed to build compact skeleton; sending full compact block only");
                        None
                    }
                }
            });
        let raw_fallback = if self.raw_fallback_with_tx_cache
            && self.compact_from_tx_cache
            && !compact.short_ids.is_empty()
        {
            Some(self.raw_block_segments(block_hash, parsed.raw_block())?)
        } else {
            None
        };
        // Wire size of the compact object as serialized for the relay. The
        // event's bytes field reports what is actually sent per mode (0 for
        // deduplicated), NOT the full block size -- downstream consumers
        // compare it against p2p_block_received bytes to measure savings.
        let compact_wire_bytes = BlockChunker::serialize_compact_block(&compact).len();
        Ok(PreparedForward {
            tx_count,
            objects: PreparedObjects::Compact {
                skeleton,
                compact,
                compact_wire_bytes,
                raw_fallback,
            },
        })
    }

    /// The emergency bypass. Only `Transaction` qualifies: the reader stopped, so
    /// nothing is known against the body. Every other reason is a finding about the
    /// body and stays refused. No check here says the body belongs to its header, so
    /// the header has to show a real proof of work; Zebra decides the rest.
    ///
    /// This runs on the blocking pool under the parse permit. The proof-of-work check
    /// is the relay node's, so it covers the mainnet target range on either network:
    /// a testnet minimum-difficulty block would stop at the first relay anyway.
    fn prepare_unreadable(
        &self,
        error: BlockBodyError,
        fallback: Option<Vec<u8>>,
    ) -> Result<PreparedForward> {
        let refused = IngressError::InvalidBlockBody(error);
        let (BlockBodyError::Transaction { .. }, Some(block)) = (error, fallback) else {
            return Err(refused);
        };
        let header = &block[..ZCASH_FULL_HEADER_SIZE];
        // Reserve only after parsing has established an unreadable body. Doing it
        // before parsing could hide a valid body sharing this header.
        let body = UnverifiedBody {
            header_hash: zcash_block_hash(header),
            digest: Sha256::digest(&block).into(),
        };
        let reservation = self
            .unverified_forwards
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserve(body, std::time::Instant::now());
        let elsewhere = |objects| {
            Ok(PreparedForward {
                tx_count: declared_tx_count(&block),
                objects,
            })
        };
        let left = match reservation {
            UnverifiedReservation::Reserved => false,
            UnverifiedReservation::Owed => true,
            UnverifiedReservation::Sending(sending) => {
                return elsewhere(PreparedObjects::BeingSent(sending));
            }
            UnverifiedReservation::Repeat => return elsewhere(PreparedObjects::PreviouslySent),
            UnverifiedReservation::HeaderFull => return Err(refused),
        };
        let slot = UnverifiedSlot {
            forwards: Arc::clone(&self.unverified_forwards),
            body,
            left,
            sent: false,
        };
        if EquihashPowValidator.validate(header) != PowResult::Valid {
            return Err(refused);
        }
        let segments = self.raw_block_segments(zcash_block_hash(header), &block)?;
        Ok(PreparedForward {
            tx_count: declared_tx_count(&block),
            objects: PreparedObjects::Unverified {
                segments,
                error,
                slot,
            },
        })
    }

    async fn send_prepared(&self, prepared: PreparedForward) -> Result<ForwardedBlock> {
        let PreparedForward { tx_count, objects } = prepared;
        let (compact_wire_bytes, raw_fallback) = match objects {
            PreparedObjects::PreviouslySent | PreparedObjects::BeingSent(_) => {
                unreachable!("dedup handled before sending")
            }
            PreparedObjects::Unverified { segments, .. } => {
                let raw_wire_bytes = self.raw_segments_wire_bytes(&segments);
                let relay_objects = self.send_raw_block_segments(&segments).await?;
                return Ok(ForwardedBlock {
                    tx_count,
                    bytes: raw_wire_bytes,
                    relay_objects,
                    mode: ForwardMode::RawBlockSegmentsUnverified,
                });
            }
            PreparedObjects::RawSegments(segments) => {
                let raw_wire_bytes = self.raw_segments_wire_bytes(&segments);
                let relay_objects = self.send_raw_block_segments(&segments).await?;
                return Ok(ForwardedBlock {
                    tx_count,
                    bytes: raw_wire_bytes,
                    relay_objects,
                    mode: ForwardMode::RawBlockSegments,
                });
            }
            PreparedObjects::Compact {
                skeleton,
                compact,
                compact_wire_bytes,
                raw_fallback,
            } => {
                if let Some(skeleton) = skeleton {
                    self.sender
                        .send_skeleton(skeleton)
                        .await
                        .map_err(map_transport_error)?;
                }
                self.sender
                    .send(compact)
                    .await
                    .map_err(map_transport_error)?;
                (compact_wire_bytes, raw_fallback)
            }
        };
        let Some(segments) = raw_fallback else {
            return Ok(ForwardedBlock {
                tx_count,
                bytes: compact_wire_bytes,
                relay_objects: 1,
                mode: ForwardMode::CompactBlock,
            });
        };
        let raw_wire_bytes = self.raw_segments_wire_bytes(&segments);
        let raw_segment_relay_objects = self.send_raw_block_segments(&segments).await?;
        Ok(ForwardedBlock {
            tx_count,
            bytes: compact_wire_bytes + raw_wire_bytes,
            relay_objects: raw_segment_relay_objects + 1,
            mode: ForwardMode::CompactBlockWithRawFallback,
        })
    }

    fn with_segment_plan(
        &self,
        error: IngressError,
        compact: &CompactBlock,
        block_payload: &[u8],
    ) -> IngressError {
        let text = error.to_string();
        if !text.contains("all-prefilled compact block too large") {
            return error;
        }
        match self.plan_raw_block_segments(*compact.header_hash().as_bytes(), block_payload) {
            Ok(plan) => IngressError::Relay(format!(
                "{text}; segmented raw block plan: segments={} object_bytes={} max_segment_frame_bytes={}",
                plan.segment_count, plan.object_bytes, plan.max_segment_frame_bytes
            )),
            Err(plan_error) => IngressError::Relay(format!(
                "{text}; segmented raw block plan unavailable: {plan_error}"
            )),
        }
    }

    fn preflight_chunks(&self, compact: &CompactBlock) -> Result<()> {
        let block_hash = compact.header_hash();
        let serialized_len = BlockChunker::serialize_compact_block(compact).len();
        let max_data_bytes = self.data_shards.saturating_mul(MAX_PAYLOAD_SIZE);
        if serialized_len > max_data_bytes {
            return Err(IngressError::Relay(format!(
                "all-prefilled compact block too large for current relay frame budget: \
                 serialized_bytes={serialized_len} max_data_bytes={max_data_bytes} \
                 data_shards={} parity_shards={} max_payload={MAX_PAYLOAD_SIZE}; \
                 production full-block relay needs compact reconstruction or segmented object framing",
                self.data_shards, self.parity_shards
            )));
        }
        self.chunker
            .compact_block_to_chunks(compact, block_hash.as_bytes())
            .map(|_| ())
            .map_err(|e| IngressError::Relay(e.to_string()))
    }

    fn plan_raw_block_segments(
        &self,
        block_hash: [u8; 32],
        block_payload: &[u8],
    ) -> Result<RawBlockSegmentPlan> {
        let max_segment_frame_bytes = self.raw_segment_frame_budget();
        let segments = split_raw_block(block_hash, block_payload, max_segment_frame_bytes)
            .map_err(|e| IngressError::Relay(e.to_string()))?;
        Ok(RawBlockSegmentPlan {
            segment_count: segments.len(),
            object_bytes: block_payload.len(),
            max_segment_frame_bytes,
        })
    }

    fn raw_block_segments(
        &self,
        block_hash: [u8; 32],
        block_payload: &[u8],
    ) -> Result<Vec<sovright_relay::RawBlockSegment>> {
        let max_segment_frame_bytes = self.raw_segment_frame_budget();
        split_raw_block(block_hash, block_payload, max_segment_frame_bytes)
            .map_err(|e| IngressError::Relay(e.to_string()))
    }

    fn raw_segment_frame_budget(&self) -> usize {
        self.data_shards
            .saturating_mul(MAX_PAYLOAD_SIZE)
            .saturating_sub(RELAY_LEN_PREFIX_BYTES)
    }

    fn raw_segments_wire_bytes(&self, segments: &[RawBlockSegment]) -> usize {
        segments.iter().map(|s| s.encoded_len()).sum::<usize>() * self.raw_segment_send_rounds
    }

    async fn send_raw_block_segments(&self, segments: &[RawBlockSegment]) -> Result<usize> {
        if self.raw_wire == RawWire::Bound {
            return Ok(0);
        }
        let mut relay_objects = 0;
        for round in 0..self.raw_segment_send_rounds {
            for segment in segments {
                self.sender
                    .send_raw_block_segment(segment.clone())
                    .await
                    .map_err(map_transport_error)?;
                relay_objects += 1;
            }
            if round + 1 < self.raw_segment_send_rounds && !self.raw_segment_round_delay.is_zero() {
                sleep(self.raw_segment_round_delay).await;
            }
        }
        Ok(relay_objects)
    }
}

/// Run `work` on the blocking pool and hand `permit` back with its result.
/// Dropping the returned future does not stop blocking work, so the permit goes
/// with the work and not with the caller: with no caller left it ends with the
/// work, and a panic in the work releases it too.
pub(crate) async fn run_holding_permit<T, P>(
    permit: P,
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<(T, P), JoinError>
where
    T: Send + 'static,
    P: Send + 'static,
{
    tokio::task::spawn_blocking(move || (work(), permit)).await
}

/// The transaction count a block declares, read without parsing its body, for
/// reporting a delivery that was deduplicated. 0 if the count cannot be read.
fn declared_tx_count(block_payload: &[u8]) -> usize {
    let mut cursor = ZCASH_FULL_HEADER_SIZE;
    decode_compact_size(block_payload, &mut cursor).map_or(0, |count| count as usize)
}

pub struct ForwardedBlock {
    pub tx_count: usize,
    pub bytes: usize,
    pub relay_objects: usize,
    pub mode: ForwardMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardMode {
    CompactBlock,
    CompactBlockWithRawFallback,
    RawBlockSegments,
    /// A body the reader could not read, sent under the emergency bypass. The Merkle
    /// and duplicate checks did not run. This is the sender's local knowledge: the
    /// segments on the wire look like any others.
    RawBlockSegmentsUnverified,
    /// First-seen-wins dedup: this block hash was already forwarded within
    /// the dedup window, so the bridge skipped encoding and broadcast.
    /// `ForwardedBlock.relay_objects` is 0 in this case.
    Deduplicated,
}

impl ForwardMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardMode::CompactBlock => "compact_block",
            ForwardMode::CompactBlockWithRawFallback => "compact_block_with_raw_fallback",
            ForwardMode::RawBlockSegments => "raw_block_segments",
            ForwardMode::RawBlockSegmentsUnverified => "raw_block_segments_unverified",
            ForwardMode::Deduplicated => "deduplicated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawBlockSegmentPlan {
    segment_count: usize,
    object_bytes: usize,
    max_segment_frame_bytes: usize,
}

fn map_transport_error(error: TransportError) -> IngressError {
    IngressError::Relay(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_cache::{TxCacheConfig, TxInventoryKey};
    use sovright_relay::{
        PrefilledTx, RawBlockSegment, RelayPayload, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn bridge_with_default_fec() -> RelayBridge {
        let config = ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();
        RelayBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        }
    }

    fn minimal_v1_tx(tag: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        crate::wire::encode_compact_size(0, &mut tx);
        crate::wire::encode_compact_size(0, &mut tx);
        tx.extend_from_slice(&(tag as u32).to_le_bytes());
        tx
    }

    fn two_tx_raw_block() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let tx0 = minimal_v1_tx(0x11);
        let tx1 = minimal_v1_tx(0x22);
        let mut block =
            sovright_relay::test_support::committed_header(0xab, &[tx0.clone(), tx1.clone()]);
        crate::wire::encode_compact_size(2, &mut block);
        block.extend_from_slice(&tx0);
        block.extend_from_slice(&tx1);
        (block, tx0, tx1)
    }

    fn large_raw_block() -> Vec<u8> {
        let txs: Vec<Vec<u8>> = (0..2_000u32)
            .map(|lock_time| {
                let mut tx = minimal_v1_tx(0);
                tx[6..10].copy_from_slice(&lock_time.to_le_bytes());
                tx
            })
            .collect();
        let header = sovright_relay::test_support::committed_header(0xab, &txs);
        sovright_relay::test_support::raw_block(&header, &txs)
    }

    #[tokio::test]
    async fn forward_block_reuses_cached_fec_codec() {
        // Building the production RS(224,32) codec is ~100ms of matrix
        // construction. Rebuilding it inside every forward put a flat ~150ms
        // on the relay's critical path per block (measured in production
        // 2026-07-01), spending the relay's entire inter-region head start.
        // Forwarding several distinct blocks must therefore be decisively
        // cheaper than rebuilding the codec once per block.
        let client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let bridge = RelayBridge {
            sender: client.sender(),
            data_shards: 224,
            parity_shards: 32,
            chunker: Arc::new(BlockChunker::new(224, 32).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };

        let t = std::time::Instant::now();
        let _codec = BlockChunker::new(224, 32).unwrap();
        let codec_build = t.elapsed();

        let mut blocks = Vec::new();
        for tag in 0u8..6 {
            let tx = minimal_v1_tx(tag);
            let mut block = vec![0xab; ZCASH_FULL_HEADER_SIZE];
            block[0] = tag; // distinct hash per block so dedup never triggers
            sovright_relay::test_support::commit_header(&mut block, std::slice::from_ref(&tx));
            crate::wire::encode_compact_size(1, &mut block);
            block.extend_from_slice(&tx);
            blocks.push(block);
        }

        // Warm-up forward absorbs any one-time lazy initialization.
        bridge.forward_block(&blocks[0], None).await.unwrap();

        let t = std::time::Instant::now();
        for block in &blocks[1..] {
            let forwarded = bridge.forward_block(block, None).await.unwrap();
            assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
        }
        let five_forwards = t.elapsed();

        assert!(
            five_forwards < codec_build.max(Duration::from_millis(5)) * 3,
            "5 forwards took {five_forwards:?} vs codec build {codec_build:?}; \
             the FEC codec is being rebuilt per forwarded block"
        );
    }

    #[tokio::test]
    async fn forwarded_bytes_report_wire_bytes_per_mode() {
        // The bytes field previously logged block_payload.len() for every
        // mode, so downstream wire-vs-full comparisons (dashboard bytes card,
        // 24h fullness panel) compared full-to-full by construction. It must
        // report what was actually handed to the relay per mode.
        let (raw_block, tx0, tx1) = two_tx_raw_block();
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_tx_bytes: 512,
        });
        cache.insert(TxInventoryKey::wtx([0x31; 32], [0x41; 32]).to_wtxid(), tx0);
        cache.insert(TxInventoryKey::wtx([0x32; 32], [0x42; 32]).to_wtxid(), tx1);

        let client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let bridge = RelayBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };

        let forwarded = bridge
            .forward_block(&raw_block, Some(&cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
        let compact =
            crate::block::compact_block_from_raw_block_with_tx_cache(&raw_block, &cache).unwrap();
        let compact_wire = BlockChunker::serialize_compact_block(&compact).len();
        assert_eq!(forwarded.bytes, compact_wire);

        // Dedup suppresses the send entirely: nothing goes on the wire.
        let forwarded = bridge
            .forward_block(&raw_block, Some(&cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::Deduplicated);
        assert_eq!(forwarded.bytes, 0);
    }

    #[tokio::test]
    async fn forwarded_bytes_count_raw_fallback_segments_and_rounds() {
        let (raw_block, tx0, tx1) = two_tx_raw_block();
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_tx_bytes: 512,
        });
        cache.insert(TxInventoryKey::wtx([0x33; 32], [0x43; 32]).to_wtxid(), tx0);
        cache.insert(TxInventoryKey::wtx([0x34; 32], [0x44; 32]).to_wtxid(), tx1);

        let client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let bridge = RelayBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: true,
            raw_segment_send_rounds: 2,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };

        let forwarded = bridge
            .forward_block(&raw_block, Some(&cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlockWithRawFallback);
        let compact =
            crate::block::compact_block_from_raw_block_with_tx_cache(&raw_block, &cache).unwrap();
        let compact_wire = BlockChunker::serialize_compact_block(&compact).len();
        let segments = bridge
            .plan_raw_block_segments(*compact.header_hash().as_bytes(), &raw_block)
            .map(|plan| {
                split_raw_block(
                    *compact.header_hash().as_bytes(),
                    &raw_block,
                    plan.max_segment_frame_bytes,
                )
                .unwrap()
            })
            .unwrap();
        let raw_wire: usize = segments.iter().map(|s| s.encoded_len()).sum();
        assert_eq!(forwarded.bytes, compact_wire + raw_wire * 2);
    }

    #[test]
    fn preflight_reports_all_prefilled_frame_budget_for_large_blocks() {
        let compact = CompactBlock::new(
            vec![0xab; ZCASH_FULL_HEADER_SIZE],
            0,
            Vec::new(),
            vec![PrefilledTx {
                index: 0,
                tx_data: vec![0xcd; 20_000],
            }],
        );

        let err = bridge_with_default_fec()
            .preflight_chunks(&compact)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("all-prefilled compact block too large"),
            "{err}"
        );
        assert!(err.to_string().contains("data_shards=10"), "{err}");
    }

    #[test]
    fn raw_block_segment_plan_uses_current_fec_budget() {
        let bridge = bridge_with_default_fec();
        let raw_block = vec![0xab; 25_000];
        let block_hash = [0x42; 32];

        let plan = bridge
            .plan_raw_block_segments(block_hash, &raw_block)
            .unwrap();
        let segments =
            split_raw_block(block_hash, &raw_block, plan.max_segment_frame_bytes).unwrap();
        let reassembled = reassemble_raw_block(&segments).unwrap();

        assert_eq!(plan.object_bytes, raw_block.len());
        assert!(plan.segment_count > 1);
        assert!(
            segments
                .iter()
                .all(|segment: &RawBlockSegment| segment.encoded_len()
                    <= plan.max_segment_frame_bytes)
        );
        let chunker = BlockChunker::new(bridge.data_shards, bridge.parity_shards).unwrap();
        for segment in &segments {
            chunker.raw_block_segment_to_chunks(segment).unwrap();
        }
        assert_eq!(reassembled, raw_block);
    }

    #[tokio::test]
    async fn forwards_raw_block_segments_when_compact_exceeds_current_fec_budget() {
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };
        let raw_block = large_raw_block();

        let forwarded = bridge.forward_block(&raw_block, None).await.unwrap();

        assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
        assert!(forwarded.relay_objects > 1);

        let mut segments = Vec::new();
        for _ in 0..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected raw block segment, got {other:?}"),
            }
        }

        let reassembled = reassemble_raw_block(&segments).unwrap();
        assert_eq!(reassembled, raw_block);
    }

    #[tokio::test]
    async fn configured_raw_segment_send_rounds_retransmit_each_segment() {
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 3,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };
        let raw_block = large_raw_block();

        let forwarded = bridge.forward_block(&raw_block, None).await.unwrap();

        assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
        assert_eq!(forwarded.relay_objects % 3, 0);
        let segments_per_round = forwarded.relay_objects / 3;
        assert!(segments_per_round > 1);

        let mut segments = Vec::new();
        for _ in 0..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected raw block segment, got {other:?}"),
            }
        }

        for round in segments.chunks_exact(segments_per_round) {
            assert_eq!(reassemble_raw_block(round).unwrap(), raw_block);
        }
    }

    #[tokio::test]
    async fn tx_cache_compact_forwarding_can_send_raw_fallback_segments() {
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: true,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };
        let (raw_block, _tx0, tx1) = two_tx_raw_block();
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        tx_cache.insert(TxInventoryKey::wtx([0x41; 32], [0x42; 32]).to_wtxid(), tx1);

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();

        assert_eq!(forwarded.mode, ForwardMode::CompactBlockWithRawFallback);
        assert!(forwarded.relay_objects > 1);

        let first = outgoing.recv().await.expect("compact block queued");
        match first {
            RelayPayload::CompactBlock(compact) => {
                assert_eq!(compact.tx_count(), 2);
                assert_eq!(compact.short_ids.len(), 1);
            }
            other => panic!("compact block should be sent first, got {other:?}"),
        }

        let mut segments = Vec::new();
        for _ in 1..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("raw fallback segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected raw fallback segment, got {other:?}"),
            }
        }
        assert_eq!(reassemble_raw_block(&segments).unwrap(), raw_block);
    }

    #[tokio::test]
    async fn forward_block_flag_off_emits_no_skeleton() {
        // With skeleton_first off, forward_block sends exactly the compact block
        // and nothing else -- byte-for-byte the current behavior.
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };
        let (raw_block, _tx0, tx1) = two_tx_raw_block();
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        tx_cache.insert(TxInventoryKey::wtx([0x41; 32], [0x42; 32]).to_wtxid(), tx1);

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

        // Exactly one payload, and it is the compact block (no skeleton).
        match outgoing.recv().await.expect("compact block queued") {
            RelayPayload::CompactBlock(_) => {}
            other => panic!("expected only a compact block, got {other:?}"),
        }
        assert!(
            outgoing.try_recv().is_err(),
            "no second payload should be sent when skeleton_first is off"
        );
    }

    #[tokio::test]
    async fn forward_block_skeleton_first_sends_skeleton_then_compact() {
        // With skeleton_first on and tx-cache compaction, forward_block emits the
        // CompactSkeleton FIRST, then the full CompactBlock push fallback.
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: true,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };
        let (raw_block, _tx0, tx1) = two_tx_raw_block();
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        tx_cache.insert(TxInventoryKey::wtx([0x41; 32], [0x42; 32]).to_wtxid(), tx1);

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

        // Skeleton first ...
        let skeleton = match outgoing.recv().await.expect("skeleton queued") {
            RelayPayload::CompactSkeleton(skeleton) => skeleton,
            other => panic!("expected skeleton first, got {other:?}"),
        };
        assert_eq!(skeleton.short_ids.len(), 1, "tx1 resolved to a short_id");
        assert_eq!(skeleton.prefilled_txs.len(), 1, "only coinbase prefilled");

        // ... then the full compact block push fallback.
        match outgoing.recv().await.expect("compact block queued") {
            RelayPayload::CompactBlock(compact) => {
                assert_eq!(compact.header, skeleton.header);
            }
            other => panic!("expected compact block second, got {other:?}"),
        }
        assert!(outgoing.try_recv().is_err(), "exactly two payloads");
    }

    #[tokio::test]
    async fn forward_block_skeleton_guard_skips_all_prefilled() {
        // Small-block guard: a block whose txs are NOT in the cache is
        // all-prefilled (no short_ids), so its skeleton could only duplicate the
        // full block -- the guard must suppress it and send ONLY the compact
        // block, even with skeleton_first on.
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: true,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
            raw_wire: RawWire::Legacy,
            parse_permits: ParsePermits::new(),
            block_body_rejections: Default::default(),
            peer_pow_limit: None,
            block_log: None,
            forward_unreadable_blocks: false,
            unverified_forwards: Default::default(),
        };
        let (raw_block, _tx0, _tx1) = two_tx_raw_block();
        // Empty cache => tx1 cannot resolve to a short_id => all-prefilled.
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

        // Exactly one payload -- the compact block -- and it is NOT a skeleton.
        match outgoing.recv().await.expect("compact block queued") {
            RelayPayload::CompactBlock(compact) => {
                assert!(compact.short_ids.is_empty(), "all txs prefilled");
            }
            other => panic!("expected compact block, got {other:?}"),
        }
        assert!(
            outgoing.try_recv().is_err(),
            "guard must suppress the skeleton for an all-prefilled block"
        );
    }

    fn test_config() -> Config {
        Config {
            network: crate::wire::Network::Mainnet,
            seeds: Vec::new(),
            peers: vec!["127.0.0.1:8233".parse().unwrap()],
            max_peers: 1,
            connect_timeout: Duration::from_secs(1),
            peer_runtime: Duration::from_secs(0),
            crawler_enabled: false,
            crawler_max_known_peers: 1,
            crawler_max_addr_per_message: 1,
            crawler_drain_interval: Duration::from_secs(1),
            rotation_enabled: false,
            rotation_cooldown: Duration::from_secs(1),
            rotation_failure_cooldown: Duration::from_secs(1),
            accept_nonstandard_ports: false,
            excluded_peer_ips: std::collections::HashSet::new(),
            peer_scoring_enabled: false,
            peer_score_block_inv: 5,
            peer_score_block_first: 100,
            peer_score_block_second: 50,
            peer_score_block_third: 25,
            peer_score_half_life: Duration::from_secs(3600),
            peer_score_block_received: 25,
            peer_score_relay_forwarded: 10,
            peer_score_error: -50,
            tx_cache_enabled: false,
            tx_cache_max_entries: 200_000,
            tx_cache_max_bytes: 536_870_912,
            tx_cache_max_tx_bytes: 2_097_152,
            tx_feed_addr: None,
            tx_request_limit_per_inv: 256,
            inventory_limits: Default::default(),
            event_log: Some(PathBuf::from("/tmp/test.jsonl")),
            metrics_textfile: None,
            relay_peers: vec!["127.0.0.1:1".parse().unwrap()],
            relay_bind_addr: "127.0.0.1:0".parse().unwrap(),
            relay_auth_key: Some([0x42; 32]),
            relay_data_shards: 96,
            relay_parity_shards: 32,
            relay_adaptive_fec: false,
            relay_send_burst_packets: 0,
            relay_send_burst_delay_micros: 0,
            relay_compact_from_tx_cache: false,
            relay_skeleton_first: false,
            relay_raw_fallback_with_tx_cache: false,
            relay_forward_unreadable_blocks: false,
            relay_unreadable_bodies_per_header: DEFAULT_UNREADABLE_BODIES_PER_HEADER,
            relay_raw_segment_send_rounds: 1,
            relay_raw_wire: Default::default(),
            relay_bodies_per_header: 4,
            relay_raw_segment_round_delay_millis: 0,
            relay_forward_dedup_window: Duration::from_secs(30),
            relay_forward_dedup_capacity: 64,
            forwarding_min_peer_version: None,
            submitblock_rpc: None,
        }
    }

    /// PR-0: an operator who configures relay peers but forgets the auth key
    /// must get a hard startup error, not a silently disabled relay bridge
    /// (the old behavior, back when an unauthenticated wire format existed
    /// to fall back to).
    #[tokio::test]
    async fn from_config_errors_when_peers_configured_without_auth_key() {
        let mut config = test_config();
        config.relay_auth_key = None;

        let result = RelayBridge::from_config(&config, test_events()).await;
        let err = match result {
            Ok(_) => panic!("missing auth key with configured peers must error"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("unauthenticated mode removed"),
            "unexpected error: {err}"
        );
    }

    /// When relay peers are simply not configured at all, the bridge stays
    /// disabled (`Ok(None)`) regardless of the auth key -- this is not the
    /// misconfiguration case above.
    #[tokio::test]
    async fn from_config_disabled_when_no_relay_peers_configured() {
        let mut config = test_config();
        config.relay_peers = Vec::new();
        config.relay_auth_key = None;

        let result = RelayBridge::from_config(&config, test_events()).await;
        assert!(matches!(result, Ok(None)));
    }

    /// The other test bridges leave the peer check off, so this is what shows the
    /// real constructor turns it on, with the limit of its own network.
    #[tokio::test]
    async fn from_config_applies_the_target_check_of_its_network() {
        use super::block_body_tests::{header_missing_its_target, header_stating, unreadable_body};

        let refused = |outcome: Result<ForwardedBlock>| match outcome {
            Err(IngressError::InvalidBlockBody(error)) => error,
            Err(other) => panic!("expected a refusal, got {other}"),
            Ok(forwarded) => panic!("forwarded as {}", forwarded.mode.as_str()),
        };
        let reached_the_reader = BlockBodyError::Transaction { index: 0 };
        let real = unreadable_body(&zcash_pool_common::fixtures::mainnet_serialized_header());
        let missed = unreadable_body(&header_missing_its_target());
        let minimum_difficulty = unreadable_body(&header_stating(0x2007_ffff));

        let mainnet = RelayBridge::from_config(&test_config(), test_events())
            .await
            .unwrap()
            .unwrap();
        for (raw, expected) in [
            (&real, reached_the_reader),
            (&missed, BlockBodyError::HeaderTarget),
            (&minimum_difficulty, BlockBodyError::HeaderTarget),
        ] {
            assert_eq!(refused(mainnet.forward_block(raw, None).await), expected);
        }

        let mut config = test_config();
        config.network = crate::wire::Network::Testnet;
        let testnet = RelayBridge::from_config(&config, test_events())
            .await
            .unwrap()
            .unwrap();
        for (raw, expected) in [
            (&minimum_difficulty, reached_the_reader),
            (&missed, BlockBodyError::HeaderTarget),
        ] {
            assert_eq!(refused(testnet.forward_block(raw, None).await), expected);
        }
    }

    /// The other test bridges use the default budget, so this is what shows the real
    /// constructor takes the operator's.
    #[tokio::test]
    async fn from_config_uses_the_configured_body_budget() {
        let mut config = test_config();
        config.relay_unreadable_bodies_per_header = 7;
        config.relay_forward_dedup_window = Duration::from_secs(11);

        let bridge = RelayBridge::from_config(&config, EventSink::new(None).unwrap())
            .await
            .unwrap()
            .unwrap();

        let forwards = bridge.unverified_forwards.lock().unwrap();
        assert_eq!(forwards.per_header, 7);
        assert_eq!(forwards.window, Duration::from_secs(11));
    }

    #[tokio::test]
    async fn sent_unreadable_repeat_skips_block_preparation() {
        let mut config = test_config();
        config.relay_forward_unreadable_blocks = true;
        let bridge = RelayBridge::from_config(&config, test_events())
            .await
            .unwrap()
            .unwrap();
        let raw = super::block_body_tests::unreadable_block(40_000, 1);
        let body = UnverifiedBody {
            header_hash: zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]),
            digest: Sha256::digest(&raw).into(),
        };
        {
            let mut forwards = bridge.unverified_forwards.lock().unwrap();
            assert!(matches!(
                forwards.reserve(body, std::time::Instant::now()),
                UnverifiedReservation::Reserved
            ));
            forwards.commit(&body);
        }
        let prepared = bridge.prepare_forward(raw, None).unwrap();
        assert!(matches!(prepared.objects, PreparedObjects::PreviouslySent));
    }

    /// The gateway checks the target itself, on any network this runs on.
    #[tokio::test]
    async fn from_config_leaves_the_gateway_path_alone() {
        use super::block_body_tests::{header_missing_its_target, unreadable_body};

        let bridge = RelayBridge::from_config(&test_config(), test_events())
            .await
            .unwrap()
            .unwrap();
        let raw = unreadable_body(&header_missing_its_target());

        assert!(matches!(
            bridge.forward_pool_block(&raw, None).await,
            Err(IngressError::InvalidBlockBody(
                BlockBodyError::Transaction { index: 0 }
            ))
        ));
    }

    struct AcceptingZebra {
        submitted: std::sync::Mutex<Vec<String>>,
    }

    impl sovright_relay_sidecar::submit::SubmitBlock for AcceptingZebra {
        fn submit_block<'a>(
            &'a self,
            block_hex: &'a str,
        ) -> sovright_relay_sidecar::submit::SubmitFuture<'a> {
            self.submitted.lock().unwrap().push(block_hex.to_owned());
            Box::pin(async { Ok(None) })
        }
    }

    struct KnownParents;

    impl sovright_relay_sidecar::submit_gate::ChainView for KnownParents {
        fn tip_height(&self) -> u64 {
            100
        }

        fn parent_known(&self, _parent_hash: &[u8; 32]) -> bool {
            true
        }
    }

    /// A relay node that verifies Equihash and the target, a receiving client over
    /// UDP loopback, and a bridge from the real constructor with the bypass on.
    struct RelayPath {
        node: Arc<sovright_relay::RelayNode>,
        node_task: tokio::task::JoinHandle<std::result::Result<(), TransportError>>,
        receiver_task: tokio::task::JoinHandle<std::result::Result<(), TransportError>>,
        receiver: sovright_relay::BlockReceiver,
        bridge: RelayBridge,
    }

    impl RelayPath {
        async fn start() -> Self {
            use sovright_relay::{AuthKey, RelayConfig, RelayNode};

            let auth_key = [0x42; 32];
            let node_config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
                .with_authorized_keys(vec![AuthKey::new("fleet", auth_key)]);
            let mut node = RelayNode::new(node_config).unwrap();
            node.bind().await.unwrap();
            let node_addr = node.local_addr().unwrap();
            let node = Arc::new(node);
            let running_node = Arc::clone(&node);
            let node_task = tokio::spawn(async move { running_node.run().await });
            sleep(Duration::from_millis(50)).await;

            let mut receiving_client = RelayClient::new(
                ClientConfig::new(vec![node_addr], auth_key).with_auth_required(true),
            )
            .unwrap();
            receiving_client.bind().await.unwrap();
            let (receiver, outgoing) = receiving_client.take_receiver().unwrap();
            let receiver_task =
                tokio::spawn(async move { receiving_client.run_with_outgoing(outgoing).await });
            sleep(Duration::from_millis(200)).await;

            let mut config = test_config();
            config.relay_peers = vec![node_addr];
            config.relay_auth_key = Some(auth_key);
            config.relay_data_shards = 10;
            config.relay_parity_shards = 3;
            config.relay_forward_unreadable_blocks = true;
            let events = EventSink::new(None).unwrap();
            let bridge = RelayBridge::from_config(&config, events)
                .await
                .unwrap()
                .unwrap();
            sleep(Duration::from_millis(100)).await;
            Self {
                node,
                node_task,
                receiver_task,
                receiver,
                bridge,
            }
        }

        async fn stop(self) {
            self.node.stop();
            self.receiver_task.abort();
            let _ = self.node_task.await;
        }
    }

    /// The first body of a header is delivered, and the second never crosses the
    /// relay, because object ids are bound to the header and not to the body. Quotas
    /// are not what stops it here: both bodies were sent. A later block shows the
    /// path is still working. This is the open delivery race in #130.
    #[tokio::test]
    async fn known_gap_a_second_body_of_one_header_does_not_cross_the_relay() {
        use super::block_body_tests::unreadable_block;
        use sovright_relay::reassemble_raw_block;

        let mut path = RelayPath::start().await;
        let forged = unreadable_block(40_000, 1);
        let real = unreadable_block(40_000, 2);
        let later = super::nu7_fixture::Nu7Fixture::load().raw;
        for raw in [&forged, &real] {
            let forwarded = path.bridge.forward_block(raw, None).await.unwrap();
            assert_eq!(forwarded.mode, ForwardMode::RawBlockSegmentsUnverified);
        }
        path.bridge.forward_block(&later, None).await.unwrap();

        let later_header = &later[..ZCASH_FULL_HEADER_SIZE];
        let mut segments = Vec::new();
        loop {
            let payload =
                tokio::time::timeout(Duration::from_secs(5), path.receiver.recv_payload())
                    .await
                    .expect("the later block crosses the relay")
                    .expect("the receiver stays open");
            match payload {
                sovright_relay::RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                sovright_relay::RelayPayload::CompactBlock(compact)
                    if compact.header == later_header =>
                {
                    break;
                }
                _ => {}
            }
        }

        assert_eq!(reassemble_raw_block(&segments).unwrap(), forged);
        path.stop().await;
    }

    /// The whole way, on real components: the real constructor, raw segmentation, a
    /// relay node that verifies the header's Equihash solution and target, a
    /// receiving client over UDP loopback, reassembly, and the sidecar deciding for
    /// itself. A helper returning `Ok` would show none of this.
    #[tokio::test]
    async fn an_unreadable_block_crosses_the_relay_and_reaches_zebra() {
        use sovright_relay::reassemble_raw_block;
        use sovright_relay_sidecar::submit::{
            RelayBlockError, SubmissionOutcome, SubmitBlockMode, SubmitBlockStatus,
            UnverifiedLimits, submit_unverified_raw_block, unreadable_body,
            validate_then_gate_raw_block,
        };
        use sovright_relay_sidecar::submit_gate::{
            CandidateMeta, GateConfig, ParentObservation, SubmitGate,
        };
        use std::sync::atomic::{AtomicU64, Ordering};

        let mut path = RelayPath::start().await;
        let raw = super::block_body_tests::unreadable_block(40_000, 1);
        let forwarded = path.bridge.forward_block(&raw, None).await.unwrap();
        assert_eq!(forwarded.mode, ForwardMode::RawBlockSegmentsUnverified);
        assert!(forwarded.relay_objects > 1, "several segments");

        let mut segments = Vec::new();
        loop {
            let segment = tokio::time::timeout(
                Duration::from_secs(5),
                path.receiver.recv_raw_block_segment(),
            )
            .await
            .expect("the relay delivers the segments")
            .expect("the receiver stays open");
            let expected = segment.segment_count as usize;
            segments.push(segment);
            if segments.len() == expected {
                break;
            }
        }
        let received = reassemble_raw_block(&segments).unwrap();
        assert_eq!(received, raw, "the bytes survive the relay");

        let block_hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
        let zebra = AcceptingZebra {
            submitted: Default::default(),
        };
        let gate = tokio::sync::Mutex::new(SubmitGate::new(
            GateConfig {
                enabled: true,
                ..GateConfig::default()
            },
            KnownParents,
        ));
        let parent = || async {
            Some(ParentObservation {
                parent_hash: CandidateMeta::parent_hash_from_header(&raw[..ZCASH_FULL_HEADER_SIZE])
                    .unwrap(),
                height: 100,
                confirmations: Some(1),
            })
        };

        // A sidecar with its own switch off refuses what the sender forwarded.
        let strict = validate_then_gate_raw_block(
            &zebra,
            &received,
            Some(block_hash),
            SubmitBlockMode::Live,
            &gate,
            parent,
        )
        .await;
        assert!(matches!(
            strict,
            Err(RelayBlockError::InvalidBlockBody(
                BlockBodyError::Transaction { index: 1 }
            ))
        ));
        assert!(zebra.submitted.lock().unwrap().is_empty());

        let error = unreadable_body(&strict).expect("the bypass may take this one");
        let bypassed = AtomicU64::new(0);
        let limits = UnverifiedLimits {
            budget: Duration::from_secs(5),
            bypassed: &bypassed,
        };
        let outcome = submit_unverified_raw_block(
            &zebra,
            &received,
            error,
            SubmitBlockMode::Live,
            &gate,
            limits,
            parent,
        )
        .await;

        match outcome {
            Ok(SubmissionOutcome::Submitted { status, candidate }) => {
                assert_eq!(status, SubmitBlockStatus::Accepted);
                assert_eq!(
                    candidate.unverified,
                    Some(BlockBodyError::Transaction { index: 1 })
                );
            }
            Ok(_) => panic!("the block did not reach Zebra"),
            Err(error) => panic!("the block did not reach Zebra: {error}"),
        }
        assert_eq!(*zebra.submitted.lock().unwrap(), [hex::encode(&raw)]);
        assert_eq!(bypassed.load(Ordering::Relaxed), 1);
        path.stop().await;
    }

    /// `main` hands the bridge straight to the gateway, so the real constructor is
    /// what has to name it. The line is written before the send, so its outcome
    /// does not matter here.
    #[tokio::test]
    async fn from_config_names_the_gateway_in_its_coinbase_events() {
        let log = std::env::temp_dir().join(format!(
            "sovright-p2p-gateway-coinbase-{}.jsonl",
            std::process::id()
        ));
        let events = EventSink::new(Some(log.clone())).unwrap();
        let bridge = RelayBridge::from_config(&test_config(), events)
            .await
            .unwrap()
            .unwrap();
        let raw = zcash_pool_common::fixtures::mainnet_raw_block();

        let _ = bridge.forward_pool_block(&raw, None).await;

        let lines = std::fs::read_to_string(&log).unwrap();
        let coinbase: serde_json::Value = lines
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| event["event"] == "p2p_block_coinbase")
            .expect("a coinbase line");
        assert_eq!(coinbase["peer"], POOL_GATEWAY_SOURCE);
        assert_eq!(
            coinbase["consensus_hash"],
            consensus_block_hash_display(&raw[..ZCASH_FULL_HEADER_SIZE])
        );
    }

    fn test_events() -> EventSink {
        EventSink::new(None).unwrap()
    }

    #[test]
    fn bridge_uses_configured_relay_fec_profile() {
        let bridge = RelayBridge::new_for_config(&test_config()).unwrap();

        assert_eq!(bridge.data_shards, 96);
        assert_eq!(bridge.parity_shards, 32);
    }

    #[test]
    fn bridge_keeps_tx_cache_compaction_disabled_by_default() {
        let bridge = RelayBridge::new_for_config(&test_config()).unwrap();

        assert!(!bridge.compact_from_tx_cache);
    }

    #[test]
    fn bridge_keeps_raw_fallback_disabled_by_default() {
        let bridge = RelayBridge::new_for_config(&test_config()).unwrap();

        assert!(!bridge.raw_fallback_with_tx_cache);
    }

    #[test]
    fn bridge_uses_configured_raw_segment_retransmission_profile() {
        let mut config = test_config();
        config.relay_raw_segment_send_rounds = 3;
        config.relay_raw_segment_round_delay_millis = 25;

        let bridge = RelayBridge::new_for_config(&config).unwrap();

        assert_eq!(bridge.raw_segment_send_rounds, 3);
        assert_eq!(bridge.raw_segment_round_delay, Duration::from_millis(25));
    }

    // ----------------------------------------------------------------
    // Dedup ring tests (the RecentForwardedHashes helper)
    // ----------------------------------------------------------------

    #[test]
    fn recent_forwarded_initially_empty() {
        let mut r = RecentForwardedHashes::new(4, Duration::from_secs(30));
        let now = std::time::Instant::now();
        assert!(!r.contains(&[1u8; 32], now));
    }

    #[test]
    fn recent_forwarded_records_and_finds() {
        let mut r = RecentForwardedHashes::new(4, Duration::from_secs(30));
        let now = std::time::Instant::now();
        r.record([7u8; 32], now);
        assert!(r.contains(&[7u8; 32], now));
        assert!(!r.contains(&[1u8; 32], now));
    }

    #[test]
    fn recent_forwarded_evicts_expired() {
        let mut r = RecentForwardedHashes::new(4, Duration::from_secs(30));
        let t0 = std::time::Instant::now();
        r.record([7u8; 32], t0);
        assert!(!r.contains(&[7u8; 32], t0 + Duration::from_secs(31)));
    }

    #[test]
    fn recent_forwarded_capacity_evicts_oldest() {
        let mut r = RecentForwardedHashes::new(2, Duration::from_secs(30));
        let t0 = std::time::Instant::now();
        r.record([1u8; 32], t0);
        r.record([2u8; 32], t0);
        r.record([3u8; 32], t0);
        // Oldest entry [1; 32] should be evicted.
        assert!(!r.contains(&[1u8; 32], t0));
        assert!(r.contains(&[2u8; 32], t0));
        assert!(r.contains(&[3u8; 32], t0));
    }

    #[test]
    fn recent_forwarded_zero_capacity_is_no_op() {
        let mut r = RecentForwardedHashes::new(0, Duration::from_secs(30));
        let t0 = std::time::Instant::now();
        r.record([7u8; 32], t0);
        // Zero-capacity ring never retains, never reports a hit.
        assert!(!r.contains(&[7u8; 32], t0));
    }
}

#[cfg(test)]
#[path = "nu7_fixture.rs"]
mod nu7_fixture;

#[cfg(test)]
#[path = "nu7_transport_tests.rs"]
mod nu7_transport_tests;

#[cfg(test)]
#[path = "block_body_tests.rs"]
pub(crate) mod block_body_tests;

#[cfg(test)]
#[path = "nu7_relay_path_tests.rs"]
mod nu7_relay_path_tests;
