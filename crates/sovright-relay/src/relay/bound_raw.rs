//! The #130 PR B candidate on the real raw path, for research. Nothing here runs unless a
//! config asks for it, and nothing here is a decided format: it is the chunk and frame
//! candidates of the design note, on the real sockets, sessions, keys and PoW check.
//!
//! The same raw block has two ways across, and they do not share a record:
//!
//! | | Legacy | Bound |
//! |---------------------|---------------------------|------------------------------------|
//! | Chunk               | v2 or v3, a MAC           | v4, a MAC and a proof to the object|
//! | Object id           | Block hash and index      | Commits to the shards              |
//! | Body id             | None                      | Commits to every segment           |
//! | Delivered record    | `recent_delivered`, set   | The ledger, ended by the consumer's|
//! |                     | before anyone has checked | verdict on the block               |
//! | A node's record     | By chunk and session, 120s| By object and session, a window    |
//! | What crosses to the | One segment at a time     | One whole block with its owners    |
//! | consumer            |                           |                                    |
//!
//! So a receiver with this on takes both and a receiver without it drops every v4 datagram
//! at `Chunk::from_bytes`, which is what makes it possible to send both and to turn this off
//! again. Nothing here protects a legacy receiver, and sending both does not either.
//!
//! Every number in this file is a research value, chosen so a block of the largest size
//! fits. None of them is a setting anyone decided, and [`SEGMENT_BYTES`] is the design's
//! placeholder.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chunk_proof::assembler::{Arrival, Assembler, AssemblerLimits, DecodedObject, Interest};
use chunk_proof::budget::{Budget, InvalidLimits, Limits as BudgetLimits, Refusal};
use chunk_proof::datagram::{Verifier, claims_this_format, seal};
use chunk_proof::handoff::{Bridge, Handoff, Stack, StackLimits, Step};
use chunk_proof::object::{Encoded, MSG_RAW_SEGMENT, Profile, encode};
use chunk_proof::tree::Node;
use delivery_lease::body_buffer::{AssembledBlock, BufferLimits};
use delivery_lease::segment_frame::{FrameRules, SetKey, build, verify};
use delivery_lease::{
    DeliveryLedger, Limits as LedgerLimits, Refusal as LedgerRefusal, Snapshot, Transit,
};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::warn;

use crate::transport::{PowResult, ZCASH_FULL_HEADER_SIZE};

pub use chunk_proof::budget::Used as BoundUsed;

pub const SEGMENT_BYTES: u32 = 9584;
pub const MAX_BODY_BYTES: u64 = 2_000_000;
/// The largest frame of a body of [`MAX_BODY_BYTES`]: 209 segments, so a proof of 8 nodes.
const MAX_FRAME_BYTES: usize = 9926;
const SHARDS: u16 = 13;
const DATA_SHARDS: u16 = 10;
/// Copies of one object past the first, in a window, on a receiver and on a node alike.
const RESENDS: u32 = 2;
const RELEASED_TTL: Duration = Duration::from_secs(60);

fn hash_header(header: &[u8]) -> [u8; 32] {
    crate::zcash_block_hash(header)
}

pub fn frame_rules() -> FrameRules {
    FrameRules::new(
        SEGMENT_BYTES,
        MAX_BODY_BYTES,
        ZCASH_FULL_HEADER_SIZE,
        hash_header,
    )
    .expect("the research rules are valid")
}

fn max_content(_msg_type: u8) -> usize {
    MAX_FRAME_BYTES
}

fn assembler_limits() -> AssemblerLimits {
    AssemblerLimits {
        max_rejected: 64,
        assembly_ttl: Duration::from_secs(30),
        rejected_ttl: Duration::from_secs(120),
        max_content,
    }
}

/// A receiver's research values. See the module note.
#[derive(Clone, Copy, Debug)]
pub struct BoundRawConfig {
    pub stack: StackLimits,
    /// Whole blocks the channel to the consumer holds.
    pub channel_blocks: usize,
    /// How often the shelf and the timers are looked at. An owner on another task can go at
    /// any moment and nothing here hears of it.
    pub look_every: Duration,
}

impl Default for BoundRawConfig {
    fn default() -> Self {
        Self {
            stack: StackLimits {
                budget: BudgetLimits {
                    max_sessions: 4,
                    max_objects: 32,
                    max_held_bytes: 1 << 20,
                    max_work_bytes: 1 << 20,
                    max_spare_objects: 32,
                    max_spare_bytes: 1 << 20,
                },
                ledger: LedgerLimits {
                    max_records: 4096,
                    max_live_owners: 1024,
                    max_reserved_bytes: 4 * MAX_BODY_BYTES as usize,
                    repeat_budget: RESENDS,
                    completed_ttl: Duration::from_secs(300),
                    released_ttl: RELEASED_TTL,
                    transit: Transit {
                        bytes: 8 * SEGMENT_BYTES as usize,
                        owners: 8,
                        records: 8,
                    },
                },
                buffer: BufferLimits {
                    max_sets: 8,
                    max_sets_per_block: 4,
                    max_segments: 1024,
                    ttl: Duration::from_secs(120),
                },
                assembler: assembler_limits(),
                max_carried: 1024,
            },
            channel_blocks: 4,
            look_every: Duration::from_millis(250),
        }
    }
}

/// A node's research values, for one session and for the node.
#[derive(Clone, Copy, Debug)]
pub struct BoundForwardConfig {
    /// What one session can hold. Only a session holding less can push it, and only when
    /// the pool is full. See [`BoundForwarder`].
    pub session_budget: BudgetLimits,
    /// What all sessions together can hold, and how many there can be on this path. Every
    /// reservation of a session counts here too.
    pub pool: BudgetLimits,
    /// Objects one session has had sent on. Forgetting one costs a second decode and a
    /// second send.
    pub max_forwarded: usize,
    /// Those records over all sessions. Past this the session with the most gives one up.
    pub max_forwarded_total: usize,
    /// Chunks of an object sent on this recently are left over from that send: the shards a
    /// decode did not need, or the same datagrams again. They are dropped.
    pub resend_after: Duration,
    /// How long the count of an object's sends stands, from its first send.
    pub resend_window: Duration,
    /// Sends of one object past the first in a window. Past this its chunks are dropped
    /// until the window ends.
    pub max_resends: u32,
    /// Sets whose segment 0 passed the PoW check.
    pub max_anchors: usize,
    /// Decoded objects of one session that wait for their segment 0.
    pub max_unanchored: usize,
}

impl Default for BoundForwardConfig {
    fn default() -> Self {
        Self {
            session_budget: BudgetLimits {
                max_sessions: 2,
                max_objects: 32,
                max_held_bytes: 1 << 20,
                max_work_bytes: 1 << 20,
                max_spare_objects: 8,
                max_spare_bytes: 1 << 18,
            },
            pool: BudgetLimits {
                max_sessions: 256,
                max_objects: 2048,
                max_held_bytes: 16 << 20,
                max_work_bytes: 1 << 20,
                max_spare_objects: 256,
                max_spare_bytes: 4 << 20,
            },
            max_forwarded: 4096,
            max_forwarded_total: 1 << 16,
            resend_after: Duration::from_secs(2),
            // Past the receiver's records, so a window that opens finds them gone.
            resend_window: Duration::from_secs(90),
            max_resends: RESENDS,
            max_anchors: 256,
            max_unanchored: 64,
        }
    }
}

/// Whether this datagram claims the bound format. Nothing is checked yet.
pub fn is_bound(datagram: &[u8]) -> bool {
    claims_this_format(datagram)
}

fn seal_object(key: &[u8; 32], object: &Encoded) -> Vec<Vec<u8>> {
    object
        .shards
        .iter()
        .zip(&object.proofs)
        .zip(0u16..)
        .map(|((shard, proof), index)| {
            seal(key, &object.shape, &object.object_id, index, proof, shard)
        })
        .collect()
}

/// The frames of one body. `None` if it does not fit.
pub fn body_frames(raw: &[u8]) -> Option<Vec<Vec<u8>>> {
    build(raw, &frame_rules())
}

/// Every datagram of one frame, with `key`, whatever the frame says. The chunks are honest
/// about the object: what the frame claims is checked after a decode.
pub fn sealed_frame(frame: &[u8], key: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let object = encode(MSG_RAW_SEGMENT, SHARDS, DATA_SHARDS, frame)?;
    Some(seal_object(key, &object))
}

/// Every datagram of one body, with `key`, for a sender. `None` if it does not fit.
pub fn sealed_body(raw: &[u8], key: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let mut datagrams = Vec::new();
    for frame in body_frames(raw)? {
        datagrams.append(&mut sealed_frame(&frame, key)?);
    }
    Some(datagrams)
}

/// A whole body, owned by whoever holds this. Its owners go with it: [`Self::finish`] says
/// it is finished with, and anything else, [`Self::give_back`] or just dropping it, lets a
/// copy in. Ending it says nothing about the block itself: it says what this consumer did.
#[derive(Debug)]
pub struct BoundBlock(AssembledBlock<Vec<u8>>);

impl BoundBlock {
    pub fn raw(&self) -> &[u8] {
        self.0.block()
    }

    pub fn finish(self) {
        self.0.finish(Instant::now());
    }

    pub fn give_back(self) {
        self.0.give_back();
    }
}

/// A plain struct to read, and a live one to count in. Counting is a relaxed atomic, so it
/// takes no lock on the path being measured. Reading goes field by field, so one read is no
/// single instant: a later count can sit next to an earlier one.
macro_rules! counters {
    ($(#[$doc:meta])* $read:ident, $live:ident, $($field:ident),+ $(,)?) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $read {
            $(pub $field: u64,)+
        }

        #[derive(Debug, Default)]
        struct $live {
            $($field: AtomicU64,)+
        }

        impl $live {
            fn read(&self) -> $read {
                $read {
                    $($field: self.$field.load(Ordering::Relaxed),)+
                }
            }
        }
    };
}

fn add(count: &AtomicU64, by: u64) {
    count.fetch_add(by, Ordering::Relaxed);
}

counters!(
    /// What the datagrams that reached this code came to, on one node or one receiver. It says
    /// nothing of a datagram that never got here, so a gap between what one side sent and this
    /// count is no proof of loss on its own: the socket's queue and the kernel's drops say that.
    BoundArrivals,
    LiveArrivals,
    datagrams,
    invalid,
    known_bad,
    repeats,
    other_shape,
    not_wanted,
    spares,
    pending,
    decoded,
    rejected,
    refused_for_objects,
    refused_for_bytes,
    refused_for_work,
    refused_by_pool,
    refused_otherwise,
);

impl LiveArrivals {
    fn note(&self, arrival: &Arrival) {
        add(&self.datagrams, 1);
        let count = match arrival {
            Arrival::Invalid(_) => &self.invalid,
            Arrival::Repeat => &self.repeats,
            Arrival::KnownBad => &self.known_bad,
            Arrival::OtherShape => &self.other_shape,
            Arrival::NotWanted => &self.not_wanted,
            Arrival::Spare { .. } => &self.spares,
            Arrival::Pending { .. } => &self.pending,
            Arrival::Decoded(_) => &self.decoded,
            Arrival::Rejected(_) => &self.rejected,
            Arrival::Refused(Refusal::Objects) => &self.refused_for_objects,
            Arrival::Refused(Refusal::HeldBytes) => &self.refused_for_bytes,
            Arrival::Refused(Refusal::WorkBytes) => &self.refused_for_work,
            Arrival::Refused(Refusal::Shared) => &self.refused_by_pool,
            Arrival::Refused(_) => &self.refused_otherwise,
        };
        add(count, 1);
    }
}

counters!(
    /// What became of the objects a receiver decoded. The last three say what it held at its
    /// last timed look, not now.
    BoundHandoffs,
    LiveHandoffs,
    segments_held,
    sets_whole,
    already_held,
    not_wanted,
    refused_for_room,
    refused_repeat_budget,
    bad_content,
    too_long,
    not_a_segment,
    sets_evicted,
    sets_expired,
    objects_expired,
    blocks_to_consumer,
    assembly_failures,
    sets_open,
    segments_buffered,
    waiting_for_channel,
);

impl LiveHandoffs {
    fn note(&self, handoff: &Handoff) {
        let count = match handoff {
            Handoff::Held(evicted) => {
                add(&self.sets_evicted, evicted.len() as u64);
                &self.segments_held
            }
            Handoff::Whole(_) => &self.sets_whole,
            Handoff::AlreadyHeld(_) => &self.already_held,
            Handoff::NotWanted => &self.not_wanted,
            Handoff::Refused(LedgerRefusal::RepeatBudget) => &self.refused_repeat_budget,
            Handoff::Refused(_) => &self.refused_for_room,
            Handoff::BadContent(_) => &self.bad_content,
            Handoff::TooLong(_) => &self.too_long,
            Handoff::NotASegment(_) => &self.not_a_segment,
        };
        add(count, 1);
    }
}

/// How far a receiver has got, for diagnosing a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoundProgress {
    pub arrivals: BoundArrivals,
    pub handoffs: BoundHandoffs,
}

#[derive(Debug, Default)]
struct LiveProgress {
    arrivals: LiveArrivals,
    handoffs: LiveHandoffs,
}

/// A read of the counters of a running receiver, for tests and metrics.
#[derive(Clone, Debug)]
pub struct BoundProbe {
    budget: Budget,
    ledger: DeliveryLedger,
    progress: Arc<LiveProgress>,
}

impl BoundProbe {
    pub fn used(&self) -> BoundUsed {
        self.budget.used()
    }

    pub fn ledger(&self) -> Snapshot {
        self.ledger.snapshot()
    }

    /// Read field by field, so no single instant.
    pub fn progress(&self) -> BoundProgress {
        BoundProgress {
            arrivals: self.progress.arrivals.read(),
            handoffs: self.progress.handoffs.read(),
        }
    }
}

/// One client's way in: everything from a datagram to the channel, on the client's task.
pub(crate) struct BoundReceiver {
    // Field order: the bridge and session give their reservations back to the stack.
    session: Assembler,
    bridge: Bridge,
    stack: Stack,
    consumer: mpsc::Sender<BoundBlock>,
    look_again: bool,
    progress: Arc<LiveProgress>,
}

impl BoundReceiver {
    pub(crate) fn new(
        key: [u8; 32],
        config: &BoundRawConfig,
        consumer: mpsc::Sender<BoundBlock>,
    ) -> Option<Self> {
        let stack = Stack::new(key, Profile::Research, frame_rules(), config.stack).ok()?;
        let bridge = stack.bridge().ok()?;
        let session = stack.session().ok()?;
        Some(Self {
            session,
            bridge,
            stack,
            consumer,
            look_again: false,
            progress: Arc::default(),
        })
    }

    pub(crate) fn probe(&self) -> BoundProbe {
        BoundProbe {
            budget: self.stack.budget().clone(),
            ledger: self.stack.ledger().clone(),
            progress: Arc::clone(&self.progress),
        }
    }

    /// On the timer and not for each datagram, so the measured path does none of this work.
    fn note_what_it_holds(&self) {
        let (buffer, handoffs) = (self.bridge.buffer(), &self.progress.handoffs);
        let store = |count: &AtomicU64, value: usize| count.store(value as u64, Ordering::Relaxed);
        store(&handoffs.sets_open, buffer.sets());
        store(&handoffs.segments_buffered, buffer.segments());
        store(&handoffs.waiting_for_channel, self.bridge.waiting());
    }

    pub(crate) fn consumer(&self) -> mpsc::Sender<BoundBlock> {
        self.consumer.clone()
    }

    pub(crate) fn has_waiting(&self) -> bool {
        self.bridge.waiting() > 0
    }

    fn settle(&mut self, handoff: Handoff, now: Instant) {
        self.progress.handoffs.note(&handoff);
        match handoff {
            Handoff::Whole(set) => self.bridge.wait_for_consumer(set, now),
            Handoff::Held(evicted) if !evicted.is_empty() => self.look_again = true,
            Handoff::NotASegment(object) => {
                warn!(
                    msg_type = object.msg_type(),
                    "Bound object is not a segment"
                );
            }
            _ => {}
        }
    }

    /// One datagram, all the way to the channel if it finished a block. False once the
    /// consumer is gone.
    pub(crate) fn take(&mut self, datagram: &[u8], now: Instant) -> bool {
        match self.bridge.take(&mut self.session, datagram, now) {
            Step::Handed(handoff) => {
                add(&self.progress.arrivals.datagrams, 1);
                add(&self.progress.arrivals.decoded, 1);
                self.settle(handoff, now);
            }
            Step::Chunk(arrival) => self.progress.arrivals.note(&arrival),
        }
        if std::mem::take(&mut self.look_again) {
            self.sweep(now);
        }
        self.pump(now)
    }

    fn sweep(&mut self, now: Instant) {
        for handoff in self.bridge.sweep(&mut self.session, now) {
            self.settle(handoff, now);
        }
    }

    /// The timers and the shelf. False once the consumer is gone.
    pub(crate) fn look(&mut self, now: Instant) -> bool {
        add(
            &self.progress.handoffs.sets_expired,
            self.bridge.expire(now).len() as u64,
        );
        add(
            &self.progress.handoffs.objects_expired,
            self.session.expire(now).len() as u64,
        );
        self.sweep(now);
        let live = self.pump(now);
        self.note_what_it_holds();
        live
    }

    /// What is waiting, as far as the channel has room. Room is asked for first, so a block
    /// is never put together with nowhere to go. False once the consumer is gone.
    pub(crate) fn pump(&mut self, now: Instant) -> bool {
        while self.has_waiting() {
            match self.consumer.try_reserve() {
                Ok(permit) => match self.bridge.next_block(now) {
                    Some(Ok(block)) => {
                        permit.send(BoundBlock(block));
                        add(&self.progress.handoffs.blocks_to_consumer, 1);
                    }
                    Some(Err(error)) => {
                        warn!(?error, "Bound block did not assemble");
                        add(&self.progress.handoffs.assembly_failures, 1);
                    }
                    None => break,
                },
                Err(TrySendError::Full(())) => break,
                Err(TrySendError::Closed(())) => {
                    self.bridge.abandon_waiting();
                    return false;
                }
            }
        }
        !self.consumer.is_closed()
    }
}

/// Wait until the channel has room, or is closed. Pends for good with no channel.
pub(crate) async fn wait_for_room(consumer: Option<&mpsc::Sender<BoundBlock>>) {
    match consumer {
        Some(consumer) => drop(consumer.reserve().await),
        None => std::future::pending().await,
    }
}

/// Bounded and first in, first out.
#[derive(Debug)]
struct Recent<T> {
    max: usize,
    known: HashSet<T>,
    order: VecDeque<T>,
}

impl<T: Copy + Eq + std::hash::Hash> Recent<T> {
    fn new(max: usize) -> Self {
        Self {
            max,
            known: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    fn contains(&self, item: &T) -> bool {
        self.known.contains(item)
    }

    fn insert(&mut self, item: T) {
        if !self.known.insert(item) {
            return;
        }
        self.order.push_back(item);
        if self.order.len() > self.max
            && let Some(oldest) = self.order.pop_front()
        {
            self.known.remove(&oldest);
        }
    }
}

/// One object's sends through one session.
#[derive(Clone, Copy, Debug)]
struct Sends {
    first: Instant,
    last: Instant,
    count: u32,
}

/// What a session has had sent on. Bounded, oldest forgotten first, and each record ends.
#[derive(Debug, Default)]
struct Forwarded {
    sends: HashMap<Node, Sends>,
    order: VecDeque<Node>,
}

impl Forwarded {
    fn len(&self) -> usize {
        self.sends.len()
    }

    /// Whether a copy of `object` can go through at `now`.
    fn allows(&self, object: &Node, now: Instant, config: &BoundForwardConfig) -> bool {
        let Some(sends) = self.sends.get(object) else {
            return true;
        };
        if now.saturating_duration_since(sends.last) < config.resend_after {
            return false;
        }
        let lapsed = now.saturating_duration_since(sends.first) >= config.resend_window;
        lapsed || sends.count <= config.max_resends
    }

    fn note(&mut self, object: Node, now: Instant, config: &BoundForwardConfig) {
        let fresh = Sends {
            first: now,
            last: now,
            count: 1,
        };
        match self.sends.get_mut(&object) {
            Some(sends) if now.saturating_duration_since(sends.first) >= config.resend_window => {
                *sends = fresh;
            }
            Some(sends) => {
                sends.last = now;
                sends.count += 1;
            }
            None => {
                self.sends.insert(object, fresh);
                self.order.push_back(object);
                if self.order.len() > config.max_forwarded {
                    self.forget_oldest();
                }
            }
        }
    }

    fn forget_oldest(&mut self) {
        if let Some(oldest) = self.order.pop_front() {
            self.sends.remove(&oldest);
        }
    }

    fn forget_lapsed(&mut self, now: Instant, window: Duration) {
        self.sends
            .retain(|_, sends| now.saturating_duration_since(sends.first) < window);
        let sends = &self.sends;
        self.order.retain(|object| sends.contains_key(object));
    }
}

#[derive(Debug)]
struct BoundPeer {
    key: [u8; 32],
    budget: Budget,
    session: Assembler,
    forwarded: Forwarded,
    unanchored: VecDeque<(SetKey, DecodedObject)>,
}

impl BoundPeer {
    fn holds(&self) -> usize {
        self.budget.used().held_bytes
    }

    fn give_way(&mut self) -> bool {
        self.session.give_way() || self.unanchored.pop_front().is_some()
    }
}

/// What a node holds on this path, for tests and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoundNodeUsage {
    /// What all sessions hold together.
    pub pool: BoundUsed,
    pub peers: usize,
    pub forwarded_records: usize,
    /// Datagrams dropped because their session has no place in the pool.
    pub datagrams_without_a_place: u64,
    /// What the datagrams that reached this code came to, over all sessions.
    pub arrivals: BoundArrivals,
    pub frames_rejected: u64,
    pub pow_refused: u64,
    pub pow_indeterminate: u64,
    pub objects_sent_on: u64,
    pub objects_waiting_for_segment_0: usize,
    pub waiting_pushed_out: u64,
}

/// What a datagram came to on a node.
pub(crate) enum BoundStep {
    /// A1 to A4. Nothing changed.
    Invalid,
    /// Objects to send on, all `n` shards of each.
    Forward(Vec<Encoded>),
}

/// A node's way through. An object is forwarded whole, after it decoded and its set's
/// segment 0 passed the PoW check. Encoding is deterministic and the decode already held
/// the object to its canonical form, so this is what the sender sent, and a shard lost on
/// the way here is back for the next hop.
///
/// A node cannot know a receiver gave a body back, so a new copy has to be able to cross,
/// from any session and from the one that sent it before. So the record is kept for each
/// session, and it says how far a session has gone with an object, not that the object is
/// done:
///
/// | Sends of this object, this session | Its chunks                                  |
/// |------------------------------------|---------------------------------------------|
/// | None, or the window has ended      | Decoded and sent on                         |
/// | Within [`BoundForwardConfig::resend_after`] of the last | Left over, dropped     |
/// | At most `max_resends` so far       | Decoded and sent on, and counted            |
/// | More than that, inside the window  | Dropped until the window ends               |
///
/// So a passing failure below costs a resend and not the object, and one object through
/// one session is at most `1 + max_resends` sends in a window, at any rate of resending.
/// The receiver counts for itself, so what gets through is the lower of the two.
///
/// All sessions share a pool, and each has limits of its own inside it. Sharing costs what
/// separate budgets gave, that one session cannot touch another, so a session the pool
/// refuses can ask for room: the session holding the most moves its longest-waiting object
/// aside, as long as that is more than the one asking holds. So a session is only ever
/// pushed by one holding less, and however many sessions fill the pool, each keeps about
/// its share. A session the pool has no place for gets nothing here.
///
/// A real header with a body of someone's own passes here as its own set. Telling such a
/// body from the real one is for strict validation and the node behind the consumer.
#[derive(Debug)]
pub(crate) struct BoundForwarder {
    config: BoundForwardConfig,
    rules: FrameRules,
    pool: Budget,
    peers: HashMap<SocketAddr, BoundPeer>,
    anchors: Recent<SetKey>,
    datagrams_without_a_place: u64,
    arrivals: LiveArrivals,
    frames_rejected: u64,
    pow_refused: u64,
    pow_indeterminate: u64,
    objects_sent_on: u64,
    waiting_pushed_out: u64,
}

impl BoundForwarder {
    pub(crate) fn new(config: BoundForwardConfig) -> Result<Self, InvalidLimits> {
        Ok(Self {
            config,
            rules: frame_rules(),
            pool: Budget::new(config.pool)?,
            peers: HashMap::new(),
            anchors: Recent::new(config.max_anchors),
            datagrams_without_a_place: 0,
            arrivals: LiveArrivals::default(),
            frames_rejected: 0,
            pow_refused: 0,
            pow_indeterminate: 0,
            objects_sent_on: 0,
            waiting_pushed_out: 0,
        })
    }

    pub(crate) fn usage(&self) -> BoundNodeUsage {
        BoundNodeUsage {
            pool: self.pool.used(),
            peers: self.peers.len(),
            forwarded_records: self.forwarded_records(),
            datagrams_without_a_place: self.datagrams_without_a_place,
            arrivals: self.arrivals.read(),
            frames_rejected: self.frames_rejected,
            pow_refused: self.pow_refused,
            pow_indeterminate: self.pow_indeterminate,
            objects_sent_on: self.objects_sent_on,
            objects_waiting_for_segment_0: self.peers.values().map(|p| p.unanchored.len()).sum(),
            waiting_pushed_out: self.waiting_pushed_out,
        }
    }

    fn forwarded_records(&self) -> usize {
        let peers = self.peers.values();
        peers.map(|peer| peer.forwarded.len()).sum()
    }

    fn peer(&mut self, src: SocketAddr, key: [u8; 32]) -> Option<&mut BoundPeer> {
        if self.peers.get(&src).is_some_and(|peer| peer.key != key) {
            self.peers.remove(&src);
        }
        if !self.peers.contains_key(&src) {
            let budget = Budget::within(self.config.session_budget, &self.pool).ok()?;
            let verifier = Verifier::new(key, Profile::Research);
            let Ok(session) = Assembler::new(verifier, budget.clone(), assembler_limits()) else {
                self.datagrams_without_a_place += 1;
                return None;
            };
            let peer = BoundPeer {
                key,
                budget,
                session,
                forwarded: Forwarded::default(),
                unanchored: VecDeque::new(),
            };
            self.peers.insert(src, peer);
        }
        self.peers.get_mut(&src)
    }

    fn arrive(
        &mut self,
        src: SocketAddr,
        key: [u8; 32],
        datagram: &[u8],
        now: Instant,
    ) -> Option<Arrival> {
        let config = self.config;
        let BoundPeer {
            session,
            forwarded,
            unanchored,
            ..
        } = self.peer(src, key)?;
        Some(session.receive_if(datagram, now, |object| {
            let waiting = unanchored
                .iter()
                .any(|(_, kept)| kept.object_id() == *object);
            if !waiting && forwarded.allows(object, now, &config) {
                Interest::New
            } else {
                Interest::Done
            }
        }))
    }

    /// The pool had no room for `src`. See the note on [`BoundForwarder`].
    fn someone_heavier_gives_way(&mut self, src: SocketAddr) -> bool {
        let own = self.peers.get(&src).map_or(0, BoundPeer::holds);
        let others = self.peers.iter_mut().filter(|(addr, _)| **addr != src);
        let heaviest = others.max_by_key(|(_, peer)| peer.holds());
        heaviest.is_some_and(|(_, peer)| peer.holds() > own && peer.give_way())
    }

    pub(crate) fn take(
        &mut self,
        src: SocketAddr,
        key: [u8; 32],
        datagram: &[u8],
        now: Instant,
        validate: impl Fn(&[u8]) -> PowResult,
    ) -> BoundStep {
        let mut arrival = self.arrive(src, key, datagram, now);
        if matches!(arrival, Some(Arrival::Refused(Refusal::Shared)))
            && self.someone_heavier_gives_way(src)
        {
            arrival = self.arrive(src, key, datagram, now);
        }
        if let Some(arrival) = &arrival {
            self.arrivals.note(arrival);
        }
        match arrival {
            Some(Arrival::Invalid(_)) => BoundStep::Invalid,
            Some(Arrival::Decoded(decoded)) => {
                BoundStep::Forward(self.admit(src, decoded, now, validate))
            }
            _ => BoundStep::Forward(Vec::new()),
        }
    }

    fn reject(&mut self, src: SocketAddr, object: Node, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&src) {
            peer.session.reject(object, now);
        }
    }

    fn admit(
        &mut self,
        src: SocketAddr,
        decoded: DecodedObject,
        now: Instant,
        validate: impl Fn(&[u8]) -> PowResult,
    ) -> Vec<Encoded> {
        if decoded.msg_type() != MSG_RAW_SEGMENT {
            return Vec::new();
        }
        let Ok(segment) = verify(decoded.content(), &self.rules) else {
            self.frames_rejected += 1;
            self.reject(src, decoded.object_id(), now);
            return Vec::new();
        };
        let key = segment.key();
        if segment.index() != 0 {
            if self.anchors.contains(&key) {
                return self.send_on(src, decoded, now).into_iter().collect();
            }
            if let Some(peer) = self.peers.get_mut(&src) {
                if peer.unanchored.len() >= self.config.max_unanchored {
                    peer.unanchored.pop_front();
                    self.waiting_pushed_out += 1;
                }
                peer.unanchored.push_back((key, decoded));
            }
            return Vec::new();
        }
        match validate(&segment.payload()[..ZCASH_FULL_HEADER_SIZE]) {
            PowResult::Valid => {}
            PowResult::Invalid => {
                self.pow_refused += 1;
                self.reject(src, decoded.object_id(), now);
                return Vec::new();
            }
            PowResult::Indeterminate => {
                self.pow_indeterminate += 1;
                return Vec::new();
            }
        }
        self.anchors.insert(key);
        let mut ready = vec![(src, decoded)];
        for (addr, peer) in &mut self.peers {
            let (anchored, rest): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut peer.unanchored)
                .into_iter()
                .partition(|(waiting, _)| *waiting == key);
            peer.unanchored = rest;
            ready.extend(anchored.into_iter().map(|(_, object)| (*addr, object)));
        }
        ready
            .into_iter()
            .filter_map(|(from, object)| self.send_on(from, object, now))
            .collect()
    }

    fn send_on(
        &mut self,
        from: SocketAddr,
        decoded: DecodedObject,
        now: Instant,
    ) -> Option<Encoded> {
        let shape = decoded.shape();
        let object = encode(shape.msg_type, shape.n, shape.k, decoded.content())?;
        let forwarded = &mut self.peers.get_mut(&from)?.forwarded;
        let id = object.object_id;
        if id != decoded.object_id() || !forwarded.allows(&id, now, &self.config) {
            return None;
        }
        forwarded.note(id, now, &self.config);
        self.objects_sent_on += 1;
        self.keep_records_within_limit();
        Some(object)
    }

    fn keep_records_within_limit(&mut self) {
        for _ in self.config.max_forwarded_total..self.forwarded_records() {
            let fullest = self.peers.values_mut();
            if let Some(peer) = fullest.max_by_key(|peer| peer.forwarded.len()) {
                peer.forwarded.forget_oldest();
            }
        }
    }

    /// Sessions that went, and timers.
    pub(crate) fn tidy(&mut self, now: Instant, is_live: impl Fn(&SocketAddr) -> bool) {
        self.peers.retain(|addr, _| is_live(addr));
        let window = self.config.resend_window;
        for peer in self.peers.values_mut() {
            peer.session.expire(now);
            peer.forwarded.forget_lapsed(now, window);
        }
    }

    /// Datagrams of `object` for one session's key.
    pub(crate) fn sealed(key: &[u8; 32], object: &Encoded) -> Vec<Vec<u8>> {
        seal_object(key, object)
    }
}

/// A consumer's side of one receiver.
pub(crate) type BoundChannel = (Option<BoundReceiver>, Option<BoundConsumer>);

/// What a [`crate::BlockReceiver`] holds of the bound path.
#[derive(Debug)]
pub(crate) struct BoundConsumer {
    pub(crate) blocks: mpsc::Receiver<BoundBlock>,
    pub(crate) probe: BoundProbe,
}

/// The two ends of the bound path for one client, if the config asks for it.
pub(crate) fn bound_channel(key: [u8; 32], config: Option<&BoundRawConfig>) -> BoundChannel {
    let Some(config) = config else {
        return (None, None);
    };
    let (tx, blocks) = mpsc::channel(config.channel_blocks);
    let Some(receiver) = BoundReceiver::new(key, config, tx) else {
        warn!("Bound raw limits cannot start, leaving the bound path off");
        return (None, None);
    };
    let probe = receiver.probe();
    (Some(receiver), Some(BoundConsumer { blocks, probe }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_largest_frame_is_what_the_rules_say() {
        assert_eq!(MAX_FRAME_BYTES, frame_rules().max_frame_len());
    }

    #[test]
    fn a_datagram_of_the_largest_body_fits() {
        let raw = vec![7u8; MAX_BODY_BYTES as usize];
        let datagrams = sealed_body(&raw, &[1; 32]).unwrap();
        let longest = datagrams.iter().map(Vec::len).max().unwrap();
        assert!(longest <= chunk_proof::datagram::MAX_DATAGRAM, "{longest}");
    }

    /// What a session held goes with it, and a key change starts it again.
    #[test]
    fn a_session_that_went_leaves_nothing_here() {
        let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let now = Instant::now();
        let datagrams = sealed_body(&[7u8; 5000], &[1; 32]).unwrap();
        let mut bound = BoundForwarder::new(BoundForwardConfig::default()).unwrap();
        let accept = |_: &[u8]| PowResult::Valid;
        assert!(matches!(
            bound.take(src, [1; 32], &datagrams[0], now, accept),
            BoundStep::Forward(_)
        ));
        assert_eq!(bound.peers.len(), 1);

        assert!(matches!(
            bound.take(src, [2; 32], &datagrams[1], now, accept),
            BoundStep::Invalid
        ));
        assert_eq!(bound.peers[&src].key, [2; 32]);

        bound.tidy(now, |_| false);
        assert!(bound.peers.is_empty());
    }

    const KEY: [u8; 32] = [1; 32];

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn body(fill: u8) -> Vec<Vec<u8>> {
        sealed_body(&[fill; 5000], &KEY).unwrap()
    }

    /// How many objects a whole send of `datagrams` sent on.
    fn send(
        bound: &mut BoundForwarder,
        src: SocketAddr,
        datagrams: &[Vec<u8>],
        now: Instant,
    ) -> usize {
        let accept = |_: &[u8]| PowResult::Valid;
        let steps = datagrams
            .iter()
            .map(|datagram| bound.take(src, KEY, datagram, now, accept));
        steps
            .map(|step| match step {
                BoundStep::Forward(objects) => objects.len(),
                BoundStep::Invalid => panic!("a sealed datagram is valid"),
            })
            .sum()
    }

    fn config() -> BoundForwardConfig {
        BoundForwardConfig {
            resend_after: Duration::from_secs(2),
            resend_window: Duration::from_secs(90),
            max_resends: 2,
            ..Default::default()
        }
    }

    /// The two ends of one resend have to agree, or one of them shuts out what the other
    /// let through: a receiver with repeats left needs a node that sends them, and a window
    /// that opens on a node has to find the receiver's records gone.
    #[test]
    fn the_node_and_the_receiver_count_resends_alike() {
        let (node, receiver) = (BoundForwardConfig::default(), BoundRawConfig::default());
        let ledger = receiver.stack.ledger;
        assert!(node.max_resends >= ledger.repeat_budget);
        let resending = node.resend_after * node.max_resends;
        assert!(node.resend_window >= ledger.released_ttl + resending);
    }

    #[test]
    fn a_copy_right_after_a_send_is_left_over_from_it() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let datagrams = body(7);

        assert_eq!(send(&mut bound, addr(1), &datagrams, now), 1);
        let just_after = now + Duration::from_millis(1999);
        assert_eq!(send(&mut bound, addr(1), &datagrams, just_after), 0);
    }

    #[test]
    fn a_session_can_send_an_object_again_within_its_limit_and_no_further() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let datagrams = body(7);
        let at = |secs| now + Duration::from_secs(secs);

        assert_eq!(send(&mut bound, addr(1), &datagrams, at(0)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(2)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(4)), 1);

        assert_eq!(send(&mut bound, addr(1), &datagrams, at(6)), 0);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(89)), 0);
    }

    /// What is left over comes after the latest send, not the first.
    #[test]
    fn the_short_hold_counts_from_the_latest_send() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let datagrams = body(7);
        let at = |secs| now + Duration::from_secs(secs);

        assert_eq!(send(&mut bound, addr(1), &datagrams, at(0)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(2)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(3)), 0);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(4)), 1);
    }

    /// The limit closes an object for a window and not for good.
    #[test]
    fn the_end_of_a_window_opens_an_object_again_and_counts_from_there() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let datagrams = body(7);
        let at = |secs| now + Duration::from_secs(secs);
        for secs in [0, 2, 4] {
            assert_eq!(send(&mut bound, addr(1), &datagrams, at(secs)), 1);
        }

        assert_eq!(send(&mut bound, addr(1), &datagrams, at(90)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(92)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(94)), 1);
        assert_eq!(send(&mut bound, addr(1), &datagrams, at(96)), 0);
    }

    /// One session's sends are its own, so another's copy needs none of its allowance.
    #[test]
    fn another_session_has_a_count_of_its_own() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let datagrams = body(7);
        let at = |secs| now + Duration::from_secs(secs);
        for secs in [0, 2, 4] {
            send(&mut bound, addr(1), &datagrams, at(secs));
        }

        assert_eq!(send(&mut bound, addr(2), &datagrams, at(4)), 1);
    }

    #[test]
    fn records_past_their_window_go() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        send(&mut bound, addr(1), &body(7), now);
        assert_eq!(bound.usage().forwarded_records, 1);

        bound.tidy(now + Duration::from_secs(89), |_| true);
        assert_eq!(bound.usage().forwarded_records, 1);
        bound.tidy(now + Duration::from_secs(90), |_| true);
        assert_eq!(bound.usage().forwarded_records, 0);
    }

    #[test]
    fn one_session_keeps_its_own_number_of_records() {
        let config = BoundForwardConfig {
            max_forwarded: 2,
            ..config()
        };
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        for fill in 1..=4 {
            send(&mut bound, addr(1), &body(fill), now);
        }

        assert_eq!(bound.usage().forwarded_records, 2);
    }

    /// A session that sends little keeps its records, however much others send.
    #[test]
    fn the_session_with_the_most_records_gives_one_up() {
        let config = BoundForwardConfig {
            max_forwarded: 8,
            max_forwarded_total: 4,
            ..config()
        };
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let quiet = body(1);
        assert_eq!(send(&mut bound, addr(1), &quiet, now), 1);
        for fill in 2..=9 {
            send(&mut bound, addr(2), &body(fill), now);
        }

        assert_eq!(bound.usage().forwarded_records, 4);
        assert_eq!(bound.peers[&addr(1)].forwarded.len(), 1);
        let later = now + Duration::from_secs(1);
        assert_eq!(send(&mut bound, addr(1), &quiet, later), 0);
    }

    fn pool_config(objects: usize, sessions: usize) -> BoundForwardConfig {
        let mut config = config();
        config.pool.max_objects = objects;
        config.pool.max_sessions = sessions;
        config
    }

    /// Open one object of `fill` with a chunk, and say what came of it.
    fn open_one(bound: &mut BoundForwarder, src: SocketAddr, fill: u8, now: Instant) {
        let _ = send(bound, src, &body(fill)[..1], now);
    }

    #[test]
    fn sessions_together_stay_inside_the_pool() {
        let mut config = pool_config(4, 256);
        config.pool.max_spare_objects = 1;
        config.pool.max_spare_bytes = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());

        for session in 1..=32 {
            for fill in 1..=8 {
                open_one(&mut bound, addr(session), fill + session as u8, now);
            }
            assert!(bound.usage().pool.objects <= 4);
        }

        assert_eq!(bound.usage().peers, 32);
        assert_eq!(bound.usage().pool.objects, 4);
    }

    /// A session that holds nothing gets a place, from the one holding the most.
    #[test]
    fn a_session_with_less_makes_the_heaviest_give_way() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 256)).unwrap(),
            Instant::now(),
        );
        for fill in 1..=4 {
            open_one(&mut bound, addr(1), fill, now);
        }

        open_one(&mut bound, addr(2), 9, now);

        assert_eq!(bound.peers[&addr(2)].session.state().open, 1);
        assert_eq!(bound.peers[&addr(1)].session.state().open, 3);
        assert_eq!(bound.usage().pool.objects, 4);
    }

    /// A session with open objects of its own moves those, so a flood from one session
    /// comes out of that session and another's stay where they are.
    #[test]
    fn a_session_moves_its_own_objects_before_it_asks_anyone() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 256)).unwrap(),
            Instant::now(),
        );
        open_one(&mut bound, addr(1), 1, now);
        for fill in 2..=4 {
            open_one(&mut bound, addr(2), fill, now);
        }

        open_one(&mut bound, addr(2), 5, now);

        assert_eq!(bound.peers[&addr(1)].session.state().open, 1);
        assert_eq!(bound.peers[&addr(2)].session.state().open, 3);
        assert_eq!(bound.usage().pool.objects, 4);
    }

    /// Leave a session with nothing open and nothing of its own to move: one decoded object
    /// waiting for its segment 0. What it holds is the frame's length.
    fn hold_decoded(bound: &mut BoundForwarder, src: SocketAddr, fill: u8, now: Instant) {
        let frames = body_frames(&vec![fill; 2 * SEGMENT_BYTES as usize]).unwrap();
        let later = sealed_frame(&frames[1], &KEY).unwrap();
        assert_eq!(send(bound, src, &later, now), 0);
        assert_eq!(bound.peers[&src].session.state().open, 0);
        assert_eq!(bound.peers[&src].unanchored.len(), 1);
    }

    /// Only a session holding less asks anyone to move: this one has nothing of its own to
    /// move, is refused, and holds more than the other, which stays.
    #[test]
    fn a_session_holding_more_cannot_push_one_holding_less() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(1, 256)).unwrap(),
            Instant::now(),
        );
        hold_decoded(&mut bound, addr(1), 1, now);
        open_one(&mut bound, addr(2), 2, now);
        assert!(bound.peers[&addr(1)].holds() > bound.peers[&addr(2)].holds());

        open_one(&mut bound, addr(1), 3, now);

        assert_eq!(bound.peers[&addr(1)].session.state().open, 0);
        assert_eq!(bound.peers[&addr(2)].session.state().open, 1);
    }

    /// Equal sessions keep what they have, so they cannot take turns pushing each other.
    #[test]
    fn sessions_holding_the_same_leave_each_other_alone() {
        let frames = body_frames(&vec![1u8; 2 * SEGMENT_BYTES as usize]).unwrap();
        let object = encode(MSG_RAW_SEGMENT, SHARDS, DATA_SHARDS, &frames[1]).unwrap();
        let mut limits = config();
        // One decoded object and the decode of a second, and no more than that.
        limits.pool.max_held_bytes =
            frames[1].len() + chunk_proof::object::held_bytes(&object.shape);
        let (mut bound, now) = (BoundForwarder::new(limits).unwrap(), Instant::now());
        hold_decoded(&mut bound, addr(1), 1, now);
        hold_decoded(&mut bound, addr(2), 2, now);
        assert_eq!(bound.peers[&addr(1)].holds(), bound.peers[&addr(2)].holds());

        open_one(&mut bound, addr(1), 3, now);

        assert_eq!(bound.peers[&addr(1)].session.state().open, 0);
        assert_eq!(bound.peers[&addr(2)].unanchored.len(), 1);
    }

    /// What is decoded and waiting gives way as well, when that is all the heavier one has.
    #[test]
    fn a_heavier_session_with_nothing_open_gives_up_what_waits() {
        let frames = body_frames(&vec![1u8; 2 * SEGMENT_BYTES as usize]).unwrap();
        let object = encode(MSG_RAW_SEGMENT, SHARDS, DATA_SHARDS, &frames[1]).unwrap();
        let mut limits = config();
        limits.pool.max_held_bytes = chunk_proof::object::held_bytes(&object.shape);
        let (mut bound, now) = (BoundForwarder::new(limits).unwrap(), Instant::now());
        hold_decoded(&mut bound, addr(1), 1, now);

        let _ = send(
            &mut bound,
            addr(2),
            &sealed_frame(&frames[0], &KEY).unwrap()[..1],
            now,
        );

        assert_eq!(bound.peers[&addr(1)].unanchored.len(), 0);
        assert_eq!(bound.peers[&addr(2)].session.state().open, 1);
    }

    #[test]
    fn a_session_past_the_pools_places_gets_nothing_and_is_counted() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 1)).unwrap(),
            Instant::now(),
        );
        open_one(&mut bound, addr(1), 1, now);

        open_one(&mut bound, addr(2), 2, now);

        assert_eq!(bound.usage().peers, 1);
        assert_eq!(bound.usage().pool.sessions, 1);
        assert_eq!(bound.usage().datagrams_without_a_place, 1);
    }

    #[test]
    fn a_session_that_goes_gives_everything_back_to_the_pool() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        for session in 1..=8 {
            open_one(&mut bound, addr(session), session as u8, now);
            send(&mut bound, addr(session), &body(100 + session as u8), now);
        }
        assert!(bound.usage().pool.held_bytes > 0);
        assert!(bound.usage().forwarded_records > 0);

        bound.tidy(now, |_| false);

        assert_eq!(bound.usage().pool, BoundUsed::default());
        assert_eq!(bound.usage().peers, 0);
        assert_eq!(bound.usage().forwarded_records, 0);
    }

    /// What waits for its segment 0 is held in the pool, so it cannot grow past it either.
    #[test]
    fn objects_waiting_for_their_segment_0_count_in_the_pool() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let raw = vec![9u8; 2 * SEGMENT_BYTES as usize];
        let frames = body_frames(&raw).unwrap();
        let later = sealed_frame(&frames[1], &KEY).unwrap();

        assert_eq!(send(&mut bound, addr(1), &later, now), 0);

        assert_eq!(bound.peers[&addr(1)].unanchored.len(), 1);
        assert_eq!(bound.usage().pool.held_bytes, frames[1].len());
        bound.tidy(now, |_| false);
        assert_eq!(bound.usage().pool.held_bytes, 0);
    }

    #[test]
    fn the_research_values_of_a_session_fit_the_pool() {
        let config = BoundForwardConfig::default();
        let (session, pool) = (config.session_budget, config.pool);
        assert!(session.max_held_bytes <= pool.max_held_bytes);
        assert!(session.max_objects <= pool.max_objects);
        assert!(session.max_work_bytes <= pool.max_work_bytes);
        assert!(session.max_spare_bytes <= pool.max_spare_bytes);
        assert!(config.max_forwarded <= config.max_forwarded_total);
    }

    #[test]
    fn a_legacy_chunk_is_not_taken_for_a_bound_one() {
        let chunker = crate::transport::BlockChunker::new(10, 3).unwrap();
        let segments = crate::split_raw_block([1; 32], &[1, 2, 3, 4], 2048).unwrap();
        let chunk = &chunker.raw_block_segment_to_chunks(&segments[0]).unwrap()[0];
        assert!(!is_bound(&chunk.to_bytes()));
    }

    #[test]
    fn a_bound_datagram_is_not_read_as_a_legacy_chunk() {
        let datagrams = sealed_body(&[7u8; 5000], &[1; 32]).unwrap();
        assert!(is_bound(&datagrams[0]));
        assert!(crate::Chunk::from_bytes(&datagrams[0]).is_err());
    }
}
