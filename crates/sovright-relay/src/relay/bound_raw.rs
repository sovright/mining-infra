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

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
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
use tracing::{error, warn};

use crate::transport::{
    Chunk, ChunkHeader, MessageType, PowResult, RelaySession, ZCASH_FULL_HEADER_SIZE,
};

pub use chunk_proof::budget::Used as BoundUsed;

pub const SEGMENT_BYTES: u32 = 9584;
pub const MAX_BODY_BYTES: u64 = 2_000_000;
/// The largest frame of a body of [`MAX_BODY_BYTES`]: 209 segments, so a proof of 8 nodes.
const MAX_FRAME_BYTES: usize = 9926;
const SHARDS: u16 = 13;
const DATA_SHARDS: u16 = 10;
/// Copies of one object past the first, in a window, on a receiver and on a node alike.
const RESENDS: u32 = 2;
/// A sender's pace on this path: one object, then a pause. A node decodes, encodes again and
/// sends on inside its receive loop, and a burst has only the socket's buffer to wait in for as
/// long as that takes. A research value, and it adds to how long a large body takes to send.
pub const BOUND_SEND_BURST_PACKETS: usize = SHARDS as usize;
pub const BOUND_SEND_BURST_DELAY: Duration = Duration::from_millis(1);
/// The most a node reads of one datagram.
pub(crate) const MAX_READ_BYTES: usize = 2048;
const RELEASED_TTL: Duration = Duration::from_secs(60);

/// Why this build cannot run the bound raw path, if it cannot. Panics on the path are only
/// caught by unwinding, so a build that aborts would lose the process to one, the legacy path
/// with it. What is asked to turn the path on has to refuse with this, and never go on without
/// it. A build that leaves the path off is not affected.
pub fn bound_raw_refused() -> Option<&'static str> {
    refused_by(cfg!(panic = "unwind"))
}

fn refused_by(unwinds: bool) -> Option<&'static str> {
    (!unwinds).then_some("the bound raw path needs panic = \"unwind\", and this build aborts")
}

/// The variable that turns the bound path on, on a relay node and a sidecar.
const BOUND_RAW_SWITCH: &str = "SOVRIGHT_RELAY_BOUND_RAW";

/// Whether [`BOUND_RAW_SWITCH`] asks for the bound path. Anything it cannot read is an error
/// for the caller to stop on, and never a yes.
pub fn bound_raw_switch() -> Result<bool, String> {
    read_bound_raw_switch(std::env::var_os(BOUND_RAW_SWITCH).as_deref())
}

/// The words the ingress takes for its switches. Empty counts as off, with a warning, so that
/// `VAR=` is a way back.
fn read_bound_raw_switch(value: Option<&std::ffi::OsStr>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    let text = value.to_str().map(|text| text.trim().to_ascii_lowercase());
    match text.as_deref() {
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some("") => {
            warn!("{BOUND_RAW_SWITCH} is set and empty, leaving the bound path off");
            Ok(false)
        }
        _ => Err(format!("invalid {BOUND_RAW_SWITCH}: {}", value.display())),
    }
}

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

/// How long a node keeps an object open. An
/// object's first datagram takes the room the whole object needs, about eight times its own
/// size, so that what was let in can always finish. A sender sends an object's datagrams in
/// one burst, and a second copy comes after `resend_after`, so a node needs no longer than
/// this to finish one; holding the pool with first datagrams costs a datagram an object this
/// often. The receiver keeps its own, longer time.
pub const NODE_ASSEMBLY_TTL: Duration = Duration::from_secs(5);

/// How long a node keeps a decoded object waiting for its segment 0. It gives way when the
/// pool is short of bytes, so it holds nothing anyone else needs meanwhile.
const WAITING_TTL: Duration = Duration::from_secs(30);

fn node_assembler_limits() -> AssemblerLimits {
    AssemblerLimits {
        assembly_ttl: NODE_ASSEMBLY_TTL,
        ..assembler_limits()
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
    /// What one session can hold. See [`BoundForwarder`] for when another can ask it to
    /// make room.
    pub session_budget: BudgetLimits,
    /// What all sessions of one verified key can hold together, and how many there can be.
    /// Like every value here this is for research, and it assumes nothing about how a fleet
    /// lays out its keys: with one key for everybody, this binds them all as one.
    pub key_budget: BudgetLimits,
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
    /// Bodies whose segment 0 passed the PoW check.
    pub max_anchors: usize,
    /// Of those, how many one key pays for at a time. A research value like the rest.
    pub max_anchors_per_key: usize,
    /// Bodies a block can have here, over all keys, the same number the gate takes. This is
    /// no part of the budgets: a key inside all of its limits can use up what a block has, and
    /// then the right body is refused until those anchors lapse, for as long as they are used.
    pub max_bodies_per_block: usize,
    /// How long a key's payment for an anchor lasts from that key's last use. As long as a
    /// resend can come.
    pub anchor_ttl: Duration,
    /// Decoded objects of one session that wait for their segment 0, each for up to 30 s. When
    /// the pool or their key is short of bytes they give way, the oldest first, to a session
    /// that holds less, after any open object of theirs that can move.
    pub max_unanchored: usize,
    /// Datagrams a node holds between its socket and its work, so that slow work does not
    /// leave the socket's buffer as all a burst has. Past this they stay in the socket. Zero
    /// leaves the receive loop as it is on the legacy path.
    ///
    /// This comes ahead of every check, so it holds whatever anyone sends to the port, and it
    /// is no part of [`Self::pool`]: its memory adds to the pool's, and one source can fill it.
    /// It takes up a burst and adds no capacity. Traffic beyond what a node can work through
    /// fills it, and then loss is back at the socket.
    pub max_queued_datagrams: usize,
    /// The bytes of those datagrams. This counts payload only: each entry costs a vector and
    /// an address on top, and the allocator its share.
    pub max_queued_bytes: usize,
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
            key_budget: BudgetLimits {
                max_sessions: 64,
                max_objects: 512,
                max_held_bytes: 4 << 20,
                max_work_bytes: 1 << 20,
                max_spare_objects: 64,
                max_spare_bytes: 1 << 20,
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
            max_anchors_per_key: 64,
            max_bodies_per_block: 4,
            anchor_ttl: Duration::from_secs(90),
            max_unanchored: 64,
            max_queued_datagrams: 8192,
            max_queued_bytes: 8192 * MAX_READ_BYTES,
        }
    }
}

/// Whether this datagram claims the bound format. Nothing is checked yet.
pub fn is_bound(datagram: &[u8]) -> bool {
    claims_this_format(datagram)
}

// Capability negotiation. A peer says it has the bound path with a keepalive whose block
// hash is [`BOUND_HELLO`], authenticated like any keepalive, and a node with the path on
// answers with one whose block hash is [`BOUND_HELLO_ACK`]. Absent either, the other side is
// legacy, and that is what a peer is taken to be until it says otherwise:
//
// - A node sends bound objects only to sessions whose hello said they take them.
// - A client sends a bound block only to relays that answered its hello, and fails the send
//   when none did.
//
// An old node, or one with the path off, refuses a hello as a keepalive it cannot read and
// answers nothing, and the plain keepalive sent beside it keeps the session. So the rollout
// order does not lose a body in silence: relays first, then receivers, then senders, and a
// sender in front of a relay without the path hears so on every send.
//
// A receiver that refused a body downstream, Zebra turning it away, says so with a keepalive
// whose block hash is [`BOUND_RELEASE`] and whose payload is the body's block hash and body
// id. A node with the path on takes the body's anchor away (see `BoundForwarder::release`).
// An old node refuses it as it refuses a hello.

const fn marker(text: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut at = 0;
    while at < text.len() {
        out[at] = text[at];
        at += 1;
    }
    out
}

/// The block hash of a keepalive that announces the bound path.
pub const BOUND_HELLO: [u8; 32] = marker(b"sovright/bound-raw/hello/v1");
/// The block hash of a node's answer to [`BOUND_HELLO`].
pub const BOUND_HELLO_ACK: [u8; 32] = marker(b"sovright/bound-raw/ack/v1");
/// The block hash of a keepalive that says a receiver refused a body.
pub const BOUND_RELEASE: [u8; 32] = marker(b"sovright/bound-raw/release/v1");
/// A hello's `chunk_id` flag: this peer takes bound objects, not only sends them.
pub const HELLO_RECEIVES: u16 = 1;

fn control(key: &[u8; 32], marker: &[u8; 32], flags: u16, payload: Vec<u8>) -> Vec<u8> {
    let session = RelaySession::new("0.0.0.0:0".parse().expect("an address"), "", *key);
    let length = u16::try_from(payload.len()).expect("a short payload");
    let hmac = session.compute_hmac(marker, flags, 0, length, &payload);
    let mut header = ChunkHeader::new_keepalive_authenticated(hmac);
    header.block_hash = *marker;
    header.chunk_id = flags;
    header.payload_len = length;
    Chunk::new(header, payload).to_bytes()
}

/// A receiver's word that it refused the body `block_hash` and `body_id` name, under `key`.
pub fn bound_release(key: &[u8; 32], block_hash: &[u8; 32], body_id: &[u8; 32]) -> Vec<u8> {
    control(key, &BOUND_RELEASE, 0, [*block_hash, *body_id].concat())
}

/// The body a release names, if `chunk` is framed as one. Its MAC is checked with the
/// session.
pub(crate) fn released_body(chunk: &Chunk) -> Option<SetKey> {
    let header = &chunk.header;
    let framed = header.block_hash == BOUND_RELEASE
        && header.chunk_id == 0
        && header.total_chunks == 0
        && usize::from(header.payload_len) == chunk.payload.len()
        && chunk.payload.len() == 64;
    let (block_hash, body_id) = chunk.payload.split_at_checked(32)?;
    framed.then(|| SetKey {
        block_hash: block_hash.try_into().expect("32 bytes"),
        body_id: body_id.try_into().expect("32 bytes"),
    })
}

/// A bound hello under `key`. `receives` says this peer takes bound objects; a peer that
/// only sends them says so too, so that it hears whether a relay has the path.
pub fn bound_hello(key: &[u8; 32], receives: bool) -> Vec<u8> {
    let flags = if receives { HELLO_RECEIVES } else { 0 };
    control(key, &BOUND_HELLO, flags, Vec::new())
}

/// A node's answer to a hello, under the session's key.
pub(crate) fn bound_hello_ack(key: &[u8; 32]) -> Vec<u8> {
    control(key, &BOUND_HELLO_ACK, 0, Vec::new())
}

/// Whether `chunk` is a node's answer to a hello under `key`.
pub(crate) fn is_hello_ack(chunk: &Chunk, key: &[u8; 32]) -> bool {
    let header = &chunk.header;
    header.msg_type == MessageType::Keepalive
        && header.block_hash == BOUND_HELLO_ACK
        && header.chunk_id == 0
        && header.total_chunks == 0
        && header.payload_len == 0
        && chunk.payload.is_empty()
        && RelaySession::new("0.0.0.0:0".parse().expect("an address"), "", *key).verify_hmac(
            &header.block_hash,
            0,
            0,
            0,
            &[],
            &header.hmac,
        )
}

/// The flags of a hello, if `chunk` is framed as one. Its MAC is checked with the session.
pub(crate) fn hello_flags(chunk: &Chunk) -> Option<u16> {
    let header = &chunk.header;
    let framed = header.block_hash == BOUND_HELLO
        && header.total_chunks == 0
        && header.payload_len == 0
        && chunk.payload.is_empty();
    framed.then_some(header.chunk_id)
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
pub struct BoundBlock {
    block: AssembledBlock<Vec<u8>>,
    key: SetKey,
    refusals: Option<Arc<Refusals>>,
}

impl BoundBlock {
    pub fn raw(&self) -> &[u8] {
        self.block.block()
    }

    /// The block hash the body's frames name.
    pub fn block_hash(&self) -> [u8; 32] {
        self.key.block_hash
    }

    /// The body's id, from its frames. Two bodies of one block differ here.
    pub fn body_id(&self) -> [u8; 32] {
        self.key.body_id
    }

    pub fn finish(self) {
        self.block.finish(Instant::now());
    }

    pub fn give_back(self) {
        self.block.give_back();
    }

    /// The body was refused downstream, by Zebra: give it back, as [`Self::give_back`]
    /// does, and tell every relay of this client, so that the place the body holds there is
    /// freed for a rival body of the same block. See [`bound_release`]. Only for a refusal
    /// that says the body is wrong: a relay keeps it out for a while after. How many relays
    /// the socket took the word for, which says nothing of whether it arrived.
    pub fn refuse(self) -> usize {
        let told = self
            .refusals
            .as_ref()
            .map_or(0, |refusals| refusals.tell(&self.key));
        self.block.give_back();
        told
    }
}

/// Where a client's receiver says it refused a body: every relay of that client.
#[derive(Debug)]
pub(crate) struct Refusals {
    pub(crate) socket: Arc<tokio::net::UdpSocket>,
    pub(crate) relays: Vec<SocketAddr>,
    pub(crate) key: [u8; 32],
}

impl Refusals {
    fn tell(&self, body: &SetKey) -> usize {
        let release = bound_release(&self.key, &body.block_hash, &body.body_id);
        let sent = |relay: &&SocketAddr| match self.socket.try_send_to(&release, **relay) {
            Ok(_) => true,
            Err(error) => {
                warn!(%relay, %error, "Could not tell a relay of a refused bound body");
                false
            }
        };
        self.relays.iter().filter(sent).count()
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
        pub(crate) struct $live {
            $($field: AtomicU64,)+
        }

        impl $live {
            pub(crate) fn read(&self) -> $read {
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
            Arrival::Refused(Refusal::Shared | Refusal::Outer) => &self.refused_by_pool,
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
    panics_contained,
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

counters!(
    /// A node's receive loop: the most datagrams waiting between its socket and its work, how
    /// many it handled from there, and how long that took. The longest one is the longest the
    /// socket went with nothing reading it. Empty with no queue.
    BoundIngress,
    LiveIngress,
    queue_peak,
    queue_peak_bytes,
    handled,
    handling_micros,
    longest_handling_micros,
);

impl LiveIngress {
    pub(crate) fn note_queue(&self, queue: &IngressQueue) {
        let (datagrams, bytes) = (queue.datagrams() as u64, queue.bytes() as u64);
        self.queue_peak.fetch_max(datagrams, Ordering::Relaxed);
        self.queue_peak_bytes.fetch_max(bytes, Ordering::Relaxed);
    }

    pub(crate) fn note_handled(&self, took: Duration) {
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        add(&self.handled, 1);
        add(&self.handling_micros, micros);
        self.longest_handling_micros
            .fetch_max(micros, Ordering::Relaxed);
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
    /// Where the blocks handed over say they were refused, once the client has a socket.
    refusals: Option<Arc<Refusals>>,
    #[cfg(test)]
    pub(crate) trip_next: bool,
}

impl BoundReceiver {
    pub(crate) fn new(
        key: [u8; 32],
        config: &BoundRawConfig,
        consumer: mpsc::Sender<BoundBlock>,
    ) -> Option<Self> {
        let stack = Stack::new(key, Profile::BoundSegment, frame_rules(), config.stack).ok()?;
        let bridge = stack.bridge().ok()?;
        let session = stack.session().ok()?;
        Some(Self {
            session,
            bridge,
            stack,
            consumer,
            look_again: false,
            progress: Arc::default(),
            refusals: None,
            #[cfg(test)]
            trip_next: false,
        })
    }

    pub(crate) fn tell_refusals_to(&mut self, refusals: Refusals) {
        self.refusals = Some(Arc::new(refusals));
    }

    /// After a panic. The session and bridge go and give back all they held, blocks waiting
    /// for the channel included, so a copy of those is welcome. The stack stays: blocks with
    /// the consumer keep their owners in its ledger, so a copy of one is turned away while it
    /// is held, and a record of one finished with stands for as long as it would have.
    fn start_over(self) -> Option<Self> {
        add(&self.progress.handoffs.panics_contained, 1);
        let Self {
            session,
            bridge,
            stack,
            consumer,
            progress,
            refusals,
            ..
        } = self;
        drop(session);
        drop(bridge);
        let bridge = stack.bridge().ok()?;
        let session = stack.session().ok()?;
        Some(Self {
            session,
            bridge,
            stack,
            consumer,
            look_again: false,
            progress,
            refusals,
            #[cfg(test)]
            trip_next: false,
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
        #[cfg(test)]
        assert!(!std::mem::take(&mut self.trip_next), "tripped");
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
                Ok(permit) => match (self.bridge.next_key(), self.bridge.next_block(now)) {
                    (Some(key), Some(Ok(block))) => {
                        let refusals = self.refusals.clone();
                        permit.send(BoundBlock {
                            block,
                            key,
                            refusals,
                        });
                        add(&self.progress.handoffs.blocks_to_consumer, 1);
                    }
                    (_, Some(Err(error))) => {
                        warn!(?error, "Bound block did not assemble");
                        add(&self.progress.handoffs.assembly_failures, 1);
                    }
                    (_, _) => break,
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

/// One step of a client's way in, on the client's task. This is the only way to take one: a
/// panic left alone would end that task, and the legacy path and keepalives with it. Only the
/// step is caught, and sending from that task is not one. A step
/// that says the consumer is gone ends the path, and so does a stack with no place to start
/// over in, which a start that worked rules out.
pub(crate) fn contain(
    bound: &mut Option<BoundReceiver>,
    step: impl FnOnce(&mut BoundReceiver) -> bool,
) {
    let Some(receiver) = bound else {
        return;
    };
    match catch_unwind(AssertUnwindSafe(|| step(receiver))) {
        Ok(true) => {}
        Ok(false) => {
            warn!("The bound path's consumer went, so this client takes no more bound blocks");
            *bound = None;
        }
        Err(_) => {
            error!("Bound path panicked, starting it over");
            *bound = bound.take().and_then(BoundReceiver::start_over);
        }
    }
}

/// Wait until the channel has room, or is closed. Pends for good with no channel.
pub(crate) async fn wait_for_room(consumer: Option<&mpsc::Sender<BoundBlock>>) {
    match consumer {
        Some(consumer) => drop(consumer.reserve().await),
        None => std::future::pending().await,
    }
}

/// What a node has read from its socket and not yet worked on, in order. See
/// [`BoundForwardConfig::max_queued_datagrams`]. A datagram cannot be put back once it is read,
/// so room is asked for at the most one can be.
#[derive(Debug)]
pub(crate) struct IngressQueue {
    max_datagrams: usize,
    max_bytes: usize,
    bytes: usize,
    waiting: VecDeque<(Vec<u8>, SocketAddr)>,
}

impl IngressQueue {
    /// With no config it never has room, and the socket stays as the only buffer.
    pub(crate) fn new(config: Option<&BoundForwardConfig>) -> Self {
        Self {
            max_datagrams: config.map_or(0, |config| config.max_queued_datagrams),
            max_bytes: config.map_or(0, |config| config.max_queued_bytes),
            bytes: 0,
            waiting: VecDeque::new(),
        }
    }

    pub(crate) fn has_room(&self) -> bool {
        self.waiting.len() < self.max_datagrams && self.bytes + MAX_READ_BYTES <= self.max_bytes
    }

    pub(crate) fn push(&mut self, datagram: &[u8], src: SocketAddr) {
        self.bytes += datagram.len();
        self.waiting.push_back((datagram.to_vec(), src));
    }

    pub(crate) fn pop(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        let (datagram, src) = self.waiting.pop_front()?;
        self.bytes -= datagram.len();
        Some((datagram, src))
    }

    pub(crate) fn datagrams(&self) -> usize {
        self.waiting.len()
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

/// One body whose segment 0 passed the PoW check.
#[derive(Debug)]
struct Anchor {
    body_id: [u8; 32],
    /// Its header's time, which a newer header can make too old. See [`ANCHOR_HEADER_WINDOW`].
    time: u32,
    /// The keys that pay for its place in the table, each up to a time of its own.
    paid_until: HashMap<String, Instant>,
}

impl Anchor {
    /// With nobody paying there is no anchor.
    fn stands(&self, now: Instant) -> bool {
        self.paid_until.values().any(|until| now < *until)
    }

    fn paid_by(&self, key_id: &str, now: Instant) -> bool {
        let until = self.paid_until.get(key_id);
        until.is_some_and(|until| now < *until)
    }
}

/// Why a segment 0 gets no anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnchorRefusal {
    /// Its block has all the bodies it can have.
    Bodies,
    /// Its key pays for all of this block's bodies it may. See
    /// [`MAX_BODIES_PER_KEY_PER_BLOCK`].
    KeyBodies,
    /// Its key or the table has no room.
    Room,
    /// Its header is older than the newest header here by more than
    /// [`ANCHOR_HEADER_WINDOW`].
    Old,
    /// A receiver refused this body, and it stays refused for a while. See
    /// [`BoundForwarder::release`].
    Released,
}

/// How far behind the newest header a node has anchored a header's time may be, and still
/// open an anchor. A header that far behind is refused before its PoW check, and an anchor
/// that falls that far behind a newer one goes. The newest is never taken as later than this
/// node's clock, so a header dated in the future cannot make every other look old.
///
/// A node has no chain view, so this stands in for one: a header with good PoW from long ago
/// can no longer hold the table, but a node that has seen nothing newer yet takes it. A
/// research value: consensus lets a block's time lag the chain by the median of the last 11
/// blocks, about a quarter of an hour, so this leaves room for that and for clocks.
pub const ANCHOR_HEADER_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Of one block's bodies, how many one key can pay for. A key that saw the header first can
/// then not take every place [`BoundForwardConfig::max_bodies_per_block`] gives the block.
/// An honest key needs one. With one key for the whole fleet this is the fleet's share, and
/// [`BoundForwarder::release`] is what frees a place a refused body holds.
pub const MAX_BODIES_PER_KEY_PER_BLOCK: usize = 2;

/// Where a header's time sits in it.
const HEADER_TIME: std::ops::Range<usize> = 100..104;

/// A header's time, from the header at the front of a segment 0.
fn header_time(header: &[u8]) -> u32 {
    let bytes = header.get(HEADER_TIME).and_then(|b| b.try_into().ok());
    bytes.map_or(0, u32::from_le_bytes)
}

/// This node's clock as a header's time.
fn wall_clock() -> u32 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |since| {
        u32::try_from(since.as_secs()).unwrap_or(u32::MAX)
    })
}

/// Whether a header dated `time` is too old next to `newest`.
fn too_old(time: u32, newest: u32) -> bool {
    let window = u32::try_from(ANCHOR_HEADER_WINDOW.as_secs()).unwrap_or(u32::MAX);
    time.saturating_add(window) < newest
}

/// Anchors by block, so a block's bodies can be counted. What one opens is the one body whose
/// segment 0 passed: the same header says nothing about a rival body of that block.
///
/// Nothing here pushes anything out. With no room a new anchor is refused, so a flood of
/// headers, old or new, cannot take an anchor a body is using, and it costs what it opened and
/// no more.
///
/// An anchor stands as long as a key pays for it, and in no other way, so everything in the
/// table is inside some key's share. [`BoundForwardConfig::max_anchors`] is a limit of its own
/// on top of that, not what holds the keys to their shares.
///
/// - The key that opens an anchor pays for it, and so does any key that uses it and has room,
///   each for [`BoundForwardConfig::anchor_ttl`] from its own last use. So a key with room has
///   the same hold on a body under way whoever opened it.
/// - A payment is its key's own. Another key's use neither extends it nor ends it, and neither
///   does a session going or the key being revoked, so leaving and coming back frees nothing.
/// - A key with no room gets through on what others pay and extends nothing, and each such use
///   is counted. When the last payment ends the anchor goes, whoever is still using it. What
///   comes next of that body waits for its segment 0, and a copy of that opens the anchor again
///   once the key has room.
///
/// That last rule has a price: a key at its share can have a body under way stopped, however
/// sound its anchor, when whoever paid moves on. Keeping the anchor would have to put it on
/// nobody or past a share, and making room would push out another body of that key. Keys that
/// work together then stay inside their shares, and so a full table takes as many keys as the
/// table has shares.
#[derive(Debug, Default)]
struct Anchors {
    blocks: HashMap<[u8; 32], Vec<Anchor>>,
    /// Uses by a key with no room to pay. They renewed nothing.
    uses_without_room: u64,
    /// The time of the newest header that passed its PoW check here.
    newest: Option<u32>,
    /// Bodies a receiver refused, each until a time.
    released: HashMap<SetKey, Instant>,
}

impl Anchors {
    fn len(&self) -> usize {
        self.blocks.values().map(Vec::len).sum()
    }

    /// What `key_id` pays for now.
    fn of_key(&self, key_id: &str, now: Instant) -> usize {
        let pays = |anchor: &&Anchor| anchor.paid_by(key_id, now);
        self.blocks.values().flatten().filter(pays).count()
    }

    fn find(&mut self, key: &SetKey, now: Instant) -> Option<&mut Anchor> {
        let bodies = self.blocks.get_mut(&key.block_hash)?;
        let this_body = |anchor: &&mut Anchor| anchor.body_id == key.body_id && anchor.stands(now);
        bodies.iter_mut().find(this_body)
    }

    /// Whether this very body has an anchor, used now by `key_id`, which pays for it if it can.
    fn used(
        &mut self,
        key: &SetKey,
        key_id: &str,
        now: Instant,
        config: &BoundForwardConfig,
    ) -> bool {
        let room = self.of_key(key_id, now) < config.max_anchors_per_key;
        let Some(anchor) = self.find(key, now) else {
            return false;
        };
        if room || anchor.paid_by(key_id, now) {
            let until = now + config.anchor_ttl;
            anchor.paid_until.insert(key_id.to_string(), until);
        } else {
            self.uses_without_room += 1;
        }
        true
    }

    /// The newest header's time, never later than `wall`.
    fn newest(&self, wall: u32) -> Option<u32> {
        self.newest.map(|newest| newest.min(wall))
    }

    /// Whether a header dated `time` would, once it passed, make an anchor here too old.
    fn would_age_any(&self, time: u32, wall: u32) -> bool {
        let newest = time.min(wall);
        let anchors = self.blocks.values().flatten();
        anchors
            .into_iter()
            .any(|anchor| too_old(anchor.time, newest))
    }

    /// A header dated `time` passed its PoW check. What it makes too old goes.
    fn passed(&mut self, time: u32, wall: u32) {
        self.newest = Some(self.newest.map_or(time, |newest| newest.max(time)));
        let Some(newest) = self.newest(wall) else {
            return;
        };
        for bodies in self.blocks.values_mut() {
            bodies.retain(|anchor| !too_old(anchor.time, newest));
        }
        self.blocks.retain(|_, bodies| !bodies.is_empty());
    }

    fn refusal(
        &mut self,
        key: &SetKey,
        key_id: &str,
        time: u32,
        now: Instant,
        config: &BoundForwardConfig,
    ) -> Option<AnchorRefusal> {
        self.forget_lapsed(now);
        if self.find(key, now).is_some() {
            return None;
        }
        if self.released.contains_key(key) {
            return Some(AnchorRefusal::Released);
        }
        if self
            .newest(wall_clock())
            .is_some_and(|newest| too_old(time, newest))
        {
            return Some(AnchorRefusal::Old);
        }
        let of_block = self.blocks.get(&key.block_hash);
        let paid = |anchor: &&Anchor| anchor.paid_by(key_id, now);
        let mine = of_block.map_or(0, |bodies| bodies.iter().filter(paid).count());
        if mine >= MAX_BODIES_PER_KEY_PER_BLOCK {
            return Some(AnchorRefusal::KeyBodies);
        }
        let bodies = of_block.map_or(0, Vec::len);
        if bodies >= config.max_bodies_per_block {
            return Some(AnchorRefusal::Bodies);
        }
        let room = self.len() < config.max_anchors
            && self.of_key(key_id, now) < config.max_anchors_per_key;
        (!room).then_some(AnchorRefusal::Room)
    }

    /// Whoever opens an anchor pays for it. A key that brings a body with one has used it.
    fn add(
        &mut self,
        key: SetKey,
        key_id: &str,
        time: u32,
        now: Instant,
        config: &BoundForwardConfig,
    ) {
        if self.used(&key, key_id, now, config) {
            return;
        }
        let until = now + config.anchor_ttl;
        self.blocks.entry(key.block_hash).or_default().push(Anchor {
            body_id: key.body_id,
            time,
            paid_until: HashMap::from([(key_id.to_string(), until)]),
        });
    }

    /// A receiver refused this body: its anchor goes, whoever paid, and a copy of its
    /// segment 0 opens none until `until`. At most `limit` such bodies are kept, the ones
    /// closest to their end going first. Whether it had an anchor.
    fn release(&mut self, key: SetKey, until: Instant, limit: usize) -> bool {
        let mut had = false;
        if let Some(bodies) = self.blocks.get_mut(&key.block_hash) {
            let before = bodies.len();
            bodies.retain(|anchor| anchor.body_id != key.body_id);
            had = bodies.len() < before;
            if bodies.is_empty() {
                self.blocks.remove(&key.block_hash);
            }
        }
        self.released.insert(key, until);
        while self.released.len() > limit {
            let first = self.released.iter().min_by_key(|(_, until)| **until);
            let Some(first) = first.map(|(key, _)| *key) else {
                break;
            };
            self.released.remove(&first);
        }
        had
    }

    fn forget_lapsed(&mut self, now: Instant) {
        self.released.retain(|_, until| now < *until);
        for bodies in self.blocks.values_mut() {
            for anchor in bodies.iter_mut() {
                anchor.paid_until.retain(|_, until| now < *until);
            }
            bodies.retain(|anchor| !anchor.paid_until.is_empty());
        }
        self.blocks.retain(|_, bodies| !bodies.is_empty());
    }
}

/// How long chunks of an object a node has just let go count as left over from that decode,
/// whether or not the object then went anywhere: the shards the decode did not need come in
/// the same burst. This is no send and counts as none. A research value: a copy that comes
/// later than this, after a send that never happened, goes through.
pub const RELEASE_LEFTOVER: Duration = Duration::from_millis(500);

/// One object's sends through one session. A record with no sends says it was let go and
/// never went out.
#[derive(Clone, Copy, Debug)]
struct Sends {
    first: Instant,
    last: Instant,
    count: u32,
    released: Instant,
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
        if sends.count == 0 {
            return now.saturating_duration_since(sends.released) >= RELEASE_LEFTOVER;
        }
        if now.saturating_duration_since(sends.last) < config.resend_after {
            return false;
        }
        let lapsed = now.saturating_duration_since(sends.first) >= config.resend_window;
        lapsed || sends.count <= config.max_resends
    }

    /// The object was let go, and nothing says yet that it went anywhere.
    fn note_released(&mut self, object: Node, now: Instant, config: &BoundForwardConfig) {
        if let Some(sends) = self.sends.get_mut(&object) {
            sends.released = now;
            return;
        }
        let record = Sends {
            first: now,
            last: now,
            count: 0,
            released: now,
        };
        self.insert(object, record, config);
    }

    /// The object went out. Only this counts against the session's sends.
    fn note(&mut self, object: Node, now: Instant, config: &BoundForwardConfig) {
        let fresh = Sends {
            first: now,
            last: now,
            count: 1,
            released: now,
        };
        match self.sends.get_mut(&object) {
            Some(sends)
                if sends.count == 0
                    || now.saturating_duration_since(sends.first) >= config.resend_window =>
            {
                *sends = Sends {
                    released: sends.released,
                    ..fresh
                };
            }
            Some(sends) => {
                sends.last = now;
                sends.count += 1;
            }
            None => self.insert(object, fresh, config),
        }
    }

    fn insert(&mut self, object: Node, record: Sends, config: &BoundForwardConfig) {
        self.sends.insert(object, record);
        self.order.push_back(object);
        if self.order.len() > config.max_forwarded {
            self.forget_oldest();
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
    key_id: String,
    key_budget: Budget,
    budget: Budget,
    session: Assembler,
    forwarded: Forwarded,
    unanchored: VecDeque<Waiting>,
    /// A spare here has all it needs and was refused its decode for room. See
    /// [`BoundForwarder::revive`].
    stuck: bool,
}

/// A decoded object whose segment 0 has not passed.
#[derive(Debug)]
struct Waiting {
    key: SetKey,
    object: DecodedObject,
    since: Instant,
}

/// What a node wants of an object a session has: nothing once it waits for its segment 0 or
/// its record holds it back, and otherwise all of it.
fn interest(
    unanchored: &VecDeque<Waiting>,
    forwarded: &Forwarded,
    object: &Node,
    now: Instant,
    config: &BoundForwardConfig,
) -> Interest {
    let waiting = unanchored
        .iter()
        .any(|kept| kept.object.object_id() == *object);
    if !waiting && forwarded.allows(object, now, config) {
        Interest::New
    } else {
        Interest::Done
    }
}

/// What a budget has here, on the shelf as well: moving there is no way of looking light.
fn share_of(budget: &Budget) -> usize {
    let used = budget.used();
    used.held_bytes + used.spare_bytes
}

impl BoundPeer {
    fn share(&self) -> usize {
        share_of(&self.budget)
    }

    fn key_share(&self) -> usize {
        share_of(&self.key_budget)
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
    /// Objects the node let go on, whether or not anyone was there to take them.
    pub objects_released: u64,
    /// Of those, the ones that went out to at least one peer, every datagram of them. Only
    /// these count against their session's sends.
    pub objects_sent_on: u64,
    /// Objects whose decode was refused for room when their last chunk came, and that
    /// decoded later, once there was room.
    pub spares_revived: u64,
    pub objects_waiting_for_segment_0: usize,
    pub waiting_pushed_out: u64,
    /// Objects that waited for their segment 0 and gave way to a session holding less, when
    /// the pool had no room.
    pub waiting_gave_way: u64,
    /// Objects that waited for their segment 0 until their time was up.
    pub waiting_expired: u64,
    pub anchors: usize,
    /// Segments 0 refused because their block had all the bodies it can have.
    pub anchors_refused_for_bodies: u64,
    /// Segments 0 refused because their key paid for all of their block's bodies it may.
    /// See [`MAX_BODIES_PER_KEY_PER_BLOCK`].
    pub anchors_refused_for_key_bodies: u64,
    /// Segments 0 refused because their key or the table had no room for an anchor.
    pub anchors_refused_for_room: u64,
    /// Segments 0 refused, before their PoW check, for a header too far behind the newest.
    /// See [`ANCHOR_HEADER_WINDOW`].
    pub anchors_refused_for_age: u64,
    /// Segments 0 of a body a receiver refused, while that refusal stands.
    pub anchors_refused_as_released: u64,
    /// Anchors a receiver's refusal took away.
    pub anchors_released: u64,
    /// Uses of an anchor by a key with no room to pay for it. They got through and renewed
    /// nothing, so what they used can go while they are using it.
    pub anchor_uses_without_room: u64,
    /// Sessions that lost what they held here to a panic. See [`BoundForwarder`].
    pub sessions_lost_to_a_panic: u64,
    /// Times everything here went because of a panic nobody could be held to.
    pub panic_resets: u64,
    pub ingress: BoundIngress,
}

/// An object a node may send on, and the session it came from. That session already has
/// it, so it is left out of the fan-out, whatever datagram released the object.
#[derive(Debug)]
pub(crate) struct Outgoing {
    pub(crate) object: Encoded,
    pub(crate) from: SocketAddr,
}

/// What a datagram came to on a node.
pub(crate) enum BoundStep {
    /// A1 to A4. Nothing changed.
    Invalid,
    /// Objects to send on, all `n` shards of each. Nothing records them as sent: the node
    /// does, with [`BoundForwarder::sent`], once a send of one has gone out.
    Forward(Vec<Outgoing>),
    /// A panic took the session it came from.
    Lost,
}

/// Where a test stops a step with a panic, after what that step changes. Each one fires once.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trip {
    Arrived(SocketAddr),
    GaveWay(SocketAddr),
    BetweenSteps,
    Drained,
    Noted(SocketAddr),
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
/// All sessions share a pool, and each has limits of its own inside it. Between the two
/// stands the budget of the verified key, which all sessions of that key share: a source port
/// costs nothing, so a limit has to hold to the key. How many keys a fleet has is not known
/// here, and with a single key its limit binds everybody as one. Sessions that came in
/// without authentication are one key.
///
/// Sharing costs what separate budgets gave, that one session cannot touch another, so a
/// session that is refused can ask for room, on these terms:
///
/// - It holds something itself, open, decoded or on its shelf. A session holding nothing
///   earns nothing, or anybody could push with no cost at all.
/// - If the pool refused, the one that moves belongs to the key with the largest share, as
///   long as that is more than the share of the key asking, shelves and all sessions
///   counted. Failing that it is a session of its own key.
/// - If its key refused, only a session of that key holding more than it does can move.
/// - What moves is the longest-waiting open object, to its own session's shelf, where it can
///   still finish. If the shelf cannot take it, nothing moves and the newcomer is refused.
///   Nothing already here is deleted, and that goes for decoded objects waiting too.
///
/// A session the pool or its key has no place for gets nothing here, and a session holding
/// nothing waits for what the pool holds to finish or expire.
///
/// A real header with a body of someone's own passes here as its own set. Telling such a
/// body from the real one is for strict validation and the node behind the consumer. Each
/// such body takes one of its block's places, so the right one can be turned away once they
/// are gone. See [`Anchors`] and [`BoundForwardConfig::max_bodies_per_block`].
///
/// The PoW check says nothing of a header's age, and the node has no chain source to ask, so
/// any old header with a valid proof opens an anchor. Limits bound that and do not stop it.
///
/// Catching a panic says nothing by itself about what it left half done. So each step here
/// belongs to one session, whose content it works on, and that session goes if the step
/// panics: all it held comes back by the same `Drop` as any other end, and what it sends next
/// starts again. This has been tried at the points in [`Trip`] and nowhere else, and it covers
/// no other code on the path. Stopped at those points, others were left with this:
///
/// | Stopped after                 | What stays                                         |
/// |-------------------------------|----------------------------------------------------|
/// | A session moved its objects   | Moved. They can still finish on its shelf          |
/// | An anchor went in             | True, since its PoW check passed                   |
/// | Waiting objects were gathered | Those objects are gone, and their sessions can resend |
/// | A send was recorded           | The record goes with its session                   |
///
/// A panic between those steps belongs to nobody, so everything on this path goes
/// ([`Self::start_over`]). That costs every session what it had open, and nothing here stops
/// it being repeated. No datagram is known to reach it, which rests on reading the code.
#[derive(Debug)]
pub(crate) struct BoundForwarder {
    config: BoundForwardConfig,
    rules: FrameRules,
    pool: Budget,
    peers: HashMap<SocketAddr, BoundPeer>,
    anchors: Anchors,
    datagrams_without_a_place: u64,
    arrivals: LiveArrivals,
    frames_rejected: u64,
    pow_refused: u64,
    pow_indeterminate: u64,
    objects_released: u64,
    objects_sent_on: u64,
    spares_revived: u64,
    waiting_pushed_out: u64,
    waiting_gave_way: u64,
    waiting_expired: u64,
    anchors_refused_for_bodies: u64,
    anchors_refused_for_key_bodies: u64,
    anchors_refused_for_room: u64,
    anchors_refused_for_age: u64,
    anchors_refused_as_released: u64,
    anchors_released: u64,
    sessions_lost_to_a_panic: u64,
    panic_resets: u64,
    #[cfg(test)]
    pub(crate) trips: Vec<Trip>,
}

impl BoundForwarder {
    pub(crate) fn new(config: BoundForwardConfig) -> Result<Self, InvalidLimits> {
        if config.max_anchors == 0 {
            return Err(InvalidLimits("max_anchors"));
        }
        if config.max_anchors_per_key == 0 {
            return Err(InvalidLimits("max_anchors_per_key"));
        }
        if config.max_bodies_per_block == 0 {
            return Err(InvalidLimits("max_bodies_per_block"));
        }
        Ok(Self {
            config,
            rules: frame_rules(),
            pool: {
                Budget::new(config.key_budget)?;
                Budget::new(config.pool)?
            },
            peers: HashMap::new(),
            anchors: Anchors::default(),
            datagrams_without_a_place: 0,
            arrivals: LiveArrivals::default(),
            frames_rejected: 0,
            pow_refused: 0,
            pow_indeterminate: 0,
            objects_released: 0,
            objects_sent_on: 0,
            spares_revived: 0,
            waiting_pushed_out: 0,
            waiting_gave_way: 0,
            waiting_expired: 0,
            anchors_refused_for_bodies: 0,
            anchors_refused_for_key_bodies: 0,
            anchors_refused_for_room: 0,
            anchors_refused_for_age: 0,
            anchors_refused_as_released: 0,
            anchors_released: 0,
            sessions_lost_to_a_panic: 0,
            panic_resets: 0,
            #[cfg(test)]
            trips: Vec::new(),
        })
    }

    #[cfg(test)]
    fn trip(&mut self, at: Trip) {
        if let Some(found) = self.trips.iter().position(|trip| *trip == at) {
            self.trips.remove(found);
            panic!("tripped at {at:?}");
        }
    }

    /// Everything but the counts. Every reservation comes back with the sessions, and the
    /// node's sessions are not here, so they stay, and what they send next starts again.
    pub(crate) fn start_over(&mut self) {
        error!(
            sessions = self.peers.len(),
            "Bound path panicked outside any one session, starting it over"
        );
        self.peers.clear();
        self.anchors.blocks.clear();
        self.panic_resets += 1;
    }

    /// `step`, which works on what `session` holds. See the note on [`BoundForwarder`].
    fn only_for<T>(&mut self, session: SocketAddr, step: impl FnOnce(&mut Self) -> T) -> Option<T> {
        match catch_unwind(AssertUnwindSafe(|| step(self))) {
            Ok(result) => Some(result),
            Err(_) => {
                error!(peer = %session, "Bound path panicked, dropping what this session held");
                self.peers.remove(&session);
                self.sessions_lost_to_a_panic += 1;
                None
            }
        }
    }

    /// What all sessions of a key hold.
    #[cfg(test)]
    fn key_used(&self, key_id: &str) -> BoundUsed {
        let peer = self.peers.values().find(|peer| peer.key_id == key_id);
        peer.map_or_else(BoundUsed::default, |peer| peer.key_budget.used())
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
            objects_released: self.objects_released,
            objects_sent_on: self.objects_sent_on,
            spares_revived: self.spares_revived,
            objects_waiting_for_segment_0: self.peers.values().map(|p| p.unanchored.len()).sum(),
            waiting_pushed_out: self.waiting_pushed_out,
            waiting_gave_way: self.waiting_gave_way,
            waiting_expired: self.waiting_expired,
            anchors: self.anchors.len(),
            anchors_refused_for_bodies: self.anchors_refused_for_bodies,
            anchors_refused_for_key_bodies: self.anchors_refused_for_key_bodies,
            anchors_refused_for_room: self.anchors_refused_for_room,
            anchors_refused_for_age: self.anchors_refused_for_age,
            anchors_refused_as_released: self.anchors_refused_as_released,
            anchors_released: self.anchors_released,
            anchor_uses_without_room: self.anchors.uses_without_room,
            sessions_lost_to_a_panic: self.sessions_lost_to_a_panic,
            panic_resets: self.panic_resets,
            ingress: BoundIngress::default(),
        }
    }

    fn forwarded_records(&self) -> usize {
        let peers = self.peers.values();
        peers.map(|peer| peer.forwarded.len()).sum()
    }

    /// The budget all sessions of `key_id` share. It lasts as long as they do.
    fn key_budget(&self, key_id: &str) -> Option<Budget> {
        match self.peers.values().find(|peer| peer.key_id == key_id) {
            Some(peer) => Some(peer.key_budget.clone()),
            None => Budget::within(self.config.key_budget, &self.pool).ok(),
        }
    }

    fn peer(&mut self, src: SocketAddr, key: [u8; 32], key_id: &str) -> Option<&mut BoundPeer> {
        let moved_on = |peer: &BoundPeer| peer.key != key || peer.key_id != key_id;
        if self.peers.get(&src).is_some_and(moved_on) {
            self.peers.remove(&src);
        }
        if !self.peers.contains_key(&src) {
            let key_budget = self.key_budget(key_id)?;
            let budget = Budget::within(self.config.session_budget, &key_budget).ok()?;
            let verifier = Verifier::new(key, Profile::BoundSegment);
            let limits = node_assembler_limits();
            let Ok(session) = Assembler::new(verifier, budget.clone(), limits) else {
                self.datagrams_without_a_place += 1;
                return None;
            };
            let peer = BoundPeer {
                key,
                key_id: key_id.to_string(),
                key_budget,
                budget,
                session,
                forwarded: Forwarded::default(),
                unanchored: VecDeque::new(),
                stuck: false,
            };
            self.peers.insert(src, peer);
        }
        self.peers.get_mut(&src)
    }

    fn arrive(
        &mut self,
        src: SocketAddr,
        key: [u8; 32],
        key_id: &str,
        datagram: &[u8],
        now: Instant,
    ) -> Option<Arrival> {
        let config = self.config;
        let BoundPeer {
            session,
            forwarded,
            unanchored,
            ..
        } = self.peer(src, key, key_id)?;
        let arrival = session.receive_if(datagram, now, |object| {
            interest(unanchored, forwarded, object, now, &config)
        });
        #[cfg(test)]
        if !matches!(arrival, Arrival::Refused(_)) {
            self.trip(Trip::Arrived(src));
        }
        Some(arrival)
    }

    /// The pool, or `src`'s key, had no room for it. See the note on [`BoundForwarder`].
    fn someone_heavier_gives_way(&mut self, src: SocketAddr, refusal: Refusal) -> bool {
        let Some(asking) = self.peers.get(&src).filter(|peer| peer.share() > 0) else {
            return false;
        };
        let (own, own_key) = (asking.share(), asking.key_share());
        let heavier = |peer: &BoundPeer| {
            if peer.key_id == asking.key_id {
                peer.share() > own
            } else {
                refusal == Refusal::Outer && peer.key_share() > own_key
            }
        };
        // What waits holds bytes and no open place, so it makes room only for a budget that
        // is short of bytes.
        let (used, limits) = match refusal {
            Refusal::Outer => (self.pool.used(), self.config.pool),
            _ => (asking.key_budget.used(), self.config.key_budget),
        };
        let waiting_makes_room = used.objects < limits.max_objects;
        let can_give = |peer: &BoundPeer| {
            peer.session.has_open() || (waiting_makes_room && !peer.unanchored.is_empty())
        };
        let others = self
            .peers
            .iter()
            .filter(|(addr, peer)| **addr != src && can_give(peer) && heavier(peer));
        let weight =
            |peer: &BoundPeer| (peer.key_id != asking.key_id, peer.key_share(), peer.share());
        let Some((heaviest, _)) = others.max_by_key(|(_, peer)| weight(peer)) else {
            return false;
        };
        let heaviest = *heaviest;
        // An open object moves to the shelf and can still finish there. Failing that, what
        // waits for its segment 0 goes, oldest first: it is the only copy here, and its
        // session can send it again.
        let give_way = |this: &mut Self| {
            let Some(peer) = this.peers.get_mut(&heaviest) else {
                return false;
            };
            let mut moved = peer.session.give_way();
            if !moved && waiting_makes_room && peer.unanchored.pop_front().is_some() {
                this.waiting_gave_way += 1;
                moved = true;
            }
            #[cfg(test)]
            this.trip(Trip::GaveWay(heaviest));
            moved
        };
        // If it panicked, what it held is back in the pool, and that is room as well.
        self.only_for(heaviest, give_way).unwrap_or(true)
    }

    pub(crate) fn take(
        &mut self,
        src: SocketAddr,
        key: [u8; 32],
        key_id: &str,
        datagram: &[u8],
        now: Instant,
        validate: impl Fn(&[u8]) -> PowResult,
    ) -> BoundStep {
        let arrive = |this: &mut Self| this.arrive(src, key, key_id, datagram, now);
        let Some(mut arrival) = self.only_for(src, arrive) else {
            return BoundStep::Lost;
        };
        if let Some(Arrival::Refused(refusal @ (Refusal::Shared | Refusal::Outer))) = arrival
            && self.someone_heavier_gives_way(src, refusal)
        {
            let Some(again) = self.only_for(src, arrive) else {
                return BoundStep::Lost;
            };
            arrival = again;
        }
        if let Some(arrival) = &arrival {
            self.arrivals.note(arrival);
        }
        if let Some(Arrival::Refused(_)) = arrival
            && let Some(peer) = self.peers.get_mut(&src)
        {
            peer.stuck = peer.session.has_ready_spares();
        }
        #[cfg(test)]
        self.trip(Trip::BetweenSteps);
        match arrival {
            Some(Arrival::Invalid(_)) => BoundStep::Invalid,
            Some(Arrival::Decoded(decoded)) => {
                let admit = |this: &mut Self| this.admit(src, decoded, now, validate);
                let ready = self.only_for(src, admit).unwrap_or_default();
                BoundStep::Forward(self.send_on_each(ready, now))
            }
            _ => BoundStep::Forward(Vec::new()),
        }
    }

    /// Spares that have all they need and were refused their decode for room, tried again:
    /// for after something has given room back. Each session's spares stay for the next try
    /// while there is still no room. What decodes goes on as [`Self::take`]'s would.
    pub(crate) fn revive(
        &mut self,
        now: Instant,
        validate: impl Fn(&[u8]) -> PowResult,
    ) -> Vec<Outgoing> {
        let stuck: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.stuck)
            .map(|(addr, _)| *addr)
            .collect();
        let mut ready = Vec::new();
        for src in stuck {
            let config = self.config;
            let revive = |this: &mut Self| {
                let peer = this.peers.get_mut(&src)?;
                let BoundPeer {
                    session,
                    forwarded,
                    unanchored,
                    stuck,
                    ..
                } = peer;
                let arrivals = session.revive(now, |object| {
                    interest(unanchored, forwarded, object, now, &config)
                });
                *stuck = session.has_ready_spares();
                Some(arrivals)
            };
            let Some(arrivals) = self.only_for(src, revive).flatten() else {
                continue;
            };
            for arrival in arrivals {
                if let Arrival::Decoded(decoded) = arrival {
                    self.spares_revived += 1;
                    let admit = |this: &mut Self| this.admit(src, decoded, now, &validate);
                    ready.extend(self.only_for(src, admit).unwrap_or_default());
                }
            }
        }
        self.send_on_each(ready, now)
    }

    fn reject(&mut self, src: SocketAddr, object: Node, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&src) {
            peer.session.reject(object, now);
        }
    }

    /// What `decoded` lets go on, each with the session it came from.
    fn admit(
        &mut self,
        src: SocketAddr,
        decoded: DecodedObject,
        now: Instant,
        validate: impl Fn(&[u8]) -> PowResult,
    ) -> Vec<(SocketAddr, DecodedObject)> {
        if decoded.msg_type() != MSG_RAW_SEGMENT {
            return Vec::new();
        }
        let Ok(segment) = verify(decoded.content(), &self.rules) else {
            self.frames_rejected += 1;
            self.reject(src, decoded.object_id(), now);
            return Vec::new();
        };
        let key = segment.key();
        let Some(key_id) = self.peers.get(&src).map(|peer| peer.key_id.clone()) else {
            return Vec::new();
        };
        if segment.index() != 0 {
            if self.anchors.used(&key, &key_id, now, &self.config) {
                return vec![(src, decoded)];
            }
            if let Some(peer) = self.peers.get_mut(&src) {
                if peer.unanchored.len() >= self.config.max_unanchored {
                    peer.unanchored.pop_front();
                    self.waiting_pushed_out += 1;
                }
                peer.unanchored.push_back(Waiting {
                    key,
                    object: decoded,
                    since: now,
                });
            }
            return Vec::new();
        }
        // Ahead of the PoW check, which is the costly part. A body turned away leaves no
        // record: nothing is wrong with it, and it can come again when there is room.
        let header = &segment.payload()[..ZCASH_FULL_HEADER_SIZE];
        let (time, wall) = (header_time(header), wall_clock());
        let mut checked = false;
        if let Some(refusal) = self.anchors.refusal(&key, &key_id, time, now, &self.config) {
            // Without room, a newer header may still make room by aging out what holds it.
            // Only a header that passed can, so this one is checked first.
            let may_make_room = matches!(refusal, AnchorRefusal::Room | AnchorRefusal::Bodies);
            if !may_make_room || !self.anchors.would_age_any(time, wall) {
                self.count_refusal(refusal);
                return Vec::new();
            }
            if !self.pow_passes(src, &decoded, header, now, &validate) {
                return Vec::new();
            }
            checked = true;
            self.anchors.passed(time, wall);
            if let Some(refusal) = self.anchors.refusal(&key, &key_id, time, now, &self.config) {
                self.count_refusal(refusal);
                return Vec::new();
            }
        }
        if !checked && !self.pow_passes(src, &decoded, header, now, &validate) {
            return Vec::new();
        }
        self.anchors.passed(time, wall);
        self.anchors.add(key, &key_id, time, now, &self.config);
        let mut ready = vec![(src, decoded)];
        for (addr, peer) in &mut self.peers {
            let (anchored, rest): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut peer.unanchored)
                .into_iter()
                .partition(|waiting| waiting.key == key);
            peer.unanchored = rest;
            ready.extend(anchored.into_iter().map(|waiting| (*addr, waiting.object)));
        }
        #[cfg(test)]
        self.trip(Trip::Drained);
        ready
    }

    fn pow_passes(
        &mut self,
        src: SocketAddr,
        decoded: &DecodedObject,
        header: &[u8],
        now: Instant,
        validate: &impl Fn(&[u8]) -> PowResult,
    ) -> bool {
        match validate(header) {
            PowResult::Valid => true,
            PowResult::Invalid => {
                self.pow_refused += 1;
                self.reject(src, decoded.object_id(), now);
                false
            }
            PowResult::Indeterminate => {
                self.pow_indeterminate += 1;
                false
            }
        }
    }

    fn count_refusal(&mut self, refusal: AnchorRefusal) {
        let count = match refusal {
            AnchorRefusal::Bodies => &mut self.anchors_refused_for_bodies,
            AnchorRefusal::KeyBodies => &mut self.anchors_refused_for_key_bodies,
            AnchorRefusal::Room => &mut self.anchors_refused_for_room,
            AnchorRefusal::Old => &mut self.anchors_refused_for_age,
            AnchorRefusal::Released => &mut self.anchors_refused_as_released,
        };
        *count += 1;
    }

    /// A receiver refused the body `key` names, downstream of here: its anchor goes, which
    /// frees its place in its block and in the table, and what comes next of it goes no
    /// further. A copy of its segment 0 opens no anchor again for
    /// [`BoundForwardConfig::anchor_ttl`], so a sender cannot put it straight back. Whether
    /// it had an anchor.
    ///
    /// This takes the receiver's word. Only a key with the full role is asked, and that key
    /// can already send whatever it likes; see the node.
    pub(crate) fn release(&mut self, key: SetKey, now: Instant) -> bool {
        let until = now + self.config.anchor_ttl;
        let had = self.anchors.release(key, until, self.config.max_anchors);
        self.anchors_released += u64::from(had);
        for peer in self.peers.values_mut() {
            peer.unanchored.retain(|waiting| waiting.key != key);
        }
        had
    }

    fn send_on_each(
        &mut self,
        ready: Vec<(SocketAddr, DecodedObject)>,
        now: Instant,
    ) -> Vec<Outgoing> {
        let mut objects = Vec::with_capacity(ready.len());
        for (from, object) in ready {
            let send = |this: &mut Self| this.send_on(from, object, now);
            objects.extend(self.only_for(from, send).flatten());
        }
        objects
    }

    /// The object to send on, if its session's record lets it go. No send is recorded here:
    /// one written before the send would hold back the next copy, and count against the
    /// session, for a send that never happened, with no peer to send to or a socket that
    /// refused. Only that it was let go is, for [`RELEASE_LEFTOVER`].
    fn send_on(
        &mut self,
        from: SocketAddr,
        decoded: DecodedObject,
        now: Instant,
    ) -> Option<Outgoing> {
        let shape = decoded.shape();
        let object = encode(shape.msg_type, shape.n, shape.k, decoded.content())?;
        let config = self.config;
        let forwarded = &mut self.peers.get_mut(&from)?.forwarded;
        let id = object.object_id;
        if id != decoded.object_id() || !forwarded.allows(&id, now, &config) {
            return None;
        }
        forwarded.note_released(id, now, &config);
        self.keep_records_within_limit();
        self.objects_released += 1;
        Some(Outgoing { object, from })
    }

    /// `object` from `from` went out to at least one peer, every datagram of it. Only now
    /// does it count against that session's sends. A session that went meanwhile has no
    /// record to write.
    pub(crate) fn sent(&mut self, from: SocketAddr, object: Node, now: Instant) {
        let note = |this: &mut Self| {
            let config = this.config;
            let Some(peer) = this.peers.get_mut(&from) else {
                return;
            };
            peer.forwarded.note(object, now, &config);
            this.objects_sent_on += 1;
            #[cfg(test)]
            this.trip(Trip::Noted(from));
            this.keep_records_within_limit();
        };
        self.only_for(from, note);
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
        let can_wait = WAITING_TTL;
        for peer in self.peers.values_mut() {
            peer.session.expire(now);
            peer.forwarded.forget_lapsed(now, window);
            let waiting = peer.unanchored.len();
            let in_time = |kept: &Waiting| now.saturating_duration_since(kept.since) < can_wait;
            peer.unanchored.retain(in_time);
            self.waiting_expired += (waiting - peer.unanchored.len()) as u64;
        }
        self.anchors.forget_lapsed(now);
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
            bound.take(src, [1; 32], FLEET, &datagrams[0], now, accept),
            BoundStep::Forward(_)
        ));
        assert_eq!(bound.peers.len(), 1);

        assert!(matches!(
            bound.take(src, [2; 32], FLEET, &datagrams[1], now, accept),
            BoundStep::Invalid
        ));
        assert_eq!(bound.peers[&src].key, [2; 32]);

        bound.tidy(now, |_| false);
        assert!(bound.peers.is_empty());
    }

    const KEY: [u8; 32] = [1; 32];
    const FLEET: &str = "fleet";

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
        send_as(bound, FLEET, src, datagrams, now)
    }

    /// [`send`] from a session verified as `key_id`.
    fn send_as(
        bound: &mut BoundForwarder,
        key_id: &str,
        src: SocketAddr,
        datagrams: &[Vec<u8>],
        now: Instant,
    ) -> usize {
        let accept = |_: &[u8]| PowResult::Valid;
        let mut forwarded = 0;
        for datagram in datagrams {
            match bound.take(src, KEY, key_id, datagram, now, accept) {
                BoundStep::Forward(objects) => {
                    forwarded += objects.len();
                    // As the node does once a send went out.
                    for outgoing in objects {
                        bound.sent(outgoing.from, outgoing.object.object_id, now);
                    }
                }
                BoundStep::Invalid => panic!("a sealed datagram is valid"),
                BoundStep::Lost => {}
            }
        }
        forwarded
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

    /// What `take` lets go is not yet sent. Until the node says it went, nothing holds the
    /// next copy back, and a session's sends are what went out.
    #[test]
    fn an_object_let_go_and_never_sent_leaves_no_record() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let datagrams = body(7);
        let accept = |_: &[u8]| PowResult::Valid;
        let take = |bound: &mut BoundForwarder, now: Instant| {
            let steps = datagrams
                .iter()
                .map(|datagram| bound.take(addr(1), KEY, FLEET, datagram, now, accept))
                .collect::<Vec<_>>();
            let objects = steps.into_iter().map(|step| match step {
                BoundStep::Forward(objects) => objects,
                _ => Vec::new(),
            });
            objects.flatten().collect::<Vec<_>>()
        };

        let first = take(&mut bound, now);
        assert_eq!(first.len(), 1);
        assert_eq!(bound.usage().objects_sent_on, 0);
        assert_eq!(bound.usage().objects_released, 1);
        assert!(
            take(&mut bound, now).is_empty(),
            "left over from that decode"
        );

        let later = now + RELEASE_LEFTOVER;
        let again = take(&mut bound, later);
        assert_eq!(again.len(), 1, "never sent, so it goes inside resend_after");
        bound.sent(again[0].from, again[0].object.object_id, later);
        assert_eq!(bound.usage().objects_sent_on, 1);
        let soon = later + RELEASE_LEFTOVER;
        assert!(soon < later + bound.config.resend_after);
        assert!(
            take(&mut bound, soon).is_empty(),
            "sent, so held to resend_after"
        );
    }

    /// Objects let go by another session's segment 0 say which session they came from, so
    /// the node can leave that session out.
    #[test]
    fn objects_let_go_by_a_segment_0_keep_their_own_origin() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &later, now), 0);
        let accept = |_: &[u8]| PowResult::Valid;

        let mut origins = Vec::new();
        for datagram in &first {
            if let BoundStep::Forward(objects) =
                bound.take(addr(2), KEY, FLEET, datagram, now, accept)
            {
                origins.extend(objects.iter().map(|outgoing| outgoing.from));
            }
        }

        origins.sort();
        assert_eq!(origins, vec![addr(1), addr(2)]);
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
        hold_decoded_as(bound, FLEET, src, fill, now);
    }

    fn hold_decoded_as(
        bound: &mut BoundForwarder,
        key_id: &str,
        src: SocketAddr,
        fill: u8,
        now: Instant,
    ) {
        let frames = body_frames(&vec![fill; 2 * SEGMENT_BYTES as usize]).unwrap();
        let later = sealed_frame(&frames[1], &KEY).unwrap();
        assert_eq!(send_as(bound, key_id, src, &later, now), 0);
        assert_eq!(bound.peers[&src].session.state().open, 0);
        assert_eq!(bound.peers[&src].unanchored.len(), 1);
    }

    #[test]
    fn a_build_that_aborts_is_refused_and_one_that_unwinds_is_not() {
        assert!(refused_by(false).is_some());
        assert!(refused_by(true).is_none());
        assert!(bound_raw_refused().is_none(), "tests always unwind");
    }

    /// Nine chunks of an object, as many others as fill both its places, and its tenth. At
    /// the limits a node has today, and the object is sent on.
    #[test]
    fn a_full_table_and_shelf_cost_a_node_no_object() {
        let config = BoundForwardConfig::default();
        let limits = config.session_budget;
        let crowd = limits.max_objects + limits.max_spare_objects - 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let object = body(200);

        assert_eq!(send(&mut bound, addr(1), &object[..9], now), 0);
        for fill in 0..crowd {
            open_one(&mut bound, addr(1), fill as u8, now);
        }
        assert_eq!(bound.peers[&addr(1)].session.state().spares, 8);

        assert_eq!(send(&mut bound, addr(1), &object[9..10], now), 1);
    }

    fn a_client() -> (BoundReceiver, mpsc::Receiver<BoundBlock>, usize) {
        let config = BoundRawConfig::default();
        let limits = config.stack.budget;
        let (consumer, blocks) = mpsc::channel(config.channel_blocks);
        let receiver = BoundReceiver::new(KEY, &config, consumer).unwrap();
        let crowd = limits.max_objects + limits.max_spare_objects - 1;
        (receiver, blocks, crowd)
    }

    #[test]
    fn a_full_table_and_shelf_cost_a_client_no_object() {
        let (mut receiver, mut blocks, crowd) = a_client();
        let now = Instant::now();
        let object = body(200);

        for datagram in &object[..9] {
            assert!(receiver.take(datagram, now));
        }
        for fill in 0..crowd {
            assert!(receiver.take(&body(fill as u8)[0], now));
        }
        assert!(receiver.take(&object[9], now));

        assert_eq!(blocks.try_recv().unwrap().raw(), [200; 5000]);
    }

    /// A block given back with its spares on a full shelf, and the timer finds them.
    #[test]
    fn a_full_table_and_shelf_cost_a_client_no_recovery() {
        let (mut receiver, mut blocks, crowd) = a_client();
        let now = Instant::now();
        let object = body(200);
        for datagram in &object {
            assert!(receiver.take(datagram, now));
        }
        let first = blocks.try_recv().unwrap();
        for datagram in &object {
            assert!(receiver.take(datagram, now));
        }
        for fill in 0..crowd {
            assert!(receiver.take(&body(fill as u8)[0], now));
        }

        first.give_back();
        assert!(receiver.look(now));

        assert_eq!(blocks.try_recv().unwrap().raw(), [200; 5000]);
    }

    // A panic on a node. Each of these stops a step just after what it changes, and looks at
    // what everyone else is left with.

    /// What the pool holds is what the sessions it still has hold, to the byte.
    fn pool_is_what_the_sessions_hold(bound: &BoundForwarder) {
        let mut sum = BoundUsed::default();
        for peer in bound.peers.values() {
            let used = peer.budget.used();
            sum.sessions += used.sessions;
            sum.objects += used.objects;
            sum.held_bytes += used.held_bytes;
            sum.work_bytes += used.work_bytes;
            sum.spare_objects += used.spare_objects;
            sum.spare_bytes += used.spare_bytes;
        }
        assert_eq!(bound.usage().pool, sum);
    }

    /// A body of `fill` but for its header's time, which is that of a body of ones, so that
    /// bodies of different fills are all as new. See [`ANCHOR_HEADER_WINDOW`].
    fn dated(fill: u8, segments: usize) -> Vec<u8> {
        let mut raw = vec![fill; segments * SEGMENT_BYTES as usize];
        raw[HEADER_TIME].fill(1);
        raw
    }

    /// Two frames of one body, each sealed.
    fn two_frames(fill: u8) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let frames = body_frames(&dated(fill, 2)).unwrap();
        (
            sealed_frame(&frames[0], &KEY).unwrap(),
            sealed_frame(&frames[1], &KEY).unwrap(),
        )
    }

    /// It decoded, and what it had open, waiting and on its shelf goes with it. The panic is
    /// right after the decode, with the most held.
    #[test]
    fn a_panic_costs_its_session_what_it_held_and_nobody_else_anything() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (honest, other) = (body(1), body(2));
        assert_eq!(send(&mut bound, addr(1), &honest[..9], now), 0);
        hold_decoded(&mut bound, addr(2), 3, now);
        assert_eq!(send(&mut bound, addr(2), &other[..9], now), 0);
        assert!(bound.peers[&addr(2)].share() > bound.peers[&addr(1)].share());
        bound.trips = vec![Trip::Arrived(addr(2))];

        assert_eq!(send(&mut bound, addr(2), &other[9..10], now), 0);

        assert!(!bound.peers.contains_key(&addr(2)));
        pool_is_what_the_sessions_hold(&bound);
        assert_eq!(bound.usage().sessions_lost_to_a_panic, 1);
        assert_eq!(bound.usage().panic_resets, 0);
        assert_eq!(send(&mut bound, addr(1), &honest[9..10], now), 1);

        assert_eq!(send(&mut bound, addr(2), &other, now), 1, "it starts again");
        pool_is_what_the_sessions_hold(&bound);
    }

    /// Stopped once `place` has moved an object to the last place on the shelf.
    #[test]
    fn a_panic_with_the_shelf_half_moved_goes_with_its_session() {
        let now = Instant::now();
        let crowded = || {
            let config = BoundForwardConfig::default();
            let limits = config.session_budget;
            let mut bound = BoundForwarder::new(config).unwrap();
            assert_eq!(send(&mut bound, addr(1), &body(250)[..9], now), 0);
            for fill in 0..limits.max_objects + limits.max_spare_objects - 1 {
                open_one(&mut bound, addr(2), fill as u8, now);
            }
            assert_eq!(bound.peers[&addr(2)].session.state().spares, 7);
            bound
        };
        // The same step with nothing to stop it: this is what the panic lands after.
        let mut unstopped = crowded();
        open_one(&mut unstopped, addr(2), 200, now);
        assert_eq!(unstopped.peers[&addr(2)].session.state().spares, 8);
        let mut bound = crowded();
        bound.trips = vec![Trip::Arrived(addr(2))];

        open_one(&mut bound, addr(2), 200, now);

        assert!(bound.trips.is_empty(), "it never got as far as the panic");
        assert_eq!(bound.usage().sessions_lost_to_a_panic, 1);
        assert!(!bound.peers.contains_key(&addr(2)));
        pool_is_what_the_sessions_hold(&bound);
        assert_eq!(send(&mut bound, addr(1), &body(250)[9..10], now), 1);
    }

    /// The session asked to move is the one whose objects stopped it, and what it held is
    /// the room that was asked for.
    #[test]
    fn a_panic_while_giving_way_costs_the_session_that_gave_way() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 256)).unwrap(),
            Instant::now(),
        );
        keep_a_little(&mut bound, FLEET, addr(2), 8, 1, now);
        for fill in 1..=4 {
            open_one(&mut bound, addr(1), fill, now);
        }
        bound.trips = vec![Trip::GaveWay(addr(1))];

        open_one(&mut bound, addr(2), 9, now);

        assert!(bound.trips.is_empty(), "it never got as far as the panic");
        assert_eq!(bound.usage().sessions_lost_to_a_panic, 1);
        assert!(!bound.peers.contains_key(&addr(1)));
        assert_eq!(bound.peers[&addr(2)].session.state().open, 1);
        pool_is_what_the_sessions_hold(&bound);
    }

    /// Another session moved an object for this one, and this one panicked. The move stands
    /// and is a state like any other: the object finishes from the shelf.
    #[test]
    fn an_object_moved_for_a_session_that_panicked_can_still_finish() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 256)).unwrap(),
            Instant::now(),
        );
        let honest = body(1);
        keep_a_little(&mut bound, FLEET, addr(2), 8, 1, now);
        assert_eq!(send(&mut bound, addr(1), &honest[..9], now), 0);
        for fill in 2..=4 {
            open_one(&mut bound, addr(1), fill, now);
        }
        bound.trips = vec![Trip::Arrived(addr(2))];

        open_one(&mut bound, addr(2), 9, now);

        assert!(bound.trips.is_empty(), "it never got as far as the panic");
        assert_eq!(bound.usage().sessions_lost_to_a_panic, 1);
        assert!(!bound.peers.contains_key(&addr(2)));
        assert_eq!(bound.peers[&addr(1)].session.state().open, 3);
        assert_eq!(bound.peers[&addr(1)].session.state().spares, 1);
        pool_is_what_the_sessions_hold(&bound);
        assert_eq!(send(&mut bound, addr(1), &honest[9..10], now), 1);
    }

    /// The anchor is in, and what waited for it had been gathered. Those objects are gone
    /// and nobody else's state says otherwise: no record was written, so a resend goes
    /// straight through, and the anchor stays true.
    #[test]
    fn a_panic_with_waiting_objects_gathered_costs_them_a_resend() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &later, now), 0);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
        bound.trips = vec![Trip::Drained];

        assert_eq!(send(&mut bound, addr(2), &first[..10], now), 0);

        assert!(!bound.peers.contains_key(&addr(2)));
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 0);
        pool_is_what_the_sessions_hold(&bound);
        assert_eq!(send(&mut bound, addr(1), &later, now), 1);
    }

    /// Recording one send fails with its record written. The records around it go on, and
    /// the record goes with its session, so nothing says that session sent it when it did
    /// not. Recording comes after the send, so the object itself went.
    #[test]
    fn a_panic_on_one_send_leaves_the_others_and_no_false_record() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &later, now), 0);
        assert_eq!(send(&mut bound, addr(3), &later, now), 0);
        bound.trips = vec![Trip::Noted(addr(1))];

        assert_eq!(send(&mut bound, addr(2), &first, now), 3);

        assert!(!bound.peers.contains_key(&addr(1)));
        assert_eq!(bound.usage().objects_sent_on, 3);
        pool_is_what_the_sessions_hold(&bound);

        assert_eq!(send(&mut bound, addr(1), &later, now), 1);
    }

    /// A session that panics on every datagram: what it pays is its own, so nothing has to
    /// hold it off, and everyone else carries on through it.
    #[test]
    fn a_session_that_always_panics_wears_out_only_itself() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let honest = body(1);
        assert_eq!(send(&mut bound, addr(1), &honest[..9], now), 0);
        let held = bound.peers[&addr(1)].budget.used();

        for datagram in body(2).iter().cycle().take(50) {
            bound.trips = vec![Trip::Arrived(addr(2))];
            let step = bound.take(addr(2), KEY, FLEET, datagram, now, |_| PowResult::Valid);
            assert!(matches!(step, BoundStep::Lost));
        }

        assert_eq!(bound.usage().sessions_lost_to_a_panic, 50);
        assert_eq!(bound.usage().panic_resets, 0);
        assert_eq!(bound.peers.len(), 1);
        assert_eq!(bound.peers[&addr(1)].budget.used(), held);
        pool_is_what_the_sessions_hold(&bound);
        assert_eq!(send(&mut bound, addr(1), &honest[9..10], now), 1);
    }

    /// Everything goes and every reservation with it. Anchors and records are gone as well,
    /// and the counts are what they were.
    #[test]
    fn starting_over_gives_everything_back_and_keeps_the_counts() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);
        let (_, waiting) = two_frames(2);
        assert_eq!(send(&mut bound, addr(1), &waiting, now), 0);
        assert_eq!(send(&mut bound, addr(2), &body(3)[..9], now), 0);

        bound.start_over();

        let usage = bound.usage();
        assert_eq!(usage.pool, BoundUsed::default());
        assert_eq!(usage.peers, 0);
        assert_eq!(usage.forwarded_records, 0);
        assert_eq!(usage.objects_waiting_for_segment_0, 0);
        assert_eq!(usage.objects_sent_on, 1);
        assert_eq!(usage.panic_resets, 1);
        assert_eq!(send(&mut bound, addr(1), &later, now), 0, "no anchor now");
    }

    /// What a reset costs. It is for a panic nobody can be held to, and it takes what every
    /// session had open. If anything a session sends could reach it, that would stop other
    /// sessions' objects from ever finishing, however often they were sent, and nothing here
    /// limits how often. Nothing known reaches it.
    #[test]
    fn known_gap_a_reset_costs_every_session_what_it_had_open() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let honest = body(1);
        assert_eq!(send(&mut bound, addr(1), &honest[..9], now), 0);

        bound.start_over();

        assert_eq!(send(&mut bound, addr(1), &honest[9..10], now), 0);
        assert_eq!(
            send(&mut bound, addr(1), &honest[..9], now),
            1,
            "from the start"
        );
    }

    // A panic on a client.

    /// What it held goes, and a copy of the block it could not hand over is welcome. The
    /// block with the consumer keeps its owners: no second copy of it gets out while it is
    /// held or after it is finished with.
    #[test]
    fn a_panic_on_a_client_keeps_what_the_consumer_has() {
        let config = BoundRawConfig {
            channel_blocks: 1,
            ..Default::default()
        };
        let (consumer, mut blocks) = mpsc::channel(config.channel_blocks);
        let receiver = BoundReceiver::new(KEY, &config, consumer).unwrap();
        let probe = receiver.probe();
        let mut bound = Some(receiver);
        let now = Instant::now();
        let (with_consumer, waiting, open) = (body(1), body(2), body(3));
        let idle = probe.used();
        let feed = |bound: &mut Option<BoundReceiver>, datagrams: &[Vec<u8>]| {
            for datagram in datagrams {
                contain(bound, |receiver| receiver.take(datagram, now));
            }
        };

        feed(&mut bound, &with_consumer);
        feed(&mut bound, &waiting);
        feed(&mut bound, &open[..9]);
        assert_eq!(bound.as_ref().unwrap().bridge.waiting(), 1);
        // The block with the consumer has a record of its own beside its segment's.
        assert_eq!(probe.ledger().held, 3);
        assert_ne!(probe.used(), idle);

        contain(&mut bound, |_| panic!("stopped on purpose"));

        assert_eq!(probe.progress().handoffs.panics_contained, 1);
        assert_eq!(
            probe.used(),
            idle,
            "the block with the consumer is not here"
        );
        assert_eq!(probe.ledger().held, 2);
        assert_eq!(probe.ledger().released, 1);
        assert_eq!(bound.as_ref().unwrap().bridge.waiting(), 0);

        feed(&mut bound, &with_consumer);
        let block = blocks.try_recv().unwrap();
        assert_eq!(block.raw(), [1; 5000]);
        assert!(blocks.try_recv().is_err(), "held, so no second copy");

        feed(&mut bound, &waiting);
        block.finish();
        assert!(contain_pump(&mut bound));
        assert_eq!(blocks.try_recv().unwrap().raw(), [2; 5000]);
        feed(&mut bound, &with_consumer);
        assert!(
            blocks.try_recv().is_err(),
            "finished with, so no second copy"
        );
    }

    fn contain_pump(bound: &mut Option<BoundReceiver>) -> bool {
        contain(bound, |receiver| receiver.pump(Instant::now()));
        bound.is_some()
    }

    /// A consumer that went still ends the path, and nothing else does.
    #[test]
    fn a_client_whose_consumer_went_still_lets_go() {
        let (receiver, blocks, _) = a_client();
        drop(blocks);
        let mut bound = Some(receiver);

        contain(&mut bound, |receiver| receiver.pump(Instant::now()));

        assert!(bound.is_none());
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
        assert!(bound.peers[&addr(1)].share() > bound.peers[&addr(2)].share());

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
        assert_eq!(bound.peers[&addr(1)].share(), bound.peers[&addr(2)].share());

        open_one(&mut bound, addr(1), 3, now);

        assert_eq!(bound.peers[&addr(1)].session.state().open, 0);
        assert_eq!(bound.peers[&addr(2)].unanchored.len(), 1);
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

    /// Two bodies of the largest size, so a node takes both in whatever its work is doing.
    #[test]
    fn a_nodes_queue_holds_two_bodies_of_the_largest_size() {
        let config = BoundForwardConfig::default();
        let body = sealed_body(&vec![7u8; MAX_BODY_BYTES as usize], &KEY).unwrap();
        let bytes: usize = body.iter().map(Vec::len).sum();
        assert!(config.max_queued_datagrams >= 2 * body.len());
        assert!(config.max_queued_bytes >= 2 * bytes);
    }

    fn queue_of(datagrams: usize, bytes: usize) -> IngressQueue {
        let config = BoundForwardConfig {
            max_queued_datagrams: datagrams,
            max_queued_bytes: bytes,
            ..config()
        };
        IngressQueue::new(Some(&config))
    }

    fn fill(queue: &mut IngressQueue, each: usize) {
        let datagram = vec![0u8; each];
        while queue.has_room() {
            queue.push(&datagram, addr(1));
        }
    }

    #[test]
    fn the_queue_stops_at_its_number_of_datagrams() {
        let mut queue = queue_of(3, 1 << 20);
        fill(&mut queue, 100);

        assert_eq!(queue.datagrams(), 3);
        assert_eq!(queue.bytes(), 300);
    }

    /// The longest a read can be, past any datagram this path sends, because the queue comes
    /// ahead of every check.
    #[test]
    fn the_queue_stops_at_its_bytes_with_the_longest_datagrams() {
        let mut queue = queue_of(100, 3 * MAX_READ_BYTES);
        fill(&mut queue, MAX_READ_BYTES);

        assert_eq!(queue.datagrams(), 3);
        assert_eq!(queue.bytes(), 3 * MAX_READ_BYTES);
    }

    /// Room is asked for before a read, when its length is not known yet.
    #[test]
    fn the_queue_never_passes_its_bytes_with_short_datagrams() {
        let limit = 3 * MAX_READ_BYTES;
        let mut queue = queue_of(usize::MAX, limit);
        fill(&mut queue, 1);

        assert!(queue.bytes() <= limit);
        assert!(!queue.has_room());
    }

    #[test]
    fn a_full_queue_of_the_longest_datagrams_keeps_to_the_research_limits() {
        let config = BoundForwardConfig::default();
        let mut queue = IngressQueue::new(Some(&config));
        fill(&mut queue, MAX_READ_BYTES);

        assert_eq!(queue.datagrams(), config.max_queued_datagrams);
        assert_eq!(queue.bytes(), config.max_queued_bytes);
        assert_eq!(queue.bytes(), 16 << 20);
    }

    #[test]
    fn a_datagram_taken_out_gives_its_room_back_in_order() {
        let mut queue = queue_of(2, 1 << 20);
        queue.push(&[1], addr(1));
        queue.push(&[2, 2], addr(2));
        assert!(!queue.has_room());

        assert_eq!(queue.pop(), Some((vec![1], addr(1))));

        assert!(queue.has_room());
        assert_eq!(queue.bytes(), 2);
        assert_eq!(queue.pop(), Some((vec![2, 2], addr(2))));
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.bytes(), 0);
    }

    /// The legacy path's loop, with the bound path off or the queue turned down.
    #[test]
    fn a_queue_with_no_limit_never_reads_ahead() {
        assert!(!IngressQueue::new(None).has_room());
        assert!(!queue_of(0, 1 << 20).has_room());
        assert!(!queue_of(8, 0).has_room());
    }

    #[test]
    fn the_research_values_of_a_session_fit_the_pool() {
        let config = BoundForwardConfig::default();
        let (session, key, pool) = (config.session_budget, config.key_budget, config.pool);
        for (inner, outer) in [(session, key), (key, pool)] {
            assert!(inner.max_held_bytes <= outer.max_held_bytes);
            assert!(inner.max_objects <= outer.max_objects);
            assert!(inner.max_work_bytes <= outer.max_work_bytes);
            assert!(inner.max_spare_objects <= outer.max_spare_objects);
            assert!(inner.max_spare_bytes <= outer.max_spare_bytes);
        }
        assert!(key.max_sessions < pool.max_sessions);
        assert!(key.max_objects < pool.max_objects);
        assert!(key.max_held_bytes < pool.max_held_bytes);
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

    // Keys. A source port costs nothing, so what a limit can hold to is the key that was
    // verified. The values are for research.

    const OTHER: &str = "other";

    fn key_config(sessions: usize, objects: usize) -> BoundForwardConfig {
        let mut config = config();
        config.key_budget.max_sessions = sessions;
        config.key_budget.max_objects = objects;
        config
    }

    fn open_as(bound: &mut BoundForwarder, key_id: &str, src: SocketAddr, fill: u8, now: Instant) {
        let _ = send_as(bound, key_id, src, &body(fill)[..1], now);
    }

    fn open_in(bound: &BoundForwarder, src: SocketAddr) -> usize {
        bound.peers[&src].session.state().open
    }

    #[test]
    fn one_key_on_many_ports_stops_at_its_limit() {
        let (mut bound, now) = (
            BoundForwarder::new(key_config(3, 512)).unwrap(),
            Instant::now(),
        );

        for port in 1..=6 {
            open_one(&mut bound, addr(port), port as u8, now);
        }

        assert_eq!(bound.usage().peers, 3);
        assert_eq!(bound.usage().pool.sessions, 3);
        assert_eq!(bound.usage().datagrams_without_a_place, 3);
    }

    /// Every limit a key has, over more ports than it may have sessions, at every step.
    #[test]
    fn one_key_on_many_ports_stays_inside_every_limit_of_its_own() {
        let frame = body_frames(&[0; 5000]).unwrap().swap_remove(0);
        let object = encode(MSG_RAW_SEGMENT, SHARDS, DATA_SHARDS, &frame).unwrap();
        let mut config = key_config(4, 6);
        config.key_budget.max_held_bytes = 5 * chunk_proof::object::held_bytes(&object.shape);
        config.key_budget.max_spare_objects = 3;
        let limits = config.key_budget;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());

        for port in 1..=12u16 {
            for object in 0..8u8 {
                open_one(&mut bound, addr(port), port as u8 * 16 + object, now);
                let used = bound.key_used(FLEET);
                assert!(used.sessions <= limits.max_sessions, "{used:?}");
                assert!(used.objects <= limits.max_objects, "{used:?}");
                assert!(used.held_bytes <= limits.max_held_bytes, "{used:?}");
                assert!(used.spare_objects <= limits.max_spare_objects, "{used:?}");
                assert_eq!(
                    used,
                    bound.usage().pool,
                    "nothing of it is outside its budget"
                );
            }
        }

        let used = bound.key_used(FLEET);
        assert_eq!(used.sessions, limits.max_sessions);
        assert_eq!(used.objects, 5, "the bytes ran out first");
        assert_eq!(used.spare_objects, limits.max_spare_objects);
    }

    #[test]
    fn another_key_gets_a_place_when_one_key_is_at_its_limit() {
        let mut config = key_config(3, 512);
        config.pool.max_sessions = 4;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        for port in 1..=6 {
            open_one(&mut bound, addr(port), port as u8, now);
        }

        open_as(&mut bound, OTHER, addr(9), 9, now);

        assert_eq!(open_in(&bound, addr(9)), 1);
    }

    #[test]
    fn a_keys_sessions_share_one_budget() {
        let (mut bound, now) = (
            BoundForwarder::new(key_config(8, 4)).unwrap(),
            Instant::now(),
        );

        for fill in 1..=3 {
            open_one(&mut bound, addr(1), fill, now);
        }
        for fill in 4..=6 {
            open_one(&mut bound, addr(2), fill, now);
        }

        assert_eq!(bound.key_used(FLEET).sessions, 2);
        assert_eq!(bound.key_used(FLEET).objects, 4);
        assert_eq!(bound.usage().pool.objects, 4);
    }

    #[test]
    fn a_session_that_goes_gives_its_keys_room_back() {
        let (mut bound, now) = (
            BoundForwarder::new(key_config(2, 512)).unwrap(),
            Instant::now(),
        );
        for port in 1..=3 {
            open_one(&mut bound, addr(port), port as u8, now);
        }
        assert!(!bound.peers.contains_key(&addr(3)));

        bound.tidy(now, |src| *src != addr(1));
        open_one(&mut bound, addr(3), 3, now);

        assert_eq!(open_in(&bound, addr(3)), 1);
        assert_eq!(bound.key_used(FLEET).sessions, 2);
    }

    /// A panic takes one session, and all it held comes back to its key as well.
    #[test]
    fn a_panic_gives_its_keys_room_back() {
        let (mut bound, now) = (
            BoundForwarder::new(key_config(2, 512)).unwrap(),
            Instant::now(),
        );
        open_one(&mut bound, addr(1), 1, now);
        open_one(&mut bound, addr(2), 2, now);
        bound.trips = vec![Trip::Arrived(addr(1))];

        open_one(&mut bound, addr(1), 3, now);

        assert!(!bound.peers.contains_key(&addr(1)));
        assert_eq!(bound.key_used(FLEET).sessions, 1);
        assert_eq!(bound.key_used(FLEET).objects, 1);
        pool_is_what_the_sessions_hold(&bound);
        open_one(&mut bound, addr(3), 4, now);
        assert_eq!(open_in(&bound, addr(3)), 1);
    }

    /// A key at its limits, in open objects, on shelves and in what waits. What a session
    /// held comes back to its key to the byte, and the key can then use all of it again.
    #[test]
    fn a_key_at_its_limit_gets_back_exactly_what_a_session_held() {
        let (mut bound, now) = (
            BoundForwarder::new(key_config(2, 4)).unwrap(),
            Instant::now(),
        );
        hold_decoded(&mut bound, addr(1), 1, now);
        for fill in 2..=3 {
            open_one(&mut bound, addr(1), fill, now);
        }
        keep_a_little(&mut bound, FLEET, addr(2), 4, 3, now);
        for fill in 5..=6 {
            open_one(&mut bound, addr(2), fill, now);
        }
        assert_eq!(bound.key_used(FLEET).sessions, 2);
        assert_eq!(bound.key_used(FLEET).objects, 4);
        let stays = bound.peers[&addr(2)].budget.used();
        open_one(&mut bound, addr(3), 7, now);
        assert!(!bound.peers.contains_key(&addr(3)), "no place left");

        bound.tidy(now, |src| *src != addr(1));

        let used = bound.key_used(FLEET);
        assert_eq!(used.objects, stays.objects);
        assert_eq!(used.held_bytes, stays.held_bytes);
        assert_eq!(used.spare_objects, stays.spare_objects);
        assert_eq!(used.spare_bytes, stays.spare_bytes);
        assert_eq!(used.sessions, 1);
        assert_eq!(used, bound.usage().pool);

        open_one(&mut bound, addr(3), 7, now);
        open_one(&mut bound, addr(3), 8, now);
        assert_eq!(open_in(&bound, addr(3)), 2);
        assert_eq!(bound.key_used(FLEET).objects, 4);

        bound.tidy(now, |_| false);
        assert_eq!(bound.usage().pool, BoundUsed::default());
    }

    /// The last session of a key takes the budget with it, and the pool has it all back.
    #[test]
    fn the_last_session_of_a_key_leaves_nothing_of_it() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        open_as(&mut bound, OTHER, addr(1), 1, now);

        bound.tidy(now, |_| false);

        assert_eq!(bound.usage().pool, BoundUsed::default());
        assert_eq!(bound.key_used(OTHER), BoundUsed::default());
    }

    /// The same source under another key is another session, of that key.
    #[test]
    fn a_source_that_changes_key_moves_to_that_keys_budget() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        open_one(&mut bound, addr(1), 1, now);

        open_as(&mut bound, OTHER, addr(1), 2, now);

        assert_eq!(bound.usage().peers, 1);
        assert_eq!(bound.key_used(FLEET), BoundUsed::default());
        assert_eq!(bound.key_used(OTHER).objects, 1);
    }

    #[test]
    fn a_key_budget_that_cannot_hold_anything_does_not_start() {
        let mut config = config();
        config.key_budget.max_objects = 0;
        assert!(BoundForwarder::new(config).is_err());
    }

    /// A key at its limit is its own matter: its sessions sort it out among themselves.
    #[test]
    fn a_key_at_its_limit_moves_its_own_session_and_no_other_keys() {
        let (mut bound, now) = (
            BoundForwarder::new(key_config(8, 3)).unwrap(),
            Instant::now(),
        );
        hold_decoded_as(&mut bound, OTHER, addr(3), 1, now);
        for fill in 2..=4 {
            open_as(&mut bound, OTHER, addr(3), fill, now);
        }
        keep_a_little(&mut bound, FLEET, addr(2), 5, 1, now);
        for fill in 6..=8 {
            open_one(&mut bound, addr(1), fill, now);
        }
        assert!(bound.peers[&addr(3)].key_share() > bound.peers[&addr(1)].key_share());

        open_one(&mut bound, addr(2), 9, now);

        assert_eq!(open_in(&bound, addr(1)), 2);
        assert_eq!(open_in(&bound, addr(2)), 1);
        assert_eq!(
            open_in(&bound, addr(3)),
            3,
            "a heavier key, but this is not its limit"
        );
        assert_eq!(bound.key_used(FLEET).objects, 3);
    }

    /// The heaviest may have nothing it could move. That does not stop the next one.
    #[test]
    fn a_session_with_nothing_to_move_is_passed_over() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(2, 256)).unwrap(),
            Instant::now(),
        );
        keep_a_little(&mut bound, FLEET, addr(1), 1, 1, now);
        hold_decoded_as(&mut bound, OTHER, addr(2), 2, now);
        hold_decoded_as(&mut bound, OTHER, addr(3), 3, now);
        for fill in 4..=5 {
            open_as(&mut bound, "third", addr(4), fill, now);
        }

        open_one(&mut bound, addr(1), 9, now);

        assert_eq!(open_in(&bound, addr(1)), 1);
        assert_eq!(open_in(&bound, addr(4)), 1);
        assert_eq!(bound.peers[&addr(2)].unanchored.len(), 1);
        assert_eq!(bound.peers[&addr(3)].unanchored.len(), 1);
    }

    // Who can ask for room, and what it can cost.

    /// Move a session's object of `chunks` chunks to its shelf. It holds little after that,
    /// and nothing it could move for itself.
    fn keep_a_little(
        bound: &mut BoundForwarder,
        key_id: &str,
        src: SocketAddr,
        fill: u8,
        chunks: usize,
        now: Instant,
    ) {
        let _ = send_as(bound, key_id, src, &body(fill)[..chunks], now);
        assert!(bound.peers.get_mut(&src).unwrap().session.give_way());
    }

    /// A spare with all it needs whose decode was refused for room decodes once there is
    /// room, rather than waiting for its time to run out.
    #[test]
    fn a_full_spare_refused_for_room_decodes_once_there_is_room() {
        let (held, spare) = {
            let (mut probe, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
            open_one(&mut probe, addr(9), 9, now);
            keep_a_little(&mut probe, FLEET, addr(1), 1, 9, now);
            let used = probe.usage().pool;
            (used.held_bytes, used.spare_bytes)
        };
        let mut config = config();
        // Room for one open object, and a shelf with room for this spare and nothing else.
        config.pool.max_held_bytes = held + held / 2;
        config.pool.max_spare_bytes = spare + spare / 9;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let honest = body(1);
        keep_a_little(&mut bound, FLEET, addr(1), 1, 9, now);
        open_as(&mut bound, OTHER, addr(2), 2, now);

        assert_eq!(send(&mut bound, addr(1), &honest[9..10], now), 0);
        assert_eq!(bound.usage().arrivals.refused_by_pool, 1);
        assert!(bound.peers[&addr(1)].stuck);
        let accept = |_: &[u8]| PowResult::Valid;
        assert!(bound.revive(now, accept).is_empty(), "still no room");
        assert!(bound.peers[&addr(1)].stuck);

        bound.tidy(now, |peer| *peer != addr(2));
        let revived = bound.revive(now, accept);

        assert_eq!(revived.len(), 1);
        assert_eq!(revived[0].from, addr(1));
        assert_eq!(bound.usage().spares_revived, 1);
        assert!(!bound.peers[&addr(1)].stuck);
        assert_eq!(bound.peers[&addr(1)].session.state().spares, 0);
    }

    #[test]
    fn a_session_holding_nothing_pushes_nobody() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 256)).unwrap(),
            Instant::now(),
        );
        for fill in 1..=4 {
            open_as(&mut bound, OTHER, addr(1), fill, now);
        }

        open_one(&mut bound, addr(2), 9, now);

        assert_eq!(open_in(&bound, addr(1)), 4);
        assert_eq!(open_in(&bound, addr(2)), 0);
    }

    /// An object of one data shard decodes, fails and is gone at once, so what sends them
    /// always holds nothing. They are not let in, and they buy no room.
    #[test]
    fn k_one_objects_never_earn_room() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(1, 256)).unwrap(),
            Instant::now(),
        );
        open_as(&mut bound, OTHER, addr(1), 1, now);

        for fill in 0..8u8 {
            let object = encode(MSG_RAW_SEGMENT, 2, 1, &[fill; 64]).unwrap();
            for datagram in BoundForwarder::sealed(&KEY, &object) {
                bound.take(addr(2), KEY, FLEET, &datagram, now, |_| PowResult::Valid);
            }
        }

        assert_eq!(open_in(&bound, addr(1)), 1);
    }

    /// Its shelf is part of what a session holds, so it cannot look light by moving things
    /// there.
    #[test]
    fn share_counts_spares_too() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(2, 256)).unwrap(),
            Instant::now(),
        );
        for fill in 1..=3 {
            keep_a_little(&mut bound, OTHER, addr(1), fill, 9, now);
        }
        hold_decoded_as(&mut bound, OTHER, addr(1), 7, now);
        for fill in 4..=5 {
            open_one(&mut bound, addr(2), fill, now);
        }
        let (asking, other) = (
            bound.peers[&addr(1)].budget.used(),
            bound.peers[&addr(2)].budget.used(),
        );
        assert!(asking.held_bytes > 0);
        assert!(
            asking.held_bytes < other.held_bytes,
            "lighter without its shelf"
        );
        assert!(asking.held_bytes + asking.spare_bytes > other.held_bytes);

        open_as(&mut bound, OTHER, addr(1), 6, now);

        assert_eq!(open_in(&bound, addr(2)), 2);
        assert_eq!(open_in(&bound, addr(1)), 0);
    }

    /// One session on each port looks lighter than it is.
    #[test]
    fn a_key_is_weighed_across_its_ports() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(3, 256)).unwrap(),
            Instant::now(),
        );
        hold_decoded_as(&mut bound, OTHER, addr(1), 1, now);
        hold_decoded_as(&mut bound, OTHER, addr(2), 2, now);
        for fill in 3..=5 {
            open_one(&mut bound, addr(3), fill, now);
        }
        let held = |port| bound.peers[&addr(port)].budget.used().held_bytes;
        assert!(held(3) > held(1), "one session of it weighs less");
        assert!(held(1) + held(2) > held(3), "all of it weighs more");

        open_as(&mut bound, OTHER, addr(1), 9, now);

        assert_eq!(open_in(&bound, addr(3)), 3);
        assert_eq!(open_in(&bound, addr(1)), 0);
    }

    /// Holding little still gets a place from a key holding far more.
    #[test]
    fn a_lighter_session_that_holds_something_gets_a_place() {
        let (mut bound, now) = (
            BoundForwarder::new(pool_config(4, 256)).unwrap(),
            Instant::now(),
        );
        keep_a_little(&mut bound, OTHER, addr(1), 1, 1, now);
        for fill in 2..=5 {
            open_one(&mut bound, addr(2), fill, now);
        }

        open_as(&mut bound, OTHER, addr(1), 9, now);

        assert_eq!(open_in(&bound, addr(1)), 1);
        assert_eq!(open_in(&bound, addr(2)), 3);
        assert_eq!(bound.peers[&addr(2)].session.state().spares, 1);
    }

    #[test]
    fn a_full_shelf_refuses_the_newcomer_and_deletes_nothing() {
        let mut config = pool_config(3, 256);
        config.pool.max_spare_bytes = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        hold_decoded_as(&mut bound, OTHER, addr(1), 1, now);
        let honest = body(2);
        assert_eq!(send(&mut bound, addr(2), &honest[..9], now), 0);
        for fill in 3..=4 {
            open_one(&mut bound, addr(2), fill, now);
        }

        open_as(&mut bound, OTHER, addr(1), 9, now);

        assert_eq!(open_in(&bound, addr(2)), 3);
        assert_eq!(open_in(&bound, addr(1)), 0);
        assert_eq!(bound.usage().arrivals.refused_by_pool, 1);
        assert_eq!(send(&mut bound, addr(2), &honest[9..10], now), 1);
    }

    /// Decoded and waiting for its segment 0 gives way to a session that holds less, as an
    /// open object does: held without end, it would keep the pool from anyone else for as
    /// long as it waits. Its session can send it again.
    #[test]
    fn what_waits_for_its_segment_0_gives_way_to_a_lighter_session() {
        let frames = body_frames(&vec![1u8; 2 * SEGMENT_BYTES as usize]).unwrap();
        let mut limits = config();
        limits.pool.max_held_bytes = frames[1].len() + 1000;
        let (mut bound, now) = (BoundForwarder::new(limits).unwrap(), Instant::now());
        keep_a_little(&mut bound, OTHER, addr(1), 1, 1, now);
        hold_decoded(&mut bound, addr(2), 2, now);

        open_as(&mut bound, OTHER, addr(1), 3, now);

        assert_eq!(bound.peers[&addr(2)].unanchored.len(), 0);
        assert_eq!(open_in(&bound, addr(1)), 1);
        assert_eq!(bound.usage().waiting_gave_way, 1);
    }

    /// An open object that can move goes first, since it can still finish on the shelf.
    #[test]
    fn an_open_object_moves_before_what_waits_goes() {
        let config = pool_config(1, 256);
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        hold_decoded_as(&mut bound, OTHER, addr(1), 1, now);
        hold_decoded(&mut bound, addr(2), 2, now);
        open_one(&mut bound, addr(2), 3, now);

        open_as(&mut bound, OTHER, addr(1), 9, now);

        assert_eq!(bound.peers[&addr(2)].unanchored.len(), 1);
        assert_eq!(open_in(&bound, addr(2)), 0);
        assert_eq!(open_in(&bound, addr(1)), 1);
        assert_eq!(bound.usage().waiting_gave_way, 0);
    }

    /// What waits holds no open place, so with the pool out of places it would make no room,
    /// and it stays, as does an open object that cannot move.
    #[test]
    fn what_waits_stays_when_the_open_object_cannot_move() {
        let mut config = pool_config(1, 256);
        config.pool.max_spare_bytes = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        hold_decoded_as(&mut bound, OTHER, addr(1), 1, now);
        hold_decoded(&mut bound, addr(2), 2, now);
        open_one(&mut bound, addr(2), 3, now);

        open_as(&mut bound, OTHER, addr(1), 9, now);

        assert_eq!(bound.peers[&addr(2)].unanchored.len(), 1);
        assert_eq!(open_in(&bound, addr(2)), 1);
        assert_eq!(open_in(&bound, addr(1)), 0);
        assert_eq!(bound.usage().waiting_gave_way, 0);
    }

    /// The same frame under a shape of its own would be another object, sent on again.
    #[test]
    fn a_frame_under_another_shape_is_refused() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let frame = body_frames(&[7; 5000]).unwrap().swap_remove(0);
        let other = encode(MSG_RAW_SEGMENT, 14, 12, &frame).unwrap();

        for datagram in BoundForwarder::sealed(&KEY, &other) {
            bound.take(addr(1), KEY, FLEET, &datagram, now, |_| PowResult::Valid);
        }

        assert_eq!(bound.usage().objects_sent_on, 0);
        assert_eq!(bound.usage().pool.objects, 0);
    }

    // Anchors, and what waits for them. A valid header proves nothing about how recent it is,
    // and the node has no chain source, so anyone with a key can open anchors with old headers.

    /// A body of its own under a header nobody else has, in one segment.
    /// A body of a block of its own, in one segment. Its header's time is that of the bodies
    /// of ones here, so neither looks old next to the other. See [`ANCHOR_HEADER_WINDOW`].
    fn one_segment(mark: u32) -> Vec<Vec<u8>> {
        let mut raw = vec![0u8; 5000];
        raw[..4].copy_from_slice(&mark.to_le_bytes());
        raw[HEADER_TIME].fill(1);
        sealed_body(&raw, &KEY).unwrap()
    }

    /// A body of block 1 in one segment: the header is the same for all of them, the rest is
    /// not, so they share a block hash and each has a body id of its own.
    fn body_of_a_block(mark: u8) -> Vec<Vec<u8>> {
        let mut raw = vec![1u8; 5000];
        raw[4000] = mark;
        sealed_body(&raw, &KEY).unwrap()
    }

    fn three_frames(fill: u8) -> SealedFrames {
        let frames = body_frames(&dated(fill, 3)).unwrap();
        let sealed = frames
            .iter()
            .map(|frame| sealed_frame(frame, &KEY).unwrap());
        sealed.collect()
    }

    #[test]
    fn an_active_body_keeps_its_anchor_through_a_flood() {
        let config = config();
        let flood = config.max_anchors as u32 + 8;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        for mark in 0..flood {
            send_as(&mut bound, OTHER, addr(2), &one_segment(mark), now);
        }

        assert_eq!(send(&mut bound, addr(1), &later, now), 1);
    }

    /// One key for everybody is as good a layout as any, so this holds there too.
    #[test]
    fn a_flood_under_the_same_key_costs_an_active_body_nothing() {
        let config = config();
        let flood = config.max_anchors as u32 + 8;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        for mark in 0..flood {
            send(&mut bound, addr(2), &one_segment(mark), now);
        }

        assert_eq!(send(&mut bound, addr(1), &later, now), 1);
    }

    /// One key cannot fill the table, so this is what it takes: as many keys as fill it, and
    /// more. The body's anchor stays, and what comes past the table is turned away.
    #[test]
    fn a_flood_from_many_keys_costs_an_active_body_nothing() {
        let config = config();
        let (table, share) = (config.max_anchors, config.max_anchors_per_key);
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        for mark in 0..table + 8 {
            let key_id = format!("key{}", mark / share);
            let port = 100 + (mark / share) as u16;
            send_as(
                &mut bound,
                &key_id,
                addr(port),
                &one_segment(mark as u32),
                now,
            );
        }

        assert_eq!(bound.usage().anchors, table, "the flood filled the table");
        assert!(bound.usage().anchors_refused_for_room > 0);
        assert_eq!(send(&mut bound, addr(1), &later, now), 1);
    }

    /// Closing every session and coming back is no way round a key's share. What it opened
    /// is still in the table, and the table is what the share is there to protect.
    #[test]
    fn a_key_cannot_fill_the_table_by_leaving_and_coming_back() {
        let mut config = config();
        config.max_anchors = 16;
        config.max_anchors_per_key = 2;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());

        let mut mark = 0;
        for round in 0..8u16 {
            for _ in 0..2 {
                mark += 1;
                send(&mut bound, addr(round + 1), &one_segment(mark), now);
            }
            bound.tidy(now, |_| false);
        }

        assert_eq!(bound.usage().anchors, 2);
        assert_eq!(bound.anchors.of_key(FLEET, now), 2);
    }

    #[test]
    fn a_key_that_comes_back_answers_for_what_it_opened() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        bound.tidy(now, |_| false);

        assert_eq!(send(&mut bound, addr(2), &one_segment(2), now), 0);

        assert_eq!(bound.usage().anchors_refused_for_room, 1);
    }

    #[test]
    fn a_key_stops_at_its_share_of_the_anchors() {
        let mut config = config();
        config.max_anchors_per_key = 2;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        assert_eq!(send(&mut bound, addr(2), &one_segment(2), now), 1);

        assert_eq!(send(&mut bound, addr(3), &one_segment(3), now), 0);

        assert_eq!(bound.usage().anchors, 2);
        assert_eq!(bound.usage().anchors_refused_for_room, 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(4), &one_segment(4), now), 1);
    }

    #[test]
    fn a_full_table_refuses_a_new_anchor_and_keeps_the_ones_it_has() {
        let mut config = config();
        config.max_anchors = 2;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &one_segment(2), now), 1);

        assert_eq!(
            send_as(&mut bound, "third", addr(3), &one_segment(3), now),
            0
        );

        assert_eq!(bound.usage().anchors, 2);
        assert_eq!(bound.usage().anchors_refused_for_room, 1);
        assert_eq!(send(&mut bound, addr(1), &later, now), 1);
    }

    /// A body that keeps crossing keeps its anchor, past the time its segment 0 alone gives it.
    #[test]
    fn a_used_anchor_lasts_from_its_last_use() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let frames = three_frames(1);
        assert_eq!(send(&mut bound, addr(1), &frames[0], now), 1);

        let used = now + ttl - Duration::from_secs(1);
        assert_eq!(send(&mut bound, addr(1), &frames[1], used), 1);

        let later = now + ttl + Duration::from_secs(30);
        bound.tidy(later, |_| true);
        assert_eq!(send(&mut bound, addr(1), &frames[2], later), 1);
    }

    #[test]
    fn an_anchor_nobody_uses_goes_at_its_time() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        bound.tidy(now + ttl - Duration::from_secs(1), |_| true);
        assert_eq!(bound.usage().anchors, 1);
        bound.tidy(now + ttl, |_| true);
        assert_eq!(bound.usage().anchors, 0);

        assert_eq!(send(&mut bound, addr(1), &later, now + ttl), 0);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
    }

    /// With no tidy since, an anchor past its time is no anchor either.
    #[test]
    fn an_anchor_past_its_time_opens_nothing_before_the_next_tidy() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        assert_eq!(send(&mut bound, addr(1), &later, now + ttl), 0);
    }

    #[test]
    fn an_anchor_that_went_comes_back_with_its_segment_0() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);
        bound.tidy(now + ttl, |_| true);
        assert_eq!(send(&mut bound, addr(1), &later, now + ttl), 0);

        assert_eq!(send(&mut bound, addr(1), &first, now + ttl), 2);

        assert_eq!(bound.usage().objects_waiting_for_segment_0, 0);
    }

    /// Room in the table comes back with time, and a key has its share again.
    #[test]
    fn a_keys_share_of_the_anchors_comes_back_at_their_time() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        assert_eq!(send(&mut bound, addr(1), &one_segment(2), now), 0);

        assert_eq!(send(&mut bound, addr(1), &one_segment(2), now + ttl), 1);
    }

    /// Each frame of a body, as its datagrams.
    type SealedFrames = Vec<Vec<Vec<u8>>>;

    /// Two bodies of one block: the same header, and so the same hash, in two segments each.
    fn rivals() -> (SealedFrames, SealedFrames) {
        let size = 2 * SEGMENT_BYTES as usize;
        let (mut honest, mut rival) = (vec![1u8; size], vec![1u8; size]);
        honest[size - 1] = 2;
        rival[size - 1] = 3;
        let frames = |raw: &[u8]| -> SealedFrames {
            let frames = body_frames(raw).unwrap();
            let sealed = frames
                .iter()
                .map(|frame| sealed_frame(frame, &KEY).unwrap());
            sealed.collect()
        };
        (frames(&honest), frames(&rival))
    }

    /// A body's own segment 0 is what opens its way. Another body's, under the same header,
    /// proves nothing about this one.
    #[test]
    fn a_rival_body_does_not_inherit_an_anchor() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (honest, rival) = rivals();
        assert_eq!(send(&mut bound, addr(1), &honest[0], now), 1);

        assert_eq!(send_as(&mut bound, OTHER, addr(2), &rival[1], now), 0);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);

        assert_eq!(send(&mut bound, addr(1), &honest[1], now), 1);
        assert_eq!(
            bound.usage().objects_waiting_for_segment_0,
            1,
            "still waiting"
        );
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &rival[0], now), 2);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 0);
    }

    #[test]
    fn a_block_takes_only_so_many_bodies_at_a_relay() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let limit = bound.config.max_bodies_per_block as u8;

        for mark in 0..limit {
            let key_id = format!("key{mark}");
            assert_eq!(
                send_as(
                    &mut bound,
                    &key_id,
                    addr(u16::from(mark) + 1),
                    &body_of_a_block(mark),
                    now
                ),
                1
            );
        }
        let past = send_as(&mut bound, "last", addr(99), &body_of_a_block(limit), now);

        assert_eq!(past, 0);
        assert_eq!(bound.usage().anchors, usize::from(limit));
        assert_eq!(bound.usage().anchors_refused_for_bodies, 1);
    }

    /// A body already here is not one more body, so a resend of it gets through.
    #[test]
    fn a_body_that_has_its_anchor_can_come_again_with_the_block_full() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let limit = bound.config.max_bodies_per_block as u8;
        for mark in 0..limit {
            send(&mut bound, addr(1), &body_of_a_block(mark), now);
        }

        let resent = send(
            &mut bound,
            addr(1),
            &body_of_a_block(0),
            now + Duration::from_secs(3),
        );

        assert_eq!(resent, 1);
        assert_eq!(bound.usage().anchors_refused_for_bodies, 0);
    }

    /// A body turned away is no bad body: it leaves no record, and once a place is free it
    /// gets through.
    #[test]
    fn a_body_turned_away_can_cross_when_its_block_has_room() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let limit = bound.config.max_bodies_per_block as u8;
        for mark in 0..limit {
            send(&mut bound, addr(1), &body_of_a_block(mark), now);
        }
        assert_eq!(send(&mut bound, addr(2), &body_of_a_block(limit), now), 0);

        bound.tidy(now + ttl, |_| true);

        assert_eq!(
            send(&mut bound, addr(2), &body_of_a_block(limit), now + ttl),
            1
        );
    }

    /// A key that saw the header first can pay for only its share of the block's bodies, so
    /// a real body under that block from another key still gets a place. This was a known
    /// gap: one key could take every body a block has.
    #[test]
    fn one_key_cannot_use_up_a_blocks_bodies() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let limit = bound.config.max_bodies_per_block as u8;
        assert!(MAX_BODIES_PER_KEY_PER_BLOCK < limit as usize);
        for mark in 0..limit {
            let opened = send_as(&mut bound, OTHER, addr(1), &body_of_a_block(mark), now);
            let mine = usize::from(mark) < MAX_BODIES_PER_KEY_PER_BLOCK;
            assert_eq!(opened, usize::from(mine), "body {mark}");
        }
        let refused = limit as u64 - MAX_BODIES_PER_KEY_PER_BLOCK as u64;
        assert_eq!(bound.usage().anchors_refused_for_key_bodies, refused);

        assert_eq!(send(&mut bound, addr(2), &body_of_a_block(limit), now), 1);
    }

    /// A receiver's refusal frees the place a body held in its block, and its segment 0 opens
    /// nothing again while the refusal stands. A rival body of the same block then gets in.
    #[test]
    fn a_released_body_frees_its_place_and_stays_out() {
        let mut config = config();
        config.max_bodies_per_block = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (forged, honest) = (body_of_a_block(1), body_of_a_block(2));
        assert_eq!(send_as(&mut bound, OTHER, addr(1), &forged, now), 1);
        assert_eq!(send(&mut bound, addr(2), &honest, now), 0);
        assert_eq!(bound.usage().anchors_refused_for_bodies, 1);
        let key = only_anchor(&bound);

        assert!(bound.release(key, now));

        let again = now + Duration::from_secs(5);
        assert_eq!(send_as(&mut bound, OTHER, addr(3), &forged, again), 0);
        assert_eq!(bound.usage().anchors_refused_as_released, 1);
        assert_eq!(send(&mut bound, addr(4), &honest, again), 1);
        assert_eq!(bound.usage().anchors_released, 1);
        assert!(!bound.release(key, again), "no anchor is left to release");
        let lapsed = again + bound.config.anchor_ttl;
        bound.tidy(lapsed, |_| true);
        assert!(bound.anchors.released.is_empty());
    }

    fn only_anchor(bound: &BoundForwarder) -> SetKey {
        let (block_hash, bodies) = bound.anchors.blocks.iter().next().unwrap();
        assert_eq!(bodies.len(), 1);
        SetKey {
            block_hash: *block_hash,
            body_id: bodies[0].body_id,
        }
    }

    fn at_time(mark: u32, time: u32) -> Vec<Vec<u8>> {
        let mut raw = vec![0u8; 5000];
        raw[..4].copy_from_slice(&mark.to_le_bytes());
        raw[HEADER_TIME].copy_from_slice(&time.to_le_bytes());
        sealed_body(&raw, &KEY).unwrap()
    }

    /// A header far behind the newest one here is refused before its PoW check, and it costs
    /// nothing: it was a known gap that any old header with good PoW opened an anchor.
    #[test]
    fn an_old_header_opens_no_anchor_next_to_a_newer_one() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let window = ANCHOR_HEADER_WINDOW.as_secs() as u32;
        let newest = 1_700_000_000;
        assert_eq!(send(&mut bound, addr(1), &at_time(1, newest), now), 1);
        let checks = std::cell::Cell::new(0);
        let count = |_: &[u8]| {
            checks.set(checks.get() + 1);
            PowResult::Valid
        };

        for datagram in &at_time(2, newest - window - 1) {
            let step = bound.take(addr(2), KEY, FLEET, datagram, now, count);
            assert!(matches!(step, BoundStep::Forward(objects) if objects.is_empty()));
        }

        assert_eq!(checks.get(), 0, "an old header was checked");
        assert_eq!(bound.usage().anchors_refused_for_age, 1);
        assert_eq!(
            send(&mut bound, addr(3), &at_time(3, newest - window), now),
            1
        );
    }

    /// A table that old headers filled, before anything newer came, is cleared by the first
    /// newer header that passes. A cold start is no way to hold the path shut for good.
    #[test]
    fn a_newer_header_clears_a_table_old_headers_filled() {
        let mut config = config();
        config.max_anchors = 4;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let old = 1_600_000_000;
        for mark in 0..4 {
            let key_id = format!("key{mark}");
            send_as(
                &mut bound,
                &key_id,
                addr(10 + mark as u16),
                &at_time(mark, old),
                now,
            );
        }
        assert_eq!(bound.usage().anchors, 4);

        assert_eq!(send(&mut bound, addr(1), &at_time(9, old + 3600), now), 1);

        assert_eq!(bound.usage().anchors, 1);
        assert_eq!(bound.usage().anchors_refused_for_room, 0);
    }

    #[test]
    fn a_frame_waiting_for_segment_0_gives_its_room_back() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let time = WAITING_TTL;
        hold_decoded(&mut bound, addr(1), 1, now);
        let held = bound.usage().pool.held_bytes;
        assert!(held > 0);

        bound.tidy(now + time - Duration::from_secs(1), |_| true);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
        assert_eq!(bound.usage().pool.held_bytes, held);

        bound.tidy(now + time, |_| true);

        assert_eq!(bound.usage().objects_waiting_for_segment_0, 0);
        assert_eq!(bound.usage().pool.held_bytes, 0);
        assert_eq!(bound.key_used(FLEET).held_bytes, 0);
        assert_eq!(bound.usage().waiting_expired, 1);
    }

    /// Its time up, the object is not refused: a copy can wait again.
    #[test]
    fn a_frame_that_stopped_waiting_can_come_again() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let time = WAITING_TTL;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &later, now), 0);
        bound.tidy(now + time, |_| true);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 0);

        let again = now + time + Duration::from_secs(1);
        assert_eq!(send(&mut bound, addr(1), &later, again), 0);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
        assert_eq!(send(&mut bound, addr(1), &first, again), 2);
    }

    /// A first datagram holds the room of its whole object, so on a node that lasts only as
    /// long as finishing it can take.
    #[test]
    fn a_node_keeps_an_open_object_only_for_its_own_time() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        open_one(&mut bound, addr(1), 1, now);
        let held = bound.usage().pool.held_bytes;
        assert!(held > 0);

        bound.tidy(now + NODE_ASSEMBLY_TTL - Duration::from_millis(1), |_| true);
        assert_eq!(open_in(&bound, addr(1)), 1);

        bound.tidy(now + NODE_ASSEMBLY_TTL, |_| true);
        assert_eq!(open_in(&bound, addr(1)), 0);
        assert_eq!(bound.usage().pool.held_bytes, 0);
    }

    /// A session waits for no more than its limit, whatever its budget has room for.
    #[test]
    fn a_session_keeps_only_so_many_objects_waiting() {
        let mut config = config();
        config.max_unanchored = 2;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());

        for fill in 1..=3 {
            assert_eq!(send(&mut bound, addr(1), &two_frames(fill).1, now), 0);
        }

        assert_eq!(bound.usage().objects_waiting_for_segment_0, 2);
        assert_eq!(bound.usage().waiting_pushed_out, 1);
    }

    #[test]
    fn a_rival_segment_0_does_not_release_another_bodys_frames() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let (honest, rival) = rivals();
        assert_eq!(send(&mut bound, addr(1), &honest[1], now), 0);

        assert_eq!(send_as(&mut bound, OTHER, addr(2), &rival[0], now), 1);

        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
        assert_eq!(bound.usage().anchors, 1);
        assert_eq!(send(&mut bound, addr(1), &honest[0], now), 2);
        assert_eq!(bound.usage().anchors, 2);
    }

    /// One body is one anchor, however many keys bring it, and each key with room pays for it.
    #[test]
    fn a_body_from_two_keys_is_one_anchor_both_pay_for() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (first, _) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        assert_eq!(send_as(&mut bound, OTHER, addr(2), &first, now), 1);

        assert_eq!(bound.usage().anchors, 1);
        assert_eq!(bound.anchors.of_key(FLEET, now), 1);
        assert_eq!(bound.anchors.of_key(OTHER, now), 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &one_segment(2), now), 0);
    }

    #[test]
    fn a_key_at_its_share_can_still_bring_a_body_with_an_anchor() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let (first, later) = two_frames(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &one_segment(2), now), 1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        assert_eq!(send_as(&mut bound, OTHER, addr(2), &first, now), 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &later, now), 1);

        assert_eq!(bound.usage().anchors_refused_for_room, 0);
        assert_eq!(bound.usage().anchor_uses_without_room, 2);
        assert_eq!(bound.anchors.of_key(OTHER, now), 1);
    }

    /// Using a body's anchor keeps it, at the cost of the key that used it. The first key's
    /// time stays its own.
    #[test]
    fn another_keys_use_keeps_an_anchor_at_its_own_cost() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        let used = now + ttl - Duration::from_secs(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &later, used), 1);
        let first_time_up = now + ttl;
        bound.tidy(first_time_up, |_| true);

        assert_eq!(bound.usage().anchors, 1);
        assert_eq!(bound.anchors.of_key(FLEET, first_time_up), 0);
        assert_eq!(bound.anchors.of_key(OTHER, first_time_up), 1);
    }

    /// A payment does not end with its key's sessions, so the anchor stays and its key goes on
    /// paying to the end of it.
    #[test]
    fn a_key_with_no_session_left_keeps_paying_and_its_anchors_stay() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);
        open_as(&mut bound, OTHER, addr(2), 9, now);

        bound.tidy(now, |src| *src != addr(1));

        assert_eq!(bound.anchors.of_key(FLEET, now), 1);
        assert_eq!(bound.usage().anchors, 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &later, now), 1);
        assert_eq!(bound.anchors.of_key(OTHER, now), 1);
        assert_eq!(send(&mut bound, addr(3), &one_segment(3), now), 0);

        let lapsed = now + ttl;
        assert_eq!(send(&mut bound, addr(3), &one_segment(3), lapsed), 1);
        assert_eq!(bound.anchors.of_key(FLEET, now), 1);
        assert_eq!(bound.usage().anchors, 1);
    }

    /// One opens, another goes on using, the first uses it no more. The body under way keeps
    /// its anchor, and nobody's use holds down the share of a key that has moved on.
    #[test]
    fn a_key_stops_paying_when_only_another_key_uses_its_anchor() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let frames: Vec<_> = body_frames(&vec![1u8; 4 * SEGMENT_BYTES as usize])
            .unwrap()
            .iter()
            .map(|frame| sealed_frame(frame, &KEY).unwrap())
            .collect();
        assert_eq!(send(&mut bound, addr(1), &frames[0], now), 1);

        let renewed = now + ttl - Duration::from_secs(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &frames[1], renewed), 1);

        let past_its_own_time = now + ttl;
        assert_eq!(
            send(&mut bound, addr(1), &one_segment(2), past_its_own_time),
            1
        );
        let still_under_way = renewed + ttl - Duration::from_secs(1);
        assert_eq!(
            send_as(&mut bound, OTHER, addr(2), &frames[2], still_under_way),
            1
        );
    }

    /// Using an anchor is not ending someone else's charge either.
    #[test]
    fn another_keys_use_does_not_end_a_charge_early() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        let used = now + ttl - Duration::from_secs(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &later, used), 1);

        assert_eq!(send(&mut bound, addr(1), &one_segment(2), used), 0);
        assert_eq!(bound.anchors.of_key(FLEET, used), 1);
    }

    /// A key's own use goes on costing it.
    #[test]
    fn a_key_that_keeps_using_what_it_opened_keeps_paying() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let (first, later) = two_frames(1);
        assert_eq!(send(&mut bound, addr(1), &first, now), 1);

        let used = now + ttl - Duration::from_secs(1);
        assert_eq!(send(&mut bound, addr(1), &later, used), 1);

        let its_first_time_up = now + ttl;
        assert_eq!(bound.anchors.of_key(FLEET, its_first_time_up), 1);
        assert_eq!(
            send(&mut bound, addr(3), &one_segment(2), its_first_time_up),
            0
        );
    }

    /// The first key's time runs out, and the key still using the anchor has paid for it since
    /// it first did. The first has its share back, and the body has lost nothing.
    #[test]
    fn a_key_still_using_an_anchor_holds_it_after_the_first_stops() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let frames = three_frames(1);
        assert_eq!(send(&mut bound, addr(1), &frames[0], now), 1);
        let renewed = now + ttl - Duration::from_secs(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &frames[1], renewed), 1);

        let later = now + ttl + Duration::from_secs(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &frames[2], later), 1);

        assert_eq!(bound.anchors.of_key(FLEET, later), 0);
        assert_eq!(bound.anchors.of_key(OTHER, later), 1);
        assert_eq!(
            send_as(&mut bound, OTHER, addr(2), &one_segment(3), later),
            0
        );
    }

    /// What cannot all be had. `OTHER` is at its share with a body of its own, and uses a body
    /// `FLEET` opened, which gets through on what `FLEET` pays and extends nothing. When `FLEET`
    /// stops the anchor could stay only with nobody paying or with `OTHER` past its share, and
    /// making room would cost `OTHER` its own body. So it goes. What comes next of that body
    /// waits, and a copy of its segment 0 opens the way once `OTHER` has room.
    #[test]
    fn a_body_under_way_waits_when_its_key_has_no_room_and_nobody_pays() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let frames = three_frames(1);
        let (own, own_later) = two_frames(2);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &own, now), 1);
        assert_eq!(send(&mut bound, addr(1), &frames[0], now), 1);
        let renewed = now + Duration::from_secs(10);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &own_later, renewed), 1);

        let used = now + ttl - Duration::from_secs(1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &frames[1], used), 1);
        assert_eq!(bound.usage().anchor_uses_without_room, 1);

        let stopped = now + ttl;
        assert_eq!(bound.anchors.of_key(FLEET, stopped), 0);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &frames[2], stopped), 0);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &frames[0], stopped), 0);
        assert_eq!(bound.usage().anchors_refused_for_room, 1);
        assert_eq!(bound.anchors.of_key(OTHER, stopped), 1, "its own, no more");

        let room_back = renewed + ttl;
        bound.tidy(room_back, |_| true);
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 1);
        assert_eq!(
            send_as(&mut bound, OTHER, addr(2), &frames[0], room_back),
            2
        );
        assert_eq!(bound.usage().objects_waiting_for_segment_0, 0);
    }

    /// What two keys came to against a table of four shares: the anchors after each time the
    /// first opened, then at the end those in the table, those the three keys pay for, what a
    /// third key got through and how often the table turned something away.
    type TwoKeys = (Vec<usize>, usize, usize, usize, u64);

    /// Each opens no more than its share and they work together. `FLEET` opens its share each
    /// time its last payment runs out and `OTHER` uses all of it, from the opening on if
    /// `other_opens`, in time for nothing to lapse. If `leave`, every session goes each round.
    fn two_keys_against_the_table(other_opens: bool, rounds: usize, leave: bool) -> TwoKeys {
        let mut config = config();
        config.max_anchors = 8;
        config.max_anchors_per_key = 2;
        let share = config.max_anchors_per_key;
        let (mut bound, start) = (BoundForwarder::new(config).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        let bodies: Vec<SealedFrames> = (1..=12u8)
            .map(|fill| {
                let frames = body_frames(&dated(fill, 6)).unwrap();
                let sealed = frames
                    .iter()
                    .map(|frame| sealed_frame(frame, &KEY).unwrap());
                sealed.collect()
            })
            .collect();
        let mut fresh = bodies.iter();
        let mut opened = Vec::new();
        if other_opens {
            for body in fresh.by_ref().take(share) {
                send_as(&mut bound, OTHER, addr(2), &body[0], start);
                opened.push(body);
            }
        }
        let (mut standing, mut end) = (Vec::new(), start);
        for round in 0..rounds {
            let at = start + ttl * round as u32;
            for body in fresh.by_ref().take(share) {
                send_as(&mut bound, FLEET, addr(1), &body[0], at);
                opened.push(body);
            }
            standing.push(bound.usage().anchors);
            end = at + ttl - Duration::from_secs(1 + round as u64);
            for body in &opened {
                send_as(&mut bound, OTHER, addr(2), &body[round + 1], end);
            }
            if leave {
                bound.tidy(end, |_| false);
            }
        }
        let third = send_as(&mut bound, "third", addr(3), &one_segment(99), end);
        let usage = bound.usage();
        let keys = [FLEET, OTHER, "third"];
        let paid = keys.map(|key_id| bound.anchors.of_key(key_id, end));
        (
            standing,
            usage.anchors,
            paid.iter().sum(),
            third,
            usage.anchors_refused_for_room,
        )
    }

    #[test]
    fn two_keys_cannot_fill_the_table_past_their_shares() {
        assert_eq!(
            two_keys_against_the_table(true, 3, false),
            (vec![4, 4, 4], 5, 5, 1, 0)
        );
    }

    #[test]
    fn two_keys_leaving_and_coming_back_stay_inside_their_shares() {
        assert_eq!(
            two_keys_against_the_table(true, 3, true),
            (vec![4, 4, 4], 5, 5, 1, 0)
        );
    }

    #[test]
    fn a_key_that_opens_nothing_adds_no_more_than_its_share() {
        assert_eq!(
            two_keys_against_the_table(false, 4, false),
            (vec![2, 4, 4, 4], 5, 5, 1, 0)
        );
    }

    #[test]
    fn a_key_with_a_session_left_keeps_paying() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        open_one(&mut bound, addr(2), 9, now);

        bound.tidy(now, |src| *src != addr(1));

        assert_eq!(bound.anchors.of_key(FLEET, now), 1);
    }

    /// With no session left an anchor still goes at its time, and its charge with it.
    #[test]
    fn an_anchor_of_a_key_with_no_session_goes_at_its_time() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        bound.tidy(now, |_| false);
        assert_eq!(bound.usage().anchors, 1);

        bound.tidy(now + ttl, |_| false);

        assert_eq!(bound.usage().anchors, 0);
        assert_eq!(bound.anchors.of_key(FLEET, now), 0);
        assert!(bound.anchors.blocks.is_empty());
    }

    #[test]
    fn an_anchor_that_goes_takes_its_charge_and_its_block_with_it() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        let ttl = bound.config.anchor_ttl;
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        assert_eq!(bound.anchors.of_key(FLEET, now), 1);

        bound.tidy(now + ttl, |_| true);

        assert_eq!(bound.anchors.of_key(FLEET, now), 0);
        assert!(bound.anchors.blocks.is_empty());
    }

    /// A panic takes a session and not what its key has opened, nor what that costs.
    #[test]
    fn a_panic_does_not_free_what_its_key_opened() {
        let (mut bound, now) = (BoundForwarder::new(config()).unwrap(), Instant::now());
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        bound.trips = vec![Trip::Arrived(addr(1))];

        open_one(&mut bound, addr(1), 9, now);

        assert!(bound.trips.is_empty(), "it never got as far as the panic");
        assert_eq!(bound.anchors.of_key(FLEET, now), 1);
        bound.tidy(now, |_| true);
        assert_eq!(bound.anchors.of_key(FLEET, now), 1);
        assert_eq!(bound.usage().anchors, 1);
    }

    #[test]
    fn starting_over_forgets_every_anchor_and_who_paid() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &one_segment(2), now), 1);
        assert_eq!(send_as(&mut bound, OTHER, addr(2), &one_segment(1), now), 1);

        bound.start_over();

        let usage = bound.usage();
        assert_eq!(usage.anchors, 0);
        assert_eq!(usage.anchor_uses_without_room, 1, "the count stays");
        assert_eq!(bound.anchors.of_key(FLEET, now), 0);
    }

    #[test]
    fn anchor_limits_of_zero_do_not_start() {
        for limit in 0..3 {
            let mut config = config();
            match limit {
                0 => config.max_anchors = 0,
                1 => config.max_anchors_per_key = 0,
                _ => config.max_bodies_per_block = 0,
            }
            assert!(BoundForwarder::new(config).is_err());
        }
    }

    #[test]
    fn the_bound_switch_means_what_it_says() {
        let read = |value: &str| read_bound_raw_switch(Some(value.as_ref()));

        assert_eq!(read_bound_raw_switch(None), Ok(false));
        for value in ["1", "true", "TRUE", " true ", "yes", "on"] {
            assert_eq!(read(value), Ok(true), "{value:?}");
        }
        for value in ["0", "false", "False", " 0 ", "no", "off", "", "   "] {
            assert_eq!(read(value), Ok(false), "{value:?}");
        }
        for value in ["2", "-1", "maybe", "truee", "enabled", "1 0"] {
            let error = read(value).unwrap_err();
            assert!(error.contains(BOUND_RAW_SWITCH), "{error}");
            assert!(error.contains(value), "{error}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let not_text = std::ffi::OsStr::from_bytes(&[0xff]);
            assert!(read_bound_raw_switch(Some(not_text)).is_err());
        }
    }

    /// Asking again takes a look at the table. It costs the PoW check nothing, so a segment 0
    /// turned away is not worth a flood.
    #[test]
    fn a_body_turned_away_costs_no_pow_check() {
        let mut config = config();
        config.max_anchors_per_key = 1;
        let (mut bound, now) = (BoundForwarder::new(config).unwrap(), Instant::now());
        assert_eq!(send(&mut bound, addr(1), &one_segment(1), now), 1);
        let checks = std::cell::Cell::new(0);
        let count = |_: &[u8]| {
            checks.set(checks.get() + 1);
            PowResult::Valid
        };

        for datagram in one_segment(2) {
            bound.take(addr(1), KEY, FLEET, &datagram, now, count);
        }

        assert_eq!(checks.get(), 0);
        assert_eq!(bound.usage().anchors_refused_for_room, 1);
    }
}
