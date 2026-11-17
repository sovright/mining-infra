//! A small research buffer for the competing bodies of a block, on top of the delivery
//! ledger. Only the bound raw path uses it, and it is not the sidecar's `RawSegmentBuffer`.
//!
//! Sets are keyed by `(block_hash, body_id)`, so two bodies of one header never share a
//! slot. A segment's payload and its lease live in one record, so dropping a set is what
//! evicts it, and nothing has to find out afterwards what went.
//!
//! Only a [`VerifiedSegment`] can enter, and only [`verify`](super::segment_frame::verify)
//! makes one. Two segments of one key therefore agree on their metadata, and a slot can
//! only ever hold the bytes its proof names. A sender cannot claim another body's slot.
//! It can still build a consistent body of its own, which gets a set of its own and
//! competes for the same limits. That competition is an open limit here.
//!
//! What each path lets go of, payload first and lease after in every case:
//!
//! | Path                | Payload                    | Reservation                  |
//! |---------------------|----------------------------|------------------------------|
//! | Set too big to fit  | That segment's only        | That segment's only          |
//! | Eviction, `discard` | Every segment of the set   | Every segment of the set     |
//! | TTL                 | Every segment of the set   | Every segment of the set     |
//! | Complete            | Nothing, the caller has it | Nothing, the caller has them |
//! | Assembly            | Segments, once copied      | Kept, see [`AssembledBlock`] |
//! | Assembly refused    | Every segment of the set   | Every segment of the set     |
//!
//! No path here calls [`Lease::complete`] on its own. A set being whole says nothing
//! about whether anyone wants the body, and what follows a refusal is the caller's
//! policy, which is not decided. The research default is [`AssembledBlock::give_back`].

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::segment_frame::{SetKey, VerifiedSegment};
use super::{Admission, DeliveryLedger, Holding, Lease, Phase, Refusal, Ticket};

/// How long a set counts as still arriving after its last segment came. Room is never made
/// by giving up such a set: a newcomer, however many there are, waits instead (see
/// [`BodyBuffer::room_for`]). A set quiet for longer can go, the least advanced and then the
/// newest first, since the oldest is likeliest to be the body that came first.
///
/// A research value. An honest body's segments come in one paced burst, and a resend comes
/// a relay node's `resend_after` behind it, so this is longer than both; a set held open by a trickle still
/// ends at the buffer's TTL, counted from its first segment.
pub const ACTIVE_SET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub struct BufferLimits {
    pub max_sets: usize,
    /// When a block is at this limit, its least advanced set goes, and no other block's.
    pub max_sets_per_block: usize,
    pub max_segments: usize,
    pub ttl: Duration,
}

/// A limit of zero leaves nothing to evict and nowhere to put a set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidLimits(pub &'static str);

/// A verified segment and its ownership, as one value. Fields drop in order, so a
/// segment lost in a queue loses its payload before its reservation comes back.
/// `witness` sits between them for tests that watch the order; it is `()` otherwise.
#[derive(Debug)]
pub struct Arrival<W = ()> {
    segment: VerifiedSegment,
    witness: W,
    ticket: Ticket,
}

impl Arrival {
    pub fn new(segment: VerifiedSegment, ticket: Ticket) -> Self {
        Self::with_witness(segment, ticket, ())
    }
}

impl<W> Arrival<W> {
    /// # Panics
    ///
    /// If the ticket is for another object: that is a bug in the caller.
    pub fn with_witness(segment: VerifiedSegment, ticket: Ticket, witness: W) -> Self {
        assert_eq!(ticket.id(), segment.ledger_key());
        Self {
            segment,
            witness,
            ticket,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The set could never fit, whatever else was evicted.
    TooManySegments,
    /// Room could only have been made by giving up a set that is still arriving. This is no
    /// fact about the segment: it can come again. See [`ACTIVE_SET`].
    Busy,
}

#[derive(Debug)]
pub enum Outcome<W = ()> {
    Pending,
    Complete(CompleteSet<W>),
    Rejected(Reject),
}

#[derive(Debug)]
pub struct Insertion<W = ()> {
    pub outcome: Outcome<W>,
    /// Sets dropped to make room, for the record. They are gone by now.
    pub evicted: Vec<SetKey>,
}

/// Fields drop in order: payload, then the lease that counts it.
#[derive(Debug)]
struct Held<W> {
    payload: Vec<u8>,
    witness: W,
    lease: Lease,
}

#[derive(Debug)]
struct BodySet<W> {
    raw_len: u64,
    first_seen: Instant,
    /// When its last segment came. See [`ACTIVE_SET`].
    last_arrival: Instant,
    order: u64,
    filled: usize,
    bytes: usize,
    slots: Vec<Option<Held<W>>>,
}

/// One set that could be given up, and what doing so would free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evictable {
    pub key: SetKey,
    pub holding: Holding,
}

#[derive(Debug)]
pub struct BodyBuffer<W = ()> {
    limits: BufferLimits,
    sets: HashMap<SetKey, BodySet<W>>,
    segments: usize,
    next_order: u64,
}

impl<W> BodyBuffer<W> {
    pub fn new(limits: BufferLimits) -> Result<Self, InvalidLimits> {
        if limits.max_sets == 0 {
            return Err(InvalidLimits("max_sets"));
        }
        if limits.max_sets_per_block == 0 {
            return Err(InvalidLimits("max_sets_per_block"));
        }
        if limits.max_segments == 0 {
            return Err(InvalidLimits("max_segments"));
        }
        if limits.ttl.is_zero() {
            return Err(InvalidLimits("ttl"));
        }
        Ok(Self {
            limits,
            sets: HashMap::new(),
            segments: 0,
            next_order: 0,
        })
    }

    pub fn sets(&self) -> usize {
        self.sets.len()
    }

    pub fn segments(&self) -> usize {
        self.segments
    }

    pub fn holds(&self, key: &SetKey) -> bool {
        self.sets.contains_key(key)
    }

    /// Whether a set of `count` segments could ever fit, whatever else was evicted.
    pub fn can_hold(&self, count: u16) -> bool {
        usize::from(count) <= self.limits.max_segments
    }

    pub fn insert(&mut self, arrival: Arrival<W>, now: Instant) -> Insertion<W> {
        let Arrival {
            segment,
            witness,
            ticket,
        } = arrival;
        let (key, index, segment_count, raw_len) = (
            segment.key(),
            usize::from(segment.index()),
            segment.count(),
            segment.raw_len(),
        );
        let held = Held {
            payload: segment.into_payload(),
            witness,
            lease: ticket.accept(),
        };
        if !self.can_hold(segment_count) {
            drop(held);
            return Insertion {
                outcome: Outcome::Rejected(Reject::TooManySegments),
                evicted: Vec::new(),
            };
        }

        let Some(victims) = self.room_for(&key, now) else {
            drop(held);
            return Insertion {
                outcome: Outcome::Rejected(Reject::Busy),
                evicted: Vec::new(),
            };
        };
        let mut evicted = Vec::new();
        for victim in &victims {
            self.drop_set(victim, &mut evicted);
        }

        let order = self.next_order;
        let set = self.sets.entry(key).or_insert_with(|| BodySet {
            raw_len,
            first_seen: now,
            last_arrival: now,
            order,
            filled: 0,
            bytes: 0,
            slots: std::iter::repeat_with(|| None)
                .take(usize::from(segment_count))
                .collect(),
        });
        // One ticket per object means one arrival per slot, and the proof fixes the bytes.
        debug_assert!(set.slots[index].is_none());
        set.last_arrival = now;
        set.bytes += held.payload.len();
        set.slots[index] = Some(held);
        set.filled += 1;
        self.segments += 1;
        self.next_order += 1;

        let outcome = if set.filled == set.slots.len() {
            let set = self.sets.remove(&key).expect("this set was just filled");
            self.segments -= set.filled;
            Outcome::Complete(CompleteSet {
                key,
                raw_len: set.raw_len,
                segments: set.slots.into_iter().flatten().collect(),
            })
        } else {
            Outcome::Pending
        };
        Insertion { outcome, evicted }
    }

    /// The sets that would go for a segment of `key` to fit at `now`, or `None` if only a set
    /// still arriving could make room ([`ACTIVE_SET`]). A new set of a block at
    /// [`BufferLimits::max_sets_per_block`] takes one of that block's quiet sets, and then
    /// the counts of sets and segments take quiet sets of any block: the least advanced
    /// first and, of those, the newest. `key`'s own set never goes.
    pub fn room_for(&self, key: &SetKey, now: Instant) -> Option<Vec<SetKey>> {
        let mut quiet: Vec<_> = self
            .sets
            .iter()
            .filter(|(other, set)| *other != key && !set.is_active(now))
            .collect();
        quiet.sort_by_key(|(_, set)| (set.filled, std::cmp::Reverse(set.order)));
        let mut gone = Vec::new();
        let mut taken = HashSet::new();
        let (mut sets, mut segments) = (self.sets.len(), self.segments);
        let mut take = |same_block: bool, sets: &mut usize, segments: &mut usize| {
            let next = quiet.iter().find(|(other, _)| {
                !taken.contains(*other) && (!same_block || other.block_hash == key.block_hash)
            });
            let (other, set) = next?;
            taken.insert(**other);
            gone.push(**other);
            *sets -= 1;
            *segments -= set.filled;
            Some(())
        };
        if !self.sets.contains_key(key) {
            let in_block = self
                .sets
                .keys()
                .filter(|other| other.block_hash == key.block_hash);
            if in_block.count() >= self.limits.max_sets_per_block {
                take(true, &mut sets, &mut segments)?;
            }
            while sets >= self.limits.max_sets {
                take(false, &mut sets, &mut segments)?;
            }
        }
        while segments >= self.limits.max_segments {
            take(false, &mut sets, &mut segments)?;
        }
        Some(gone)
    }

    fn drop_set(&mut self, key: &SetKey, evicted: &mut Vec<SetKey>) {
        if let Some(set) = self.sets.remove(key) {
            self.segments -= set.filled;
            evicted.push(*key);
        }
    }

    /// The sets this buffer could give up for `incoming` at `now`, best victim first: the
    /// least advanced of its own block, then the oldest of the rest. `incoming`'s own set is
    /// never offered, and nothing outside this buffer ever is. For a segment, a set still
    /// arriving is not offered either ([`ACTIVE_SET`]). With nothing incoming, for the copy of
    /// a whole body, it is: refusing that copy would lose a body that is all there.
    pub fn evictable(&self, incoming: Option<&SetKey>, now: Instant) -> Vec<Evictable> {
        let offered = |(key, set): &(&SetKey, &BodySet<W>)| match incoming {
            Some(incoming) => *key != incoming && !set.is_active(now),
            None => true,
        };
        let mut sets: Vec<_> = self.sets.iter().filter(offered).collect();
        sets.sort_by_key(|(key, set)| {
            let same_block = incoming.is_some_and(|other| other.block_hash == key.block_hash);
            (!same_block, same_block.then_some(set.filled), set.order)
        });
        sets.into_iter()
            .map(|(key, set)| Evictable {
                key: *key,
                holding: Holding {
                    bytes: set.bytes,
                    owners: set.filled,
                },
            })
            .collect()
    }

    /// Give up on a set the caller no longer wants.
    pub fn discard(&mut self, key: &SetKey) -> bool {
        let mut gone = Vec::new();
        self.drop_set(key, &mut gone);
        !gone.is_empty()
    }

    pub fn expire(&mut self, now: Instant) -> Vec<SetKey> {
        let ttl = self.limits.ttl;
        let lapsed: Vec<SetKey> = self
            .sets
            .iter()
            .filter(|(_, set)| now.saturating_duration_since(set.first_seen) >= ttl)
            .map(|(key, _)| *key)
            .collect();
        let mut gone = Vec::new();
        for key in &lapsed {
            self.drop_set(key, &mut gone);
        }
        gone
    }
}

impl<W> BodySet<W> {
    fn is_active(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_arrival) < ACTIVE_SET
    }
}

/// A whole set, out of the buffer, with its payloads and leases.
#[derive(Debug)]
pub struct CompleteSet<W = ()> {
    pub key: SetKey,
    raw_len: u64,
    segments: Vec<Held<W>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssemblyError {
    Refused(Refusal),
    /// This body is already assembled and in someone's hands.
    Owned(Phase),
    Completed,
}

impl<W> CompleteSet<W> {
    pub fn raw_len(&self) -> u64 {
        self.raw_len
    }

    /// Reserve the copy first, because the segments and the block are alive together
    /// while it runs. Any failure gives the whole set back. `wrap` receives the copy.
    /// The rules that made these segments guarantee they add up to `raw_len`.
    pub fn assemble<B>(
        self,
        ledger: &DeliveryLedger,
        now: Instant,
        wrap: impl FnOnce(Vec<u8>) -> B,
    ) -> Result<AssembledBlock<B>, AssemblyError> {
        let admission = ledger.admit(self.key.body_id, self.raw_len as usize, now);
        self.assemble_under(admission, wrap)
    }

    /// The copy, under a reservation the caller has already asked for.
    pub(super) fn assemble_under<B>(
        self,
        admission: Admission,
        wrap: impl FnOnce(Vec<u8>) -> B,
    ) -> Result<AssembledBlock<B>, AssemblyError> {
        let ticket = match admission {
            Admission::Admitted(ticket) => ticket,
            Admission::Owned(phase) => return Err(AssemblyError::Owned(phase)),
            Admission::Completed => return Err(AssemblyError::Completed),
            Admission::Refused(refusal) => return Err(AssemblyError::Refused(refusal)),
        };
        let mut raw = Vec::with_capacity(self.raw_len as usize);
        for segment in &self.segments {
            raw.extend_from_slice(&segment.payload);
        }
        let block = wrap(raw);
        let mut segment_leases = Vec::with_capacity(self.segments.len());
        for Held {
            payload,
            witness,
            lease,
        } in self.segments
        {
            drop(payload);
            drop(witness);
            segment_leases.push(lease);
        }
        Ok(AssembledBlock {
            block,
            block_lease: ticket.accept(),
            segment_leases,
        })
    }
}

/// A block and every lease that goes with it, moved as one value to whoever judges it.
/// Fields drop in order: the block, then its lease, then the segments' leases.
///
/// The segment leases come along so that a copy of a segment is not delivered again
/// while this block is out. The segments' payloads are gone by now, so their bytes stay
/// counted for as long as the leases stay. [`Self::release_segments`] is the other
/// choice. Neither is a decided policy.
#[derive(Debug)]
pub struct AssembledBlock<B> {
    block: B,
    block_lease: Lease,
    segment_leases: Vec<Lease>,
}

impl<B> AssembledBlock<B> {
    pub fn block(&self) -> &B {
        &self.block
    }

    pub fn holds_segments(&self) -> usize {
        self.segment_leases.len()
    }

    /// Return the segments' bytes at once. Copies of them can then be admitted while the
    /// block is still out, and a whole set they make finds the body owned.
    pub fn release_segments(&mut self) {
        self.segment_leases.clear();
    }

    /// Say nothing about the body and let everything go. A copy can come in again, and
    /// spends a repeat. This is the research assumption after a refusal or an error,
    /// not a decided policy.
    pub fn give_back(self) {}

    /// The caller is done with this body and does not want it again until the completed
    /// record ends. Being assembled is not a reason to call this, and calling it on a
    /// refusal shuts out a body whose refusal was only temporary.
    pub fn finish(self, now: Instant) {
        let Self {
            block,
            block_lease,
            segment_leases,
        } = self;
        drop(block);
        block_lease.complete(now);
        for lease in segment_leases {
            lease.complete(now);
        }
    }
}
