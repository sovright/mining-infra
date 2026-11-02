//! The hand-over from this crate to the segment prototype in `delivery-lease`, for research.
//! An adapter over its public API.
//!
//! Three states that must not be one record:
//!
//! | State                  | Where it lives                                          |
//! |------------------------|---------------------------------------------------------|
//! | Transport verified     | A [`DecodedObject`] while it exists. Nothing is written |
//! | The layer below has it | The ledger's record of the segment: in flight or held   |
//! | Not wanted again       | The same record: completed                              |
//!
//! So the ledger's record is the only delivery record there is. An eviction, an expiry, a
//! refused assembly and a block given back all end the ownership there on their own, and
//! nothing here has to hear about them. What a [`Bridge`] keeps is a fact and not a state:
//! which segment an object carries. That cannot go stale, and forgetting it costs one
//! decode.
//!
//! What a hand-over can end in, and what it leaves behind:
//!
//! | Outcome                     | Kind           | Recorded                           |
//! |-----------------------------|----------------|------------------------------------|
//! | [`Handoff::Held`], `Whole`  | Delivered      | The ledger's owner                 |
//! | [`Handoff::AlreadyHeld`]    | A second copy  | Nothing new                        |
//! | [`Handoff::NotWanted`]      | Finished with  | Nothing new                        |
//! | [`Handoff::Refused`]        | Resources      | Nothing. The content waits a turn  |
//! | [`Handoff::BadContent`]     | The bytes      | Rejected, in the assembler         |
//!
//! Ownership is not taken when an object opens. One replayed chunk would then hold the
//! object for as long as its assembly lives, and every other session would be turned away
//! from an object it could have finished. It is taken where it always was, in
//! [`Intake::receive`], after the decode, so a second decode of one object costs CPU and
//! delivers nothing.
//!
//! Two claims stay apart here. *No second delivery* rests on `Intake::receive` alone.
//! *A lost copy can be replaced* rests on what happens to chunks of an object that has
//! already been decoded, and that is what [`Bridge::interest`] decides:
//!
//! | Segment's record   | Chunks of its object                              |
//! |--------------------|---------------------------------------------------|
//! | Not known here     | A normal place                                    |
//! | Owned              | The spare shelf, no decode                        |
//! | Released, or none  | The spare shelf, decoded when there are `k` shards|
//! | Completed          | Dropped                                           |
//!
//! Spares never take a normal place: left in one, parity from each burst fills the budget
//! with no attacker involved, and that includes objects the layer below just refused.
//! They are not dropped either: an owner can go on another task at any moment, and what
//! was dropped could not replace it. The shelf is bounded and has a budget of its own, and
//! when it is full the oldest spare goes, so pressure on it costs a spare and nothing else.
//!
//! The answer can be stale the moment it is read. That is safe in both directions: a chunk
//! kept for an owner that has gone is decoded by the next [`Bridge::sweep`], and a decode
//! for an owner that has come back ends in `AlreadyHeld`.
//!
//! An object the layer below has no room for goes back on the shelf decoded, and the next
//! sweep offers it again, so a moment without room costs no copy and no second decode.
//!
//! What crosses a channel to a consumer is a whole block, not a decoded object: the block
//! carries its owners, so whoever holds it owns it, and nothing else has to be kept in step
//! across the channel. A set finished while the channel is full waits here with its
//! owners ([`Bridge::wait_for_consumer`]), so its bytes stay counted and nobody delivers it
//! again. Those counted bytes are what pushes back: new segments are refused for room and
//! wait on the shelf as above. What the channel does to the rest:
//!
//! | The channel                     | Content          | Reservations        |
//! |---------------------------------|------------------|---------------------|
//! | Has room                        | With the consumer| Its until it settles|
//! | Full                            | Waits here       | Stay                |
//! | Full past the buffer's time     | Gone             | Back, record released |
//! | Closed                          | Gone             | Back, record released |
//! | Dropped with a block in it      | Gone             | Back, record released |
//! | The consumer drops a block      | Gone             | Back, record released |
//!
//! A released record lets a copy in. That is what recovery rests on: without one, and
//! with no spares here, the block is gone, and nothing asks for it again.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use delivery_lease::Limits as LedgerLimits;
use delivery_lease::body_buffer::{
    AssembledBlock, AssemblyError, BodyBuffer, BufferLimits, CompleteSet, Insertion, Outcome,
    Reject,
};
use delivery_lease::intake::{Intake, Offer};
use delivery_lease::segment_frame::{FrameError, FrameRules, SetKey, check};
use delivery_lease::{DeliveryLedger, ObjectId, Phase, Refusal};

use super::assembler::{Arrival, Assembler, AssemblerLimits, CannotStart, DecodedObject, Interest};
use super::budget::{Budget, Limits as BudgetLimits, Session};
use super::datagram::Verifier;
use super::object::{MSG_RAW_SEGMENT, Profile};
use super::tree::Node;

#[derive(Debug)]
pub enum Handoff {
    /// The segment layer holds it, and these sets went to make room.
    Held(Vec<SetKey>),
    /// The segment layer holds it, and it finished a set.
    Whole(CompleteSet),
    /// Someone owns this segment, so this copy added nothing.
    AlreadyHeld(Phase),
    NotWanted,
    /// No room, or no repeats left. Nothing is recorded against the object.
    Refused(Refusal),
    /// The object is fine and what it carries is not. The same bytes give the same answer.
    BadContent(FrameError),
    TooLong(Reject),
    /// Not for this adapter.
    NotASegment(DecodedObject),
}

impl Handoff {
    /// Whether this is a fact about the bytes. A refusal is not.
    fn is_about_the_bytes(&self) -> bool {
        matches!(self, Self::BadContent(_) | Self::TooLong(_))
    }

    /// Room can open. A spent repeat budget is not that, and is left to the ledger.
    fn is_a_lack_of_room(&self) -> bool {
        matches!(
            self,
            Self::Refused(
                Refusal::Bytes
                    | Refusal::Owners
                    | Refusal::Records
                    | Refusal::Transit
                    | Refusal::Sets
            )
        )
    }
}

/// What one chunk came to.
#[derive(Debug)]
pub enum Step {
    Chunk(Arrival),
    Handed(Handoff),
}

/// Which segment an object carries, oldest forgotten first.
#[derive(Debug)]
struct Carried {
    max: usize,
    segments: HashMap<Node, ObjectId>,
    order: VecDeque<Node>,
}

impl Carried {
    fn note(&mut self, object: Node, segment: ObjectId) {
        if self.segments.insert(object, segment).is_some() {
            return;
        }
        self.order.push_back(object);
        if self.order.len() > self.max
            && let Some(oldest) = self.order.pop_front()
        {
            self.segments.remove(&oldest);
        }
    }
}

/// Every limit of one stack, in one place.
#[derive(Clone, Copy, Debug)]
pub struct StackLimits {
    pub budget: BudgetLimits,
    pub ledger: LedgerLimits,
    pub buffer: BufferLimits,
    pub assembler: AssemblerLimits,
    pub max_carried: usize,
}

/// What the counters of one stack can reach together. There is no shared counter, and
/// this is the sum of the fixed budgets.
///
/// Counted: the shards of open objects, spares on the shelf, decoded content not yet
/// handed over, segment payloads and assembled blocks, and what one eviction overlaps.
/// `work_bytes` is what the budget charges for decodes, and that charge is an estimate.
///
/// Not counted: datagrams a caller read, maps and tables, queue nodes, allocator slack.
/// So this bounds the counters, and it is no bound on the memory of a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ceiling {
    pub held_bytes: usize,
    pub work_bytes: usize,
    pub spare_bytes: usize,
    pub reserved_bytes: usize,
    pub transit_bytes: usize,
}

impl Ceiling {
    pub fn total_bytes(&self) -> usize {
        self.held_bytes
            + self.work_bytes
            + self.spare_bytes
            + self.reserved_bytes
            + self.transit_bytes
    }
}

/// The only place a [`Bridge`] comes from, so all of a stack's bridges and sessions share
/// one ledger and one budget, and each takes a place in it.
pub struct Stack {
    key: [u8; 32],
    profile: Profile,
    rules: FrameRules,
    limits: StackLimits,
    budget: Budget,
    ledger: DeliveryLedger,
}

impl Stack {
    pub fn new(
        key: [u8; 32],
        profile: Profile,
        rules: FrameRules,
        limits: StackLimits,
    ) -> Result<Self, CannotStart> {
        if limits.max_carried == 0 {
            return Err(CannotStart("max_carried"));
        }
        let budget = Budget::new(limits.budget).map_err(|invalid| CannotStart(invalid.0))?;
        Ok(Self {
            key,
            profile,
            rules,
            limits,
            budget,
            ledger: DeliveryLedger::new(limits.ledger),
        })
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    pub fn ledger(&self) -> &DeliveryLedger {
        &self.ledger
    }

    pub fn ceiling(&self) -> Ceiling {
        Ceiling {
            held_bytes: self.limits.budget.max_held_bytes,
            work_bytes: self.limits.budget.max_work_bytes,
            spare_bytes: self.limits.budget.max_spare_bytes,
            reserved_bytes: self.limits.ledger.max_reserved_bytes,
            transit_bytes: self.limits.ledger.transit.bytes,
        }
    }

    pub fn session(&self) -> Result<Assembler, CannotStart> {
        Assembler::new(
            Verifier::new(self.key, self.profile),
            self.budget.clone(),
            self.limits.assembler,
        )
    }

    pub fn bridge(&self) -> Result<Bridge, CannotStart> {
        let buffer =
            BodyBuffer::new(self.limits.buffer).map_err(|invalid| CannotStart(invalid.0))?;
        let session = self.budget.session().map_err(|_| CannotStart("sessions"))?;
        Ok(Bridge {
            intake: Intake::new(self.ledger.clone(), buffer, self.rules),
            ledger: self.ledger.clone(),
            rules: self.rules,
            carried: Carried {
                max: self.limits.max_carried,
                segments: HashMap::new(),
                order: VecDeque::new(),
            },
            waiting: VecDeque::new(),
            waiting_ttl: self.limits.buffer.ttl,
            _session: session,
        })
    }
}

#[derive(Debug)]
pub struct Bridge {
    intake: Intake,
    ledger: DeliveryLedger,
    rules: FrameRules,
    carried: Carried,
    waiting: VecDeque<(CompleteSet, Instant)>,
    waiting_ttl: Duration,
    _session: Session,
}

impl Bridge {
    pub fn buffer(&self) -> &BodyBuffer {
        self.intake.buffer()
    }

    /// What to do with a chunk of this object at `now`. See the module note.
    pub fn interest(&self, object: &Node, now: Instant) -> Interest {
        let Some(segment) = self.carried.segments.get(object) else {
            return Interest::New;
        };
        match self.ledger.phase_at(segment, now) {
            None | Some(Phase::Released) => Interest::Due,
            Some(Phase::InFlight | Phase::Held) => Interest::Spare,
            Some(Phase::Completed) => Interest::Done,
        }
    }

    /// Give a decoded object to the layer below with no shelf to fall back on. Refused, it
    /// is gone, so this is for tests of that layer. No real path uses it: [`Self::take`]
    /// keeps what was refused, and what crosses a channel is a whole block. Its content and
    /// the reservation that counts it last until the segment layer has its own counted copy.
    pub fn deliver(&mut self, decoded: DecodedObject, now: Instant) -> Handoff {
        if decoded.msg_type() != MSG_RAW_SEGMENT {
            return Handoff::NotASegment(decoded);
        }
        self.offer(&decoded, now)
    }

    fn offer(&mut self, decoded: &DecodedObject, now: Instant) -> Handoff {
        let segment = match check(decoded.content(), &self.rules) {
            Ok(frame) => frame.ledger_key(),
            Err(error) => return Handoff::BadContent(error),
        };
        self.carried.note(decoded.object_id(), segment);
        match self.intake.receive(decoded.content(), now) {
            Offer::Taken(Insertion {
                outcome: Outcome::Complete(set),
                ..
            }) => Handoff::Whole(set),
            Offer::Taken(Insertion {
                outcome: Outcome::Rejected(Reject::Busy),
                ..
            }) => Handoff::Refused(Refusal::Sets),
            Offer::Taken(Insertion {
                outcome: Outcome::Rejected(reject),
                ..
            }) => Handoff::TooLong(reject),
            Offer::Taken(Insertion { evicted, .. }) => Handoff::Held(evicted),
            Offer::Owned(phase) => Handoff::AlreadyHeld(phase),
            Offer::Completed => Handoff::NotWanted,
            Offer::Refused(refusal) => Handoff::Refused(refusal),
            Offer::Rejected(reject) => Handoff::TooLong(reject),
            Offer::Invalid(error) => Handoff::BadContent(error),
        }
    }

    /// One chunk, all the way down, on the consumer that holds this bridge.
    pub fn take(&mut self, assembler: &mut Assembler, datagram: &[u8], now: Instant) -> Step {
        let arrival = assembler.receive_if(datagram, now, |object| self.interest(object, now));
        match arrival {
            Arrival::Decoded(decoded) => Step::Handed(self.hand_over(assembler, decoded, now)),
            other => Step::Chunk(other),
        }
    }

    fn hand_over(
        &mut self,
        assembler: &mut Assembler,
        decoded: DecodedObject,
        now: Instant,
    ) -> Handoff {
        if decoded.msg_type() != MSG_RAW_SEGMENT {
            return Handoff::NotASegment(decoded);
        }
        let handoff = self.offer(&decoded, now);
        if handoff.is_about_the_bytes() {
            assembler.reject(decoded.object_id(), now);
        } else if handoff.is_a_lack_of_room() {
            assembler.shelve_decoded(decoded, now);
        }
        handoff
    }

    /// Look over `assembler`'s spares. Call this after a hand-over that evicted something,
    /// after [`Self::expire`], and on a timer: an owner on another task can go at any
    /// moment, and nothing here hears of it.
    pub fn sweep(&mut self, assembler: &mut Assembler, now: Instant) -> Vec<Handoff> {
        let arrivals = assembler.revive(now, |object| self.interest(object, now));
        let mut handoffs = Vec::new();
        for arrival in arrivals {
            if let Arrival::Decoded(decoded) = arrival {
                handoffs.push(self.hand_over(assembler, decoded, now));
            }
        }
        handoffs
    }

    pub fn assemble(
        &mut self,
        set: CompleteSet,
        now: Instant,
    ) -> Result<AssembledBlock<Vec<u8>>, AssemblyError> {
        self.intake.assemble(set, now)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<SetKey> {
        let ttl = self.waiting_ttl;
        self.waiting
            .retain(|(_, since)| now.saturating_duration_since(*since) < ttl);
        self.intake.buffer_mut().expire(now)
    }

    /// A whole set the consumer has no room for yet. It keeps its owners. See the module note.
    pub fn wait_for_consumer(&mut self, set: CompleteSet, now: Instant) {
        self.waiting.push_back((set, now));
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Which body [`Self::next_block`] puts together next.
    pub fn next_key(&self) -> Option<SetKey> {
        self.waiting.front().map(|(set, _)| set.key)
    }

    /// The oldest waiting set, put together, for a consumer that has room for one. Ask for
    /// the room first: past this point a block that cannot be handed over is lost.
    pub fn next_block(
        &mut self,
        now: Instant,
    ) -> Option<Result<AssembledBlock<Vec<u8>>, AssemblyError>> {
        let (set, _) = self.waiting.pop_front()?;
        Some(self.intake.assemble(set, now))
    }

    /// The consumer is gone. What waited for it goes, and its reservations come back.
    pub fn abandon_waiting(&mut self) {
        self.waiting.clear();
    }
}
