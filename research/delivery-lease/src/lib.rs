//! Research prototype for #130 PR B. The bound raw path in `sovright-relay` uses it, behind
//! switches that are off by default.
//!
//! The ledger replaces "I delivered this" with "who owns this now", without the
//! producer knowing how the consumer stores anything. A producer asks to admit an
//! object and gets a [`Ticket`], which travels with the payload. A consumer turns the
//! ticket into a [`Lease`] and holds it for as long as it holds the object. Dropping
//! either one gives the object back, so an eviction, a cancelled send and a closed
//! channel are all the same event.
//!
//! ```text
//!             admit                 accept                complete
//!  (absent) ---------> InFlight ------------> Held ------------------> Completed
//!                         |                    |
//!                         | drop               | drop
//!                         v                    v
//!                      Released <--------------+
//!                         |
//!                         | admit, spends one repeat
//!                         v
//!                      InFlight (new generation)
//! ```
//!
//! A released record ends after [`Limits::released_ttl`], and with it what repeats were
//! spent, so a spent budget closes an object for a while and never for good.
//!
//! Every transition is one short critical section, and that is its atomic point. No
//! method here is async, so the lock cannot be held across an await. Two operations
//! on one object happen in the order they take the lock, and there is no third
//! outcome: a copy either sees the object owned and is refused, or sees it released
//! and is admitted.
//!
//! Ownership ends only by a drop or by [`Lease::complete`]. No timer ends it, because a
//! consumer past any deadline may still hold its payload. A record therefore has at
//! most one live owner. The cost is an open limit: a consumer that hangs keeps its
//! bytes and its place until it is dropped, and copies are refused meanwhile.
//!
//! A generation names one delivery. It also keeps the drop that follows `complete`
//! from touching a later delivery of an object whose completed record has ended.
//!
//! `Completed` means the consumer finished with the object and does not want it again.
//! It says nothing about a node accepting a block; that meaning belongs to the caller.
//!
//! Bytes and owner places are taken at admission and come back only when that [`Ticket`]
//! or [`Lease`] is dropped. `max_records` bounds the ledger's own map, and an idle
//! record can be forgotten. `max_live_owners` bounds the tickets and leases themselves.
//! Small or empty objects cannot get past it.
//!
//! One thing lets the counts stand above those limits, and [`Limits::transit`] says how
//! far. An admission can count on owners its caller is about to drop. They cannot go
//! inside the admission, because dropping an owner needs this lock, and dropping them
//! first would hand their room to anyone. So the new owner is counted while they are
//! still alive and still counted, and each returns its own reservation when it drops.
//! That overlap is what the share pays for. There is one share for the whole ledger, so
//! more callers cannot stack more of it, and if it cannot cover the overlap the admission
//! is refused and nothing is given up.
//!
//! These limits cover owners and the payload bytes declared for them. They are not a
//! bound on process memory: queues, allocator slack and anything a consumer copies
//! without declaring it are outside them.
//!
//! The ledger cannot see a payload, so this bounds payload memory only if the consumer
//! keeps its side: the payload goes when its owner goes. It keeps no copy after
//! dropping a lease, and calls [`Lease::complete`] only once the payload is gone or
//! something else accounts for it, because the bytes come back there. Nothing here
//! enforces that.
//!
//! The ledger never recovers anything. It only decides what to do with a copy that
//! arrives, and if none arrives, a released object stays released.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub mod body_buffer;
pub mod intake;
pub mod segment_frame;

pub type ObjectId = [u8; 32];

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Records of every phase together. This bounds the map, and an idle record can be
    /// forgotten to make room.
    pub max_records: usize,
    /// Every live ticket and lease. Only dropping one frees a place.
    pub max_live_owners: usize,
    /// Bytes of every live ticket and lease.
    pub max_reserved_bytes: usize,
    /// How many times one object can be admitted again while its record lives.
    /// Forgetting the record forgets the count, so this is no lasting limit on repeats
    /// and no limit on CPU.
    pub repeat_budget: u32,
    pub completed_ttl: Duration,
    /// How long a released record stands, from the moment its owner went. The time
    /// [`Self::repeat_budget`] counts in: with no end, a body given back that many times
    /// would stay shut out until other records happened to push its record out, and that
    /// turns a passing error into silence.
    pub released_ttl: Duration,
    /// What can stand above the limits while owners are being given up.
    pub transit: Transit,
}

/// One share for the whole ledger, on top of the limits. The counts never pass a limit
/// plus its share. Only an admission that gives something up can use it, and only until
/// that has gone. With no share a full ledger refuses and nothing is given up.
///
/// `bytes` has to cover the overlap, which on a full ledger is the whole new object: a
/// segment to take one in, a body to assemble one. The share is a ceiling and not a
/// reservation, so nothing here holds it and nothing has to return it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transit {
    pub bytes: usize,
    pub owners: usize,
    pub records: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    InFlight,
    Held,
    Released,
    Completed,
}

/// Nothing in the ledger changes when a copy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Every record belongs to an owner, so none can be forgotten.
    Records,
    Owners,
    Bytes,
    RepeatBudget,
    /// Enough could be given up, but holding both until it has gone would pass
    /// [`Limits::transit`]. Nothing was given up, and a later try can pass.
    Transit,
    /// The body buffer could make room only by giving up a set still arriving. The ledger
    /// was not asked. See [`body_buffer::ACTIVE_SET`].
    Sets,
}

#[derive(Debug)]
pub enum Admission {
    Admitted(Ticket),
    /// Someone owns the object, so this copy adds nothing and is not kept. If the owner
    /// is evicted a moment later, this copy is lost.
    Owned(Phase),
    Completed,
    Refused(Refusal),
}

/// What giving up something the caller owns would free.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Holding {
    pub bytes: usize,
    pub owners: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub in_flight: usize,
    pub held: usize,
    pub released: usize,
    pub completed: usize,
    pub reserved_bytes: usize,
    pub live_owners: usize,
}

#[derive(Debug)]
struct Record {
    phase: Phase,
    generation: u64,
    repeats: u32,
    /// When a completed or released record ends. A record with an owner has no end.
    deadline: Option<Instant>,
    /// Order among records nobody owns, oldest forgotten first.
    idle_since: u64,
}

impl Record {
    /// A record past its end still sits in the map until something clears it.
    fn stands_at(&self, now: Instant) -> bool {
        self.deadline.is_none_or(|end| now < end)
    }
}

#[derive(Debug, Default)]
struct State {
    records: HashMap<ObjectId, Record>,
    reserved_bytes: usize,
    live_owners: usize,
    next_generation: u64,
    next_idle: u64,
}

impl State {
    fn generation(&mut self) -> u64 {
        self.next_generation += 1;
        self.next_generation
    }

    fn idle(&mut self) -> u64 {
        self.next_idle += 1;
        self.next_idle
    }

    fn drop_lapsed(&mut self, now: Instant) {
        self.records.retain(|_, record| record.stands_at(now));
    }

    /// What stops one more owner of `bytes`, with `given_up` counted as gone. Every owner
    /// has a record and every other record can be forgotten, so owners alone can fill
    /// the map. This changes nothing.
    fn shortage(
        &self,
        limits: &Limits,
        bytes: usize,
        new_record: bool,
        given_up: Holding,
    ) -> Option<Refusal> {
        let owners = self.live_owners.saturating_sub(given_up.owners);
        if owners >= limits.max_live_owners {
            return Some(Refusal::Owners);
        }
        let within_bytes = self
            .reserved_bytes
            .saturating_sub(given_up.bytes)
            .checked_add(bytes)
            .is_some_and(|total| total <= limits.max_reserved_bytes);
        if !within_bytes {
            return Some(Refusal::Bytes);
        }
        if new_record && owners >= limits.max_records {
            return Some(Refusal::Records);
        }
        None
    }

    /// Whether one more owner of `bytes`, with everything counted now still alive, would
    /// pass a limit plus its share.
    fn over_ceiling(&self, limits: &Limits, bytes: usize) -> bool {
        let share = limits.transit;
        let bytes_fit = self
            .reserved_bytes
            .checked_add(bytes)
            .is_some_and(|total| total <= limits.max_reserved_bytes.saturating_add(share.bytes));
        let owners_fit = self.live_owners < limits.max_live_owners.saturating_add(share.owners);
        let records_fit = self.live_owners < limits.max_records.saturating_add(share.records);
        !(bytes_fit && owners_fit && records_fit)
    }

    /// Bring the map below `limit`. An owned record is never taken, and a released record
    /// goes before a completed one, because forgetting a completed object only costs
    /// a repeat delivery. Forgetting a released one forgets the repeats it has spent.
    fn make_room(&mut self, limit: usize) {
        while self.records.len() >= limit {
            let oldest = |phase| {
                self.records
                    .iter()
                    .filter(|(_, record)| record.phase == phase)
                    .min_by_key(|(_, record)| record.idle_since)
                    .map(|(id, _)| *id)
            };
            let Some(id) = oldest(Phase::Released).or_else(|| oldest(Phase::Completed)) else {
                return;
            };
            self.records.remove(&id);
        }
    }

    fn end_ownership(&mut self, id: &ObjectId, generation: u64, phase: Phase) -> bool {
        let idle = self.idle();
        let Some(record) = self.records.get_mut(id) else {
            return false;
        };
        if record.generation != generation || !is_owned(record.phase) {
            return false;
        }
        record.phase = phase;
        record.idle_since = idle;
        record.deadline = None;
        true
    }
}

fn is_owned(phase: Phase) -> bool {
    matches!(phase, Phase::InFlight | Phase::Held)
}

#[derive(Clone, Debug)]
pub struct DeliveryLedger {
    limits: Limits,
    state: Arc<Mutex<State>>,
}

impl DeliveryLedger {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Arc::default(),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    // Tickets and leases release from `Drop`, which can run while unwinding.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The authoritative check for one arriving copy. `bytes` is the object's size, so
    /// a caller has usually paid to decode it by now.
    pub fn admit(&self, id: ObjectId, bytes: usize, now: Instant) -> Admission {
        self.admit_giving_up(id, bytes, now, &[]).0
    }

    /// [`Self::admit`], counting `offered` as room, best first and only as far as needed.
    /// All of it is one critical section, so what it decides cannot be taken from it.
    /// Nothing offered stops being counted here. The overlap has to fit [`Limits::transit`],
    /// and each owner returns its own reservation when it is dropped.
    ///
    /// The number returned is how many of `offered` this admission spent, and it is zero
    /// unless the object was admitted. The caller must then drop that many. They must
    /// be owners it holds and nobody else can release, which is why this is not public.
    pub(crate) fn admit_giving_up(
        &self,
        id: ObjectId,
        bytes: usize,
        now: Instant,
        offered: &[Holding],
    ) -> (Admission, usize) {
        let mut state = self.lock();
        state.drop_lapsed(now);
        let existing = state
            .records
            .get(&id)
            .map(|record| (record.phase, record.repeats));
        let repeats = match existing {
            Some((Phase::Completed, _)) => return (Admission::Completed, 0),
            Some((phase, _)) if is_owned(phase) => return (Admission::Owned(phase), 0),
            Some((_, repeats)) if repeats >= self.limits.repeat_budget => {
                return (Admission::Refused(Refusal::RepeatBudget), 0);
            }
            Some((_, repeats)) => repeats + 1,
            None => 0,
        };
        let mut given_up = Holding::default();
        let mut spent = 0;
        while let Some(refusal) = state.shortage(&self.limits, bytes, existing.is_none(), given_up)
        {
            let Some(next) = offered.get(spent) else {
                return (Admission::Refused(refusal), 0);
            };
            given_up.bytes = given_up.bytes.saturating_add(next.bytes);
            given_up.owners = given_up.owners.saturating_add(next.owners);
            spent += 1;
        }
        if spent > 0 && state.over_ceiling(&self.limits, bytes) {
            return (Admission::Refused(Refusal::Transit), 0);
        }
        if existing.is_none() {
            state.make_room(self.limits.max_records);
        }

        let generation = state.generation();
        state.reserved_bytes += bytes;
        state.live_owners += 1;
        state.records.insert(
            id,
            Record {
                phase: Phase::InFlight,
                generation,
                repeats,
                deadline: None,
                idle_since: 0,
            },
        );
        let ticket = Ticket {
            owner: Owner {
                ledger: self.clone(),
                id,
                generation,
                bytes,
            },
        };
        (Admission::Admitted(ticket), spent)
    }

    /// For logs and tests. Do not drop a chunk on this: the answer can change before
    /// the chunk is gone, and a chunk dropped just ahead of an eviction cannot be got
    /// back. Filtering early needs its own atomic design.
    pub fn observe(&self, id: &ObjectId) -> Option<Phase> {
        self.lock().records.get(id).map(|record| record.phase)
    }

    /// What the record says at `now`, so a record past its end reads as gone even if
    /// nothing has cleared it yet. For a caller that decides on the answer, which
    /// [`Self::observe`] cannot serve.
    ///
    /// Nothing holds the answer in place, and an owner can let go on another task at any
    /// moment. A copy dropped because of it is lost if the owner goes next, the same as a
    /// copy refused with [`Admission::Owned`], and that is the whole of what this costs:
    /// an owner that has gone reads as gone from then on.
    pub fn phase_at(&self, id: &ObjectId, now: Instant) -> Option<Phase> {
        let state = self.lock();
        let record = state.records.get(id)?;
        record.stands_at(now).then_some(record.phase)
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.lock();
        let count = |phase| {
            state
                .records
                .values()
                .filter(|record| record.phase == phase)
                .count()
        };
        Snapshot {
            in_flight: count(Phase::InFlight),
            held: count(Phase::Held),
            released: count(Phase::Released),
            completed: count(Phase::Completed),
            reserved_bytes: state.reserved_bytes,
            live_owners: state.live_owners,
        }
    }
}

#[derive(Debug)]
struct Owner {
    ledger: DeliveryLedger,
    id: ObjectId,
    generation: u64,
    bytes: usize,
}

impl Owner {
    fn accept(&self) {
        let mut state = self.ledger.lock();
        if let Some(record) = state.records.get_mut(&self.id) {
            debug_assert_eq!(record.generation, self.generation);
            record.phase = Phase::Held;
        }
    }

    fn complete(&self, now: Instant) {
        let ttl = self.ledger.limits.completed_ttl;
        let mut state = self.ledger.lock();
        state.end_ownership(&self.id, self.generation, Phase::Completed);
        if let Some(record) = state.records.get_mut(&self.id) {
            record.deadline = Some(now + ttl);
        }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // The record change is a no-op once this ownership has ended. The bytes and the
        // owner's place are this owner's either way, and only this gives them back.
        let ttl = self.ledger.limits.released_ttl;
        let mut state = self.ledger.lock();
        if state.end_ownership(&self.id, self.generation, Phase::Released)
            && let Some(record) = state.records.get_mut(&self.id)
        {
            record.deadline = Instant::now().checked_add(ttl);
        }
        state.reserved_bytes -= self.bytes;
        state.live_owners -= 1;
        // An admission that counted on this owner can have left the map over its limit.
        let limit = self.ledger.limits.max_records.saturating_add(1);
        state.make_room(limit);
    }
}

/// Ownership of an object on its way to the consumer. It travels with the payload, so
/// whatever destroys the payload in a queue or a cancelled send also releases this.
#[derive(Debug)]
#[must_use = "dropping a ticket releases the object"]
pub struct Ticket {
    owner: Owner,
}

impl Ticket {
    pub fn id(&self) -> ObjectId {
        self.owner.id
    }

    pub fn generation(&self) -> u64 {
        self.owner.generation
    }

    pub fn accept(self) -> Lease {
        self.owner.accept();
        Lease { owner: self.owner }
    }
}

/// Ownership of an object the consumer holds. Evicting the object is dropping this.
#[derive(Debug)]
#[must_use = "dropping a lease releases the object"]
pub struct Lease {
    owner: Owner,
}

impl Lease {
    pub fn id(&self) -> ObjectId {
        self.owner.id
    }

    pub fn generation(&self) -> u64 {
        self.owner.generation
    }

    /// Call this once the payload is gone or something else accounts for it, because
    /// the bytes come back here.
    pub fn complete(self, now: Instant) {
        self.owner.complete(now);
    }
}
