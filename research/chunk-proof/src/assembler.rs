//! One session's reassembly, A5 to A7 and D1 to D4. Everything is synchronous, so no lock
//! outlives a call.
//!
//! The design's per-chunk marks are slots while an object is open. After that only a
//! failure leaves a record, because only a failure is a fact about the bytes: the same
//! chunks would fail again. A decode that worked leaves nothing here, since whether the
//! object got anywhere is not this layer's to say. See [`handoff`](super::handoff).
//!
//! The rules, in order:
//!
//! 1. A chunk that fails A1 to A4 changes nothing and costs no allocation.
//! 2. A chunk of a rejected object, a repeat of a slot, or a chunk whose shape differs from
//!    its object's changes nothing.
//! 3. An object's place and all its bytes are taken at its first chunk. Taken piece by
//!    piece, half-filled objects could use up the bytes so that none could finish. A shape
//!    whose shortest content is past `max_content` takes nothing: no such object can pass.
//! 4. The chunk that would finish an object first takes its decode budget. Without it the
//!    chunk is refused and not stored, so the object stays as it was and can still finish.
//! 5. A refused chunk leaves no record, so a copy of it is welcome later.
//! 6. A place held by an object that has stopped moving is not lost to a new one. When
//!    the budget is full, the open object that has waited longest for a chunk moves to the
//!    shelf with what it has, and can still finish there. So what fills the normal places
//!    needs no one to recognise it, and that includes parity of an object whose record was
//!    forgotten. Moving costs an object its normal place and nothing else, and an object
//!    that cannot move stays where it is. New objects are refused when what holds the
//!    budget is not this session's to move: decoded content, other sessions' objects, and
//!    objects the shelf cannot take. A place made for a new object never costs one that
//!    is here. A caller that shares a budget between sessions can ask another one to
//!    [`give way`](Assembler::give_way), by a rule of its own.
//!
//! An object this side has already decoded is treated differently: its chunks are spares,
//! and they never take a normal place. Parity left over from a burst can never finish an
//! object by itself, and held in normal places it would keep the next objects out with no
//! attacker involved. Dropped, it could not replace anything. So spares go on a shelf:
//!
//! 7. The shelf has a budget of its own, so no normal object ever waits for a spare.
//! 8. It keeps at most `k` shards of an object, so it never holds more than a decode needs.
//! 9. When it is full the oldest spare on it goes, which costs only that spare, since
//!    somebody has that object. What moved here unfinished and decoded content are the only
//!    copy, so they stay, and what would have taken their place is refused. A spare on its
//!    way to a normal place keeps its own until it has that place.
//! 10. Only verified chunks get there, and a spare is decoded only when the layer above
//!     says nobody owns the object, so it can bring an object back and do nothing else.
//! 11. A decoded object the layer below had no room for goes back on the shelf as it is,
//!     so a moment without room costs neither a copy nor a second decode.
//! 12. An object here in full needs bytes to become content and no open place, so one on
//!     the shelf can finish with every open place taken.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::budget::{Budget, Hold, Refusal, Session, Shelved, Work};
use super::datagram::{ChunkError, VerifiedChunk, Verifier};
use super::object::{ObjectError, Shape, decode, held_bytes, least_content, work_bytes};
use super::tree::Node;

/// Everything here but `max_content` is about this session's own bookkeeping.
#[derive(Clone, Copy, Debug)]
pub struct AssemblerLimits {
    /// Rejected records, oldest forgotten first. A forgotten object can be tried again.
    pub max_rejected: usize,
    pub assembly_ttl: Duration,
    pub rejected_ttl: Duration,
    /// `max(msg_type)`. The values are not chosen.
    pub max_content: fn(u8) -> usize,
}

/// A limit of zero leaves nowhere to record a result, and `sessions` means the budget has
/// no place for another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CannotStart(pub &'static str);

/// A decoded object's content, and the reservation that counts it. Fields drop in order.
/// This says the transport was verified, and it records nothing: dropping it leaves no
/// trace that it ever existed.
#[derive(Debug)]
pub struct DecodedObject {
    content: Vec<u8>,
    object_id: Node,
    shape: Shape,
    _hold: Hold,
}

impl DecodedObject {
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn object_id(&self) -> Node {
        self.object_id
    }

    pub fn msg_type(&self) -> u8 {
        self.shape.msg_type
    }

    pub fn shape(&self) -> Shape {
        self.shape
    }
}

/// What the layer above wants done with an object's chunks, at this moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interest {
    /// Nothing is known of it. It takes a normal place.
    New,
    /// It was decoded here and nobody owns it now. Keep its chunks as spares, and decode
    /// as soon as there are enough.
    Due,
    /// Someone owns it. Keep its chunks as spares, and do not decode.
    Spare,
    /// It is finished with. Keep nothing.
    Done,
}

#[derive(Debug)]
pub enum Arrival {
    /// A1 to A4. Nothing changed.
    Invalid(ChunkError),
    /// A5. This slot is full, and its bytes are the same by the proof.
    Repeat,
    /// A5a. These bytes failed before, and they would again.
    KnownBad,
    /// A6a. A consistent tree of mixed shapes: the first chunk's stands.
    OtherShape,
    /// Nothing is wanted of this object, or a spare did not fit on the shelf.
    NotWanted,
    /// On the shelf.
    Spare {
        have: usize,
        need: usize,
    },
    /// A6. Nothing changed and nothing was recorded.
    Refused(Refusal),
    Pending {
        have: usize,
        need: usize,
    },
    Decoded(DecodedObject),
    /// D1 to D4. The object is gone, and its rejected record stops it being tried again.
    Rejected(ObjectError),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssemblerState {
    pub open: usize,
    pub shards: usize,
    pub rejected: usize,
    pub spares: usize,
}

#[derive(Debug)]
struct Assembly {
    shape: Shape,
    first_seen: Instant,
    /// When a chunk last came, by this session's own count of chunks.
    touched: u64,
    filled: usize,
    slots: Vec<Option<Vec<u8>>>,
    hold: Hold,
}

#[derive(Debug)]
struct Spare {
    shape: Shape,
    first_seen: Instant,
    filled: usize,
    slots: Vec<Option<Vec<u8>>>,
    /// Already decoded, waiting for room below. There are no slots then.
    decoded: Option<Vec<u8>>,
    /// It moved here open, and nobody is known to have it.
    unfinished: bool,
    _shelved: Shelved,
}

impl Spare {
    /// Whether losing this costs only a spare. See rule 9.
    fn can_go(&self) -> bool {
        !self.unfinished && self.decoded.is_none()
    }
}

#[derive(Debug)]
pub struct Assembler {
    verifier: Verifier,
    budget: Budget,
    limits: AssemblerLimits,
    open: HashMap<Node, Assembly>,
    rejected: HashMap<Node, Instant>,
    rejected_order: VecDeque<Node>,
    spares: HashMap<Node, Spare>,
    spare_order: VecDeque<Node>,
    chunks_seen: u64,
    _session: Session,
}

impl Assembler {
    pub fn new(
        verifier: Verifier,
        budget: Budget,
        limits: AssemblerLimits,
    ) -> Result<Self, CannotStart> {
        if limits.max_rejected == 0 {
            return Err(CannotStart("max_rejected"));
        }
        if limits.assembly_ttl.is_zero() {
            return Err(CannotStart("assembly_ttl"));
        }
        if limits.rejected_ttl.is_zero() {
            return Err(CannotStart("rejected_ttl"));
        }
        let session = budget.session().map_err(|_| CannotStart("sessions"))?;
        Ok(Self {
            verifier,
            budget,
            limits,
            open: HashMap::new(),
            rejected: HashMap::new(),
            rejected_order: VecDeque::new(),
            spares: HashMap::new(),
            spare_order: VecDeque::new(),
            chunks_seen: 0,
            _session: session,
        })
    }

    pub fn state(&self) -> AssemblerState {
        AssemblerState {
            open: self.open.len(),
            shards: self.open.values().map(|assembly| assembly.filled).sum(),
            rejected: self.rejected.len(),
            spares: self.spares.len(),
        }
    }

    /// How many shards of this object are here, open or spare.
    pub fn have(&self, id: &Node) -> usize {
        let open = self.open.get(id).map_or(0, |assembly| assembly.filled);
        open + self.spares.get(id).map_or(0, |spare| spare.filled)
    }

    pub fn receive(&mut self, datagram: &[u8], now: Instant) -> Arrival {
        self.receive_if(datagram, now, |_| Interest::New)
    }

    /// [`Self::receive`], asking `interest` when this chunk would open an object or pay for
    /// its decode. Whether a delivery counts is decided further down.
    pub fn receive_if(
        &mut self,
        datagram: &[u8],
        now: Instant,
        interest: impl FnOnce(&Node) -> Interest,
    ) -> Arrival {
        match self.verifier.verify(datagram) {
            Ok(chunk) => self.take(chunk, now, interest),
            Err(error) => Arrival::Invalid(error),
        }
    }

    fn is_rejected(&self, id: &Node, now: Instant) -> bool {
        self.rejected.get(id).is_some_and(|end| now < *end)
    }

    fn take(
        &mut self,
        chunk: VerifiedChunk<'_>,
        now: Instant,
        interest: impl FnOnce(&Node) -> Interest,
    ) -> Arrival {
        let (id, shape) = (chunk.object_id(), chunk.shape());
        let index = usize::from(chunk.index());
        if self.is_rejected(&id, now) {
            return Arrival::KnownBad;
        }
        if least_content(&shape) > (self.limits.max_content)(shape.msg_type) {
            return Arrival::Refused(Refusal::NeverFits);
        }
        let filled = match self.open.get(&id) {
            Some(assembly) if assembly.shape != shape => return Arrival::OtherShape,
            Some(assembly) if assembly.slots[index].is_some() => return Arrival::Repeat,
            Some(assembly) => assembly.filled,
            None => 0,
        };

        let need = usize::from(shape.k);
        if filled == 0 || filled + 1 == need {
            match interest(&id) {
                Interest::New if filled == 0 && self.spares.contains_key(&id) => {
                    return self.shelve(chunk, now, true);
                }
                Interest::New => {}
                Interest::Due if filled > 0 => {}
                Interest::Due => return self.shelve(chunk, now, true),
                Interest::Spare if filled > 0 => return self.shelve_open(chunk, now),
                Interest::Spare => return self.shelve(chunk, now, false),
                Interest::Done => {
                    self.open.remove(&id);
                    self.remove_spare(&id);
                    return Arrival::NotWanted;
                }
            }
        }
        let cost = work_bytes(&shape);
        if cost > self.budget.limits().max_work_bytes {
            return Arrival::Refused(Refusal::NeverFits);
        }
        let hold = if filled == 0 {
            match self.place(held_bytes(&shape), &id, true) {
                Ok(hold) => Some(hold),
                Err(refusal) => return Arrival::Refused(refusal),
            }
        } else {
            None
        };
        let work = if filled + 1 == need {
            match self.budget.work(cost) {
                Ok(work) => Some(work),
                Err(refusal) => return Arrival::Refused(refusal),
            }
        } else {
            None
        };

        self.chunks_seen += 1;
        let touched = self.chunks_seen;
        let assembly = self.open.entry(id).or_insert_with(|| Assembly {
            shape,
            first_seen: now,
            touched,
            filled: 0,
            slots: std::iter::repeat_with(|| None)
                .take(usize::from(shape.n))
                .collect(),
            hold: hold.expect("a first chunk took a hold"),
        });
        assembly.slots[index] = Some(chunk.shard().to_vec());
        assembly.filled += 1;
        assembly.touched = touched;
        if work.is_none() {
            return Arrival::Pending {
                have: assembly.filled,
                need,
            };
        }

        let work = work.expect("the chunk that finishes an object took its budget");
        let Assembly { slots, hold, .. } =
            self.open.remove(&id).expect("this object was just filled");
        self.finish(id, shape, slots, hold, work, now)
    }

    /// A place for `bytes`, moving objects that have stopped to the shelf until there is
    /// one. Rule 6. `keep` is the object the place is for: what moves does not take its
    /// place on the shelf from it. `open` says whether it will wait for chunks, or is here
    /// in full and needs bytes alone. What cannot move stays, and the place is refused.
    fn place(&mut self, bytes: usize, keep: &Node, open: bool) -> Result<Hold, Refusal> {
        loop {
            let held = if open {
                self.budget.hold(bytes)
            } else {
                self.budget.hold_settled(bytes)
            };
            let refusal = match held {
                Err(
                    refusal @ (Refusal::Objects
                    | Refusal::HeldBytes
                    | Refusal::Shared
                    | Refusal::Outer),
                ) => refusal,
                other => return other,
            };
            match self.longest_waiting() {
                Some(stopped) if self.open_to_shelf(&stopped, keep) => {}
                _ => return Err(refusal),
            }
        }
    }

    /// What rule 6 does for this session's own new object, at another session's asking.
    /// False if nothing here is open, or the shelf cannot take it, and then nothing changed.
    pub fn give_way(&mut self) -> bool {
        self.longest_waiting()
            .is_some_and(|stopped| self.open_to_shelf(&stopped, &stopped))
    }

    /// Whether there is anything [`Self::give_way`] could move.
    pub fn has_open(&self) -> bool {
        !self.open.is_empty()
    }

    fn longest_waiting(&self) -> Option<Node> {
        self.open
            .iter()
            .min_by_key(|(_, assembly)| assembly.touched)
            .map(|(id, _)| *id)
    }

    /// An open object leaves its normal place with all it has. If the shelf has nothing it
    /// can give up for it, it stays as it is.
    fn open_to_shelf(&mut self, id: &Node, keep: &Node) -> bool {
        let assembly = self.open.get(id).expect("this object is open");
        let (shape, filled) = (assembly.shape, assembly.filled);
        let list = held_bytes(&shape) - usize::from(shape.k) * usize::from(shape.s);
        let bytes = list + filled * usize::from(shape.s);
        let Some(shelved) = self.shelf_place(&shape, bytes, keep) else {
            return false;
        };
        let assembly = self.open.remove(id).expect("this object is open");
        let spare = Spare {
            shape,
            first_seen: assembly.first_seen,
            filled,
            slots: assembly.slots,
            decoded: None,
            unfinished: true,
            _shelved: shelved,
        };
        self.spares.insert(*id, spare);
        self.spare_order.push_back(*id);
        true
    }

    fn finish(
        &mut self,
        id: Node,
        shape: Shape,
        slots: Vec<Option<Vec<u8>>>,
        mut hold: Hold,
        work: Work,
        now: Instant,
    ) -> Arrival {
        let max_content = (self.limits.max_content)(shape.msg_type);
        let result = decode(&shape, &id, slots, max_content);
        drop(work);
        match result {
            Ok(content) => {
                hold.settle(content.len());
                Arrival::Decoded(DecodedObject {
                    content,
                    object_id: id,
                    shape,
                    _hold: hold,
                })
            }
            Err(error) => {
                self.reject(id, now);
                Arrival::Rejected(error)
            }
        }
    }

    fn remove_spare(&mut self, id: &Node) -> Option<Spare> {
        let spare = self.spares.remove(id)?;
        self.spare_order.retain(|other| other != id);
        Some(spare)
    }

    /// A place on the shelf for `bytes`, for an object it has none for, giving up the
    /// oldest spares that can go to make one. An object that could not fit even on an
    /// empty shelf gives up nothing.
    fn shelf_place(&mut self, shape: &Shape, bytes: usize, keep: &Node) -> Option<Shelved> {
        if held_bytes(shape) > self.budget.limits().max_spare_bytes {
            return None;
        }
        loop {
            if let Ok(shelved) = self.budget.shelve(bytes) {
                return Some(shelved);
            }
            self.drop_oldest_spare(keep)?;
        }
    }

    fn drop_oldest_spare(&mut self, keep: &Node) -> Option<()> {
        let spares = &self.spares;
        let can_go = |id: &&Node| *id != keep && spares.get(*id).is_some_and(Spare::can_go);
        let oldest = *self.spare_order.iter().find(can_go)?;
        self.remove_spare(&oldest).map(drop)
    }

    fn add_spare(&mut self, chunk: &VerifiedChunk<'_>, now: Instant) -> bool {
        let (id, shape) = (chunk.object_id(), chunk.shape());
        let shard = usize::from(shape.s);
        if !self.spares.contains_key(&id) {
            let list = held_bytes(&shape) - usize::from(shape.k) * shard;
            let Some(shelved) = self.shelf_place(&shape, list + shard, &id) else {
                return false;
            };
            let spare = Spare {
                shape,
                first_seen: now,
                filled: 0,
                slots: std::iter::repeat_with(|| None)
                    .take(usize::from(shape.n))
                    .collect(),
                decoded: None,
                unfinished: false,
                _shelved: shelved,
            };
            self.spares.insert(id, spare);
            self.spare_order.push_back(id);
        } else {
            loop {
                let spare = self.spares.get_mut(&id).expect("checked above");
                if spare._shelved.grow(shard).is_ok() {
                    break;
                }
                if self.drop_oldest_spare(&id).is_none() {
                    return false;
                }
            }
        }
        let spare = self.spares.get_mut(&id).expect("checked above");
        spare.slots[usize::from(chunk.index())] = Some(chunk.shard().to_vec());
        spare.filled += 1;
        true
    }

    fn shelve(&mut self, chunk: VerifiedChunk<'_>, now: Instant, due: bool) -> Arrival {
        let (id, shape) = (chunk.object_id(), chunk.shape());
        let index = usize::from(chunk.index());
        let need = usize::from(shape.k);
        // Somebody owns this now, so it is a spare like any other.
        if !due && let Some(spare) = self.spares.get_mut(&id) {
            spare.unfinished = false;
        }
        if self
            .spares
            .get(&id)
            .is_some_and(|spare| spare.decoded.is_some())
        {
            return if due {
                self.release_decoded(id)
            } else {
                Arrival::Spare { have: need, need }
            };
        }
        let repeated = match self.spares.get(&id) {
            Some(spare) if spare.shape != shape => return Arrival::OtherShape,
            Some(spare) => spare.slots[index].is_some(),
            None => false,
        };
        let have = self.spares.get(&id).map_or(0, |spare| spare.filled);
        if !repeated && have < need && !self.add_spare(&chunk, now) {
            return Arrival::NotWanted;
        }
        let have = self.spares.get(&id).map_or(0, |spare| spare.filled);
        if due && have >= need {
            return self.decode_spare(id, now);
        }
        if repeated {
            return Arrival::Repeat;
        }
        Arrival::Spare { have, need }
    }

    /// An open object one chunk short, and someone else has delivered it meanwhile. It
    /// stops holding a normal place, and moves to the shelf with all it has.
    fn shelve_open(&mut self, chunk: VerifiedChunk<'_>, now: Instant) -> Arrival {
        let id = chunk.object_id();
        if self.spares.contains_key(&id) {
            return Arrival::NotWanted;
        }
        if !self.open_to_shelf(&id, &id) {
            self.open.remove(&id);
            return Arrival::NotWanted;
        }
        self.shelve(chunk, now, false)
    }

    fn decode_spare(&mut self, id: Node, now: Instant) -> Arrival {
        let shape = self.spares[&id].shape;
        let hold = match self.place(held_bytes(&shape), &id, false) {
            Ok(hold) => hold,
            Err(refusal) => return Arrival::Refused(refusal),
        };
        let work = match self.budget.work(work_bytes(&shape)) {
            Ok(work) => work,
            Err(refusal) => return Arrival::Refused(refusal),
        };
        let spare = self.remove_spare(&id).expect("this spare was just read");
        self.finish(id, shape, spare.slots, hold, work, now)
    }

    /// The layer below had no room for this object. It goes back on the shelf as it is, so
    /// the next look can offer it again with no copy and no decode. `false` if the shelf
    /// cannot take it, and then it is gone.
    pub fn shelve_decoded(&mut self, decoded: DecodedObject, now: Instant) -> bool {
        let DecodedObject {
            content,
            object_id,
            shape,
            _hold,
        } = decoded;
        self.remove_spare(&object_id);
        let Some(shelved) = self.shelf_place(&shape, content.len(), &object_id) else {
            return false;
        };
        let spare = Spare {
            shape,
            first_seen: now,
            filled: usize::from(shape.k),
            slots: Vec::new(),
            decoded: Some(content),
            unfinished: false,
            _shelved: shelved,
        };
        self.spares.insert(object_id, spare);
        self.spare_order.push_back(object_id);
        true
    }

    fn release_decoded(&mut self, id: Node) -> Arrival {
        let bytes = self.spares[&id].decoded.as_ref().map_or(0, Vec::len);
        let hold = match self.place(bytes, &id, false) {
            Ok(hold) => hold,
            Err(refusal) => return Arrival::Refused(refusal),
        };
        let spare = self.remove_spare(&id).expect("this spare was just read");
        Arrival::Decoded(DecodedObject {
            content: spare.decoded.expect("this spare was decoded"),
            object_id: id,
            shape: spare.shape,
            _hold: hold,
        })
    }

    /// Look over the shelf: what is finished with goes, and what nobody owns and has enough
    /// shards is decoded. For after anything that can end an owner, and on a timer, since
    /// an owner can go on another task with nothing here hearing of it. A spare that cannot
    /// get a decode budget now stays for the next look.
    pub fn revive(
        &mut self,
        now: Instant,
        mut interest: impl FnMut(&Node) -> Interest,
    ) -> Vec<Arrival> {
        let ids: Vec<Node> = self.spare_order.iter().copied().collect();
        let mut arrivals = Vec::new();
        for id in ids {
            // A decode further up this list may have cost this spare its place.
            if !self.spares.contains_key(&id) {
                continue;
            }
            let answer = interest(&id);
            if answer == Interest::Done {
                self.remove_spare(&id);
                continue;
            }
            let spare = &self.spares[&id];
            if answer != Interest::Spare && spare.filled >= usize::from(spare.shape.k) {
                let arrival = if spare.decoded.is_some() {
                    self.release_decoded(id)
                } else {
                    self.decode_spare(id, now)
                };
                if !matches!(arrival, Arrival::Refused(_)) {
                    arrivals.push(arrival);
                }
            }
        }
        arrivals
    }

    /// These bytes will fail again whoever looks at them, so spare the next look. For a
    /// failure in the decode, and for the caller when the content turned out bad. A refusal
    /// for room is no reason to call this.
    pub fn reject(&mut self, id: Node, now: Instant) {
        self.open.remove(&id);
        self.remove_spare(&id);
        // A record past its time can still be here, and two entries would end the new one.
        if self.rejected.remove(&id).is_some() {
            self.rejected_order.retain(|other| *other != id);
        }
        if self.rejected.len() >= self.limits.max_rejected
            && let Some(oldest) = self.rejected_order.pop_front()
        {
            self.rejected.remove(&oldest);
        }
        self.rejected.insert(id, now + self.limits.rejected_ttl);
        self.rejected_order.push_back(id);
    }

    /// Open objects and spares past their time go, slots and all, so they can start again.
    /// Rejected records past theirs go too.
    pub fn expire(&mut self, now: Instant) -> Vec<Node> {
        let ttl = self.limits.assembly_ttl;
        let lapsed: Vec<Node> = self
            .open
            .iter()
            .filter(|(_, assembly)| now.saturating_duration_since(assembly.first_seen) >= ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in &lapsed {
            self.open.remove(id);
        }
        let old_spares: Vec<Node> = self
            .spares
            .iter()
            .filter(|(_, spare)| now.saturating_duration_since(spare.first_seen) >= ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in &old_spares {
            self.remove_spare(id);
        }
        self.rejected.retain(|_, end| now < *end);
        let rejected = &self.rejected;
        self.rejected_order.retain(|id| rejected.contains_key(id));
        lapsed
    }
}
