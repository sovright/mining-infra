//! Where the ledger and the buffer meet, for research. The ledger answers first, so
//! when it is full the buffer's own limits never run. `Intake` asks the ledger, and if
//! the only thing in the way is capacity, asks again with the buffer's sets on offer.
//!
//! The rules, in order:
//!
//! 1. A frame that fails verification changes nothing and evicts nothing.
//! 2. A set the buffer could never hold is turned away first, so it costs no other set.
//! 3. Only capacity makes room. A repeat budget, an owner or a completed record does not.
//! 4. Only sets this buffer owns can go. Tickets in a channel and blocks held downstream
//!    keep their reservations, because their holders still have the payloads.
//! 5. A set never goes to make room for itself.
//! 6. A set goes only after the ledger has admitted against it. The ledger counts the
//!    sets on offer and reserves in one critical section, so nobody can take that room,
//!    and an admission that fails has cost nothing.
//! 7. A frame is copied only once its reservation exists and its victims have gone, so
//!    every payload this path holds is counted.
//! 8. All of this is synchronous, so no lock outlives a call and none spans an await.
//!
//! The sets go after that lock is released, because their leases take it on their way
//! out, and each returns its own reservation only then. Until they have, the counts hold
//! the new object and its victims together. That overlap comes out of
//! [`Limits::transit`](super::Limits::transit), one share for the whole ledger however
//! many `Intake`s use it. A plain admission never uses the share. If it cannot cover
//! the overlap the answer is [`Refusal::Transit`] and no set goes.
//!
//! The sets on offer are read before that ask, and only this `Intake` changes them, so
//! they are still there when it evicts. Another producer can change the ledger in
//! between, and the second ask sees that.
//!
//! A verified segment can still evict an honest set. Verification proves a segment
//! belongs to its own tree, and a sender can build a consistent body of its own, so this
//! competition for capacity stays open.

use std::time::Instant;

use super::body_buffer::{
    Arrival, AssembledBlock, AssemblyError, BodyBuffer, CompleteSet, Insertion, Outcome, Reject,
};
use super::segment_frame::{CheckedFrame, FrameError, FrameRules, SetKey, check};
use super::{Admission, DeliveryLedger, Holding, ObjectId, Phase, Refusal};

#[derive(Debug)]
pub enum Offer {
    /// The frame broke a rule. Nothing changed.
    Invalid(FrameError),
    /// Someone owns this segment already, so this copy adds nothing and is not kept.
    Owned(Phase),
    Completed,
    /// No room, and none could be made. Nothing was evicted for it.
    Refused(Refusal),
    /// The buffer could never hold this set, so the ledger was not asked.
    Rejected(Reject),
    Taken(Insertion),
}

mod step {
    /// The points where another producer can run, for tests that need one at an exact
    /// place. Outside this file it exists only with the `research-steps` feature.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Step {
        /// The ledger refused for capacity, and has not been asked again.
        BeforeAsking,
        /// The ledger admitted against some sets, and they have not gone yet.
        BeforeEvicting,
    }
}

#[cfg(feature = "research-steps")]
pub use step::Step;
#[cfg(not(feature = "research-steps"))]
use step::Step;

#[derive(Debug)]
pub struct Intake {
    ledger: DeliveryLedger,
    buffer: BodyBuffer,
    rules: FrameRules,
}

impl Intake {
    pub fn new(ledger: DeliveryLedger, buffer: BodyBuffer, rules: FrameRules) -> Self {
        Self {
            ledger,
            buffer,
            rules,
        }
    }

    pub fn buffer(&self) -> &BodyBuffer {
        &self.buffer
    }

    pub fn buffer_mut(&mut self) -> &mut BodyBuffer {
        &mut self.buffer
    }

    /// The frame is only borrowed, and is copied once, after it has passed.
    pub fn receive(&mut self, frame: &[u8], now: Instant) -> Offer {
        self.receive_with(frame, now, |_| {})
    }

    /// [`Self::receive`], calling `step` at each `Step` it reaches.
    #[cfg(feature = "research-steps")]
    pub fn receive_stepping(
        &mut self,
        frame: &[u8],
        now: Instant,
        step: impl FnMut(Step),
    ) -> Offer {
        self.receive_with(frame, now, step)
    }

    fn receive_with(&mut self, frame: &[u8], now: Instant, step: impl FnMut(Step)) -> Offer {
        match check(frame, &self.rules) {
            Ok(frame) => self.offer(frame, now, step),
            Err(error) => Offer::Invalid(error),
        }
    }

    fn offer(&mut self, frame: CheckedFrame<'_>, now: Instant, step: impl FnMut(Step)) -> Offer {
        if !self.buffer.can_hold(frame.count()) {
            return Offer::Rejected(Reject::TooManySegments);
        }
        let (id, key, bytes) = (frame.ledger_key(), frame.key(), frame.payload_len());
        let (admission, mut evicted) = self.reserve(id, bytes, now, Some(&key), step);
        let ticket = match admission {
            Admission::Admitted(ticket) => ticket,
            Admission::Owned(phase) => return Offer::Owned(phase),
            Admission::Completed => return Offer::Completed,
            Admission::Refused(refusal) => return Offer::Refused(refusal),
        };
        let arrival = Arrival::new(frame.into_segment(), ticket);
        let mut insertion = self.buffer.insert(arrival, now);
        evicted.append(&mut insertion.evicted);
        insertion.evicted = evicted;
        Offer::Taken(insertion)
    }

    /// Reserve `bytes` and one owner, giving up just enough sets, or none at all.
    fn reserve(
        &mut self,
        id: ObjectId,
        bytes: usize,
        now: Instant,
        incoming: Option<&SetKey>,
        mut step: impl FnMut(Step),
    ) -> (Admission, Vec<SetKey>) {
        let first = self.ledger.admit(id, bytes, now);
        if !matches!(
            first,
            Admission::Refused(Refusal::Records | Refusal::Owners | Refusal::Bytes)
        ) {
            return (first, Vec::new());
        }

        let offered = self.buffer.evictable(incoming);
        let holdings: Vec<Holding> = offered.iter().map(|set| set.holding).collect();
        step(Step::BeforeAsking);
        let (admission, spent) = self.ledger.admit_giving_up(id, bytes, now, &holdings);

        let evicted: Vec<SetKey> = offered[..spent].iter().map(|set| set.key).collect();
        if !evicted.is_empty() {
            step(Step::BeforeEvicting);
        }
        for key in &evicted {
            self.buffer.discard(key);
        }
        (admission, evicted)
    }

    /// Assemble with the same rules for room: the copy can push out other sets, and if
    /// it cannot fit even so, the whole set is given back. This does not complete
    /// anything.
    pub fn assemble(
        &mut self,
        set: CompleteSet,
        now: Instant,
    ) -> Result<AssembledBlock<Vec<u8>>, AssemblyError> {
        self.assemble_with(set, now, |_| {})
    }

    /// [`Self::assemble`], calling `step` at each `Step` it reaches.
    #[cfg(feature = "research-steps")]
    pub fn assemble_stepping(
        &mut self,
        set: CompleteSet,
        now: Instant,
        step: impl FnMut(Step),
    ) -> Result<AssembledBlock<Vec<u8>>, AssemblyError> {
        self.assemble_with(set, now, step)
    }

    fn assemble_with(
        &mut self,
        set: CompleteSet,
        now: Instant,
        step: impl FnMut(Step),
    ) -> Result<AssembledBlock<Vec<u8>>, AssemblyError> {
        let bytes = set.raw_len() as usize;
        let (admission, _) = self.reserve(set.key.body_id, bytes, now, None, step);
        set.assemble_under(admission, |raw| raw)
    }
}

/// The whole set an offer finished, if it finished one.
pub fn into_complete(offer: Offer) -> Option<CompleteSet> {
    match offer {
        Offer::Taken(Insertion {
            outcome: Outcome::Complete(set),
            ..
        }) => Some(set),
        _ => None,
    }
}
