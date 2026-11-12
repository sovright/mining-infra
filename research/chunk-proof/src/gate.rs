//! The state rules of Ek A section 5 as a small model, so the research chain ends in what
//! the design says and not in a comparison of bytes. It stands for what `submit_gate.rs`
//! and `relay_bridge.rs` would have to become, and neither of them is touched.
//!
//! Two records of today's code stop a right body after a wrong one. The gate writes the
//! block hash before Zebra has answered (N1), and the ingress dedups on the header (N2).
//! Here a block is recorded only when Zebra says it has it, and a header can have more
//! than one body in flight, within a budget.
//!
//! Live mode only. `DryRun` and the emergency bypass are not modelled, and nothing here
//! says what a real Zebra would answer.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug)]
pub struct GateLimits {
    /// Zebra calls per block in a window, the same bytes included.
    pub max_calls: usize,
    /// Different bodies per block in a window.
    pub max_bodies: usize,
    /// Blocks remembered, oldest forgotten first.
    pub max_blocks: usize,
    pub window: Duration,
}

/// What came back from Zebra, as far as this model needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// `duplicate`, or a lost race. Zebra has the block.
    AlreadyKnown,
    Refused,
    /// A timeout or an error. Zebra may or may not have it.
    Failed,
}

#[derive(Debug)]
pub enum Reservation {
    Go(Attempt),
    /// The same bytes are with Zebra now.
    Merged,
    /// Zebra has this block.
    Known,
    OverBudget,
}

#[derive(Debug)]
struct BlockRecord {
    calls: usize,
    bodies: HashSet<Hash>,
    accepted: bool,
    end: Instant,
}

#[derive(Debug, Default)]
struct GateState {
    blocks: HashMap<Hash, BlockRecord>,
    order: VecDeque<Hash>,
    in_flight: HashMap<Hash, u64>,
    next_rid: u64,
}

#[derive(Clone, Debug)]
pub struct BodyGate {
    limits: GateLimits,
    state: Arc<Mutex<GateState>>,
}

impl BodyGate {
    pub fn new(limits: GateLimits) -> Self {
        Self {
            limits,
            state: Arc::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every check and the reservation in one critical section. Nothing is held across the
    /// call to Zebra, and the attempt counts whatever comes back.
    pub fn reserve(&self, block: Hash, body: Hash, now: Instant) -> Reservation {
        let mut state = self.lock();
        let state = &mut *state;
        state.blocks.retain(|_, record| now < record.end);
        let blocks = &state.blocks;
        state.order.retain(|id| blocks.contains_key(id));
        if !state.blocks.contains_key(&block) {
            if state.blocks.len() >= self.limits.max_blocks
                && let Some(oldest) = state.order.pop_front()
            {
                state.blocks.remove(&oldest);
            }
            state.order.push_back(block);
        }
        let record = state.blocks.entry(block).or_insert_with(|| BlockRecord {
            calls: 0,
            bodies: HashSet::new(),
            accepted: false,
            end: now + self.limits.window,
        });

        if record.accepted {
            return Reservation::Known;
        }
        if state.in_flight.contains_key(&body) {
            return Reservation::Merged;
        }
        let new_body = !record.bodies.contains(&body);
        if record.calls >= self.limits.max_calls
            || (new_body && record.bodies.len() >= self.limits.max_bodies)
        {
            return Reservation::OverBudget;
        }
        record.calls += 1;
        record.bodies.insert(body);
        state.next_rid += 1;
        let rid = state.next_rid;
        state.in_flight.insert(body, rid);
        Reservation::Go(Attempt {
            gate: self.clone(),
            block,
            body,
            rid,
        })
    }

    pub fn is_accepted(&self, block: &Hash) -> bool {
        self.lock()
            .blocks
            .get(block)
            .is_some_and(|record| record.accepted)
    }
}

/// One call to Zebra. Dropping it, for a cancel or a panic, ends the reservation and writes
/// nothing about the block.
#[derive(Debug)]
#[must_use = "dropping an attempt ends it with nothing learned"]
pub struct Attempt {
    gate: BodyGate,
    block: Hash,
    body: Hash,
    rid: u64,
}

impl Attempt {
    fn release(&self) {
        let mut state = self.gate.lock();
        if state.in_flight.get(&self.body) == Some(&self.rid) {
            state.in_flight.remove(&self.body);
        }
    }

    /// A deadline passed with the call still out, so the next copy can try. This attempt
    /// can still `finish`, and that cannot touch a newer attempt's reservation.
    pub fn time_out(&self) {
        self.release();
    }

    /// Only Zebra's knowledge of the block is written, however late it comes.
    pub fn finish(self, verdict: Verdict, now: Instant) {
        if matches!(verdict, Verdict::Accepted | Verdict::AlreadyKnown) {
            let window = self.gate.limits.window;
            let mut state = self.gate.lock();
            if let Some(record) = state.blocks.get_mut(&self.block) {
                record.accepted = true;
                record.end = record.end.max(now + window);
            }
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IngressLimits {
    /// Different bodies forwarded per header in a window.
    pub max_bodies: usize,
    /// Headers remembered, oldest forgotten first.
    pub max_headers: usize,
    pub window: Duration,
}

#[derive(Debug)]
pub enum Forward {
    Go(ForwardClaim),
    /// These bytes were forwarded in this window.
    AlreadySent,
    /// These bytes are being forwarded now.
    InFlight,
    OverBudget,
}

#[derive(Debug)]
struct HeaderRecord {
    bodies: HashSet<Hash>,
    sent: HashSet<Hash>,
    end: Instant,
}

#[derive(Debug, Default)]
struct IngressState {
    headers: HashMap<Hash, HeaderRecord>,
    order: VecDeque<Hash>,
    in_flight: HashMap<Hash, u64>,
    next_rid: u64,
}

#[derive(Clone, Debug)]
pub struct BodyIngress {
    limits: IngressLimits,
    state: Arc<Mutex<IngressState>>,
}

impl BodyIngress {
    pub fn new(limits: IngressLimits) -> Self {
        Self {
            limits,
            state: Arc::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, IngressState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// For a body that passed the strict reader. One that did not never gets here, so it
    /// leaves no record and uses no budget.
    pub fn claim(&self, header: Hash, body: Hash, now: Instant) -> Forward {
        let mut state = self.lock();
        let state = &mut *state;
        state.headers.retain(|_, record| now < record.end);
        let headers = &state.headers;
        state.order.retain(|id| headers.contains_key(id));
        if !state.headers.contains_key(&header) {
            if state.headers.len() >= self.limits.max_headers
                && let Some(oldest) = state.order.pop_front()
            {
                state.headers.remove(&oldest);
            }
            state.order.push_back(header);
        }
        let record = state.headers.entry(header).or_insert_with(|| HeaderRecord {
            bodies: HashSet::new(),
            sent: HashSet::new(),
            end: now + self.limits.window,
        });

        if record.sent.contains(&body) {
            return Forward::AlreadySent;
        }
        if state.in_flight.contains_key(&body) {
            return Forward::InFlight;
        }
        if !record.bodies.contains(&body) && record.bodies.len() >= self.limits.max_bodies {
            return Forward::OverBudget;
        }
        record.bodies.insert(body);
        state.next_rid += 1;
        let rid = state.next_rid;
        state.in_flight.insert(body, rid);
        Forward::Go(ForwardClaim {
            ingress: self.clone(),
            header,
            body,
            rid,
            sent: false,
        })
    }
}

/// One forward. Dropped without [`Self::sent`] it gives its budget back, so a send that
/// failed cannot hide a good copy.
#[derive(Debug)]
#[must_use = "dropping a claim gives the forward back"]
pub struct ForwardClaim {
    ingress: BodyIngress,
    header: Hash,
    body: Hash,
    rid: u64,
    sent: bool,
}

impl ForwardClaim {
    pub fn sent(mut self) {
        self.sent = true;
        let mut state = self.ingress.lock();
        if let Some(record) = state.headers.get_mut(&self.header) {
            record.sent.insert(self.body);
        }
    }
}

impl Drop for ForwardClaim {
    fn drop(&mut self) {
        let mut state = self.ingress.lock();
        if state.in_flight.get(&self.body) == Some(&self.rid) {
            state.in_flight.remove(&self.body);
        }
        if !self.sent
            && let Some(record) = state.headers.get_mut(&self.header)
        {
            record.bodies.remove(&self.body);
        }
    }
}
