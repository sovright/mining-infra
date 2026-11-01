//! One stack in the design's real format, the way the integrated tests use it: the research
//! profile, the real frame rules, one ledger and one budget from one constructor.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use chunk_proof::assembler::Assembler;
use chunk_proof::budget::{Limits as BudgetLimits, Used};
use chunk_proof::handoff::{Bridge, Handoff, Stack, StackLimits, Step};
use chunk_proof::object::{Encoded, Profile};
use delivery_lease::Limits as LedgerLimits;
use delivery_lease::Transit;
use delivery_lease::body_buffer::{AssembledBlock, BufferLimits};

use super::bodies::{Body, SEG, rules};
use super::{KEY, assembler_limits, datagrams};

pub const BUFFER_TTL: Duration = Duration::from_secs(120);
pub const COMPLETED_TTL: Duration = Duration::from_secs(300);

pub fn limits() -> StackLimits {
    StackLimits {
        budget: BudgetLimits {
            max_sessions: 8,
            max_objects: 32,
            max_held_bytes: 1 << 20,
            max_work_bytes: 1 << 20,
            max_spare_objects: 32,
            max_spare_bytes: 1 << 20,
        },
        ledger: LedgerLimits {
            max_records: 256,
            max_live_owners: 64,
            max_reserved_bytes: 16 * SEG,
            repeat_budget: 2,
            completed_ttl: COMPLETED_TTL,
            released_ttl: std::time::Duration::from_secs(86_400),
            transit: Transit {
                bytes: 8 * SEG,
                owners: 8,
                records: 8,
            },
        },
        buffer: BufferLimits {
            max_sets: 8,
            max_sets_per_block: 4,
            max_segments: 64,
            ttl: BUFFER_TTL,
        },
        assembler: assembler_limits(),
        max_carried: 256,
    }
}

pub struct World {
    pub stack: Stack,
    pub bridge: Bridge,
    pub session: Assembler,
    pub now: Instant,
}

impl World {
    pub fn new(limits: StackLimits) -> Self {
        let stack = Stack::new(KEY, Profile::Research, rules(), limits).unwrap();
        let bridge = stack.bridge().unwrap();
        let session = stack.session().unwrap();
        Self {
            stack,
            bridge,
            session,
            now: Instant::now(),
        }
    }

    /// The counters against the sum of the budgets. Every test goes through this after
    /// every chunk.
    pub fn check_ceiling(&self) {
        let (used, snapshot) = (self.stack.budget().used(), self.stack.ledger().snapshot());
        let counted =
            used.held_bytes + used.work_bytes + used.spare_bytes + snapshot.reserved_bytes;
        let ceiling = self.stack.ceiling();
        let limits = self.stack.budget().limits();
        assert!(
            counted <= ceiling.total_bytes(),
            "{counted} over {ceiling:?}"
        );
        assert!(snapshot.reserved_bytes <= ceiling.reserved_bytes + ceiling.transit_bytes);
        assert!(used.spare_bytes <= ceiling.spare_bytes);
        assert!(used.spare_objects <= limits.max_spare_objects);
        assert!(used.objects <= limits.max_objects);
        let ledger = self.stack.ledger().limits();
        let records = snapshot.in_flight + snapshot.held + snapshot.released + snapshot.completed;
        assert!(snapshot.live_owners <= ledger.max_live_owners + ledger.transit.owners);
        assert!(records <= ledger.max_records + ledger.transit.records);
    }

    pub fn chunks(&mut self, object: &Encoded, indices: &[usize]) -> Step {
        let frames = datagrams(object);
        let mut last = None;
        for at in indices {
            last = Some(self.bridge.take(&mut self.session, &frames[*at], self.now));
            self.check_ceiling();
        }
        last.expect("at least one chunk")
    }

    /// Chunks until one is handed over.
    pub fn object(&mut self, object: &Encoded) -> Handoff {
        for at in 0..usize::from(object.shape.n) {
            if let Step::Handed(handoff) = self.chunks(object, &[at]) {
                return handoff;
            }
        }
        panic!("no chunk was handed over");
    }

    /// Every frame of `body`, in order, to the block.
    pub fn whole_body(&mut self, body: &Body) -> AssembledBlock<Vec<u8>> {
        let (last, rest) = body.objects.split_last().expect("a body has a frame");
        for object in rest {
            held(self.object(object));
        }
        let last = self.object(last);
        self.assemble(last)
    }

    pub fn assemble(&mut self, handoff: Handoff) -> AssembledBlock<Vec<u8>> {
        match handoff {
            Handoff::Whole(set) => self.bridge.assemble(set, self.now).unwrap(),
            other => panic!("expected a whole set, got {other:?}"),
        }
    }

    pub fn later(&mut self, by: Duration) {
        self.now += by;
    }

    /// Everything goes away and every counter is back at nothing.
    pub fn settled(self) {
        let Self {
            stack,
            bridge,
            session,
            ..
        } = self;
        drop(bridge);
        drop(session);
        let snapshot = stack.ledger().snapshot();
        assert_eq!(stack.budget().used(), Used::default());
        assert_eq!(snapshot.reserved_bytes, 0);
        assert_eq!(snapshot.live_owners, 0);
    }
}

pub fn held(handoff: Handoff) -> Vec<[u8; 32]> {
    match handoff {
        Handoff::Held(evicted) => evicted.iter().map(|key| key.body_id).collect(),
        other => panic!("expected the segment to be held, got {other:?}"),
    }
}
