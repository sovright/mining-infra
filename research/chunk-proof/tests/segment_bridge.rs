//! The hand-over to the segment prototype. Real frames, a real `Intake` and ledger,
//! no network, relay, node or sidecar. A decode is not a delivery, and these are the cases
//! that show the difference.

mod common;

use std::time::{Duration, Instant};

use chunk_proof::assembler::{Arrival, Assembler, CannotStart, DecodedObject, Interest};
use chunk_proof::budget::{Budget, Used};
use chunk_proof::datagram::{ChunkError, seal};
use chunk_proof::handoff::{Bridge, Handoff, Stack, StackLimits, Step};
use chunk_proof::object::{Encoded, MSG_BLOCK, Profile, encode};
use common::segments::{SEGMENT, body, carried, frame_rules, frames_of};
use common::{
    KEY, assembler_limits, assembler_on, content, datagrams, decoded, object, pending, roomy,
    roomy_limits,
};
use delivery_lease::body_buffer::{ACTIVE_SET, BufferLimits};
use delivery_lease::segment_frame::{FrameError, check};
use delivery_lease::{
    Admission, DeliveryLedger, Limits, ObjectId, Phase, Refusal, Snapshot, Ticket, Transit,
};
use tokio::sync::mpsc;

const BUFFER_TTL: Duration = Duration::from_secs(120);
const COMPLETED_TTL: Duration = Duration::from_secs(300);

fn ledger_limits(segments: usize) -> Limits {
    Limits {
        max_records: 64,
        max_live_owners: 64,
        max_reserved_bytes: segments * SEGMENT,
        repeat_budget: 2,
        completed_ttl: COMPLETED_TTL,
        released_ttl: std::time::Duration::from_secs(86_400),
        transit: Transit {
            bytes: 8 * SEGMENT,
            owners: 8,
            records: 8,
        },
    }
}

fn buffer_limits() -> BufferLimits {
    BufferLimits {
        max_sets: 8,
        max_sets_per_block: 4,
        max_segments: 32,
        ttl: BUFFER_TTL,
    }
}

fn stack_limits(ledger: Limits, buffer: BufferLimits, max_carried: usize) -> StackLimits {
    StackLimits {
        budget: roomy_limits(),
        ledger,
        buffer,
        assembler: assembler_limits(),
        max_carried,
    }
}

fn stack_of(limits: StackLimits) -> Stack {
    Stack::new(KEY, Profile::EveryShape, frame_rules(), limits).unwrap()
}

struct Rig {
    stack: Stack,
    budget: Budget,
    ledger: DeliveryLedger,
    bridge: Bridge,
    session: Assembler,
}

impl Rig {
    fn new(limits: Limits) -> Self {
        Self::with_carried(limits, 64)
    }

    fn with_carried(limits: Limits, max_carried: usize) -> Self {
        let stack = stack_of(stack_limits(limits, buffer_limits(), max_carried));
        let (budget, ledger) = (stack.budget().clone(), stack.ledger().clone());
        let bridge = stack.bridge().unwrap();
        let session = stack.session().unwrap();
        Self {
            stack,
            budget,
            ledger,
            bridge,
            session,
        }
    }

    /// Chunks of `object`, and what the last one came to.
    fn send(&mut self, object: &Encoded, indices: &[usize], now: Instant) -> Step {
        let frames = datagrams(object);
        let mut last = None;
        for at in indices {
            last = Some(self.bridge.take(&mut self.session, &frames[*at], now));
        }
        last.expect("at least one chunk")
    }

    /// Chunks until one is handed over.
    fn deliver(&mut self, object: &Encoded, now: Instant) -> Handoff {
        let frames = datagrams(object);
        for frame in &frames {
            if let Step::Handed(handoff) = self.bridge.take(&mut self.session, frame, now) {
                return handoff;
            }
        }
        panic!("no chunk was handed over");
    }

    fn idle(&self) -> Used {
        Used {
            sessions: 2,
            ..Used::default()
        }
    }
}

fn held(handoff: Handoff) -> Vec<[u8; 32]> {
    match handoff {
        Handoff::Held(evicted) => evicted.iter().map(|key| key.body_id).collect(),
        other => panic!("expected the segment to be held, got {other:?}"),
    }
}

fn whole(rig: &mut Rig, handoff: Handoff, now: Instant) -> Vec<u8> {
    let Handoff::Whole(set) = handoff else {
        panic!("expected a whole set, got {handoff:?}");
    };
    rig.bridge.assemble(set, now).unwrap().block().clone()
}

fn segment_of(frame: &[u8]) -> ObjectId {
    check(frame, &frame_rules()).unwrap().ledger_key()
}

/// A body's frames, each carried as an object, and what the ledger calls them.
fn carried_body(fill: u8) -> (Vec<u8>, Vec<Encoded>, Vec<ObjectId>) {
    let raw = body(fill);
    let frames = frames_of(&raw);
    let objects = frames.iter().map(|frame| carried(frame)).collect();
    let segments = frames.iter().map(|frame| segment_of(frame)).collect();
    (raw, objects, segments)
}

fn ticket(ledger: &DeliveryLedger, id: ObjectId, bytes: usize, now: Instant) -> Ticket {
    match ledger.admit(id, bytes, now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    }
}

fn records(snapshot: &Snapshot) -> usize {
    snapshot.in_flight + snapshot.held + snapshot.released + snapshot.completed
}

// A decode is not a delivery.

/// The object decoded and the layer below had no room. Nothing is written against it, and
/// it waits on the shelf as it is, so it needs neither a copy nor a second decode.
#[test]
fn a_refusal_below_writes_nothing_and_the_object_goes_in_once_there_is_room() {
    let mut rig = Rig::new(ledger_limits(1));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    let room = ticket(&rig.ledger, [9; 32], SEGMENT, now);

    let refused = rig.deliver(&objects[0], now);

    assert!(matches!(refused, Handoff::Refused(Refusal::Bytes)));
    assert_eq!(rig.session.state().rejected, 0);
    assert_eq!(rig.session.state().open, 0);
    assert_eq!(rig.session.state().spares, 1);
    assert_eq!(rig.budget.used().held_bytes, 0, "it counts on the shelf");
    assert!(rig.budget.used().spare_bytes > 0);
    assert_eq!(rig.ledger.observe(&segments[0]), None, "and no record");

    assert!(matches!(
        &rig.bridge.sweep(&mut rig.session, now)[..],
        [Handoff::Refused(Refusal::Bytes)]
    ));
    assert_eq!(rig.session.state().spares, 1, "still no room, still there");

    drop(room);
    assert!(matches!(
        &rig.bridge.sweep(&mut rig.session, now)[..],
        [Handoff::Held(_)]
    ));
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
    assert_eq!(rig.budget.used().spare_bytes, 0);
}

/// One chunk each of as many objects as it takes to fill the normal places and the shelf,
/// with whatever is on the shelf already taking the last of it.
fn crowd(rig: &mut Rig, count: usize, now: Instant) {
    for fill in 0..count {
        let stopped = object(MSG_BLOCK, 6, 4, fill as u8, 40);
        let step = rig
            .bridge
            .take(&mut rig.session, &datagrams(&stopped)[0], now);
        assert!(
            matches!(step, Step::Chunk(Arrival::Pending { .. })),
            "{step:?}"
        );
    }
}

/// An object on its way through, with everything full as its last chunk comes. A client's
/// way to what a node does in `tests/assembler.rs`.
#[test]
fn the_chunk_that_finishes_an_object_on_a_full_shelf_hands_it_over() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    rig.send(&objects[0], &[0, 1, 2], now);
    crowd(&mut rig, 16 + 16 - 1, now);
    assert_eq!(rig.session.state().spares, 16);

    let step = rig.send(&objects[0], &[3], now);

    assert!(matches!(step, Step::Handed(Handoff::Held(_))), "{step:?}");
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
}

/// A sweep that hands over a decoded object from a full shelf.
#[test]
fn a_sweep_with_everything_full_keeps_what_it_hands_over() {
    let mut rig = Rig::new(ledger_limits(1));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    let room = ticket(&rig.ledger, [9; 32], SEGMENT, now);
    assert!(matches!(
        rig.deliver(&objects[0], now),
        Handoff::Refused(Refusal::Bytes)
    ));
    crowd(&mut rig, 16 + 16 - 1, now);
    assert_eq!(rig.session.state().spares, 16);
    drop(room);

    let handed = rig.bridge.sweep(&mut rig.session, now);

    assert!(matches!(&handed[..], [Handoff::Held(_)]), "{handed:?}");
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
}

/// A chunk of it does the same as a sweep.
#[test]
fn a_chunk_of_a_refused_object_offers_it_again() {
    let mut rig = Rig::new(ledger_limits(1));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    let room = ticket(&rig.ledger, [9; 32], SEGMENT, now);
    assert!(matches!(rig.deliver(&objects[0], now), Handoff::Refused(_)));
    drop(room);

    assert!(matches!(
        rig.send(&objects[0], &[5], now),
        Step::Handed(Handoff::Held(_))
    ));
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
}

/// With the shelf gone, or never used, the object comes back from a copy.
#[test]
fn a_refused_object_past_its_time_on_the_shelf_comes_back_from_a_copy() {
    let mut rig = Rig::new(ledger_limits(1));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    let room = ticket(&rig.ledger, [9; 32], SEGMENT, now);
    assert!(matches!(rig.deliver(&objects[0], now), Handoff::Refused(_)));
    drop(room);

    let now = now + common::ASSEMBLY_TTL;
    rig.session.expire(now);
    assert_eq!(rig.session.state().spares, 0);

    held(rig.deliver(&objects[0], now));
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
}

/// An eviction ends the ownership in the ledger and nothing here has to hear about it.
#[test]
fn a_segment_evicted_for_capacity_can_come_back() {
    let mut rig = Rig::new(ledger_limits(2));
    let now = Instant::now();
    let (_, first, first_segments) = carried_body(10);
    let (_, second, _) = carried_body(20);
    let (_, third, _) = carried_body(30);
    held(rig.deliver(&first[0], now));
    held(rig.deliver(&second[0], now));
    // A set still arriving is never given up, so these have gone quiet.
    let now = now + ACTIVE_SET;

    let evicted = held(rig.deliver(&third[0], now));

    assert_eq!(evicted.len(), 1);
    assert_eq!(
        rig.ledger.observe(&first_segments[0]),
        Some(Phase::Released)
    );
    assert_eq!(rig.bridge.interest(&first[0].object_id, now), Interest::Due);
    let now = now + ACTIVE_SET;

    assert_eq!(held(rig.deliver(&first[0], now)).len(), 1);
    assert_eq!(rig.ledger.observe(&first_segments[0]), Some(Phase::Held));
}

/// The same for an expiry, all the way to the block, byte for byte.
#[test]
fn an_expired_set_comes_back_from_new_copies() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (raw, objects, segments) = carried_body(10);
    held(rig.deliver(&objects[0], now));

    let now = now + BUFFER_TTL;
    assert_eq!(rig.bridge.expire(now).len(), 1);
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Released));

    held(rig.deliver(&objects[0], now));
    let last = rig.deliver(&objects[1], now);
    assert_eq!(whole(&mut rig, last, now), raw);
}

// No needless second delivery.

/// Two sessions decode one object before either hands it over. The ledger takes one.
#[test]
fn two_sessions_deliver_one_object_once() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    let frames = datagrams(&objects[0]);
    let mut other = assembler_on(&rig.budget);
    let feed = |session: &mut Assembler| {
        let mut last = None;
        for frame in &frames[..4] {
            last = Some(session.receive(frame, now));
        }
        decoded(last.unwrap())
    };
    let (one, two) = (feed(&mut rig.session), feed(&mut other));

    assert!(held(rig.bridge.deliver(one, now)).is_empty());
    assert!(matches!(
        rig.bridge.deliver(two, now),
        Handoff::AlreadyHeld(Phase::Held)
    ));

    assert_eq!(rig.bridge.buffer().segments(), 1);
    assert_eq!(rig.ledger.snapshot().live_owners, 1);
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
    assert_eq!(rig.budget.used().held_bytes, 0);
}

/// Once it is delivered another session's chunks are spares: no normal place, no decode.
#[test]
fn a_second_session_keeps_spares_once_the_object_is_held() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, _) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    let mut other = assembler_on(&rig.budget);

    let frames = datagrams(&objects[0]);
    for frame in &frames {
        assert!(matches!(
            rig.bridge.take(&mut other, frame, now),
            Step::Chunk(Arrival::Spare { .. } | Arrival::Repeat)
        ));
    }

    assert_eq!(other.state().open, 0);
    assert_eq!(other.state().spares, 1);
    assert_eq!(rig.budget.used().objects, 0);
}

/// What the shelf saves, in the same case without it: a whole object's bytes for each
/// object delivered, until it expires. Nothing is delivered twice either way.
#[test]
fn without_the_check_spare_chunks_hold_an_object_until_it_expires() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, _) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    let frames = datagrams(&objects[0]);

    pending(rig.session.receive(&frames[4], now));
    pending(rig.session.receive(&frames[5], now));

    assert_eq!(rig.session.state().open, 1);
    assert!(rig.budget.used().held_bytes > 0);
}

/// The table is a fact and no state, so losing it costs a decode and no delivery.
#[test]
fn forgetting_what_an_object_carries_costs_a_decode_and_nothing_else() {
    let mut rig = Rig::with_carried(ledger_limits(16), 1);
    let now = Instant::now();
    let (_, first, first_segments) = carried_body(10);
    let (_, second, _) = carried_body(20);
    held(rig.deliver(&first[0], now));
    held(rig.deliver(&second[0], now));
    assert_eq!(
        rig.bridge.interest(&first[0].object_id, now),
        Interest::New,
        "forgotten"
    );

    let again = rig.deliver(&first[0], now);

    assert!(matches!(again, Handoff::AlreadyHeld(Phase::Held)));
    assert_eq!(rig.ledger.observe(&first_segments[0]), Some(Phase::Held));
}

// Generations.

/// An old block lets go of everything after a new copy of its segment has come in. The
/// new delivery's record stands, and the body can still finish.
#[test]
fn an_old_owner_letting_go_leaves_the_new_delivery_alone() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (raw, objects, segments) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    let Handoff::Whole(set) = rig.deliver(&objects[1], now) else {
        panic!("the second segment finishes the set");
    };
    let mut old = rig.bridge.assemble(set, now).unwrap();
    old.release_segments();
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Released));

    held(rig.deliver(&objects[0], now));
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));

    old.give_back();

    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
    assert_eq!(rig.bridge.buffer().segments(), 1);
    let last = rig.deliver(&objects[1], now);
    assert_eq!(whole(&mut rig, last, now), raw);
}

/// A copy decoded earlier and still on its way changes nothing when it goes, and when it
/// arrives after an eviction it is a delivery of its own.
#[test]
fn a_late_copy_has_only_its_own_reservation_to_give_back() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    let frames = datagrams(&objects[0]);
    let mut other = assembler_on(&rig.budget);
    let mut late = None;
    for frame in &frames[..4] {
        late = Some(other.receive(frame, now));
    }
    let late = decoded(late.unwrap());
    let in_hand = rig.budget.used();
    held(rig.deliver(&objects[0], now));
    assert_eq!(
        rig.budget.used(),
        in_hand,
        "only the late copy is still held"
    );

    let now = now + BUFFER_TTL;
    rig.bridge.expire(now);
    assert!(held(rig.bridge.deliver(late, now)).is_empty());

    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
    assert_eq!(rig.budget.used().held_bytes, 0);
    assert_eq!(rig.ledger.snapshot().live_owners, 1);
}

/// `Completed` is what "not wanted again" means, and only `finish` writes it.
#[test]
fn a_finished_block_is_not_wanted_again() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    let Handoff::Whole(set) = rig.deliver(&objects[1], now) else {
        panic!("the second segment finishes the set");
    };
    let block = rig.bridge.assemble(set, now).unwrap();
    assert!(
        rig.bridge.interest(&objects[0].object_id, now) == Interest::Spare,
        "the block has it"
    );
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));

    block.finish(now);

    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Completed));
    assert_eq!(
        rig.bridge.interest(&objects[0].object_id, now),
        Interest::Done
    );
    assert!(matches!(
        rig.send(&objects[0], &[0], now),
        Step::Chunk(Arrival::NotWanted)
    ));
    let mut other = assembler_on(&rig.budget);
    let frames = datagrams(&objects[0]);
    let mut last = None;
    for frame in &frames[..4] {
        last = Some(other.receive(frame, now));
    }
    assert!(matches!(
        rig.bridge.deliver(decoded(last.unwrap()), now),
        Handoff::NotWanted
    ));
}

/// `Completed` ends at its time. A copy after that is a new delivery, whether or not
/// anything else has gone through the ledger meanwhile to clear the record.
#[test]
fn a_lapsed_completed_record_does_not_stop_a_new_copy() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (raw, objects, segments) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    let Handoff::Whole(set) = rig.deliver(&objects[1], now) else {
        panic!("the second segment finishes the set");
    };
    rig.bridge.assemble(set, now).unwrap().finish(now);
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Completed));

    let now = now + COMPLETED_TTL;

    held(rig.deliver(&objects[0], now));
    let last = rig.deliver(&objects[1], now);
    assert_eq!(whole(&mut rig, last, now), raw);
}

// Channels and cancellation.

fn decoded_copy(budget: &Budget, fill: u8) -> DecodedObject {
    let mut session = assembler_on(budget);
    let object = object(3, 2, 1, fill, 50);
    decoded(session.receive(&datagrams(&object)[0], Instant::now()))
}

/// Objects between the layers are counted, and a closed channel gives them back.
#[test]
fn closing_the_channel_returns_what_was_in_it() {
    let budget = roomy();
    let (sender, receiver) = mpsc::channel(2);
    sender.try_send(decoded_copy(&budget, 1)).unwrap();
    sender.try_send(decoded_copy(&budget, 2)).unwrap();
    assert_eq!(budget.used().held_bytes, 100);

    drop(receiver);

    assert_eq!(budget.used().held_bytes, 0);
    assert!(sender.try_send(decoded_copy(&budget, 3)).is_err());
    assert_eq!(budget.used(), Used::default());
}

/// A send waiting on a full channel is cancelled, and the object it held goes with it.
#[tokio::test]
async fn cancelling_a_pending_send_returns_its_object() {
    let budget = roomy();
    let (sender, mut receiver) = mpsc::channel(1);
    sender.try_send(decoded_copy(&budget, 1)).unwrap();
    let waiting = decoded_copy(&budget, 2);
    let task_sender = sender.clone();
    let task = tokio::spawn(async move {
        let _ = task_sender.send(waiting).await;
    });
    tokio::task::yield_now().await;
    assert_eq!(budget.used().held_bytes, 100);

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    assert_eq!(budget.used().held_bytes, 50, "the one in the channel stays");
    drop(receiver.recv().await);
    assert_eq!(budget.used().held_bytes, 0);
}

/// The consumer goes away with segments held and an object on the way. Every reservation
/// on either side of the bridge comes back.
#[tokio::test]
async fn cancelling_the_consumer_returns_every_reservation() {
    let stack = stack_of(stack_limits(ledger_limits(16), buffer_limits(), 64));
    let (budget, ledger) = (stack.budget().clone(), stack.ledger().clone());
    let mut bridge = stack.bridge().unwrap();
    let (sender, mut receiver) = mpsc::channel::<DecodedObject>(4);
    let (delivered, mut told) = mpsc::channel::<()>(4);
    let consumer = tokio::spawn(async move {
        while let Some(object) = receiver.recv().await {
            drop(bridge.deliver(object, Instant::now()));
            delivered.send(()).await.unwrap();
        }
    });
    let (_, objects, _) = carried_body(10);
    let mut session = assembler_on(&budget);
    let frames = datagrams(&objects[0]);
    let now = Instant::now();
    let mut last = None;
    for frame in &frames[..4] {
        last = Some(session.receive(frame, now));
    }
    sender.send(decoded(last.unwrap())).await.unwrap();
    told.recv().await.unwrap();
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);
    pending(session.receive(&frames[4], now));
    assert!(budget.used().held_bytes > 0);

    consumer.abort();
    assert!(consumer.await.unwrap_err().is_cancelled());
    drop(session);

    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(ledger.snapshot().live_owners, 0);
    assert_eq!(budget.used(), Used::default());
}

// A fact about the bytes is not a shortage of room.

#[test]
fn a_bad_object_and_a_refusal_are_not_recorded_alike() {
    let mut rig = Rig::new(ledger_limits(1));
    let now = Instant::now();

    // The transport failed: these bytes fail again, so they are not tried again.
    let good = object(3, 6, 4, 10, 40);
    let mut shards = good.shards.clone();
    shards[5][0] ^= 1;
    let leaves = shards
        .iter()
        .enumerate()
        .map(|(at, shard)| chunk_proof::tree::chunk_leaf(1, 3, 6, 4, at as u16, shard))
        .collect();
    let levels = chunk_proof::tree::levels(leaves);
    let broken = Encoded {
        shape: good.shape,
        object_id: levels[levels.len() - 1][0],
        proofs: (0..6)
            .map(|at| chunk_proof::tree::proof(&levels, at))
            .collect(),
        shards,
    };
    assert!(matches!(
        rig.send(&broken, &[0, 1, 2, 3], now),
        Step::Chunk(Arrival::Rejected(_))
    ));
    assert!(matches!(
        rig.send(&broken, &[4], now),
        Step::Chunk(Arrival::KnownBad)
    ));

    // The content failed: the same.
    let mut frame = frames_of(&body(10)).swap_remove(1);
    *frame.last_mut().unwrap() ^= 1;
    let bad_frame = carried(&frame);
    assert!(matches!(
        rig.send(&bad_frame, &[0, 1, 2, 3], now),
        Step::Handed(Handoff::BadContent(FrameError::Proof))
    ));
    assert!(matches!(
        rig.send(&bad_frame, &[4], now),
        Step::Chunk(Arrival::KnownBad)
    ));
    let rejected = rig.session.state().rejected;
    assert_eq!(rejected, 2);

    // No room is a fact about now: no record, and the same chunks are welcome.
    let (_, objects, _) = carried_body(20);
    let room = ticket(&rig.ledger, [9; 32], SEGMENT, now);
    assert!(matches!(
        rig.deliver(&objects[0], now),
        Handoff::Refused(Refusal::Bytes)
    ));
    assert_eq!(rig.session.state().rejected, rejected);
    drop(room);
    held(rig.deliver(&objects[0], now));
}

/// A set this buffer could never hold is the same answer for the same bytes, in this
/// binary, so it is recorded like bad content and not like a shortage of room.
#[test]
fn a_set_too_long_for_the_buffer_is_recorded_like_bad_content() {
    let small = BufferLimits {
        max_segments: 1,
        ..buffer_limits()
    };
    let stack = stack_of(stack_limits(ledger_limits(16), small, 64));
    let ledger = stack.ledger().clone();
    let mut bridge = stack.bridge().unwrap();
    let mut session = stack.session().unwrap();
    let now = Instant::now();
    let (_, objects, _) = carried_body(10);
    let frames = datagrams(&objects[0]);

    let mut last = None;
    for frame in &frames[..4] {
        last = Some(bridge.take(&mut session, frame, now));
    }

    assert!(matches!(last, Some(Step::Handed(Handoff::TooLong(_)))));
    assert_eq!(session.state().rejected, 1);
    assert!(matches!(
        bridge.take(&mut session, &frames[4], now),
        Step::Chunk(Arrival::KnownBad)
    ));
    assert_eq!(records(&ledger.snapshot()), 0);
}

// The two layers meet.

/// Forged chunks come first and a competing body's chunks are interleaved. Each decoded
/// frame goes down, and both bodies come out byte for byte under their own ids.
#[test]
fn a_decoded_raw_object_is_a_frame_the_segment_layer_verifies_again() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (honest_raw, honest, _) = carried_body(10);
    let (other_raw, other, _) = carried_body(20);

    let forged = seal(
        &KEY,
        &honest[0].shape,
        &honest[0].object_id,
        2,
        &honest[0].proofs[2],
        &other[0].shards[2],
    );
    assert!(matches!(
        rig.bridge.take(&mut rig.session, &forged, now),
        Step::Chunk(Arrival::Invalid(ChunkError::Proof))
    ));

    held(rig.deliver(&honest[0], now));
    held(rig.deliver(&other[0], now));
    let first = rig.deliver(&honest[1], now);
    assert_eq!(whole(&mut rig, first, now), honest_raw);
    let second = rig.deliver(&other[1], now);
    assert_eq!(whole(&mut rig, second, now), other_raw);
}

#[test]
fn an_object_of_another_type_is_handed_back() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let bytes = content(5, 40);
    let block = encode(MSG_BLOCK, 6, 4, &bytes).unwrap();

    let Handoff::NotASegment(decoded) = rig.deliver(&block, now) else {
        panic!("expected the object back");
    };

    assert_eq!(decoded.content(), bytes);
    assert_eq!(records(&rig.ledger.snapshot()), 0);
}

/// Bridges come from one place, are bounded the way assemblers are, and share its ledger.
#[test]
fn a_stack_bounds_its_bridges_and_gives_them_one_ledger() {
    let limits = StackLimits {
        budget: chunk_proof::budget::Limits {
            max_sessions: 2,
            ..roomy_limits()
        },
        ..stack_limits(ledger_limits(16), buffer_limits(), 8)
    };
    let stack = stack_of(limits);
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);

    let (mut first, mut second) = (stack.bridge().unwrap(), stack.bridge().unwrap());
    assert_eq!(stack.bridge().err(), Some(CannotStart("sessions")));
    assert_eq!(stack.session().err(), Some(CannotStart("sessions")));

    let frames = datagrams(&objects[0]);
    let budget = roomy();
    let mut session = assembler_on(&budget);
    let mut copy = |bridge: &mut Bridge| {
        let mut last = None;
        for frame in &frames[..4] {
            last = Some(session.receive(frame, now));
        }
        bridge.deliver(decoded(last.unwrap()), now)
    };

    held(copy(&mut first));
    assert!(matches!(
        copy(&mut second),
        Handoff::AlreadyHeld(Phase::Held)
    ));
    assert_eq!(stack.ledger().observe(&segments[0]), Some(Phase::Held));

    drop(first);
    assert_eq!(stack.budget().used().sessions, 1);
    assert_eq!(stack.ledger().snapshot().reserved_bytes, 0);
    assert!(stack.bridge().is_ok());
}

#[test]
fn a_stack_refuses_limits_that_cannot_work() {
    let limits = stack_limits(ledger_limits(16), buffer_limits(), 0);
    assert_eq!(
        Stack::new(KEY, Profile::EveryShape, frame_rules(), limits).err(),
        Some(CannotStart("max_carried"))
    );

    let no_sessions = StackLimits {
        budget: chunk_proof::budget::Limits {
            max_sessions: 0,
            ..roomy_limits()
        },
        ..stack_limits(ledger_limits(16), buffer_limits(), 8)
    };
    assert_eq!(
        Stack::new(KEY, Profile::EveryShape, frame_rules(), no_sessions).err(),
        Some(CannotStart("max_sessions"))
    );

    let no_sets = stack_limits(
        ledger_limits(16),
        BufferLimits {
            max_sets: 0,
            ..buffer_limits()
        },
        8,
    );
    assert_eq!(
        stack_of(no_sets).bridge().err(),
        Some(CannotStart("max_sets"))
    );
}

/// The sum of the budgets, and nothing more clever.
#[test]
fn the_ceiling_is_the_sum_of_the_fixed_budgets() {
    let rig = Rig::new(ledger_limits(16));
    let ceiling = rig.stack.ceiling();

    assert_eq!(ceiling.held_bytes, roomy_limits().max_held_bytes);
    assert_eq!(ceiling.work_bytes, roomy_limits().max_work_bytes);
    assert_eq!(ceiling.reserved_bytes, 16 * SEGMENT);
    assert_eq!(ceiling.transit_bytes, 8 * SEGMENT);
    assert_eq!(ceiling.spare_bytes, roomy_limits().max_spare_bytes);
    assert_eq!(
        ceiling.total_bytes(),
        (1 << 20) + (1 << 22) + (1 << 20) + 24 * SEGMENT
    );
}

// What stays open.

/// The hand-over makes recovery possible and no more. If no copy comes, nothing comes:
/// nothing here asks for one, and the set stays short.
#[test]
fn known_gap_a_segment_that_never_comes_again_stays_gone() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    held(rig.deliver(&objects[0], now));

    let later = now + BUFFER_TTL;
    rig.bridge.expire(later);
    rig.session.expire(later);

    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Released));
    assert_eq!(rig.bridge.buffer().sets(), 0);
    assert_eq!(rig.budget.used(), rig.idle());
}

/// Chunks that came while the owner lived are kept, so they are there when it goes.
#[test]
fn spares_kept_while_the_owner_lived_bring_the_object_back() {
    let mut rig = Rig::new(ledger_limits(16));
    let now = Instant::now();
    let (_, objects, segments) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    assert!(matches!(
        rig.send(&objects[0], &[0, 1, 2, 3, 4, 5], now),
        Step::Chunk(Arrival::Spare { .. } | Arrival::Repeat)
    ));

    rig.bridge.expire(now + BUFFER_TTL);
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Released));

    let back = rig.bridge.sweep(&mut rig.session, now + BUFFER_TTL);
    assert!(matches!(&back[..], [Handoff::Held(_)]));
    assert_eq!(rig.ledger.observe(&segments[0]), Some(Phase::Held));
}

/// The repeat budget is a limit of the ledger. Used up, copies stop while the
/// record lives. It is no fact about the bytes, so nothing is rejected for it.
#[test]
fn known_gap_copies_stop_when_the_repeat_budget_is_spent() {
    let mut rig = Rig::new(Limits {
        repeat_budget: 0,
        ..ledger_limits(16)
    });
    let now = Instant::now();
    let (_, objects, _) = carried_body(10);
    held(rig.deliver(&objects[0], now));
    let now = now + BUFFER_TTL;
    rig.bridge.expire(now);

    assert!(matches!(
        rig.deliver(&objects[0], now),
        Handoff::Refused(Refusal::RepeatBudget)
    ));
    assert_eq!(rig.session.state().rejected, 0);
    assert_eq!(
        rig.session.state().spares,
        0,
        "no room can open for this one"
    );
    assert_eq!(rig.budget.used().spare_bytes, 0);
}
