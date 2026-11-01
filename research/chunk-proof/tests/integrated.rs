//! The whole research chain in one suite, in the design's real format: datagrams go in and
//! a body comes out, compared byte for byte with what was sent. One stack, one ledger, one
//! budget, and the counters are checked against the sum of the budgets after every chunk.
//!
//! The judge is a stand-in that compares bytes. No node, relay, client, sidecar, gate, UDP
//! or mixed fleet is involved, and passing here says nothing about any of them.

mod common;

use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::{Duration, Instant};

use chunk_proof::assembler::{Arrival, AssemblerState, DecodedObject, Interest};
use chunk_proof::budget::Limits as BudgetLimits;
use chunk_proof::datagram::{ChunkError, seal};
use chunk_proof::gate::{
    Attempt, BodyGate, BodyIngress, Forward, GateLimits, Hash, IngressLimits, Reservation, Verdict,
};
use chunk_proof::handoff::{Handoff, Stack, StackLimits, Step};
use chunk_proof::object::Profile;
use common::bodies::{Body, HEADER, SEG, body, carried, forged_frame, rules};
use common::world::{BUFFER_TTL, COMPLETED_TTL, World, held, limits};
use common::{ASSEMBLY_TTL, KEY, datagrams};
use delivery_lease::segment_frame::FrameError;
use delivery_lease::{Admission, Limits as LedgerLimits, Phase, Refusal, Transit};
use sha2::{Digest, Sha256};

/// Three segments, the last one short, so the tree has padding.
const RAW_LEN: usize = 2 * SEG + 5000;
const GATE_WINDOW: Duration = Duration::from_secs(120);

fn honest() -> Body {
    body(1, 10, RAW_LEN)
}

fn with_ledger(change: impl FnOnce(&mut LedgerLimits)) -> StackLimits {
    let mut limits = limits();
    change(&mut limits.ledger);
    limits
}

#[test]
fn the_real_format_passes_the_research_profile() {
    let body = honest();
    assert_eq!(body.frames.len(), 3);
    assert_eq!(body.objects[0].shape.n, 13);
    assert_eq!(body.objects[0].shape.k, 10);
    assert!(usize::from(body.objects[0].shape.s) <= 993);
    assert!(body.raw[..HEADER].iter().all(|byte| *byte == 1));
}

// Forgeries first.

/// Forged chunks under every honest id and index, each with a valid MAC. None takes a slot
/// or leaves a mark, and the honest body comes out whole.
#[test]
fn forged_chunks_come_first_and_the_honest_body_comes_out() {
    let mut world = World::new(limits());
    let (honest, other) = (honest(), body(1, 20, RAW_LEN));

    for (object, rival) in honest.objects.iter().zip(&other.objects) {
        for at in 0..13 {
            let forged = seal(
                &KEY,
                &object.shape,
                &object.object_id,
                at as u16,
                &object.proofs[at],
                &rival.shards[at],
            );
            assert!(matches!(
                world.bridge.take(&mut world.session, &forged, world.now),
                Step::Chunk(Arrival::Invalid(ChunkError::Proof))
            ));
        }
    }
    assert_eq!(world.session.state(), AssemblerState::default());
    assert_eq!(world.stack.ledger().snapshot().live_owners, 0);

    let block = world.whole_body(&honest);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

/// A canonical object can carry a forged frame, and the chunk layer cannot know. The
/// segment layer refuses it, the object is recorded as bad, and the honest frames are other
/// objects that nothing has touched.
#[test]
fn forged_segments_come_first_and_the_honest_body_comes_out() {
    let mut world = World::new(limits());
    let (honest, other) = (honest(), body(1, 20, RAW_LEN));

    for at in 0..honest.frames.len() {
        let forged = carried(&forged_frame(&honest, &other, at));
        assert!(matches!(
            world.object(&forged),
            Handoff::BadContent(FrameError::Proof)
        ));
        assert!(matches!(
            world.chunks(&forged, &[10]),
            Step::Chunk(Arrival::KnownBad)
        ));
    }
    assert_eq!(world.session.state().rejected, 3);
    assert_eq!(world.bridge.buffer().sets(), 0);
    assert_eq!(world.stack.ledger().snapshot().live_owners, 0);

    let block = world.whole_body(&honest);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

// Two bodies of one header.

/// Both are valid here, under their own ids, and they meet nowhere. Only a judge can tell
/// them apart, and this one is a stand-in that knows the answer.
#[test]
fn two_bodies_of_one_header_interleaved_come_out_separately() {
    let mut world = World::new(limits());
    let (honest, rival) = (honest(), body(1, 20, RAW_LEN));
    assert_eq!(honest.key.block_hash, rival.key.block_hash);
    assert_ne!(honest.key.body_id, rival.key.body_id);

    let mut blocks = Vec::new();
    for (mine, theirs) in honest.objects.iter().zip(&rival.objects) {
        let (mine, theirs) = (datagrams(mine), datagrams(theirs));
        for at in 0..13 {
            for frame in [&mine[at], &theirs[at]] {
                match world.bridge.take(&mut world.session, frame, world.now) {
                    Step::Handed(Handoff::Whole(set)) => {
                        blocks.push(world.bridge.assemble(set, world.now).unwrap());
                    }
                    Step::Handed(Handoff::Held(evicted)) => assert!(evicted.is_empty()),
                    Step::Chunk(Arrival::Pending { .. } | Arrival::Spare { .. }) => {}
                    other => panic!("chunk {at}: {other:?}"),
                }
                world.check_ceiling();
            }
        }
    }

    assert_eq!(blocks.len(), 2);
    for block in blocks {
        if *block.block() == honest.raw {
            block.finish(world.now);
        } else {
            assert_eq!(*block.block(), rival.raw);
            block.give_back();
        }
    }
    let ledger = world.stack.ledger();
    assert_eq!(ledger.observe(&honest.key.body_id), Some(Phase::Completed));
    assert_eq!(ledger.observe(&rival.key.body_id), Some(Phase::Released));
    world.settled();
}

// All the way: a wrong body first, through the ingress, the chain and the gate.

fn gate() -> BodyGate {
    BodyGate::new(GateLimits {
        max_calls: 4,
        max_bodies: 2,
        max_blocks: 16,
        window: GATE_WINDOW,
    })
}

fn ingress() -> BodyIngress {
    BodyIngress::new(IngressLimits {
        max_bodies: 2,
        max_headers: 16,
        window: GATE_WINDOW,
    })
}

fn digest(raw: &[u8]) -> Hash {
    Sha256::digest(raw).into()
}

fn forwarded(ingress: &BodyIngress, body: &Body, now: Instant) {
    match ingress.claim(body.key.block_hash, digest(&body.raw), now) {
        Forward::Go(claim) => claim.sent(),
        other => panic!("the body has to get through, got {other:?}"),
    }
}

fn attempt(gate: &BodyGate, body: &Body, now: Instant) -> Attempt {
    match gate.reserve(body.key.block_hash, digest(&body.raw), now) {
        Reservation::Go(attempt) => attempt,
        other => panic!("expected an attempt, got {other:?}"),
    }
}

/// N1 and N2 together. Two strict bodies of one header. The wrong one gets everywhere first,
/// Zebra refuses it, and the right one still goes through the ingress, the chain and the
/// gate. Zebra's answers are written by this test, and this is the model of Ek A section 5.
#[test]
fn a_wrong_body_first_all_the_way_does_not_stop_the_right_one() {
    let mut world = World::new(limits());
    let (gate, ingress) = (gate(), ingress());
    let (wrong, right) = (body(1, 20, RAW_LEN), honest());
    assert_eq!(wrong.key.block_hash, right.key.block_hash);

    forwarded(&ingress, &wrong, world.now);
    let block = world.whole_body(&wrong);
    attempt(&gate, &wrong, world.now).finish(Verdict::Refused, world.now);
    block.give_back();
    assert!(!gate.is_accepted(&wrong.key.block_hash));

    forwarded(&ingress, &right, world.now);
    let block = world.whole_body(&right);
    assert_eq!(*block.block(), right.raw);
    attempt(&gate, &right, world.now).finish(Verdict::Accepted, world.now);
    block.finish(world.now);

    assert!(gate.is_accepted(&right.key.block_hash));
    assert!(matches!(
        gate.reserve(wrong.key.block_hash, digest(&wrong.raw), world.now),
        Reservation::Known
    ));
    world.settled();
}

/// The same with the call lost: no answer, nothing recorded anywhere, and the body comes
/// back from a resend for a second try.
#[test]
fn a_failed_call_gives_the_body_back_for_another_try() {
    let mut world = World::new(limits());
    let gate = gate();
    let right = honest();

    let block = world.whole_body(&right);
    attempt(&gate, &right, world.now).finish(Verdict::Failed, world.now);
    block.give_back();

    let block = world.whole_body(&right);
    assert_eq!(*block.block(), right.raw);
    attempt(&gate, &right, world.now).finish(Verdict::Accepted, world.now);
    block.finish(world.now);

    assert!(gate.is_accepted(&right.key.block_hash));
    world.settled();
}

// The layer below has no room.

/// Refused, room opens, and the body comes out. What was decoded waits on the shelf, so the
/// first segment needs no copy.
#[test]
fn a_refusal_below_is_followed_by_room_and_the_body_comes_out() {
    let mut world = World::new(with_ledger(|ledger| {
        ledger.max_reserved_bytes = 6 * SEG;
    }));
    let honest = honest();
    let ledger = world.stack.ledger().clone();
    let Admission::Admitted(room) = ledger.admit([9; 32], 6 * SEG, world.now) else {
        panic!("expected an admission");
    };

    assert!(matches!(
        world.object(&honest.objects[0]),
        Handoff::Refused(Refusal::Bytes)
    ));
    assert_eq!(world.session.state().rejected, 0);
    assert_eq!(world.stack.budget().used().held_bytes, 0);
    assert_eq!(ledger.observe(&honest.segments[0]), None);

    drop(room);
    assert!(matches!(
        &world.bridge.sweep(&mut world.session, world.now)[..],
        [Handoff::Held(_)]
    ));
    assert_eq!(ledger.observe(&honest.segments[0]), Some(Phase::Held));

    held(world.object(&honest.objects[1]));
    let last = world.object(&honest.objects[2]);
    let block = world.assemble(last);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

/// The same when the shelf could not keep it: the copy does the work.
#[test]
fn a_refusal_below_with_nothing_kept_is_recovered_by_a_resend() {
    let mut world = World::new(with_ledger(|ledger| {
        ledger.max_reserved_bytes = 6 * SEG;
    }));
    let honest = honest();
    let ledger = world.stack.ledger().clone();
    let Admission::Admitted(room) = ledger.admit([9; 32], 6 * SEG, world.now) else {
        panic!("expected an admission");
    };
    assert!(matches!(
        world.object(&honest.objects[0]),
        Handoff::Refused(Refusal::Bytes)
    ));
    drop(room);
    world.later(ASSEMBLY_TTL);
    world.session.expire(world.now);
    assert_eq!(world.session.state().spares, 0);

    let block = world.whole_body(&honest);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

/// A set is evicted for another block's, and comes back from new copies.
#[test]
fn an_evicted_set_is_rebuilt_from_a_resend() {
    let mut limits = limits();
    limits.buffer.max_sets = 1;
    let mut world = World::new(limits);
    let (first, second) = (honest(), body(2, 20, RAW_LEN));
    held(world.object(&first.objects[0]));
    held(world.object(&first.objects[1]));

    let evicted = held(world.object(&second.objects[0]));

    assert_eq!(evicted, vec![first.key.body_id]);
    let ledger = world.stack.ledger().clone();
    assert_eq!(ledger.observe(&first.segments[0]), Some(Phase::Released));
    assert_eq!(
        world
            .bridge
            .interest(&first.objects[0].object_id, world.now),
        Interest::Due
    );

    held(world.object(&second.objects[1]));
    let last = world.object(&second.objects[2]);
    let other = world.assemble(last);
    assert_eq!(*other.block(), second.raw);

    let block = world.whole_body(&first);
    assert_eq!(*block.block(), first.raw);
    block.finish(world.now);
    other.finish(world.now);
    world.settled();
}

// Copies at the same time.

/// Two sessions on two threads decode every object and race to one consumer over a
/// channel. One body comes out, and each object has one delivery and one spare copy.
#[test]
fn concurrent_copies_deliver_one_body() {
    let world = World::new(limits());
    let World {
        stack,
        mut bridge,
        session,
        now,
    } = world;
    let honest = honest();
    let (sender, receiver) = sync_channel::<DecodedObject>(2);
    let (mut blocks, mut held_count, mut copies) = (Vec::new(), 0, 0);

    thread::scope(|scope| {
        for mut session in [session, stack.session().unwrap()] {
            let (sender, honest) = (sender.clone(), &honest);
            scope.spawn(move || {
                for object in &honest.objects {
                    for frame in datagrams(object) {
                        if let Arrival::Decoded(decoded) = session.receive(&frame, now) {
                            sender.send(decoded).unwrap();
                        }
                    }
                }
            });
        }
        drop(sender);
        for decoded in receiver {
            match bridge.deliver(decoded, now) {
                Handoff::Held(_) => held_count += 1,
                Handoff::Whole(set) => blocks.push(bridge.assemble(set, now).unwrap()),
                Handoff::AlreadyHeld(_) => copies += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
    });

    assert_eq!(blocks.len(), 1, "one body");
    assert_eq!(*blocks[0].block(), honest.raw);
    assert_eq!((held_count, copies), (2, 3));
    assert_eq!(stack.budget().used().held_bytes, 0, "and no copy is left");
}

// Old owners.

/// An old block lets go on another thread after a new copy has come in. The new delivery's
/// record stands and the body finishes.
#[test]
fn an_old_owner_letting_go_on_another_thread_leaves_the_new_delivery_alone() {
    let mut world = World::new(limits());
    let honest = honest();
    let mut old = world.whole_body(&honest);
    old.release_segments();
    let (release, wait) = sync_channel::<()>(0);
    let owner = thread::spawn(move || {
        wait.recv().unwrap();
        old.give_back();
    });

    held(world.object(&honest.objects[0]));
    release.send(()).unwrap();
    owner.join().unwrap();

    let ledger = world.stack.ledger().clone();
    assert_eq!(ledger.observe(&honest.segments[0]), Some(Phase::Held));
    assert_eq!(world.bridge.buffer().segments(), 1);

    held(world.object(&honest.objects[1]));
    let last = world.object(&honest.objects[2]);
    let block = world.assemble(last);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

/// `Completed` holds until its time and no longer, whether or not anything else has gone
/// through the ledger to clear it.
#[test]
fn a_completed_body_is_not_wanted_until_its_time_ends() {
    let mut world = World::new(limits());
    let honest = honest();
    let finished = world.whole_body(&honest);
    finished.finish(world.now);

    assert!(matches!(
        world.chunks(&honest.objects[0], &[0]),
        Step::Chunk(Arrival::NotWanted)
    ));

    world.later(COMPLETED_TTL);
    let block = world.whole_body(&honest);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

// Budgets.

/// A sender with the key fills the chunk budget with objects of its own and stops. They
/// give way, and the honest body goes through with no wait.
#[test]
fn the_chunk_budget_cannot_be_held_by_objects_that_stopped() {
    let mut limits = limits();
    limits.budget = BudgetLimits {
        max_objects: 3,
        ..limits.budget
    };
    let mut world = World::new(limits);
    let (honest, own) = (honest(), body(2, 20, 4 * SEG));
    for object in &own.objects[..3] {
        assert!(matches!(
            world.chunks(object, &[0, 1, 2]),
            Step::Chunk(Arrival::Pending { .. })
        ));
    }

    let block = world.whole_body(&honest);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

/// The same below: a consistent body of its own holds the ledger, and with no share an
/// honest segment is refused. The set expires, and the honest body comes out from a resend.
#[test]
fn known_gap_the_ledger_can_be_held_until_a_set_expires() {
    let mut world = World::new(with_ledger(|ledger| {
        ledger.max_reserved_bytes = 6 * SEG;
        ledger.transit = Transit::default();
    }));
    let (honest, own) = (honest(), body(2, 20, 7 * SEG));
    for object in &own.objects[..6] {
        held(world.object(object));
    }

    assert!(matches!(
        world.object(&honest.objects[0]),
        Handoff::Refused(Refusal::Transit)
    ));

    world.later(BUFFER_TTL);
    assert_eq!(world.bridge.expire(world.now).len(), 1);
    let block = world.whole_body(&honest);
    assert_eq!(*block.block(), honest.raw);
    block.finish(world.now);
    world.settled();
}

/// The hand-over makes recovery possible and no more. With no copy nothing comes back,
/// nothing asks for one, and all that is left is that everything was given back.
#[test]
fn known_gap_a_segment_that_never_comes_again_leaves_no_body() {
    let mut world = World::new(limits());
    let honest = honest();
    held(world.object(&honest.objects[0]));
    held(world.object(&honest.objects[1]));

    world.later(BUFFER_TTL);
    assert_eq!(world.bridge.expire(world.now), vec![honest.key]);

    let ledger = world.stack.ledger().clone();
    assert_eq!(ledger.observe(&honest.segments[0]), Some(Phase::Released));
    assert_eq!(ledger.observe(&honest.key.body_id), None, "no body");
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(world.bridge.buffer().sets(), 0);
    world.settled();
}

// Everything comes back.

/// A consumer goes away with segments held, and a channel closes with objects in it.
#[tokio::test]
async fn a_cancelled_consumer_and_a_closed_channel_give_everything_back() {
    let world = World::new(limits());
    let World {
        stack,
        mut bridge,
        mut session,
        now,
    } = world;
    let (budget, ledger) = (stack.budget().clone(), stack.ledger().clone());
    let honest = honest();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<DecodedObject>(4);
    let (told, mut heard) = tokio::sync::mpsc::channel::<()>(4);
    let consumer = tokio::spawn(async move {
        while let Some(object) = receiver.recv().await {
            drop(bridge.deliver(object, now));
            told.send(()).await.unwrap();
        }
    });

    for object in &honest.objects[..2] {
        for frame in &datagrams(object)[..10] {
            if let Arrival::Decoded(decoded) = session.receive(frame, now) {
                sender.send(decoded).await.unwrap();
                heard.recv().await.unwrap();
            }
        }
    }
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEG);

    consumer.abort();
    assert!(consumer.await.unwrap_err().is_cancelled());
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(ledger.snapshot().live_owners, 0);

    let frames = datagrams(&honest.objects[2]);
    let mut last = None;
    for frame in &frames[..10] {
        last = Some(session.receive(frame, now));
    }
    let Some(Arrival::Decoded(decoded)) = last else {
        panic!("expected a decoded object");
    };
    assert!(budget.used().held_bytes > 0);
    assert!(sender.send(decoded).await.is_err(), "the channel closed");

    drop(session);
    assert_eq!(budget.used().held_bytes, 0);
    assert_eq!(budget.used().objects, 0);
    assert_eq!(budget.used().sessions, 0);
}

/// The stack's own constructor is the only way in, and its ceiling covers what it says.
#[test]
fn every_bridge_of_a_stack_shares_its_ledger_and_budget() {
    let limits = limits();
    let stack = Stack::new(KEY, Profile::Research, rules(), limits).unwrap();
    let (first, second) = (stack.bridge().unwrap(), stack.bridge().unwrap());
    assert_eq!(stack.budget().used().sessions, 2);
    assert_eq!(
        stack.ceiling().total_bytes(),
        limits.budget.max_held_bytes
            + limits.budget.max_work_bytes
            + limits.budget.max_spare_bytes
            + limits.ledger.max_reserved_bytes
            + limits.ledger.transit.bytes
    );
    drop((first, second));
    assert_eq!(stack.budget().used().sessions, 0);
}

/// The sender's frames are the ones the tests build their own way.
#[test]
fn a_sender_builds_the_same_frames_as_the_independent_builder() {
    let body = honest();
    let built = delivery_lease::segment_frame::build(&body.raw, &common::bodies::rules());
    assert_eq!(built.as_ref(), Some(&body.frames));
}
