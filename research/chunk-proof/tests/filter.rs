//! What to do with chunks of an object that has already been decoded. Four ways over the
//! same counter-examples, and then the chosen one on its own.
//!
//! The numbers here describe these arrangements and nothing else. They are no loss rate
//! of any network. All four ways run on the assembler's rule 6, under which an object that
//! stopped gives up its place, so all four deliver the load and leave room for a new
//! object. Before that rule the other three did neither. What still differs is whether an
//! object can come back after its owner goes.
//!
//! Two claims stay apart. No second delivery is `Intake`'s doing and holds for all four.
//! Whether a lost copy can be replaced is what differs.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::thread;

use chunk_proof::assembler::{Arrival, AssemblerState, Interest};
use chunk_proof::budget::Used;
use chunk_proof::datagram::{ChunkError, seal};
use chunk_proof::handoff::{Handoff, Step};
use chunk_proof::object::{Encoded, held_bytes};
use common::bodies::{Body, SEG, body};
use common::world::{BUFFER_TTL, COMPLETED_TTL, World, held, limits};
use common::{ASSEMBLY_TTL, KEY, datagrams};
use delivery_lease::body_buffer::{ACTIVE_SET, CompleteSet};
use delivery_lease::{Admission, Phase, Ticket};

const RAW_LEN: usize = 2 * SEG;
const CHUNKS: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    /// Turn away what an owner holds, and let the rest take a normal place.
    Drop,
    /// No check at all.
    Open,
    /// Check only before paying for a decode. Normal places stay held meanwhile.
    AtFinish,
    /// Spares go to a bounded shelf.
    Shelf,
}

const WAYS: [Way; 4] = [Way::Drop, Way::Open, Way::AtFinish, Way::Shelf];

fn two_segments(fill: u8) -> Body {
    body(1, fill, RAW_LEN)
}

/// One chunk, the given way. `position` is how many chunks of this burst came before it.
fn send(world: &mut World, way: Way, object: &Encoded, position: usize) -> Option<Handoff> {
    let now = world.now;
    let frame = &datagrams(object)[position];
    let arrival = match way {
        Way::Shelf => {
            return match world.bridge.take(&mut world.session, frame, now) {
                Step::Handed(handoff) => Some(handoff),
                Step::Chunk(_) => None,
            };
        }
        Way::Drop => {
            let bridge = &world.bridge;
            world
                .session
                .receive_if(frame, now, |id| match bridge.interest(id, now) {
                    Interest::Spare => Interest::Done,
                    Interest::Due => Interest::New,
                    other => other,
                })
        }
        Way::Open => world.session.receive(frame, now),
        Way::AtFinish => {
            let owned = world.bridge.interest(&object.object_id, now) == Interest::Spare;
            if owned && world.session.have(&object.object_id) == 9 {
                return None;
            }
            world.session.receive(frame, now)
        }
    };
    match arrival {
        Arrival::Decoded(decoded) => Some(world.bridge.deliver(decoded, now)),
        _ => None,
    }
}

fn objects_of_one_segment(count: u8) -> Vec<Encoded> {
    (0..count)
        .map(|at| body(at + 1, at, 5000).objects.remove(0))
        .collect()
}

/// Counter-example 1: an object is sent again while its owner lives, and the owner is
/// evicted after `gone_after` of the chunks. Is the object back at the end?
fn back_after_eviction(way: Way, gone_after: usize) -> bool {
    let (first, other) = (two_segments(10), body(2, 20, RAW_LEN));
    let mut limits = limits();
    limits.buffer.max_sets = 1;
    let mut world = World::new(limits);
    held(world.object(&first.objects[0]));

    for position in 0..gone_after {
        send(&mut world, way, &first.objects[0], position);
    }
    // A set still arriving is never given up, so the first has gone quiet.
    world.later(ACTIVE_SET);
    held(world.object(&other.objects[0]));
    // And the other has gone quiet by the time the first comes back.
    world.later(ACTIVE_SET);
    assert_eq!(
        world.stack.ledger().observe(&first.segments[0]),
        Some(Phase::Released)
    );
    if way == Way::Shelf {
        world.bridge.sweep(&mut world.session, world.now);
    }
    for position in gone_after..CHUNKS {
        send(&mut world, way, &first.objects[0], position);
    }
    world.stack.ledger().observe(&first.segments[0]) == Some(Phase::Held)
}

/// Counter-example 2: steady traffic and no attacker. Every object's 13 chunks arrive, so
/// 3 are left over, and there are 8 normal places.
fn delivered_under_load(way: Way) -> usize {
    let mut limits = limits();
    limits.budget.max_objects = 8;
    limits.ledger.max_reserved_bytes = 32 * SEG;
    let mut world = World::new(limits);
    let mut sets: Vec<CompleteSet> = Vec::new();

    for object in &objects_of_one_segment(20) {
        for position in 0..CHUNKS {
            if let Some(Handoff::Whole(set)) = send(&mut world, way, object, position) {
                sets.push(set);
            }
        }
    }
    sets.len()
}

/// Counter-example 3: no attacker. The layer below is full for a moment, 12 objects decode
/// and are refused, and room opens. Does the next new object get in?
fn new_object_after_a_full_moment(way: Way) -> bool {
    let mut limits = limits();
    limits.budget.max_objects = 8;
    limits.ledger.max_reserved_bytes = 2 * SEG;
    let mut world = World::new(limits);
    let room = match world.stack.ledger().admit([9; 32], 2 * SEG, world.now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    };

    for object in &objects_of_one_segment(12) {
        for position in 0..CHUNKS {
            send(&mut world, way, object, position);
        }
    }
    drop(room);

    let fresh = body(200, 200, 5000);
    let mut result = None;
    for position in 0..10 {
        result = send(&mut world, way, &fresh.objects[0], position);
    }
    matches!(result, Some(Handoff::Whole(_)))
}

#[test]
fn every_way_on_the_same_counter_examples() {
    println!("yol        tahliye/14  yuk/20  dolu-an");
    let mut table = Vec::new();
    for way in WAYS {
        let back = (0..=CHUNKS)
            .filter(|gone_after| back_after_eviction(way, *gone_after))
            .count();
        let load = delivered_under_load(way);
        let fresh = new_object_after_a_full_moment(way);
        println!("{way:10?} {back:10}  {load:6}  {fresh}");
        table.push((way, back, load, fresh));
    }

    assert_eq!(
        table,
        [
            (Way::Drop, 4, 20, true),
            (Way::Open, 10, 20, true),
            (Way::AtFinish, 13, 20, true),
            (Way::Shelf, 14, 20, true),
        ]
    );
}

// The shelf on its own.

/// The same recovery when the owner goes on another thread, and the only thing that
/// notices is the next look over the shelf.
#[test]
fn an_owner_going_on_another_thread_is_found_by_the_next_sweep() {
    let body = two_segments(10);
    let mut world = World::new(limits());
    let block = world.whole_body(&body);
    let (release, wait) = sync_channel::<()>(0);
    let owner = thread::spawn(move || {
        wait.recv().unwrap();
        block.give_back();
    });

    for position in 0..CHUNKS {
        send(&mut world, Way::Shelf, &body.objects[0], position);
    }
    assert_eq!(world.session.state().spares, 1);
    assert!(world.bridge.sweep(&mut world.session, world.now).is_empty());

    release.send(()).unwrap();
    owner.join().unwrap();

    let back = world.bridge.sweep(&mut world.session, world.now);
    assert!(matches!(&back[..], [Handoff::Held(_)]));
    assert_eq!(
        world.stack.ledger().observe(&body.segments[0]),
        Some(Phase::Held)
    );
}

fn owner_of(world: &World, segment: [u8; 32]) -> Ticket {
    match world.stack.ledger().admit(segment, 0, world.now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    }
}

/// The race on real threads. An owner lets go while this thread keeps asking. A "someone
/// has it" read after the release had finished would be a wrong answer, and never happens.
#[test]
fn an_owner_letting_go_on_another_thread_is_seen_by_the_next_read() {
    const ROUNDS: usize = 2000;
    let body = two_segments(10);
    let mut limits = limits();
    limits.ledger.repeat_budget = u32::MAX;
    let mut world = World::new(limits);
    held(world.object(&body.objects[0]));
    world.later(BUFFER_TTL);
    world.bridge.expire(world.now);
    let object = body.objects[0].object_id;

    let mut seen_held = 0;
    for _ in 0..ROUNDS {
        let owner = owner_of(&world, body.segments[0]);
        let released = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                drop(owner);
                released.store(true, Ordering::SeqCst);
            });
            loop {
                let already = released.load(Ordering::SeqCst);
                let interest = world.bridge.interest(&object, world.now);
                assert!(
                    !already || interest == Interest::Due,
                    "a stale answer after the owner had gone"
                );
                seen_held += usize::from(interest == Interest::Spare);
                if already {
                    break;
                }
            }
        });
    }
    assert!(seen_held > 0, "the race was never run");
}

/// Every way an owner can go, and what the next chunk finds.
#[test]
fn a_copy_after_the_owner_has_gone_is_taken_however_it_went() {
    let body = two_segments(10);
    let object = body.objects[0].object_id;

    let mut world = World::new(limits());
    held(world.object(&body.objects[0]));
    world.later(BUFFER_TTL);
    world.bridge.expire(world.now);
    assert_eq!(world.bridge.interest(&object, world.now), Interest::Due);
    held(world.object(&body.objects[0]));

    let mut evicting = limits();
    evicting.buffer.max_sets = 1;
    let mut world = World::new(evicting);
    held(world.object(&body.objects[0]));
    world.later(ACTIVE_SET);
    held(world.object(&two_segments(20).objects[0]));
    world.later(ACTIVE_SET);
    assert_eq!(world.bridge.interest(&object, world.now), Interest::Due);
    held(world.object(&body.objects[0]));

    let mut world = World::new(limits());
    let mut block = world.whole_body(&body);
    block.release_segments();
    assert_eq!(world.bridge.interest(&object, world.now), Interest::Due);
    held(world.object(&body.objects[0]));

    let mut world = World::new(limits());
    let block = world.whole_body(&body);
    thread::spawn(move || block.give_back()).join().unwrap();
    assert_eq!(world.bridge.interest(&object, world.now), Interest::Due);
    held(world.object(&body.objects[0]));

    let mut world = World::new(limits());
    world.whole_body(&body).finish(world.now);
    assert_eq!(world.bridge.interest(&object, world.now), Interest::Done);
    world.later(COMPLETED_TTL);
    assert_eq!(world.bridge.interest(&object, world.now), Interest::Due);
    held(world.object(&body.objects[0]));
}

/// A decode from the shelf can lose to another session. It is a late result like any
/// other: nothing is delivered twice and the delivery that won is untouched.
#[test]
fn a_late_decode_from_the_shelf_leaves_a_new_delivery_alone() {
    let body = two_segments(10);
    let mut world = World::new(limits());
    held(world.object(&body.objects[0]));
    for position in 0..CHUNKS {
        send(&mut world, Way::Shelf, &body.objects[0], position);
    }
    world.later(BUFFER_TTL);
    world.bridge.expire(world.now);

    let mut other = world.stack.session().unwrap();
    let frames = datagrams(&body.objects[0]);
    let mut last = None;
    for frame in &frames[..10] {
        last = Some(other.receive(frame, world.now));
    }
    let Some(Arrival::Decoded(decoded)) = last else {
        panic!("expected a decoded object");
    };
    held(world.bridge.deliver(decoded, world.now));

    let frozen = world.stack.ledger().snapshot();
    assert!(world.bridge.sweep(&mut world.session, world.now).is_empty());
    assert_eq!(world.session.state().spares, 1, "it stays a spare");

    assert_eq!(world.stack.ledger().snapshot(), frozen);
    assert_eq!(world.bridge.buffer().segments(), 1);
    assert_eq!(
        world.stack.ledger().observe(&body.segments[0]),
        Some(Phase::Held)
    );
}

#[test]
fn spares_of_a_finished_object_go_at_the_next_sweep() {
    let body = two_segments(10);
    let mut world = World::new(limits());
    let block = world.whole_body(&body);
    for position in 0..CHUNKS {
        send(&mut world, Way::Shelf, &body.objects[0], position);
    }
    assert_eq!(world.session.state().spares, 1);

    block.finish(world.now);
    assert!(world.bridge.sweep(&mut world.session, world.now).is_empty());

    assert_eq!(world.session.state().spares, 0);
    assert_eq!(world.stack.budget().used().spare_bytes, 0);
}

/// A spare whose decode cannot start stays where it is and is tried again.
#[test]
fn a_spare_that_cannot_get_a_decode_budget_waits_on_the_shelf() {
    let body = two_segments(10);
    let mut world = World::new(limits());
    held(world.object(&body.objects[0]));
    for position in 0..CHUNKS {
        send(&mut world, Way::Shelf, &body.objects[0], position);
    }
    world.later(BUFFER_TTL);
    world.bridge.expire(world.now);

    let max = world.stack.budget().limits().max_work_bytes;
    let elsewhere = world.stack.budget().work(max).unwrap();
    assert!(world.bridge.sweep(&mut world.session, world.now).is_empty());
    assert_eq!(world.session.state().spares, 1);

    drop(elsewhere);
    let back = world.bridge.sweep(&mut world.session, world.now);
    assert!(matches!(&back[..], [Handoff::Held(_)]));
}

/// Only verified chunks get there, and nothing can claim a slot in an honest spare.
#[test]
fn a_forged_chunk_never_reaches_the_shelf() {
    let (honest, other) = (two_segments(10), two_segments(20));
    let mut world = World::new(limits());
    held(world.object(&honest.objects[0]));
    let object = &honest.objects[0];
    let forged = seal(
        &KEY,
        &object.shape,
        &object.object_id,
        11,
        &object.proofs[11],
        &other.objects[0].shards[11],
    );

    assert!(matches!(
        world.bridge.take(&mut world.session, &forged, world.now),
        Step::Chunk(Arrival::Invalid(ChunkError::Proof))
    ));

    assert_eq!(world.session.state().spares, 0);
    assert_eq!(world.stack.budget().used().spare_bytes, 0);
}

/// Pressure on the shelf: the oldest spare goes, the counters hold at every step, and no
/// new object is refused for it. The object that lost its spare needs a copy.
#[test]
fn a_full_shelf_gives_up_its_oldest_spare_and_nothing_else() {
    let mut limits = limits();
    limits.budget.max_spare_objects = 2;
    limits.ledger.max_reserved_bytes = 64 * SEG;
    let mut world = World::new(limits);
    let objects = objects_of_one_segment(6);
    let mut sets = Vec::new();

    for object in &objects {
        for position in 0..CHUNKS {
            if let Some(Handoff::Whole(set)) = send(&mut world, Way::Shelf, object, position) {
                sets.push(set);
            }
            let used = world.stack.budget().used();
            assert!(used.spare_objects <= 2, "{used:?}");
            assert!(used.objects <= 32, "{used:?}");
        }
    }

    assert_eq!(sets.len(), 6, "every new object got in");
    assert_eq!(world.session.state().spares, 2);
    assert_eq!(world.session.state().open, 0);
    let have = |at: usize| world.session.have(&objects[at].object_id);
    assert_eq!((have(0), have(3)), (0, 0), "the oldest went");
    assert_eq!((have(4), have(5)), (3, 3), "the newest stayed");
}

/// The byte limit on its own, with places to spare. A new object's spares push the oldest
/// out once the bytes run short.
#[test]
fn the_shelf_keeps_to_its_byte_limit_as_objects_arrive() {
    let objects = objects_of_one_segment(6);
    let shape = objects[0].shape;
    let shard = usize::from(shape.s);
    let spare = held_bytes(&shape) - 7 * shard;
    let mut limits = limits();
    // Three objects' spares fit, and the first shard of a fourth does not.
    limits.budget.max_spare_bytes = 3 * spare + shard / 2;
    assert!(limits.budget.max_spare_bytes >= held_bytes(&shape));
    limits.ledger.max_reserved_bytes = 64 * SEG;
    let mut world = World::new(limits);
    let mut sets = Vec::new();

    for object in &objects {
        for position in 0..CHUNKS {
            if let Some(Handoff::Whole(set)) = send(&mut world, Way::Shelf, object, position) {
                sets.push(set);
            }
            world.check_ceiling();
        }
    }

    assert_eq!(sets.len(), 6);
    assert_eq!(
        world.session.have(&objects[0].object_id),
        0,
        "the oldest went"
    );
    assert_eq!(
        world.session.have(&objects[5].object_id),
        3,
        "the newest stayed"
    );
}

/// The same when one object grows: another object's spares go before the limit does.
#[test]
fn a_growing_spare_keeps_to_the_byte_limit_too() {
    let objects = objects_of_one_segment(2);
    let (first, second) = (&objects[0], &objects[1]);
    let mut limits = limits();
    limits.budget.max_spare_bytes = held_bytes(&first.shape);
    let mut world = World::new(limits);
    let mut sets = Vec::new();
    for object in [first, second] {
        for position in 0..10 {
            if let Some(Handoff::Whole(set)) = send(&mut world, Way::Shelf, object, position) {
                sets.push(set);
            }
        }
    }

    for position in 10..CHUNKS {
        send(&mut world, Way::Shelf, second, position);
        world.check_ceiling();
    }
    assert_eq!(world.session.have(&second.object_id), 3);
    for position in 0..10 {
        send(&mut world, Way::Shelf, first, position);
        world.check_ceiling();
    }

    assert_eq!(world.session.have(&first.object_id), 10);
    assert_eq!(world.session.have(&second.object_id), 0, "it made the room");
    drop(sets);
}

/// A sender with the key can push honest spares off the shelf. The object is then where it
/// would be with no shelf: it needs a copy. This budget is really used up, and no delivery
/// is promised.
#[test]
fn known_gap_a_spare_pushed_off_a_full_shelf_is_gone() {
    let mut limits = limits();
    limits.budget.max_spare_objects = 1;
    limits.buffer.max_sets = 2;
    let mut world = World::new(limits);
    let (honest, own) = (two_segments(10), body(2, 20, RAW_LEN));
    held(world.object(&honest.objects[0]));
    held(world.object(&own.objects[0]));

    send(&mut world, Way::Shelf, &honest.objects[0], 10);
    assert_eq!(world.session.state().spares, 1);
    send(&mut world, Way::Shelf, &own.objects[0], 10);
    assert_eq!(world.session.state().spares, 1);

    world.later(BUFFER_TTL);
    world.bridge.expire(world.now);
    assert!(world.bridge.sweep(&mut world.session, world.now).is_empty());
    assert_eq!(
        world.stack.ledger().observe(&honest.segments[0]),
        Some(Phase::Released)
    );
}

#[test]
fn spares_expire_and_give_their_bytes_back() {
    let body = two_segments(10);
    let mut world = World::new(limits());
    held(world.object(&body.objects[0]));
    send(&mut world, Way::Shelf, &body.objects[0], 10);
    assert_ne!(world.stack.budget().used().spare_bytes, 0);

    world.later(ASSEMBLY_TTL);
    world.session.expire(world.now);

    assert_eq!(world.session.state(), AssemblerState::default());
    let used = world.stack.budget().used();
    assert_eq!(
        used,
        Used {
            sessions: 2,
            ..Used::default()
        }
    );
}

/// With no copy at all, no shelf brings anything back.
#[test]
fn known_gap_with_no_copy_there_is_nothing_to_keep() {
    let body = two_segments(10);
    let mut world = World::new(limits());
    held(world.object(&body.objects[0]));

    world.later(BUFFER_TTL);
    world.bridge.expire(world.now);

    assert!(world.bridge.sweep(&mut world.session, world.now).is_empty());
    assert_eq!(world.bridge.buffer().sets(), 0);
}

/// Objects of one segment each, every one decoded and given up before the next, so each
/// carried fact is the only trace of its object.
fn delivered_and_finished(world: &mut World, objects: &[Encoded]) {
    for object in objects {
        for at in 0..10 {
            if let Step::Handed(handoff) = world.chunks(object, &[at]) {
                let block = world.assemble(handoff);
                block.give_back();
            }
        }
    }
}

#[test]
fn leftovers_of_forgotten_objects_leave_room_for_the_next_honest_object() {
    let mut limits = limits();
    limits.budget.max_objects = 4;
    limits.max_carried = 2;
    let mut world = World::new(limits);
    let objects = objects_of_one_segment(9);
    let (old, rest) = objects.split_at(6);
    let (recent, next) = rest.split_at(2);
    delivered_and_finished(&mut world, old);
    delivered_and_finished(&mut world, recent);

    // The last parity of each object, from a path that ran late. Only the last two are
    // still known, so the rest ask for a normal place.
    for object in old.iter().take(4) {
        world.chunks(object, &[12]);
    }
    assert_eq!(world.session.state().open, 4, "the normal places are full");

    let frames = datagrams(&next[0]);
    let mut handed = None;
    for frame in &frames[..10] {
        match world.bridge.take(&mut world.session, frame, world.now) {
            Step::Handed(handoff) => handed = Some(handoff),
            Step::Chunk(Arrival::Pending { .. }) => {}
            Step::Chunk(other) => panic!("the honest object was turned away: {other:?}"),
        }
    }
    assert!(matches!(handed, Some(Handoff::Whole(_))), "{handed:?}");
}
