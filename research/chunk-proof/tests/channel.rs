//! A bounded channel to a consumer, under the same owners and the same shelf: full, closed,
//! and dropped with a block in it. This is the rule on its own, with the real channel type.
//! What the real client and sidecar do is tested on those, in the workspace.

mod common;

use std::time::Duration;

use chunk_proof::handoff::{Handoff, Step};
use common::bodies::{Body, SEG, body};
use common::datagrams;
use common::world::{BUFFER_TTL, World, limits};
use delivery_lease::Phase;
use delivery_lease::body_buffer::AssembledBlock;
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};

type Block = AssembledBlock<Vec<u8>>;

fn pump(world: &mut World, tx: &Sender<Block>) {
    while world.bridge.waiting() > 0 {
        match tx.try_reserve() {
            Ok(permit) => permit.send(world.bridge.next_block(world.now).unwrap().unwrap()),
            Err(TrySendError::Full(())) => return,
            Err(TrySendError::Closed(())) => {
                world.bridge.abandon_waiting();
                return;
            }
        }
    }
}

fn one(world: &mut World, body: &Body, tx: &Sender<Block>) {
    match world.object(&body.objects[0]) {
        Handoff::Whole(set) => world.bridge.wait_for_consumer(set, world.now),
        other => panic!("expected a whole set, got {other:?}"),
    }
    pump(world, tx);
}

fn phase(world: &World, body: &Body) -> Option<Phase> {
    world.stack.ledger().phase_at(&body.segments[0], world.now)
}

fn one_segment(fill: u8) -> Body {
    body(fill, fill, 5000)
}

fn channel(room: usize) -> (Sender<Block>, Receiver<Block>) {
    mpsc::channel(room)
}

#[test]
fn a_full_channel_keeps_the_block_and_its_reservations() {
    let mut world = World::new(limits());
    let (tx, mut rx) = channel(1);
    let (first, second) = (one_segment(1), one_segment(2));
    one(&mut world, &first, &tx);
    let reserved = world.stack.ledger().snapshot().reserved_bytes;

    one(&mut world, &second, &tx);

    assert_eq!(world.bridge.waiting(), 1);
    assert_eq!(phase(&world, &second), Some(Phase::Held));
    assert!(world.stack.ledger().snapshot().reserved_bytes > reserved);

    rx.try_recv().unwrap().finish(world.now);
    pump(&mut world, &tx);
    assert_eq!(world.bridge.waiting(), 0);
    let block = rx.try_recv().unwrap();
    assert_eq!(*block.block(), second.raw);
    block.finish(world.now);
    world.settled();
}

/// A copy while it waits is a copy of something owned, so there is no second delivery.
#[test]
fn a_copy_of_a_waiting_block_delivers_nothing() {
    let mut world = World::new(limits());
    let (tx, _rx) = channel(1);
    let (first, second) = (one_segment(1), one_segment(2));
    one(&mut world, &first, &tx);
    one(&mut world, &second, &tx);

    let frames = datagrams(&second.objects[0]);
    for frame in &frames {
        let step = world.bridge.take(&mut world.session, frame, world.now);
        assert!(!matches!(step, Step::Handed(Handoff::Whole(_))), "{step:?}");
    }

    assert_eq!(world.bridge.waiting(), 1);
}

/// What pushes back through a full channel: new segments are refused for room and keep on
/// the shelf, and once the channel moves the next sweep takes them with no copy and no
/// second decode.
#[test]
fn what_arrives_behind_a_full_channel_waits_on_the_shelf() {
    let mut limits = limits();
    limits.ledger.max_reserved_bytes = 2 * SEG;
    limits.ledger.transit.bytes = 0;
    limits.ledger.transit.owners = 0;
    limits.ledger.transit.records = 0;
    let mut world = World::new(limits);
    let (tx, mut rx) = channel(1);
    let (first, second, third) = (one_segment(1), one_segment(2), one_segment(3));
    one(&mut world, &first, &tx);
    one(&mut world, &second, &tx);

    let refused = world.object(&third.objects[0]);
    assert!(matches!(refused, Handoff::Refused(_)), "{refused:?}");
    assert_eq!(world.session.state().spares, 1);

    rx.try_recv().unwrap().finish(world.now);
    pump(&mut world, &tx);
    rx.try_recv().unwrap().finish(world.now);

    let mut swept = world.bridge.sweep(&mut world.session, world.now);
    match swept.pop() {
        Some(Handoff::Whole(set)) => world.bridge.wait_for_consumer(set, world.now),
        other => panic!("expected the shelf to give the set back, got {other:?}"),
    }
    pump(&mut world, &tx);
    let block = rx.try_recv().unwrap();
    assert_eq!(*block.block(), third.raw);
    block.finish(world.now);
    world.settled();
}

#[test]
fn a_closed_channel_gives_everything_back_and_lets_a_copy_in() {
    let mut world = World::new(limits());
    let (tx, rx) = channel(1);
    let (first, second) = (one_segment(1), one_segment(2));
    one(&mut world, &first, &tx);
    one(&mut world, &second, &tx);

    // With a block still in it, and one more waiting.
    drop(rx);
    pump(&mut world, &tx);

    assert_eq!(world.bridge.waiting(), 0);
    assert_eq!(world.stack.ledger().snapshot().reserved_bytes, 0);
    assert_eq!(phase(&world, &first), Some(Phase::Released));
    assert_eq!(phase(&world, &second), Some(Phase::Released));

    let (tx, mut rx) = channel(1);
    one(&mut world, &second, &tx);
    let block = rx.try_recv().unwrap();
    assert_eq!(*block.block(), second.raw);
    block.finish(world.now);
    world.settled();
}

#[test]
fn a_block_dropped_by_the_consumer_goes_the_same_way() {
    let mut world = World::new(limits());
    let (tx, mut rx) = channel(1);
    let first = one_segment(1);
    one(&mut world, &first, &tx);

    drop(rx.try_recv().unwrap());

    assert_eq!(world.stack.ledger().snapshot().reserved_bytes, 0);
    assert_eq!(phase(&world, &first), Some(Phase::Released));
}

/// A consumer that never comes back must not hold reservations for good.
#[test]
fn a_block_that_waits_past_the_buffers_time_gives_them_back() {
    let mut world = World::new(limits());
    let (tx, _rx) = channel(1);
    let (first, second) = (one_segment(1), one_segment(2));
    one(&mut world, &first, &tx);
    one(&mut world, &second, &tx);

    world.later(BUFFER_TTL - Duration::from_secs(1));
    world.bridge.expire(world.now);
    assert_eq!(world.bridge.waiting(), 1, "one second short");

    world.later(Duration::from_secs(1));
    world.bridge.expire(world.now);
    assert_eq!(world.bridge.waiting(), 0);
    assert_eq!(phase(&world, &second), Some(Phase::Released));
}

/// Dropped on the sender's side, as a cancelled task drops it, with a set waiting. Every
/// counter comes back. A block already in the channel is the receiver's until it goes too.
#[test]
fn a_cancelled_sender_leaves_nothing_counted() {
    let mut world = World::new(limits());
    let (tx, rx) = channel(1);
    let (first, second) = (one_segment(1), one_segment(2));
    one(&mut world, &first, &tx);
    one(&mut world, &second, &tx);
    drop(rx);
    drop(tx);
    world.settled();
}

/// Decoded content waiting on the shelf needs a normal place for a moment on its way down,
/// and objects that stopped are not in its way.
#[test]
fn objects_that_stopped_do_not_keep_a_decoded_spare_on_the_shelf() {
    let mut limits = limits();
    limits.budget.max_objects = 2;
    limits.ledger.max_reserved_bytes = 2 * SEG;
    limits.ledger.transit.bytes = 0;
    limits.ledger.transit.owners = 0;
    limits.ledger.transit.records = 0;
    let mut world = World::new(limits);
    let (tx, mut rx) = channel(1);
    let (first, second, third) = (one_segment(1), one_segment(2), one_segment(3));
    one(&mut world, &first, &tx);
    one(&mut world, &second, &tx);
    let refused = world.object(&third.objects[0]);
    assert!(matches!(refused, Handoff::Refused(_)), "{refused:?}");
    for fill in [4, 5] {
        world.chunks(&one_segment(fill).objects[0], &[0]);
    }
    assert_eq!(world.session.state().open, 2, "every normal place is taken");

    rx.try_recv().unwrap().finish(world.now);
    pump(&mut world, &tx);
    rx.try_recv().unwrap().finish(world.now);

    let mut swept = world.bridge.sweep(&mut world.session, world.now);
    assert!(matches!(swept.pop(), Some(Handoff::Whole(_))));
}
