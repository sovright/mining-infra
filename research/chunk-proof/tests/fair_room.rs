//! What a bound segment can declare, and what making room can cost. A sender with the key
//! can open objects of its own, so what it declares has to stay near what it sends, and a
//! place made for a new object must never cost one that is already here.

use std::time::{Duration, Instant};

use chunk_proof::assembler::{Arrival, Assembler, AssemblerLimits, Interest};
use chunk_proof::budget::{Budget, Limits, Refusal};
use chunk_proof::datagram::{ChunkError, Verifier, seal};
use chunk_proof::object::{
    Encoded, MSG_BLOCK, MSG_RAW_SEGMENT, MSG_SKELETON, ObjectError, Profile, Shape, encode,
    held_bytes,
};

const KEY: [u8; 32] = [9; 32];
/// As a node has it for a frame of the largest body.
const MAX_CONTENT: usize = 9926;
const LENGTH: usize = 4000;

fn limits() -> Limits {
    Limits {
        max_sessions: 4,
        max_objects: 2,
        max_held_bytes: 1 << 20,
        max_work_bytes: 1 << 20,
        max_spare_objects: 2,
        max_spare_bytes: 1 << 20,
    }
}

fn session(budget: &Budget) -> Assembler {
    session_up_to(budget, |_| MAX_CONTENT)
}

fn session_up_to(budget: &Budget, max_content: fn(u8) -> usize) -> Assembler {
    let rules = AssemblerLimits {
        max_rejected: 8,
        assembly_ttl: Duration::from_secs(30),
        rejected_ttl: Duration::from_secs(120),
        max_content,
    };
    let verifier = Verifier::new(KEY, Profile::BoundSegment);
    Assembler::new(verifier, budget.clone(), rules).unwrap()
}

fn sized(fill: u8, length: usize) -> Encoded {
    encode(MSG_RAW_SEGMENT, 13, 10, &vec![fill; length]).unwrap()
}

fn object(fill: u8) -> Encoded {
    sized(fill, LENGTH)
}

fn datagram(object: &Encoded, index: usize) -> Vec<u8> {
    seal(
        &KEY,
        &object.shape,
        &object.object_id,
        index as u16,
        &object.proofs[index],
        &object.shards[index],
    )
}

fn feed(session: &mut Assembler, object: &Encoded, chunks: std::ops::Range<usize>, now: Instant) {
    for index in chunks {
        let arrival = session.receive(&datagram(object, index), now);
        assert!(
            matches!(arrival, Arrival::Pending { .. } | Arrival::Spare { .. }),
            "{arrival:?}"
        );
    }
}

fn open_each(session: &mut Assembler, fills: std::ops::Range<u8>, now: Instant) {
    for fill in fills {
        feed(session, &object(fill), 0..1, now);
    }
}

// What a segment can declare.

#[test]
fn the_bound_profile_takes_the_senders_shape_and_no_other() {
    let shape = |msg_type, n, k| Shape {
        msg_type,
        n,
        k,
        s: 900,
    };
    assert!(Profile::BoundSegment.allows(&shape(MSG_RAW_SEGMENT, 13, 10)));
    for other in [
        shape(MSG_RAW_SEGMENT, 256, 227),
        shape(MSG_RAW_SEGMENT, 14, 12),
        shape(MSG_RAW_SEGMENT, 9, 8),
        shape(MSG_RAW_SEGMENT, 2, 1),
        shape(MSG_BLOCK, 13, 10),
        shape(MSG_SKELETON, 13, 10),
    ] {
        assert!(!Profile::BoundSegment.allows(&other), "{other:?}");
    }
}

/// About 200 KB of reservation for one datagram, and a decode of about 53 ms, on the research
/// profile. Nothing of it here.
#[test]
fn a_large_declared_shape_reserves_nothing() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session(&budget);
    let large = encode(MSG_RAW_SEGMENT, 256, 227, &vec![1; 195_000]).unwrap();

    let arrival = session.receive(&datagram(&large, 0), Instant::now());

    assert!(
        matches!(arrival, Arrival::Invalid(ChunkError::Profile)),
        "{arrival:?}"
    );
    assert_eq!(budget.used().objects, 0);
    assert_eq!(budget.used().held_bytes, 0);
}

/// With shards of 502 bytes the shortest content is 5007. This is a limit below what a
/// datagram can carry, and the check does not rest on the datagram's size.
#[test]
fn a_shape_past_max_content_is_refused_before_place() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session_up_to(&budget, |_| 5000);
    let now = Instant::now();

    let arrival = session.receive(&datagram(&sized(1, 5007), 0), now);

    assert!(
        matches!(arrival, Arrival::Refused(Refusal::NeverFits)),
        "{arrival:?}"
    );
    assert_eq!(budget.used().objects, 0);
    assert_eq!(budget.used().held_bytes, 0);
    assert_eq!(session.state().rejected, 0, "a refusal leaves no record");
}

/// A shard of 501 bytes can carry 4997 to 5006 bytes, so only the decode can tell.
#[test]
fn a_shape_that_can_fit_max_content_is_left_to_the_decode() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session_up_to(&budget, |_| 5000);
    let now = Instant::now();
    let past = sized(1, 5006);
    feed(&mut session, &past, 0..9, now);

    let arrival = session.receive(&datagram(&past, 9), now);

    assert!(
        matches!(arrival, Arrival::Rejected(ObjectError::ContentLimit)),
        "{arrival:?}"
    );
}

/// At the research values a shard past the largest frame does not fit in a datagram at all.
#[test]
fn a_shard_past_the_largest_frame_does_not_fit_a_datagram() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session(&budget);

    let arrival = session.receive(&datagram(&sized(1, MAX_CONTENT + 1), 0), Instant::now());

    assert!(
        matches!(arrival, Arrival::Invalid(ChunkError::Size)),
        "{arrival:?}"
    );
    assert_eq!(budget.used().held_bytes, 0);
}

/// The limit stops what no honest frame can be, and a frame at the limit goes through.
#[test]
fn a_frame_at_the_limit_finishes() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let largest = sized(1, MAX_CONTENT);
    feed(&mut session, &largest, 0..9, now);

    let arrival = session.receive(&datagram(&largest, 9), now);

    let Arrival::Decoded(decoded) = arrival else {
        panic!("{arrival:?}");
    };
    assert_eq!(decoded.content().len(), MAX_CONTENT);
}

#[test]
fn one_datagram_cannot_reserve_more_than_its_object_costs() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session(&budget);
    let largest = sized(1, MAX_CONTENT);

    feed(&mut session, &largest, 0..1, Instant::now());

    assert_eq!(budget.used().held_bytes, held_bytes(&largest.shape));
    let sent = usize::from(largest.shape.s);
    assert!(budget.used().held_bytes <= 11 * sent, "{:?}", budget.used());
}

// What making room can cost.

/// As many new objects as there are places on both, and one more. The last is refused and
/// the object that was here finishes.
#[test]
fn a_flood_cannot_push_an_open_object_off_the_shelf() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let honest = object(200);
    feed(&mut session, &honest, 0..2, now);
    open_each(&mut session, 0..3, now);
    assert_eq!(session.have(&honest.object_id), 2, "it is on the shelf");

    let next = session.receive(&datagram(&object(9), 0), now);

    assert!(
        matches!(next, Arrival::Refused(Refusal::Objects)),
        "{next:?}"
    );
    assert_eq!(session.have(&honest.object_id), 2);
    feed(&mut session, &honest, 2..9, now);
    let arrival = session.receive(&datagram(&honest, 9), now);
    assert!(matches!(arrival, Arrival::Decoded(_)), "{arrival:?}");
}

/// Another session's asking is no reason to lose anything.
#[test]
fn an_object_the_shelf_cannot_take_does_not_give_way() {
    let budget = Budget::new(Limits {
        max_spare_bytes: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let honest = object(200);
    feed(&mut session, &honest, 0..4, now);

    assert!(!session.give_way());

    assert_eq!(session.state().open, 1);
    assert_eq!(session.have(&honest.object_id), 4);
}

#[test]
fn a_shelf_that_cannot_take_the_oldest_refuses_the_newcomer() {
    let budget = Budget::new(Limits {
        max_objects: 1,
        max_spare_bytes: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let honest = object(200);
    feed(&mut session, &honest, 0..4, now);

    let next = session.receive(&datagram(&object(9), 0), now);

    assert!(
        matches!(next, Arrival::Refused(Refusal::Objects)),
        "{next:?}"
    );
    assert_eq!(session.have(&honest.object_id), 4);
}

/// A leftover of something somebody has can go. An object that moved here is the only copy
/// of what it holds, so a leftover does not take its place.
#[test]
fn a_leftover_does_not_take_the_place_of_what_moved() {
    let budget = Budget::new(Limits {
        max_objects: 1,
        max_spare_objects: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let moved = object(200);
    feed(&mut session, &moved, 0..3, now);
    open_each(&mut session, 0..1, now);
    assert_eq!(session.state().spares, 1);

    let leftover = object(9);
    let arrival = session.receive_if(&datagram(&leftover, 0), now, |_| Interest::Spare);

    assert!(matches!(arrival, Arrival::NotWanted), "{arrival:?}");
    assert_eq!(session.have(&moved.object_id), 3);
    assert_eq!(session.have(&leftover.object_id), 0);
}

/// Once somebody has it, what moved here is a leftover like any other.
#[test]
fn an_object_somebody_owns_stops_being_the_only_copy() {
    let budget = Budget::new(Limits {
        max_objects: 1,
        max_spare_objects: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let moved = object(200);
    feed(&mut session, &moved, 0..3, now);
    open_each(&mut session, 0..1, now);
    let arrival = session.receive_if(&datagram(&moved, 3), now, |_| Interest::Spare);
    assert!(matches!(arrival, Arrival::Spare { .. }), "{arrival:?}");

    open_each(&mut session, 1..2, now);

    assert_eq!(session.have(&moved.object_id), 0);
}

/// Somebody has it, and the shelf cannot take it: it goes, as nothing is lost with it.
#[test]
fn an_open_object_somebody_owns_goes_if_the_shelf_cannot_take_it() {
    let budget = Budget::new(Limits {
        max_spare_bytes: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let owned = object(200);
    feed(&mut session, &owned, 0..9, now);

    let arrival = session.receive_if(&datagram(&owned, 9), now, |_| Interest::Spare);

    assert!(matches!(arrival, Arrival::NotWanted), "{arrival:?}");
    assert_eq!(session.state().open, 0);
    assert_eq!(budget.used().objects, 0);
}

/// What the layer below had no room for is the only copy here, and it stays too.
#[test]
fn a_new_object_does_not_take_the_place_of_decoded_content() {
    let budget = Budget::new(Limits {
        max_objects: 1,
        max_spare_objects: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let whole = object(200);
    feed(&mut session, &whole, 0..9, now);
    let arrival = session.receive(&datagram(&whole, 9), now);
    let Arrival::Decoded(decoded) = arrival else {
        panic!("{arrival:?}");
    };
    assert!(session.shelve_decoded(decoded, now));
    open_each(&mut session, 0..1, now);

    let next = session.receive(&datagram(&object(9), 0), now);

    assert!(
        matches!(next, Arrival::Refused(Refusal::Objects)),
        "{next:?}"
    );
    let again = session.receive_if(&datagram(&whole, 0), now, |_| Interest::Due);
    assert!(matches!(again, Arrival::Decoded(_)), "{again:?}");
}

/// Rule 9 stands: a true leftover still goes for an object that has to move.
#[test]
fn a_leftover_gives_way_to_what_has_to_move() {
    let budget = Budget::new(Limits {
        max_objects: 1,
        max_spare_objects: 1,
        ..limits()
    })
    .unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let leftover = object(200);
    let arrival = session.receive_if(&datagram(&leftover, 0), now, |_| Interest::Spare);
    assert!(matches!(arrival, Arrival::Spare { .. }), "{arrival:?}");
    let stopped = object(201);
    feed(&mut session, &stopped, 0..2, now);

    feed(&mut session, &object(202), 0..1, now);

    assert_eq!(session.have(&leftover.object_id), 0);
    assert_eq!(session.have(&stopped.object_id), 2);
}

/// Decoding takes bytes for a moment and no open place, so with every place taken an object
/// that has all its shards costs nobody anything.
#[test]
fn an_object_that_finishes_on_a_full_shelf_moves_nothing() {
    let budget = Budget::new(limits()).unwrap();
    let mut session = session(&budget);
    let now = Instant::now();
    let whole = object(200);
    let neighbour = object(0);
    feed(&mut session, &whole, 0..9, now);
    open_each(&mut session, 0..3, now);
    assert_eq!(session.state().open, 2);
    assert_eq!(session.state().spares, 2);

    let arrival = session.receive(&datagram(&whole, 9), now);

    assert!(matches!(arrival, Arrival::Decoded(_)), "{arrival:?}");
    assert_eq!(session.state().open, 2);
    assert_eq!(session.state().spares, 1);
    assert_eq!(session.have(&neighbour.object_id), 1);
}
