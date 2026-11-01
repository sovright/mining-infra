//! Verification in front of the buffer, and the ledger and the buffer working together.
//! The judge is a stand-in, not a node or a gate.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant};

use common::{Body, SEGMENT, body, frame, levels, padded_body, proof, rules, sized};
use delivery_lease::body_buffer::{
    AssembledBlock, AssemblyError, BodyBuffer, BufferLimits, Reject,
};
use delivery_lease::intake::{Intake, Offer, Step, into_complete};
use delivery_lease::segment_frame::{FrameError, segment_leaf, verify};
use delivery_lease::{
    Admission, DeliveryLedger, Limits, Phase, Refusal, Snapshot, Ticket, Transit,
};
use tokio::sync::{mpsc, oneshot};

fn limits() -> Limits {
    Limits {
        max_records: 64,
        max_live_owners: 64,
        max_reserved_bytes: 64 * SEGMENT,
        repeat_budget: 2,
        completed_ttl: Duration::from_secs(300),
        released_ttl: Duration::from_secs(86_400),
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
        ttl: Duration::from_secs(120),
    }
}

fn intake_with(limits: Limits, buffer: BufferLimits) -> (DeliveryLedger, Intake) {
    let ledger = DeliveryLedger::new(limits);
    let intake = Intake::new(ledger.clone(), BodyBuffer::new(buffer).unwrap(), rules());
    (ledger, intake)
}

fn intake() -> (DeliveryLedger, Intake) {
    intake_with(limits(), buffer_limits())
}

fn bytes_limit(segments: usize) -> Limits {
    Limits {
        max_reserved_bytes: segments * SEGMENT,
        ..limits()
    }
}

fn id(body: &Body, index: usize) -> [u8; 32] {
    verify(&body.frames[index], &rules()).unwrap().ledger_key()
}

fn phase(ledger: &DeliveryLedger, body: &Body, index: usize) -> Option<Phase> {
    ledger.observe(&id(body, index))
}

fn take(intake: &mut Intake, body: &Body, index: usize, now: Instant) -> Vec<[u8; 32]> {
    match intake.receive(&body.frames[index], now) {
        Offer::Taken(insertion) => insertion.evicted.iter().map(|key| key.body_id).collect(),
        other => panic!("expected the segment to be taken, got {other:?}"),
    }
}

fn whole(intake: &mut Intake, body: &Body, now: Instant) -> AssembledBlock<Vec<u8>> {
    take(intake, body, 0, now);
    let offer = intake.receive(&body.frames[1], now);
    let set = into_complete(offer).expect("the second segment finishes the set");
    intake.assemble(set, now).unwrap()
}

/// The honest metadata, root and index, with the payload of another body.
fn forged_payload(honest: &Body, other: &Body, index: usize) -> Vec<u8> {
    let mut forged = honest.frames[index].clone();
    let at = forged.len() - SEGMENT;
    forged[at..].copy_from_slice(&other.frames[index][at..]);
    forged
}

/// The honest root with a proof built for the forged payload, as far as one can be.
fn forged_proof(honest: &Body, other: &Body, index: usize) -> Vec<u8> {
    let at = honest.frames[index].len() - SEGMENT;
    let payload = &other.frames[index][at..];
    let leaves = vec![
        segment_leaf(0, 2, &other.frames[0][at..]),
        segment_leaf(1, 2, &other.frames[1][at..]),
    ];
    let levels = levels(leaves);
    frame(
        index as u16,
        2,
        honest.raw.len() as u64,
        &honest.key.block_hash,
        &honest.root,
        &proof(&levels, index),
        payload,
    )
}

fn assert_unchanged(intake: &Intake, ledger: &DeliveryLedger, sets: usize, before: Snapshot) {
    assert_eq!(intake.buffer().sets(), sets);
    assert_eq!(ledger.snapshot(), before);
}

// The regression.

/// S10 on the research path. A forged segment claiming the honest body's identity and
/// root arrives first, and the honest segments then complete the body.
#[test]
fn a_forged_segment_claiming_the_honest_root_takes_no_slot() {
    let (ledger, mut intake) = intake();
    let now = Instant::now();
    let (honest, other) = (body(1, 10), body(1, 20));

    for forged in [
        forged_payload(&honest, &other, 1),
        forged_proof(&honest, &other, 1),
        forged_payload(&honest, &other, 0),
    ] {
        let before = ledger.snapshot();
        assert!(matches!(
            intake.receive(&forged, now),
            Offer::Invalid(FrameError::Proof)
        ));
        assert_unchanged(&intake, &ledger, 0, before);
    }

    let block = whole(&mut intake, &honest, now);
    assert_eq!(*block.block(), honest.raw, "byte for byte the honest body");
}

#[test]
fn a_forged_segment_between_honest_ones_changes_nothing() {
    let (ledger, mut intake) = intake();
    let now = Instant::now();
    let (honest, other) = (body(1, 10), body(1, 20));
    take(&mut intake, &honest, 0, now);

    let before = ledger.snapshot();
    assert!(matches!(
        intake.receive(&forged_payload(&honest, &other, 1), now),
        Offer::Invalid(FrameError::Proof)
    ));
    assert_unchanged(&intake, &ledger, 1, before);

    let set = into_complete(intake.receive(&honest.frames[1], now)).unwrap();
    assert_eq!(*intake.assemble(set, now).unwrap().block(), honest.raw);
}

/// Claiming another index or a different shape of the honest body fails as well.
#[test]
fn a_frame_lying_about_its_metadata_changes_nothing() {
    let (ledger, mut intake) = intake();
    let now = Instant::now();
    let honest = body(1, 10);
    take(&mut intake, &honest, 0, now);
    let before = ledger.snapshot();

    let mut other_index = honest.frames[1].clone();
    other_index[6..8].copy_from_slice(&0u16.to_be_bytes());
    assert!(matches!(
        intake.receive(&other_index, now),
        Offer::Invalid(FrameError::Proof)
    ));

    let mut other_length = honest.frames[1].clone();
    other_length[14..22].copy_from_slice(&(2 * SEGMENT as u64 - 1).to_be_bytes());
    assert!(matches!(
        intake.receive(&other_length, now),
        Offer::Invalid(FrameError::SegmentLength)
    ));

    assert_unchanged(&intake, &ledger, 1, before);
}

#[test]
fn an_invalid_frame_evicts_nothing_even_with_the_ledger_full() {
    let (ledger, mut intake) = intake_with(bytes_limit(2), buffer_limits());
    let now = Instant::now();
    let (first, second, other) = (body(1, 10), body(2, 10), body(3, 30));
    take(&mut intake, &first, 0, now);
    take(&mut intake, &second, 0, now);
    let before = ledger.snapshot();

    assert!(matches!(
        intake.receive(&forged_payload(&other, &first, 1), now),
        Offer::Invalid(FrameError::Proof)
    ));

    assert_unchanged(&intake, &ledger, 2, before);
    assert!(intake.buffer().holds(&first.key));
    assert!(intake.buffer().holds(&second.key));
}

// What stays open.

/// A consistent body of the same header passes verification under its own identity. It
/// cannot touch the honest slots, but it competes for capacity, and with one set per
/// block it evicts the honest one. This is the known limit, kept visible.
#[test]
fn known_gap_a_consistent_body_of_the_header_can_evict_the_honest_one() {
    let limits = BufferLimits {
        max_sets_per_block: 1,
        ..buffer_limits()
    };
    let (ledger, mut intake) = intake_with(self::limits(), limits);
    let now = Instant::now();
    let (honest, own_root) = (body(1, 10), body(1, 20));
    take(&mut intake, &honest, 0, now);

    let evicted = take(&mut intake, &own_root, 0, now);

    assert_eq!(evicted, vec![honest.key.body_id]);
    assert_eq!(phase(&ledger, &honest, 0), Some(Phase::Released));
}

/// The honest bytes in a tree with other padding, and the honest tree.
fn padded_twice() -> (Body, Body) {
    let raw = sized(1, 10, 3 * SEGMENT - 7).raw;
    let other_padding = segment_leaf(u16::MAX, u16::MAX, b"not padding");
    (
        padded_body(raw.clone(), &[]),
        padded_body(raw, &[other_padding]),
    )
}

/// No second identity for one body can complete: its last segment never gets in, and
/// the honest body finishes under the only identity those bytes have.
#[test]
fn other_padding_gives_a_body_no_second_complete_identity() {
    let (ledger, mut intake) = intake();
    let now = Instant::now();
    let (honest, forged) = padded_twice();
    assert_ne!(honest.key.body_id, forged.key.body_id);
    take(&mut intake, &forged, 0, now);
    take(&mut intake, &forged, 1, now);
    let before = ledger.snapshot();

    assert!(matches!(
        intake.receive(&forged.frames[2], now),
        Offer::Invalid(FrameError::Padding)
    ));
    assert_unchanged(&intake, &ledger, 1, before);

    take(&mut intake, &honest, 0, now);
    take(&mut intake, &honest, 1, now);
    let set = into_complete(intake.receive(&honest.frames[2], now)).unwrap();
    assert_eq!(set.key, honest.key);
    assert_eq!(*intake.assemble(set, now).unwrap().block(), honest.raw);
}

/// What stays open: until something drops it, the partial set of a non-canonical root
/// holds capacity. A sender can do the same with any root of its own.
#[test]
fn known_gap_a_tree_with_other_padding_holds_capacity_until_it_expires() {
    let (ledger, mut intake) = intake();
    let now = Instant::now();
    let (_, forged) = padded_twice();
    take(&mut intake, &forged, 0, now);
    take(&mut intake, &forged, 1, now);
    assert!(intake.buffer().holds(&forged.key));
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);

    let gone = intake.buffer_mut().expire(now + buffer_limits().ttl);

    assert_eq!(gone, vec![forged.key]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

// The ledger and the buffer together.

/// What used to stop at the ledger: a verified segment now makes room from sets the
/// buffer owns.
#[test]
fn a_full_ledger_makes_room_from_the_buffer() {
    let (ledger, mut intake) = intake_with(bytes_limit(2), buffer_limits());
    let now = Instant::now();
    let (first, second, third) = (body(1, 10), body(2, 10), body(3, 10));
    take(&mut intake, &first, 0, now);
    take(&mut intake, &second, 0, now);

    let evicted = take(&mut intake, &third, 0, now);

    assert_eq!(
        evicted,
        vec![first.key.body_id],
        "the oldest, and only as many as needed"
    );
    assert_eq!(phase(&ledger, &first, 0), Some(Phase::Released));
    assert_eq!(phase(&ledger, &second, 0), Some(Phase::Held));
    assert_eq!(phase(&ledger, &third, 0), Some(Phase::Held));
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
}

#[test]
fn under_pressure_the_same_block_gives_up_its_least_advanced_set_first() {
    let (ledger, mut intake) = intake_with(bytes_limit(3), buffer_limits());
    let now = Instant::now();
    let other_block = body(9, 90);
    let advanced = sized(1, 10, 3 * SEGMENT);
    let (behind, new) = (body(1, 20), body(1, 30));
    take(&mut intake, &other_block, 0, now);
    take(&mut intake, &advanced, 0, now);
    take(&mut intake, &behind, 0, now);

    let evicted = take(&mut intake, &new, 0, now);

    assert_eq!(
        evicted,
        vec![advanced.key.body_id],
        "the older of two equal sets"
    );
    assert!(intake.buffer().holds(&other_block.key));
    assert_eq!(ledger.snapshot().reserved_bytes, 3 * SEGMENT);
}

#[test]
fn a_full_owner_limit_makes_room_the_same_way() {
    let limits = Limits {
        max_live_owners: 1,
        ..limits()
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (first, second) = (body(1, 10), body(2, 10));
    take(&mut intake, &first, 0, now);

    assert_eq!(take(&mut intake, &second, 0, now), vec![first.key.body_id]);
    assert_eq!(ledger.snapshot().live_owners, 1);
}

/// A ticket in a channel and a block downstream still hold their payloads, so nothing
/// here may take their room. With nothing of its own to give, the buffer says no.
#[test]
fn reservations_outside_the_buffer_are_never_taken() {
    let (ledger, mut intake) = intake_with(bytes_limit(2), buffer_limits());
    let now = Instant::now();
    let (queued, downstream, incoming) = (body(5, 50), body(6, 60), body(1, 10));
    let Admission::Admitted(in_channel) = ledger.admit(id(&queued, 0), SEGMENT, now) else {
        panic!("expected an admission");
    };
    let Admission::Admitted(held) = ledger.admit(id(&downstream, 0), SEGMENT, now) else {
        panic!("expected an admission");
    };
    let held = held.accept();

    assert!(matches!(
        intake.receive(&incoming.frames[0], now),
        Offer::Refused(Refusal::Bytes)
    ));

    assert_eq!(phase(&ledger, &queued, 0), Some(Phase::InFlight));
    assert_eq!(phase(&ledger, &downstream, 0), Some(Phase::Held));
    assert_eq!(
        phase(&ledger, &incoming, 0),
        None,
        "a refusal leaves no record"
    );
    drop((in_channel, held));
    take(&mut intake, &incoming, 0, now);
}

/// Room is planned first, so a set is not lost for a segment that would not fit anyway.
#[test]
fn a_plan_that_cannot_free_enough_evicts_nothing() {
    let limits = Limits {
        max_reserved_bytes: 2 * SEGMENT + 50,
        ..limits()
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (outside, small, incoming) = (sized(5, 50, 2 * SEGMENT), sized(2, 10, 150), body(3, 10));
    let Admission::Admitted(in_channel) = ledger.admit(id(&outside, 0), 2 * SEGMENT, now) else {
        panic!("expected an admission");
    };
    take(&mut intake, &small, 1, now);
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT + 50);

    assert!(matches!(
        intake.receive(&incoming.frames[0], now),
        Offer::Refused(Refusal::Bytes)
    ));

    assert!(
        intake.buffer().holds(&small.key),
        "the set was not lost for nothing"
    );
    drop(in_channel);
}

#[test]
fn a_set_is_not_evicted_to_make_room_for_itself() {
    let (ledger, mut intake) = intake_with(bytes_limit(1), buffer_limits());
    let now = Instant::now();
    let x = body(1, 10);
    take(&mut intake, &x, 0, now);

    assert!(matches!(
        intake.receive(&x.frames[1], now),
        Offer::Refused(Refusal::Bytes)
    ));

    assert!(intake.buffer().holds(&x.key));
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Held));
}

#[test]
fn only_capacity_makes_room() {
    let limits = Limits {
        max_reserved_bytes: SEGMENT,
        repeat_budget: 0,
        ..limits()
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (x, y) = (body(1, 10), body(2, 10));
    take(&mut intake, &x, 0, now);

    assert!(matches!(
        intake.receive(&x.frames[0], now),
        Offer::Owned(Phase::Held)
    ));
    assert!(intake.buffer().holds(&x.key), "a duplicate evicts nothing");

    take(&mut intake, &y, 0, now);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
    let before = ledger.snapshot();
    assert!(matches!(
        intake.receive(&x.frames[0], now),
        Offer::Refused(Refusal::RepeatBudget)
    ));
    assert!(
        intake.buffer().holds(&y.key),
        "a spent budget evicts nothing"
    );
    assert_eq!(ledger.snapshot(), before);
}

#[test]
fn assembly_makes_room_from_other_sets() {
    let (ledger, mut intake) = intake_with(bytes_limit(4), buffer_limits());
    let now = Instant::now();
    let (x, other) = (body(1, 10), body(2, 10));
    take(&mut intake, &other, 0, now);
    take(&mut intake, &x, 0, now);
    let set = into_complete(intake.receive(&x.frames[1], now)).unwrap();

    let block = intake.assemble(set, now).unwrap();

    assert_eq!(*block.block(), x.raw);
    assert!(!intake.buffer().holds(&other.key));
    assert_eq!(ledger.snapshot().reserved_bytes, 4 * SEGMENT);
}

#[test]
fn assembly_gives_the_set_back_when_no_room_can_be_made() {
    let (ledger, mut intake) = intake_with(bytes_limit(3), buffer_limits());
    let now = Instant::now();
    let x = body(1, 10);
    take(&mut intake, &x, 0, now);
    let set = into_complete(intake.receive(&x.frames[1], now)).unwrap();

    assert_eq!(
        intake.assemble(set, now).err(),
        Some(AssemblyError::Refused(Refusal::Bytes))
    );

    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
}

// Capacity moving while room is made. Another producer runs at an exact step.

fn ticket(ledger: &DeliveryLedger, object: [u8; 32], bytes: usize, now: Instant) -> Ticket {
    match ledger.admit(object, bytes, now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    }
}

/// The room a plan counted on goes to someone else before the ledger answers. The
/// segment is refused, as it must be, and that refusal costs no set.
#[test]
fn capacity_taken_in_between_costs_no_set() {
    let (ledger, mut intake) = intake_with(bytes_limit(2), buffer_limits());
    let now = Instant::now();
    let (outside, small, incoming) = (body(5, 50), sized(2, 10, 150), body(3, 10));
    let thief = body(7, 70);
    let in_channel = ticket(&ledger, id(&outside, 0), SEGMENT, now);
    take(&mut intake, &small, 1, now);
    assert_eq!(ledger.snapshot().reserved_bytes, 150);

    let mut stolen = None;
    let offer = intake.receive_stepping(&incoming.frames[0], now, |step| {
        assert_eq!(step, Step::BeforeAsking);
        stolen = Some(ticket(&ledger, id(&thief, 0), 50, now));
    });

    assert!(
        intake.buffer().holds(&small.key),
        "a refused segment cost a set"
    );
    assert_eq!(phase(&ledger, &small, 1), Some(Phase::Held));
    assert!(matches!(offer, Offer::Refused(Refusal::Bytes)));
    assert_eq!(phase(&ledger, &incoming, 0), None);
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
    drop((in_channel, stolen));
}

/// Room an eviction will free is spoken for before anything goes. Nobody can take it in
/// the moment both the new segment and its victim are alive, and no lock is held then.
#[test]
fn room_promised_by_an_eviction_cannot_be_taken() {
    let (ledger, mut intake) = intake_with(bytes_limit(2), buffer_limits());
    let now = Instant::now();
    let (first, second, third, thief) = (body(1, 10), body(2, 10), body(3, 10), body(7, 70));
    take(&mut intake, &first, 0, now);
    take(&mut intake, &second, 0, now);

    let mut steps = Vec::new();
    let offer = intake.receive_stepping(&third.frames[0], now, |step| {
        steps.push(step);
        assert!(
            matches!(
                ledger.admit(id(&thief, 0), SEGMENT, now),
                Admission::Refused(Refusal::Bytes)
            ),
            "the room went to someone else at {step:?}"
        );
        if step == Step::BeforeEvicting {
            let reserved = ledger.snapshot().reserved_bytes;
            assert_eq!(reserved, 3 * SEGMENT, "everything alive is counted");
        }
    });

    assert_eq!(steps, [Step::BeforeAsking, Step::BeforeEvicting]);
    let Offer::Taken(insertion) = offer else {
        panic!("expected the segment to be taken, got {offer:?}");
    };
    assert_eq!(insertion.evicted, vec![first.key]);
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
    assert_eq!(phase(&ledger, &first, 0), Some(Phase::Released));
    assert_eq!(phase(&ledger, &third, 0), Some(Phase::Held));
}

#[test]
fn capacity_taken_in_between_costs_no_set_at_assembly() {
    let (ledger, mut intake) = intake_with(bytes_limit(4), buffer_limits());
    let now = Instant::now();
    let (x, small, thief) = (body(1, 10), sized(2, 10, 150), body(7, 70));
    take(&mut intake, &small, 1, now);
    take(&mut intake, &x, 0, now);
    let set = into_complete(intake.receive(&x.frames[1], now)).unwrap();

    let mut stolen = None;
    let assembled = intake.assemble_stepping(set, now, |step| {
        assert_eq!(step, Step::BeforeAsking);
        stolen = Some(ticket(&ledger, id(&thief, 0), 150, now));
    });

    assert!(
        intake.buffer().holds(&small.key),
        "a refused assembly cost a set"
    );
    assert_eq!(
        assembled.err(),
        Some(AssemblyError::Refused(Refusal::Bytes))
    );
    assert_eq!(ledger.snapshot().reserved_bytes, 200);
    drop(stolen);
}

/// The other way an accepted room came to nothing: a set the buffer could never hold
/// used to make room in the ledger and then be turned away.
#[test]
fn a_set_too_long_to_hold_evicts_nothing() {
    let limits = BufferLimits {
        max_segments: 2,
        ..buffer_limits()
    };
    let (ledger, mut intake) = intake_with(bytes_limit(1), limits);
    let now = Instant::now();
    let (first, too_long) = (body(1, 10), sized(2, 20, 3 * SEGMENT));
    take(&mut intake, &first, 0, now);
    let before = ledger.snapshot();

    let offer = intake.receive(&too_long.frames[0], now);

    assert!(
        intake.buffer().holds(&first.key),
        "a hopeless set cost a set"
    );
    assert!(matches!(offer, Offer::Rejected(Reject::TooManySegments)));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(phase(&ledger, &too_long, 0), None);
}

/// Someone else admits this very object in between, so the second answer is theirs.
#[test]
fn the_same_object_taken_in_between_costs_no_set() {
    let (ledger, mut intake) = intake_with(bytes_limit(1), buffer_limits());
    let now = Instant::now();
    let (first, incoming) = (body(1, 10), body(2, 10));
    take(&mut intake, &first, 0, now);

    let mut theirs = None;
    let offer = intake.receive_stepping(&incoming.frames[0], now, |_| {
        theirs = Some(ticket(&ledger, id(&incoming, 0), 0, now));
    });

    assert!(intake.buffer().holds(&first.key));
    assert!(matches!(offer, Offer::Owned(Phase::InFlight)));
    drop(theirs);
}

#[test]
fn a_full_record_map_makes_room_the_same_way_and_ends_at_its_limit() {
    let limits = Limits {
        max_records: 1,
        ..limits()
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (first, second) = (body(1, 10), body(2, 10));
    take(&mut intake, &first, 0, now);

    assert_eq!(take(&mut intake, &second, 0, now), vec![first.key.body_id]);

    assert_eq!(
        phase(&ledger, &first, 0),
        None,
        "forgotten once it was idle"
    );
    assert_eq!(phase(&ledger, &second, 0), Some(Phase::Held));
    assert_eq!(ledger.snapshot().held, 1);
}

fn records(snapshot: &Snapshot) -> usize {
    snapshot.in_flight + snapshot.held + snapshot.released + snapshot.completed
}

/// The contract: at no moment does a count pass its limit plus its share.
fn assert_within_ceilings(ledger: &DeliveryLedger, at: &str) {
    let (limits, counts) = (ledger.limits(), ledger.snapshot());
    let share = limits.transit;
    assert!(
        counts.reserved_bytes <= limits.max_reserved_bytes + share.bytes,
        "bytes at {at}: {counts:?}"
    );
    assert!(
        counts.live_owners <= limits.max_live_owners + share.owners,
        "owners at {at}: {counts:?}"
    );
    assert!(
        records(&counts) <= limits.max_records + share.records,
        "records at {at}: {counts:?}"
    );
}

/// Every count tight, then each one alone, so each ceiling has to hold by itself.
fn tight_limits() -> [(&'static str, Limits); 4] {
    let roomy = limits();
    let wide = Transit {
        bytes: 8 * SEGMENT,
        owners: 8,
        records: 8,
    };
    [
        (
            "all",
            Limits {
                max_records: 4,
                max_live_owners: 4,
                max_reserved_bytes: 4 * SEGMENT,
                transit: Transit {
                    bytes: SEGMENT,
                    owners: 1,
                    records: 1,
                },
                ..roomy
            },
        ),
        (
            "bytes",
            Limits {
                max_reserved_bytes: 4 * SEGMENT,
                transit: Transit {
                    bytes: SEGMENT,
                    ..wide
                },
                ..roomy
            },
        ),
        (
            "owners",
            Limits {
                max_live_owners: 4,
                transit: Transit { owners: 1, ..wide },
                ..roomy
            },
        ),
        (
            "records",
            Limits {
                max_records: 4,
                transit: Transit { records: 1, ..wide },
                ..roomy
            },
        ),
    ]
}

/// One admission waits between its reservation and its evictions, and a second intake
/// tries the same thing. The share is already in use, so the second is refused, gives up
/// nothing and leaves every count where it was. The nested step is there because a
/// second eviction would be over before `receive` returned.
#[test]
fn a_second_intake_cannot_stack_on_a_reservation_in_transit() {
    for (name, limits) in tight_limits() {
        let ledger = DeliveryLedger::new(limits);
        let buffer = || BodyBuffer::new(buffer_limits()).unwrap();
        let mut waiting = Intake::new(ledger.clone(), buffer(), rules());
        let mut other = Intake::new(ledger.clone(), buffer(), rules());
        let now = Instant::now();

        let victim = body(1, 10);
        take(&mut waiting, &victim, 0, now);
        for block in 2..5 {
            take(&mut other, &body(block, 10), 0, now);
        }
        let (first_new, second_new) = (body(5, 10), body(6, 10));

        let offer = waiting.receive_stepping(&first_new.frames[0], now, |step| {
            if step != Step::BeforeEvicting {
                return;
            }
            let during = ledger.snapshot();
            assert_eq!(during.reserved_bytes, 5 * SEGMENT, "{name}");
            assert_eq!(during.live_owners, 5, "{name}");
            assert_eq!(records(&during), 5, "{name}");
            assert_eq!(
                phase(&ledger, &victim, 0),
                Some(Phase::Held),
                "{name}: a live owner keeps its reservation"
            );
            assert_within_ceilings(&ledger, "the first eviction");

            let second = other.receive_stepping(&second_new.frames[0], now, |step| {
                if step == Step::BeforeEvicting {
                    assert_within_ceilings(&ledger, "the second eviction");
                }
            });
            assert!(
                matches!(second, Offer::Refused(Refusal::Transit)),
                "{name}: got {second:?}"
            );
            assert_eq!(other.buffer().sets(), 3, "{name}: the refusal cost a set");
            assert_eq!(ledger.snapshot(), during, "{name}");
        });

        assert!(matches!(offer, Offer::Taken(_)), "{name}");
        let after = ledger.snapshot();
        assert_eq!(after.reserved_bytes, 4 * SEGMENT, "{name}");
        assert_eq!(after.live_owners, 4, "{name}");
        assert!(records(&after) <= limits.max_records, "{name}");

        take(&mut other, &second_new, 0, now);
        assert_within_ceilings(&ledger, "the end");
        assert_eq!(ledger.snapshot().reserved_bytes, 4 * SEGMENT, "{name}");
    }
}

/// A plain admission never touches the share, even with room above the limit in sight.
#[test]
fn a_plain_admission_stays_under_the_limit() {
    let (ledger, mut intake) = intake_with(bytes_limit(1), buffer_limits());
    let now = Instant::now();
    let (victim, new, thief) = (body(1, 10), body(2, 10), body(7, 70));
    take(&mut intake, &victim, 0, now);
    assert!(ledger.limits().transit.bytes >= SEGMENT);

    assert!(matches!(
        ledger.admit(id(&thief, 0), SEGMENT, now),
        Admission::Refused(Refusal::Bytes)
    ));

    take(&mut intake, &new, 0, now);
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);
}

#[test]
fn with_no_share_a_full_ledger_refuses_and_gives_up_nothing() {
    let limits = Limits {
        transit: Transit::default(),
        ..bytes_limit(2)
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (first, second, third) = (body(1, 10), body(2, 10), body(3, 10));
    take(&mut intake, &first, 0, now);
    take(&mut intake, &second, 0, now);
    let before = ledger.snapshot();

    assert!(matches!(
        intake.receive(&third.frames[0], now),
        Offer::Refused(Refusal::Transit)
    ));
    assert_unchanged(&intake, &ledger, 2, before);

    intake.buffer_mut().discard(&first.key);
    take(&mut intake, &third, 0, now);
}

#[test]
fn a_share_smaller_than_the_object_gives_up_nothing() {
    let limits = Limits {
        transit: Transit {
            bytes: SEGMENT - 1,
            ..limits().transit
        },
        ..bytes_limit(1)
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (first, second) = (body(1, 10), body(2, 10));
    take(&mut intake, &first, 0, now);
    let before = ledger.snapshot();

    assert!(matches!(
        intake.receive(&second.frames[0], now),
        Offer::Refused(Refusal::Transit)
    ));
    assert_unchanged(&intake, &ledger, 1, before);
}

/// The price of a share smaller than a body: on a full ledger a whole set cannot be
/// assembled and goes back, though nothing else is lost for it.
#[test]
fn a_share_smaller_than_the_body_gives_the_set_back_and_keeps_the_others() {
    let limits = Limits {
        transit: Transit {
            bytes: SEGMENT,
            ..limits().transit
        },
        ..bytes_limit(4)
    };
    let (ledger, mut intake) = intake_with(limits, buffer_limits());
    let now = Instant::now();
    let (x, older, oldest) = (body(1, 10), body(2, 10), body(3, 10));
    take(&mut intake, &oldest, 0, now);
    take(&mut intake, &older, 0, now);
    take(&mut intake, &x, 0, now);
    let set = into_complete(intake.receive(&x.frames[1], now)).unwrap();
    assert_eq!(ledger.snapshot().reserved_bytes, 4 * SEGMENT);

    assert_eq!(
        intake.assemble(set, now).err(),
        Some(AssemblyError::Refused(Refusal::Transit))
    );

    assert!(intake.buffer().holds(&oldest.key));
    assert!(intake.buffer().holds(&older.key));
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
}

// What comes back when a call dies in the middle.

fn dies(run: impl FnOnce()) {
    let result = catch_unwind(AssertUnwindSafe(run));
    assert!(result.is_err(), "the step was reached");
}

/// The panic lands where the new owner and its victims overlap. The ticket unwinds, its
/// reservation comes back, the sets were never touched, and the ledger still works.
#[test]
fn a_panic_before_the_evictions_gives_the_reservation_back_and_keeps_the_sets() {
    let (ledger, mut intake) = intake_with(bytes_limit(1), buffer_limits());
    let now = Instant::now();
    let (victim, new) = (body(1, 10), body(2, 10));
    take(&mut intake, &victim, 0, now);
    let before = ledger.snapshot();

    dies(|| {
        intake.receive_stepping(&new.frames[0], now, |step| {
            if step == Step::BeforeEvicting {
                assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
                panic!("stopped between the reservation and the evictions");
            }
        });
    });

    let after = ledger.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_owners, before.live_owners);
    assert!(intake.buffer().holds(&victim.key));
    assert_eq!(phase(&ledger, &victim, 0), Some(Phase::Held));
    assert_eq!(phase(&ledger, &new, 0), Some(Phase::Released));

    take(&mut intake, &new, 0, now);
    assert!(!intake.buffer().holds(&victim.key));
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);
}

#[test]
fn a_panic_before_the_second_ask_changes_nothing() {
    let (ledger, mut intake) = intake_with(bytes_limit(1), buffer_limits());
    let now = Instant::now();
    let (victim, new) = (body(1, 10), body(2, 10));
    take(&mut intake, &victim, 0, now);
    let before = ledger.snapshot();

    dies(|| {
        intake.receive_stepping(&new.frames[0], now, |_| panic!("stopped before asking"));
    });

    assert_unchanged(&intake, &ledger, 1, before);
    assert_eq!(phase(&ledger, &new, 0), None);
}

#[test]
fn a_panic_during_assembly_gives_everything_back_and_keeps_the_others() {
    let (ledger, mut intake) = intake_with(bytes_limit(4), buffer_limits());
    let now = Instant::now();
    let (x, other) = (body(1, 10), body(2, 10));
    take(&mut intake, &other, 0, now);
    take(&mut intake, &x, 0, now);
    let set = into_complete(intake.receive(&x.frames[1], now)).unwrap();

    dies(|| {
        let _ = intake.assemble_stepping(set, now, |step| {
            if step == Step::BeforeEvicting {
                assert_eq!(ledger.snapshot().reserved_bytes, 5 * SEGMENT);
                panic!("stopped between the reservation and the evictions");
            }
        });
    });

    assert!(intake.buffer().holds(&other.key));
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);
    assert_eq!(ledger.snapshot().live_owners, 1);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
    assert_eq!(ledger.observe(&x.key.body_id), Some(Phase::Released));
}

/// Real threads on one ledger, so the order is whatever it is. What must hold in any
/// order: every count stays under its ceiling at every look, a refusal costs its own
/// intake no set, nothing deadlocks on the way out of an eviction, and with everyone
/// finished the counts are back within the limits.
#[test]
fn producers_on_one_ledger_keep_their_sets_through_a_refusal() {
    const PRODUCERS: u8 = 4;
    let ledger = DeliveryLedger::new(Limits {
        transit: Transit {
            bytes: SEGMENT,
            owners: 1,
            records: 1,
        },
        ..bytes_limit(6)
    });
    let barrier = Barrier::new(usize::from(PRODUCERS));

    let intakes: Vec<Intake> = thread::scope(|scope| {
        let producers: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let (ledger, barrier) = (ledger.clone(), &barrier);
                scope.spawn(move || {
                    let buffer = BodyBuffer::new(buffer_limits()).unwrap();
                    let mut intake = Intake::new(ledger.clone(), buffer, rules());
                    let now = Instant::now();
                    barrier.wait();
                    for round in 0..120 {
                        let frame = &body(producer + 1, round).frames[0];
                        let sets = intake.buffer().sets();
                        if let Offer::Refused(_) = intake.receive(frame, now) {
                            assert_eq!(intake.buffer().sets(), sets);
                        }
                        assert_within_ceilings(&ledger, "a look from a producer");
                    }
                    intake
                })
            })
            .collect();
        producers
            .into_iter()
            .map(|producer| producer.join().unwrap())
            .collect()
    });

    assert!(ledger.snapshot().reserved_bytes <= 6 * SEGMENT);
    drop(intakes);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(ledger.snapshot().live_owners, 0);
}

// Real tasks, ordered by replies.

#[derive(Debug)]
enum Answer {
    Invalid,
    Pending,
    Assembled,
}

type FrameMessage = (Vec<u8>, oneshot::Sender<Answer>);
type Verdict = (bool, oneshot::Sender<()>);

/// The consumer owns the intake and hands whole blocks to a judge. Nothing is held
/// across an await, because the intake has no async calls.
fn pipeline(
    ledger: DeliveryLedger,
) -> (
    mpsc::Sender<FrameMessage>,
    mpsc::Sender<Verdict>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (frames, mut incoming) = mpsc::channel::<FrameMessage>(1);
    let (blocks, mut judged) = mpsc::channel::<AssembledBlock<Vec<u8>>>(1);
    let (verdicts, mut decisions) = mpsc::channel::<Verdict>(1);
    let consumer = tokio::spawn(async move {
        let buffer = BodyBuffer::new(buffer_limits()).unwrap();
        let mut intake = Intake::new(ledger, buffer, rules());
        while let Some((frame, reply)) = incoming.recv().await {
            let now = Instant::now();
            let offer = intake.receive(&frame, now);
            let answer = match offer {
                Offer::Invalid(_) => Answer::Invalid,
                offer => match into_complete(offer) {
                    Some(set) => {
                        blocks
                            .send(intake.assemble(set, now).unwrap())
                            .await
                            .unwrap();
                        Answer::Assembled
                    }
                    None => Answer::Pending,
                },
            };
            reply.send(answer).unwrap();
        }
    });
    let judge = tokio::spawn(async move {
        while let Some(block) = judged.recv().await {
            let (accept, done) = decisions.recv().await.unwrap();
            if accept {
                block.finish(Instant::now());
            } else {
                block.give_back();
            }
            done.send(()).unwrap();
        }
    });
    (frames, verdicts, consumer, judge)
}

async fn send(frames: &mpsc::Sender<FrameMessage>, frame: &[u8]) -> Answer {
    let (reply, answer) = oneshot::channel();
    frames.send((frame.to_vec(), reply)).await.unwrap();
    answer.await.unwrap()
}

async fn decide(verdicts: &mpsc::Sender<Verdict>, accept: bool) {
    let (done, finished) = oneshot::channel();
    verdicts.send((accept, done)).await.unwrap();
    finished.await.unwrap();
}

/// The whole research path: forged frames among honest ones, a refusal that gives the
/// body back, and the same body returning. Giving back is the research assumption.
#[tokio::test]
async fn a_body_survives_forgeries_and_a_refusal_across_tasks() {
    let ledger = DeliveryLedger::new(limits());
    let (frames, verdicts, consumer, judge) = pipeline(ledger.clone());
    let (honest, other) = (body(1, 10), body(1, 20));

    let forged = forged_payload(&honest, &other, 1);
    assert!(matches!(send(&frames, &forged).await, Answer::Invalid));
    assert!(matches!(
        send(&frames, &honest.frames[0]).await,
        Answer::Pending
    ));
    assert!(matches!(send(&frames, &forged).await, Answer::Invalid));
    assert!(matches!(
        send(&frames, &honest.frames[1]).await,
        Answer::Assembled
    ));

    decide(&verdicts, false).await;
    assert_eq!(phase(&ledger, &honest, 0), Some(Phase::Released));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);

    assert!(matches!(
        send(&frames, &honest.frames[1]).await,
        Answer::Pending
    ));
    assert!(matches!(
        send(&frames, &honest.frames[0]).await,
        Answer::Assembled
    ));
    decide(&verdicts, true).await;

    assert_eq!(ledger.observe(&honest.key.body_id), Some(Phase::Completed));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);

    drop(frames);
    consumer.await.unwrap();
    drop(verdicts);
    judge.await.unwrap();
}
