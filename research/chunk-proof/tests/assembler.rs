//! One session's reassembly. Nothing here is a node, a client or a network.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use chunk_proof::assembler::{
    Arrival, Assembler, AssemblerLimits, AssemblerState, CannotStart, Interest,
};
use chunk_proof::budget::{Budget, InvalidLimits, Limits, Refusal, Used};
use chunk_proof::datagram::{ChunkError, Verifier, seal};
use chunk_proof::object::{
    Encoded, MSG_BLOCK, MSG_RAW_SEGMENT, MSG_SKELETON, ObjectError, Profile, Shape, encode,
    held_bytes, work_bytes,
};
use chunk_proof::tree::{Node, empty_leaf, levels, proof};
use common::{
    ASSEMBLY_TTL, KEY, REJECTED_TTL, assembler_limits, assembler_on, budget_with, content,
    datagram, datagrams, decoded, later, object, pending, roomy, roomy_limits, verifier,
};

const RAW: u8 = MSG_RAW_SEGMENT;

fn honest() -> Encoded {
    object(RAW, 6, 4, 10, 40)
}

fn other() -> Encoded {
    object(RAW, 6, 4, 77, 40)
}

/// `other`'s shard in `honest`'s place, with the honest proof.
fn with_other_shard(honest: &Encoded, other: &Encoded, index: usize) -> Vec<u8> {
    seal(
        &KEY,
        &honest.shape,
        &honest.object_id,
        index as u16,
        &honest.proofs[index],
        &other.shards[index],
    )
}

/// `other`'s shard and its own proof, under `honest`'s id.
fn with_other_proof(honest: &Encoded, other: &Encoded, index: usize) -> Vec<u8> {
    seal(
        &KEY,
        &honest.shape,
        &honest.object_id,
        index as u16,
        &other.proofs[index],
        &other.shards[index],
    )
}

fn lying_about_k(honest: &Encoded, index: usize) -> Vec<u8> {
    let shape = Shape {
        k: honest.shape.k - 1,
        ..honest.shape
    };
    seal(
        &KEY,
        &shape,
        &honest.object_id,
        index as u16,
        &honest.proofs[index],
        &honest.shards[index],
    )
}

/// One assembler alive and nothing else.
fn idle() -> Used {
    Used {
        sessions: 1,
        ..Used::default()
    }
}

fn assert_nothing_changed(
    assembler: &Assembler,
    budget: &Budget,
    state: AssemblerState,
    used: Used,
) {
    assert_eq!(assembler.state(), state);
    assert_eq!(budget.used(), used);
}

fn feed(assembler: &mut Assembler, frames: &[Vec<u8>], indices: &[usize], now: Instant) -> Arrival {
    let mut last = None;
    for at in indices {
        last = Some(assembler.receive(&frames[*at], now));
    }
    last.expect("at least one chunk")
}

// The regression: today's node marks a chunk before it knows anything about it.

/// A forged chunk under the honest id comes first, in every form a key holder can make.
/// None takes a slot or leaves a mark, and every honest index is still welcome.
#[test]
fn a_forged_chunk_under_the_honest_id_blocks_nothing() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let (honest, other) = (honest(), other());
    let now = Instant::now();

    for index in 0..6 {
        for (forged, rule) in [
            (with_other_shard(&honest, &other, index), ChunkError::Proof),
            (lying_about_k(&honest, index), ChunkError::Proof),
        ] {
            assert!(matches!(
                assembler.receive(&forged, now),
                Arrival::Invalid(error) if error == rule
            ));
            assert_nothing_changed(&assembler, &budget, AssemblerState::default(), idle());
        }
    }

    let frames = datagrams(&honest);
    feed(&mut assembler, &frames, &[0, 1, 2], now);
    let object = decoded(assembler.receive(&frames[3], now));
    assert_eq!(object.content(), content(10, 40));
    assert_eq!(object.object_id(), honest.object_id);
}

#[test]
fn a_forged_chunk_between_honest_ones_changes_nothing() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let (honest, other) = (honest(), other());
    let now = Instant::now();
    let frames = datagrams(&honest);
    pending(assembler.receive(&frames[0], now));
    let (state, used) = (assembler.state(), budget.used());

    // Index 1 is still free, and a chunk for it must not take it. Its own proof makes a
    // different root, so this is what a slot claim looks like from a key holder.
    let forged = with_other_proof(&honest, &other, 1);
    assert!(matches!(
        assembler.receive(&forged, now),
        Arrival::Invalid(ChunkError::Proof | ChunkError::Padding)
    ));
    assert_nothing_changed(&assembler, &budget, state, used);

    pending(assembler.receive(&frames[1], now));
    pending(assembler.receive(&frames[2], now));
    let object = decoded(assembler.receive(&frames[3], now));
    assert_eq!(object.content(), content(10, 40));
}

#[test]
fn a_tampered_padding_sibling_stops_before_the_proof() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let honest = object(RAW, 3, 2, 10, 40);
    let mut siblings = honest.proofs[2].clone();
    assert_eq!(siblings[0], empty_leaf(), "index 3 is padding");
    siblings[0] = [7; 32];

    let forged = seal(
        &KEY,
        &honest.shape,
        &honest.object_id,
        2,
        &siblings,
        &honest.shards[2],
    );

    assert!(matches!(
        assembler.receive(&forged, Instant::now()),
        Arrival::Invalid(ChunkError::Padding)
    ));
    assert_eq!(assembler.state(), AssemblerState::default());
}

// Two objects at once.

#[test]
fn two_objects_interleaved_do_not_mix() {
    let mut assembler = assembler_on(&roomy());
    let now = Instant::now();
    let (first, second) = (honest(), other());
    let (first_frames, second_frames) = (datagrams(&first), datagrams(&second));

    for at in [0, 1, 2] {
        pending(assembler.receive(&first_frames[at], now));
        pending(assembler.receive(&second_frames[5 - at], now));
    }
    let one = decoded(assembler.receive(&first_frames[4], now));
    let two = decoded(assembler.receive(&second_frames[0], now));

    assert_eq!(one.content(), content(10, 40));
    assert_eq!(two.content(), content(77, 40));
}

#[test]
fn a_chunk_moved_to_another_object_is_refused() {
    let mut assembler = assembler_on(&roomy());
    let (first, second) = (honest(), other());
    let moved = seal(
        &KEY,
        &first.shape,
        &second.object_id,
        2,
        &first.proofs[2],
        &first.shards[2],
    );

    assert!(matches!(
        assembler.receive(&moved, Instant::now()),
        Arrival::Invalid(ChunkError::Proof)
    ));
    assert_eq!(assembler.state(), AssemblerState::default());
}

/// The same content is a different object under another type or shape.
#[test]
fn one_content_makes_different_objects_and_they_stay_apart() {
    let mut assembler = assembler_on(&roomy());
    let now = Instant::now();
    let bytes = content(5, 40);
    let raw = encode(MSG_RAW_SEGMENT, 6, 4, &bytes).unwrap();
    let skeleton = encode(MSG_SKELETON, 6, 4, &bytes).unwrap();
    let block = encode(MSG_BLOCK, 7, 4, &bytes).unwrap();
    assert_ne!(raw.object_id, skeleton.object_id);
    assert_ne!(raw.object_id, block.object_id);

    for object in [&raw, &skeleton, &block] {
        let frames = datagrams(object);
        let done = decoded(feed(&mut assembler, &frames, &[0, 1, 2, 3], now));
        assert_eq!(done.content(), bytes);
        assert_eq!(done.msg_type(), object.shape.msg_type);
    }
}

// Shapes of the code.

#[test]
fn with_k_of_one_any_single_shard_is_the_object() {
    for index in 0..4 {
        let mut assembler = assembler_on(&roomy());
        let object = object(RAW, 4, 1, 3, 30);
        let frames = datagrams(&object);
        let done = decoded(assembler.receive(&frames[index], Instant::now()));
        assert_eq!(done.content(), content(3, 30), "index {index}");
    }
}

/// A decode leaves nothing here: whether the object got anywhere is not this layer's to
/// say. A later chunk starts again, and what stops a second delivery is further down.
#[test]
fn a_decode_leaves_no_record_and_a_late_chunk_starts_again() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let object = object(RAW, 4, 1, 3, 30);
    let frames = datagrams(&object);

    let first = decoded(assembler.receive(&frames[0], now));
    assert_eq!(assembler.state(), AssemblerState::default());

    let second = decoded(assembler.receive(&frames[1], now));
    assert_eq!(second.content(), first.content());
}

/// Asked where a chunk would start a cost: opening an object, or paying for its decode.
#[test]
fn a_chunk_nobody_wants_opens_nothing_and_pays_for_no_decode() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&honest());

    assert!(matches!(
        assembler.receive_if(&frames[0], now, |_| Interest::Done),
        Arrival::NotWanted
    ));
    assert_nothing_changed(&assembler, &budget, AssemblerState::default(), idle());

    pending(assembler.receive_if(&frames[0], now, |_| Interest::New));
    for at in [1, 2] {
        pending(assembler.receive_if(&frames[at], now, |_| {
            panic!("a chunk in the middle has no cost to ask about")
        }));
    }

    let done = decoded(assembler.receive_if(&frames[3], now, |_| Interest::New));
    assert_eq!(done.content(), content(10, 40));
}

/// A place the layer above says is taken: the object leaves its normal place and all its
/// shards go to the shelf, with the chunk that would have finished it.
#[test]
fn an_open_object_someone_else_delivered_moves_to_the_shelf() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&honest());
    pending(feed(&mut assembler, &frames, &[0, 1, 2], now));

    assert!(matches!(
        assembler.receive_if(&frames[3], now, |_| Interest::Spare),
        Arrival::Spare { have: 4, need: 4 }
    ));

    assert_eq!(assembler.state().open, 0);
    assert_eq!(assembler.state().spares, 1);
    assert_eq!(budget.used().objects, 0, "no normal place is held");
    assert_eq!(budget.used().held_bytes, 0);

    let done = assembler.revive(now, |_| Interest::Due);
    assert!(matches!(&done[..], [Arrival::Decoded(_)]));
}

/// The shelf keeps what a decode needs and no more.
#[test]
fn the_shelf_keeps_at_most_k_shards_of_an_object() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&honest());

    for frame in &frames {
        assembler.receive_if(frame, now, |_| Interest::Spare);
    }

    let shards = 4 * usize::from(honest().shape.s);
    assert_eq!(budget.used().spare_objects, 1);
    assert!(budget.used().spare_bytes <= held_bytes(&honest().shape));
    assert!(budget.used().spare_bytes >= shards);
    assert!(matches!(
        assembler.receive_if(&frames[0], now, |_| Interest::Spare),
        Arrival::Repeat
    ));
}

#[test]
fn all_data_shards_need_no_recovery_and_parity_can_stand_in() {
    let object = honest();
    let frames = datagrams(&object);
    for indices in [[0, 1, 2, 3], [2, 3, 4, 5], [0, 2, 4, 5], [5, 4, 3, 2]] {
        let mut assembler = assembler_on(&roomy());
        let done = decoded(feed(&mut assembler, &frames, &indices, Instant::now()));
        assert_eq!(done.content(), content(10, 40), "{indices:?}");
    }
}

#[test]
fn a_missing_shard_decodes_nothing_and_the_object_can_start_again() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let object = honest();
    let frames = datagrams(&object);

    pending(feed(&mut assembler, &frames, &[0, 1, 2], now));
    assert_eq!(assembler.state().open, 1);
    assert_eq!(budget.used().work_bytes, 0, "no decode has started");

    assert_eq!(
        assembler.expire(later(now, ASSEMBLY_TTL)),
        vec![object.object_id]
    );
    assert_eq!(budget.used(), idle(), "an expiry returns the object");

    let now = later(now, ASSEMBLY_TTL);
    let done = decoded(feed(&mut assembler, &frames, &[3, 4, 5, 0], now));
    assert_eq!(done.content(), content(10, 40));
}

/// A repeat fills nothing, so `k` chunks of three indices are not `k` shards.
#[test]
fn a_repeated_index_does_not_count() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let object = honest();
    let frames = datagrams(&object);
    pending(feed(&mut assembler, &frames, &[0, 1, 2], now));
    let (state, used) = (assembler.state(), budget.used());

    for at in [0, 1, 2, 2, 1] {
        assert!(matches!(
            assembler.receive(&frames[at], now),
            Arrival::Repeat
        ));
    }

    assert_nothing_changed(&assembler, &budget, state, used);
    let done = decoded(assembler.receive(&frames[3], now));
    assert_eq!(done.content(), content(10, 40));
}

// Bad objects.

fn tree_over(shape: Shape, shards: Vec<Vec<u8>>) -> Encoded {
    let leaves = shards
        .iter()
        .enumerate()
        .map(|(at, shard)| {
            chunk_proof::tree::chunk_leaf(1, shape.msg_type, shape.n, shape.k, at as u16, shard)
        })
        .collect();
    let levels = levels(leaves);
    let object_id = levels[levels.len() - 1][0];
    let proofs = (0..shards.len()).map(|at| proof(&levels, at)).collect();
    Encoded {
        shape,
        object_id,
        shards,
        proofs,
    }
}

/// A consistent tree over a broken code: every proof holds under its own root. Whatever
/// `k` shards arrive the object is refused. Which rule stops it depends on the subset,
/// since a broken shard can decode to a nonsense length, and the vectors pin that down.
#[test]
fn proofs_of_a_broken_code_pass_and_the_object_does_not() {
    let budget = roomy();
    let good = honest();
    let mut shards = good.shards.clone();
    shards[5][0] ^= 1;
    let broken = tree_over(good.shape, shards);
    let frames = datagrams(&broken);

    for indices in [[0, 1, 2, 3], [1, 2, 3, 5], [2, 3, 4, 5]] {
        let mut assembler = assembler_on(&budget);
        let arrival = feed(&mut assembler, &frames, &indices, Instant::now());
        assert!(
            matches!(arrival, Arrival::Rejected(_)),
            "{indices:?}: {arrival:?}"
        );
        assert_eq!(assembler.state().open, 0);
    }
    assert_eq!(
        budget.used(),
        Used::default(),
        "a rejection returns everything"
    );
}

/// `k = 1` and a broken code, so one chunk is one rejection.
fn rejected_on_arrival(fill: u8) -> Vec<Vec<u8>> {
    let good = object(RAW, 2, 1, fill, 20);
    let mut shards = good.shards.clone();
    shards[1][0] ^= 1;
    datagrams(&tree_over(good.shape, shards))
}

fn rejected(arrival: Arrival) {
    assert!(
        matches!(arrival, Arrival::Rejected(_)),
        "expected a rejection, got {arrival:?}"
    );
}

/// The same bytes are not decoded again by this session.
#[test]
fn a_rejected_object_is_not_tried_again() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let good = honest();
    let mut shards = good.shards.clone();
    shards[0][0] ^= 1;
    let broken = tree_over(good.shape, shards);
    let frames = datagrams(&broken);
    assert!(matches!(
        feed(&mut assembler, &frames, &[0, 1, 2, 3], now),
        Arrival::Rejected(_)
    ));

    assert!(matches!(
        assembler.receive(&frames[4], now),
        Arrival::KnownBad
    ));
    assert!(matches!(
        assembler.receive(&frames[0], now),
        Arrival::KnownBad
    ));
    assert_eq!(assembler.state().open, 0);
}

/// A rejection said later, for content that turned out bad, stands for the object and
/// takes any of its spare chunks with it.
#[test]
fn a_rejection_from_above_closes_what_was_open() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let object = honest();
    let frames = datagrams(&object);
    pending(assembler.receive(&frames[0], now));

    assembler.reject(object.object_id, now);

    assert_eq!(assembler.state().open, 0);
    assert_eq!(budget.used(), idle());
    assert!(matches!(
        assembler.receive(&frames[1], now),
        Arrival::KnownBad
    ));
}

/// The same for spares: what the shelf holds of a bad object goes with it.
#[test]
fn a_rejection_from_above_clears_the_shelf_of_that_object() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let object = honest();
    let frames = datagrams(&object);
    assembler.receive_if(&frames[0], now, |_| Interest::Spare);
    assert_eq!(assembler.state().spares, 1);

    assembler.reject(object.object_id, now);

    assert_eq!(assembler.state().spares, 0);
    assert_eq!(budget.used(), idle());
}

/// Past its time a rejected record ends, and this is the whole of what it promises.
#[test]
fn known_gap_a_rejected_record_ends_and_the_bytes_are_tried_again() {
    let mut assembler = assembler_on(&roomy());
    let now = Instant::now();
    let frames = rejected_on_arrival(1);
    rejected(assembler.receive(&frames[0], now));

    rejected(assembler.receive(&frames[0], later(now, REJECTED_TTL)));
}

#[test]
fn known_gap_a_full_rejected_table_forgets_the_oldest() {
    let limits = AssemblerLimits {
        max_rejected: 1,
        ..assembler_limits()
    };
    let mut assembler = Assembler::new(verifier(), roomy(), limits).unwrap();
    let now = Instant::now();
    let (first, second) = (rejected_on_arrival(1), rejected_on_arrival(2));

    rejected(assembler.receive(&first[0], now));
    rejected(assembler.receive(&second[0], now));
    assert_eq!(assembler.state().rejected, 1);

    rejected(assembler.receive(&first[0], now));
}

/// A record that lapsed unnoticed and an object rejected again must not leave two entries.
/// The second only matters once the table is full: the oldest entry is then the old
/// record's turn, and taking it would end the new record ahead of older ones.
#[test]
fn an_object_rejected_again_keeps_one_record() {
    let limits = AssemblerLimits {
        max_rejected: 3,
        ..assembler_limits()
    };
    let mut assembler = Assembler::new(verifier(), roomy(), limits).unwrap();
    let start = Instant::now();
    let objects = [1, 2, 3, 4].map(rejected_on_arrival);
    let [first, second, third, fourth] = &objects;

    rejected(assembler.receive(&first[0], start));
    rejected(assembler.receive(&second[0], later(start, REJECTED_TTL / 2)));

    let now = later(start, REJECTED_TTL);
    rejected(assembler.receive(&first[0], now));
    rejected(assembler.receive(&third[0], now));
    rejected(assembler.receive(&fourth[0], now));

    assert!(
        matches!(assembler.receive(&first[0], now), Arrival::KnownBad),
        "the second object's record is older and goes first"
    );
    rejected(assembler.receive(&second[0], now));
}

// Padding.

fn tree_with_padding(shape: Shape, shards: &[Vec<u8>], padding: Vec<[u8; 32]>) -> Encoded {
    let mut leaves: Vec<[u8; 32]> = shards
        .iter()
        .enumerate()
        .map(|(at, shard)| {
            chunk_proof::tree::chunk_leaf(1, shape.msg_type, shape.n, shape.k, at as u16, shard)
        })
        .collect();
    leaves.extend(padding);
    let levels = levels(leaves);
    Encoded {
        shape,
        object_id: levels[levels.len() - 1][0],
        shards: shards.to_vec(),
        proofs: (0..shards.len()).map(|at| proof(&levels, at)).collect(),
    }
}

/// The difference from segments: any `k` chunks finish an object, so the one whose proof
/// covers the padding need not be among them. Every padding leaf of every shape up to 33
/// is changed in turn, and the first two chunks that pass decode and stop at the rebuild.
/// This is a sweep and not a proof.
#[test]
fn every_padding_leaf_is_caught_by_the_rebuild_without_the_last_chunk() {
    let verifier = verifier();
    let mut trees = 0;
    for n in 3..=33u16 {
        let good = object(RAW, n, 2, 10, 40);
        for changed in usize::from(n)..usize::from(n).next_power_of_two() {
            let mut padding = vec![empty_leaf(); changed - usize::from(n)];
            padding.push([7; 32]);
            let forged = tree_with_padding(good.shape, &good.shards, padding);
            assert_ne!(forged.object_id, good.object_id);

            let passing: Vec<Vec<u8>> = datagrams(&forged)
                .into_iter()
                .filter(|frame| verifier.verify(frame).is_ok())
                .take(2)
                .collect();
            assert_eq!(passing.len(), 2, "n {n}, leaf {changed}");

            let mut assembler = assembler_on(&roomy());
            let arrival = feed(&mut assembler, &passing, &[0, 1], Instant::now());
            assert!(
                matches!(arrival, Arrival::Rejected(ObjectError::Root)),
                "n {n}, leaf {changed}: {arrival:?}"
            );
            trees += 1;
        }
    }
    assert!(trees > 100, "the trees were tried: {trees}");
}

/// What one chunk cannot show: a chunk of other padding takes a slot under a root of its
/// own until the object is rejected. The canonical object is another object, and untouched.
#[test]
fn known_gap_chunks_of_other_padding_hold_an_assembly_until_it_is_rejected() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let good = object(RAW, 3, 2, 10, 40);
    let forged = tree_with_padding(good.shape, &good.shards, vec![[7; 32]]);
    let frames = datagrams(&forged);

    pending(assembler.receive(&frames[0], now));
    assert_eq!(assembler.state().open, 1);
    assert!(matches!(
        assembler.receive(&frames[2], now),
        Arrival::Invalid(ChunkError::Padding)
    ));
    assert!(matches!(
        assembler.receive(&frames[1], now),
        Arrival::Rejected(ObjectError::Root)
    ));

    let honest = datagrams(&good);
    let done = decoded(feed(&mut assembler, &honest, &[1, 2], now));
    assert_eq!(done.content(), content(10, 40));
}

// What a refusal does to an honest assembly in progress.

#[test]
fn a_full_table_moves_the_object_that_stopped_and_it_can_still_finish() {
    let (first, second) = (honest(), other());
    let budget = budget_with(1, 1 << 20, 1 << 22);
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&first);
    pending(feed(&mut assembler, &frames, &[0, 1], now));

    pending(assembler.receive(&datagram(&second, 0), now));

    let state = assembler.state();
    assert_eq!((state.open, state.spares), (1, 1));
    assert_eq!(
        assembler.have(&first.object_id),
        2,
        "nothing it had was lost"
    );
    assert_eq!(budget.used().objects, 1);
    let done = decoded(feed(&mut assembler, &frames, &[2, 3], now));
    assert_eq!(done.content(), content(10, 40));
    assert_eq!(assembler.have(&second.object_id), 1);
}

/// The object that waited longest is the one to move, so an object still taking chunks
/// keeps its place.
#[test]
fn the_object_still_taking_chunks_keeps_its_place() {
    let (first, second, third) = (honest(), other(), object(RAW, 6, 4, 3, 40));
    let budget = Budget::new(Limits {
        max_objects: 2,
        ..*roomy().limits()
    })
    .unwrap();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let (frames, moving) = (datagrams(&first), datagrams(&second));
    pending(assembler.receive(&frames[0], now));
    pending(assembler.receive(&moving[0], now));
    pending(assembler.receive(&frames[1], now));
    pending(assembler.receive(&moving[1], now));
    pending(assembler.receive(&frames[2], now));

    pending(assembler.receive(&datagram(&third, 0), now));

    assert_eq!(assembler.state().spares, 1, "the one that waited moved");
    assert_eq!(assembler.state().open, 2);
    assert_eq!(assembler.have(&second.object_id), 2);
    assert_eq!(assembler.have(&first.object_id), 3);
    let done = decoded(assembler.receive(&frames[3], now));
    assert_eq!(done.content(), content(10, 40));
}

/// What holds the budget here is not this session's to move, so nothing changes.
#[test]
fn a_full_table_of_decoded_content_refuses_and_leaves_everything_alone() {
    let (first, second) = (honest(), other());
    let budget = budget_with(8, held_bytes(&first.shape), 1 << 22);
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&first);
    let held = decoded(feed(&mut assembler, &frames, &[0, 1, 2, 3], now));
    let (state, used) = (assembler.state(), budget.used());

    assert!(matches!(
        assembler.receive(&datagram(&second, 0), now),
        Arrival::Refused(Refusal::HeldBytes)
    ));

    assert_nothing_changed(&assembler, &budget, state, used);
    drop(held);
}

/// Another session's objects are not this one's to move either.
#[test]
fn another_sessions_open_objects_stay_where_they_are() {
    let (first, second) = (honest(), other());
    let budget = budget_with(1, 1 << 20, 1 << 22);
    let (mut theirs, mut ours) = (assembler_on(&budget), assembler_on(&budget));
    let now = Instant::now();
    pending(theirs.receive(&datagram(&first, 0), now));

    assert!(matches!(
        ours.receive(&datagram(&second, 0), now),
        Arrival::Refused(Refusal::Objects)
    ));

    assert_eq!(theirs.state().open, 1);
}

/// A refusal leaves no mark. This is the fix for today's mark written before the room.
#[test]
fn a_refused_chunk_is_welcome_once_there_is_room() {
    let (first, second) = (honest(), other());
    let budget = budget_with(8, held_bytes(&first.shape), 1 << 22);
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&first);
    let held = decoded(feed(&mut assembler, &frames, &[0, 1, 2, 3], now));
    let refused = datagram(&second, 0);
    assert!(matches!(
        assembler.receive(&refused, now),
        Arrival::Refused(_)
    ));

    drop(held);

    pending(assembler.receive(&refused, now));
    let frames = datagrams(&second);
    let done = decoded(feed(&mut assembler, &frames, &[1, 2, 3], now));
    assert_eq!(done.content(), content(77, 40));
}

/// All of an object's bytes are taken at its first chunk, so half-filled objects cannot
/// use up the budget between them.
#[test]
fn an_object_that_was_let_in_always_has_its_bytes() {
    let (first, second) = (honest(), other());
    let held = held_bytes(&first.shape);
    let budget = budget_with(8, held, 1 << 22);
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&first);

    pending(assembler.receive(&frames[0], now));
    assert_eq!(budget.used().held_bytes, held, "all of it, at once");

    pending(assembler.receive(&datagram(&second, 0), now));
    assert_eq!(
        budget.used().held_bytes,
        held,
        "the second took the first's place"
    );

    let done = decoded(feed(&mut assembler, &frames, &[1, 2, 3], now));
    assert_eq!(done.content(), content(10, 40));
}

/// Another decode has the work budget. The chunk that would finish the object is refused
/// without being stored, the object stays as it was, and the same chunk finishes it later.
#[test]
fn the_last_chunk_waits_for_the_work_budget_and_loses_nothing() {
    let first = honest();
    let cost = work_bytes(&first.shape);
    let budget = budget_with(8, 1 << 20, cost);
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let frames = datagrams(&first);
    pending(feed(&mut assembler, &frames, &[0, 1, 2], now));
    let (state, used) = (assembler.state(), budget.used());

    let elsewhere = budget.work(1).unwrap();
    let during = budget.used();
    assert!(matches!(
        assembler.receive(&frames[3], now),
        Arrival::Refused(Refusal::WorkBytes)
    ));
    assert_nothing_changed(&assembler, &budget, state, during);

    drop(elsewhere);
    assert_eq!(budget.used(), used);
    let done = decoded(assembler.receive(&frames[3], now));
    assert_eq!(done.content(), content(10, 40));
}

/// `k = 1`: the first chunk needs both budgets, and a refusal of the second must not
/// leave the first behind.
#[test]
fn a_first_chunk_refused_for_work_leaves_no_hold() {
    let first = object(RAW, 2, 1, 3, 30);
    let cost = work_bytes(&first.shape);
    let budget = budget_with(8, 1 << 20, cost);
    let mut assembler = assembler_on(&budget);
    let elsewhere = budget.work(1).unwrap();
    let during = budget.used();

    assert!(matches!(
        assembler.receive(&datagram(&first, 0), Instant::now()),
        Arrival::Refused(Refusal::WorkBytes)
    ));

    assert_nothing_changed(&assembler, &budget, AssemblerState::default(), during);
    drop(elsewhere);
}

#[test]
fn a_shape_that_could_never_fit_takes_nothing() {
    let first = honest();
    let held = held_bytes(&first.shape);
    for budget in [
        budget_with(8, held - 1, 1 << 22),
        budget_with(8, 1 << 20, work_bytes(&first.shape) - 1),
    ] {
        let mut assembler = assembler_on(&budget);
        assert!(matches!(
            assembler.receive(&datagram(&first, 0), Instant::now()),
            Arrival::Refused(Refusal::NeverFits)
        ));
        assert_nothing_changed(&assembler, &budget, AssemblerState::default(), idle());
    }
}

/// The budget is one budget. A second session gets no more of it.
#[test]
fn two_assemblers_share_one_budget() {
    let (first, second) = (honest(), other());
    let budget = budget_with(1, 1 << 20, 1 << 22);
    let (mut one, mut two) = (assembler_on(&budget), assembler_on(&budget));
    let now = Instant::now();

    pending(one.receive(&datagram(&first, 0), now));
    assert!(matches!(
        two.receive(&datagram(&second, 0), now),
        Arrival::Refused(Refusal::Objects)
    ));
    assert_eq!(budget.used().objects, 1);
}

/// A sender with the key opens consistent objects of its own. They stop, so they give
/// way, and an honest object goes straight through.
#[test]
fn own_objects_that_stopped_cannot_hold_the_budget() {
    let budget = budget_with(2, 1 << 20, 1 << 22);
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    for fill in [1, 2] {
        pending(assembler.receive(&datagram(&object(RAW, 6, 4, fill, 40), 0), now));
    }
    let honest = honest();
    let frames = datagrams(&honest);

    let done = decoded(feed(&mut assembler, &frames, &[0, 1, 2, 3], now));

    assert_eq!(done.content(), content(10, 40));
}

/// A sender with the key that opens new objects faster than an honest object's chunks come
/// can push it out of its place and onto the shelf, and no further: past as many new objects
/// as there are places on both, the new ones are refused.
#[test]
fn a_flood_of_new_objects_cannot_push_an_open_object_off_the_shelf() {
    let (normal, shelf) = (2, 2);
    let budget = Budget::new(Limits {
        max_objects: normal,
        max_spare_objects: shelf,
        ..*roomy().limits()
    })
    .unwrap();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let honest = honest();
    let frames = datagrams(&honest);
    pending(feed(&mut assembler, &frames, &[0, 1], now));

    for fill in 0..normal + shelf - 1 {
        pending(assembler.receive(&datagram(&object(RAW, 6, 4, fill as u8, 40), 0), now));
    }
    assert_eq!(
        assembler.have(&honest.object_id),
        2,
        "one short of the limit"
    );

    let refused = assembler.receive(&datagram(&object(RAW, 6, 4, 200, 40), 0), now);
    assert!(
        matches!(refused, Arrival::Refused(Refusal::Objects)),
        "{refused:?}"
    );
    assert_eq!(assembler.have(&honest.object_id), 2);
}

// A spare's own way out. Making its place moves a stopped object to a full shelf, and the
// shelf's oldest goes then, which is often the spare that asked.

/// The places of one session on a node, as the relay has them today.
fn a_nodes_session() -> (Budget, Assembler) {
    let budget = Budget::new(Limits {
        max_sessions: 2,
        max_objects: 32,
        max_held_bytes: 1 << 20,
        max_work_bytes: 1 << 20,
        max_spare_objects: 8,
        max_spare_bytes: 1 << 18,
    })
    .unwrap();
    let assembler = assembler_on(&budget);
    (budget, assembler)
}

fn whole_object() -> Encoded {
    object(RAW, 13, 10, 250, 4000)
}

/// One chunk each of `count` objects that go no further.
fn crowd(assembler: &mut Assembler, count: usize, now: Instant) {
    for fill in 0..count {
        let stopped = object(RAW, 13, 10, fill as u8, 4000);
        pending(assembler.receive(&datagram(&stopped, 0), now));
    }
}

/// Spares with all it takes, kept for an owner.
fn shelve_whole(assembler: &mut Assembler, object: &Encoded, now: Instant) {
    for frame in &datagrams(object)[..usize::from(object.shape.k)] {
        let arrival = assembler.receive_if(frame, now, |_| Interest::Spare);
        assert!(matches!(arrival, Arrival::Spare { .. }), "{arrival:?}");
    }
}

fn due_only<'a>(wanted: &'a [Node]) -> impl FnMut(&Node) -> Interest + 'a {
    |id| {
        if wanted.contains(id) {
            Interest::Due
        } else {
            Interest::Spare
        }
    }
}

/// Nine chunks of an object, thirty-nine of others, and its tenth: everything is full, and
/// the object is the shelf's oldest as its last chunk comes.
#[test]
fn the_chunk_that_finishes_a_spare_does_not_push_it_off_the_shelf() {
    let (budget, mut assembler) = a_nodes_session();
    let now = Instant::now();
    let target = whole_object();
    let frames = datagrams(&target);
    for frame in &frames[..9] {
        pending(assembler.receive(frame, now));
    }
    crowd(&mut assembler, 39, now);
    assert_eq!(assembler.state().open, 32);
    assert_eq!(assembler.state().spares, 8);
    assert_eq!(assembler.have(&target.object_id), 9);

    let arrival = decoded(assembler.receive(&frames[9], now));

    assert_eq!(arrival.content(), &content(250, 4000)[..]);
    assert_eq!(assembler.state().open, 32, "nothing moved for it");
    assert_eq!(assembler.state().spares, 7, "and only it left the shelf");
    assert_eq!(budget.used().objects, 32);
    assert_eq!(budget.used().spare_objects, 7);
}

#[test]
fn a_decoded_object_stays_on_the_shelf_until_it_has_its_place() {
    let (_budget, mut assembler) = a_nodes_session();
    let now = Instant::now();
    let target = whole_object();
    let frames = datagrams(&target);
    let first = decoded(feed(
        &mut assembler,
        &frames,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        now,
    ));
    assert!(assembler.shelve_decoded(first, now));
    crowd(&mut assembler, 39, now);
    assert_eq!(assembler.state().spares, 8);

    let again = decoded(assembler.receive_if(&frames[0], now, |_| Interest::Due));

    assert_eq!(again.content(), &content(250, 4000)[..]);
}

#[test]
fn a_look_over_the_shelf_keeps_the_spare_it_is_decoding() {
    let (_budget, mut assembler) = a_nodes_session();
    let now = Instant::now();
    let target = whole_object();
    shelve_whole(&mut assembler, &target, now);
    crowd(&mut assembler, 39, now);
    assert_eq!(assembler.state().spares, 8);

    let wanted = [target.object_id];
    let mut arrivals = assembler.revive(now, due_only(&wanted));

    assert_eq!(arrivals.len(), 1);
    let arrival = decoded(arrivals.pop().unwrap());
    assert_eq!(arrival.content(), &content(250, 4000)[..]);
}

/// With the bytes short too, the first decode's place moves a stopped object, and that
/// costs the next spare on the list its own.
#[test]
fn a_look_over_the_shelf_passes_over_a_spare_that_has_gone() {
    let (first, second) = (whole_object(), object(RAW, 13, 10, 251, 4000));
    let budget = Budget::new(Limits {
        max_held_bytes: 32 * held_bytes(&first.shape),
        ..*a_nodes_session().0.limits()
    })
    .unwrap();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    shelve_whole(&mut assembler, &first, now);
    shelve_whole(&mut assembler, &second, now);
    crowd(&mut assembler, 38, now);
    assert_eq!(assembler.state().spares, 8);

    let wanted = [first.object_id, second.object_id];
    let mut arrivals = assembler.revive(now, due_only(&wanted));

    assert_eq!(arrivals.len(), 1);
    let arrival = decoded(arrivals.pop().unwrap());
    assert_eq!(arrival.object_id(), first.object_id);
    assert_eq!(assembler.have(&second.object_id), 0);
    assert_eq!(budget.used().spare_objects, assembler.state().spares);
}

/// A refusal is no reason to lose a place: the spare stays on the shelf with its shards and
/// its age, and the next look decodes it.
#[test]
fn a_decode_with_no_room_leaves_the_spare_where_it_was() {
    let (budget, mut assembler) = a_nodes_session();
    let now = Instant::now();
    let (first, second) = (whole_object(), object(RAW, 13, 10, 251, 4000));
    shelve_whole(&mut assembler, &first, now);
    shelve_whole(&mut assembler, &second, now);
    let on_the_shelf = budget.used();
    let room = budget.hold(budget.limits().max_held_bytes).unwrap();

    let wanted = [first.object_id];
    assert!(assembler.revive(now, due_only(&wanted)).is_empty());

    assert_eq!(assembler.have(&first.object_id), 10);
    assert_eq!(budget.used().spare_bytes, on_the_shelf.spare_bytes);
    assert_eq!(budget.used().spare_objects, on_the_shelf.spare_objects);

    drop(room);
    crowd(&mut assembler, 32 + 6, now);
    pending(assembler.receive(&datagram(&object(RAW, 13, 10, 252, 4000), 0), now));
    assert_eq!(
        assembler.have(&first.object_id),
        0,
        "it was still the oldest"
    );
    assert_eq!(assembler.have(&second.object_id), 10);
}

// Everything comes back.

#[test]
fn a_decoded_object_keeps_only_its_content_held() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let now = Instant::now();
    let object = honest();
    let frames = datagrams(&object);

    let done = decoded(feed(&mut assembler, &frames, &[0, 1, 2, 3], now));

    assert_eq!(
        budget.used(),
        Used {
            held_bytes: 40,
            ..idle()
        }
    );
    drop(done);
    assert_eq!(budget.used(), idle());
}

#[test]
fn dropping_the_assembler_returns_every_open_object() {
    let budget = roomy();
    let mut assembler = assembler_on(&budget);
    let frames = datagrams(&honest());
    pending(assembler.receive(&frames[0], Instant::now()));
    assert_ne!(budget.used(), idle());

    drop(assembler);

    assert_eq!(budget.used(), Used::default());
}

/// A reservation is a value, so an unwind returns it the same way a drop does, and a
/// poisoned lock does not stop that.
#[test]
fn an_unwind_returns_reservations() {
    let budget = roomy();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _hold = budget.hold(100).unwrap();
        let _work = budget.work(100).unwrap();
        panic!("stopped with both reservations out");
    }));

    assert!(result.is_err());
    assert_eq!(budget.used(), Used::default());
}

// Settings.

#[test]
fn a_limit_of_zero_is_refused() {
    let limits = Limits {
        max_sessions: 1,
        max_objects: 1,
        max_held_bytes: 1,
        max_work_bytes: 1,
        max_spare_objects: 1,
        max_spare_bytes: 1,
    };
    for (limits, name) in [
        (
            Limits {
                max_spare_objects: 0,
                ..limits
            },
            "max_spare_objects",
        ),
        (
            Limits {
                max_spare_bytes: 0,
                ..limits
            },
            "max_spare_bytes",
        ),
        (
            Limits {
                max_sessions: 0,
                ..limits
            },
            "max_sessions",
        ),
        (
            Limits {
                max_objects: 0,
                ..limits
            },
            "max_objects",
        ),
        (
            Limits {
                max_held_bytes: 0,
                ..limits
            },
            "max_held_bytes",
        ),
        (
            Limits {
                max_work_bytes: 0,
                ..limits
            },
            "max_work_bytes",
        ),
    ] {
        assert_eq!(Budget::new(limits).err(), Some(InvalidLimits(name)));
    }

    let make = |limits| Assembler::new(verifier(), roomy(), limits).err();
    let limits = assembler_limits();
    assert_eq!(
        make(AssemblerLimits {
            max_rejected: 0,
            ..limits
        }),
        Some(CannotStart("max_rejected"))
    );
    assert_eq!(
        make(AssemblerLimits {
            assembly_ttl: Default::default(),
            ..limits
        }),
        Some(CannotStart("assembly_ttl"))
    );
    assert_eq!(
        make(AssemblerLimits {
            rejected_ttl: Default::default(),
            ..limits
        }),
        Some(CannotStart("rejected_ttl"))
    );
}

#[test]
fn a_budget_bounds_how_many_assemblers_there_are() {
    let budget = Budget::new(Limits {
        max_sessions: 2,
        ..roomy_limits()
    })
    .unwrap();
    let start = || Assembler::new(verifier(), budget.clone(), assembler_limits());

    let (first, _second) = (start().unwrap(), start().unwrap());
    assert_eq!(start().err(), Some(CannotStart("sessions")));

    drop(first);
    assert!(start().is_ok());
}

// The research profile. It decides what is taken here, and nothing about the protocol.

fn shape(msg_type: u8, n: u16, k: u16) -> Shape {
    Shape {
        msg_type,
        n,
        k,
        s: 100,
    }
}

#[test]
fn the_research_profile_takes_the_shapes_the_relay_sends_today() {
    let research = Profile::Research;
    for (msg_type, n, k) in [
        (RAW, 2, 1),
        (RAW, 9, 8),
        (RAW, 11, 9),
        (RAW, 13, 10),
        (MSG_BLOCK, 13, 10),
        (MSG_BLOCK, 256, 227),
        (MSG_SKELETON, 3, 1),
        (MSG_SKELETON, 6, 4),
        (MSG_SKELETON, 12, 9),
        (MSG_SKELETON, 13, 10),
        (MSG_SKELETON, 255, 204),
    ] {
        assert!(research.allows(&shape(msg_type, n, k)), "({n}, {k})");
    }
}

#[test]
fn the_research_profile_refuses_the_rest() {
    let research = Profile::Research;
    for (msg_type, n, k) in [
        (RAW, 256, 1),
        (RAW, 256, 128),
        (RAW, 256, 255),
        (RAW, 3, 1),
        (RAW, 6, 4),
        (MSG_SKELETON, 2, 1),
        (MSG_SKELETON, 256, 255),
    ] {
        assert!(!research.allows(&shape(msg_type, n, k)), "({n}, {k})");
    }
}

/// The costly shape, kept as an attack. Under the profile it stops before the MAC at no
/// cost, and with every shape allowed the budget is all that stands in front of it.
#[test]
fn a_costly_shape_stays_outside_the_profile_and_inside_the_budget() {
    let costly = object(RAW, 256, 1, 3, 800);
    let frame = datagram(&costly, 0);
    let charge = work_bytes(&costly.shape);
    assert!(charge > 200 * costly.shards[0].len());

    let budget = roomy();
    let research = Verifier::new(KEY, Profile::Research);
    let mut assembler = Assembler::new(research, budget.clone(), assembler_limits()).unwrap();
    assert!(matches!(
        assembler.receive(&frame, Instant::now()),
        Arrival::Invalid(ChunkError::Profile)
    ));
    assert_nothing_changed(&assembler, &budget, AssemblerState::default(), idle());

    let small = budget_with(8, 1 << 20, charge - 1);
    assert!(matches!(
        assembler_on(&small).receive(&frame, Instant::now()),
        Arrival::Refused(Refusal::NeverFits)
    ));

    let enough = budget_with(8, 1 << 20, charge);
    let done = decoded(assembler_on(&enough).receive(&frame, Instant::now()));
    assert_eq!(done.content(), content(3, 800));
}
