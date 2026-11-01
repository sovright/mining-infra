//! A budget inside a shared one: what a node's sessions have in common. The limits of one
//! session stand, and the sum has a limit of its own.

use std::time::{Duration, Instant};

use chunk_proof::assembler::{Arrival, Assembler, AssemblerLimits, Interest};
use chunk_proof::budget::{Budget, Limits, Refusal, Used};
use chunk_proof::datagram::{Verifier, seal};
use chunk_proof::object::{Encoded, MSG_RAW_SEGMENT, Profile, encode, held_bytes};

const KEY: [u8; 32] = [7; 32];
const BYTES: usize = 1000;

fn limits() -> Limits {
    Limits {
        max_sessions: 4,
        max_objects: 4,
        max_held_bytes: 1 << 20,
        max_work_bytes: 1 << 20,
        max_spare_objects: 4,
        max_spare_bytes: 1 << 20,
    }
}

fn assembler_limits() -> AssemblerLimits {
    AssemblerLimits {
        max_rejected: 8,
        assembly_ttl: Duration::from_secs(30),
        rejected_ttl: Duration::from_secs(120),
        max_content: |_| 1 << 16,
    }
}

fn session(budget: Budget) -> Assembler {
    Assembler::new(
        Verifier::new(KEY, Profile::Research),
        budget,
        assembler_limits(),
    )
    .unwrap()
}

fn object(fill: u8) -> Encoded {
    encode(MSG_RAW_SEGMENT, 13, 10, &vec![fill; 5000]).unwrap()
}

fn datagrams(object: &Encoded) -> Vec<Vec<u8>> {
    let pairs = object.shards.iter().zip(&object.proofs).zip(0u16..);
    pairs
        .map(|((shard, proof), index)| {
            seal(&KEY, &object.shape, &object.object_id, index, proof, shard)
        })
        .collect()
}

#[test]
fn every_reservation_counts_in_both_and_comes_back_from_both() {
    let pool = Budget::new(limits()).unwrap();
    let budget = Budget::within(limits(), &pool).unwrap();

    let session = budget.session().unwrap();
    let hold = budget.hold(BYTES).unwrap();
    let work = budget.work(BYTES).unwrap();
    let shelved = budget.shelve(BYTES).unwrap();
    let held = Used {
        sessions: 1,
        objects: 1,
        held_bytes: BYTES,
        work_bytes: BYTES,
        spare_objects: 1,
        spare_bytes: BYTES,
    };
    assert_eq!(pool.used(), held);
    assert_eq!(budget.used(), held);

    drop((session, hold, work, shelved));
    assert_eq!(pool.used(), Used::default());
    assert_eq!(budget.used(), Used::default());
}

#[test]
fn the_shared_limit_stops_what_each_budget_alone_would_take() {
    let shared = Limits {
        max_sessions: 3,
        max_objects: 3,
        max_held_bytes: 3 * BYTES,
        max_work_bytes: 3 * BYTES,
        max_spare_objects: 3,
        max_spare_bytes: 3 * BYTES,
    };
    let pool = Budget::new(shared).unwrap();
    let (one, other) = (
        Budget::within(limits(), &pool).unwrap(),
        Budget::within(limits(), &pool).unwrap(),
    );
    let (mut holds, mut works, mut shelves, mut sessions) = (vec![], vec![], vec![], vec![]);
    for budget in [&one, &other, &one] {
        holds.push(budget.hold(BYTES).unwrap());
        works.push(budget.work(BYTES).unwrap());
        shelves.push(budget.shelve(BYTES).unwrap());
        sessions.push(budget.session().unwrap());
    }

    assert!(matches!(other.hold(BYTES), Err(Refusal::Shared)));
    assert!(matches!(other.work(BYTES), Err(Refusal::Shared)));
    assert!(matches!(other.shelve(BYTES), Err(Refusal::Spares)));
    assert!(matches!(other.session(), Err(Refusal::Sessions)));
}

/// A refusal from the pool gives back what the session had just taken.
#[test]
fn a_refusal_from_the_pool_leaves_nothing_counted() {
    let shared = Limits {
        max_sessions: 1,
        max_objects: 1,
        max_held_bytes: BYTES,
        max_work_bytes: BYTES,
        max_spare_objects: 1,
        max_spare_bytes: BYTES,
    };
    let pool = Budget::new(shared).unwrap();
    let budget = Budget::within(limits(), &pool).unwrap();
    let before = budget.used();

    let _taken = (
        pool.hold(BYTES).unwrap(),
        pool.work(BYTES).unwrap(),
        pool.shelve(BYTES).unwrap(),
        pool.session().unwrap(),
    );
    assert!(budget.hold(1).is_err());
    assert!(budget.work(1).is_err());
    assert!(budget.shelve(1).is_err());
    assert!(budget.session().is_err());

    assert_eq!(budget.used(), before);
}

#[test]
fn a_session_cannot_pass_its_own_limit_on_the_pools_room() {
    let pool = Budget::new(limits()).unwrap();
    let small = Limits {
        max_objects: 1,
        ..limits()
    };
    let budget = Budget::within(small, &pool).unwrap();
    let _hold = budget.hold(BYTES).unwrap();

    assert!(matches!(budget.hold(BYTES), Err(Refusal::Objects)));
    assert_eq!(pool.used().objects, 1);
}

/// A shelf place that grows past the pool stops there, and counts nothing of what it asked.
#[test]
fn a_shelf_that_grows_counts_in_both_or_neither() {
    let object = object(1);
    let shard = usize::from(object.shape.s);
    let first = held_bytes(&object.shape) - usize::from(object.shape.k) * shard + shard;
    let pool = Budget::new(Limits {
        max_spare_bytes: first + 2 * shard,
        ..limits()
    })
    .unwrap();
    let budget = Budget::within(limits(), &pool).unwrap();
    let mut session = session(budget.clone());
    let now = Instant::now();

    for datagram in &datagrams(&object)[..4] {
        let _ = session.receive_if(datagram, now, |_| Interest::Spare);
    }

    assert_eq!(pool.used().spare_bytes, first + 2 * shard);
    assert_eq!(budget.used().spare_bytes, first + 2 * shard);
}

/// Decoded content stays counted in the pool, and stops counting as an open object.
#[test]
fn a_decoded_object_settles_in_both() {
    let pool = Budget::new(limits()).unwrap();
    let budget = Budget::within(limits(), &pool).unwrap();
    let mut session = session(budget.clone());
    let now = Instant::now();
    let object = object(1);
    let mut decoded = None;

    for datagram in &datagrams(&object)[..10] {
        if let Arrival::Decoded(content) = session.receive(datagram, now) {
            decoded = Some(content);
        }
    }

    let decoded = decoded.expect("ten shards decode");
    assert_eq!(pool.used().objects, 0);
    assert_eq!(pool.used().held_bytes, decoded.content().len());
    assert_eq!(budget.used().held_bytes, decoded.content().len());
    drop(decoded);
    assert_eq!(pool.used().held_bytes, 0);
}

/// Rule 6 with the pool as the limit: a session's own stopped object moves for its new one.
#[test]
fn a_session_the_pool_refuses_moves_its_own_stopped_object() {
    let pool = Budget::new(Limits {
        max_objects: 1,
        ..limits()
    })
    .unwrap();
    let budget = Budget::within(limits(), &pool).unwrap();
    let mut session = session(budget);
    let now = Instant::now();
    let (stopped, next) = (object(1), object(2));

    let opened = session.receive(&datagrams(&stopped)[0], now);
    assert!(matches!(opened, Arrival::Pending { .. }), "{opened:?}");
    let moved = session.receive(&datagrams(&next)[0], now);

    assert!(matches!(moved, Arrival::Pending { .. }), "{moved:?}");
    assert_eq!(session.state().open, 1);
    assert_eq!(session.state().spares, 1);
}

/// Another session's object in the pool is not this session's to move.
#[test]
fn a_session_cannot_move_another_sessions_object_by_itself() {
    let pool = Budget::new(Limits {
        max_objects: 1,
        ..limits()
    })
    .unwrap();
    let mut one = session(Budget::within(limits(), &pool).unwrap());
    let mut other = session(Budget::within(limits(), &pool).unwrap());
    let now = Instant::now();

    let _ = one.receive(&datagrams(&object(1))[0], now);
    let refused = other.receive(&datagrams(&object(2))[0], now);

    assert!(
        matches!(refused, Arrival::Refused(Refusal::Shared)),
        "{refused:?}"
    );
    assert_eq!(one.state().open, 1);
}

/// What gives way is moved and not lost: the rest of its chunks still finish it.
#[test]
fn an_object_that_gives_way_can_still_finish() {
    let pool = Budget::new(limits()).unwrap();
    let mut session = session(Budget::within(limits(), &pool).unwrap());
    let now = Instant::now();
    let object = object(1);
    let chunks = datagrams(&object);
    for datagram in &chunks[..9] {
        let _ = session.receive(datagram, now);
    }

    assert!(session.give_way());
    assert_eq!(session.state().open, 0);
    assert_eq!(pool.used().objects, 0);

    let finished = session.receive(&chunks[9], now);
    assert!(matches!(finished, Arrival::Decoded(_)), "{finished:?}");
}

#[test]
fn nothing_open_means_nothing_gives_way() {
    let pool = Budget::new(limits()).unwrap();
    let mut session = session(Budget::within(limits(), &pool).unwrap());

    assert!(!session.give_way());
}
