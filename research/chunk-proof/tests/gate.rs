//! The rules of Ek A section 5, as a model. The Zebra answers are made up by each test, and
//! nothing here says what a real Zebra would answer.

use std::time::{Duration, Instant};

use chunk_proof::gate::{
    BodyGate, BodyIngress, Forward, GateLimits, Hash, IngressLimits, Reservation, Verdict,
};

const WINDOW: Duration = Duration::from_secs(120);
const BLOCK: Hash = [1; 32];
const WRONG: Hash = [2; 32];
const RIGHT: Hash = [3; 32];

fn gate() -> BodyGate {
    BodyGate::new(GateLimits {
        max_calls: 4,
        max_bodies: 2,
        max_blocks: 8,
        window: WINDOW,
    })
}

fn go(gate: &BodyGate, body: Hash, now: Instant) -> chunk_proof::gate::Attempt {
    match gate.reserve(BLOCK, body, now) {
        Reservation::Go(attempt) => attempt,
        other => panic!("expected an attempt, got {other:?}"),
    }
}

/// N1, the other way round: a body Zebra refused writes nothing, so the right one goes.
#[test]
fn a_refused_body_does_not_stop_the_right_one() {
    let (gate, now) = (gate(), Instant::now());
    go(&gate, WRONG, now).finish(Verdict::Refused, now);
    assert!(!gate.is_accepted(&BLOCK));

    go(&gate, RIGHT, now).finish(Verdict::Accepted, now);

    assert!(gate.is_accepted(&BLOCK));
    assert!(matches!(
        gate.reserve(BLOCK, WRONG, now),
        Reservation::Known
    ));
}

#[test]
fn two_bodies_of_one_block_run_side_by_side_and_the_same_bytes_merge() {
    let (gate, now) = (gate(), Instant::now());
    let first = go(&gate, WRONG, now);
    let second = go(&gate, RIGHT, now);

    assert!(matches!(
        gate.reserve(BLOCK, RIGHT, now),
        Reservation::Merged
    ));

    first.finish(Verdict::Refused, now);
    second.finish(Verdict::Accepted, now);
    assert!(gate.is_accepted(&BLOCK));
}

/// A cancel, a panic or a failed call writes nothing, and the next copy can try.
#[test]
fn an_attempt_that_is_dropped_or_fails_leaves_the_way_open() {
    let (gate, now) = (gate(), Instant::now());
    drop(go(&gate, RIGHT, now));
    go(&gate, RIGHT, now).finish(Verdict::Failed, now);

    assert!(!gate.is_accepted(&BLOCK));
    go(&gate, RIGHT, now).finish(Verdict::Accepted, now);
    assert!(gate.is_accepted(&BLOCK));
}

/// A late answer of an old attempt cannot touch a newer attempt's reservation, and what
/// Zebra knows is written however late it comes.
#[test]
fn a_late_result_leaves_a_new_attempt_alone() {
    let (gate, now) = (gate(), Instant::now());
    let old = go(&gate, RIGHT, now);
    old.time_out();
    let new = go(&gate, RIGHT, now);

    old.finish(Verdict::Refused, now);

    assert!(matches!(
        gate.reserve(BLOCK, RIGHT, now),
        Reservation::Merged
    ));
    new.finish(Verdict::Accepted, now);

    let (gate, now) = (self::gate(), Instant::now());
    let old = go(&gate, RIGHT, now);
    old.time_out();
    old.finish(Verdict::AlreadyKnown, now);
    assert!(gate.is_accepted(&BLOCK));
}

#[test]
fn calls_and_bodies_are_two_budgets() {
    let (gate, now) = (gate(), Instant::now());
    go(&gate, WRONG, now).finish(Verdict::Refused, now);
    go(&gate, RIGHT, now).finish(Verdict::Refused, now);

    assert!(matches!(
        gate.reserve(BLOCK, [9; 32], now),
        Reservation::OverBudget
    ));

    go(&gate, RIGHT, now).finish(Verdict::Refused, now);
    go(&gate, RIGHT, now).finish(Verdict::Refused, now);
    assert!(matches!(
        gate.reserve(BLOCK, RIGHT, now),
        Reservation::OverBudget
    ));

    go_after_window(&gate, now);
}

fn go_after_window(gate: &BodyGate, now: Instant) {
    assert!(matches!(
        gate.reserve(BLOCK, RIGHT, now + WINDOW),
        Reservation::Go(_)
    ));
}

#[test]
fn the_ring_of_blocks_is_bounded() {
    let gate = BodyGate::new(GateLimits {
        max_calls: 4,
        max_bodies: 2,
        max_blocks: 1,
        window: WINDOW,
    });
    let now = Instant::now();
    match gate.reserve([1; 32], RIGHT, now) {
        Reservation::Go(attempt) => attempt.finish(Verdict::Accepted, now),
        other => panic!("{other:?}"),
    }
    drop(gate.reserve([2; 32], WRONG, now));

    assert!(!gate.is_accepted(&[1; 32]), "the oldest went");
}

fn ingress() -> BodyIngress {
    BodyIngress::new(IngressLimits {
        max_bodies: 2,
        max_headers: 8,
        window: WINDOW,
    })
}

/// N2, the other way round: a second strict body of a header is forwarded.
#[test]
fn a_second_body_of_a_header_is_forwarded_and_the_same_bytes_are_not() {
    let (ingress, now) = (ingress(), Instant::now());
    let Forward::Go(first) = ingress.claim(BLOCK, WRONG, now) else {
        panic!("expected a claim");
    };
    first.sent();

    let Forward::Go(second) = ingress.claim(BLOCK, RIGHT, now) else {
        panic!("the right body has to get through");
    };
    assert!(matches!(
        ingress.claim(BLOCK, RIGHT, now),
        Forward::InFlight
    ));
    second.sent();

    assert!(matches!(
        ingress.claim(BLOCK, RIGHT, now),
        Forward::AlreadySent
    ));
}

/// A send that failed gives its place back, so it cannot hide a good copy.
#[test]
fn a_failed_forward_gives_its_place_back() {
    let (ingress, now) = (ingress(), Instant::now());
    drop(ingress.claim(BLOCK, WRONG, now));
    drop(ingress.claim(BLOCK, RIGHT, now));

    assert!(matches!(ingress.claim(BLOCK, [9; 32], now), Forward::Go(_)));
}

/// More than the budget of bodies for one header stops here. This is where a sender that
/// forges bodies can keep the right one out for a window, and it is a limit to choose.
#[test]
fn known_gap_a_full_budget_of_bodies_stops_a_further_body() {
    let (ingress, now) = (ingress(), Instant::now());
    for body in [[7; 32], [8; 32]] {
        let Forward::Go(claim) = ingress.claim(BLOCK, body, now) else {
            panic!("expected a claim");
        };
        claim.sent();
    }

    assert!(matches!(
        ingress.claim(BLOCK, RIGHT, now),
        Forward::OverBudget
    ));
    assert!(matches!(
        ingress.claim(BLOCK, RIGHT, now + WINDOW),
        Forward::Go(_)
    ));
}
