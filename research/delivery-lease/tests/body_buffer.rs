//! Bookkeeping of the body buffer, on frames from the honest test sender. The judge is
//! a stand-in that says what a test tells it to, and is not a node or a gate.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Body, SEGMENT, body, rules, sized};
use delivery_lease::body_buffer::{
    Arrival, AssembledBlock, AssemblyError, BodyBuffer, BufferLimits, CompleteSet, InvalidLimits,
    Outcome, Reject,
};
use delivery_lease::segment_frame::verify;
use delivery_lease::{Admission, DeliveryLedger, Limits, Phase, Refusal, Ticket, Transit};
use tokio::sync::{mpsc, oneshot};

const TTL: Duration = Duration::from_secs(120);

fn limits() -> Limits {
    Limits {
        max_records: 64,
        max_live_owners: 64,
        max_reserved_bytes: 64 * SEGMENT,
        repeat_budget: 2,
        completed_ttl: Duration::from_secs(300),
        released_ttl: Duration::from_secs(86_400),
        transit: Transit::default(),
    }
}

fn buffer_limits() -> BufferLimits {
    BufferLimits {
        max_sets: 8,
        max_sets_per_block: 4,
        max_segments: 32,
        ttl: TTL,
    }
}

fn buffer<W>() -> BodyBuffer<W> {
    BodyBuffer::new(buffer_limits()).unwrap()
}

fn id(body: &Body, index: usize) -> [u8; 32] {
    verify(&body.frames[index], &rules()).unwrap().ledger_key()
}

fn ticket(ledger: &DeliveryLedger, body: &Body, index: usize, now: Instant) -> Ticket {
    match ledger.admit(id(body, index), body.frames[index].len().min(SEGMENT), now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    }
}

fn seg(ledger: &DeliveryLedger, body: &Body, index: usize, now: Instant) -> Arrival {
    let segment = verify(&body.frames[index], &rules()).unwrap();
    Arrival::new(segment, ticket(ledger, body, index, now))
}

fn pending(buffer: &mut BodyBuffer, arrival: Arrival, now: Instant) {
    assert!(matches!(
        buffer.insert(arrival, now).outcome,
        Outcome::Pending
    ));
}

fn complete(buffer: &mut BodyBuffer, arrival: Arrival, now: Instant) -> CompleteSet {
    match buffer.insert(arrival, now).outcome {
        Outcome::Complete(set) => set,
        other => panic!("expected a whole set, got {other:?}"),
    }
}

fn phase(ledger: &DeliveryLedger, body: &Body, index: usize) -> Option<Phase> {
    ledger.observe(&id(body, index))
}

/// A whole body, assembled.
fn built(
    ledger: &DeliveryLedger,
    buffer: &mut BodyBuffer,
    body: &Body,
    now: Instant,
) -> AssembledBlock<Vec<u8>> {
    pending(buffer, seg(ledger, body, 0, now), now);
    let set = complete(buffer, seg(ledger, body, 1, now), now);
    set.assemble(ledger, now, |raw| raw).unwrap()
}

// Configuration.

#[test]
fn a_limit_of_zero_is_refused() {
    let new = |limits| BodyBuffer::<()>::new(limits).err();
    let base = buffer_limits();
    assert_eq!(
        new(BufferLimits {
            max_sets: 0,
            ..base
        }),
        Some(InvalidLimits("max_sets"))
    );
    assert_eq!(
        new(BufferLimits {
            max_sets_per_block: 0,
            ..base
        }),
        Some(InvalidLimits("max_sets_per_block"))
    );
    assert_eq!(
        new(BufferLimits {
            max_segments: 0,
            ..base
        }),
        Some(InvalidLimits("max_segments"))
    );
    assert_eq!(
        new(BufferLimits {
            ttl: Duration::ZERO,
            ..base
        }),
        Some(InvalidLimits("ttl"))
    );
    assert!(new(base).is_none());
}

/// The smallest valid buffer still holds to its limit.
#[test]
fn a_limit_of_one_holds() {
    let limits = BufferLimits {
        max_sets: 1,
        max_sets_per_block: 1,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let (first, second) = (body(1, 10), body(2, 10));
    pending(&mut buffer, seg(&ledger, &first, 0, now), now);

    let insertion = buffer.insert(seg(&ledger, &second, 0, now), now);

    assert_eq!(insertion.evicted, vec![first.key]);
    assert_eq!(buffer.sets(), 1);
}

// Two bodies of one header.

#[test]
fn two_bodies_of_a_header_fill_separate_sets_when_interleaved() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let (x, y) = (body(1, 10), body(1, 20));
    assert_eq!(x.key.block_hash, y.key.block_hash);
    assert_ne!(x.key.body_id, y.key.body_id);

    pending(&mut buffer, seg(&ledger, &x, 0, now), now);
    pending(&mut buffer, seg(&ledger, &y, 1, now), now);
    assert_eq!(buffer.sets(), 2);

    let set_x = complete(&mut buffer, seg(&ledger, &x, 1, now), now);
    let set_y = complete(&mut buffer, seg(&ledger, &y, 0, now), now);
    assert_eq!(buffer.sets(), 0);

    let block_x = set_x.assemble(&ledger, now, |raw| raw).unwrap();
    let block_y = set_y.assemble(&ledger, now, |raw| raw).unwrap();
    assert_eq!(
        *block_x.block(),
        x.raw,
        "nothing of the other body is in it"
    );
    assert_eq!(*block_y.block(), y.raw);
}

#[test]
fn discarding_one_body_leaves_the_other_as_it_was() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let (x, y) = (body(1, 10), body(1, 20));
    pending(&mut buffer, seg(&ledger, &x, 0, now), now);
    pending(&mut buffer, seg(&ledger, &y, 0, now), now);

    assert!(buffer.discard(&x.key));

    assert!(!buffer.holds(&x.key));
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
    assert!(buffer.holds(&y.key));
    assert_eq!(phase(&ledger, &y, 0), Some(Phase::Held));
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);

    let set = complete(&mut buffer, seg(&ledger, &y, 1, now), now);
    assert!(set.assemble(&ledger, now, |raw| raw).is_ok());
}

// Eviction.

#[test]
fn a_full_block_gives_up_its_least_advanced_set_and_no_other_blocks() {
    let limits = BufferLimits {
        max_sets_per_block: 2,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let other_block = body(9, 90);
    let advanced = sized(1, 10, 3 * SEGMENT);
    let (behind, new) = (body(1, 20), body(1, 30));
    pending(&mut buffer, seg(&ledger, &other_block, 0, now), now);
    pending(&mut buffer, seg(&ledger, &advanced, 0, now), now);
    pending(&mut buffer, seg(&ledger, &advanced, 1, now), now);
    pending(&mut buffer, seg(&ledger, &behind, 0, now), now);

    let insertion = buffer.insert(seg(&ledger, &new, 0, now), now);

    assert_eq!(insertion.evicted, vec![behind.key]);
    assert!(buffer.holds(&advanced.key));
    assert!(buffer.holds(&other_block.key));
    assert_eq!(phase(&ledger, &behind, 0), Some(Phase::Released));
    assert_eq!(phase(&ledger, &advanced, 1), Some(Phase::Held));
}

#[test]
fn the_older_of_two_equal_sets_goes_first() {
    let limits = BufferLimits {
        max_sets_per_block: 2,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let (older, newer, new) = (body(1, 10), body(1, 20), body(1, 30));
    pending(&mut buffer, seg(&ledger, &older, 0, now), now);
    pending(&mut buffer, seg(&ledger, &newer, 0, now), now);

    let insertion = buffer.insert(seg(&ledger, &new, 0, now), now);

    assert_eq!(insertion.evicted, vec![older.key]);
}

#[test]
fn the_set_limit_holds_across_blocks() {
    let limits = BufferLimits {
        max_sets: 2,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let (first, second, third) = (body(1, 10), body(2, 10), body(3, 10));
    pending(&mut buffer, seg(&ledger, &first, 0, now), now);
    pending(&mut buffer, seg(&ledger, &second, 0, now), now);

    let insertion = buffer.insert(seg(&ledger, &third, 0, now), now);

    assert_eq!(insertion.evicted, vec![first.key]);
    assert_eq!(buffer.sets(), 2);
    assert_eq!(ledger.snapshot().live_owners, 2);
}

#[test]
fn the_segment_limit_gives_up_other_sets_and_not_the_one_filling() {
    let limits = BufferLimits {
        max_segments: 2,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let (first, second) = (body(1, 10), body(2, 10));
    pending(&mut buffer, seg(&ledger, &first, 0, now), now);
    pending(&mut buffer, seg(&ledger, &second, 0, now), now);

    let insertion = buffer.insert(seg(&ledger, &second, 1, now), now);

    assert_eq!(insertion.evicted, vec![first.key]);
    assert!(matches!(insertion.outcome, Outcome::Complete(_)));
    assert_eq!(buffer.segments(), 0);
}

#[test]
fn a_set_that_could_never_fit_is_refused_and_evicts_nothing() {
    let limits = BufferLimits {
        max_segments: 2,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let held = body(1, 10);
    let huge = sized(2, 10, 3 * SEGMENT);
    pending(&mut buffer, seg(&ledger, &held, 0, now), now);

    let insertion = buffer.insert(seg(&ledger, &huge, 0, now), now);

    assert!(matches!(
        insertion.outcome,
        Outcome::Rejected(Reject::TooManySegments)
    ));
    assert!(insertion.evicted.is_empty());
    assert!(buffer.holds(&held.key));
    assert_eq!(phase(&ledger, &huge, 0), Some(Phase::Released));
}

// TTL.

#[test]
fn the_ttl_ends_a_set_at_its_age_and_only_that_set() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let (old, young) = (body(1, 10), body(1, 20));
    pending(&mut buffer, seg(&ledger, &old, 0, now), now);
    let later = now + Duration::from_secs(1);
    pending(&mut buffer, seg(&ledger, &young, 0, later), later);

    assert!(buffer.expire(now + TTL - Duration::from_secs(1)).is_empty());

    assert_eq!(buffer.expire(now + TTL), vec![old.key]);
    assert_eq!(phase(&ledger, &old, 0), Some(Phase::Released));
    assert_eq!(phase(&ledger, &young, 0), Some(Phase::Held));
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);
    assert_eq!(buffer.segments(), 1);
}

// Assembly.

#[test]
fn the_copy_is_reserved_before_it_is_made() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    pending(&mut buffer, seg(&ledger, &x, 0, now), now);
    let set = complete(&mut buffer, seg(&ledger, &x, 1, now), now);
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);

    let seen = ledger.clone();
    let block = set
        .assemble(&ledger, now, |raw| {
            assert_eq!(
                seen.snapshot().reserved_bytes,
                4 * SEGMENT,
                "both copies are alive and both are counted"
            );
            raw
        })
        .unwrap();

    assert_eq!(*block.block(), x.raw);
    assert_eq!(block.holds_segments(), 2);
    assert_eq!(ledger.snapshot().reserved_bytes, 4 * SEGMENT);
    assert_eq!(ledger.snapshot().live_owners, 3);
    assert_eq!(
        ledger.snapshot().completed,
        0,
        "assembling finishes nothing"
    );
}

#[test]
fn a_copy_that_does_not_fit_gives_the_whole_set_back() {
    let limits = Limits {
        max_reserved_bytes: 3 * SEGMENT,
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    pending(&mut buffer, seg(&ledger, &x, 0, now), now);
    let set = complete(&mut buffer, seg(&ledger, &x, 1, now), now);

    assert_eq!(
        set.assemble(&ledger, now, |raw| raw).err(),
        Some(AssemblyError::Refused(Refusal::Bytes))
    );

    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
}

#[test]
fn the_owner_limit_covers_the_block_as_well() {
    let limits = Limits {
        max_live_owners: 2,
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    pending(&mut buffer, seg(&ledger, &x, 0, now), now);
    let set = complete(&mut buffer, seg(&ledger, &x, 1, now), now);

    assert_eq!(
        set.assemble(&ledger, now, |raw| raw).err(),
        Some(AssemblyError::Refused(Refusal::Owners))
    );
    assert_eq!(ledger.snapshot().live_owners, 0);
}

// Handing a block on. The judge is a real task and says what the test tells it to.

#[derive(Clone, Copy)]
enum Verdict {
    Accept,
    Refuse,
    Fail,
}

/// One of the two choices the tests compare. `GiveBack` is the research assumption.
#[derive(Clone, Copy)]
enum AfterRefusal {
    GiveBack,
    Finish,
}

type Handed = (AssembledBlock<Vec<u8>>, Verdict, oneshot::Sender<()>);

fn judge(after_refusal: AfterRefusal) -> (mpsc::Sender<Handed>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Handed>(1);
    let task = tokio::spawn(async move {
        while let Some((block, verdict, done)) = rx.recv().await {
            match (verdict, after_refusal) {
                (Verdict::Accept, _) | (Verdict::Refuse, AfterRefusal::Finish) => {
                    block.finish(Instant::now());
                }
                (Verdict::Refuse, AfterRefusal::GiveBack) | (Verdict::Fail, _) => {
                    block.give_back();
                }
            }
            done.send(()).unwrap();
        }
    });
    (tx, task)
}

async fn hand(judge: &mpsc::Sender<Handed>, block: AssembledBlock<Vec<u8>>, verdict: Verdict) {
    let (done, finished) = oneshot::channel();
    judge
        .send((block, verdict, done))
        .await
        .map_err(|_| ())
        .unwrap();
    finished.await.unwrap();
}

#[tokio::test]
async fn while_a_block_is_out_its_segments_are_not_delivered_again() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    let block = built(&ledger, &mut buffer, &x, now);

    assert!(matches!(
        ledger.admit(id(&x, 0), SEGMENT, now),
        Admission::Owned(Phase::Held)
    ));

    let (tx, task) = judge(AfterRefusal::GiveBack);
    hand(&tx, block, Verdict::Refuse).await;
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    drop(tx);
    task.await.unwrap();
}

/// The other choice: the bytes come back early, and a whole set made of copies finds the
/// body in someone's hands and is given back.
#[test]
fn releasing_the_segments_early_lets_copies_meet_the_owned_block() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    let mut block = built(&ledger, &mut buffer, &x, now);

    block.release_segments();
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);

    pending(&mut buffer, seg(&ledger, &x, 0, now), now);
    let set = complete(&mut buffer, seg(&ledger, &x, 1, now), now);
    assert_eq!(
        set.assemble(&ledger, now, |raw| raw).err(),
        Some(AssemblyError::Owned(Phase::Held))
    );
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
    block.give_back();
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

/// Giving a refused body back lets it return, and each return spends the repeats of all
/// its objects. It stops when they run out, whether or not the body was the right one.
#[tokio::test]
async fn a_body_given_back_returns_until_its_repeats_run_out() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    let (tx, task) = judge(AfterRefusal::GiveBack);

    for _ in 0..=limits().repeat_budget {
        let block = built(&ledger, &mut buffer, &x, now);
        hand(&tx, block, Verdict::Refuse).await;
    }

    assert!(matches!(
        ledger.admit(id(&x, 0), SEGMENT, now),
        Admission::Refused(Refusal::RepeatBudget)
    ));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    drop(tx);
    task.await.unwrap();
}

/// A failed call is treated like the refusal above here: the body returns.
#[tokio::test]
async fn a_body_returns_after_a_failed_call_and_can_then_be_accepted() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    let (tx, task) = judge(AfterRefusal::GiveBack);

    let block = built(&ledger, &mut buffer, &x, now);
    hand(&tx, block, Verdict::Fail).await;
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));

    let block = built(&ledger, &mut buffer, &x, now);
    hand(&tx, block, Verdict::Accept).await;

    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Completed));
    assert_eq!(ledger.observe(&x.key.body_id), Some(Phase::Completed));
    assert!(matches!(
        ledger.admit(id(&x, 0), SEGMENT, now),
        Admission::Completed
    ));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    drop(tx);
    task.await.unwrap();
}

/// Finishing on a refusal shuts the same bytes out for the whole completed window, which
/// is the refusal cache this design left out. If the refusal was passing, the right body
/// stays out too. Shown so the cost is visible. It is not the default.
#[tokio::test]
async fn finishing_a_refused_body_shuts_it_out_until_the_record_ends() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    let (tx, task) = judge(AfterRefusal::Finish);

    let block = built(&ledger, &mut buffer, &x, now);
    hand(&tx, block, Verdict::Refuse).await;

    assert!(matches!(
        ledger.admit(id(&x, 0), SEGMENT, Instant::now()),
        Admission::Completed
    ));
    let after = Instant::now() + limits().completed_ttl;
    assert!(matches!(
        ledger.admit(id(&x, 0), SEGMENT, after),
        Admission::Admitted(_)
    ));
    drop(tx);
    task.await.unwrap();
}

#[tokio::test]
async fn refusing_one_body_leaves_the_other_of_its_header_alone() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let (bad, good) = (body(1, 10), body(1, 20));
    let (tx, task) = judge(AfterRefusal::GiveBack);

    pending(&mut buffer, seg(&ledger, &bad, 0, now), now);
    pending(&mut buffer, seg(&ledger, &good, 0, now), now);
    let set = complete(&mut buffer, seg(&ledger, &bad, 1, now), now);
    let block = set.assemble(&ledger, now, |raw| raw).unwrap();

    hand(&tx, block, Verdict::Refuse).await;

    assert_eq!(phase(&ledger, &bad, 0), Some(Phase::Released));
    assert_eq!(phase(&ledger, &good, 0), Some(Phase::Held));
    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);

    let set = complete(&mut buffer, seg(&ledger, &good, 1, now), now);
    let block = set.assemble(&ledger, now, |raw| raw).unwrap();
    hand(&tx, block, Verdict::Accept).await;

    assert_eq!(ledger.observe(&good.key.body_id), Some(Phase::Completed));
    assert_eq!(ledger.observe(&bad.key.body_id), Some(Phase::Released));
    drop(tx);
    task.await.unwrap();
}

#[test]
fn nothing_comes_back_for_an_evicted_body_without_its_segments() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = buffer();
    let x = body(1, 10);
    pending(&mut buffer, seg(&ledger, &x, 0, now), now);

    assert!(buffer.discard(&x.key));

    assert_eq!(buffer.sets(), 0);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
    assert_eq!(ledger.snapshot().live_owners, 0);
}

// Tasks ending.

#[tokio::test]
async fn a_closed_channel_gives_back_an_arrival() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let x = body(1, 10);
    let (tx, rx) = mpsc::channel(2);
    tx.try_send(seg(&ledger, &x, 0, now))
        .map_err(|_| ())
        .unwrap();

    drop(rx);

    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Released));
}

#[tokio::test]
async fn an_aborted_task_gives_back_its_buffer() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let x = body(1, 10);
    let (tx, mut rx) = mpsc::channel::<(Arrival, oneshot::Sender<()>)>(1);
    let consumer = tokio::spawn(async move {
        let mut buffer = buffer();
        while let Some((arrival, done)) = rx.recv().await {
            pending(&mut buffer, arrival, Instant::now());
            done.send(()).unwrap();
        }
    });
    let (done, taken) = oneshot::channel();
    tx.send((seg(&ledger, &x, 0, now), done))
        .await
        .map_err(|_| ())
        .unwrap();
    taken.await.unwrap();
    assert_eq!(phase(&ledger, &x, 0), Some(Phase::Held));

    consumer.abort();

    assert!(consumer.await.unwrap_err().is_cancelled());
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
    assert_eq!(ledger.snapshot().live_owners, 0);
}

// Payload before reservation, on every path. A probe sits between the payload and the
// lease and reads the ledger as it dies.

#[derive(Clone)]
struct Probe {
    ledger: DeliveryLedger,
    seen: Arc<Mutex<Vec<usize>>>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        let reserved = self.ledger.snapshot().reserved_bytes;
        self.seen.lock().unwrap().push(reserved);
    }
}

fn probed(
    ledger: &DeliveryLedger,
    seen: &Arc<Mutex<Vec<usize>>>,
    body: &Body,
    index: usize,
    now: Instant,
) -> Arrival<Probe> {
    let probe = Probe {
        ledger: ledger.clone(),
        seen: Arc::clone(seen),
    };
    let segment = verify(&body.frames[index], &rules()).unwrap();
    Arrival::with_witness(segment, ticket(ledger, body, index, now), probe)
}

/// Each probe must have seen its own reservation still counted.
fn assert_died_first(seen: &Arc<Mutex<Vec<usize>>>, expected: &[usize]) {
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen, expected);
}

#[test]
fn a_refused_segment_dies_before_its_reservation() {
    let limits = BufferLimits {
        max_segments: 2,
        ..buffer_limits()
    };
    let (ledger, now) = (DeliveryLedger::new(self::limits()), Instant::now());
    let seen = Arc::default();
    let mut buffer = BodyBuffer::new(limits).unwrap();
    let huge = sized(1, 10, 3 * SEGMENT);

    let _ = buffer.insert(probed(&ledger, &seen, &huge, 0, now), now);

    assert_died_first(&seen, &[SEGMENT]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[test]
fn a_discarded_set_dies_before_its_reservations() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let seen = Arc::default();
    let mut buffer = buffer();
    let x = body(1, 10);
    let _ = buffer.insert(probed(&ledger, &seen, &x, 0, now), now);

    assert!(buffer.discard(&x.key));

    assert_died_first(&seen, &[SEGMENT]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[test]
fn an_expired_set_dies_before_its_reservations() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let seen = Arc::default();
    let mut buffer = buffer();
    let _ = buffer.insert(probed(&ledger, &seen, &body(1, 10), 0, now), now);

    assert_eq!(buffer.expire(now + TTL).len(), 1);

    assert_died_first(&seen, &[SEGMENT]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[test]
fn a_dropped_buffer_dies_before_its_reservations() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let seen = Arc::default();
    let mut buffer = buffer();
    let _ = buffer.insert(probed(&ledger, &seen, &body(1, 10), 0, now), now);

    drop(buffer);

    assert_died_first(&seen, &[SEGMENT]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[test]
fn a_queued_arrival_dies_before_its_reservation() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let seen = Arc::default();
    let arrival = probed(&ledger, &seen, &body(1, 10), 0, now);

    drop(arrival);

    assert_died_first(&seen, &[SEGMENT]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

/// Assembly lets the segments' payloads go with their leases still alive, then the block
/// goes before its lease.
#[test]
fn an_assembled_block_lets_go_in_order() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let seen = Arc::default();
    let mut buffer = buffer();
    let x = body(1, 10);
    let _ = buffer.insert(probed(&ledger, &seen, &x, 0, now), now);
    let insertion = buffer.insert(probed(&ledger, &seen, &x, 1, now), now);
    let Outcome::Complete(set) = insertion.outcome else {
        panic!("expected a whole set");
    };
    let block_probe = Probe {
        ledger: ledger.clone(),
        seen: Arc::clone(&seen),
    };

    let block = set
        .assemble(&ledger, now, |raw| (raw, block_probe))
        .unwrap();
    assert_died_first(&seen, &[4 * SEGMENT, 4 * SEGMENT]);

    block.give_back();

    assert_died_first(&seen, &[4 * SEGMENT, 4 * SEGMENT, 4 * SEGMENT]);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}
