//! Each test sets its order with a barrier, a bounded channel, a manual poll or a
//! request and reply to a real consumer task. Time is an argument, so no test sleeps.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use delivery_lease::{
    Admission, DeliveryLedger, Lease, Limits, ObjectId, Phase, Refusal, Snapshot, Ticket, Transit,
};
use tokio::sync::{Barrier, mpsc, oneshot};

const BYTES: usize = 100;
const A: ObjectId = [0xa0; 32];
const B: ObjectId = [0xb0; 32];

fn limits() -> Limits {
    Limits {
        max_records: 16,
        max_live_owners: 16,
        max_reserved_bytes: 16 * BYTES,
        repeat_budget: 2,
        completed_ttl: Duration::from_secs(120),
        released_ttl: Duration::from_secs(86_400),
        transit: Transit::default(),
    }
}

fn ledger() -> DeliveryLedger {
    DeliveryLedger::new(limits())
}

fn id(body: u8, segment: u8) -> ObjectId {
    let mut id = [body; 32];
    id[31] = segment;
    id
}

fn admitted(ledger: &DeliveryLedger, id: ObjectId, now: Instant) -> Ticket {
    match ledger.admit(id, BYTES, now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    }
}

fn held(ledger: &DeliveryLedger, id: ObjectId, now: Instant) -> Lease {
    admitted(ledger, id, now).accept()
}

// 1. A copy and an eviction at the same moment.

#[test]
fn a_copy_checked_before_the_eviction_is_refused_and_lost() {
    let (ledger, now) = (ledger(), Instant::now());
    let lease = held(&ledger, A, now);

    assert!(matches!(
        ledger.admit(A, BYTES, now),
        Admission::Owned(Phase::Held)
    ));
    drop(lease);

    assert_eq!(ledger.observe(&A), Some(Phase::Released));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[test]
fn a_copy_checked_after_the_eviction_is_admitted() {
    let (ledger, now) = (ledger(), Instant::now());
    let lease = held(&ledger, A, now);
    let first = lease.generation();

    drop(lease);

    let ticket = admitted(&ledger, A, now);
    assert!(ticket.generation() > first);
}

/// Real threads, each round released by a barrier. The order is not chosen, so this
/// asserts that only the two orders above can happen, not that both did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_racing_copy_and_eviction_end_in_one_of_the_two_orders() {
    let (mut copy_first, mut eviction_first) = (0, 0);
    for _ in 0..2_000 {
        let (ledger, now) = (ledger(), Instant::now());
        let lease = held(&ledger, A, now);
        let start = Arc::new(Barrier::new(2));

        let evict = tokio::spawn({
            let start = Arc::clone(&start);
            async move {
                start.wait().await;
                drop(lease);
            }
        });
        let copy = tokio::spawn({
            let ledger = ledger.clone();
            async move {
                start.wait().await;
                ledger.admit(A, BYTES, now)
            }
        });
        evict.await.unwrap();
        match copy.await.unwrap() {
            Admission::Owned(Phase::Held) => {
                copy_first += 1;
                assert_eq!(ledger.observe(&A), Some(Phase::Released));
                assert_eq!(ledger.snapshot().reserved_bytes, 0);
            }
            Admission::Admitted(ticket) => {
                eviction_first += 1;
                assert_eq!(ledger.observe(&A), Some(Phase::InFlight));
                assert_eq!(ledger.snapshot().reserved_bytes, BYTES);
                drop(ticket);
            }
            other => panic!("a third outcome: {other:?}"),
        }
    }
    eprintln!("copy first {copy_first}, eviction first {eviction_first}");
}

// 2. Waiting in the queue: cancelled, or the channel closes.

#[test]
fn a_cancelled_send_releases_the_object_and_holds_no_lock_meanwhile() {
    let (ledger, now) = (ledger(), Instant::now());
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(admitted(&ledger, B, now)).unwrap();

    let mut send = tokio_test::task::spawn(tx.send(admitted(&ledger, A, now)));
    assert!(send.poll().is_pending(), "the channel is full");
    assert_eq!(ledger.observe(&A), Some(Phase::InFlight));

    // The send is parked and owns the ticket. A held lock would deadlock these calls.
    let other = id(0xc0, 0);
    assert!(matches!(
        ledger.admit(other, BYTES, now),
        Admission::Admitted(_)
    ));
    assert_eq!(ledger.observe(&other), Some(Phase::Released));

    drop(send);
    assert_eq!(ledger.observe(&A), Some(Phase::Released));

    let queued = rx.try_recv().unwrap();
    assert_eq!(queued.id(), B);
    assert_eq!(ledger.observe(&B), Some(Phase::InFlight));
}

#[test]
fn a_closed_channel_releases_every_queued_ticket() {
    let (ledger, now) = (ledger(), Instant::now());
    let (tx, rx) = mpsc::channel(4);
    tx.try_send(admitted(&ledger, A, now)).unwrap();
    tx.try_send(admitted(&ledger, B, now)).unwrap();
    assert_eq!(ledger.snapshot().in_flight, 2);

    drop(rx);

    let snapshot = ledger.snapshot();
    assert_eq!((snapshot.in_flight, snapshot.released), (0, 2));
    assert_eq!(snapshot.reserved_bytes, 0);
}

#[tokio::test]
async fn an_aborted_task_releases_what_it_owned() {
    let (ledger, now) = (ledger(), Instant::now());
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(admitted(&ledger, B, now)).unwrap();
    let ticket = admitted(&ledger, A, now);
    let (parked_tx, parked) = oneshot::channel();

    let task = tokio::spawn(async move {
        parked_tx.send(()).unwrap();
        tx.send(ticket).await.is_ok()
    });
    parked.await.unwrap();
    task.abort();

    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(ledger.observe(&A), Some(Phase::Released));
}

// 4. Concurrent copies of one object.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_copies_admit_exactly_one() {
    const COPIES: usize = 32;
    for _ in 0..200 {
        let (ledger, now) = (ledger(), Instant::now());
        let start = Arc::new(Barrier::new(COPIES));
        let copies: Vec<_> = (0..COPIES)
            .map(|_| {
                let (ledger, start) = (ledger.clone(), Arc::clone(&start));
                tokio::spawn(async move {
                    start.wait().await;
                    ledger.admit(A, BYTES, now)
                })
            })
            .collect();

        let mut tickets = Vec::new();
        for copy in copies {
            match copy.await.unwrap() {
                Admission::Admitted(ticket) => tickets.push(ticket),
                Admission::Owned(Phase::InFlight) => {}
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert_eq!(tickets.len(), 1);
        assert_eq!(ledger.snapshot().reserved_bytes, BYTES);
    }
}

// A real consumer task holding sets of leases, told what to do step by step.

type Delivery = (u8, Ticket);

enum Step {
    Take(oneshot::Sender<()>),
    Evict(u8, oneshot::Sender<()>),
    Finish(u8, oneshot::Sender<usize>),
}

fn consumer(
    mut deliveries: mpsc::Receiver<Delivery>,
) -> (mpsc::Sender<Step>, tokio::task::JoinHandle<()>) {
    let (steps, mut orders) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        let mut sets: HashMap<u8, Vec<Lease>> = HashMap::new();
        while let Some(step) = orders.recv().await {
            match step {
                Step::Take(done) => {
                    let (body, ticket) = deliveries.recv().await.unwrap();
                    let lease = ticket.accept();
                    sets.entry(body).or_default().push(lease);
                    done.send(()).unwrap();
                }
                Step::Evict(body, done) => {
                    sets.remove(&body);
                    done.send(()).unwrap();
                }
                Step::Finish(body, done) => {
                    let leases = sets.remove(&body).unwrap_or_default();
                    let finished = leases.len();
                    for lease in leases {
                        lease.complete(Instant::now());
                    }
                    done.send(finished).unwrap();
                }
            }
        }
    });
    (steps, task)
}

struct Path {
    ledger: DeliveryLedger,
    deliveries: mpsc::Sender<Delivery>,
    steps: mpsc::Sender<Step>,
    task: tokio::task::JoinHandle<()>,
}

impl Path {
    fn new() -> Self {
        Self::with(ledger())
    }

    fn with(ledger: DeliveryLedger) -> Self {
        let (deliveries, queue) = mpsc::channel(8);
        let (steps, task) = consumer(queue);
        Self {
            ledger,
            deliveries,
            steps,
            task,
        }
    }

    /// One copy reaching the producer. True if it entered the channel.
    async fn copy(&self, body: u8, segment: u8) -> bool {
        match self.ledger.admit(id(body, segment), BYTES, Instant::now()) {
            Admission::Admitted(ticket) => {
                self.deliveries.send((body, ticket)).await.unwrap();
                true
            }
            _ => false,
        }
    }

    async fn take(&self) {
        let (done, reply) = oneshot::channel();
        self.steps.send(Step::Take(done)).await.unwrap();
        reply.await.unwrap();
    }

    async fn evict(&self, body: u8) {
        let (done, reply) = oneshot::channel();
        self.steps.send(Step::Evict(body, done)).await.unwrap();
        reply.await.unwrap();
    }

    async fn finish(&self, body: u8) -> usize {
        let (done, reply) = oneshot::channel();
        self.steps.send(Step::Finish(body, done)).await.unwrap();
        reply.await.unwrap()
    }

    fn queue_is_empty(&self) -> bool {
        self.deliveries.capacity() == self.deliveries.max_capacity()
    }

    async fn stop(self) {
        drop(self.steps);
        self.task.await.unwrap();
    }
}

// 5. Two bodies.

#[tokio::test]
async fn two_bodies_move_independently() {
    let path = Path::new();
    assert!(path.copy(1, 0).await);
    assert!(path.copy(2, 0).await);
    path.take().await;
    path.take().await;

    path.evict(1).await;
    assert_eq!(path.ledger.observe(&id(1, 0)), Some(Phase::Released));
    assert_eq!(path.ledger.observe(&id(2, 0)), Some(Phase::Held));

    assert!(path.copy(2, 1).await);
    path.take().await;
    assert_eq!(path.finish(2).await, 2);
    assert_eq!(path.ledger.observe(&id(2, 0)), Some(Phase::Completed));
    assert_eq!(path.ledger.observe(&id(1, 0)), Some(Phase::Released));

    assert!(path.copy(1, 0).await, "the other body kept its way back");
    path.take().await;
    path.stop().await;
}

// 6 and 7. After an eviction, with and without a copy.

#[tokio::test]
async fn an_evicted_set_is_rebuilt_when_its_copies_come_back() {
    let path = Path::new();
    assert!(path.copy(1, 0).await);
    assert!(path.copy(1, 1).await);
    path.take().await;
    path.take().await;
    path.evict(1).await;

    assert!(path.copy(1, 0).await);
    assert!(path.copy(1, 1).await);
    path.take().await;
    path.take().await;
    assert_eq!(path.finish(1).await, 2);

    assert_eq!(path.ledger.observe(&id(1, 0)), Some(Phase::Completed));
    assert!(
        !path.copy(1, 0).await,
        "a finished object is not delivered again"
    );
    path.stop().await;
}

#[tokio::test]
async fn nothing_comes_back_without_a_copy() {
    let path = Path::new();
    assert!(path.copy(1, 0).await);
    path.take().await;
    path.evict(1).await;

    assert_eq!(path.ledger.observe(&id(1, 0)), Some(Phase::Released));
    assert!(path.queue_is_empty(), "nothing asked for it again");
    assert_eq!(
        path.ledger.snapshot(),
        Snapshot {
            released: 1,
            ..Snapshot::default()
        }
    );
    assert_eq!(path.finish(1).await, 0, "the consumer has nothing");
    path.stop().await;
}

// 8. Limits.

#[test]
fn the_repeat_budget_ends_readmission() {
    let (ledger, now) = (ledger(), Instant::now());
    for _ in 0..=limits().repeat_budget {
        drop(held(&ledger, A, now));
    }

    assert!(matches!(
        ledger.admit(A, BYTES, now),
        Admission::Refused(Refusal::RepeatBudget)
    ));
    assert_eq!(ledger.observe(&A), Some(Phase::Released));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

/// A spent budget closes an object for a while. With no end it would stay shut until other
/// records pushed this one out, and a passing failure below would cost the object for good.
#[test]
fn a_spent_repeat_budget_ends_with_its_record() {
    let limits = Limits {
        released_ttl: Duration::from_secs(60),
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    for _ in 0..=limits.repeat_budget {
        drop(held(&ledger, A, now));
    }
    assert!(matches!(
        ledger.admit(A, BYTES, now),
        Admission::Refused(Refusal::RepeatBudget)
    ));
    assert_eq!(ledger.phase_at(&A, now), Some(Phase::Released));

    let later = Instant::now() + limits.released_ttl + Duration::from_secs(1);
    assert_eq!(ledger.phase_at(&A, later), None);
    assert!(matches!(
        ledger.admit(A, BYTES, later),
        Admission::Admitted(_)
    ));
}

/// No timer ends an ownership, however long the owner takes.
#[test]
fn an_owned_record_outlasts_the_released_time() {
    let limits = Limits {
        released_ttl: Duration::from_secs(60),
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    let lease = held(&ledger, A, now);

    let later = now + 10 * limits.released_ttl;
    assert_eq!(ledger.phase_at(&A, later), Some(Phase::Held));
    assert!(matches!(
        ledger.admit(A, BYTES, later),
        Admission::Owned(Phase::Held)
    ));
    drop(lease);
}

#[test]
fn a_full_ledger_refuses_rather_than_take_an_owned_record() {
    let limits = Limits {
        max_live_owners: 2 * limits().max_records,
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    let owned: Vec<Lease> = (0..limits.max_records as u8)
        .map(|i| held(&ledger, id(1, i), now))
        .collect();

    assert!(matches!(
        ledger.admit(id(2, 0), 0, now),
        Admission::Refused(Refusal::Records)
    ));
    assert_eq!(ledger.snapshot().held, limits.max_records);
    assert_eq!(
        ledger.observe(&id(2, 0)),
        None,
        "a refusal leaves no record"
    );
    drop(owned);
}

#[test]
fn a_full_ledger_forgets_the_oldest_released_record_first() {
    let (ledger, now) = (ledger(), Instant::now());
    let max = limits().max_records as u8;
    let mut owned = Vec::new();
    let completed = held(&ledger, id(1, 0), now);
    completed.complete(now);
    drop(held(&ledger, id(1, 1), now));
    drop(held(&ledger, id(1, 2), now));
    for i in 3..max {
        owned.push(held(&ledger, id(1, i), now));
    }

    let ticket = admitted(&ledger, id(2, 0), now);

    assert_eq!(
        ledger.observe(&id(1, 1)),
        None,
        "the oldest released record"
    );
    assert_eq!(ledger.observe(&id(1, 2)), Some(Phase::Released));
    assert_eq!(ledger.observe(&id(1, 0)), Some(Phase::Completed));
    drop(ticket);
    drop(owned);
}

/// `observe` reports what is in the map, and only `admit` clears it. `phase_at` answers
/// for the moment it is asked about, without clearing anything.
#[test]
fn a_completed_record_past_its_end_reads_as_gone() {
    let (ledger, now) = (ledger(), Instant::now());
    held(&ledger, A, now).complete(now);
    let end = now + limits().completed_ttl;

    assert_eq!(
        ledger.phase_at(&A, end - Duration::from_nanos(1)),
        Some(Phase::Completed)
    );
    assert_eq!(ledger.phase_at(&A, end), None);
    assert_eq!(
        ledger.observe(&A),
        Some(Phase::Completed),
        "it is still in the map"
    );
}

#[test]
fn phase_at_says_what_observe_says_for_everything_else() {
    let (ledger, now) = (ledger(), Instant::now());
    assert_eq!(ledger.phase_at(&A, now), None);

    let Admission::Admitted(ticket) = ledger.admit(A, BYTES, now) else {
        panic!("expected an admission");
    };
    assert_eq!(ledger.phase_at(&A, now), Some(Phase::InFlight));

    let lease = ticket.accept();
    assert_eq!(ledger.phase_at(&A, now), Some(Phase::Held));

    drop(lease);
    assert_eq!(ledger.phase_at(&A, now), Some(Phase::Released));
}

#[test]
fn forgetting_a_released_record_forgets_its_repeats() {
    let limits = Limits {
        max_records: 2,
        repeat_budget: 0,
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    drop(held(&ledger, A, now));
    assert!(matches!(
        ledger.admit(A, BYTES, now),
        Admission::Refused(Refusal::RepeatBudget)
    ));

    drop(held(&ledger, id(1, 0), now));
    drop(held(&ledger, id(1, 1), now));

    assert_eq!(ledger.observe(&A), None);
    assert!(
        matches!(ledger.admit(A, BYTES, now), Admission::Admitted(_)),
        "the known limit: enough other records wipe this object's spent budget"
    );
}

#[test]
fn reserved_bytes_are_bounded_and_returned() {
    let (ledger, now) = (ledger(), Instant::now());
    let limit = limits().max_reserved_bytes;
    let big = match ledger.admit(A, limit, now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        ledger.admit(B, 1, now),
        Admission::Refused(Refusal::Bytes)
    ));
    assert_eq!(ledger.observe(&B), None);

    let lease = big.accept();
    assert_eq!(ledger.snapshot().reserved_bytes, limit);
    lease.complete(now);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);

    assert!(matches!(
        ledger.admit(B, usize::MAX, now),
        Admission::Refused(Refusal::Bytes)
    ));
}

#[test]
fn a_refused_readmission_spends_no_repeat() {
    let (ledger, now) = (ledger(), Instant::now());
    drop(held(&ledger, A, now));
    let filler = match ledger.admit(B, limits().max_reserved_bytes, now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("{other:?}"),
    };

    for _ in 0..4 {
        assert!(matches!(
            ledger.admit(A, BYTES, now),
            Admission::Refused(Refusal::Bytes)
        ));
    }
    drop(filler);

    for _ in 0..limits().repeat_budget {
        drop(held(&ledger, A, now));
    }
    assert!(matches!(
        ledger.admit(A, BYTES, now),
        Admission::Refused(Refusal::RepeatBudget)
    ));
}

#[test]
fn a_completed_record_ends_at_its_ttl_and_only_then() {
    let (ledger, now) = (ledger(), Instant::now());
    held(&ledger, A, now).complete(now);

    let before = now + limits().completed_ttl - Duration::from_secs(1);
    assert!(matches!(
        ledger.admit(A, BYTES, before),
        Admission::Completed
    ));

    let at = now + limits().completed_ttl;
    assert!(matches!(ledger.admit(A, BYTES, at), Admission::Admitted(_)));
}

// Time ends no ownership. A consumer past any deadline may still hold its payload.

/// The open limit: nothing here frees a hung consumer's capacity, however late it is.
#[test]
fn a_stuck_owner_keeps_its_capacity_however_late_it_is() {
    let (ledger, now) = (one_object(), Instant::now());
    let stuck = held(&ledger, A, now);
    let much_later = now + Duration::from_secs(365 * 24 * 60 * 60);

    for object in [A, B] {
        assert!(!matches!(
            ledger.admit(object, BYTES, much_later),
            Admission::Admitted(_)
        ));
    }
    assert_eq!(ledger.observe(&A), Some(Phase::Held));
    assert_eq!(ledger.snapshot().reserved_bytes, BYTES);

    drop(stuck);
    assert!(matches!(
        ledger.admit(A, BYTES, much_later),
        Admission::Admitted(_)
    ));
}

/// The same with a real consumer task, alive and holding its lease.
#[tokio::test]
async fn a_live_consumer_keeps_its_capacity() {
    let path = Path::with(one_object());
    assert!(path.copy(1, 0).await);
    path.take().await;

    assert!(!path.copy(1, 0).await, "its own copy is refused");
    assert!(!path.copy(2, 0).await, "and so is another body");
    assert_eq!(path.ledger.snapshot().reserved_bytes, BYTES);

    path.evict(1).await;

    assert_eq!(path.ledger.snapshot().reserved_bytes, 0);
    assert!(path.copy(1, 0).await);
    path.take().await;
    assert_eq!(path.finish(1).await, 1);
    path.stop().await;
}

/// Room for exactly one object, so any second reservation shows up as a refusal.
fn one_object() -> DeliveryLedger {
    DeliveryLedger::new(Limits {
        max_reserved_bytes: BYTES,
        ..limits()
    })
}

// Live owners, whatever their size.

fn owner_limit(max_live_owners: usize, max_records: usize) -> DeliveryLedger {
    DeliveryLedger::new(Limits {
        max_live_owners,
        max_records,
        ..limits()
    })
}

fn empty(ledger: &DeliveryLedger, id: ObjectId, now: Instant) -> Ticket {
    match ledger.admit(id, 0, now) {
        Admission::Admitted(ticket) => ticket,
        other => panic!("expected an admission, got {other:?}"),
    }
}

#[test]
fn empty_objects_cannot_pass_the_owner_limit() {
    let (ledger, now) = (owner_limit(3, 16), Instant::now());
    let owners: Vec<Ticket> = (0..3).map(|i| empty(&ledger, id(1, i), now)).collect();
    assert_eq!(ledger.snapshot().reserved_bytes, 0);

    assert!(matches!(
        ledger.admit(id(1, 3), 0, now),
        Admission::Refused(Refusal::Owners)
    ));
    assert_eq!(
        ledger.observe(&id(1, 3)),
        None,
        "a refusal leaves no record"
    );

    drop(owners);
    assert_eq!(ledger.snapshot().live_owners, 0);
    assert!(matches!(
        ledger.admit(id(1, 3), 0, now),
        Admission::Admitted(_)
    ));
}

#[test]
fn a_copy_refused_for_the_owner_limit_spends_no_repeat() {
    let (ledger, now) = (owner_limit(1, 16), Instant::now());
    drop(held(&ledger, A, now));
    let filler = admitted(&ledger, B, now);
    for _ in 0..4 {
        assert!(matches!(
            ledger.admit(A, BYTES, now),
            Admission::Refused(Refusal::Owners)
        ));
    }
    drop(filler);

    for _ in 0..limits().repeat_budget {
        drop(held(&ledger, A, now));
    }
    assert!(matches!(
        ledger.admit(A, BYTES, now),
        Admission::Refused(Refusal::RepeatBudget)
    ));
}

// A payload carried with its owner. Fields drop in order, so the payload goes first and
// its bytes are still counted while it dies. This is a test adapter, not a library type.

struct Carried<Owner> {
    _payload: Probe,
    _owner: Owner,
}

/// Reads what the ledger says at the moment the payload is destroyed.
struct Probe {
    ledger: DeliveryLedger,
    reserved_at_drop: Arc<std::sync::Mutex<Option<usize>>>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        *self.reserved_at_drop.lock().unwrap() = Some(self.ledger.snapshot().reserved_bytes);
    }
}

#[test]
fn a_carried_payload_is_gone_before_its_bytes_come_back() {
    let (ledger, now) = (ledger(), Instant::now());
    let seen = Arc::new(std::sync::Mutex::new(None));
    let probe = |seen: &Arc<std::sync::Mutex<Option<usize>>>| Probe {
        ledger: ledger.clone(),
        reserved_at_drop: Arc::clone(seen),
    };

    let ticket = Carried {
        _payload: probe(&seen),
        _owner: admitted(&ledger, A, now),
    };
    drop(ticket);
    assert_eq!(
        *seen.lock().unwrap(),
        Some(BYTES),
        "still reserved as it died"
    );
    assert_eq!(ledger.snapshot().reserved_bytes, 0);

    let lease = Carried {
        _payload: probe(&seen),
        _owner: held(&ledger, B, now),
    };
    drop(lease);
    assert_eq!(
        *seen.lock().unwrap(),
        Some(BYTES),
        "still reserved as it died"
    );
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}
