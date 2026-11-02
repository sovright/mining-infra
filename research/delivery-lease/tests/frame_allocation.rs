//! What verification and intake allocate, measured on this thread by a counting
//! allocator. Kept in a binary of its own so no other test shares the allocator.
//!
//! These figures are for what each test names and no further. The frame a caller read
//! off the network is its own allocation, and is outside all of them.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::{Duration, Instant};

use common::{SEGMENT, body, rules};
use delivery_lease::body_buffer::{ACTIVE_SET, BodyBuffer, BufferLimits};
use delivery_lease::intake::{Intake, Offer, Step, into_complete};
use delivery_lease::segment_frame::{FrameError, verify};
use delivery_lease::{DeliveryLedger, Limits, Refusal, Transit};

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    allocated: usize,
    /// Allocations of exactly one segment, which is what a payload copy is.
    copies: usize,
    /// What was alive beyond the start, at its highest and at the end.
    peak: isize,
    live: isize,
}

thread_local! {
    static COUNTED: Cell<Option<Counts>> = const { Cell::new(None) };
}

fn count(change: impl FnOnce(&mut Counts)) {
    let _ = COUNTED.try_with(|counted| {
        if let Some(mut counts) = counted.get() {
            change(&mut counts);
            counts.peak = counts.peak.max(counts.live);
            counted.set(Some(counts));
        }
    });
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(|counts| {
            counts.allocated += layout.size();
            counts.copies += usize::from(layout.size() == SEGMENT);
            counts.live += layout.size() as isize;
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(|counts| counts.live -= layout.size() as isize);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measured<T>(run: impl FnOnce() -> T) -> (T, Counts) {
    COUNTED.with(|counted| counted.set(Some(Counts::default())));
    let result = run();
    let counts = COUNTED.with(|counted| counted.take()).unwrap();
    (result, counts)
}

fn allocated_by<T>(run: impl FnOnce() -> T) -> (T, usize) {
    let (result, counts) = measured(run);
    (result, counts.allocated)
}

fn intake(max_reserved_bytes: usize) -> (DeliveryLedger, Intake) {
    let ledger = DeliveryLedger::new(Limits {
        max_records: 64,
        max_live_owners: 64,
        max_reserved_bytes,
        repeat_budget: 2,
        completed_ttl: Duration::from_secs(300),
        released_ttl: Duration::from_secs(86_400),
        transit: Transit {
            bytes: 8 * SEGMENT,
            owners: 8,
            records: 8,
        },
    });
    let buffer = BodyBuffer::new(BufferLimits {
        max_sets: 8,
        max_sets_per_block: 4,
        max_segments: 32,
        ttl: Duration::from_secs(120),
    })
    .unwrap();
    // On some platforms a mutex allocates on first use, and that is not what is measured.
    ledger.snapshot();
    (ledger.clone(), Intake::new(ledger, buffer, rules()))
}

#[test]
fn a_bad_frame_allocates_nothing_and_a_good_one_only_its_payload() {
    let (honest, rules) = (body(1, 10), rules());

    let mut flipped = honest.frames[1].clone();
    *flipped.last_mut().unwrap() ^= 1;
    let (result, bytes) = allocated_by(|| verify(&flipped, &rules).map(|_| ()));
    assert_eq!(result, Err(FrameError::Proof));
    assert_eq!(
        bytes, 0,
        "the whole frame was hashed and nothing was allocated"
    );

    let oversized = vec![0u8; rules.max_frame_len() + 1];
    let (result, bytes) = allocated_by(|| verify(&oversized, &rules).map(|_| ()));
    assert_eq!(result, Err(FrameError::TooLong));
    assert_eq!(bytes, 0);

    let (result, bytes) = allocated_by(|| verify(&honest.frames[1], &rules));
    assert!(result.is_ok());
    assert_eq!(
        bytes, SEGMENT,
        "one copy of the payload, once it has passed"
    );
}

/// `Intake` asks before it copies, so a frame the ledger refuses costs no payload at all.
/// `verify` alone still copies, and that test is above.
#[test]
fn a_good_frame_the_ledger_refuses_is_never_copied() {
    let (ledger, mut intake) = intake(SEGMENT - 1);
    let honest = body(1, 10);

    let (refused, counts) = measured(|| {
        let offer = intake.receive(&honest.frames[0], Instant::now());
        matches!(offer, Offer::Refused(Refusal::Bytes))
    });

    assert!(refused);
    assert_eq!(counts.allocated, 0);
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

/// The new payload does not exist while the counts overlap: it is copied once the
/// reservation is in place and the victims are gone.
#[test]
fn the_copy_comes_after_the_reservation_and_the_evictions() {
    let (ledger, mut intake) = intake(SEGMENT);
    let (victim, new) = (body(1, 10), body(2, 10));
    let now = Instant::now();
    assert!(matches!(
        intake.receive(&victim.frames[0], now),
        Offer::Taken(_)
    ));

    let mut at_eviction = None;
    let (taken, total) = measured(|| {
        let offer = intake.receive_stepping(&new.frames[0], now + ACTIVE_SET, |step| {
            if step == Step::BeforeEvicting {
                at_eviction = COUNTED.with(|counted| counted.get());
                assert_eq!(ledger.snapshot().reserved_bytes, 2 * SEGMENT);
            }
        });
        matches!(offer, Offer::Taken(_))
    });

    assert!(taken);
    let at_eviction = at_eviction.expect("the eviction was reached");
    assert_eq!(at_eviction.copies, 0, "copied before the eviction");
    assert_eq!(total.copies, 1, "and once");
}

/// The reservation counts payloads only. A set also costs its table, slots and keys.
#[test]
fn an_accepted_segment_costs_more_than_its_reservation() {
    let (ledger, mut intake) = intake(100 * SEGMENT);
    let honest = body(1, 10);

    let (_, counts) = measured(|| intake.receive(&honest.frames[0], Instant::now()));

    assert_eq!(ledger.snapshot().reserved_bytes, SEGMENT);
    assert!(counts.live > SEGMENT as isize);
    println!("kabul edilen ilk segment: canli {} bayt", counts.live);
}

/// While the copy runs the payloads and the block are alive together, and the ledger
/// counts both. Afterwards the payloads are gone and their reservation stays with their
/// leases, so the count is above real memory until those go.
#[test]
fn assembly_peaks_at_the_set_and_the_block_together() {
    let (ledger, mut intake) = intake(4 * SEGMENT);
    let honest = body(1, 10);
    let now = Instant::now();
    assert!(matches!(
        intake.receive(&honest.frames[0], now),
        Offer::Taken(_)
    ));
    let set = into_complete(intake.receive(&honest.frames[1], now)).unwrap();
    let raw = honest.raw.len();
    assert_eq!(ledger.snapshot().reserved_bytes, raw);

    let (block, counts) = measured(|| intake.assemble(set, now).unwrap());

    assert_eq!(
        counts.allocated - raw,
        2 * size_of::<delivery_lease::Lease>()
    );
    assert!(counts.peak >= raw as isize, "the block, with the set alive");
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * raw);
    assert!(
        counts.live <= counts.allocated as isize - raw as isize,
        "the payloads were freed once copied"
    );
    drop(block);
}
