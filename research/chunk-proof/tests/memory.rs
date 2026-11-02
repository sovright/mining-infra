//! What arrival and decode allocate, measured on this thread by a counting allocator. Kept
//! in a binary of its own so no other test shares the allocator. These are measurements
//! of the shapes named, not proofs, and the datagram a caller read is outside all of them.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::Instant;

use chunk_proof::assembler::Arrival;
use chunk_proof::budget::Used;
use chunk_proof::datagram::seal;
use chunk_proof::handoff::{Handoff, Stack, StackLimits, Step};
use chunk_proof::object::{
    MSG_BLOCK, MSG_RAW_SEGMENT, MSG_SKELETON, Profile, Shape, decode, encode, held_bytes,
    work_bytes,
};
use common::segments::{SEGMENT, body, frame_rules, frames_of};
use common::{
    KEY, assembler_limits, assembler_on, budget_with, content, datagrams, object, pending, roomy,
    roomy_limits, verifier,
};
use delivery_lease::body_buffer::BufferLimits;
use delivery_lease::{Limits, Transit};

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    allocated: usize,
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

#[test]
fn verifying_a_chunk_allocates_nothing_whatever_the_outcome() {
    let verifier = verifier();
    let object = object(MSG_RAW_SEGMENT, 6, 4, 1, 40);
    let good = datagrams(&object).swap_remove(2);
    let mut bad_proof = good.clone();
    *bad_proof.last_mut().unwrap() ^= 1;
    let bad_proof = seal(
        &KEY,
        &object.shape,
        &object.object_id,
        2,
        &object.proofs[2],
        &bad_proof[bad_proof.len() - usize::from(object.shape.s)..],
    );
    let mut bad_mac = good.clone();
    bad_mac[0] ^= 1;

    for frame in [&good, &bad_proof, &bad_mac] {
        let (_, counts) = measured(|| verifier.verify(frame).map(|chunk| chunk.index()));
        assert_eq!(counts.allocated, 0);
    }
}

#[test]
fn a_chunk_that_is_refused_is_never_copied() {
    let (first, second) = (
        object(MSG_RAW_SEGMENT, 6, 4, 1, 40),
        object(MSG_RAW_SEGMENT, 6, 4, 2, 40),
    );
    let budget = budget_with(8, held_bytes(&first.shape), 1 << 22);
    budget.used();
    let mut assembler = assembler_on(&budget);
    let (frames, refused) = (datagrams(&first), datagrams(&second));
    let now = Instant::now();
    let mut holding = None;
    for frame in &frames[..4] {
        if let Arrival::Decoded(decoded) = assembler.receive(frame, now) {
            holding = Some(decoded);
        }
    }
    assert!(holding.is_some());

    let (arrival, counts) =
        measured(|| matches!(assembler.receive(&refused[0], now), Arrival::Refused(_)));

    assert!(arrival);
    assert_eq!(counts.allocated, 0);
}

type DecodeInput = (Shape, [u8; 32], Vec<Option<Vec<u8>>>, Vec<u8>);

fn worst_case(n: u16, k: u16, s: usize) -> DecodeInput {
    let bytes = content(9, usize::from(k) * s - 4);
    let encoded = encode(MSG_RAW_SEGMENT, n, k, &bytes).expect("a valid shape");
    let (n, k) = (usize::from(n), usize::from(k));
    let shards = encoded
        .shards
        .iter()
        .enumerate()
        .map(|(at, shard)| (at >= n - k).then(|| shard.clone()))
        .collect();
    (encoded.shape, encoded.object_id, shards, bytes)
}

/// The most a decode has to rebuild: the last `k` shards, so as many data shards as there
/// are parity shards are missing. `work_bytes` is what the budget charges, and this is
/// the check that it covers the decode, library matrices included.
#[test]
fn a_decode_stays_under_what_the_budget_charges() {
    let mut over = Vec::new();
    for (n, k, s) in [
        (2, 1, 5),
        (3, 2, 3),
        (100, 50, 1),
        (256, 128, 1),
        (256, 200, 1),
        (256, 255, 1),
        (2, 1, 1000),
        (4, 2, 993),
        (6, 4, 993),
        (13, 10, 993),
        (64, 32, 900),
        (128, 96, 880),
        (256, 1, 865),
        (256, 128, 865),
        (256, 200, 865),
        (256, 255, 865),
    ] {
        let (shape, id, shards, bytes) = worst_case(n, k, s);
        let charged = work_bytes(&shape) as isize;

        let (result, counts) = measured(|| decode(&shape, &id, shards, 1 << 20));

        assert_eq!(result.as_ref(), Ok(&bytes), "({n}, {k})");
        let ratio = charged as f64 / counts.peak as f64;
        println!(
            "n {n:3} k {k:3} s {s:4}: tepe {:8} bayt, odenen {charged:8} bayt, oran {ratio:.2}",
            counts.peak
        );
        if counts.peak > charged {
            over.push((n, k));
        }
    }
    assert_eq!(over, Vec::<(u16, u16)>::new(), "shapes over their charge");
}

/// What an open object holds is its shards and slot list. The map entry is not charged.
#[test]
fn an_open_object_holds_what_it_was_charged_for_and_a_table_entry() {
    let budget = roomy();
    budget.used();
    let mut assembler = assembler_on(&budget);
    let object = object(MSG_RAW_SEGMENT, 13, 10, 1, 9926);
    let frames = datagrams(&object);
    let now = Instant::now();

    let (_, counts) = measured(|| {
        for frame in &frames[..9] {
            pending(assembler.receive(frame, now));
        }
    });

    let charged = held_bytes(&object.shape) as isize;
    assert_eq!(budget.used().held_bytes as isize, charged);
    println!(
        "n 13 k 10: 9 shard, canli {} bayt, tutulan odeme {charged} bayt",
        counts.live
    );
    assert!(counts.live <= charged + 2048, "live {}", counts.live);
    assert_ne!(budget.used(), Used::default());
}

/// Every shape the research profile allows, at the smallest and the largest shard the
/// datagram leaves room for. Supporting data for `work_bytes`, not a proof of it, and for
/// the pinned library only. Slow without optimisation:
/// `cargo test --release --test memory -- --ignored --nocapture`
#[test]
#[ignore = "the whole profile, for a release build"]
fn every_shape_of_the_research_profile_stays_under_its_charge() {
    let mut shapes = vec![(MSG_RAW_SEGMENT, 13u16, 10u16)];
    for msg_type in [MSG_BLOCK, MSG_SKELETON] {
        for k in 1..=255u16 {
            let n = (k + 1..=256).find(|n| {
                Profile::Research.allows(&Shape {
                    msg_type,
                    n: *n,
                    k,
                    s: 1,
                })
            });
            if let Some(n) = n {
                shapes.push((msg_type, n, k));
            }
        }
    }

    let (mut shapes_tried, mut lowest, mut highest) = (0, f64::MAX, 0f64);
    for (msg_type, n, k) in shapes {
        let cap = 1200 - 79 - 32 * n.next_power_of_two().trailing_zeros() as usize;
        for s in [5usize.div_ceil(usize::from(k)), cap] {
            let bytes = content(9, usize::from(k) * s - 4);
            let encoded = encode(msg_type, n, k, &bytes).expect("a valid shape");
            assert!(Profile::Research.allows(&encoded.shape));
            let from = usize::from(n - k);
            let shards = encoded
                .shards
                .iter()
                .enumerate()
                .map(|(at, shard)| (at >= from).then(|| shard.clone()))
                .collect();
            let charged = work_bytes(&encoded.shape) as isize;

            let (result, counts) =
                measured(|| decode(&encoded.shape, &encoded.object_id, shards, 1 << 20));

            assert_eq!(result.as_ref(), Ok(&bytes), "({n}, {k}, {s})");
            assert!(
                counts.peak <= charged,
                "({n}, {k}, {s}): peak {}, charged {charged}",
                counts.peak
            );
            let ratio = charged as f64 / counts.peak as f64;
            (lowest, highest) = (lowest.min(ratio), highest.max(ratio));
            shapes_tried += 1;
        }
    }
    println!("profil: {shapes_tried} sekil, oran {lowest:.2} ile {highest:.2} arasi");
}

/// One body from the first chunk to the block, with the counters beside what is alive.
/// What the counters do not cover is tables, and this shows how much. The sum of the fixed
/// budgets is the ceiling: there is no shared counter across the two layers.
#[test]
fn every_stage_stays_under_what_the_budgets_count() {
    let stack = Stack::new(
        KEY,
        Profile::EveryShape,
        frame_rules(),
        StackLimits {
            budget: roomy_limits(),
            ledger: Limits {
                max_records: 64,
                max_live_owners: 64,
                max_reserved_bytes: 16 * SEGMENT,
                repeat_budget: 2,
                completed_ttl: std::time::Duration::from_secs(300),
                released_ttl: std::time::Duration::from_secs(86_400),
                transit: Transit {
                    bytes: 8 * SEGMENT,
                    owners: 8,
                    records: 8,
                },
            },
            buffer: BufferLimits {
                max_sets: 8,
                max_sets_per_block: 4,
                max_segments: 32,
                ttl: std::time::Duration::from_secs(120),
            },
            assembler: assembler_limits(),
            max_carried: 64,
        },
    )
    .unwrap();
    let (budget, ledger) = (stack.budget().clone(), stack.ledger().clone());
    let mut bridge = stack.bridge().unwrap();
    let mut session = stack.session().unwrap();
    ledger.snapshot();
    budget.used();
    let raw = body(10);
    let objects: Vec<_> = frames_of(&raw)
        .iter()
        .map(|frame| encode(MSG_RAW_SEGMENT, 13, 10, frame).expect("a valid shape"))
        .collect();
    let frames: Vec<Vec<Vec<u8>>> = objects.iter().map(datagrams).collect();
    let now = Instant::now();

    let mut stages = Vec::new();
    let stage = |name: &'static str, stages: &mut Vec<_>| {
        let live = COUNTED.with(|counted| counted.get()).map_or(0, |c| c.live);
        let (used, reserved) = (budget.used(), ledger.snapshot().reserved_bytes);
        stages.push((name, live, used.held_bytes, used.work_bytes, reserved));
    };

    let (block, counts) = measured(|| {
        for object_frames in &frames {
            for frame in &object_frames[..9] {
                assert!(matches!(
                    bridge.take(&mut session, frame, now),
                    Step::Chunk(_)
                ));
            }
            stage("toplama, 9 shard", &mut stages);
            let last = bridge.take(&mut session, &object_frames[9], now);
            stage("devir sonrasi", &mut stages);
            if let Step::Handed(Handoff::Whole(set)) = last {
                let block = bridge.assemble(set, now).unwrap();
                stage("birlesmis blok", &mut stages);
                return block;
            }
        }
        panic!("the second object finishes the set");
    });

    assert_eq!(*block.block(), raw);
    for (name, live, held, work, reserved) in &stages {
        let counted = (held + work + reserved) as isize;
        println!("{name:20} canli {live:6}, tutulan {held:5}, is {work:5}, defter {reserved:5}");
        assert!(
            *live <= counted + 16 * 1024,
            "{name}: {live} over {counted}"
        );
    }
    println!("tepe {}", counts.peak);
    assert!(counts.peak <= stack.ceiling().total_bytes() as isize);
}
