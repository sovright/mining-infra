//! Not a benchmark: one machine, one thread, to put a number on A1 to A4 and D1 to D4.
//! Ignored by default, because a debug build says nothing:
//! `cargo test --release --test timing -- --ignored --nocapture`

mod common;

use std::time::{Duration, Instant};

use chunk_proof::object::{MSG_RAW_SEGMENT, decode, encode};
use common::{content, datagrams, verifier};

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[test]
#[ignore = "a measurement, for a release build"]
fn how_long_arrival_and_decode_take() {
    for (n, k, s) in [(6u16, 4u16, 993usize), (13, 10, 993), (256, 200, 865)] {
        let bytes = content(9, usize::from(k) * s - 4);
        let object = encode(MSG_RAW_SEGMENT, n, k, &bytes).expect("a valid shape");
        let verifier = verifier();
        let frames = datagrams(&object);
        let (total, data) = (usize::from(n), usize::from(k));
        let last_k: Vec<Option<Vec<u8>>> = object
            .shards
            .iter()
            .enumerate()
            .map(|(at, shard)| (at >= total - data).then(|| shard.clone()))
            .collect();

        let arrival = median(
            (0..101)
                .map(|at| {
                    let frame = &frames[at % frames.len()];
                    let start = Instant::now();
                    assert!(verifier.verify(frame).is_ok());
                    start.elapsed()
                })
                .collect(),
        );
        let object_time = median(
            (0..31)
                .map(|_| {
                    let shards = last_k.clone();
                    let start = Instant::now();
                    let result = decode(&object.shape, &object.object_id, shards, 1 << 20);
                    let spent = start.elapsed();
                    assert!(result.is_ok());
                    spent
                })
                .collect(),
        );
        println!(
            "n {n:3} k {k:3} s {s}: chunk {arrival:?}, nesne {object_time:?}, icerik {} bayt",
            bytes.len()
        );
    }
}
