use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zcash_mining_protocol::messages::{NewEquihashJob, SubmitEquihashShare};
use zcash_pool_server::{InMemoryDuplicateDetector, ShareProcessor};

fn bench_share_validation(c: &mut Criterion) {
    let processor = ShareProcessor::new();
    let block_target = [0xff; 32];
    let job_time: u32 = 1_700_000_000;

    let job = NewEquihashJob {
        channel_id: 1,
        job_id: 1,
        future_job: false,
        version: 5,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        block_commitments: [0; 32],
        nonce_1: vec![0; 4],
        nonce_2_len: 28,
        time: job_time,
        bits: 0x2007ffff,
        target: [0xff; 32],
        clean_jobs: false,
    };

    // Dummy share with zero-byte solution -- will be rejected quickly for InvalidSolution.
    // That is the point: we measure the overhead of the validation path before the
    // expensive Equihash check.
    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2: vec![0; 28],
        time: job_time,
        solution: [0; 1344],
    };

    c.bench_function("validate_share_with_job_rejected", |b| {
        b.iter(|| {
            // Use a fresh detector each iteration so duplicates don't short-circuit
            let detector = InMemoryDuplicateDetector::new();
            let _ = processor.validate_share_with_job(
                black_box(&share),
                black_box(&job),
                &detector,
                black_box(&block_target),
            );
        })
    });
}

criterion_group!(benches, bench_share_validation);
criterion_main!(benches);
