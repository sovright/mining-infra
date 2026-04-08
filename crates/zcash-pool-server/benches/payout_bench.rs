use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zcash_pool_server::PayoutTracker;

fn bench_record_share(c: &mut Criterion) {
    // Pre-generate 1000 unique miner IDs
    let miner_ids: Vec<String> = (0..1000).map(|i| format!("miner_{}", i)).collect();

    c.bench_function("payout_record_share_1000_miners", |b| {
        b.iter(|| {
            let tracker = PayoutTracker::default();
            for id in &miner_ids {
                tracker.record_share(black_box(id), black_box(1.0));
            }
        })
    });

    c.bench_function("payout_record_share_repeated", |b| {
        let tracker = PayoutTracker::default();
        let mut idx = 0usize;
        b.iter(|| {
            let id = &miner_ids[idx % miner_ids.len()];
            tracker.record_share(black_box(id), black_box(1.0));
            idx = idx.wrapping_add(1);
        })
    });
}

criterion_group!(benches, bench_record_share);
criterion_main!(benches);
