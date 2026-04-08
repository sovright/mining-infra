use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zcash_pool_common::{read_compact_size, write_compact_size};

fn bench_compact_size(c: &mut Criterion) {
    let values = [0u64, 0xfc, 0xfd, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000];

    c.bench_function("compact_size_roundtrip", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(9);
            for &v in &values {
                buf.clear();
                write_compact_size(black_box(v), &mut buf);
                let mut cursor = 0;
                let _ = read_compact_size(black_box(&buf), &mut cursor);
            }
        })
    });
}

criterion_group!(benches, bench_compact_size);
criterion_main!(benches);
