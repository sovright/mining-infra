//! Performance benchmarks for sovright-relay

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sovright_relay::{
    fec::{FecDecoder, FecEncoder},
    AuthDigest, BlockChunker, BlockHash, CompactBlock, CompactBlockReconstructor, ShortId,
    TestMempool, TxId, WtxId,
};

/// Create a synthetic block for benchmarking
fn create_bench_block(tx_count: usize, tx_size: usize) -> (BlockHash, Vec<u8>, Vec<(WtxId, Vec<u8>)>) {
    let mut header = vec![0u8; 1487];
    header[0..4].copy_from_slice(&4u32.to_le_bytes());

    let hash = BlockHash::from_bytes({
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&header[..140]);
        let first = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(first);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    let mut transactions = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let mut tx_data = vec![0u8; tx_size];
        tx_data[0..4].copy_from_slice(&(i as u32).to_le_bytes());

        let txid = TxId::from_bytes({
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&tx_data);
            let first = hasher.finalize();
            let mut hasher = Sha256::new();
            hasher.update(first);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        });

        let wtxid = WtxId::new(txid, AuthDigest::from_bytes([0u8; 32]));
        transactions.push((wtxid, tx_data));
    }

    (hash, header, transactions)
}

fn bench_compact_block_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_block_build");

    for tx_count in [50, 500, 2500] {
        let (hash, header, transactions) = create_bench_block(tx_count, 300);
        let size = header.len() + transactions.len() * 300;
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("txs", tx_count),
            &(hash, header.clone(), &transactions),
            |b, (hash, header, txs)| {
                b.iter(|| {
                    // Create short IDs for the compact block
                    let short_ids: Vec<_> = txs
                        .iter()
                        .map(|(wtxid, _)| ShortId::compute(wtxid, hash.as_bytes(), 0))
                        .collect();
                    let compact = CompactBlock::new(header.clone(), 0, short_ids, vec![]);
                    black_box(BlockChunker::serialize_compact_block(&compact))
                });
            },
        );
    }

    group.finish();
}

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_encode");

    for size_kb in [10, 100, 1000] {
        let data = vec![0xABu8; size_kb * 1024];
        group.throughput(Throughput::Bytes(data.len() as u64));

        let encoder = FecEncoder::new(10, 3).unwrap();

        group.bench_with_input(BenchmarkId::new("kb", size_kb), &data, |b, data| {
            b.iter(|| black_box(encoder.encode(data).unwrap()))
        });
    }

    group.finish();
}

fn bench_fec_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_decode");

    for size_kb in [10, 100, 1000] {
        let data = vec![0xABu8; size_kb * 1024];
        let encoder = FecEncoder::new(10, 3).unwrap();
        let shards = encoder.encode(&data).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        group.throughput(Throughput::Bytes(data.len() as u64));

        // All shards available
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        group.bench_with_input(
            BenchmarkId::new("kb", size_kb),
            &(shard_opts.clone(), data.len()),
            |b, (shards, orig_len)| b.iter(|| black_box(decoder.decode(shards.clone(), *orig_len).unwrap())),
        );
    }

    group.finish();
}

fn bench_fec_decode_with_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_decode_loss");

    for size_kb in [10, 100, 1000] {
        let data = vec![0xABu8; size_kb * 1024];
        let encoder = FecEncoder::new(10, 3).unwrap();
        let shards = encoder.encode(&data).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        group.throughput(Throughput::Bytes(data.len() as u64));

        // Simulate 3 lost shards
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[0] = None;
        shard_opts[5] = None;
        shard_opts[10] = None;

        group.bench_with_input(
            BenchmarkId::new("kb", size_kb),
            &(shard_opts.clone(), data.len()),
            |b, (shards, orig_len)| b.iter(|| black_box(decoder.decode(shards.clone(), *orig_len).unwrap())),
        );
    }

    group.finish();
}

fn bench_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconstruction");

    for mempool_hit_rate in [50, 80, 95] {
        let (hash, header, transactions) = create_bench_block(500, 300);

        // Build compact block
        let short_ids: Vec<_> = transactions
            .iter()
            .map(|(wtxid, _)| ShortId::compute(wtxid, hash.as_bytes(), 0))
            .collect();
        let compact = CompactBlock::new(header.clone(), 0, short_ids, vec![]);

        // Prepare transaction data for mempool
        let hit_count = 500 * mempool_hit_rate / 100;
        let mempool_txs: Vec<_> = transactions.iter().take(hit_count).cloned().collect();

        group.bench_with_input(
            BenchmarkId::new("hit_rate", format!("{}%", mempool_hit_rate)),
            &(compact.clone(), mempool_txs, hash),
            |b, (compact, txs, block_hash): &(CompactBlock, Vec<(WtxId, Vec<u8>)>, BlockHash)| {
                b.iter(|| {
                    // Create mempool fresh each iteration (fast because it's just inserts)
                    let mut mempool = TestMempool::new();
                    for (wtxid, tx_data) in txs {
                        mempool.insert(*wtxid, tx_data.clone());
                    }
                    let mut reconstructor = CompactBlockReconstructor::new(&mempool);
                    reconstructor.prepare(block_hash.as_bytes(), 0);
                    black_box(reconstructor.reconstruct(compact))
                });
            },
        );
    }

    group.finish();
}

fn bench_chunker_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunker_roundtrip");

    for tx_count in [50, 500, 2500] {
        let (hash, header, transactions) = create_bench_block(tx_count, 300);

        let short_ids: Vec<_> = transactions
            .iter()
            .map(|(wtxid, _)| ShortId::compute(wtxid, hash.as_bytes(), 0))
            .collect();
        let compact = CompactBlock::new(header, 0, short_ids, vec![]);
        let data = BlockChunker::serialize_compact_block(&compact);

        group.throughput(Throughput::Bytes(data.len() as u64));

        let chunker = BlockChunker::new(10, 3).unwrap();

        group.bench_with_input(
            BenchmarkId::new("txs", tx_count),
            &(compact.clone(), *hash.as_bytes(), data.len()),
            |b, (compact, block_hash, orig_len)| {
                b.iter(|| {
                    let chunks = chunker.compact_block_to_chunks(compact, block_hash).unwrap();
                    let shard_opts: Vec<Option<Vec<u8>>> =
                        chunks.into_iter().map(|c| Some(c.payload)).collect();
                    black_box(chunker.chunks_to_compact_block(shard_opts, *orig_len).unwrap())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compact_block_build,
    bench_fec_encode,
    bench_fec_decode,
    bench_fec_decode_with_loss,
    bench_reconstruction,
    bench_chunker_roundtrip,
);
criterion_main!(benches);
