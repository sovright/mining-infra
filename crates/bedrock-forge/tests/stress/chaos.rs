//! Chaos testing - packet loss, high load, network failures

use std::sync::Arc;
use std::time::{Duration, Instant};

use bedrock_forge::{
    fec::{FecDecoder, FecEncoder},
    AuthDigest, BlockChunker, Chunk, ChunkHeader, CompactBlock, RelayConfig, RelayNode,
    StubPowValidator, ShortId, WtxId,
};

#[path = "../harness/mod.rs"]
mod harness;
use harness::network::{NetworkConditions, PacketFate, SimulatedNetwork};

#[path = "../fixtures/mod.rs"]
mod fixtures;
use fixtures::blocks::{create_synthetic_block, TestBlock};

/// Helper to build compact block bytes
fn build_compact_block(block: &TestBlock) -> CompactBlock {
    CompactBlock::new(
        block.header.clone(),
        0,
        block
            .transactions
            .iter()
            .map(|(txid, _)| {
                let wtxid = WtxId::new(*txid, AuthDigest::from_bytes([0u8; 32]));
                ShortId::compute(&wtxid, block.hash.as_bytes(), 0)
            })
            .collect(),
        vec![],
    )
}

/// Test: FEC recovery under packet loss
#[tokio::test]
async fn stress_fec_recovery_under_loss() {
    let block = create_synthetic_block(100, 300);
    let compact = build_compact_block(&block);
    let data = BlockChunker::serialize_compact_block(&compact);

    let encoder = FecEncoder::new(10, 5).unwrap(); // 10 data + 5 parity
    let decoder = FecDecoder::new(10, 5).unwrap();
    let shards = encoder.encode(&data).unwrap();

    // Simulate various loss rates
    for loss_rate in [0.1, 0.2, 0.3] {
        let conditions = NetworkConditions {
            packet_loss: loss_rate,
            ..Default::default()
        };
        let network = SimulatedNetwork::with_seed(conditions, 42);

        // Simulate sending all shards and filtering by network
        let mut received = Vec::new();
        let mut received_indices = Vec::new();
        for (i, shard) in shards.iter().enumerate() {
            if network.process_packet() == PacketFate::Delivered {
                received.push(shard.clone());
                received_indices.push(i);
            }
        }

        let stats = network.stats();

        // With 10 data + 5 parity, we need at least 10 shards
        if received.len() >= 10 {
            // Build Option<Vec<u8>> with correct positions
            let mut shard_opts = vec![None; 15];
            for (shard, idx) in received.into_iter().zip(received_indices.into_iter()) {
                shard_opts[idx] = Some(shard);
            }

            let decoded = decoder.decode(shard_opts, data.len());
            assert!(
                decoded.is_ok(),
                "Should decode with {} shards (loss rate {})",
                stats.packets_delivered,
                loss_rate
            );
            assert_eq!(decoded.unwrap(), data);
        }
    }
}

/// Test: High throughput chunk processing
#[tokio::test]
async fn stress_high_throughput() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_unauthenticated_peers_allowed(true);
    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create socket and send many chunks rapidly
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let block_hash = [0xABu8; 32];
    let chunk_data = vec![0u8; 1024];

    let start = Instant::now();
    let num_chunks = 10_000;

    for i in 0..num_chunks {
        let header = ChunkHeader::new_block(&block_hash, (i % 100) as u16, 100, chunk_data.len() as u16);
        let chunk = Chunk::new(header, chunk_data.clone());
        let _ = socket.send_to(&chunk.to_bytes(), addr).await;
    }

    let elapsed = start.elapsed();
    let rate = num_chunks as f64 / elapsed.as_secs_f64();

    // Give relay time to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics = node.metrics().snapshot();

    println!(
        "Sent {} chunks in {:?} ({:.0} chunks/sec)",
        num_chunks, elapsed, rate
    );
    println!("Relay received: {} packets", metrics.packets_received);

    // Should handle at least 1000 chunks/sec
    assert!(rate > 1000.0, "Throughput too low: {:.0} chunks/sec", rate);

    node.stop();
    let _ = handle.await;
}

/// Test: Multiple concurrent senders
#[tokio::test]
async fn stress_concurrent_senders() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_unauthenticated_peers_allowed(true);
    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn 10 concurrent senders
    let num_senders = 10;
    let chunks_per_sender = 1000;

    let mut sender_handles = Vec::new();

    for sender_id in 0..num_senders {
        let addr = addr;
        sender_handles.push(tokio::spawn(async move {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let chunk_data = vec![sender_id as u8; 512];
            let mut block_hash = [0u8; 32];
            block_hash[0] = sender_id as u8;

            for i in 0..chunks_per_sender {
                let header =
                    ChunkHeader::new_block(&block_hash, (i % 50) as u16, 50, chunk_data.len() as u16);
                let chunk = Chunk::new(header, chunk_data.clone());
                let _ = socket.send_to(&chunk.to_bytes(), addr).await;
            }
        }));
    }

    // Wait for all senders
    for h in sender_handles {
        let _ = h.await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics = node.metrics().snapshot();
    let expected = (num_senders * chunks_per_sender) as u64;

    println!(
        "Expected {} packets, received {}",
        expected, metrics.packets_received
    );

    // Should receive a good portion of packets (UDP loss can be significant with concurrent senders)
    // On macOS with 10 concurrent senders, loss rates of 20-30% are common
    assert!(
        metrics.packets_received > expected * 50 / 100,
        "Too many packets lost: {} of {} (only {}% received)",
        expected - metrics.packets_received,
        expected,
        metrics.packets_received * 100 / expected
    );

    node.stop();
    let _ = handle.await;
}

/// Test: Large block handling
#[tokio::test]
async fn stress_large_block() {
    // 2MB block worth of data
    let large_data = vec![0xABu8; 2 * 1024 * 1024];

    let encoder = FecEncoder::new(100, 30).unwrap(); // More shards for large data
    let decoder = FecDecoder::new(100, 30).unwrap();

    let start = Instant::now();
    let shards = encoder.encode(&large_data).unwrap();
    let encode_time = start.elapsed();

    println!(
        "Encoded {}MB into {} shards in {:?}",
        large_data.len() / 1024 / 1024,
        shards.len(),
        encode_time
    );

    // Simulate 10% loss (drop every 10th shard)
    let shard_opts: Vec<Option<Vec<u8>>> = shards
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i % 10 == 0 {
                None
            } else {
                Some(s.clone())
            }
        })
        .collect();

    let received_count = shard_opts.iter().filter(|s| s.is_some()).count();

    let start = Instant::now();
    let decoded = decoder.decode(shard_opts, large_data.len()).unwrap();
    let decode_time = start.elapsed();

    println!(
        "Decoded with {} shards ({} lost) in {:?}",
        received_count,
        130 - received_count,
        decode_time
    );

    assert_eq!(decoded, large_data);

    // Should be reasonably fast
    assert!(encode_time < Duration::from_secs(1), "Encoding too slow");
    assert!(decode_time < Duration::from_secs(1), "Decoding too slow");
}

/// Test: Graceful degradation under extreme loss
#[tokio::test]
async fn stress_extreme_loss_graceful() {
    let data = vec![0xABu8; 100 * 1024]; // 100KB
    let encoder = FecEncoder::new(10, 10).unwrap(); // 50% redundancy
    let decoder = FecDecoder::new(10, 10).unwrap();
    let shards = encoder.encode(&data).unwrap();

    // 60% loss - should fail but gracefully
    let conditions = NetworkConditions {
        packet_loss: 0.6,
        ..Default::default()
    };
    let network = SimulatedNetwork::with_seed(conditions, 999);

    let mut received = Vec::new();
    let mut indices = Vec::new();
    for (i, shard) in shards.iter().enumerate() {
        if network.process_packet() == PacketFate::Delivered {
            received.push(shard.clone());
            indices.push(i);
        }
    }

    println!(
        "With 60% loss: {} of {} shards received",
        received.len(),
        20
    );

    // Build shard_opts with correct positions
    let mut shard_opts = vec![None; 20];
    for (shard, idx) in received.into_iter().zip(indices.into_iter()) {
        shard_opts[idx] = Some(shard);
    }

    let received_count = shard_opts.iter().filter(|s| s.is_some()).count();
    let result = decoder.decode(shard_opts, data.len());

    if received_count >= 10 {
        assert!(result.is_ok(), "Should decode with enough shards");
    } else {
        assert!(
            result.is_err(),
            "Should fail gracefully with too few shards"
        );
    }
}

/// Test: Rapid block succession
#[tokio::test]
async fn stress_rapid_blocks() {
    let encoder = FecEncoder::new(10, 3).unwrap();
    let decoder = FecDecoder::new(10, 3).unwrap();

    let start = Instant::now();
    let num_blocks = 100;

    for i in 0..num_blocks {
        let block = create_synthetic_block(50, 200);
        let compact = build_compact_block(&block);
        let data = BlockChunker::serialize_compact_block(&compact);

        let shards = encoder.encode(&data).unwrap();
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let decoded = decoder.decode(shard_opts, data.len()).unwrap();

        assert_eq!(decoded, data, "Block {} failed", i);
    }

    let elapsed = start.elapsed();
    let rate = num_blocks as f64 / elapsed.as_secs_f64();

    println!(
        "Processed {} blocks in {:?} ({:.1} blocks/sec)",
        num_blocks, elapsed, rate
    );

    // Should handle at least 10 blocks/sec
    assert!(rate > 10.0, "Block processing too slow: {:.1} blocks/sec", rate);
}
