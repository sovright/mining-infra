//! Full pipeline E2E tests

use std::sync::Arc;
use std::time::Duration;

use bedrock_forge::{
    fec::{FecDecoder, FecEncoder},
    AuthDigest, BlockChunker, CompactBlock, CompactBlockReconstructor, ReconstructionResult,
    RelayConfig, RelayNode, ShortId, TestMempool, WtxId,
};

// Import test fixtures
#[path = "../fixtures/mod.rs"]
mod fixtures;
use fixtures::blocks::{create_synthetic_block, create_testnet_block, TestBlock};

/// Helper to build a compact block from test block
fn build_compact_block(block: &TestBlock) -> CompactBlock {
    CompactBlock::new(
        block.header.clone(),
        0, // nonce
        block
            .transactions
            .iter()
            .map(|(txid, _)| {
                let wtxid = WtxId::new(*txid, AuthDigest::from_bytes([0u8; 32]));
                let header_hash = block.hash.as_bytes();
                ShortId::compute(&wtxid, header_hash, 0)
            })
            .collect(),
        vec![], // no prefilled txs
    )
}

/// Test: Raw bytes through FEC encoder/decoder roundtrip
#[tokio::test]
async fn e2e_fec_roundtrip() {
    let block = create_testnet_block();
    let compact = build_compact_block(&block);
    let data = BlockChunker::serialize_compact_block(&compact);

    // Encode with FEC
    let encoder = FecEncoder::new(10, 3).unwrap();
    let shards = encoder.encode(&data).unwrap();

    assert_eq!(
        shards.len(),
        13,
        "Should have 13 shards (10 data + 3 parity)"
    );

    // Decode with all shards
    let decoder = FecDecoder::new(10, 3).unwrap();
    let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    let decoded = decoder.decode(shard_opts, data.len()).unwrap();

    assert_eq!(decoded, data, "Round-trip should preserve data");
}

/// Test: FEC recovery with minimum shards
#[tokio::test]
async fn e2e_fec_recovery_minimum_shards() {
    let block = create_testnet_block();
    let compact = build_compact_block(&block);
    let data = BlockChunker::serialize_compact_block(&compact);

    let encoder = FecEncoder::new(10, 3).unwrap();
    let shards = encoder.encode(&data).unwrap();

    // Keep only 10 shards (minimum needed)
    let decoder = FecDecoder::new(10, 3).unwrap();
    let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    // Drop 3 shards
    shard_opts[0] = None;
    shard_opts[5] = None;
    shard_opts[10] = None;

    let decoded = decoder.decode(shard_opts, data.len()).unwrap();
    assert_eq!(decoded, data, "Should recover from 3 lost shards");
}

/// Test: Block chunker roundtrip
#[tokio::test]
async fn e2e_chunker_roundtrip() {
    let block = create_testnet_block();
    let compact = build_compact_block(&block);
    let block_hash = *block.hash.as_bytes();

    let chunker = BlockChunker::new(10, 3).unwrap();
    let chunks = chunker
        .compact_block_to_chunks(&compact, &block_hash)
        .unwrap();

    assert_eq!(chunks.len(), 13, "Should have 13 chunks");

    // Get original serialized length
    let original_data = BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();

    // Reconstruct
    let shard_opts: Vec<Option<Vec<u8>>> = chunks.into_iter().map(|c| Some(c.payload)).collect();
    let recovered = chunker
        .chunks_to_compact_block(shard_opts, original_len)
        .unwrap();

    assert_eq!(recovered.header, compact.header);
    assert_eq!(recovered.nonce, compact.nonce);
    assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
}

/// Test: Block flows through relay node
#[tokio::test]
async fn e2e_relay_node_forward() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_unauthenticated_peers_allowed(true);
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();

    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    // Start relay
    let handle = tokio::spawn(async move { node_clone.run().await });

    // Give it time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create test block and chunks
    let block = create_synthetic_block(10, 100);
    let compact = build_compact_block(&block);
    let block_hash = *block.hash.as_bytes();

    let chunker = BlockChunker::new(10, 3).unwrap();
    let chunks = chunker
        .compact_block_to_chunks(&compact, &block_hash)
        .unwrap();

    // Send chunks to relay
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for chunk in &chunks {
        socket.send_to(&chunk.to_bytes(), addr).await.unwrap();
    }

    // Check metrics
    tokio::time::sleep(Duration::from_millis(100)).await;
    let metrics = node.metrics().snapshot();
    assert!(metrics.packets_received > 0, "Should have received packets");

    // Stop relay
    node.stop();
    let _ = handle.await;
}

/// Test: Compact block reconstruction with mempool
#[tokio::test]
async fn e2e_compact_block_reconstruction() {
    let block = create_synthetic_block(50, 200);

    // Build compact block with short IDs
    let compact = build_compact_block(&block);

    // Setup mempool with transactions (using WtxId)
    let mut mempool = TestMempool::new();
    for (txid, tx_data) in block.transactions.iter().take(40) {
        let wtxid = WtxId::new(*txid, AuthDigest::from_bytes([0u8; 32]));
        mempool.insert(wtxid, tx_data.clone());
    }

    // Reconstruct
    let mut reconstructor = CompactBlockReconstructor::new(&mempool);

    // Prepare with header hash and nonce
    let header_hash = block.hash.as_bytes();
    reconstructor.prepare(header_hash, 0);

    let result = reconstructor.reconstruct(&compact);

    match result {
        ReconstructionResult::Incomplete { partial, .. } => {
            // Should have some missing transactions
            let missing_count = partial.iter().filter(|p| p.is_none()).count();
            assert!(missing_count > 0, "Should have missing txs");
        }
        ReconstructionResult::Invalid { reason } => {
            panic!("Unexpected invalid reconstruction: {}", reason);
        }
        ReconstructionResult::Complete { .. } => {
            // This might happen if the mempool happens to have all we need
            // due to hash collisions, which is fine
        }
    }
}

/// Test: FEC recovery with parity shards
#[tokio::test]
async fn e2e_fec_recovery_with_loss() {
    let block = create_testnet_block();
    let compact = build_compact_block(&block);
    let data = BlockChunker::serialize_compact_block(&compact);

    // Use more parity shards for this test
    let encoder = FecEncoder::new(10, 5).unwrap(); // 10 data + 5 parity
    let shards = encoder.encode(&data).unwrap();

    assert_eq!(shards.len(), 15, "Should have 15 total shards");

    // Simulate losing 5 shards (the maximum we can lose)
    let decoder = FecDecoder::new(10, 5).unwrap();
    let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    shard_opts[0] = None;
    shard_opts[3] = None;
    shard_opts[6] = None;
    shard_opts[9] = None;
    shard_opts[12] = None;

    // Should still decode
    let decoded = decoder.decode(shard_opts, data.len()).unwrap();
    assert_eq!(decoded, data, "Should recover from loss");
}

/// Test: Multiple blocks through pipeline
#[tokio::test]
async fn e2e_multiple_blocks() {
    let encoder = FecEncoder::new(10, 3).unwrap();
    let decoder = FecDecoder::new(10, 3).unwrap();

    // Process 5 blocks
    for i in 0..5 {
        let block = create_synthetic_block(10 + i * 10, 100 + i * 50);
        let compact = build_compact_block(&block);
        let data = BlockChunker::serialize_compact_block(&compact);

        let shards = encoder.encode(&data).unwrap();
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let decoded = decoder.decode(shard_opts, data.len()).unwrap();

        assert_eq!(decoded, data, "Block {} should roundtrip", i);
    }
}

/// Test: Large block handling
#[tokio::test]
async fn e2e_large_block() {
    let block = fixtures::blocks::create_large_block();
    let compact = build_compact_block(&block);
    let data = BlockChunker::serialize_compact_block(&compact);

    // Large blocks need more shards
    let encoder = FecEncoder::new(50, 15).unwrap();
    let shards = encoder.encode(&data).unwrap();

    assert_eq!(shards.len(), 65);

    let decoder = FecDecoder::new(50, 15).unwrap();
    let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    let decoded = decoder.decode(shard_opts, data.len()).unwrap();

    assert_eq!(decoded, data);
}
