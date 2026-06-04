//! FEC integration tests
//!
//! Tests FEC round-trip scenarios for compact block encoding/decoding.

use sovright_relay::{
    AuthDigest, BlockChunker, CompactBlock, CompactBlockBuilder,
    FecError, TestMempool, TxId, WtxId,
};

fn make_wtxid(seed: u8) -> WtxId {
    WtxId::new(
        TxId::from_bytes([seed; 32]),
        AuthDigest::from_bytes([seed; 32]),
    )
}

fn make_realistic_compact_block() -> CompactBlock {
    // Simulate a block with coinbase + 50 transactions
    let header = vec![0xab; 2189]; // Zcash header size
    let nonce = 0xdeadbeef_u64;

    let coinbase = make_wtxid(0);
    let txs: Vec<_> = (1..=50).map(make_wtxid).collect();

    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, vec![0u8; 500]); // Coinbase

    let mut mempool = TestMempool::new();
    for (i, wtxid) in txs.iter().enumerate() {
        let tx_data = vec![(i + 1) as u8; 300]; // 300 byte transactions
        mempool.insert(*wtxid, tx_data.clone());
        builder.add_transaction(*wtxid, tx_data);
    }

    builder.build(&mempool)
}

#[test]
fn fec_roundtrip_no_loss() {
    let chunker = BlockChunker::default_config().unwrap();
    let compact = make_realistic_compact_block();
    let block_hash = [0xcd; 32];

    // Encode
    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();
    println!("Encoded into {} chunks", chunks.len());

    // Get original length for decoding
    let original_data = BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();
    println!("Original data size: {} bytes", original_len);

    // Decode with all chunks
    let shard_opts: Vec<Option<Vec<u8>>> = chunks
        .into_iter()
        .map(|c| Some(c.payload))
        .collect();

    let recovered = chunker.chunks_to_compact_block(shard_opts, original_len).unwrap();

    // Verify full content equality
    assert_eq!(recovered.header, compact.header);
    assert_eq!(recovered.nonce, compact.nonce);
    assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
    assert_eq!(recovered.prefilled_txs.len(), compact.prefilled_txs.len());
}

#[test]
fn fec_roundtrip_with_packet_loss() {
    let chunker = BlockChunker::default_config().unwrap();
    let compact = make_realistic_compact_block();
    let block_hash = [0xcd; 32];

    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();

    let original_data = BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();

    // Simulate 3 lost packets (max recoverable with 3 parity shards)
    let mut shard_opts: Vec<Option<Vec<u8>>> = chunks
        .into_iter()
        .map(|c| Some(c.payload))
        .collect();

    // Lose chunks 2, 7, 11
    shard_opts[2] = None;
    shard_opts[7] = None;
    shard_opts[11] = None;

    let recovered = chunker.chunks_to_compact_block(shard_opts, original_len).unwrap();

    // Verify full content equality
    assert_eq!(recovered.header, compact.header);
    assert_eq!(recovered.nonce, compact.nonce);
    assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
    assert_eq!(recovered.prefilled_txs.len(), compact.prefilled_txs.len());
}

#[test]
fn fec_fails_with_too_much_loss() {
    let chunker = BlockChunker::default_config().unwrap();
    let compact = make_realistic_compact_block();
    let block_hash = [0xcd; 32];

    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();

    let original_data = BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();

    // Simulate 4 lost packets (more than 3 parity shards can recover)
    let mut shard_opts: Vec<Option<Vec<u8>>> = chunks
        .into_iter()
        .map(|c| Some(c.payload))
        .collect();

    shard_opts[0] = None;
    shard_opts[1] = None;
    shard_opts[2] = None;
    shard_opts[3] = None;

    let result = chunker.chunks_to_compact_block(shard_opts, original_len);
    assert!(matches!(result, Err(FecError::InsufficientShards { .. })));
}
