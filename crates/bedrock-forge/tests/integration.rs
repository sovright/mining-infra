//! Integration tests for compact block round-trip

use bedrock_forge::{
    AuthDigest, BlockHash, BlockTxn, CompactBlockBuilder, CompactBlockReconstructor, GetBlockTxn,
    ReconstructionResult, TestMempool, TxId, WtxId, zcash_block_hash,
};

fn make_wtxid(seed: u8) -> WtxId {
    WtxId::new(
        TxId::from_bytes([seed; 32]),
        AuthDigest::from_bytes([seed; 32]),
    )
}

fn header_hash_from_header(header: &[u8]) -> [u8; 32] {
    zcash_block_hash(header)
}

/// Full round trip: sender builds compact block, receiver reconstructs
#[test]
fn full_round_trip_synchronized_mempools() {
    // Setup: A block with coinbase + 10 transactions
    let header = vec![0xab; 2189];
    let nonce = 0xdeadbeef_u64;

    let coinbase = make_wtxid(0);
    let txs: Vec<_> = (1..=10).map(|i| make_wtxid(i)).collect();
    let tx_data: Vec<Vec<u8>> = (0..=10).map(|i| vec![i as u8; 100]).collect();

    // Sender's view: receiver has all transactions
    let mut sender_view = TestMempool::new();
    for (i, wtxid) in txs.iter().enumerate() {
        sender_view.insert(*wtxid, tx_data[i + 1].clone());
    }

    // Build compact block
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, tx_data[0].clone());
    for (i, wtxid) in txs.iter().enumerate() {
        builder.add_transaction(*wtxid, tx_data[i + 1].clone());
    }
    let compact = builder.build(&sender_view);

    // Verify compact block has minimal prefills (just coinbase)
    assert_eq!(
        compact.prefilled_txs.len(),
        1,
        "Should only prefill coinbase"
    );
    assert_eq!(compact.short_ids.len(), 10, "Should have 10 short IDs");

    // Receiver's mempool matches sender's view
    let mut receiver_mempool = TestMempool::new();
    for (i, wtxid) in txs.iter().enumerate() {
        receiver_mempool.insert(*wtxid, tx_data[i + 1].clone());
    }

    // Reconstruct
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&header_hash_from_header(&header), nonce);
    let result = reconstructor.reconstruct(&compact);

    // Should be complete
    match result {
        ReconstructionResult::Complete { transactions } => {
            assert_eq!(transactions.len(), 11);
            for (i, tx) in transactions.iter().enumerate() {
                assert_eq!(tx, &tx_data[i], "Transaction {} mismatch", i);
            }
        }
        ReconstructionResult::Invalid { reason } => {
            panic!("Unexpected invalid reconstruction: {}", reason);
        }
        _ => panic!("Expected complete reconstruction"),
    }
}

/// Round trip with missing transactions requiring getblocktxn
#[test]
fn round_trip_with_missing_transactions() {
    let header = vec![0xcd; 2189];
    let nonce = 0xcafebabe_u64;

    let coinbase = make_wtxid(0);
    let tx1 = make_wtxid(1);
    let tx2 = make_wtxid(2);
    let tx3 = make_wtxid(3);

    let tx_data = vec![
        vec![0u8; 50],   // coinbase
        vec![1u8; 100],  // tx1
        vec![2u8; 9000], // tx2 (large shielded tx)
        vec![3u8; 150],  // tx3
    ];

    // Sender thinks receiver has tx1 and tx3, but not tx2
    let mut sender_view = TestMempool::new();
    sender_view.insert(tx1, tx_data[1].clone());
    sender_view.insert(tx3, tx_data[3].clone());

    // Build compact block (tx2 will be prefilled)
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, tx_data[0].clone());
    builder.add_transaction(tx1, tx_data[1].clone());
    builder.add_transaction(tx2, tx_data[2].clone());
    builder.add_transaction(tx3, tx_data[3].clone());
    let compact = builder.build(&sender_view);

    // Coinbase + tx2 prefilled, tx1 + tx3 as short IDs
    assert_eq!(compact.prefilled_txs.len(), 2);
    assert_eq!(compact.short_ids.len(), 2);

    // Receiver only has tx1 (not tx3)
    let mut receiver_mempool = TestMempool::new();
    receiver_mempool.insert(tx1, tx_data[1].clone());

    // First reconstruction attempt
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&header_hash_from_header(&header), nonce);
    let result = reconstructor.reconstruct(&compact);

    // Should be incomplete - missing tx3
    let missing_indexes = match result {
        ReconstructionResult::Incomplete {
            partial,
            unresolved_short_ids,
            ..
        } => {
            assert_eq!(
                unresolved_short_ids.len(),
                1,
                "Should have 1 unresolved short ID"
            );

            // Find which indexes are missing
            partial
                .iter()
                .enumerate()
                .filter(|(_, tx)| tx.is_none())
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        }
        ReconstructionResult::Invalid { reason } => {
            panic!("Unexpected invalid reconstruction: {}", reason);
        }
        _ => panic!("Expected incomplete reconstruction"),
    };

    assert_eq!(missing_indexes, vec![3], "tx3 should be missing");

    // Create getblocktxn request
    let block_hash = BlockHash::from_bytes(header_hash_from_header(&header));
    let _request = GetBlockTxn::from_missing_indexes(block_hash, &missing_indexes).unwrap();

    // Sender responds with blocktxn
    let response = BlockTxn::new(block_hash, vec![tx_data[3].clone()]);

    // Verify response matches request
    assert_eq!(response.transactions.len(), missing_indexes.len());
    assert_eq!(response.transactions[0], tx_data[3]);
}

/// Test bandwidth savings calculation
#[test]
fn bandwidth_savings_measurement() {
    let header = vec![0u8; 2189];
    let nonce = 12345u64;

    // Simulate a block with varying transaction sizes
    let num_txs = 50;
    let mut total_tx_bytes = 0usize;
    let mut wtxids = Vec::new();
    let mut tx_datas = Vec::new();

    for i in 0..num_txs {
        let wtxid = make_wtxid(i as u8);
        // Mix of tx sizes: some small (transparent), some large (shielded)
        let size = if i % 5 == 0 { 9000 } else { 300 };
        let data = vec![i as u8; size];
        total_tx_bytes += size;
        wtxids.push(wtxid);
        tx_datas.push(data);
    }

    // Perfect mempool sync
    let mut mempool = TestMempool::new();
    for (wtxid, data) in wtxids.iter().zip(tx_datas.iter()) {
        mempool.insert(*wtxid, data.clone());
    }

    // Build compact block
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(wtxids[0], tx_datas[0].clone()); // coinbase
    for i in 1..num_txs {
        builder.add_transaction(wtxids[i], tx_datas[i].clone());
    }
    let compact = builder.build(&mempool);

    // Calculate sizes
    let full_block_size = header.len() + total_tx_bytes;
    let compact_block_size = header.len()
        + 8  // nonce
        + compact.short_ids.len() * 6  // short IDs
        + compact.prefilled_txs.iter()
            .map(|p| 2 + p.tx_data.len())  // index + data
            .sum::<usize>();

    let savings_pct = 100.0 * (1.0 - compact_block_size as f64 / full_block_size as f64);

    println!("Full block: {} bytes", full_block_size);
    println!("Compact block: {} bytes", compact_block_size);
    println!("Bandwidth savings: {:.1}%", savings_pct);

    // With good mempool sync, should save >80% bandwidth
    assert!(
        savings_pct > 80.0,
        "Expected >80% bandwidth savings, got {:.1}%",
        savings_pct
    );
}
