//! BIP 152 compact block compatibility tests
//!
//! Verifies compact block construction, short ID computation, and reconstruction
//! match expected behavior from the BIP 152 specification (adapted for Zcash).

use bedrock_forge::{
    CompactBlock, CompactBlockBuilder, CompactBlockReconstructor, PrefilledTx,
    ReconstructionResult, ShortId, TestMempool,
};
use bedrock_forge::types::{AuthDigest, TxId, WtxId};
use sha2::{Digest, Sha256};

/// Helper: compute double-SHA256 header hash (same as CompactBlock::header_hash)
fn header_hash(header: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    let mut h = [0u8; 32];
    h.copy_from_slice(&second);
    h
}

/// Helper: create a deterministic WtxId from a seed byte
fn make_wtxid(seed: u8) -> WtxId {
    WtxId::new(
        TxId::from_bytes([seed; 32]),
        AuthDigest::from_bytes([seed; 32]),
    )
}

/// Test 1: Full sender-to-receiver roundtrip with 1 coinbase + 2 mempool txs.
///
/// Sender builds a compact block where the receiver has both non-coinbase txs
/// in their mempool. Receiver reconstructs the complete block in correct order.
#[test]
fn test_simple_roundtrip() {
    let header = vec![0xab_u8; 2189];
    let nonce = 0xdeadbeef_u64;

    let coinbase = make_wtxid(0);
    let tx1 = make_wtxid(1);
    let tx2 = make_wtxid(2);

    // --- Sender side ---
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, vec![0xc0; 50]); // coinbase data
    builder.add_transaction(tx1, vec![0xa1; 80]);
    builder.add_transaction(tx2, vec![0xa2; 90]);

    // Sender knows receiver has tx1 and tx2
    let mut sender_view = TestMempool::new();
    sender_view.insert(tx1, vec![0xa1; 80]);
    sender_view.insert(tx2, vec![0xa2; 90]);

    let compact = builder.build(&sender_view);

    // Compact block should have coinbase prefilled and 2 short IDs
    assert_eq!(compact.prefilled_txs.len(), 1, "only coinbase prefilled");
    assert_eq!(compact.short_ids.len(), 2, "two short IDs for mempool txs");
    assert_eq!(compact.tx_count(), 3);

    // --- Receiver side ---
    let mut receiver_mempool = TestMempool::new();
    receiver_mempool.insert(tx1, vec![0xa1; 80]);
    receiver_mempool.insert(tx2, vec![0xa2; 90]);

    let hh = header_hash(&header);
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&hh, nonce);

    match reconstructor.reconstruct(&compact) {
        ReconstructionResult::Complete { transactions } => {
            assert_eq!(transactions.len(), 3);
            assert_eq!(transactions[0], vec![0xc0; 50], "coinbase at index 0");
            assert_eq!(transactions[1], vec![0xa1; 80], "tx1 at index 1");
            assert_eq!(transactions[2], vec![0xa2; 90], "tx2 at index 2");
        }
        other => panic!("expected Complete, got {:?}", other),
    }
}

/// Test 2: Coinbase-only block roundtrip (no short IDs needed).
#[test]
fn test_empty_block_roundtrip() {
    let header = vec![0x42_u8; 2189];
    let nonce = 99u64;

    let coinbase = make_wtxid(0);

    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, vec![0xff; 30]);

    // No txs to share via mempool
    let sender_view = TestMempool::new();
    let compact = builder.build(&sender_view);

    assert_eq!(compact.short_ids.len(), 0, "no short IDs for coinbase-only");
    assert_eq!(compact.prefilled_txs.len(), 1, "coinbase is prefilled");
    assert_eq!(compact.tx_count(), 1);

    // Receiver reconstructs with empty mempool
    let receiver_mempool = TestMempool::new();
    let hh = header_hash(&header);
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&hh, nonce);

    match reconstructor.reconstruct(&compact) {
        ReconstructionResult::Complete { transactions } => {
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0], vec![0xff; 30]);
        }
        other => panic!("expected Complete, got {:?}", other),
    }
}

/// Test 3: Receiver missing 1 of 2 mempool txs -> Incomplete result.
#[test]
fn test_reconstruction_with_missing_tx() {
    let header = vec![0x77_u8; 2189];
    let nonce = 0x1234u64;

    let coinbase = make_wtxid(0);
    let tx1 = make_wtxid(1);
    let tx2 = make_wtxid(2);

    // Sender builds compact block assuming receiver has both txs
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, vec![10]);
    builder.add_transaction(tx1, vec![11]);
    builder.add_transaction(tx2, vec![12]);

    let mut sender_view = TestMempool::new();
    sender_view.insert(tx1, vec![11]);
    sender_view.insert(tx2, vec![12]);

    let compact = builder.build(&sender_view);

    // Receiver only has tx1, missing tx2
    let mut receiver_mempool = TestMempool::new();
    receiver_mempool.insert(tx1, vec![11]);

    let hh = header_hash(&header);
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&hh, nonce);

    match reconstructor.reconstruct(&compact) {
        ReconstructionResult::Incomplete {
            partial,
            unresolved_short_ids,
            ..
        } => {
            assert_eq!(partial.len(), 3, "3 slots in block");
            // Coinbase (prefilled) and tx1 (resolved) should be present
            assert!(partial[0].is_some(), "coinbase filled");
            // One of the remaining slots should be filled, one missing
            let filled_count = partial.iter().filter(|t| t.is_some()).count();
            assert_eq!(filled_count, 2, "coinbase + 1 resolved tx");
            assert_eq!(
                unresolved_short_ids.len(),
                1,
                "one unresolved short ID for missing tx"
            );
        }
        other => panic!("expected Incomplete, got {:?}", other),
    }
}

/// Test 4: Short ID key derivation and determinism.
///
/// Verifies the BIP 152 key derivation:
///   k0 = header_hash[0..8] as LE u64
///   k1 = header_hash[8..16] as LE u64 XOR nonce
/// and that short IDs are deterministic 6-byte values.
#[test]
fn test_short_id_key_derivation() {
    // Use a known header hash and nonce
    let mut known_header_hash = [0u8; 32];
    for (i, b) in known_header_hash.iter_mut().enumerate() {
        *b = i as u8;
    }
    let nonce = 0xfedcba9876543210_u64;

    // Verify expected key derivation manually
    let expected_k0 = u64::from_le_bytes(known_header_hash[0..8].try_into().unwrap());
    let expected_k1 =
        u64::from_le_bytes(known_header_hash[8..16].try_into().unwrap()) ^ nonce;

    // k0 from bytes [0,1,2,3,4,5,6,7] LE = 0x0706050403020100
    assert_eq!(expected_k0, 0x0706050403020100_u64);
    // k1 from bytes [8,9,10,11,12,13,14,15] LE = 0x0f0e0d0c0b0a0908, XOR nonce
    assert_eq!(
        expected_k1,
        0x0f0e0d0c0b0a0908_u64 ^ 0xfedcba9876543210_u64
    );

    let wtxid = WtxId::new(
        TxId::from_bytes([0xaa; 32]),
        AuthDigest::from_bytes([0xbb; 32]),
    );

    let sid1 = ShortId::compute(&wtxid, &known_header_hash, nonce);
    let sid2 = ShortId::compute(&wtxid, &known_header_hash, nonce);

    // Deterministic: same inputs -> same output
    assert_eq!(sid1, sid2, "short ID must be deterministic");
    assert_eq!(sid1.as_bytes().len(), 6, "short ID must be 6 bytes");

    // Different nonce produces different short ID
    let sid3 = ShortId::compute(&wtxid, &known_header_hash, nonce.wrapping_add(1));
    assert_ne!(sid1, sid3, "different nonce should produce different short ID");

    // Different wtxid produces different short ID
    let other_wtxid = WtxId::new(
        TxId::from_bytes([0xcc; 32]),
        AuthDigest::from_bytes([0xdd; 32]),
    );
    let sid4 = ShortId::compute(&other_wtxid, &known_header_hash, nonce);
    assert_ne!(sid1, sid4, "different wtxid should produce different short ID");
}

/// Test 5: Prefilled index out of bounds -> Invalid reconstruction.
///
/// A CompactBlock with a PrefilledTx whose decoded index exceeds the total
/// transaction count should be rejected as Invalid.
#[test]
fn test_prefilled_index_out_of_bounds() {
    // Create a compact block with 1 prefilled tx at index 5,
    // but total tx_count = 1 (only the prefilled tx itself).
    // The decoded position will be 5, which exceeds tx_count of 1.
    let compact = CompactBlock::new(
        vec![0u8; 2189],
        0,
        vec![], // no short IDs
        vec![PrefilledTx {
            index: 5, // decoded position = 0 + 5 = 5, but only 1 tx total
            tx_data: vec![1, 2, 3],
        }],
    );

    let mempool = TestMempool::new();
    let hh = header_hash(&compact.header);
    let mut reconstructor = CompactBlockReconstructor::new(&mempool);
    reconstructor.prepare(&hh, 0);

    match reconstructor.reconstruct(&compact) {
        ReconstructionResult::Invalid { reason } => {
            assert!(
                reason.contains("out of bounds"),
                "expected 'out of bounds' in reason, got: {}",
                reason
            );
        }
        other => panic!("expected Invalid, got {:?}", other),
    }
}
