//! Blocks for exercising body validation in tests, enabled by the
//! `test-support` feature.
//!
//! These are body-validation fixtures, NOT consensus-valid blocks. The header
//! is filler apart from the merkle root and the transactions are structural:
//! nothing here has real proof of work or valid signatures. Use the real blocks
//! in `zcash_pool_common::fixtures` when consensus shape matters.

use crate::ZCASH_FULL_HEADER_SIZE;
use crate::merkle::{MERKLE_ROOT_RANGE, merkle_root, txid_from_tx_bytes};
use zcash_pool_common::write_compact_size;

/// A v5 transaction with empty bundles on the NU7 branch; `seed` is its
/// lock_time, so different seeds give different txids.
pub fn parseable_transaction(seed: u32) -> Vec<u8> {
    let mut tx = hex::decode("050000800a27a726d90a197700000000000000000000000000")
        .expect("static transaction hex");
    tx[12..16].copy_from_slice(&seed.to_le_bytes());
    tx
}

/// A v5 transaction with one transparent output whose script fills it out to
/// about `script_bytes`, for blocks too large for the compact FEC budget.
pub fn parseable_transaction_with_script(seed: u32, script_bytes: usize) -> Vec<u8> {
    let mut tx = parseable_transaction(seed);
    tx.truncate(20);
    tx.push(0); // no inputs
    tx.push(1); // one output
    tx.extend_from_slice(&0u64.to_le_bytes());
    write_compact_size(script_bytes as u64, &mut tx);
    tx.resize(tx.len() + script_bytes, 0x51);
    tx.extend_from_slice(&[0, 0, 0]); // no Sapling spends, outputs or Orchard actions
    tx
}

/// Write the merkle root of `transactions` into `header`.
pub fn commit_header(header: &mut [u8], transactions: &[Vec<u8>]) {
    let txids: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| txid_from_tx_bytes(tx))
        .collect();
    let root = merkle_root(&txids).expect("a test block has transactions");
    header[MERKLE_ROOT_RANGE].copy_from_slice(&root);
}

/// A filler header that commits to `transactions`.
pub fn committed_header(fill: u8, transactions: &[Vec<u8>]) -> Vec<u8> {
    let mut header = vec![fill; ZCASH_FULL_HEADER_SIZE];
    commit_header(&mut header, transactions);
    header
}

/// Serialize `transactions` after `header`.
pub fn raw_block(header: &[u8], transactions: &[Vec<u8>]) -> Vec<u8> {
    let mut block = header.to_vec();
    write_compact_size(transactions.len() as u64, &mut block);
    for tx in transactions {
        block.extend_from_slice(tx);
    }
    block
}
