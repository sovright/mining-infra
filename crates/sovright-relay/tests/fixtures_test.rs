//! Test the fixtures module

mod fixtures;

use fixtures::blocks::{create_large_block, create_minimal_block, create_synthetic_block, create_testnet_block};

#[test]
fn synthetic_block_creation() {
    let block = create_synthetic_block(10, 250);
    assert_eq!(block.tx_count(), 10);
    assert_eq!(block.header.len(), 1487);
    // Header + 10 txs of 250 bytes
    assert_eq!(block.total_size(), 1487 + 10 * 250);
}

#[test]
fn testnet_block_reasonable_size() {
    let block = create_testnet_block();
    assert!(block.tx_count() >= 10);
    assert!(block.total_size() > 10_000); // At least 10KB
}

#[test]
fn large_block_creation() {
    let block = create_large_block();
    assert_eq!(block.tx_count(), 2500);
    assert!(block.total_size() > 1_000_000); // At least 1MB
}

#[test]
fn minimal_block_creation() {
    let block = create_minimal_block();
    assert_eq!(block.tx_count(), 1);
}
