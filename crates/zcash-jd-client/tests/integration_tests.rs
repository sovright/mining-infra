//! JD Client integration tests
//!
//! These tests verify the JD Client components including:
//! - Configuration defaults
//! - Template building
//! - Block hex construction
//! - Error type handling

use zcash_jd_client::{
    BlockSubmitter, JdClientConfig, JdClientError, TemplateBuilder, TxSelectionStrategy,
};

#[test]
fn test_client_config_defaults() {
    let config = JdClientConfig::default();
    assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
    assert_eq!(config.pool_jd_addr.port(), 3334);
    assert_eq!(config.user_identifier, "zcash-jd-client");
    assert_eq!(config.template_poll_ms, 1000);
    assert!(config.miner_payout_address.is_none());
    // Noise is disabled by default
    assert!(!config.noise_enabled);
    assert!(config.pool_public_key.is_none());
    // Full-Template mode is disabled by default
    assert!(!config.full_template_mode);
    assert_eq!(config.tx_selection, TxSelectionStrategy::All);
}

#[test]
fn test_client_config_custom() {
    let config = JdClientConfig {
        zebra_url: "http://192.168.1.100:8232".to_string(),
        pool_jd_addr: "10.0.0.1:3335".parse().unwrap(),
        user_identifier: "my-miner".to_string(),
        template_poll_ms: 500,
        miner_payout_address: Some("t1abc123...".to_string()),
        noise_enabled: true,
        pool_public_key: Some("abc123".to_string()),
        full_template_mode: true,
        tx_selection: TxSelectionStrategy::ByFeeRate,
    };

    assert_eq!(config.zebra_url, "http://192.168.1.100:8232");
    assert_eq!(config.pool_jd_addr.port(), 3335);
    assert_eq!(config.user_identifier, "my-miner");
    assert_eq!(config.template_poll_ms, 500);
    assert_eq!(config.miner_payout_address, Some("t1abc123...".to_string()));
    assert!(config.noise_enabled);
    assert_eq!(config.pool_public_key, Some("abc123".to_string()));
    assert!(config.full_template_mode);
    assert_eq!(config.tx_selection, TxSelectionStrategy::ByFeeRate);
}

#[test]
fn test_template_builder() {
    let builder = TemplateBuilder::new(
        vec![0x76, 0xa9, 0x14], // P2PKH prefix
        256,
        Some("t1abc...".to_string()),
    );

    assert_eq!(builder.max_additional_size(), 256);
    assert_eq!(builder.pool_coinbase_output(), &[0x76, 0xa9, 0x14]);
    assert!(builder.miner_payout_address().is_some());
    assert_eq!(builder.miner_payout_address(), Some("t1abc..."));
}

#[test]
fn test_template_builder_no_miner_address() {
    let builder = TemplateBuilder::new(vec![0x76, 0xa9, 0x14], 512, None);

    assert_eq!(builder.max_additional_size(), 512);
    assert!(builder.miner_payout_address().is_none());
}

#[test]
fn test_template_builder_set_pool_output() {
    let mut builder = TemplateBuilder::new(vec![], 0, None);

    assert!(builder.pool_coinbase_output().is_empty());
    assert_eq!(builder.max_additional_size(), 0);

    builder.set_pool_output(vec![0x01, 0x02, 0x03], 1024);

    assert_eq!(builder.pool_coinbase_output(), &[0x01, 0x02, 0x03]);
    assert_eq!(builder.max_additional_size(), 1024);
}

#[test]
fn test_block_submitter_hex_building() {
    let header = [0xaa; 140];
    let solution = [0xbb; 1344];
    let coinbase_tx = vec![0x01; 100];
    let transactions: Vec<Vec<u8>> = vec![];

    let hex = BlockSubmitter::build_block_hex(&header, &solution, &coinbase_tx, &transactions);

    // Verify it starts with header (all 0xaa)
    assert!(hex.starts_with("aa"));

    // Verify length: header(140) + fd(1) + len(2) + solution(1344) + tx_count(1) + coinbase(100) = 1588 bytes = 3176 hex chars
    assert_eq!(hex.len(), 3176);
}

#[test]
fn test_block_submitter_hex_with_transactions() {
    let header = [0xaa; 140];
    let solution = [0xbb; 1344];
    let coinbase_tx = vec![0x01; 100];
    let transactions: Vec<Vec<u8>> = vec![
        vec![0x02; 50], // tx1
        vec![0x03; 75], // tx2
    ];

    let hex = BlockSubmitter::build_block_hex(&header, &solution, &coinbase_tx, &transactions);

    // header(140) + fd(1) + len(2) + solution(1344) + tx_count(1) + coinbase(100) + tx1(50) + tx2(75) = 1713 bytes = 3426 hex chars
    assert_eq!(hex.len(), 3426);
}

#[test]
fn test_error_types() {
    // Test ConnectionFailed error
    let err = JdClientError::ConnectionFailed("test".to_string());
    assert!(err.to_string().contains("test"));
    assert!(err.to_string().contains("Connection failed"));

    // Test TokenAllocationFailed error
    let err = JdClientError::TokenAllocationFailed("expired".to_string());
    assert!(err.to_string().contains("expired"));
    assert!(err.to_string().contains("Token allocation failed"));

    // Test JobRejected error
    let err = JdClientError::JobRejected("stale prev_hash".to_string());
    assert!(err.to_string().contains("stale prev_hash"));
    assert!(err.to_string().contains("Job declaration rejected"));

    // Test BlockSubmissionFailed error
    let err = JdClientError::BlockSubmissionFailed("network error".to_string());
    assert!(err.to_string().contains("network error"));
    assert!(err.to_string().contains("Block submission failed"));

    // Test Protocol error
    let err = JdClientError::Protocol("invalid message".to_string());
    assert!(err.to_string().contains("invalid message"));
    assert!(err.to_string().contains("Protocol error"));
}

#[test]
fn test_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let jd_err: JdClientError = io_err.into();
    assert!(jd_err.to_string().contains("IO error"));
}

#[test]
fn test_block_hex_structure() {
    // Test that the block hex is correctly structured
    let header = [0x01; 140];
    let solution = [0x02; 1344];
    let coinbase_tx = vec![0x03; 50];
    let transactions: Vec<Vec<u8>> = vec![];

    let hex = BlockSubmitter::build_block_hex(&header, &solution, &coinbase_tx, &transactions);
    let bytes = hex::decode(&hex).unwrap();

    // Verify header
    assert_eq!(&bytes[0..140], &[0x01; 140]);

    // Verify solution length prefix (0xfd + 2 bytes for 1344)
    assert_eq!(bytes[140], 0xfd);
    let solution_len = u16::from_le_bytes([bytes[141], bytes[142]]);
    assert_eq!(solution_len, 1344);

    // Verify solution
    assert_eq!(&bytes[143..143 + 1344], &[0x02; 1344]);

    // Verify transaction count (1 coinbase only)
    assert_eq!(bytes[143 + 1344], 1);

    // Verify coinbase
    assert_eq!(&bytes[143 + 1344 + 1..143 + 1344 + 1 + 50], &[0x03; 50]);
}

#[test]
fn test_config_socket_addr() {
    let config = JdClientConfig::default();

    // Default should be 127.0.0.1:3334
    assert!(config.pool_jd_addr.ip().is_loopback());
    assert_eq!(config.pool_jd_addr.port(), 3334);

    // Test parsing different addresses
    let custom_config = JdClientConfig {
        pool_jd_addr: "0.0.0.0:4444".parse().unwrap(),
        ..JdClientConfig::default()
    };
    assert!(custom_config.pool_jd_addr.ip().is_unspecified());
    assert_eq!(custom_config.pool_jd_addr.port(), 4444);
}

#[test]
fn test_tx_selection_strategy_from_str() {
    // Test valid inputs
    assert_eq!(
        TxSelectionStrategy::parse("all"),
        Some(TxSelectionStrategy::All)
    );
    assert_eq!(
        TxSelectionStrategy::parse("ALL"),
        Some(TxSelectionStrategy::All)
    );
    assert_eq!(
        TxSelectionStrategy::parse("by-fee-rate"),
        Some(TxSelectionStrategy::ByFeeRate)
    );
    assert_eq!(
        TxSelectionStrategy::parse("BY-FEE-RATE"),
        Some(TxSelectionStrategy::ByFeeRate)
    );
    assert_eq!(
        TxSelectionStrategy::parse("byfee"),
        Some(TxSelectionStrategy::ByFeeRate)
    );
    assert_eq!(
        TxSelectionStrategy::parse("fee"),
        Some(TxSelectionStrategy::ByFeeRate)
    );

    // Test invalid inputs
    assert_eq!(TxSelectionStrategy::parse("invalid"), None);
    assert_eq!(TxSelectionStrategy::parse(""), None);
}

#[test]
fn test_tx_selection_strategy_as_str() {
    assert_eq!(TxSelectionStrategy::All.as_str(), "all");
    assert_eq!(TxSelectionStrategy::ByFeeRate.as_str(), "by-fee-rate");
}

#[test]
fn test_tx_selection_strategy_display() {
    assert_eq!(format!("{}", TxSelectionStrategy::All), "all");
    assert_eq!(format!("{}", TxSelectionStrategy::ByFeeRate), "by-fee-rate");
}

#[test]
fn test_tx_selection_strategy_default() {
    let default = TxSelectionStrategy::default();
    assert_eq!(default, TxSelectionStrategy::All);
}

#[test]
fn test_large_transaction_count() {
    // Test block building with many transactions (> 252 which requires 0xfd prefix)
    let header = [0x00; 140];
    let solution = [0x00; 1344];
    let coinbase_tx = vec![0x00; 10];

    // Create 300 small transactions (> 252 so requires 3-byte compactSize)
    let transactions: Vec<Vec<u8>> = (0..300).map(|_| vec![0x00; 10]).collect();

    let hex = BlockSubmitter::build_block_hex(&header, &solution, &coinbase_tx, &transactions);
    let bytes = hex::decode(&hex).unwrap();

    // Find transaction count position
    let tx_count_pos = 140 + 1 + 2 + 1344; // header + 0xfd + solution_len(2) + solution

    // Should use 0xfd prefix for 301 transactions (coinbase + 300)
    assert_eq!(bytes[tx_count_pos], 0xfd);
    let tx_count = u16::from_le_bytes([bytes[tx_count_pos + 1], bytes[tx_count_pos + 2]]);
    assert_eq!(tx_count, 301); // 1 coinbase + 300 transactions
}
