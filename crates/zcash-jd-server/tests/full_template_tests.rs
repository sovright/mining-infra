//! Integration tests for Full-Template mode
//!
//! These tests verify the complete flow for Full-Template mode including:
//! - Mode allocation (requesting and granting Full-Template mode)
//! - Mode fallback when disabled
//! - SetFullTemplateJob encoding/decoding
//! - Template validation at different levels
//! - Missing transactions flow
//! - Backward compatibility with Coinbase-Only mode
//! - Error code handling

use std::sync::Arc;
use std::time::Duration;

use zcash_jd_server::codec::{
    decode_allocate_token, decode_allocate_token_success, decode_get_missing_transactions,
    decode_provide_missing_transactions, decode_set_custom_job, decode_set_full_template_job,
    decode_set_full_template_job_error, decode_set_full_template_job_success,
    encode_allocate_token, encode_allocate_token_success, encode_get_missing_transactions,
    encode_provide_missing_transactions, encode_set_custom_job, encode_set_full_template_job,
    encode_set_full_template_job_error, encode_set_full_template_job_success,
};
use sha2::{Digest, Sha256};
use zcash_jd_server::{
    AllocateMiningJobToken, AllocateMiningJobTokenSuccess, FullTemplateJobResponse,
    GetMissingTransactions, JdServer, JdServerConfig, JobDeclarationMode,
    ProvideMissingTransactions, SetCustomMiningJob, SetFullTemplateJob,
    SetFullTemplateJobError, SetFullTemplateJobErrorCode, SetFullTemplateJobSuccess,
    TemplateValidator, ValidationLevel, ValidationResult,
};
use zcash_pool_common::PayoutTracker;

// =============================================================================
// Test Configuration Helpers
// =============================================================================

/// Create a test configuration with Full-Template mode disabled (default)
fn test_config_coinbase_only() -> JdServerConfig {
    JdServerConfig {
        token_lifetime: Duration::from_secs(300),
        coinbase_output_max_additional_size: 256,
        pool_payout_script: vec![0x76, 0xa9, 0x14], // P2PKH prefix
        async_mining_allowed: true,
        max_tokens_per_client: 10,
        noise_enabled: false,
        full_template_enabled: false,
        full_template_validation: ValidationLevel::Standard,
        min_pool_payout: 0,
    }
}

/// Create a test configuration with Full-Template mode enabled
fn test_config_full_template() -> JdServerConfig {
    JdServerConfig {
        token_lifetime: Duration::from_secs(300),
        coinbase_output_max_additional_size: 256,
        pool_payout_script: vec![], // Empty for testing (skips payout validation)
        async_mining_allowed: true,
        max_tokens_per_client: 10,
        noise_enabled: false,
        full_template_enabled: true,
        full_template_validation: ValidationLevel::Standard,
        min_pool_payout: 0,
    }
}

/// Create a test configuration with Full-Template mode and minimal validation
fn test_config_full_template_minimal() -> JdServerConfig {
    JdServerConfig {
        token_lifetime: Duration::from_secs(300),
        coinbase_output_max_additional_size: 256,
        pool_payout_script: vec![],
        async_mining_allowed: true,
        max_tokens_per_client: 10,
        noise_enabled: false,
        full_template_enabled: true,
        full_template_validation: ValidationLevel::Minimal,
        min_pool_payout: 0,
    }
}

/// Create a test configuration with Full-Template mode and strict validation
fn test_config_full_template_strict() -> JdServerConfig {
    JdServerConfig {
        token_lifetime: Duration::from_secs(300),
        coinbase_output_max_additional_size: 256,
        pool_payout_script: vec![],
        async_mining_allowed: true,
        max_tokens_per_client: 10,
        noise_enabled: false,
        full_template_enabled: true,
        full_template_validation: ValidationLevel::Strict,
        min_pool_payout: 0,
    }
}

fn compute_txid(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&hash2);
    txid
}

fn merkle_root_for(coinbase: &[u8], txids: &[[u8; 32]]) -> [u8; 32] {
    if coinbase.is_empty() {
        return [0u8; 32];
    }

    let mut all_txids = Vec::with_capacity(1 + txids.len());
    all_txids.push(compute_txid(coinbase));
    all_txids.extend_from_slice(txids);

    let mut layer = all_txids;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { left };
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&left);
            data[32..].copy_from_slice(&right);
            next.push(compute_txid(&data));
            i += 2;
        }
        layer = next;
    }

    layer[0]
}

fn set_merkle_root(job: &mut SetFullTemplateJob) {
    job.merkle_root = merkle_root_for(&job.coinbase_tx, &job.tx_short_ids);
}

fn minimal_tx_with_script(script: &[u8]) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&1u32.to_le_bytes()); // version
    tx.push(0x01); // vin count
    tx.extend_from_slice(&[0u8; 32]); // prevout hash
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
    tx.push(0x01); // scriptSig length
    tx.push(0x00); // scriptSig
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    tx.push(0x01); // vout count
    tx.extend_from_slice(&0u64.to_le_bytes()); // value
    if script.len() < 0xfd {
        tx.push(script.len() as u8);
    } else {
        tx.push(0xfd);
        tx.extend_from_slice(&(script.len() as u16).to_le_bytes());
    }
    tx.extend_from_slice(script);
    tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
    tx
}

fn minimal_tx() -> Vec<u8> {
    minimal_tx_with_script(&[0x51])
}

// =============================================================================
// Mode Allocation Tests
// =============================================================================

/// Test that Full-Template mode can be requested and granted
#[test]
fn test_full_template_mode_allocation() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let jd_server = JdServer::new(config, payout_tracker);

    // Client requests Full-Template mode
    let response = jd_server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    assert_eq!(response.request_id, 1);
    assert!(!response.mining_job_token.is_empty());
    assert_eq!(response.granted_mode, JobDeclarationMode::FullTemplate);
}

/// Test that Full-Template request falls back to CoinbaseOnly when disabled
#[test]
fn test_full_template_fallback_when_disabled() {
    let config = test_config_coinbase_only(); // Full-Template disabled
    let payout_tracker = Arc::new(PayoutTracker::default());
    let jd_server = JdServer::new(config, payout_tracker);

    // Client requests Full-Template mode, but it's disabled
    let response = jd_server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    // Server should grant CoinbaseOnly instead
    assert_eq!(response.granted_mode, JobDeclarationMode::CoinbaseOnly);
}

/// Test AllocateMiningJobToken message encoding/decoding with mode
#[test]
fn test_allocate_token_mode_roundtrip() {
    // Test FullTemplate mode
    let request = AllocateMiningJobToken::with_mode(
        42,
        "test-miner",
        JobDeclarationMode::FullTemplate,
    );
    assert_eq!(request.requested_mode, JobDeclarationMode::FullTemplate);

    let encoded = encode_allocate_token(&request).expect("Encoding should succeed");
    let decoded = decode_allocate_token(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.user_identifier, "test-miner");
    assert_eq!(decoded.requested_mode, JobDeclarationMode::FullTemplate);

    // Test CoinbaseOnly mode (default)
    let request = AllocateMiningJobToken::new(1, "test-miner");
    assert_eq!(request.requested_mode, JobDeclarationMode::CoinbaseOnly);

    let encoded = encode_allocate_token(&request).expect("Encoding should succeed");
    let decoded = decode_allocate_token(&encoded).expect("Decoding should succeed");
    assert_eq!(decoded.requested_mode, JobDeclarationMode::CoinbaseOnly);
}

/// Test AllocateMiningJobTokenSuccess encoding/decoding with granted mode
#[test]
fn test_allocate_token_success_mode_roundtrip() {
    let response = AllocateMiningJobTokenSuccess {
        request_id: 42,
        mining_job_token: vec![0x01, 0x02, 0x03],
        coinbase_output: vec![0x76, 0xa9, 0x14],
        coinbase_output_max_additional_size: 256,
        async_mining_allowed: true,
        granted_mode: JobDeclarationMode::FullTemplate,
    };

    let encoded = encode_allocate_token_success(&response).expect("Encoding should succeed");
    let decoded = decode_allocate_token_success(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.mining_job_token, vec![0x01, 0x02, 0x03]);
    assert_eq!(decoded.granted_mode, JobDeclarationMode::FullTemplate);
}

// =============================================================================
// SetFullTemplateJob Encoding/Decoding Tests
// =============================================================================

/// Test SetFullTemplateJob encoding/decoding roundtrip
#[test]
fn test_set_full_template_job_roundtrip() {
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 42,
        mining_job_token: vec![0x01, 0x02, 0x03],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![[0x11; 32], [0x22; 32]],
        tx_data: vec![minimal_tx(), minimal_tx()],
    };

    let encoded = encode_set_full_template_job(&job).expect("Encoding should succeed");
    let decoded = decode_set_full_template_job(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.channel_id, job.channel_id);
    assert_eq!(decoded.request_id, job.request_id);
    assert_eq!(decoded.mining_job_token, job.mining_job_token);
    assert_eq!(decoded.version, job.version);
    assert_eq!(decoded.prev_hash, job.prev_hash);
    assert_eq!(decoded.merkle_root, job.merkle_root);
    assert_eq!(decoded.block_commitments, job.block_commitments);
    assert_eq!(decoded.coinbase_tx, job.coinbase_tx);
    assert_eq!(decoded.time, job.time);
    assert_eq!(decoded.bits, job.bits);
    assert_eq!(decoded.tx_short_ids.len(), 2);
    assert_eq!(decoded.tx_data.len(), 2);
    assert_eq!(decoded.tx_short_ids, job.tx_short_ids);
    assert_eq!(decoded.tx_data, job.tx_data);
}

/// Test SetFullTemplateJob with empty transaction lists
#[test]
fn test_set_full_template_job_empty_tx_roundtrip() {
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 42,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![],
        tx_data: vec![],
    };

    let encoded = encode_set_full_template_job(&job).expect("Encoding should succeed");
    let decoded = decode_set_full_template_job(&encoded).expect("Decoding should succeed");

    assert!(decoded.tx_short_ids.is_empty());
    assert!(decoded.tx_data.is_empty());
}

/// Test SetFullTemplateJob with many transactions
#[test]
fn test_set_full_template_job_many_tx_roundtrip() {
    let tx_count = 100;
    let tx_short_ids: Vec<[u8; 32]> = (0..tx_count as u8)
        .map(|i| {
            let mut arr = [0u8; 32];
            arr[0] = i;
            arr
        })
        .collect();
    let tx_data: Vec<Vec<u8>> = (0..tx_count as u8)
        .map(|i| vec![0x01, 0x00, i, 0x00])
        .collect();

    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 42,
        mining_job_token: vec![0x01, 0x02],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: tx_short_ids.clone(),
        tx_data: tx_data.clone(),
    };

    let encoded = encode_set_full_template_job(&job).expect("Encoding should succeed");
    let decoded = decode_set_full_template_job(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.tx_short_ids.len(), tx_count);
    assert_eq!(decoded.tx_data.len(), tx_count);
    assert_eq!(decoded.tx_short_ids, tx_short_ids);
    assert_eq!(decoded.tx_data, tx_data);
}

/// Test SetFullTemplateJobSuccess roundtrip
#[test]
fn test_set_full_template_job_success_roundtrip() {
    let success = SetFullTemplateJobSuccess::new(1, 42, 100);

    let encoded = encode_set_full_template_job_success(&success).expect("Encoding should succeed");
    let decoded = decode_set_full_template_job_success(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.channel_id, 1);
    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.job_id, 100);
}

/// Test SetFullTemplateJobError roundtrip with all error codes
#[test]
fn test_set_full_template_job_error_roundtrip() {
    let error_codes = [
        SetFullTemplateJobErrorCode::InvalidToken,
        SetFullTemplateJobErrorCode::TokenExpired,
        SetFullTemplateJobErrorCode::InvalidCoinbase,
        SetFullTemplateJobErrorCode::CoinbaseConstraintViolation,
        SetFullTemplateJobErrorCode::StalePrevHash,
        SetFullTemplateJobErrorCode::InvalidMerkleRoot,
        SetFullTemplateJobErrorCode::InvalidVersion,
        SetFullTemplateJobErrorCode::InvalidBits,
        SetFullTemplateJobErrorCode::ServerOverloaded,
        SetFullTemplateJobErrorCode::ModeMismatch,
        SetFullTemplateJobErrorCode::InvalidTransactions,
        SetFullTemplateJobErrorCode::TooManyTransactions,
        SetFullTemplateJobErrorCode::Other,
    ];

    for code in error_codes {
        let error = SetFullTemplateJobError::new(1, 42, code, format!("Error: {}", code));

        let encoded = encode_set_full_template_job_error(&error).expect("Encoding should succeed");
        let decoded =
            decode_set_full_template_job_error(&encoded).expect("Decoding should succeed");

        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.error_code, code);
        assert_eq!(decoded.error_message, format!("Error: {}", code));
    }
}

// =============================================================================
// Validation Level Tests
// =============================================================================

/// Test Minimal validation level accepts any job (with valid payout)
#[test]
fn test_validation_minimal_accepts_any() {
    let validator = TemplateValidator::new(ValidationLevel::Minimal, vec![], 0);

    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 1,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![[0x11; 32]],
        tx_data: vec![], // No tx data provided
    };

    assert!(matches!(validator.validate(&job), ValidationResult::Valid));
}

/// Test Standard validation requests missing transactions
#[test]
fn test_validation_standard_needs_transactions() {
    let validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);

    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 1,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![[0x11; 32], [0x22; 32]],
        tx_data: vec![], // No tx data provided
    };

    match validator.validate(&job) {
        ValidationResult::NeedTransactions(missing) => {
            assert_eq!(missing.len(), 2);
        }
        _ => panic!("Expected NeedTransactions"),
    }
}

/// Test Standard validation accepts when tx_data is provided
#[test]
fn test_validation_standard_with_tx_data() {
    let validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
    let tx1 = minimal_tx();
    let tx2 = minimal_tx_with_script(&[0x52]);

    let mut job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 1,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![compute_txid(&tx1), compute_txid(&tx2)],
        tx_data: vec![tx1, tx2],
    };
    set_merkle_root(&mut job);

    assert!(matches!(validator.validate(&job), ValidationResult::Valid));
}

/// Test Standard validation accepts when txids are known
#[test]
fn test_validation_standard_with_known_txids() {
    let mut validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
    validator.add_known_txid([0x11; 32]);
    validator.add_known_txid([0x22; 32]);

    let mut job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 1,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![[0x11; 32], [0x22; 32]],
        tx_data: vec![],
    };
    set_merkle_root(&mut job);

    assert!(matches!(validator.validate(&job), ValidationResult::Valid));
}

/// Test Strict validation (same behavior as Standard for MVP)
#[test]
fn test_validation_strict() {
    let mut validator = TemplateValidator::new(ValidationLevel::Strict, vec![], 0);
    validator.add_known_txid([0x11; 32]);

    let mut job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 1,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![[0x11; 32]],
        tx_data: vec![],
    };
    set_merkle_root(&mut job);

    assert!(matches!(validator.validate(&job), ValidationResult::Valid));
}

/// Test pool payout validation
#[test]
fn test_validation_pool_payout() {
    let payout_script = vec![0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef];
    let validator = TemplateValidator::new(ValidationLevel::Minimal, payout_script.clone(), 0);

    // Job without payout script fails
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 1,
        mining_job_token: vec![0x01],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(), // Missing payout script
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![],
        tx_data: vec![],
    };

    assert!(matches!(validator.validate(&job), ValidationResult::Invalid(_)));

    // Job with payout script succeeds
    let coinbase_with_payout = minimal_tx_with_script(&payout_script);
    let job_with_payout = SetFullTemplateJob {
        coinbase_tx: coinbase_with_payout,
        ..job
    };

    assert!(matches!(
        validator.validate(&job_with_payout),
        ValidationResult::Valid
    ));
}

// =============================================================================
// Missing Transactions Flow Tests
// =============================================================================

/// Test GetMissingTransactions encoding/decoding
#[test]
fn test_get_missing_transactions_roundtrip() {
    let get_missing = GetMissingTransactions {
        channel_id: 1,
        request_id: 42,
        missing_tx_ids: vec![[0x11; 32], [0x22; 32]],
    };

    let encoded = encode_get_missing_transactions(&get_missing).expect("Encoding should succeed");
    let decoded = decode_get_missing_transactions(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.channel_id, 1);
    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.missing_tx_ids.len(), 2);
    assert_eq!(decoded.missing_tx_ids[0], [0x11; 32]);
    assert_eq!(decoded.missing_tx_ids[1], [0x22; 32]);
}

/// Test ProvideMissingTransactions encoding/decoding
#[test]
fn test_provide_missing_transactions_roundtrip() {
    let provide = ProvideMissingTransactions {
        channel_id: 1,
        request_id: 42,
        transactions: vec![vec![0x01, 0x02], vec![0x03, 0x04]],
    };

    let encoded =
        encode_provide_missing_transactions(&provide).expect("Encoding should succeed");
    let decoded =
        decode_provide_missing_transactions(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.channel_id, 1);
    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.transactions.len(), 2);
    assert_eq!(decoded.transactions[0], vec![0x01, 0x02]);
    assert_eq!(decoded.transactions[1], vec![0x03, 0x04]);
}

/// Test complete missing transactions flow
#[tokio::test]
async fn test_missing_transactions_flow_complete() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Set current prev_hash
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Allocate Full-Template token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");
    assert_eq!(token_response.granted_mode, JobDeclarationMode::FullTemplate);

    // Submit job with an unknown txid
    let tx_data = minimal_tx_with_script(&[0x52]);
    let unknown_txid = compute_txid(&tx_data);
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token.clone(),
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![unknown_txid],
        tx_data: vec![], // Not providing tx data
    };

    // Server should request the missing transaction
    let result = server.handle_set_full_template_job(job.clone()).await;
    match result {
        Err(FullTemplateJobResponse::NeedTransactions(request)) => {
            assert_eq!(request.channel_id, 1);
            assert_eq!(request.request_id, 2);
            assert_eq!(request.missing_tx_ids.len(), 1);
            assert_eq!(request.missing_tx_ids[0], unknown_txid);
        }
        _ => panic!("Expected NeedTransactions response"),
    }

    // Client provides missing transaction
    let provide = ProvideMissingTransactions {
        channel_id: 1,
        request_id: 2,
        transactions: vec![tx_data],
    };
    server
        .handle_provide_missing_transactions(provide, "test-miner")
        .await
        .expect("Providing transactions should succeed");

    // After providing transactions, the txid is computed and added to known set
    // A real resubmission of the job would now succeed
}

// =============================================================================
// Backward Compatibility Tests
// =============================================================================

/// Test that Coinbase-Only mode still works (backward compatibility)
#[test]
fn test_coinbase_only_still_works() {
    let request = AllocateMiningJobToken::new(1, "test-miner");
    assert_eq!(request.requested_mode, JobDeclarationMode::CoinbaseOnly);
}

/// Test SetCustomMiningJob still works (backward compatibility)
#[tokio::test]
async fn test_set_custom_mining_job_still_works() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Set current prev_hash
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Allocate CoinbaseOnly token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
        .expect("Token allocation should succeed");
    assert_eq!(token_response.granted_mode, JobDeclarationMode::CoinbaseOnly);

    // Submit Coinbase-Only job
    let job = SetCustomMiningJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
    };

    assert!(job.validate().is_ok());

    let result = server.handle_declare_job(job).await;
    assert!(result.is_ok());

    let success = result.unwrap();
    assert_eq!(success.channel_id, 1);
    assert_eq!(success.request_id, 2);
}

/// Test SetCustomMiningJob encoding/decoding still works
#[test]
fn test_set_custom_job_roundtrip() {
    let job = SetCustomMiningJob {
        channel_id: 1,
        request_id: 42,
        mining_job_token: vec![0x01, 0x02, 0x03],
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
    };

    let encoded = encode_set_custom_job(&job).expect("Encoding should succeed");
    let decoded = decode_set_custom_job(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.channel_id, job.channel_id);
    assert_eq!(decoded.request_id, job.request_id);
    assert_eq!(decoded.mining_job_token, job.mining_job_token);
}

// =============================================================================
// Error Code Tests
// =============================================================================

/// Test error codes for Full-Template mode
#[test]
fn test_full_template_error_codes() {
    // ModeMismatch error
    let error = SetFullTemplateJobError::mode_mismatch(1, 42);
    assert_eq!(error.channel_id, 1);
    assert_eq!(error.request_id, 42);
    assert_eq!(error.error_code, SetFullTemplateJobErrorCode::ModeMismatch);

    // InvalidTransactions error
    let error = SetFullTemplateJobError::invalid_transactions(1, 42, "bad tx");
    assert_eq!(error.error_code, SetFullTemplateJobErrorCode::InvalidTransactions);
    assert_eq!(error.error_message, "bad tx");

    // InvalidToken error
    let error = SetFullTemplateJobError::invalid_token(1, 42);
    assert_eq!(error.error_code, SetFullTemplateJobErrorCode::InvalidToken);

    // InvalidCoinbase error
    let error = SetFullTemplateJobError::invalid_coinbase(1, 42, "missing pool output");
    assert_eq!(error.error_code, SetFullTemplateJobErrorCode::InvalidCoinbase);
    assert_eq!(error.error_message, "missing pool output");
}

/// Test error code byte values
#[test]
fn test_error_code_byte_values() {
    assert_eq!(SetFullTemplateJobErrorCode::InvalidToken.as_u8(), 0x01);
    assert_eq!(SetFullTemplateJobErrorCode::TokenExpired.as_u8(), 0x02);
    assert_eq!(SetFullTemplateJobErrorCode::InvalidCoinbase.as_u8(), 0x03);
    assert_eq!(
        SetFullTemplateJobErrorCode::CoinbaseConstraintViolation.as_u8(),
        0x04
    );
    assert_eq!(SetFullTemplateJobErrorCode::StalePrevHash.as_u8(), 0x05);
    assert_eq!(SetFullTemplateJobErrorCode::InvalidMerkleRoot.as_u8(), 0x06);
    assert_eq!(SetFullTemplateJobErrorCode::InvalidVersion.as_u8(), 0x07);
    assert_eq!(SetFullTemplateJobErrorCode::InvalidBits.as_u8(), 0x08);
    assert_eq!(SetFullTemplateJobErrorCode::ServerOverloaded.as_u8(), 0x09);
    assert_eq!(SetFullTemplateJobErrorCode::ModeMismatch.as_u8(), 0x0A);
    assert_eq!(SetFullTemplateJobErrorCode::InvalidTransactions.as_u8(), 0x0B);
    assert_eq!(SetFullTemplateJobErrorCode::TooManyTransactions.as_u8(), 0x0C);
    assert_eq!(SetFullTemplateJobErrorCode::Other.as_u8(), 0xFF);
}

// =============================================================================
// Full Template Job Server Flow Tests
// =============================================================================

/// Test Full-Template job acceptance with valid data
#[tokio::test]
async fn test_full_template_job_success() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Set current prev_hash
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Allocate Full-Template token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    // Submit job with no transactions (empty template)
    let mut job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![],
        tx_data: vec![],
    };
    set_merkle_root(&mut job);

    let result = server.handle_set_full_template_job(job).await;
    assert!(result.is_ok());

    let success = result.unwrap();
    assert_eq!(success.channel_id, 1);
    assert_eq!(success.request_id, 2);
    assert!(success.job_id > 0);
}

/// Test Full-Template job rejected when using CoinbaseOnly token
#[tokio::test]
async fn test_full_template_job_mode_mismatch() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Allocate CoinbaseOnly token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
        .expect("Token allocation should succeed");

    // Try to submit Full-Template job with CoinbaseOnly token
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![],
        tx_data: vec![],
    };

    let result = server.handle_set_full_template_job(job).await;
    match result {
        Err(FullTemplateJobResponse::Error(error)) => {
            assert_eq!(error.error_code, SetFullTemplateJobErrorCode::ModeMismatch);
        }
        _ => panic!("Expected ModeMismatch error"),
    }
}

/// Test Full-Template job rejected with stale prev_hash
#[tokio::test]
async fn test_full_template_job_stale_prev_hash() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Set current prev_hash
    let current_prev_hash = [0xaa; 32];
    server.set_current_prev_hash(current_prev_hash).await;

    // Allocate Full-Template token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    // Submit job with stale prev_hash
    let stale_prev_hash = [0x11; 32];
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: 5,
        prev_hash: stale_prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![],
        tx_data: vec![],
    };

    let result = server.handle_set_full_template_job(job).await;
    match result {
        Err(FullTemplateJobResponse::Error(error)) => {
            assert_eq!(error.error_code, SetFullTemplateJobErrorCode::StalePrevHash);
        }
        _ => panic!("Expected StalePrevHash error"),
    }
}

/// Test Full-Template job with invalid token
#[tokio::test]
async fn test_full_template_job_invalid_token() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Submit job with fake token
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: vec![0x00, 0x01, 0x02], // Invalid token
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![],
        tx_data: vec![],
    };

    let result = server.handle_set_full_template_job(job).await;
    match result {
        Err(FullTemplateJobResponse::Error(error)) => {
            assert_eq!(error.error_code, SetFullTemplateJobErrorCode::InvalidToken);
        }
        _ => panic!("Expected InvalidToken error"),
    }
}

/// Test update_known_txids updates validator
#[tokio::test]
async fn test_update_known_txids() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    let known_txid = [0x11; 32];
    server.update_known_txids([known_txid]).await;

    // Verify via validator
    let validator = server.validator().await;
    assert!(validator.is_txid_known(&known_txid));
}

/// Test job with known txids succeeds
#[tokio::test]
async fn test_full_template_job_with_known_txids() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    // Set current prev_hash
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Add known txids
    let known_txid = [0x99; 32];
    server.update_known_txids([known_txid]).await;

    // Allocate Full-Template token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    // Submit job referencing known txid
    let mut job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![known_txid],
        tx_data: vec![], // No tx_data needed since txid is known
    };
    set_merkle_root(&mut job);

    let result = server.handle_set_full_template_job(job).await;
    assert!(result.is_ok());
}

// =============================================================================
// Multiple Miners Full-Template Tests
// =============================================================================

/// Test multiple miners using Full-Template mode
#[tokio::test]
async fn test_multiple_miners_full_template() {
    let config = test_config_full_template();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Allocate tokens for multiple miners
    let mut job_ids = Vec::new();
    for i in 0..5 {
        let token = server
            .handle_allocate_token(i, &format!("miner-{}", i), JobDeclarationMode::FullTemplate)
            .expect("Token allocation should succeed");

        assert_eq!(token.granted_mode, JobDeclarationMode::FullTemplate);

        let mut job = SetFullTemplateJob {
            channel_id: i,
            request_id: i * 10,
            mining_job_token: token.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root: [(i * 11) as u8; 32],
            block_commitments: [(i * 22) as u8; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000 + i,
            bits: 0x1d00ffff,
            tx_short_ids: vec![],
            tx_data: vec![],
        };
        set_merkle_root(&mut job);

        let result = server.handle_set_full_template_job(job).await;
        assert!(result.is_ok(), "Miner {} should succeed", i);
        job_ids.push(result.unwrap().job_id);
    }

    // All job IDs should be unique
    let unique_ids: std::collections::HashSet<_> = job_ids.iter().collect();
    assert_eq!(unique_ids.len(), job_ids.len());
}

// =============================================================================
// Validation Level Server Integration Tests
// =============================================================================

/// Test server with Minimal validation level
#[tokio::test]
async fn test_server_minimal_validation() {
    let config = test_config_full_template_minimal();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    let token = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    // Submit job with unknown txids - should succeed with Minimal validation
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token.mining_job_token,
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![[0x99; 32], [0x88; 32]], // Unknown txids
        tx_data: vec![], // No tx_data
    };

    let result = server.handle_set_full_template_job(job).await;
    assert!(result.is_ok(), "Minimal validation should accept any template");
}

/// Test server with Strict validation level
#[tokio::test]
async fn test_server_strict_validation() {
    let config = test_config_full_template_strict();
    let payout_tracker = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout_tracker);

    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    let token = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
        .expect("Token allocation should succeed");

    // Submit job with unknown txids - should request transactions with Strict validation
    let unknown_txid = [0x99; 32];
    let job = SetFullTemplateJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token.mining_job_token,
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        coinbase_tx: minimal_tx(),
        time: 1700000000,
        bits: 0x1d00ffff,
        tx_short_ids: vec![unknown_txid],
        tx_data: vec![],
    };

    let result = server.handle_set_full_template_job(job).await;
    match result {
        Err(FullTemplateJobResponse::NeedTransactions(request)) => {
            assert_eq!(request.missing_tx_ids.len(), 1);
            assert_eq!(request.missing_tx_ids[0], unknown_txid);
        }
        _ => panic!("Strict validation should request missing transactions"),
    }
}
