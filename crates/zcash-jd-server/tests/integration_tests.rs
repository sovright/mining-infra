//! JD Server integration tests
//!
//! These tests verify the full flow of the JD Server including:
//! - Token allocation
//! - Job declaration
//! - Solution handling
//! - Message codec roundtrips

use std::sync::Arc;
use std::time::Duration;
use zcash_jd_server::codec::{
    decode_allocate_token, decode_push_solution, encode_allocate_token, encode_push_solution,
};
use zcash_jd_server::{
    AllocateMiningJobToken, JdServer, JdServerConfig, JobDeclarationMode, PushSolution,
    SetCustomMiningJob, ValidationLevel,
};
use zcash_pool_common::PayoutTracker;

/// Create a test configuration
fn test_config() -> JdServerConfig {
    JdServerConfig {
        token_lifetime: Duration::from_secs(300),
        coinbase_output_max_additional_size: 256,
        pool_payout_script: vec![],
        async_mining_allowed: true,
        max_tokens_per_client: 10,
        noise_enabled: false,
        full_template_enabled: false,
        full_template_validation: ValidationLevel::Standard,
        min_pool_payout: 0,
    }
}

fn minimal_tx() -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&1u32.to_le_bytes());
    tx.push(0x01);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(0x01);
    tx.push(0x00);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(0x01);
    tx.extend_from_slice(&0u64.to_le_bytes());
    tx.push(0x01);
    tx.push(0x51);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

#[test]
fn test_token_flow() {
    let config = test_config();
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout);

    // Allocate token
    let response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
        .unwrap();
    assert_eq!(response.request_id, 1);
    assert!(!response.mining_job_token.is_empty());
    assert!(response.async_mining_allowed);
    assert_eq!(response.granted_mode, JobDeclarationMode::CoinbaseOnly);
}

#[tokio::test]
async fn test_job_declaration_flow() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout);

    // Set current block
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Allocate token
    let token_response = server
        .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
        .unwrap();

    // Declare job
    let request = SetCustomMiningJob {
        channel_id: 1,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: 5,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        time: 1700000000,
        bits: 0x1d00ffff,
        coinbase_tx: minimal_tx(),
    };

    let result = server.handle_declare_job(request).await;
    assert!(result.is_ok());

    let success = result.unwrap();
    assert_eq!(success.channel_id, 1);
    assert_eq!(success.request_id, 2);
    assert!(success.job_id > 0);
}

#[test]
fn test_message_codec_roundtrips() {
    // AllocateMiningJobToken
    let msg = AllocateMiningJobToken {
        request_id: 42,
        user_identifier: "test".to_string(),
        requested_mode: JobDeclarationMode::CoinbaseOnly,
    };
    let encoded = encode_allocate_token(&msg).unwrap();
    let decoded = decode_allocate_token(&encoded).unwrap();
    assert_eq!(decoded.request_id, msg.request_id);
    assert_eq!(decoded.user_identifier, msg.user_identifier);
    assert_eq!(decoded.requested_mode, msg.requested_mode);

    // PushSolution
    let solution_msg = PushSolution {
        channel_id: 1,
        job_id: 42,
        version: 5,
        time: 1700000000,
        nonce: [0xff; 32],
        solution: [0xaa; 1344],
    };
    let encoded = encode_push_solution(&solution_msg).unwrap();
    let decoded = decode_push_solution(&encoded).unwrap();
    assert_eq!(decoded.job_id, solution_msg.job_id);
    assert_eq!(decoded.channel_id, solution_msg.channel_id);
    assert_eq!(decoded.version, solution_msg.version);
    assert_eq!(decoded.time, solution_msg.time);
    assert_eq!(decoded.nonce, solution_msg.nonce);
    assert_eq!(decoded.solution, solution_msg.solution);
}

#[tokio::test]
async fn test_full_mining_flow() {
    // This test simulates the complete mining flow:
    // 1. Allocate token
    // 2. Declare job
    // 3. Submit solution

    let config = test_config();
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout.clone());

    // Set current prev_hash
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Step 1: Allocate token
    let token_response = server
        .handle_allocate_token(1, "integration-test-miner", JobDeclarationMode::CoinbaseOnly)
        .unwrap();
    assert!(!token_response.mining_job_token.is_empty());
    assert!(token_response.coinbase_output.is_empty());

    // Step 2: Declare job
    let job_request = SetCustomMiningJob {
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

    let job_response = server.handle_declare_job(job_request).await.unwrap();
    let job_id = job_response.job_id;

    // Step 3: Submit solution
    let solution = PushSolution::new(
        1,            // channel_id
        job_id,       // job_id
        5,            // version
        1700000000,   // time
        [0x11; 32],   // nonce
        [0x22; 1344], // solution
    );

    let result = server.handle_push_solution(solution).await;
    assert!(result.is_err());

    assert!(payout
        .get_stats(&"integration-test-miner".to_string())
        .is_none());
}

#[tokio::test]
async fn test_multiple_miners() {
    let config = test_config();
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout);

    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    // Allocate tokens for multiple miners
    let token1 = server
        .handle_allocate_token(1, "miner-1", JobDeclarationMode::CoinbaseOnly)
        .unwrap();
    let token2 = server
        .handle_allocate_token(2, "miner-2", JobDeclarationMode::CoinbaseOnly)
        .unwrap();
    let token3 = server
        .handle_allocate_token(3, "miner-3", JobDeclarationMode::CoinbaseOnly)
        .unwrap();

    // All should have unique tokens
    assert_ne!(token1.mining_job_token, token2.mining_job_token);
    assert_ne!(token2.mining_job_token, token3.mining_job_token);
    assert_ne!(token1.mining_job_token, token3.mining_job_token);

    // Each miner can declare a job
    for (i, token) in [token1, token2, token3].iter().enumerate() {
        let job = SetCustomMiningJob {
            channel_id: i as u32 + 1,
            request_id: (i as u32 + 1) * 10,
            mining_job_token: token.mining_job_token.clone(),
            version: 5,
            prev_hash,
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let result = server.handle_declare_job(job).await;
        assert!(result.is_ok(), "Miner {} should declare job successfully", i + 1);
    }
}

#[tokio::test]
async fn test_job_id_uniqueness() {
    let config = test_config();
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config, payout);

    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    let mut job_ids = Vec::new();

    // Declare multiple jobs and collect their IDs
    for i in 0..10 {
        let token = server
            .handle_allocate_token(i, &format!("miner-{}", i), JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let job = SetCustomMiningJob {
            channel_id: i,
            request_id: i * 10,
            mining_job_token: token.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let result = server.handle_declare_job(job).await.unwrap();
        job_ids.push(result.job_id);
    }

    // All job IDs should be unique
    let unique_ids: std::collections::HashSet<_> = job_ids.iter().collect();
    assert_eq!(unique_ids.len(), job_ids.len(), "All job IDs should be unique");
}

#[test]
fn test_config_getters() {
    let config = test_config();
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(config.clone(), payout);

    // Verify config access
    let server_config = server.config();
    assert_eq!(
        server_config.coinbase_output_max_additional_size,
        config.coinbase_output_max_additional_size
    );
    assert_eq!(server_config.pool_payout_script, config.pool_payout_script);
    assert_eq!(server_config.async_mining_allowed, config.async_mining_allowed);

    // Verify token manager access
    let token_manager = server.token_manager();
    let token = token_manager.allocate_token("test").unwrap();
    assert!(!token.token.is_empty());
}
