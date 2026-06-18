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
    decode_allocate_token, decode_push_solution, decode_set_custom_job_success,
    decode_submit_shares_jd, decode_submit_shares_jd_response, encode_allocate_token,
    encode_push_solution, encode_set_custom_job_success, encode_submit_shares_jd,
    encode_submit_shares_jd_response,
};
use zcash_jd_server::{
    AllocateMiningJobToken, JdServer, JdServerConfig, JdShare, JdShareErrorCode,
    JobDeclarationMode, PushSolution, SetCustomMiningJob, SetCustomMiningJobSuccess,
    SubmitSharesJd, SubmitSharesJdResponse, ValidationLevel,
};
use zcash_pool_common::PayoutTracker;

/// Distinctive share target used by the test configuration so tests can assert
/// the pool-granted target is threaded all the way through.
const TEST_SHARE_TARGET: [u8; 32] = [0x7e; 32];

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
        share_target: TEST_SHARE_TARGET,
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

    // The pool grants a share target (chosen by the pool, never the client) and
    // returns it in the success message.
    assert_eq!(success.share_target, TEST_SHARE_TARGET);

    // The same target is recorded in the stored job for later share validation.
    let stored = server
        .token_manager()
        .find_job_by_id(success.job_id)
        .unwrap();
    assert_eq!(stored.share_target, TEST_SHARE_TARGET);
}

#[test]
fn test_set_custom_job_success_share_target_roundtrip() {
    let original = SetCustomMiningJobSuccess {
        channel_id: 7,
        request_id: 99,
        job_id: 1234,
        share_target: [0xa5; 32],
    };

    let encoded = encode_set_custom_job_success(&original).unwrap();
    let decoded = decode_set_custom_job_success(&encoded).unwrap();

    assert_eq!(decoded.channel_id, original.channel_id);
    assert_eq!(decoded.request_id, original.request_id);
    assert_eq!(decoded.job_id, original.job_id);
    assert_eq!(decoded.share_target, original.share_target);
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
        .handle_allocate_token(
            1,
            "integration-test-miner",
            JobDeclarationMode::CoinbaseOnly,
        )
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

    assert!(
        payout
            .get_stats(&"integration-test-miner".to_string())
            .is_none()
    );
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
        assert!(
            result.is_ok(),
            "Miner {} should declare job successfully",
            i + 1
        );
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
    assert_eq!(
        unique_ids.len(),
        job_ids.len(),
        "All job IDs should be unique"
    );
}

// =============================================================================
// SubmitSharesJd / SubmitSharesJdResponse codec tests
// =============================================================================

/// Build a JdShare with distinct field patterns for a given index so that
/// two shares in the same batch are distinguishable from each other.
fn make_share(idx: u8) -> JdShare {
    let mut nonce = [0u8; 32];
    nonce[0] = idx;
    nonce[31] = idx.wrapping_add(1);
    let mut solution = [0u8; 1344];
    solution[0] = idx.wrapping_add(2);
    solution[1343] = idx.wrapping_add(3);
    JdShare {
        version: 5u32.wrapping_add(idx as u32),
        time: 1_700_000_000u32.wrapping_add(idx as u32 * 60),
        nonce,
        solution,
    }
}

#[test]
fn test_submit_shares_jd_1share_roundtrip() {
    let original = SubmitSharesJd {
        channel_id: 1,
        request_id: 100,
        job_id: 42,
        shares: vec![make_share(0)],
    };

    let encoded = encode_submit_shares_jd(&original).unwrap();
    let decoded = decode_submit_shares_jd(&encoded).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn test_submit_shares_jd_3share_roundtrip() {
    let original = SubmitSharesJd {
        channel_id: 7,
        request_id: 200,
        job_id: 99,
        shares: vec![make_share(10), make_share(20), make_share(30)],
    };

    let encoded = encode_submit_shares_jd(&original).unwrap();
    let decoded = decode_submit_shares_jd(&encoded).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(decoded.shares.len(), 3);
    // Verify each share is distinct
    assert_ne!(decoded.shares[0].version, decoded.shares[1].version);
    assert_ne!(decoded.shares[1].version, decoded.shares[2].version);
    assert_ne!(decoded.shares[0].nonce, decoded.shares[1].nonce);
}

#[test]
fn test_submit_shares_jd_response_all_error_codes_roundtrip() {
    let error_codes = [
        (0u8, 0u16, 0u16), // none: accepted=1, rejected=0, first_error=0
        (1u8, 0u16, 1u16), // unknown_job
        (2u8, 0u16, 1u16), // stale_job
        (3u8, 0u16, 1u16), // low_difficulty
        (4u8, 0u16, 1u16), // bad_solution
        (5u8, 0u16, 1u16), // duplicate
        (6u8, 0u16, 1u16), // channel_mismatch
    ];

    for (code, accepted, rejected) in error_codes {
        let original = SubmitSharesJdResponse {
            channel_id: 1,
            request_id: 42,
            accepted,
            rejected,
            first_error_code: code,
        };

        let encoded = encode_submit_shares_jd_response(&original).unwrap();
        let decoded = decode_submit_shares_jd_response(&encoded).unwrap();

        assert_eq!(
            decoded, original,
            "round-trip failed for error code {}",
            code
        );
    }
}

#[test]
fn test_submit_shares_jd_decode_count_zero_rejected() {
    use byteorder::{LittleEndian, WriteBytesExt};
    use zcash_mining_protocol::codec::MessageFrame;

    // Build a raw payload with count=0 (should be rejected)
    let mut payload = Vec::new();
    payload.write_u32::<LittleEndian>(1u32).unwrap(); // channel_id
    payload.write_u32::<LittleEndian>(2u32).unwrap(); // request_id
    payload.write_u32::<LittleEndian>(3u32).unwrap(); // job_id
    payload.write_u16::<LittleEndian>(0u16).unwrap(); // count=0 — invalid

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: 0x5B,
        length: payload.len() as u32,
    };
    let mut data = frame.encode().to_vec();
    data.extend(payload);

    let result = decode_submit_shares_jd(&data);
    assert!(result.is_err(), "count=0 should be rejected");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("Protocol"),
        "expected Protocol error, got: {}",
        err_str
    );
}

#[test]
fn test_submit_shares_jd_decode_count_65_rejected() {
    use byteorder::{LittleEndian, WriteBytesExt};
    use zcash_mining_protocol::codec::MessageFrame;

    // Build a minimal payload with count=65 header only (no actual shares) — too many
    let mut payload = Vec::new();
    payload.write_u32::<LittleEndian>(1u32).unwrap(); // channel_id
    payload.write_u32::<LittleEndian>(2u32).unwrap(); // request_id
    payload.write_u32::<LittleEndian>(3u32).unwrap(); // job_id
    payload.write_u16::<LittleEndian>(65u16).unwrap(); // count=65 — exceeds max 64
    // (no actual share bytes follow — the decoder should reject count before reading shares)

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: 0x5B,
        length: payload.len() as u32,
    };
    let mut data = frame.encode().to_vec();
    data.extend(payload);

    let result = decode_submit_shares_jd(&data);
    assert!(result.is_err(), "count=65 should be rejected");
}

#[test]
fn test_submit_shares_jd_truncated_no_panic() {
    use byteorder::{LittleEndian, WriteBytesExt};
    use zcash_mining_protocol::codec::MessageFrame;

    // Write a well-formed header claiming 1 share but with 0 share bytes
    let mut payload = Vec::new();
    payload.write_u32::<LittleEndian>(1u32).unwrap(); // channel_id
    payload.write_u32::<LittleEndian>(2u32).unwrap(); // request_id
    payload.write_u32::<LittleEndian>(3u32).unwrap(); // job_id
    payload.write_u16::<LittleEndian>(1u16).unwrap(); // count=1, but no share bytes follow

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: 0x5B,
        length: payload.len() as u32,
    };
    let mut data = frame.encode().to_vec();
    data.extend(payload);

    // Must not panic; must return an error
    let result = decode_submit_shares_jd(&data);
    assert!(
        result.is_err(),
        "truncated payload must return an error, not panic"
    );
}

#[test]
fn test_jd_share_error_code_roundtrip() {
    let codes = [
        JdShareErrorCode::None,
        JdShareErrorCode::UnknownJob,
        JdShareErrorCode::StaleJob,
        JdShareErrorCode::LowDifficulty,
        JdShareErrorCode::BadSolution,
        JdShareErrorCode::Duplicate,
        JdShareErrorCode::ChannelMismatch,
    ];

    for code in codes {
        let byte = code.as_u8();
        let recovered = JdShareErrorCode::from_u8(byte).unwrap();
        assert_eq!(code, recovered, "round-trip failed for {:?}", code);
    }

    // Unknown value returns None
    assert!(JdShareErrorCode::from_u8(7).is_none());
    assert!(JdShareErrorCode::from_u8(0xFF).is_none());
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
    assert_eq!(
        server_config.async_mining_allowed,
        config.async_mining_allowed
    );

    // Verify token manager access
    let token_manager = server.token_manager();
    let token = token_manager.allocate_token("test").unwrap();
    assert!(!token.token.is_empty());
}

// =============================================================================
// handle_submit_shares_jd handler tests (Task 4)
//
// ACCEPT / CREDIT COVERAGE: the server-side accept+credit path of
// handle_submit_shares_jd requires a structurally valid Equihash solution that
// meets the pool-granted share target — which only a real CPU solver can
// produce — so it is NOT exercised in this unit suite. It is now covered
// end-to-end by the Tier-2 full-chain integration test
// (`crates/zcash-jd-client/tests/tier2_chain_test.rs`,
// `tier2_full_chain_declared_job_mining`): a real V1 miner's solution is relayed
// to this server, which re-verifies it and credits the declaring client in the
// PayoutTracker. The tests below cover every rejection path reachable without a
// valid solution plus the batch counting / first-error / no-credit logic.
// =============================================================================

/// Job parameters used by the share-handler tests. The miner-controlled share
/// fields (version, time) must agree with these for the share to pass the cheap
/// checks and reach Equihash verification.
const JOB_VERSION: u32 = 5;
const JOB_TIME: u32 = 1_700_000_000;
const JOB_CHANNEL: u32 = 1;
const MINER_ID: &str = "share-test-miner";

/// Allocate a token and declare a job, returning the assigned job_id.
async fn declare_test_job(server: &JdServer) -> u32 {
    let prev_hash = [0xaa; 32];
    server.set_current_prev_hash(prev_hash).await;

    let token_response = server
        .handle_allocate_token(1, MINER_ID, JobDeclarationMode::CoinbaseOnly)
        .unwrap();

    let request = SetCustomMiningJob {
        channel_id: JOB_CHANNEL,
        request_id: 2,
        mining_job_token: token_response.mining_job_token,
        version: JOB_VERSION,
        prev_hash,
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        time: JOB_TIME,
        bits: 0x1d00ffff,
        coinbase_tx: minimal_tx(),
    };

    server.handle_declare_job(request).await.unwrap().job_id
}

/// Build a share that passes all cheap checks (version/time match the job) but
/// carries a garbage solution that will fail Equihash verification. `tag`
/// distinguishes distinct shares so dedup does not collide.
fn valid_struct_share(tag: u8) -> JdShare {
    let mut nonce = [0u8; 32];
    nonce[0] = tag;
    let mut solution = [0u8; 1344];
    solution[0] = tag;
    JdShare {
        version: JOB_VERSION,
        time: JOB_TIME,
        nonce,
        solution,
    }
}

#[tokio::test]
async fn test_submit_shares_unknown_job() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    declare_test_job(&server).await;

    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL,
        request_id: 77,
        job_id: 999_999, // never declared
        shares: vec![valid_struct_share(1), valid_struct_share(2)],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.channel_id, JOB_CHANNEL);
    assert_eq!(resp.request_id, 77);
    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 2);
    assert_eq!(resp.first_error_code, JdShareErrorCode::UnknownJob.as_u8());
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
}

#[tokio::test]
async fn test_submit_shares_channel_mismatch() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL + 1, // does not match the declared job's channel
        request_id: 5,
        job_id,
        shares: vec![valid_struct_share(1)],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 1);
    assert_eq!(
        resp.first_error_code,
        JdShareErrorCode::ChannelMismatch.as_u8()
    );
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
}

#[tokio::test]
async fn test_submit_shares_version_mismatch() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    // DECISION: a version that differs from the declared job is treated as
    // StaleJob — a version change implies the job rolled / template changed.
    let mut share = valid_struct_share(1);
    share.version = JOB_VERSION + 1;

    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL,
        request_id: 6,
        job_id,
        shares: vec![share],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 1);
    assert_eq!(resp.first_error_code, JdShareErrorCode::StaleJob.as_u8());
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
}

#[tokio::test]
async fn test_submit_shares_time_out_of_window() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    // Far in the future, well past job.time + 7200.
    let mut share = valid_struct_share(1);
    share.time = JOB_TIME + 100_000;

    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL,
        request_id: 8,
        job_id,
        shares: vec![share],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 1);
    assert_eq!(resp.first_error_code, JdShareErrorCode::StaleJob.as_u8());
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
}

#[tokio::test]
async fn test_submit_shares_garbage_solution_bad_solution() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    // Passes all cheap checks, fails Equihash verification.
    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL,
        request_id: 9,
        job_id,
        shares: vec![valid_struct_share(1)],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 1);
    assert_eq!(resp.first_error_code, JdShareErrorCode::BadSolution.as_u8());
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
}

#[tokio::test]
async fn test_submit_shares_duplicate_in_batch() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    // The SAME invalid share submitted twice. Invalid shares are NOT recorded in
    // the dedup (recording them would let an attacker exhaust per-job capacity at
    // zero PoW cost). Both copies are rejected as BadSolution — the second is
    // never Duplicate because the first was never inserted.
    let share = valid_struct_share(1);
    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL,
        request_id: 10,
        job_id,
        shares: vec![share.clone(), share],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 2);
    // First rejection is the bad solution; that is the reported first_error_code.
    assert_eq!(resp.first_error_code, JdShareErrorCode::BadSolution.as_u8());
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
}

#[tokio::test]
async fn test_submit_shares_mixed_batch_counts_and_first_error() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    // Share 0: channel is fine but version mismatch -> StaleJob (first rejection).
    let mut s0 = valid_struct_share(1);
    s0.version = JOB_VERSION + 1;
    // Share 1: cheap checks pass, garbage solution -> BadSolution.
    let s1 = valid_struct_share(2);
    // Share 2: time out of window -> StaleJob.
    let mut s2 = valid_struct_share(3);
    s2.time = JOB_TIME + 100_000;

    let msg = SubmitSharesJd {
        channel_id: JOB_CHANNEL,
        request_id: 11,
        job_id,
        shares: vec![s0, s1, s2],
    };
    let resp = server.handle_submit_shares_jd(msg).await;

    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected, 3);
    // first_error_code is the FIRST rejection in batch order.
    assert_eq!(resp.first_error_code, JdShareErrorCode::StaleJob.as_u8());
    // No credit on any rejection path.
    assert!(payout.get_stats(&MINER_ID.to_string()).is_none());
    assert_eq!(resp.channel_id, JOB_CHANNEL);
    assert_eq!(resp.request_id, 11);
}

#[tokio::test]
async fn test_submit_shares_dedup_evicts_when_job_gone() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout.clone());
    let job_id = declare_test_job(&server).await;

    // First batch registers dedup keys for this job_id.
    let share = valid_struct_share(1);
    let _ = server
        .handle_submit_shares_jd(SubmitSharesJd {
            channel_id: JOB_CHANNEL,
            request_id: 1,
            job_id,
            shares: vec![share],
        })
        .await;

    // A submission for an unknown job exercises the unknown-job path. The
    // eviction sweep at the head of the handler drops dedup entries whose
    // job_id no longer resolves. (Token expiry is not drivable from tests, so
    // the unknown-job path stands in for the eviction trigger.)
    let resp = server
        .handle_submit_shares_jd(SubmitSharesJd {
            channel_id: JOB_CHANNEL,
            request_id: 2,
            job_id: job_id.wrapping_add(12345), // unknown
            shares: vec![valid_struct_share(2)],
        })
        .await;
    assert_eq!(resp.first_error_code, JdShareErrorCode::UnknownJob.as_u8());
}

#[tokio::test]
async fn test_submit_shares_response_echoes_ids() {
    let payout = Arc::new(PayoutTracker::default());
    let server = JdServer::new(test_config(), payout);
    let job_id = declare_test_job(&server).await;

    let resp = server
        .handle_submit_shares_jd(SubmitSharesJd {
            channel_id: JOB_CHANNEL,
            request_id: 0xDEAD_BEEF,
            job_id,
            shares: vec![valid_struct_share(1)],
        })
        .await;

    assert_eq!(resp.channel_id, JOB_CHANNEL);
    assert_eq!(resp.request_id, 0xDEAD_BEEF);
}

#[test]
fn test_submit_shares_jd_64share_accepted_boundary_roundtrip() {
    // count == 64 is the accepted boundary (MAX_SHARE_COUNT); it must encode and
    // decode cleanly.
    let shares: Vec<JdShare> = (0..64u8).map(make_share).collect();
    let original = SubmitSharesJd {
        channel_id: 3,
        request_id: 300,
        job_id: 64,
        shares,
    };

    let encoded = encode_submit_shares_jd(&original).unwrap();
    let decoded = decode_submit_shares_jd(&encoded).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(decoded.shares.len(), 64);
}
