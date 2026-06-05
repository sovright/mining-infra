//! Integration tests for zcash-pool-server
//!
//! These tests verify the integration between pool components without
//! requiring a running Zebra node.

use std::time::Duration;
use zcash_equihash_validator::VardiffConfig;
use zcash_mining_protocol::messages::NewEquihashJob;
use zcash_pool_server::{
    Channel, DuplicateDetector, InMemoryDuplicateDetector, JobDistributor, PayoutTracker,
    PoolConfig,
};
use zcash_template_provider::types::{BlockTemplate, EquihashHeader, Hash256};

/// Helper to create a test block template
fn make_test_template(height: u64, prev_hash: [u8; 32]) -> BlockTemplate {
    BlockTemplate {
        template_id: height,
        height,
        header: EquihashHeader {
            version: 5,
            prev_hash: Hash256(prev_hash),
            merkle_root: Hash256([0xaa; 32]),
            hash_block_commitments: Hash256([0xbb; 32]),
            time: 1700000000,
            bits: 0x1d00ffff,
            nonce: [0; 32],
        },
        target: Hash256([0xff; 32]),
        transactions: vec![],
        coinbase: vec![],
        chain_history_root: Hash256([0x42; 32]),
        consensus_branch_id: 0xc8e7_1055,
        total_fees: 0,
    }
}

// =============================================================================
// Config Tests
// =============================================================================

#[test]
fn test_config_defaults() {
    let config = PoolConfig::default();

    // Verify default values match expected pool configuration
    assert_eq!(config.listen_addr.port(), 3333);
    assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
    assert_eq!(config.template_poll_ms, 1000);
    assert_eq!(config.validation_threads, 4);
    assert_eq!(config.nonce_1_len, 4);
    assert_eq!(config.initial_difficulty, 1.0);
    assert_eq!(config.target_shares_per_minute, 5.0);
    assert_eq!(config.max_connections, 10000);
    // JD Server disabled by default
    assert!(config.jd_listen_addr.is_none());
    assert!(config.pool_payout_script.is_none());
}

#[test]
fn test_config_custom() {
    let config = PoolConfig {
        listen_addr: "0.0.0.0:4444".parse().unwrap(),
        zebra_url: "http://10.0.0.1:8232".to_string(),
        template_poll_ms: 500,
        validation_threads: 8,
        nonce_1_len: 8,
        initial_difficulty: 100.0,
        target_shares_per_minute: 10.0,
        max_connections: 5000,
        jd_listen_addr: Some("0.0.0.0:3334".parse().unwrap()),
        pool_payout_script: Some(vec![0x76, 0xa9, 0x14]),
        ..Default::default()
    };

    assert_eq!(config.listen_addr.port(), 4444);
    assert_eq!(config.nonce_1_len, 8);
    assert_eq!(config.initial_difficulty, 100.0);
    assert!(config.jd_listen_addr.is_some());
    assert!(config.pool_payout_script.is_some());
    // Verify noise defaults
    assert!(!config.noise_enabled);
    assert!(config.noise_private_key_path.is_none());
}

// =============================================================================
// Job Distribution Tests
// =============================================================================

#[test]
fn test_job_distribution_flow() {
    let mut distributor = JobDistributor::new();

    // Initially no template
    assert!(!distributor.has_template());
    assert!(distributor.current_height().is_none());

    // Update with first template
    let template1 = make_test_template(100, [0x11; 32]);
    let is_new_block = distributor.update_template(template1);
    assert!(is_new_block, "First template should be a new block");
    assert!(distributor.has_template());
    assert_eq!(distributor.current_height(), Some(100));

    // Create channel and job
    let channel = Channel::new(vec![0x01, 0x02, 0x03, 0x04], VardiffConfig::default()).unwrap();
    let job = distributor
        .create_job(&channel, true)
        .expect("Should create job");

    // Verify job contains expected data
    assert_eq!(job.channel_id, channel.id);
    assert_eq!(job.nonce_1, vec![0x01, 0x02, 0x03, 0x04]);
    assert_eq!(job.nonce_2_len, 28); // 32 - 4 = 28
    assert_eq!(job.version, 5);
    assert_eq!(job.prev_hash, [0x11; 32]);
    assert!(job.clean_jobs);

    // Same block - not new
    let template2 = make_test_template(100, [0x11; 32]);
    let is_new_block = distributor.update_template(template2);
    assert!(!is_new_block, "Same prev_hash should not be new block");

    // New block detected
    let template3 = make_test_template(101, [0x22; 32]);
    let is_new_block = distributor.update_template(template3);
    assert!(is_new_block, "Different prev_hash should be new block");
    assert_eq!(distributor.current_height(), Some(101));
}

#[test]
fn test_job_ids_are_unique() {
    let mut distributor = JobDistributor::new();
    distributor.update_template(make_test_template(100, [0x11; 32]));

    let channel1 = Channel::new(vec![0x01, 0x02, 0x03, 0x04], VardiffConfig::default()).unwrap();
    let channel2 = Channel::new(vec![0x05, 0x06, 0x07, 0x08], VardiffConfig::default()).unwrap();

    let job1 = distributor.create_job(&channel1, true).unwrap();
    let job2 = distributor.create_job(&channel2, true).unwrap();

    // Global job IDs should be unique
    assert_ne!(job1.job_id, job2.job_id);
}

// =============================================================================
// Duplicate Detection Tests
// =============================================================================

#[test]
fn test_duplicate_detection_in_validation() {
    let detector = InMemoryDuplicateDetector::new();

    let job_id = 1;
    let nonce_2 = vec![0x01, 0x02, 0x03, 0x04];
    let solution = vec![0xaa; 1344]; // Equihash solution size

    // First submission is NOT a duplicate
    let is_dup = detector.check_and_record(job_id, &nonce_2, &solution);
    assert!(!is_dup, "First submission should not be duplicate");

    // Same submission IS a duplicate
    let is_dup = detector.check_and_record(job_id, &nonce_2, &solution);
    assert!(is_dup, "Same submission should be duplicate");

    // Different nonce_2, same job - NOT a duplicate
    let nonce_2_alt = vec![0x05, 0x06, 0x07, 0x08];
    let is_dup = detector.check_and_record(job_id, &nonce_2_alt, &solution);
    assert!(!is_dup, "Different nonce should not be duplicate");

    // Same nonce_2, different job - NOT a duplicate
    let job_id_2 = 2;
    let is_dup = detector.check_and_record(job_id_2, &nonce_2, &solution);
    assert!(!is_dup, "Different job should not be duplicate");
}

#[test]
fn test_duplicate_clear_job() {
    let detector = InMemoryDuplicateDetector::new();

    let nonce_2 = vec![0x01, 0x02, 0x03];
    let solution = vec![0xaa; 1344];

    // Record share
    detector.check_and_record(1, &nonce_2, &solution);
    assert!(detector.check_and_record(1, &nonce_2, &solution)); // duplicate

    // Clear job 1
    detector.clear_job(1);

    // Same share is no longer duplicate
    assert!(!detector.check_and_record(1, &nonce_2, &solution));
}

#[test]
fn test_duplicate_clear_all() {
    let detector = InMemoryDuplicateDetector::new();

    let nonce_2 = vec![0x01, 0x02, 0x03];
    let solution = vec![0xaa; 1344];

    // Record shares for multiple jobs
    detector.check_and_record(1, &nonce_2, &solution);
    detector.check_and_record(2, &nonce_2, &solution);

    // Clear all
    detector.clear_all();

    // All shares are no longer duplicates
    assert!(!detector.check_and_record(1, &nonce_2, &solution));
    assert!(!detector.check_and_record(2, &nonce_2, &solution));
}

// =============================================================================
// Payout Tracking Tests
// =============================================================================

#[test]
fn test_payout_tracking() {
    let tracker = PayoutTracker::new(Duration::from_secs(600));

    let miner1 = "miner_001".to_string();
    let miner2 = "miner_002".to_string();

    // Record shares
    tracker.record_share(&miner1, 100.0);
    tracker.record_share(&miner1, 150.0);
    tracker.record_share(&miner2, 200.0);

    // Verify stats
    let stats1 = tracker
        .get_stats(&miner1)
        .expect("miner1 should have stats");
    assert_eq!(stats1.total_shares, 2);
    assert_eq!(stats1.total_difficulty, 250.0);
    assert_eq!(stats1.window_shares, 2);
    assert_eq!(stats1.window_difficulty, 250.0);
    assert!(stats1.last_share.is_some());

    let stats2 = tracker
        .get_stats(&miner2)
        .expect("miner2 should have stats");
    assert_eq!(stats2.total_shares, 1);
    assert_eq!(stats2.total_difficulty, 200.0);

    // Get all stats
    let all = tracker.get_all_stats();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_payout_window_reset() {
    let tracker = PayoutTracker::new(Duration::from_secs(600));
    let miner = "miner".to_string();

    tracker.record_share(&miner, 100.0);
    tracker.record_share(&miner, 100.0);

    // Reset window
    tracker.reset_window();

    // Record more
    tracker.record_share(&miner, 50.0);

    let stats = tracker.get_stats(&miner).unwrap();
    assert_eq!(stats.total_shares, 3); // Total preserved
    assert_eq!(stats.total_difficulty, 250.0); // Total preserved
    assert_eq!(stats.window_shares, 1); // Window reset
    assert_eq!(stats.window_difficulty, 50.0); // Window reset
}

#[test]
fn test_payout_unknown_miner() {
    let tracker = PayoutTracker::default();
    let stats = tracker.get_stats(&"unknown".to_string());
    assert!(stats.is_none());
}

// =============================================================================
// Channel State Tests
// =============================================================================

#[test]
fn test_channel_nonce_generation() {
    // Generate nonces for different channel IDs
    let nonce1 = Channel::generate_nonce_1(1, 4).unwrap();
    let nonce2 = Channel::generate_nonce_1(2, 4).unwrap();
    let nonce3 = Channel::generate_nonce_1(256, 4).unwrap();

    // Each should be unique
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce1, nonce3);

    // Verify encoding (little-endian)
    assert_eq!(nonce1, vec![0x01, 0x00, 0x00, 0x00]);
    assert_eq!(nonce2, vec![0x02, 0x00, 0x00, 0x00]);
    assert_eq!(nonce3, vec![0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn test_channel_nonce_length_variations() {
    // 2-byte nonce
    let nonce_2 = Channel::generate_nonce_1(0x1234, 2).unwrap();
    assert_eq!(nonce_2.len(), 2);
    assert_eq!(nonce_2, vec![0x34, 0x12]);

    // 8-byte nonce
    let nonce_8 = Channel::generate_nonce_1(0x12345678, 8).unwrap();
    assert_eq!(nonce_8.len(), 8);
    // First 4 bytes are the ID, rest is zero-padded
    assert_eq!(&nonce_8[0..4], &[0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn test_channel_job_management() {
    let mut channel = Channel::new(vec![0; 4], VardiffConfig::default()).unwrap();

    // Create test job
    let job = NewEquihashJob {
        channel_id: channel.id,
        job_id: 1,
        future_job: false,
        version: 5,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        block_commitments: [0; 32],
        nonce_1: channel.nonce_1.clone(),
        nonce_2_len: channel.nonce_2_len,
        time: 0,
        bits: 0,
        target: [0xff; 32],
        clean_jobs: false,
    };

    // Add job
    channel.add_job(job.clone(), false);
    assert!(channel.is_job_active(1));
    assert!(!channel.is_job_active(999)); // Unknown job

    // Add another job without clean
    let job2 = NewEquihashJob {
        job_id: 2,
        ..job.clone()
    };
    channel.add_job(job2, false);
    assert!(channel.is_job_active(1)); // Still active
    assert!(channel.is_job_active(2)); // New job also active

    // Add job with clean_jobs = true
    let job3 = NewEquihashJob {
        job_id: 3,
        ..job.clone()
    };
    channel.add_job(job3, true);
    assert!(!channel.is_job_active(1)); // Old job now stale
    assert!(!channel.is_job_active(2)); // Old job now stale
    assert!(channel.is_job_active(3)); // Only new job active
}

#[test]
fn test_channel_nonce_space() {
    // 4-byte nonce_1 means 28-byte nonce_2
    let channel_4 = Channel::new(vec![0; 4], VardiffConfig::default()).unwrap();
    assert_eq!(channel_4.nonce_2_len, 28);

    // 8-byte nonce_1 means 24-byte nonce_2
    let channel_8 = Channel::new(vec![0; 8], VardiffConfig::default()).unwrap();
    assert_eq!(channel_8.nonce_2_len, 24);

    // 16-byte nonce_1 means 16-byte nonce_2
    let channel_16 = Channel::new(vec![0; 16], VardiffConfig::default()).unwrap();
    assert_eq!(channel_16.nonce_2_len, 16);
}

// =============================================================================
// Integration Flow Tests
// =============================================================================

#[test]
fn test_full_job_flow() {
    // This test simulates the full flow:
    // 1. Template arrives
    // 2. Job distributor processes it
    // 3. Channel receives job
    // 4. Share is tracked

    // Step 1: Create job distributor and process template
    let mut distributor = JobDistributor::new();
    let template = make_test_template(500000, [0x12; 32]);
    let is_new = distributor.update_template(template);
    assert!(is_new);

    // Step 2: Create channels (simulating two miners)
    let channel1 = Channel::new(vec![0x01, 0x02, 0x03, 0x04], VardiffConfig::default()).unwrap();
    let channel2 = Channel::new(vec![0x05, 0x06, 0x07, 0x08], VardiffConfig::default()).unwrap();

    // Step 3: Create jobs for each channel
    let job1 = distributor.create_job(&channel1, true).unwrap();
    let job2 = distributor.create_job(&channel2, true).unwrap();

    // Verify jobs are correctly configured
    assert_ne!(job1.channel_id, job2.channel_id);
    assert_eq!(job1.prev_hash, job2.prev_hash); // Same block
    assert_eq!(job1.version, 5);

    // Step 4: Set up duplicate detector
    let detector = InMemoryDuplicateDetector::new();

    // Miner 1 submits a share
    let nonce_2 = vec![0xaa; 28];
    let solution = vec![0xbb; 1344];
    assert!(!detector.check_and_record(job1.job_id, &nonce_2, &solution));

    // Same share from miner 2 with different job is OK
    assert!(!detector.check_and_record(job2.job_id, &nonce_2, &solution));

    // Step 5: Track payouts
    let tracker = PayoutTracker::default();
    tracker.record_share(&format!("channel_{}", channel1.id), 100.0);
    tracker.record_share(&format!("channel_{}", channel2.id), 150.0);

    let all_stats = tracker.get_all_stats();
    assert_eq!(all_stats.len(), 2);
}
