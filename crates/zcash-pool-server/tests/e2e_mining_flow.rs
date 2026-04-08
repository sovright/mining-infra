//! End-to-end mining flow integration test.
//! Tests: template -> job -> share -> validation -> payout -> vardiff -> new block

use std::time::Duration;

use zcash_equihash_validator::{VardiffConfig, VardiffController};
use zcash_mining_protocol::messages::{RejectReason, ShareResult, SubmitEquihashShare};
use zcash_pool_server::{
    Channel, InMemoryDuplicateDetector, JobDistributor, PayoutTracker, ShareProcessor,
};
use zcash_template_provider::header::{assemble_header, parse_target};
use zcash_template_provider::testutil::TestTemplateFactory;
use zcash_template_provider::types::BlockTemplate;

/// Build a `BlockTemplate` from a `GetBlockTemplateResponse` using the same
/// logic as TemplateProvider::process_template, but without needing the full
/// TemplateProvider (which requires an RPC backend).
fn response_to_template(
    response: &zcash_template_provider::types::GetBlockTemplateResponse,
    template_id: u64,
) -> BlockTemplate {
    let header = assemble_header(response).expect("assemble_header should succeed");
    let target = parse_target(&response.target).expect("parse_target should succeed");

    let total_fees: i64 = response.transactions.iter().map(|tx| tx.fee).sum();

    let coinbase = if let Some(data) = response.coinbase_txn.get("data") {
        if let Some(hex_str) = data.as_str() {
            hex::decode(hex_str).expect("coinbase hex should be valid")
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    BlockTemplate {
        template_id,
        height: response.height,
        header,
        target,
        transactions: response.transactions.clone(),
        coinbase,
        total_fees,
    }
}

#[test]
fn test_full_mining_lifecycle() {
    // =========================================================================
    // Phase 1: Setup
    // =========================================================================
    let response1 = TestTemplateFactory::new().height(500_000).build();
    let template1 = response_to_template(&response1, 1);

    let mut distributor = JobDistributor::new();
    let processor = ShareProcessor::new();
    let detector = InMemoryDuplicateDetector::new();
    let payout = PayoutTracker::default();

    // =========================================================================
    // Phase 2: Template -> Job
    // =========================================================================
    let is_new_block = distributor.update_template(template1);
    assert!(is_new_block, "First template should be a new block");
    assert_eq!(distributor.current_height(), Some(500_000));

    // Create a channel with 4-byte nonce_1
    let channel = Channel::new(vec![0x01, 0x02, 0x03, 0x04], VardiffConfig::default())
        .expect("channel creation should succeed");
    assert_eq!(channel.nonce_2_len, 28);

    let job = distributor
        .create_job(&channel, true)
        .expect("create_job should succeed with a template");
    assert_eq!(job.channel_id, channel.id);
    assert_eq!(job.nonce_1, vec![0x01, 0x02, 0x03, 0x04]);
    assert_eq!(job.nonce_2_len, 28);
    assert!(job.clean_jobs);
    assert!(job.validate_nonce_len(), "nonce_1 + nonce_2 must equal 32");

    // =========================================================================
    // Phase 3: Share Submission
    // =========================================================================
    // Use an all-0xff block_target so that any valid Equihash solution would
    // qualify as a block. With a dummy (zero) solution the share will be
    // rejected for InvalidSolution -- not for any other reason.
    let block_target = [0xff; 32];

    let share = SubmitEquihashShare {
        channel_id: channel.id,
        sequence_number: 1,
        job_id: job.job_id,
        nonce_2: vec![0u8; 28],
        time: job.time,
        solution: [0u8; 1344],
    };

    let result = processor
        .validate_share_with_job(&share, &job, &detector, &block_target)
        .expect("validate_share_with_job should not return Err");

    assert!(
        !result.accepted,
        "Dummy solution should not be accepted"
    );
    assert!(
        matches!(
            result.result,
            ShareResult::Rejected(RejectReason::InvalidSolution)
        ),
        "Expected InvalidSolution rejection, got: {:?}",
        result.result
    );
    assert!(!result.is_block);

    // =========================================================================
    // Phase 4: Duplicate Detection
    // =========================================================================
    // Submit the exact same share again -- should be rejected as Duplicate
    // because the detector already recorded it in Phase 3.
    let result_dup = processor
        .validate_share_with_job(&share, &job, &detector, &block_target)
        .expect("validate_share_with_job should not return Err");

    assert!(!result_dup.accepted);
    assert!(
        matches!(
            result_dup.result,
            ShareResult::Rejected(RejectReason::Duplicate)
        ),
        "Second identical share should be Duplicate, got: {:?}",
        result_dup.result
    );

    // =========================================================================
    // Phase 5: Payout Tracking
    // =========================================================================
    let miner_id = format!("miner-channel-{}", channel.id);

    // Simulate recording accepted shares with difficulty
    payout.record_share(&miner_id, 1.0);
    payout.record_share(&miner_id, 2.5);
    payout.record_share(&miner_id, 1.0);

    let stats = payout
        .get_stats(&miner_id)
        .expect("miner stats should exist");
    assert_eq!(stats.total_shares, 3);
    assert!((stats.total_difficulty - 4.5).abs() < f64::EPSILON);
    assert_eq!(stats.window_shares, 3);

    // =========================================================================
    // Phase 6: Vardiff
    // =========================================================================
    let vardiff_config = VardiffConfig {
        initial_difficulty: 100.0,
        min_difficulty: 1.0,
        max_difficulty: 1000.0,
        retarget_interval: Duration::from_millis(1),
        target_shares_per_minute: 5.0,
        variance_tolerance: 0.25,
    };
    let mut vardiff = VardiffController::new(vardiff_config);
    assert_eq!(vardiff.current_difficulty(), 100.0);

    // Record zero shares, wait for retarget interval, trigger retarget
    std::thread::sleep(Duration::from_millis(5));
    let new_diff = vardiff.maybe_retarget();
    assert!(
        new_diff.is_some(),
        "Retarget should trigger after interval elapses"
    );
    // With zero shares the difficulty should drop (halved)
    assert!(
        new_diff.unwrap() < 100.0,
        "Difficulty should decrease with zero shares"
    );

    // =========================================================================
    // Phase 7: New Block
    // =========================================================================
    // Create a second template with a different prev_hash to simulate a new block
    let response2 = TestTemplateFactory::new()
        .height(500_001)
        .prev_hash(&"ab".repeat(32))
        .build();
    let template2 = response_to_template(&response2, 2);

    let is_new_block_2 = distributor.update_template(template2);
    assert!(
        is_new_block_2,
        "Template with different prev_hash should be a new block"
    );
    assert_eq!(distributor.current_height(), Some(500_001));

    // Create a new job with clean_jobs=true
    let job2 = distributor
        .create_job(&channel, true)
        .expect("create_job should succeed for new template");
    assert!(job2.clean_jobs);
    assert_ne!(
        job2.prev_hash, job.prev_hash,
        "New job should have different prev_hash"
    );

    // Verify old job is stale by adding both jobs to a channel and checking
    let mut channel_with_jobs =
        Channel::new(vec![0x05, 0x06, 0x07, 0x08], VardiffConfig::default())
            .expect("channel creation should succeed");
    channel_with_jobs.add_job(job.clone(), false);
    channel_with_jobs.add_job(job2.clone(), true); // clean_jobs=true marks old job stale
    assert!(
        !channel_with_jobs.is_job_active(job.job_id),
        "Old job should be stale after clean_jobs"
    );
    assert!(
        channel_with_jobs.is_job_active(job2.job_id),
        "New job should be active"
    );

    // Verify that submitting a share against the stale job is rejected
    let stale_share = SubmitEquihashShare {
        channel_id: channel_with_jobs.id,
        sequence_number: 2,
        job_id: job.job_id,
        nonce_2: vec![0xaa; 28],
        time: job.time,
        solution: [0u8; 1344],
    };
    let stale_detector = InMemoryDuplicateDetector::new();
    let stale_result = processor
        .validate_share(&stale_share, &channel_with_jobs, &stale_detector, &block_target)
        .expect("validate_share should not return Err");
    assert!(!stale_result.accepted);
    assert!(
        matches!(
            stale_result.result,
            ShareResult::Rejected(RejectReason::StaleJob)
        ),
        "Share on stale job should be rejected as StaleJob, got: {:?}",
        stale_result.result
    );
}
