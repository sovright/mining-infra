//! Integration tests for the Equihash validator

mod test_vectors;

use zcash_equihash_validator::{EquihashValidator, VardiffController, VardiffConfig};
use zcash_equihash_validator::difficulty::{difficulty_to_target, target_to_difficulty};
use zcash_mining_protocol::messages::{NewEquihashJob, SubmitEquihashShare};

#[test]
fn test_full_share_validation_flow() {
    let validator = EquihashValidator::new();

    // Create a job
    let job = NewEquihashJob {
        channel_id: 1,
        job_id: 1,
        future_job: false,
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        nonce_1: vec![0x01, 0x02, 0x03, 0x04],
        nonce_2_len: 28,
        time: 1700000000,
        bits: 0x1d00ffff,
        target: [0xff; 32], // Easy target for testing
        clean_jobs: false,
    };

    // Create a share (with invalid solution - just testing the flow)
    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2: vec![0xff; 28],
        time: 1700000000,
        solution: [0x00; 1344],
    };

    // Build full nonce
    let nonce = job.build_nonce(&share.nonce_2).unwrap();
    assert_eq!(nonce.len(), 32);

    // Build header
    let header = job.build_header(&nonce);
    assert_eq!(header.len(), 140);

    // Verification should fail (invalid solution)
    let result = validator.verify_solution(&header, &share.solution);
    assert!(result.is_err());
}

#[test]
fn test_vardiff_integration_with_protocol() {
    let config = VardiffConfig {
        target_shares_per_minute: 5.0,
        initial_difficulty: 1.0,
        min_difficulty: 1.0,
        max_difficulty: 1_000_000.0,
        retarget_interval: std::time::Duration::from_secs(60),
        variance_tolerance: 0.25,
    };
    let controller = VardiffController::new(config);

    // Get target for job
    let target = controller.current_target();

    // Create job with this target
    let job = NewEquihashJob {
        channel_id: 1,
        job_id: 1,
        future_job: false,
        version: 5,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        block_commitments: [0; 32],
        nonce_1: vec![0; 8],
        nonce_2_len: 24,
        time: 0,
        bits: 0x1d00ffff,
        target: target.to_le_bytes(),
        clean_jobs: false,
    };

    assert_eq!(job.target, target.to_le_bytes());
}

#[test]
fn test_difficulty_to_target_integration() {
    // Test that difficulty values produce sensible targets
    let difficulties = [1.0, 10.0, 100.0, 1000.0];

    for diff in difficulties {
        let target = difficulty_to_target(diff);
        let recovered = target_to_difficulty(&target);

        // Should be within 1% due to floating point
        let ratio = recovered / diff;
        assert!(
            ratio > 0.99 && ratio < 1.01,
            "Difficulty {} recovered as {}", diff, recovered
        );
    }
}

#[test]
fn test_header_construction_with_validator() {
    let validator = EquihashValidator::new();

    // Create a job with specific values
    let job = NewEquihashJob {
        channel_id: 1,
        job_id: 42,
        future_job: false,
        version: 5, // NU5 version
        prev_hash: [0x11; 32],
        merkle_root: [0x22; 32],
        block_commitments: [0x33; 32],
        nonce_1: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        nonce_2_len: 24,
        time: 0x12345678,
        bits: 0x1d00ffff,
        target: [0xff; 32],
        clean_jobs: false,
    };

    // Build nonce from miner portion
    let nonce_2 = vec![0xaa; 24];
    let nonce = job.build_nonce(&nonce_2).unwrap();

    // Build header
    let header = job.build_header(&nonce);

    // Verify header structure
    assert_eq!(header.len(), 140);

    // Version at offset 0 (little-endian)
    assert_eq!(&header[0..4], &[0x05, 0x00, 0x00, 0x00]);

    // prev_hash at offset 4
    assert_eq!(&header[4..36], &[0x11; 32]);

    // merkle_root at offset 36
    assert_eq!(&header[36..68], &[0x22; 32]);

    // block_commitments at offset 68
    assert_eq!(&header[68..100], &[0x33; 32]);

    // time at offset 100 (little-endian)
    assert_eq!(&header[100..104], &[0x78, 0x56, 0x34, 0x12]);

    // bits at offset 104 (little-endian)
    assert_eq!(&header[104..108], &[0xff, 0xff, 0x00, 0x1d]);

    // nonce at offset 108 (nonce_1 + nonce_2)
    assert_eq!(&header[108..116], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&header[116..140], &[0xaa; 24]);

    // Try to verify (should fail with invalid solution, but header should be accepted)
    let invalid_solution = [0u8; 1344];
    let result = validator.verify_solution(&header, &invalid_solution);

    // The verification should fail because the solution is invalid,
    // not because of header issues
    assert!(result.is_err());
}

#[test]
fn test_job_nonce_length_validation() {
    // Valid job with correct nonce lengths (8 + 24 = 32)
    let valid_job = NewEquihashJob {
        channel_id: 1,
        job_id: 1,
        future_job: false,
        version: 5,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        block_commitments: [0; 32],
        nonce_1: vec![0; 8],
        nonce_2_len: 24,
        time: 0,
        bits: 0,
        target: [0; 32],
        clean_jobs: false,
    };
    assert!(valid_job.validate_nonce_len());
    assert_eq!(valid_job.total_nonce_len(), 32);

    // Invalid job with wrong nonce lengths (4 + 24 = 28, not 32)
    let invalid_job = NewEquihashJob {
        nonce_1: vec![0; 4],
        nonce_2_len: 24,
        ..valid_job.clone()
    };
    assert!(!invalid_job.validate_nonce_len());
    assert_eq!(invalid_job.total_nonce_len(), 28);
}

#[test]
fn test_share_solution_length_validation() {
    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2: vec![0; 24],
        time: 0,
        solution: [0; 1344],
    };

    // Solution is exactly 1344 bytes (Equihash 200,9)
    assert!(share.validate_solution_len());
    assert_eq!(share.solution.len(), 1344);
}

#[test]
fn test_target_comparison_with_hash() {
    use zcash_equihash_validator::Target;

    // Create an easy target (high value = easy)
    let easy_target = Target::from_le_bytes([0xff; 32]);

    // A hash of all zeros should meet any non-zero target
    let easy_hash = [0x00; 32];
    assert!(easy_target.is_met_by(&easy_hash));

    // Create a hard target (low value = hard)
    let hard_target = Target::from_le_bytes([0x01; 32]);

    // A hash of all 0xff should NOT meet a low target
    let hard_hash = [0xff; 32];
    assert!(!hard_target.is_met_by(&hard_hash));

    // Equal hash and target should pass
    let same = [0x42; 32];
    let same_target = Target::from_le_bytes(same);
    assert!(same_target.is_met_by(&same));
}

