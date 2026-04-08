//! Share processing and validation
//!
//! Validates submitted shares using the Equihash validator from Phase 2.

use crate::channel::Channel;
use crate::duplicate::DuplicateDetector;
use crate::error::{PoolError, Result};
use tracing::{debug, warn};
use zcash_equihash_validator::EquihashValidator;
use zcash_equihash_validator::difficulty::{Target, target_to_difficulty};
use zcash_mining_protocol::messages::{NewEquihashJob, RejectReason, ShareResult, SubmitEquihashShare};

/// Result of share validation
#[derive(Debug)]
pub struct ShareValidationResult {
    /// Whether the share was accepted
    pub accepted: bool,
    /// The share result to send back
    pub result: ShareResult,
    /// The share's difficulty (if valid solution)
    pub difficulty: Option<f64>,
    /// Whether this share is a valid block
    pub is_block: bool,
}

/// Share processor with Equihash validation
pub struct ShareProcessor {
    validator: EquihashValidator,
}

impl ShareProcessor {
    pub fn new() -> Self {
        Self {
            validator: EquihashValidator::new(),
        }
    }

    /// Validate a submitted share
    pub fn validate_share<D: DuplicateDetector>(
        &self,
        share: &SubmitEquihashShare,
        channel: &Channel,
        duplicate_detector: &D,
        block_target: &[u8; 32],
    ) -> Result<ShareValidationResult> {
        // 1. Check job exists and is active
        let channel_job = channel.get_job(share.job_id).ok_or_else(|| {
            warn!("Unknown job {} for channel {}", share.job_id, channel.id);
            PoolError::UnknownJob(share.job_id)
        })?;

        if !channel_job.active {
            debug!("Stale share for job {}", share.job_id);
            return Ok(ShareValidationResult {
                accepted: false,
                result: ShareResult::Rejected(RejectReason::StaleJob),
                difficulty: None,
                is_block: false,
            });
        }

        self.validate_share_with_job(share, &channel_job.job, duplicate_detector, block_target)
    }

    /// Validate a submitted share given the job data
    pub fn validate_share_with_job<D: DuplicateDetector>(
        &self,
        share: &SubmitEquihashShare,
        job: &NewEquihashJob,
        duplicate_detector: &D,
        block_target: &[u8; 32],
    ) -> Result<ShareValidationResult> {
        // 1. Check for duplicate
        if duplicate_detector.check_and_record(share.job_id, &share.nonce_2, &share.solution) {
            debug!("Duplicate share for job {}", share.job_id);
            return Ok(ShareValidationResult {
                accepted: false,
                result: ShareResult::Rejected(RejectReason::Duplicate),
                difficulty: None,
                is_block: false,
            });
        }

        // 2. Validate share timestamp is within consensus-acceptable range.
        //    Miners can roll ntime forward but not too far. A block-qualifying
        //    share with an invalid timestamp gets rejected by Zebra, wasting
        //    the block find.
        const MAX_TIME_FORWARD: u32 = 7200; // 2 hours, matches Zcash/Bitcoin consensus
        const MAX_TIME_BACKWARD: u32 = 60; // 1 minute tolerance for clock skew
        if share.time < job.time.saturating_sub(MAX_TIME_BACKWARD)
            || share.time > job.time.saturating_add(MAX_TIME_FORWARD)
        {
            debug!(
                "Share timestamp {} out of range (job time: {}, allowed: {}-{})",
                share.time,
                job.time,
                job.time.saturating_sub(MAX_TIME_BACKWARD),
                job.time.saturating_add(MAX_TIME_FORWARD),
            );
            return Ok(ShareValidationResult {
                accepted: false,
                result: ShareResult::Rejected(RejectReason::Other(
                    "timestamp out of range".to_string(),
                )),
                difficulty: None,
                is_block: false,
            });
        }

        // 3. Build full nonce and header
        let full_nonce = job.build_nonce(&share.nonce_2).ok_or_else(|| {
            PoolError::InvalidMessage("Invalid nonce_2 length".to_string())
        })?;

        let mut header = job.build_header(&full_nonce);
        // Update time if miner changed it (already validated above)
        header[100..104].copy_from_slice(&share.time.to_le_bytes());

        // 4. Verify Equihash solution AND check share meets pool target.
        //    verify_share calls verify_solution internally, so we only call it
        //    once to avoid the expensive (~144 MB) duplicate Equihash verification.
        let share_target = &job.target;
        match self.validator.verify_share(&header, &share.solution, share_target) {
            Ok(hash) => {
                // Calculate share difficulty
                let difficulty = self.hash_to_difficulty(&hash);

                // Check if this meets block target
                let is_block = self.meets_target(&hash, block_target);

                debug!(
                    "Valid share: difficulty={:.2}, is_block={}",
                    difficulty, is_block
                );

                Ok(ShareValidationResult {
                    accepted: true,
                    result: ShareResult::Accepted,
                    difficulty: Some(difficulty),
                    is_block,
                })
            }
            Err(zcash_equihash_validator::ValidationError::TargetNotMet) => {
                debug!("Share below target difficulty");
                Ok(ShareValidationResult {
                    accepted: false,
                    result: ShareResult::Rejected(RejectReason::LowDifficulty),
                    difficulty: None,
                    is_block: false,
                })
            }
            Err(e) => {
                debug!("Invalid solution: {}", e);
                Ok(ShareValidationResult {
                    accepted: false,
                    result: ShareResult::Rejected(RejectReason::InvalidSolution),
                    difficulty: None,
                    is_block: false,
                })
            }
        }
    }

    /// Convert hash to difficulty
    fn hash_to_difficulty(&self, hash: &[u8; 32]) -> f64 {
        let target = Target::from_le_bytes(*hash);
        target_to_difficulty(&target)
    }

    /// Check if hash meets target using the canonical Target::is_met_by()
    fn meets_target(&self, hash: &[u8; 32], target: &[u8; 32]) -> bool {
        let target = Target::from_le_bytes(*target);
        target.is_met_by(hash)
    }
}

impl Default for ShareProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_difficulty() {
        let processor = ShareProcessor::new();

        // All zeros = maximum difficulty
        let hash_zeros = [0u8; 32];
        let diff = processor.hash_to_difficulty(&hash_zeros);
        assert!(diff > 1e70); // Very high

        // All 0xff = very low difficulty
        let hash_ones = [0xff; 32];
        let diff = processor.hash_to_difficulty(&hash_ones);
        assert!(diff < 1.0);
    }

    #[test]
    fn test_meets_target() {
        let processor = ShareProcessor::new();

        let low_hash = [0x00; 32];
        let high_target = [0xff; 32];
        assert!(processor.meets_target(&low_hash, &high_target));

        let high_hash = [0xff; 32];
        let low_target = [0x00; 32];
        assert!(!processor.meets_target(&high_hash, &low_target));
    }

    #[test]
    fn test_share_time_validation() {
        use crate::duplicate::InMemoryDuplicateDetector;
        let processor = ShareProcessor::new();
        let detector = InMemoryDuplicateDetector::new();
        let block_target = [0xff; 32];
        let job_time: u32 = 1_700_000_000;

        let job = NewEquihashJob {
            channel_id: 1,
            job_id: 1,
            future_job: false,
            version: 5,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            block_commitments: [0; 32],
            nonce_1: vec![0; 4],
            nonce_2_len: 28,
            time: job_time,
            bits: 0x2007ffff,
            target: [0xff; 32],
            clean_jobs: false,
        };

        // Share with timestamp too far in the future (>2 hours)
        let future_share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: job_time + 7201, // 2 hours + 1 second
            solution: [0; 1344],
        };
        let result = processor.validate_share_with_job(&future_share, &job, &detector, &block_target).unwrap();
        assert!(!result.accepted, "Share with timestamp >2h in future should be rejected");

        // Share with timestamp too far in the past (>60s before job)
        let past_share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 2,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: job_time - 61,
            solution: [0; 1344],
        };
        let result = processor.validate_share_with_job(&past_share, &job, &detector, &block_target).unwrap();
        assert!(!result.accepted, "Share with timestamp >60s before job time should be rejected");

        // Share with valid timestamp (same as job time) should pass time check
        // (it will fail Equihash validation, but that's expected - the point is
        // it doesn't get rejected for timestamp)
        let valid_time_share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 3,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: job_time,
            solution: [0; 1344],
        };
        let result = processor.validate_share_with_job(&valid_time_share, &job, &detector, &block_target).unwrap();
        // Should NOT be rejected for timestamp - will be rejected for invalid solution instead
        match result.result {
            ShareResult::Rejected(RejectReason::Other(_)) => {
                panic!("Valid timestamp should not trigger timestamp rejection");
            }
            _ => {} // Any other result (accepted or rejected for solution) is fine
        }
    }

    /// Helper to create a Channel with a given nonce_1 for tests
    fn make_test_channel(nonce_1: Vec<u8>) -> Channel {
        use zcash_equihash_validator::VardiffConfig;
        Channel::new_with_id(1, nonce_1, VardiffConfig::default()).unwrap()
    }

    /// Helper to create a NewEquihashJob for tests
    fn make_test_job(job_id: u32, nonce_1: &[u8], nonce_2_len: u8, time: u32) -> NewEquihashJob {
        NewEquihashJob {
            channel_id: 1,
            job_id,
            future_job: false,
            version: 5,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            block_commitments: [0; 32],
            nonce_1: nonce_1.to_vec(),
            nonce_2_len,
            time,
            bits: 0x2007ffff,
            target: [0xff; 32],
            clean_jobs: false,
        }
    }

    #[test]
    fn test_validate_share_unknown_job() {
        use crate::duplicate::InMemoryDuplicateDetector;

        let mut channel = make_test_channel(vec![0; 4]);
        let job = make_test_job(1, &channel.nonce_1, channel.nonce_2_len, 1_700_000_000);
        channel.add_job(job, false);

        let processor = ShareProcessor::new();
        let detector = InMemoryDuplicateDetector::new();
        let block_target = [0xff; 32];

        let share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 999,
            nonce_2: vec![0; 28],
            time: 1_700_000_000,
            solution: [0; 1344],
        };

        let result = processor.validate_share(&share, &channel, &detector, &block_target);
        assert!(result.is_err());
        match result.unwrap_err() {
            PoolError::UnknownJob(id) => assert_eq!(id, 999),
            other => panic!("Expected UnknownJob(999), got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_share_stale_job() {
        use crate::duplicate::InMemoryDuplicateDetector;

        let mut channel = make_test_channel(vec![0; 4]);
        let job1 = make_test_job(1, &channel.nonce_1, channel.nonce_2_len, 1_700_000_000);
        channel.add_job(job1, false);

        let job2 = make_test_job(2, &channel.nonce_1, channel.nonce_2_len, 1_700_000_000);
        channel.add_job(job2, true); // clean_jobs=true marks job 1 stale

        let processor = ShareProcessor::new();
        let detector = InMemoryDuplicateDetector::new();
        let block_target = [0xff; 32];

        let share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: 1_700_000_000,
            solution: [0; 1344],
        };

        let result = processor.validate_share(&share, &channel, &detector, &block_target).unwrap();
        assert!(!result.accepted);
        assert!(
            matches!(result.result, ShareResult::Rejected(RejectReason::StaleJob)),
            "Expected StaleJob rejection, got: {:?}",
            result.result
        );
    }

    #[test]
    fn test_validate_share_wrong_nonce2_length() {
        use crate::duplicate::InMemoryDuplicateDetector;

        let mut channel = make_test_channel(vec![0; 4]); // nonce_2_len = 28
        let job = make_test_job(1, &channel.nonce_1, channel.nonce_2_len, 1_700_000_000);
        channel.add_job(job, false);

        let processor = ShareProcessor::new();
        let detector = InMemoryDuplicateDetector::new();
        let block_target = [0xff; 32];

        let share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce_2: vec![0; 10], // Wrong length: 10 instead of 28
            time: 1_700_000_000,
            solution: [0; 1344],
        };

        let result = processor.validate_share(&share, &channel, &detector, &block_target);
        assert!(result.is_err());
        match result.unwrap_err() {
            PoolError::InvalidMessage(msg) => {
                assert!(msg.contains("nonce"), "Error message should mention nonce: {}", msg);
            }
            other => panic!("Expected InvalidMessage, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_share_duplicate_via_channel() {
        use crate::duplicate::InMemoryDuplicateDetector;

        let mut channel = make_test_channel(vec![0; 4]);
        let job = make_test_job(1, &channel.nonce_1, channel.nonce_2_len, 1_700_000_000);
        channel.add_job(job, false);

        let processor = ShareProcessor::new();
        let detector = InMemoryDuplicateDetector::new();
        let block_target = [0xff; 32];

        let share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: 1_700_000_000,
            solution: [0; 1344],
        };

        // First submission -- will get InvalidSolution (dummy solution), but not Duplicate
        let result1 = processor.validate_share(&share, &channel, &detector, &block_target).unwrap();
        assert!(
            !matches!(result1.result, ShareResult::Rejected(RejectReason::Duplicate)),
            "First submission should not be duplicate, got: {:?}",
            result1.result
        );

        // Second submission of exact same share -- should get Duplicate
        let result2 = processor.validate_share(&share, &channel, &detector, &block_target).unwrap();
        assert!(
            matches!(result2.result, ShareResult::Rejected(RejectReason::Duplicate)),
            "Second submission should be duplicate, got: {:?}",
            result2.result
        );
    }

    /// Prove that a real Equihash solution (Zcash mainnet genesis block)
    /// passes through the full ShareProcessor::validate_share_with_job() pipeline.
    ///
    /// This is critical: build_header() and build_nonce() must reconstruct the
    /// exact 140-byte header that was originally solved. If even one byte is wrong,
    /// every share gets rejected in production despite the validator working in isolation.
    #[test]
    fn test_real_equihash_solution_full_pipeline() {
        use crate::duplicate::InMemoryDuplicateDetector;

        // --- Genesis block header fields ---
        // Full header hex (140 bytes):
        // 04000000
        // 0000000000000000000000000000000000000000000000000000000000000000
        // db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4
        // 0000000000000000000000000000000000000000000000000000000000000000
        // 90041358
        // ffff071f
        // 5712000000000000000000000000000000000000000000000000000000000000

        let version: u32 = 4;

        let prev_hash = [0u8; 32]; // all zeros for genesis

        let merkle_root: [u8; 32] = hex::decode(
            "db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let block_commitments = [0u8; 32]; // all zeros for genesis

        let time: u32 = 0x58130490; // 1477641360

        let bits: u32 = 0x1f07ffff;

        // Full 32-byte nonce from genesis header bytes [108..140]
        let nonce_bytes: [u8; 32] = hex::decode(
            "5712000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap()
        .try_into()
        .unwrap();

        // Split nonce into nonce_1 (pool prefix, 4 bytes) + nonce_2 (miner suffix, 28 bytes)
        let nonce_1 = nonce_bytes[..4].to_vec();
        let nonce_2 = nonce_bytes[4..].to_vec();

        // --- Build the job matching genesis block fields ---
        let job = NewEquihashJob {
            channel_id: 1,
            job_id: 42,
            future_job: false,
            version,
            prev_hash,
            merkle_root,
            block_commitments,
            nonce_1: nonce_1.clone(),
            nonce_2_len: 28,
            time,
            bits,
            target: [0xff; 32], // easy share target -- accept any valid solution
            clean_jobs: false,
        };

        // Verify nonce reconstruction produces the original nonce
        let reconstructed = job.build_nonce(&nonce_2).expect("nonce_2 length must match");
        assert_eq!(reconstructed, nonce_bytes, "build_nonce must reconstruct original nonce");

        // Verify header reconstruction produces the original 140-byte genesis header
        let expected_header = hex::decode(
            "04000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4\
             0000000000000000000000000000000000000000000000000000000000000000\
             90041358\
             ffff071f\
             5712000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let built_header = job.build_header(&reconstructed);
        assert_eq!(
            built_header.as_slice(),
            expected_header.as_slice(),
            "build_header must produce exact genesis header"
        );

        // --- Genesis block solution (1344 bytes) ---
        let solution_vec = hex::decode(
            "000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4\
             686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed0\
             45fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf605\
             8343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072\
             a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398b\
             ca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1\
             c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a57\
             0215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098\
             f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05\
             eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc54228\
             16655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1\
             a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397\
             fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec10\
             9d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50\
             cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7b\
             b8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567a\
             ffff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719ba\
             c64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb\
             66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b\
             3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073\
             e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0\
             530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07f\
             a0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c\
             8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5\
             d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec\
             5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a59\
             9c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec0\
             6ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63f\
             ef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9f\
             cc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b660\
             2b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd8\
             61b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc0\
             9b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1a\
             ec01c4a68e41ce157",
        )
        .unwrap();
        let solution: [u8; 1344] = solution_vec.try_into().expect("solution must be 1344 bytes");

        // --- Build the share ---
        let share = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 42,
            nonce_2,
            time, // same as job time (genesis timestamp)
            solution,
        };

        // --- Run through full ShareProcessor pipeline ---
        let processor = ShareProcessor::new();
        let detector = InMemoryDuplicateDetector::new();
        let block_target = [0xff; 32]; // easy block target

        let result = processor
            .validate_share_with_job(&share, &job, &detector, &block_target)
            .expect("validate_share_with_job must not return Err");

        assert!(
            result.accepted,
            "Real genesis block solution must be accepted, got: {:?}",
            result.result
        );
        assert!(
            result.is_block,
            "Genesis solution must meet easy block target"
        );
        assert!(
            result.difficulty.is_some(),
            "Accepted share must have a difficulty value"
        );
        assert!(
            result.difficulty.unwrap() > 0.0,
            "Share difficulty must be positive"
        );
        assert_eq!(
            result.result,
            ShareResult::Accepted,
            "Result must be ShareResult::Accepted"
        );
    }

    #[test]
    fn test_timestamp_boundary_acceptance() {
        use crate::duplicate::InMemoryDuplicateDetector;

        let mut channel = make_test_channel(vec![0; 4]);
        let job_time: u32 = 1_700_000_000;
        let job = make_test_job(1, &channel.nonce_1, channel.nonce_2_len, job_time);
        channel.add_job(job, false);

        let processor = ShareProcessor::new();
        let block_target = [0xff; 32];

        // Share at exactly job_time - 60 (boundary, should NOT be rejected for timestamp)
        let detector1 = InMemoryDuplicateDetector::new();
        let share_at_lower_bound = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: job_time - 60,
            solution: [0; 1344],
        };
        let result = processor.validate_share(&share_at_lower_bound, &channel, &detector1, &block_target).unwrap();
        match result.result {
            ShareResult::Rejected(RejectReason::Other(ref msg)) if msg.contains("timestamp") => {
                panic!("time=job_time-60 should be accepted by timestamp check, got: {:?}", result.result);
            }
            _ => {} // InvalidSolution or anything else is fine
        }

        // Share at exactly job_time + 7200 (boundary, should NOT be rejected for timestamp)
        let detector2 = InMemoryDuplicateDetector::new();
        let share_at_upper_bound = SubmitEquihashShare {
            channel_id: 1,
            sequence_number: 2,
            job_id: 1,
            nonce_2: vec![1; 28], // Different nonce to avoid duplicate
            time: job_time + 7200,
            solution: [0; 1344],
        };
        let result = processor.validate_share(&share_at_upper_bound, &channel, &detector2, &block_target).unwrap();
        match result.result {
            ShareResult::Rejected(RejectReason::Other(ref msg)) if msg.contains("timestamp") => {
                panic!("time=job_time+7200 should be accepted by timestamp check, got: {:?}", result.result);
            }
            _ => {} // InvalidSolution or anything else is fine
        }
    }
}
