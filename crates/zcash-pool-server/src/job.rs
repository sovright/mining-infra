//! Job creation and distribution
//!
//! Converts templates from Phase 1 into jobs for miners.

use crate::channel::Channel;
use std::sync::atomic::{AtomicU32, Ordering};
use zcash_mining_protocol::messages::NewEquihashJob;
use zcash_template_provider::types::BlockTemplate;

/// Global job ID counter (unique across all channels)
/// Starts at 1, wraps at u32::MAX - 1 to avoid 0 (reserved for errors)
static NEXT_GLOBAL_JOB_ID: AtomicU32 = AtomicU32::new(1);

/// Maximum job ID before wrapping (reserve 0 and u32::MAX)
const MAX_JOB_ID: u32 = u32::MAX - 1;

/// Get the next global job ID with safe wraparound
fn next_job_id() -> u32 {
    loop {
        let current = NEXT_GLOBAL_JOB_ID.load(Ordering::SeqCst);
        let next = if current >= MAX_JOB_ID {
            // Wrap around to 1 (0 is reserved)
            1
        } else {
            current + 1
        };

        // Try to atomically update; if another thread beat us, retry
        if NEXT_GLOBAL_JOB_ID
            .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return current;
        }
        // Another thread updated it, retry
    }
}

/// Job distributor - creates jobs from templates
pub struct JobDistributor {
    /// Current template
    current_template: Option<BlockTemplate>,
    /// Previous block hash (to detect new blocks)
    prev_hash: Option<[u8; 32]>,
}

impl JobDistributor {
    pub fn new() -> Self {
        Self {
            current_template: None,
            prev_hash: None,
        }
    }

    /// Update the current template
    /// Returns true if this is a new block (clean_jobs should be set)
    pub fn update_template(&mut self, template: BlockTemplate) -> bool {
        let is_new_block = self.prev_hash.as_ref() != Some(&template.header.prev_hash.0);

        self.prev_hash = Some(template.header.prev_hash.0);
        self.current_template = Some(template);

        is_new_block
    }

    /// Create a job for a specific channel
    pub fn create_job(&self, channel: &Channel, clean_jobs: bool) -> Option<NewEquihashJob> {
        let template = self.current_template.as_ref()?;

        Some(NewEquihashJob {
            channel_id: channel.id,
            job_id: next_job_id(),
            future_job: false,
            version: template.header.version,
            prev_hash: template.header.prev_hash.0,
            merkle_root: template.header.merkle_root.0,
            block_commitments: template.header.hash_block_commitments.0,
            nonce_1: channel.nonce_1.clone(),
            nonce_2_len: channel.nonce_2_len,
            time: template.header.time,
            bits: template.header.bits,
            target: channel.current_target(),
            clean_jobs,
        })
    }

    /// Get current template height
    pub fn current_height(&self) -> Option<u64> {
        self.current_template.as_ref().map(|t| t.height)
    }

    /// Check if we have a template
    pub fn has_template(&self) -> bool {
        self.current_template.is_some()
    }

    /// Get a clone of the current template
    pub fn current_template(&self) -> Option<BlockTemplate> {
        self.current_template.clone()
    }
}

impl Default for JobDistributor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_equihash_validator::VardiffConfig;
    use zcash_template_provider::types::{EquihashHeader, Hash256};

    fn make_template(height: u64, prev_hash: [u8; 32]) -> BlockTemplate {
        BlockTemplate {
            template_id: 1,
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

    #[test]
    fn test_new_block_detection() {
        let mut distributor = JobDistributor::new();

        let template1 = make_template(100, [0x11; 32]);
        assert!(distributor.update_template(template1)); // First template

        let template2 = make_template(100, [0x11; 32]);
        assert!(!distributor.update_template(template2)); // Same block

        let template3 = make_template(101, [0x22; 32]);
        assert!(distributor.update_template(template3)); // New block
    }

    #[test]
    fn test_create_job() {
        let mut distributor = JobDistributor::new();
        let template = make_template(100, [0x11; 32]);
        distributor.update_template(template);

        let channel = Channel::new(vec![0x01, 0x02, 0x03, 0x04], VardiffConfig::default()).unwrap();
        let job = distributor.create_job(&channel, false).unwrap();

        assert_eq!(job.channel_id, channel.id);
        assert_eq!(job.nonce_1, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(job.nonce_2_len, 28);
        assert!(!job.clean_jobs);
    }
}
