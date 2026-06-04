//! Standard Channel state management
//!
//! Each miner connection gets one channel with a unique nonce_1 prefix.

use crate::ratelimit::RateLimiter;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;
use zcash_equihash_validator::{VardiffConfig, VardiffController};
use zcash_mining_protocol::messages::NewEquihashJob;

/// Global channel ID counter
/// Starts at 1, wraps at u32::MAX - 1 to avoid 0 (reserved for errors)
static NEXT_CHANNEL_ID: AtomicU32 = AtomicU32::new(1);

/// Maximum channel ID before wrapping (reserve 0 and u32::MAX)
const MAX_CHANNEL_ID: u32 = u32::MAX - 1;

/// Standard Channel state for a single miner
#[derive(Debug)]
pub struct Channel {
    /// Unique channel identifier
    pub id: u32,
    /// Pool-assigned nonce prefix
    pub nonce_1: Vec<u8>,
    /// Length of miner's nonce_2
    pub nonce_2_len: u8,
    /// Per-channel vardiff controller
    pub vardiff: VardiffController,
    /// Active jobs for this channel (job_id -> job)
    pub jobs: HashMap<u32, ChannelJob>,
    /// Last job ID sent
    pub last_job_id: u32,
    /// Rate limiter for share submissions
    pub rate_limiter: RateLimiter,
}

/// Default job TTL (10 minutes)
const DEFAULT_JOB_TTL: Duration = Duration::from_secs(600);

/// A job as seen by a specific channel
#[derive(Debug, Clone)]
pub struct ChannelJob {
    /// Job ID (channel-specific)
    pub job_id: u32,
    /// The full job message sent to miner
    pub job: NewEquihashJob,
    /// Whether this job is still valid
    pub active: bool,
    /// When this job was created
    pub created_at: Instant,
}

impl Channel {
    /// Reserve and return the next channel id.
    ///
    /// Used to generate nonce_1 that matches the channel's id.
    /// Handles wraparound safely by resetting to 1 when approaching MAX.
    pub fn next_id() -> u32 {
        loop {
            let current = NEXT_CHANNEL_ID.load(Ordering::SeqCst);
            let next = if current >= MAX_CHANNEL_ID {
                // Wrap around to 1 (0 is reserved)
                1
            } else {
                current + 1
            };

            // Try to atomically update; if another thread beat us, retry
            if NEXT_CHANNEL_ID
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return current;
            }
            // Another thread updated it, retry
        }
    }

    /// Create a new channel with a pre-reserved id and nonce_1 prefix.
    ///
    /// Returns `None` if nonce_1 length exceeds 32 bytes.
    pub fn new_with_id(id: u32, nonce_1: Vec<u8>, vardiff_config: VardiffConfig) -> Option<Self> {
        if nonce_1.len() > 32 {
            warn!(
                "Attempted to create channel with invalid nonce_1 length: {}",
                nonce_1.len()
            );
            return None;
        }
        let nonce_2_len = 32 - nonce_1.len() as u8;
        Some(Self {
            id,
            nonce_1,
            nonce_2_len,
            vardiff: VardiffController::new(vardiff_config),
            jobs: HashMap::with_capacity(10),
            last_job_id: 0,
            rate_limiter: RateLimiter::for_shares(),
        })
    }

    /// Create a new channel with the given nonce_1 prefix.
    ///
    /// Returns `None` if nonce_1 length exceeds 32 bytes.
    pub fn new(nonce_1: Vec<u8>, vardiff_config: VardiffConfig) -> Option<Self> {
        let id = Self::next_id();
        Self::new_with_id(id, nonce_1, vardiff_config)
    }

    /// Generate a unique nonce_1 for a channel based on channel ID
    ///
    /// Returns `None` if len exceeds 32 bytes.
    pub fn generate_nonce_1(channel_id: u32, len: u8) -> Option<Vec<u8>> {
        if len > 32 {
            return None;
        }
        let mut nonce_1 = vec![0u8; len as usize];
        let id_bytes = channel_id.to_le_bytes();
        let copy_len = (len as usize).min(4);
        nonce_1[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
        Some(nonce_1)
    }

    /// Add a job to this channel
    pub fn add_job(&mut self, job: NewEquihashJob, clean_jobs: bool) {
        if clean_jobs {
            // Mark all existing jobs as inactive
            for j in self.jobs.values_mut() {
                j.active = false;
            }
        }

        let job_id = job.job_id;
        self.last_job_id = self.last_job_id.max(job_id);
        let channel_job = ChannelJob {
            job_id,
            job,
            active: true,
            created_at: Instant::now(),
        };
        self.jobs.insert(job_id, channel_job);

        // Keep only last 10 jobs to bound memory.
        // Evict by creation time (oldest first) rather than by job ID arithmetic,
        // because job IDs wrap around at u32::MAX and ID-based eviction would
        // keep stale high-ID jobs while discarding valid low-ID jobs after wrap.
        while self.jobs.len() > 10 {
            let oldest_id = self
                .jobs
                .iter()
                .min_by_key(|(_, j)| j.created_at)
                .map(|(&id, _)| id);
            match oldest_id {
                Some(id) => {
                    self.jobs.remove(&id);
                }
                None => break,
            }
        }
    }

    /// Get a job by ID
    pub fn get_job(&self, job_id: u32) -> Option<&ChannelJob> {
        self.jobs.get(&job_id)
    }

    /// Check if a job is active (not stale and not expired)
    pub fn is_job_active(&self, job_id: u32) -> bool {
        self.jobs
            .get(&job_id)
            .map(|j| j.active && j.created_at.elapsed() < DEFAULT_JOB_TTL)
            .unwrap_or(false)
    }

    /// Return IDs of all tracked jobs (active and inactive).
    ///
    /// Includes inactive jobs because their duplicate-detection entries must be
    /// retained while in-flight shares could still reference them.  If only
    /// active IDs were returned, `prune_inactive` would drop dup entries for
    /// recently-deactivated jobs, re-opening the race condition modeled by the
    /// Quint DuplicateRace module.
    pub fn tracked_job_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.jobs.keys().copied()
    }

    /// Check if a job is active with a custom TTL
    pub fn is_job_active_with_ttl(&self, job_id: u32, ttl: Duration) -> bool {
        self.jobs
            .get(&job_id)
            .map(|j| j.active && j.created_at.elapsed() < ttl)
            .unwrap_or(false)
    }

    /// Get current target from vardiff
    pub fn current_target(&self) -> [u8; 32] {
        self.vardiff.current_target().to_le_bytes()
    }

    /// Record a share and check for vardiff adjustment
    pub fn record_share(&mut self) -> Option<f64> {
        self.vardiff.record_share();
        self.vardiff.maybe_retarget()
    }

    /// Check if a share submission is allowed by rate limiter
    ///
    /// Returns true if allowed, false if rate limited
    pub fn check_rate_limit(&mut self) -> bool {
        self.rate_limiter.check().is_allowed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_creation() {
        let nonce_1 = vec![0x01, 0x02, 0x03, 0x04];
        let channel = Channel::new(nonce_1.clone(), VardiffConfig::default()).unwrap();

        assert_eq!(channel.nonce_1, nonce_1);
        assert_eq!(channel.nonce_2_len, 28);
    }

    #[test]
    fn test_channel_creation_invalid_nonce() {
        // nonce_1 longer than 32 bytes should fail
        let nonce_1 = vec![0x01; 33];
        assert!(Channel::new(nonce_1, VardiffConfig::default()).is_none());
    }

    #[test]
    fn test_nonce_1_generation() {
        let nonce_1 = Channel::generate_nonce_1(0x12345678, 4).unwrap();
        assert_eq!(nonce_1, vec![0x78, 0x56, 0x34, 0x12]);

        let nonce_1_short = Channel::generate_nonce_1(0x12345678, 2).unwrap();
        assert_eq!(nonce_1_short, vec![0x78, 0x56]);
    }

    #[test]
    fn test_nonce_1_generation_invalid_len() {
        // len > 32 should fail
        assert!(Channel::generate_nonce_1(0x12345678, 33).is_none());
    }

    #[test]
    fn test_job_management() {
        let mut channel = Channel::new(vec![0; 4], VardiffConfig::default()).unwrap();

        let job1 = NewEquihashJob {
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

        channel.add_job(job1.clone(), false);
        assert!(channel.is_job_active(1));

        let job2 = NewEquihashJob {
            job_id: 2,
            ..job1.clone()
        };

        channel.add_job(job2, true); // clean_jobs
        assert!(!channel.is_job_active(1)); // Old job now inactive
        assert!(channel.is_job_active(2)); // New job active
    }

    #[test]
    fn test_job_eviction_after_id_wraparound() {
        // Regression: old ID-based eviction used `last_job_id.saturating_sub(10)`
        // which fails after wraparound — high-ID stale jobs survive while new
        // low-ID jobs get evicted.
        let mut channel = Channel::new(vec![0; 4], VardiffConfig::default()).unwrap();

        let make_job = |id: u32, ch: &Channel| NewEquihashJob {
            channel_id: ch.id,
            job_id: id,
            future_job: false,
            version: 5,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            block_commitments: [0; 32],
            nonce_1: ch.nonce_1.clone(),
            nonce_2_len: ch.nonce_2_len,
            time: 0,
            bits: 0,
            target: [0xff; 32],
            clean_jobs: false,
        };

        // Simulate pre-wraparound: add jobs with high IDs near u32::MAX
        for i in 0..8 {
            let id = u32::MAX - 10 + i;
            channel.add_job(make_job(id, &channel), false);
        }
        assert_eq!(channel.jobs.len(), 8);

        // Simulate post-wraparound: add jobs with low IDs (1, 2, 3, 4)
        for id in 1..=4 {
            channel.add_job(make_job(id, &channel), false);
        }

        // After 12 inserts total, eviction should have trimmed to 10.
        assert!(channel.jobs.len() <= 10);

        // The new low-ID jobs must survive — they are the most recent.
        for id in 1..=4 {
            assert!(
                channel.jobs.contains_key(&id),
                "Post-wraparound job {} was incorrectly evicted",
                id
            );
        }
    }
}
