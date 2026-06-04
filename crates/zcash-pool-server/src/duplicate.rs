//! Duplicate share detection
//!
//! Uses a trait to allow swapping implementations (in-memory, Redis, etc.)

use rustc_hash::FxHashSet;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use tracing::warn;

/// Maximum shares per job to prevent memory exhaustion
/// At 1344 bytes per solution hash (reduced to u64), 100k shares ~= 800KB per job
const MAX_SHARES_PER_JOB: usize = 100_000;

/// Trait for duplicate share detection
pub trait DuplicateDetector: Send + Sync {
    /// Start a new job epoch.
    ///
    /// This clears stale entries for a reused job ID before shares for the new
    /// epoch are recorded.
    fn start_job(&self, job_id: u32);

    /// Check if a share is a duplicate (and record it if not)
    /// Returns true if it IS a duplicate, false if it's new
    fn check_and_record(&self, job_id: u32, nonce_2: &[u8], solution: &[u8]) -> bool;

    /// Clear all shares for a job (called when job expires)
    fn clear_job(&self, job_id: u32);

    /// Clear all jobs (called on new block)
    fn clear_all(&self);

    /// Remove entries for jobs not in the active set.
    /// Prevents unbounded memory growth without the race condition of clear_all().
    fn prune_inactive(&self, active_job_ids: &HashSet<u32>);
}

/// Result of duplicate check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateCheckResult {
    /// Share is new (not a duplicate)
    New,
    /// Share is a duplicate
    Duplicate,
    /// Job is at capacity, treating as duplicate to prevent memory exhaustion
    AtCapacity,
}

/// In-memory duplicate detector using hash sets
pub struct InMemoryDuplicateDetector {
    /// Map of job_id -> set of share hashes
    jobs: RwLock<HashMap<u32, FxHashSet<u64>>>,
}

impl InMemoryDuplicateDetector {
    pub fn new() -> Self {
        Self {
            jobs: RwLock::new(HashMap::new()),
        }
    }

    /// Compute a collision-resistant hash of the share data using SipHash.
    ///
    /// SipHash (Rust's default hasher) provides collision resistance unlike
    /// FxHasher, preventing attackers from crafting shares that hash-collide.
    fn hash_share(nonce_2: &[u8], solution: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        nonce_2.hash(&mut hasher);
        solution.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for InMemoryDuplicateDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DuplicateDetector for InMemoryDuplicateDetector {
    fn start_job(&self, job_id: u32) {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| {
            warn!("Duplicate detector lock was poisoned in start_job, recovering");
            e.into_inner()
        });
        jobs.remove(&job_id);
    }

    fn check_and_record(&self, job_id: u32, nonce_2: &[u8], solution: &[u8]) -> bool {
        let hash = Self::hash_share(nonce_2, solution);

        // Handle poisoned lock gracefully - continue operating even if another thread panicked
        let mut jobs = self.jobs.write().unwrap_or_else(|e| {
            warn!("Duplicate detector lock was poisoned, recovering with potentially stale state");
            e.into_inner()
        });
        let shares = jobs.entry(job_id).or_default();

        // Check if already at capacity - reject to prevent memory exhaustion
        if shares.len() >= MAX_SHARES_PER_JOB {
            if !shares.contains(&hash) {
                warn!(
                    "Job {} hit share limit ({}), rejecting new shares",
                    job_id, MAX_SHARES_PER_JOB
                );
            }
            // Return true (duplicate) if not found, or true if actually duplicate
            // Either way, we don't add more shares
            return true;
        }

        // insert returns true if the value was NOT present
        // So we return the opposite: true if it IS a duplicate
        !shares.insert(hash)
    }

    fn clear_job(&self, job_id: u32) {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| {
            warn!("Duplicate detector lock was poisoned in clear_job, recovering");
            e.into_inner()
        });
        jobs.remove(&job_id);
    }

    fn clear_all(&self) {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| {
            warn!("Duplicate detector lock was poisoned in clear_all, recovering");
            e.into_inner()
        });
        jobs.clear();
    }

    fn prune_inactive(&self, active_job_ids: &HashSet<u32>) {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| {
            warn!("Duplicate detector lock was poisoned in prune_inactive, recovering");
            e.into_inner()
        });
        jobs.retain(|job_id, _| active_job_ids.contains(job_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_detection() {
        let detector = InMemoryDuplicateDetector::new();

        let nonce_2 = vec![0x01, 0x02, 0x03];
        let solution = vec![0xaa; 1344];

        // First submission - not a duplicate
        assert!(!detector.check_and_record(1, &nonce_2, &solution));

        // Same submission - is a duplicate
        assert!(detector.check_and_record(1, &nonce_2, &solution));

        // Different nonce_2 - not a duplicate
        let nonce_2_b = vec![0x04, 0x05, 0x06];
        assert!(!detector.check_and_record(1, &nonce_2_b, &solution));

        // Different job - not a duplicate
        assert!(!detector.check_and_record(2, &nonce_2, &solution));
    }

    #[test]
    fn test_clear_job() {
        let detector = InMemoryDuplicateDetector::new();

        let nonce_2 = vec![0x01, 0x02, 0x03];
        let solution = vec![0xaa; 1344];

        detector.check_and_record(1, &nonce_2, &solution);
        assert!(detector.check_and_record(1, &nonce_2, &solution)); // duplicate

        detector.clear_job(1);

        // After clear, same share is not a duplicate
        assert!(!detector.check_and_record(1, &nonce_2, &solution));
    }

    #[test]
    fn test_clear_all() {
        let detector = InMemoryDuplicateDetector::new();

        let nonce_2 = vec![0x01, 0x02, 0x03];
        let solution = vec![0xaa; 1344];

        detector.check_and_record(1, &nonce_2, &solution);
        detector.check_and_record(2, &nonce_2, &solution);

        detector.clear_all();

        // After clear_all, both are not duplicates
        assert!(!detector.check_and_record(1, &nonce_2, &solution));
        assert!(!detector.check_and_record(2, &nonce_2, &solution));
    }

    #[test]
    fn test_prune_inactive() {
        let detector = InMemoryDuplicateDetector::new();

        let nonce_2 = vec![0x01, 0x02, 0x03];
        let solution = vec![0xaa; 1344];

        detector.check_and_record(1, &nonce_2, &solution);
        detector.check_and_record(2, &nonce_2, &solution);
        detector.check_and_record(3, &nonce_2, &solution);

        // Only keep jobs 2 and 3 as active
        let active: HashSet<u32> = [2, 3].into_iter().collect();
        detector.prune_inactive(&active);

        // Job 1 was pruned, so same share is not a duplicate
        assert!(!detector.check_and_record(1, &nonce_2, &solution));

        // Jobs 2 and 3 still have their state, so same shares are duplicates
        assert!(detector.check_and_record(2, &nonce_2, &solution));
        assert!(detector.check_and_record(3, &nonce_2, &solution));
    }

    #[test]
    fn test_start_job_clears_stale_duplicate_state_for_reused_id() {
        let detector = InMemoryDuplicateDetector::new();

        let nonce_2 = vec![0x01, 0x02, 0x03];
        let solution = vec![0xaa; 1344];

        assert!(!detector.check_and_record(1, &nonce_2, &solution));
        assert!(detector.check_and_record(1, &nonce_2, &solution));

        detector.start_job(1);

        assert!(!detector.check_and_record(1, &nonce_2, &solution));
    }
}
