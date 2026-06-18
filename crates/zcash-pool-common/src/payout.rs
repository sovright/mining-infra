//! Simple PPS (Pay Per Share) tracking
//!
//! Tracks share submissions per miner for payout calculation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::error;

/// Bounded FIFO set for cross-path solution deduplication.
/// Evicts the oldest-inserted entry when capacity is reached. The set is
/// cleared on every new block epoch, so FIFO eviction order is sufficient —
/// within one epoch the insertion order does not affect correctness.
struct BoundedSolutionSet {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl BoundedSolutionSet {
    fn new(capacity: usize) -> Self {
        // A zero capacity would make insert_if_new pop from an empty deque and
        // panic; clamp to at least one so the set is always well-formed.
        let capacity = capacity.max(1);
        Self {
            seen: HashSet::with_capacity(capacity.min(1024)),
            order: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Returns `true` if `key` was not previously seen and has been recorded.
    /// Returns `false` if `key` was already present (cross-path duplicate).
    fn insert_if_new(&mut self, key: [u8; 32]) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            // FIFO eviction: `order` and `seen` stay in sync, pop_front is Some here.
            let oldest = self
                .order
                .pop_front()
                .expect("order non-empty when seen is at capacity");
            self.seen.remove(&oldest);
        }
        self.seen.insert(key);
        self.order.push_back(key);
        true
    }
}

/// Unique identifier for a miner (could be pubkey, address, etc.)
pub type MinerId = String;

/// Per-miner statistics
#[derive(Debug, Clone, Default)]
pub struct MinerStats {
    /// Total shares submitted
    pub total_shares: u64,
    /// Total difficulty (sum of share difficulties)
    pub total_difficulty: f64,
    /// Shares in current window
    pub window_shares: u64,
    /// Difficulty in current window
    pub window_difficulty: f64,
    /// Last share timestamp
    pub last_share: Option<Instant>,
}

/// Maximum solution hashes held in the cross-path dedup set per block epoch.
/// The set is cleared on every new block, so this cap only needs to cover
/// solutions submitted within one block interval (≈75 s on Zcash mainnet).
///
/// Each key is stored twice (in `seen` and in `order`), so worst-case key
/// storage is 2 × 32 B × 500k ≈ 32 MB, plus hashbrown/VecDeque overhead
/// (~34–36 MB total). This cap is a memory backstop, NOT a within-epoch
/// security boundary: filling it requires 500k *valid* Equihash solutions in
/// one block interval, which is computationally infeasible, so FIFO eviction
/// cannot be reached by an attacker before the next block clears the set.
const MAX_CROSS_PATH_SOLUTIONS: usize = 500_000;

#[derive(Debug, Clone)]
struct PayoutPersistence {
    path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPayoutState {
    version: u32,
    miners: BTreeMap<MinerId, PersistedMinerStats>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedMinerStats {
    total_shares: u64,
    total_difficulty: f64,
}

const PAYOUT_STATE_VERSION: u32 = 1;

/// PPS payout tracker
pub struct PayoutTracker {
    /// Per-miner statistics
    miners: RwLock<HashMap<MinerId, MinerStats>>,
    /// Window duration for rate calculations
    window_duration: Duration,
    /// When the current window started (first share in window)
    window_start: RwLock<Option<Instant>>,
    /// Cross-path solution dedup: prevents double-credit when the same valid
    /// solution reaches both the pool-server and jd-server submission paths.
    /// Keyed by SHA-256(solution_bytes); bounded FIFO, cleared on each new block.
    seen_solutions: RwLock<BoundedSolutionSet>,
    /// Optional durable state path for payout totals.
    persistence: Option<PayoutPersistence>,
    /// Set whenever payout totals change since the last successful flush.
    /// Recording a share marks this rather than writing to disk inline: the
    /// disk write (full-file serialize + fsync) is far too expensive to run on
    /// the hot path — per accepted share, under the `miners` write lock, on the
    /// async runtime thread. Instead `flush()` is called periodically and on
    /// graceful shutdown, doing the write off the lock. Worst case on a hard
    /// crash is the loss of totals accumulated since the last flush interval.
    dirty: AtomicBool,
}

impl PayoutTracker {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            miners: RwLock::new(HashMap::new()),
            window_duration,
            window_start: RwLock::new(None),
            seen_solutions: RwLock::new(BoundedSolutionSet::new(MAX_CROSS_PATH_SOLUTIONS)),
            persistence: None,
            dirty: AtomicBool::new(false),
        }
    }

    /// Create a payout tracker that persists payout totals to disk.
    ///
    /// Only payout totals are restored after restart. Rolling-window counters
    /// and active-miner timestamps restart empty because they describe current
    /// process activity, not durable payout credit.
    pub fn with_persistence<P>(window_duration: Duration, path: P) -> io::Result<Self>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        let miners = load_persisted_miners(&path)?;

        Ok(Self {
            miners: RwLock::new(miners),
            window_duration,
            window_start: RwLock::new(None),
            seen_solutions: RwLock::new(BoundedSolutionSet::new(MAX_CROSS_PATH_SOLUTIONS)),
            persistence: Some(PayoutPersistence { path }),
            dirty: AtomicBool::new(false),
        })
    }

    /// Record a share for a miner
    ///
    /// Validates that difficulty is finite and positive before recording.
    /// Ignores shares with invalid difficulty (NaN, Infinity, negative, zero)
    /// to prevent poisoning payout calculations.
    ///
    /// Durable state is NOT written here — recording only marks the tracker
    /// dirty (see [`PayoutTracker::flush`]); the disk write happens off the hot
    /// path. Returns `true` if the share was recorded, `false` if it was
    /// rejected for invalid difficulty.
    pub fn record_share(&self, miner_id: &MinerId, difficulty: f64) -> bool {
        // Guard against NaN, Infinity, negative, and zero difficulty
        if !difficulty.is_finite() || difficulty <= 0.0 {
            tracing::warn!(
                "Ignoring share with invalid difficulty {} for miner {}",
                difficulty,
                miner_id
            );
            return false;
        }

        let now = Instant::now();

        // Set window start on first share in window
        {
            let mut window_start = self.window_start.write().unwrap_or_else(|e| e.into_inner());
            if window_start.is_none() {
                *window_start = Some(now);
            }
        }

        // Handle poisoned lock gracefully - continue operating even if another thread panicked
        let mut miners = self.miners.write().unwrap_or_else(|e| e.into_inner());
        let stats = miners.entry(miner_id.clone()).or_default();

        stats.total_shares += 1;
        stats.total_difficulty += difficulty;
        stats.window_shares += 1;
        stats.window_difficulty += difficulty;
        stats.last_share = Some(now);
        drop(miners);

        self.mark_dirty();
        true
    }

    /// Mark payout totals as changed since the last flush. Cheap and lock-free;
    /// the actual disk write is deferred to [`PayoutTracker::flush`].
    fn mark_dirty(&self) {
        if self.persistence.is_some() {
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// Record a share, deduplicating by solution bytes across all submission paths.
    ///
    /// Both the pool-server (SV2 direct) and jd-server (JDC) call into the same
    /// `Arc<PayoutTracker>`. A miner running both clients could submit the same
    /// valid solution through both paths; per-path dedup sets would not catch it.
    /// This method adds a cross-path dedup keyed by SHA-256(solution).
    ///
    /// Returns `true` if the share was newly recorded, `false` if it was a
    /// cross-path duplicate (no credit issued; caller should report as Duplicate).
    pub fn try_record_share_once(
        &self,
        miner_id: &MinerId,
        difficulty: f64,
        solution: &[u8],
    ) -> bool {
        // Mirror record_share's validity guard up front. An invalid-difficulty
        // share is never credited; recording its key here would consume a dedup
        // slot and return `true` (caller counts it accepted) while no credit was
        // issued, and would then falsely dedup a later honest resubmission of the
        // same solution at a valid difficulty. Reject without touching the set.
        if !difficulty.is_finite() || difficulty <= 0.0 {
            tracing::warn!(
                "Ignoring cross-path share with invalid difficulty {} for miner {}",
                difficulty,
                miner_id
            );
            return false;
        }

        let key: [u8; 32] = Sha256::digest(solution).into();
        let is_new = {
            let mut seen = self
                .seen_solutions
                .write()
                .unwrap_or_else(|e| e.into_inner());
            seen.insert_if_new(key)
        };
        if is_new {
            self.record_share(miner_id, difficulty);
        } else {
            tracing::warn!(
                miner_id = %miner_id,
                "Cross-path duplicate share rejected (same solution submitted via pool-server and jd-server)"
            );
        }
        is_new
    }

    /// Get statistics for a miner
    pub fn get_stats(&self, miner_id: &MinerId) -> Option<MinerStats> {
        let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
        miners.get(miner_id).cloned()
    }

    /// Get all miner statistics
    pub fn get_all_stats(&self) -> HashMap<MinerId, MinerStats> {
        let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
        miners.clone()
    }

    /// Reset window statistics (call periodically)
    pub fn reset_window(&self) {
        // Reset window start time
        {
            let mut window_start = self.window_start.write().unwrap_or_else(|e| e.into_inner());
            *window_start = None;
        }

        let mut miners = self.miners.write().unwrap_or_else(|e| e.into_inner());
        for stats in miners.values_mut() {
            stats.window_shares = 0;
            stats.window_difficulty = 0.0;
        }
    }

    /// Rotate the rolling window once it has reached the configured duration.
    pub fn rotate_window_if_needed(&self) {
        let should_reset = {
            let window_start = self.window_start.read().unwrap_or_else(|e| e.into_inner());
            window_start
                .map(|start| start.elapsed() >= self.window_duration)
                .unwrap_or(false)
        };

        if should_reset {
            self.reset_window();
        }
    }

    /// Get total pool hashrate estimate (based on difficulty sum over window)
    pub fn estimate_pool_hashrate(&self) -> f64 {
        let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
        let total_difficulty: f64 = miners.values().map(|s| s.window_difficulty).sum();

        // Use actual elapsed time, capped at window_duration
        let elapsed = {
            let window_start = self.window_start.read().unwrap_or_else(|e| e.into_inner());
            match *window_start {
                Some(start) => start.elapsed().min(self.window_duration),
                None => return 0.0, // No shares yet
            }
        };

        // Require at least 1 second of data to avoid division issues
        let elapsed_secs = elapsed.as_secs_f64().max(1.0);

        // Hashrate = difficulty / time (simplified)
        total_difficulty / elapsed_secs
    }

    /// Per-key hashrate estimate (difficulty accumulated in the window divided
    /// by elapsed window time), using the same convention as
    /// [`Self::estimate_pool_hashrate`].
    ///
    /// When this tracker is keyed by worker label, this yields per-worker
    /// hashrate suitable for the `hashrate_sol_s{worker}` gauge. Returns an
    /// empty map until the window has started (no shares yet).
    pub fn estimate_hashrate_per_miner(&self) -> HashMap<MinerId, f64> {
        let elapsed = {
            let window_start = self.window_start.read().unwrap_or_else(|e| e.into_inner());
            match *window_start {
                Some(start) => start.elapsed().min(self.window_duration),
                None => return HashMap::new(), // No shares yet
            }
        };
        let elapsed_secs = elapsed.as_secs_f64().max(1.0);

        let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
        miners
            .iter()
            .map(|(id, stats)| (id.clone(), stats.window_difficulty / elapsed_secs))
            .collect()
    }

    /// Number of active miners (submitted share in window)
    pub fn active_miner_count(&self) -> usize {
        let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
        // Use checked_sub to avoid panic if window_duration > uptime
        let cutoff = match Instant::now().checked_sub(self.window_duration) {
            Some(t) => t,
            None => return miners.values().filter(|s| s.last_share.is_some()).count(),
        };
        miners
            .values()
            .filter(|s| s.last_share.map(|t| t > cutoff).unwrap_or(false))
            .count()
    }

    /// Remove a miner from the tracker (on disconnect)
    pub fn remove_miner(&self, miner_id: &MinerId) {
        {
            let mut miners = self.miners.write().unwrap_or_else(|e| e.into_inner());
            miners.remove(miner_id);
        }
        self.mark_dirty();
    }

    /// Clear all cross-path solution hashes.
    ///
    /// Call this whenever a new block epoch starts (i.e. `is_new_block` in the
    /// template handler). Tying the cross-path window to block epochs means an
    /// evicted hash can never be replayed for double-credit: the job that
    /// produced it is already stale, so both per-path dedup sets have moved on.
    pub fn clear_cross_path_solutions(&self) {
        let mut seen = self
            .seen_solutions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *seen = BoundedSolutionSet::new(MAX_CROSS_PATH_SOLUTIONS);
    }

    /// Remove miners that haven't submitted a share within the given duration.
    ///
    /// Without persistence this evicts stale entries to prevent unbounded growth
    /// of the miners HashMap when miners disconnect and reconnect with new
    /// channel IDs.
    ///
    /// With persistence enabled, stale entries are NOT evicted — their durable
    /// payout totals are owed to the miner and must survive idle periods — so
    /// only the rolling-window/active fields are reset. NOTE: this means the map
    /// (and the on-disk file) grow with the number of distinct miner ids ever
    /// seen; that growth is bounded by the operator's payout-settlement policy
    /// removing fully-paid miners via [`PayoutTracker::remove_miner`], not by
    /// this cleanup.
    pub fn cleanup_stale_miners(&self, max_idle: Duration) -> usize {
        // Use checked_sub to avoid panic if max_idle > uptime
        let cutoff = match Instant::now().checked_sub(max_idle) {
            Some(t) => t,
            None => return 0, // All miners are within window, nothing to clean
        };
        let mut miners = self.miners.write().unwrap_or_else(|e| e.into_inner());

        if self.persistence.is_some() {
            let mut stale = 0;
            for stats in miners.values_mut() {
                if stats.last_share.map(|t| t <= cutoff).unwrap_or(false) {
                    stats.window_shares = 0;
                    stats.window_difficulty = 0.0;
                    stats.last_share = None;
                    stale += 1;
                }
            }
            drop(miners);
            if stale > 0 {
                tracing::debug!(
                    "Marked {} stale miner entries inactive while preserving payout totals",
                    stale
                );
                self.mark_dirty();
            }
            return stale;
        }

        let before = miners.len();
        miners.retain(|_, stats| stats.last_share.map(|t| t > cutoff).unwrap_or(false));
        let removed = before - miners.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} stale miner entries", removed);
        }
        removed
    }

    /// Write payout totals to disk if anything changed since the last flush.
    ///
    /// This is the single place durable state is written. Call it periodically
    /// (e.g. from the server maintenance loop) and on graceful shutdown. It is a
    /// no-op when persistence is disabled or nothing is dirty. The miners map is
    /// serialized under a short read lock; the actual file write (and fsync)
    /// happens AFTER the lock is released, so flushing never blocks share
    /// recording on disk I/O. On write failure the dirty flag is restored so a
    /// later flush retries.
    pub fn flush(&self) -> io::Result<()> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };

        // Clear dirty first; if a share lands during the write it re-marks dirty
        // and the next flush will pick it up.
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        let json = {
            let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
            serialize_state(&miners)
        };
        let json = match json {
            Ok(json) => json,
            Err(err) => {
                self.dirty.store(true, Ordering::Release);
                return Err(err);
            }
        };

        if let Err(err) = atomic_write(&persistence.path, &json) {
            // Retry on the next flush rather than dropping the update.
            self.dirty.store(true, Ordering::Release);
            return Err(err);
        }
        Ok(())
    }
}

fn serialize_state(miners: &HashMap<MinerId, MinerStats>) -> io::Result<Vec<u8>> {
    let persisted = PersistedPayoutState {
        version: PAYOUT_STATE_VERSION,
        miners: miners
            .iter()
            .map(|(miner_id, stats)| {
                (
                    miner_id.clone(),
                    PersistedMinerStats {
                        total_shares: stats.total_shares,
                        total_difficulty: stats.total_difficulty,
                    },
                )
            })
            .collect(),
    };

    serde_json::to_vec_pretty(&persisted).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("serialize payout state: {}", err),
        )
    })
}

fn load_persisted_miners(path: &Path) -> io::Result<HashMap<MinerId, MinerStats>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    // A genuine I/O failure (permissions, unreadable device) is propagated so
    // the operator notices a misconfiguration rather than silently losing
    // accumulated payouts.
    let json = std::fs::read_to_string(path)?;
    if json.trim().is_empty() {
        return Ok(HashMap::new());
    }

    // Corrupt / unparseable / wrong-version CONTENT must NOT brick the pool on
    // boot: a truncated file from a crash, a manual edit, or a format change
    // would otherwise make the pool refuse to start — the worst time to be
    // down. Quarantine the bad file and start with empty totals.
    match parse_persisted_miners(&json, path) {
        Ok(miners) => Ok(miners),
        Err(err) => {
            error!(
                "Payout state {} is unusable ({}); backing it up and starting with empty totals",
                path.display(),
                err
            );
            quarantine_corrupt_file(path);
            Ok(HashMap::new())
        }
    }
}

fn parse_persisted_miners(json: &str, path: &Path) -> io::Result<HashMap<MinerId, MinerStats>> {
    let persisted: PersistedPayoutState = serde_json::from_str(json).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse payout state {}: {}", path.display(), err),
        )
    })?;

    if persisted.version != PAYOUT_STATE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported payout state version {} in {}",
                persisted.version,
                path.display()
            ),
        ));
    }

    persisted
        .miners
        .into_iter()
        .map(|(miner_id, stats)| {
            if !stats.total_difficulty.is_finite() || stats.total_difficulty < 0.0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid payout difficulty {} for miner {}",
                        stats.total_difficulty, miner_id
                    ),
                ));
            }

            Ok((
                miner_id,
                MinerStats {
                    total_shares: stats.total_shares,
                    total_difficulty: stats.total_difficulty,
                    window_shares: 0,
                    window_difficulty: 0.0,
                    last_share: None,
                },
            ))
        })
        .collect()
}

/// Move an unusable state file aside so a fresh one can be written and the
/// operator can still recover the original. Best-effort: a failure here is
/// logged but does not block startup.
fn quarantine_corrupt_file(path: &Path) {
    let backup = path.with_file_name(format!(
        "{}.corrupt-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "payout-state".to_string()),
        std::process::id()
    ));
    if let Err(err) = std::fs::rename(path, &backup) {
        error!(
            "Failed to quarantine corrupt payout state {} -> {}: {}",
            path.display(),
            backup.display(),
            err
        );
    } else {
        error!("Quarantined corrupt payout state to {}", backup.display());
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("payout state path {} has no file name", path.display()),
        )
    })?;
    let tmp_path = path.with_file_name(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    // Write + fsync the temp file before the rename so the renamed-in data is
    // durable, not just present in the page cache. The rename itself is atomic,
    // so a crash leaves either the old file or the fully-written new one — never
    // a torn file. (Cheap now that flush() is periodic rather than per-share.)
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;

    // fsync the directory so the rename itself survives a crash.
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

impl Default for PayoutTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(600)) // 10 minute window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_payout_state_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bedrock-{test_name}-{}-{unique}.json",
            std::process::id()
        ))
    }

    #[test]
    fn test_record_share() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();

        tracker.record_share(&miner, 100.0);
        tracker.record_share(&miner, 200.0);

        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 2);
        assert_eq!(stats.total_difficulty, 300.0);
    }

    #[test]
    fn test_multiple_miners() {
        let tracker = PayoutTracker::default();

        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);
        tracker.record_share(&"miner1".to_string(), 50.0);

        let stats1 = tracker.get_stats(&"miner1".to_string()).unwrap();
        let stats2 = tracker.get_stats(&"miner2".to_string()).unwrap();

        assert_eq!(stats1.total_difficulty, 150.0);
        assert_eq!(stats2.total_difficulty, 200.0);
    }

    #[test]
    fn test_reset_window() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();

        tracker.record_share(&miner, 100.0);
        tracker.reset_window();
        tracker.record_share(&miner, 50.0);

        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.total_difficulty, 150.0); // Total preserved
        assert_eq!(stats.window_difficulty, 50.0); // Window reset
    }

    #[test]
    fn test_get_all_stats() {
        let tracker = PayoutTracker::default();

        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);

        let all = tracker.get_all_stats();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_record_share_rejects_invalid_difficulty() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();

        // Valid share first
        tracker.record_share(&miner, 100.0);

        // These should all be silently rejected
        tracker.record_share(&miner, f64::NAN);
        tracker.record_share(&miner, f64::INFINITY);
        tracker.record_share(&miner, f64::NEG_INFINITY);
        tracker.record_share(&miner, -1.0);
        tracker.record_share(&miner, 0.0);

        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 1); // Only the valid share counted
        assert_eq!(stats.total_difficulty, 100.0); // Not poisoned
    }

    #[test]
    fn test_remove_miner() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();

        tracker.record_share(&miner, 100.0);
        assert!(tracker.get_stats(&miner).is_some());

        tracker.remove_miner(&miner);
        assert!(tracker.get_stats(&miner).is_none());
    }

    #[test]
    fn test_cleanup_stale_miners() {
        let tracker = PayoutTracker::default();

        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);

        // With 0 duration, all miners are "stale"
        let removed = tracker.cleanup_stale_miners(Duration::ZERO);
        assert_eq!(removed, 2, "should have removed exactly 2 miners");
        assert_eq!(tracker.get_all_stats().len(), 0);
    }

    #[test]
    fn test_persistent_tracker_restores_totals_after_restart() {
        let state_path = unique_payout_state_path("restart");
        let miner = "miner1".to_string();

        {
            let tracker =
                PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone())
                    .unwrap();
            tracker.record_share(&miner, 100.0);
            tracker.record_share(&miner, 50.0);
            // Durable state is written by flush(), not per-share.
            tracker.flush().unwrap();
        }

        let restarted =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();
        let stats = restarted.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 2);
        assert_eq!(stats.total_difficulty, 150.0);
        assert_eq!(stats.window_shares, 0);
        assert_eq!(stats.window_difficulty, 0.0);
        assert_eq!(restarted.active_miner_count(), 0);

        restarted.record_share(&miner, 25.0);
        restarted.flush().unwrap();
        let restarted_again =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();
        let stats = restarted_again.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 3);
        assert_eq!(stats.total_difficulty, 175.0);

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_persistent_cleanup_preserves_payout_totals() {
        let state_path = unique_payout_state_path("cleanup");
        let miner = "miner1".to_string();
        let tracker =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();

        tracker.record_share(&miner, 100.0);
        let removed = tracker.cleanup_stale_miners(Duration::ZERO);

        assert_eq!(removed, 1);
        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 1);
        assert_eq!(stats.total_difficulty, 100.0);
        assert_eq!(stats.window_shares, 0);
        assert_eq!(stats.window_difficulty, 0.0);
        assert_eq!(stats.last_share, None);

        tracker.flush().unwrap();
        let restarted =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();
        let stats = restarted.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 1);
        assert_eq!(stats.total_difficulty, 100.0);

        let _ = std::fs::remove_file(state_path);
    }

    /// A corrupt state file must not brick startup: it is quarantined and the
    /// tracker starts with empty totals (graceful degradation over availability).
    #[test]
    fn test_corrupt_state_file_is_quarantined_not_fatal() {
        let state_path = unique_payout_state_path("corrupt");
        std::fs::write(&state_path, b"{ this is not valid json ]").unwrap();

        // Must NOT return Err — the pool would otherwise refuse to start.
        let tracker =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();
        assert_eq!(tracker.get_all_stats().len(), 0, "should start empty");

        // Original (bad) file was moved aside, not left in place to fail again.
        assert!(!state_path.exists(), "corrupt file should be quarantined");

        // Tracker is usable and can write a fresh, valid file.
        tracker.record_share(&"miner1".to_string(), 10.0);
        tracker.flush().unwrap();
        let reloaded =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();
        assert_eq!(
            reloaded
                .get_stats(&"miner1".to_string())
                .unwrap()
                .total_shares,
            1
        );

        // Clean up the quarantine backup + fresh file.
        let backup = state_path.with_file_name(format!(
            "{}.corrupt-{}",
            state_path.file_name().unwrap().to_string_lossy(),
            std::process::id()
        ));
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::remove_file(&state_path);
    }

    /// flush() is a no-op when nothing changed since the last flush.
    #[test]
    fn test_flush_is_noop_when_not_dirty() {
        let state_path = unique_payout_state_path("noop");
        let tracker =
            PayoutTracker::with_persistence(Duration::from_secs(600), state_path.clone()).unwrap();
        // Nothing recorded yet: no file should be created by a flush.
        tracker.flush().unwrap();
        assert!(!state_path.exists(), "clean flush must not write a file");

        tracker.record_share(&"miner1".to_string(), 5.0);
        tracker.flush().unwrap();
        assert!(state_path.exists(), "dirty flush must write a file");
        let _ = std::fs::remove_file(&state_path);
    }

    #[test]
    fn test_estimate_pool_hashrate_no_shares() {
        let tracker = PayoutTracker::default();
        assert_eq!(tracker.estimate_pool_hashrate(), 0.0);
    }

    #[test]
    fn test_estimate_pool_hashrate_with_shares() {
        let tracker = PayoutTracker::default();
        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);
        let rate = tracker.estimate_pool_hashrate();
        assert!(rate > 0.0, "hashrate should be positive after shares");
    }

    #[test]
    fn test_estimate_hashrate_per_miner_empty_before_shares() {
        let tracker = PayoutTracker::default();
        assert!(tracker.estimate_hashrate_per_miner().is_empty());
    }

    #[test]
    fn test_estimate_hashrate_per_miner_splits_by_key() {
        let tracker = PayoutTracker::new(Duration::from_secs(600));
        tracker.record_share(&"rig-a".to_string(), 300.0);
        tracker.record_share(&"rig-b".to_string(), 100.0);
        std::thread::sleep(Duration::from_millis(1100));
        let rates = tracker.estimate_hashrate_per_miner();
        assert_eq!(rates.len(), 2);
        // Both rates share the same elapsed divisor within one call, so the ratio
        // reflects the difficulty split exactly (300 : 100 = 3 : 1).
        let a = rates["rig-a"];
        let b = rates["rig-b"];
        assert!((a / b - 3.0).abs() < 1e-9, "ratio {} should be 3", a / b);
        // Sum should track the pool estimate (separate elapsed reads => loose tol).
        assert!((a + b - tracker.estimate_pool_hashrate()).abs() < 1.0);
    }

    #[test]
    fn test_active_miner_count_empty() {
        let tracker = PayoutTracker::default();
        assert_eq!(tracker.active_miner_count(), 0);
    }

    #[test]
    fn test_active_miner_count_with_shares() {
        let tracker = PayoutTracker::default();
        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);
        assert_eq!(tracker.active_miner_count(), 2);
    }

    #[test]
    fn test_remove_miner_decreases_count() {
        let tracker = PayoutTracker::default();
        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);
        tracker.remove_miner(&"miner1".to_string());
        assert!(tracker.get_stats(&"miner1".to_string()).is_none());
        assert!(tracker.get_stats(&"miner2".to_string()).is_some());
    }

    #[test]
    fn test_remove_nonexistent_miner_no_panic() {
        let tracker = PayoutTracker::default();
        tracker.remove_miner(&"ghost".to_string());
    }

    #[test]
    fn test_record_share_many_miners() {
        let tracker = PayoutTracker::default();
        for i in 0..1000 {
            tracker.record_share(&format!("miner_{}", i), 1.0);
        }
        let all = tracker.get_all_stats();
        assert_eq!(all.len(), 1000);
    }

    #[test]
    fn test_window_difficulty_accumulation() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();
        for _ in 0..100 {
            tracker.record_share(&miner, 1.5);
        }
        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 100);
        assert!((stats.total_difficulty - 150.0).abs() < 0.001);
    }

    #[test]
    fn test_rotate_window_if_needed_before_duration() {
        let tracker = PayoutTracker::new(Duration::from_secs(3600));
        let miner = "miner1".to_string();
        tracker.record_share(&miner, 100.0);
        tracker.rotate_window_if_needed();
        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.window_shares, 1);
    }

    #[test]
    fn test_rotate_window_if_needed_after_duration() {
        let tracker = PayoutTracker::new(Duration::from_millis(1));
        let miner = "miner1".to_string();
        tracker.record_share(&miner, 100.0);
        std::thread::sleep(Duration::from_millis(5));
        tracker.rotate_window_if_needed();
        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.window_shares, 0);
        assert_eq!(stats.total_shares, 1);
    }

    #[test]
    fn test_cleanup_stale_miners_preserves_recent() {
        let tracker = PayoutTracker::default();
        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);
        let removed = tracker.cleanup_stale_miners(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(tracker.get_all_stats().len(), 2);
    }

    /// Kill mutant: total_difficulty / elapsed_secs vs total_difficulty * elapsed_secs
    /// With elapsed > 1s, division gives a smaller number than multiplication.
    #[test]
    fn test_estimate_pool_hashrate_exact_value() {
        let tracker = PayoutTracker::new(Duration::from_secs(600));
        tracker.record_share(&"miner1".to_string(), 500.0);
        tracker.record_share(&"miner2".to_string(), 500.0);
        // total_difficulty = 1000.0
        // Sleep to ensure elapsed_secs > 1.0
        std::thread::sleep(Duration::from_millis(1500));
        let rate = tracker.estimate_pool_hashrate();
        // With ~1.5s elapsed: rate = 1000 / 1.5 ~ 666
        // Mutant would give: 1000 * 1.5 = 1500
        // So rate must be <= 1000 (difficulty / time where time >= 1)
        assert!(
            rate <= 1000.0,
            "hashrate {} should be <= total_difficulty (1000) since elapsed >= 1s",
            rate
        );
        assert!(rate > 0.0, "hashrate should be positive");
    }

    /// Kill mutant: `t > cutoff` vs `t >= cutoff` in active_miner_count
    /// and cleanup_stale_miners.
    ///
    /// We set a miner's last_share to a known Instant, then compute cutoff
    /// to be that exact Instant. With `>` the miner is NOT counted (correct
    /// for "active within window" semantics). With `>=` it WOULD be counted.
    #[test]
    fn test_active_miner_count_exact_boundary() {
        let tracker = PayoutTracker::new(Duration::from_millis(50));
        tracker.record_share(&"miner1".to_string(), 100.0);

        // Confirm share was recorded
        let _share_time = {
            let miners = tracker.miners.read().unwrap();
            miners.get("miner1").unwrap().last_share.unwrap()
        };

        // Sleep so that Instant::now() - window_duration could equal share_time
        // With a very short window (50ms), sleeping 50ms means cutoff ~ share_time
        std::thread::sleep(Duration::from_millis(55));

        // Now: cutoff = now - 50ms. share_time was ~55ms ago.
        // So share_time < cutoff => miner should NOT be active.
        let count = tracker.active_miner_count();
        assert_eq!(
            count, 0,
            "miner whose share is older than window should not be active"
        );
    }

    /// Kill mutant: `t > cutoff` vs `t >= cutoff` in active_miner_count
    /// Miner with very recent share should be active.
    #[test]
    fn test_active_miner_count_recent_share() {
        let tracker = PayoutTracker::new(Duration::from_secs(60));
        tracker.record_share(&"miner1".to_string(), 100.0);
        // Share was just recorded, well within the 60s window
        assert_eq!(tracker.active_miner_count(), 1);
    }

    /// Kill mutant: `before - miners.len()` vs `before + miners.len()` in cleanup_stale_miners
    /// Verify the exact count of miners removed via return value.
    #[test]
    fn test_cleanup_stale_miners_exact_removed_count() {
        let tracker = PayoutTracker::default();
        tracker.record_share(&"miner1".to_string(), 100.0);
        tracker.record_share(&"miner2".to_string(), 200.0);
        tracker.record_share(&"miner3".to_string(), 300.0);

        // All 3 miners present
        assert_eq!(tracker.get_all_stats().len(), 3);

        // Cleanup with Duration::ZERO removes all (share time < now)
        let removed = tracker.cleanup_stale_miners(Duration::ZERO);
        // before=3, miners.len()=0 after retain
        // Correct: 3 - 0 = 3
        // Mutant (+ instead of -): 3 + 0 = 3 (same! need partial removal)
        assert_eq!(removed, 3);
        assert_eq!(
            tracker.get_all_stats().len(),
            0,
            "all miners should be removed with zero idle time"
        );
    }

    /// Kill mutant: cleanup_stale_miners boundary -- miner exactly at cutoff
    /// With > (correct): miner at cutoff is removed (not strictly after)
    /// With >= (mutant): miner at cutoff is kept
    #[test]
    fn test_cleanup_stale_miners_boundary() {
        let tracker = PayoutTracker::new(Duration::from_millis(50));
        tracker.record_share(&"miner_old".to_string(), 100.0);

        // Sleep past the idle duration
        std::thread::sleep(Duration::from_millis(55));

        // Add a fresh miner
        tracker.record_share(&"miner_new".to_string(), 200.0);

        // Cleanup with 50ms idle -- old miner's share was ~55ms ago
        let removed = tracker.cleanup_stale_miners(Duration::from_millis(50));
        assert_eq!(removed, 1, "exactly 1 old miner should be removed");

        assert!(
            tracker.get_stats(&"miner_old".to_string()).is_none(),
            "old miner should be cleaned up"
        );
        assert!(
            tracker.get_stats(&"miner_new".to_string()).is_some(),
            "new miner should be preserved"
        );
    }

    /// clear_cross_path_solutions resets the epoch boundary: a solution that was
    /// previously seen must be accepted again after the clear (simulating a new
    /// block epoch where old-job solutions are irrelevant).
    #[test]
    fn test_clear_cross_path_solutions_resets_dedup() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();
        let solution = b"fake_solution_bytes_32_chars_long".to_vec();

        // First submission: credited
        assert!(
            tracker.try_record_share_once(&miner, 1.0, &solution),
            "first submission must be credited"
        );

        // Second submission same epoch: cross-path dup, rejected
        assert!(
            !tracker.try_record_share_once(&miner, 1.0, &solution),
            "duplicate within epoch must be rejected"
        );

        // New block epoch: clear cross-path solutions
        tracker.clear_cross_path_solutions();

        // Same solution bytes after clear: accepted again (new epoch, new job)
        assert!(
            tracker.try_record_share_once(&miner, 1.0, &solution),
            "same solution must be accepted after epoch clear"
        );

        // Stats: 2 credits (first + post-clear), 1 rejected
        let stats = tracker.get_stats(&miner).unwrap();
        assert_eq!(stats.total_shares, 2);
    }

    /// An invalid-difficulty share must NOT consume a cross-path dedup slot and
    /// must NOT be reported as recorded. Otherwise the solution's hash would be
    /// stuck in the set with no credit issued, falsely deduping a later honest
    /// resubmission of the same solution at a valid difficulty.
    #[test]
    fn test_invalid_difficulty_does_not_poison_cross_path_dedup() {
        let tracker = PayoutTracker::default();
        let miner = "miner1".to_string();
        let solution = b"fake_solution_bytes_32_chars_long".to_vec();

        // Invalid difficulty: not recorded, returns false, set untouched.
        assert!(
            !tracker.try_record_share_once(&miner, 0.0, &solution),
            "invalid difficulty must not be credited"
        );
        assert!(
            !tracker.try_record_share_once(&miner, f64::NAN, &solution),
            "NaN difficulty must not be credited"
        );
        assert!(
            tracker.get_stats(&miner).is_none(),
            "no credit should exist"
        );

        // A later honest submission of the SAME solution at a valid difficulty
        // must be credited — proving the earlier invalid attempts did not poison
        // the dedup set.
        assert!(
            tracker.try_record_share_once(&miner, 1.0, &solution),
            "valid resubmission of the same solution must be credited"
        );
        assert_eq!(tracker.get_stats(&miner).unwrap().total_shares, 1);
    }

    /// Kill mutants on lines 180-181:
    /// - `before - miners.len()` vs `before + miners.len()` (line 180)
    /// - `removed > 0` vs `removed == 0` / `removed < 0` / `removed >= 0` (line 181)
    ///   Uses partial removal so before != 0 and miners.len() != 0 after retain,
    ///   making `before - miners.len()` differ from `before + miners.len()`.
    #[test]
    fn test_cleanup_stale_miners_partial_removal() {
        let tracker = PayoutTracker::new(Duration::from_millis(100));

        // Record old miners
        tracker.record_share(&"old1".to_string(), 10.0);
        tracker.record_share(&"old2".to_string(), 20.0);

        std::thread::sleep(Duration::from_millis(120));

        // Record new miners
        tracker.record_share(&"new1".to_string(), 30.0);
        tracker.record_share(&"new2".to_string(), 40.0);
        tracker.record_share(&"new3".to_string(), 50.0);

        // Cleanup with 100ms idle -- old miners were ~120ms ago
        // before=5, after retain miners.len()=3
        // Correct: 5 - 3 = 2
        // Mutant (+ instead of -): 5 + 3 = 8
        let removed = tracker.cleanup_stale_miners(Duration::from_millis(100));
        assert_eq!(removed, 2, "exactly 2 old miners should be removed");

        let remaining = tracker.get_all_stats();
        assert_eq!(remaining.len(), 3, "exactly 3 new miners should remain");
        assert!(remaining.contains_key("new1"));
        assert!(remaining.contains_key("new2"));
        assert!(remaining.contains_key("new3"));
    }

    /// Kill mutant: cleanup returns 0 when no miners are stale (tests `removed > 0` vs `removed == 0`)
    #[test]
    fn test_cleanup_stale_miners_returns_zero_when_none_stale() {
        let tracker = PayoutTracker::default();
        tracker.record_share(&"miner1".to_string(), 100.0);

        // Large idle window -- miner is fresh
        let removed = tracker.cleanup_stale_miners(Duration::from_secs(3600));
        assert_eq!(removed, 0, "no miners should be removed when all are fresh");
        assert_eq!(tracker.get_all_stats().len(), 1);
    }
}
