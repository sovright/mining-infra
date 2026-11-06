//! Mempool interface for compact block reconstruction
//!
//! Defines the trait that mempool implementations must satisfy
//! for compact block reconstruction to work.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::types::{TxId, WtxId};

/// Error type for mempool operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction not found in mempool
    TransactionNotFound(WtxId),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::TransactionNotFound(wtxid) => {
                write!(f, "transaction not found in mempool: {:?}", wtxid)
            }
        }
    }
}

impl std::error::Error for MempoolError {}

/// Trait for mempool implementations to support compact block reconstruction
pub trait MempoolProvider {
    /// Get all wtxids currently in mempool
    fn get_wtxids(&self) -> Vec<WtxId>;

    /// Get transaction data by wtxid
    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>>;

    /// Check if transaction exists in mempool
    fn contains(&self, wtxid: &WtxId) -> bool {
        self.get_tx_data(wtxid).is_some()
    }
}

/// In-memory mempool implementation for testing
#[derive(Default)]
pub struct TestMempool {
    transactions: std::collections::HashMap<WtxId, Vec<u8>>,
}

impl TestMempool {
    /// Create empty test mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Add transaction to mempool
    pub fn insert(&mut self, wtxid: WtxId, tx_data: Vec<u8>) {
        self.transactions.insert(wtxid, tx_data);
    }

    /// Number of transactions in mempool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl MempoolProvider for TestMempool {
    fn get_wtxids(&self) -> Vec<WtxId> {
        self.transactions.keys().copied().collect()
    }

    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>> {
        self.transactions.get(wtxid).cloned()
    }
}

/// Bounds for the shared in-memory transaction cache.
#[derive(Debug, Clone, Copy)]
pub struct TxCacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_tx_bytes: usize,
}

/// Result of inserting one transaction into [`TxCache`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TxCacheInsertOutcome {
    pub inserted: bool,
    pub entries: usize,
    pub bytes: usize,
    pub evicted_entries: usize,
    pub evicted_bytes: usize,
    pub dropped_too_large: usize,
}

/// Snapshot of cache fill level and cumulative eviction/drop counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxCacheSnapshot {
    pub entries: usize,
    pub bytes: usize,
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_tx_bytes: usize,
    pub evicted_entries_total: usize,
    pub evicted_bytes_total: usize,
    pub dropped_too_large_total: usize,
    /// Retained entries observed in the trusted canonical chain.
    pub confirmed_entries: usize,
    /// Entries removed after both confirmed-retention thresholds elapsed.
    pub confirmed_evicted_entries_total: usize,
}

/// Bounded transaction cache usable as a compact-block reconstruction mempool.
#[derive(Clone)]
pub struct TxCache {
    config: TxCacheConfig,
    inner: Arc<Mutex<TxCacheInner>>,
}

#[derive(Default)]
struct TxCacheInner {
    entries: HashMap<WtxId, CachedTx>,
    order: VecDeque<WtxId>,
    payload_index: HashMap<[u8; 32], Vec<WtxId>>,
    bytes: usize,
    evicted_entries_total: usize,
    evicted_bytes_total: usize,
    dropped_too_large_total: usize,
    confirmed_evicted_entries_total: usize,
    retention_policy: Option<RetentionPolicy>,
}

struct CachedTx {
    bytes: Vec<u8>,
    payload_digest: [u8; 32],
    confirmed: Option<Confirmation>,
}

#[derive(Clone, Copy)]
struct Confirmation {
    height: u64,
    observed_at: Instant,
}

#[derive(Clone, Copy)]
struct RetentionPolicy {
    tip_height: u64,
    grace: Duration,
    min_confirmations: u64,
}

impl RetentionPolicy {
    fn eligible(&self, confirmed: Option<Confirmation>, now: Instant) -> bool {
        confirmed.is_some_and(|confirmed| {
            let Some(depth) = self
                .tip_height
                .checked_sub(confirmed.height)
                .and_then(|depth| depth.checked_add(1))
            else {
                return false;
            };
            now.checked_duration_since(confirmed.observed_at)
                .is_some_and(|age| depth >= self.min_confirmations && age >= self.grace)
        })
    }
}

impl TxCache {
    /// Create an empty bounded transaction cache.
    pub fn new(config: TxCacheConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(TxCacheInner::default())),
        }
    }

    /// Insert raw transaction bytes by their Zcash wtxid.
    pub fn insert(&self, wtxid: WtxId, tx_bytes: Vec<u8>) -> TxCacheInsertOutcome {
        self.insert_at(wtxid, tx_bytes, Instant::now())
    }

    fn insert_at(&self, wtxid: WtxId, tx_bytes: Vec<u8>, now: Instant) -> TxCacheInsertOutcome {
        let mut inner = self.inner.lock().expect("tx cache mutex poisoned");
        if tx_bytes.len() > self.config.max_tx_bytes || self.config.max_entries == 0 {
            inner.dropped_too_large_total += 1;
            return TxCacheInsertOutcome {
                inserted: false,
                entries: inner.entries.len(),
                bytes: inner.bytes,
                dropped_too_large: 1,
                ..TxCacheInsertOutcome::default()
            };
        }

        // Duplicate untrusted announcements must not reset the grace period.
        let confirmed = remove_entry(&mut inner, &wtxid).and_then(|entry| entry.confirmed);

        let payload_digest = payload_digest(&tx_bytes);
        inner.bytes += tx_bytes.len();
        inner.entries.insert(
            wtxid,
            CachedTx {
                bytes: tx_bytes,
                payload_digest,
                confirmed,
            },
        );
        inner.order.push_back(wtxid);
        inner
            .payload_index
            .entry(payload_digest)
            .or_default()
            .push(wtxid);

        let mut evicted_entries = 0;
        let mut evicted_bytes = 0;
        while inner.entries.len() > self.config.max_entries || inner.bytes > self.config.max_bytes {
            // A confirmation can mature between maintenance ticks. Reuse only
            // the last trusted tip; never infer additional depth from time.
            let preferred = inner.retention_policy.and_then(|policy| {
                inner
                    .order
                    .iter()
                    .find(|wtxid| {
                        inner
                            .entries
                            .get(wtxid)
                            .is_some_and(|entry| policy.eligible(entry.confirmed, now))
                    })
                    .copied()
            });
            let Some(candidate) = preferred.or_else(|| inner.order.front().copied()) else {
                break;
            };
            if let Some(entry) = remove_entry(&mut inner, &candidate) {
                evicted_entries += 1;
                evicted_bytes += entry.bytes.len();
                if preferred.is_some() {
                    inner.confirmed_evicted_entries_total += 1;
                }
            }
        }
        inner.evicted_entries_total += evicted_entries;
        inner.evicted_bytes_total += evicted_bytes;

        TxCacheInsertOutcome {
            inserted: inner.entries.contains_key(&wtxid),
            entries: inner.entries.len(),
            bytes: inner.bytes,
            evicted_entries,
            evicted_bytes,
            dropped_too_large: 0,
        }
    }

    /// Mark cached variants of txids observed in a trusted canonical block.
    ///
    /// Merely hearing a block or a successful submit is not canonical evidence.
    /// Repeated observations preserve the original confirmation age; callers
    /// clear markers before applying a replacement chain after a reorg.
    pub fn mark_confirmed(&self, txids: &[TxId], height: u64, now: Instant) {
        let txids: HashSet<_> = txids.iter().copied().collect();
        let mut inner = self.inner.lock().expect("tx cache mutex poisoned");
        for (wtxid, entry) in &mut inner.entries {
            if txids.contains(wtxid.txid()) && entry.confirmed.is_none() {
                entry.confirmed = Some(Confirmation {
                    height,
                    observed_at: now,
                });
            }
        }
    }

    /// Restore retained transactions observed in the trusted node's mempool.
    pub fn restore_pending(&self, txids: &[TxId]) {
        let txids: HashSet<_> = txids.iter().copied().collect();
        let mut inner = self.inner.lock().expect("tx cache mutex poisoned");
        for (wtxid, entry) in &mut inner.entries {
            if txids.contains(wtxid.txid()) {
                entry.confirmed = None;
            }
        }
    }

    /// Conservatively forget confirmation evidence after a chain reorganization.
    /// This retains existing payloads; already evicted payloads need refetching.
    pub fn clear_confirmations(&self) {
        let mut inner = self.inner.lock().expect("tx cache mutex poisoned");
        for entry in inner.entries.values_mut() {
            entry.confirmed = None;
        }
        inner.retention_policy = None;
    }

    /// Evict confirmed entries only after both wall-time and depth retention.
    ///
    /// Stores trusted depth and retention thresholds for capacity eviction:
    /// insertions prefer eligible confirmed entries even between maintenance
    /// ticks. When none qualify, the hard byte/entry cap falls back to FIFO.
    pub fn evict_confirmed(
        &self,
        tip_height: u64,
        now: Instant,
        grace: Duration,
        min_confirmations: u64,
    ) -> usize {
        let mut inner = self.inner.lock().expect("tx cache mutex poisoned");
        let policy = RetentionPolicy {
            tip_height,
            grace,
            min_confirmations,
        };
        inner.retention_policy = Some(policy);
        let eligible: Vec<_> = inner
            .entries
            .iter()
            .filter_map(|(wtxid, entry)| policy.eligible(entry.confirmed, now).then_some(*wtxid))
            .collect();
        for wtxid in &eligible {
            if let Some(entry) = remove_entry_data(&mut inner, wtxid) {
                inner.evicted_entries_total += 1;
                inner.evicted_bytes_total += entry.bytes.len();
                inner.confirmed_evicted_entries_total += 1;
            }
        }
        // Remove queue references once for the batch, avoiding O(n²) queue
        // scans when a full cache of confirmed transactions expires together.
        let removed: HashSet<_> = eligible.iter().copied().collect();
        inner.order.retain(|wtxid| !removed.contains(wtxid));
        eligible.len()
    }

    /// Resolve a raw transaction payload to a unique cached wtxid.
    pub fn wtxid_for_payload(&self, tx_payload: &[u8]) -> Option<WtxId> {
        let digest = payload_digest(tx_payload);
        let inner = self.inner.lock().expect("tx cache mutex poisoned");
        let mut matches = inner
            .payload_index
            .get(&digest)?
            .iter()
            .copied()
            .filter(|wtxid| {
                inner
                    .entries
                    .get(wtxid)
                    .is_some_and(|entry| entry.bytes == tx_payload)
            });
        let first = matches.next()?;
        if matches.next().is_some() {
            None
        } else {
            Some(first)
        }
    }

    /// Return current cache fill state and cumulative eviction/drop counters.
    pub fn snapshot(&self) -> TxCacheSnapshot {
        let inner = self.inner.lock().expect("tx cache mutex poisoned");
        TxCacheSnapshot {
            entries: inner.entries.len(),
            bytes: inner.bytes,
            max_entries: self.config.max_entries,
            max_bytes: self.config.max_bytes,
            max_tx_bytes: self.config.max_tx_bytes,
            evicted_entries_total: inner.evicted_entries_total,
            evicted_bytes_total: inner.evicted_bytes_total,
            dropped_too_large_total: inner.dropped_too_large_total,
            confirmed_entries: inner
                .entries
                .values()
                .filter(|entry| entry.confirmed.is_some())
                .count(),
            confirmed_evicted_entries_total: inner.confirmed_evicted_entries_total,
        }
    }
}

impl MempoolProvider for TxCache {
    fn get_wtxids(&self) -> Vec<WtxId> {
        let inner = self.inner.lock().expect("tx cache mutex poisoned");
        inner.entries.keys().copied().collect()
    }

    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>> {
        let inner = self.inner.lock().expect("tx cache mutex poisoned");
        inner.entries.get(wtxid).map(|entry| entry.bytes.clone())
    }
}

fn payload_digest(tx_payload: &[u8]) -> [u8; 32] {
    Sha256::digest(tx_payload).into()
}

fn remove_entry(inner: &mut TxCacheInner, wtxid: &WtxId) -> Option<CachedTx> {
    let entry = remove_entry_data(inner, wtxid)?;
    inner.order.retain(|candidate| candidate != wtxid);
    Some(entry)
}

fn remove_entry_data(inner: &mut TxCacheInner, wtxid: &WtxId) -> Option<CachedTx> {
    let entry = inner.entries.remove(wtxid)?;
    inner.bytes = inner.bytes.saturating_sub(entry.bytes.len());
    remove_payload_index_entry(&mut inner.payload_index, entry.payload_digest, wtxid);
    Some(entry)
}

fn remove_payload_index_entry(
    payload_index: &mut HashMap<[u8; 32], Vec<WtxId>>,
    digest: [u8; 32],
    wtxid: &WtxId,
) {
    let should_remove = if let Some(candidates) = payload_index.get_mut(&digest) {
        candidates.retain(|candidate| candidate != wtxid);
        candidates.is_empty()
    } else {
        false
    };
    if should_remove {
        payload_index.remove(&digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthDigest, TxId};

    #[test]
    fn test_mempool_insert_and_retrieve() {
        let mut mempool = TestMempool::new();

        let wtxid = WtxId::new(
            TxId::from_bytes([1u8; 32]),
            AuthDigest::from_bytes([2u8; 32]),
        );
        let tx_data = vec![0xde, 0xad, 0xbe, 0xef];

        mempool.insert(wtxid, tx_data.clone());

        assert!(mempool.contains(&wtxid));
        assert_eq!(mempool.get_tx_data(&wtxid), Some(tx_data));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_get_wtxids() {
        let mut mempool = TestMempool::new();

        let wtxid1 = WtxId::new(
            TxId::from_bytes([1u8; 32]),
            AuthDigest::from_bytes([1u8; 32]),
        );
        let wtxid2 = WtxId::new(
            TxId::from_bytes([2u8; 32]),
            AuthDigest::from_bytes([2u8; 32]),
        );

        mempool.insert(wtxid1, vec![1]);
        mempool.insert(wtxid2, vec![2]);

        let wtxids = mempool.get_wtxids();
        assert_eq!(wtxids.len(), 2);
        assert!(wtxids.contains(&wtxid1));
        assert!(wtxids.contains(&wtxid2));
    }

    #[test]
    fn test_mempool_not_found() {
        let mempool = TestMempool::new();

        let wtxid = WtxId::new(
            TxId::from_bytes([99u8; 32]),
            AuthDigest::from_bytes([99u8; 32]),
        );

        assert!(!mempool.contains(&wtxid));
        assert_eq!(mempool.get_tx_data(&wtxid), None);
    }

    #[test]
    fn tx_cache_stores_wtxids_as_mempool_provider() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let wtxid = WtxId::new(
            TxId::from_bytes([0x11; 32]),
            AuthDigest::from_bytes([0x22; 32]),
        );
        let tx_bytes = vec![0xaa, 0xbb, 0xcc];

        let outcome = cache.insert(wtxid, tx_bytes.clone());

        assert!(outcome.inserted);
        assert_eq!(outcome.entries, 1);
        assert_eq!(outcome.bytes, tx_bytes.len());
        assert_eq!(cache.get_tx_data(&wtxid), Some(tx_bytes));
        assert_eq!(cache.get_wtxids(), vec![wtxid]);
    }

    #[test]
    fn tx_cache_finds_wtxid_for_exact_cached_payload() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let wtxid = WtxId::new(
            TxId::from_bytes([0x55; 32]),
            AuthDigest::from_bytes([0x66; 32]),
        );
        let tx_bytes = vec![0xde, 0xad, 0xbe, 0xef];

        cache.insert(wtxid, tx_bytes.clone());

        assert_eq!(cache.wtxid_for_payload(&tx_bytes), Some(wtxid));
        assert_eq!(cache.wtxid_for_payload(&[0xde, 0xad, 0xbe, 0x00]), None);
    }

    #[test]
    fn tx_cache_snapshot_reports_bounds_and_cumulative_evictions_and_drops() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 2,
            max_bytes: 5,
            max_tx_bytes: 4,
        });

        cache.insert(
            WtxId::new(
                TxId::from_bytes([0x01; 32]),
                AuthDigest::from_bytes([0; 32]),
            ),
            vec![1, 1],
        );
        cache.insert(
            WtxId::new(
                TxId::from_bytes([0x02; 32]),
                AuthDigest::from_bytes([0; 32]),
            ),
            vec![2, 2],
        );
        cache.insert(
            WtxId::new(
                TxId::from_bytes([0x03; 32]),
                AuthDigest::from_bytes([0; 32]),
            ),
            vec![3, 3],
        );
        cache.insert(
            WtxId::new(
                TxId::from_bytes([0x04; 32]),
                AuthDigest::from_bytes([0; 32]),
            ),
            vec![4, 4, 4, 4, 4],
        );

        let snapshot = cache.snapshot();

        assert_eq!(
            snapshot,
            TxCacheSnapshot {
                entries: 2,
                bytes: 4,
                max_entries: 2,
                max_bytes: 5,
                max_tx_bytes: 4,
                evicted_entries_total: 1,
                evicted_bytes_total: 2,
                dropped_too_large_total: 1,
                confirmed_entries: 0,
                confirmed_evicted_entries_total: 0,
            }
        );
    }
    fn retention_cache() -> (TxCache, WtxId, WtxId) {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 4,
            max_bytes: 100,
            max_tx_bytes: 100,
        });
        let a = WtxId::new(TxId::from_bytes([1; 32]), AuthDigest::from_bytes([1; 32]));
        let b = WtxId::new(TxId::from_bytes([2; 32]), AuthDigest::from_bytes([2; 32]));
        cache.insert(a, vec![1, 2, 3]);
        cache.insert(b, vec![4, 5]);
        (cache, a, b)
    }

    #[test]
    fn confirmed_retention_requires_both_time_and_depth_then_preserves_pending() {
        let (cache, a, b) = retention_cache();
        let now = Instant::now();
        cache.mark_confirmed(&[*a.txid()], 100, now);
        assert_eq!(
            cache.evict_confirmed(
                111,
                now + Duration::from_secs(599),
                Duration::from_secs(600),
                12
            ),
            0
        );
        assert_eq!(cache.get_tx_data(&a), Some(vec![1, 2, 3]));
        assert_eq!(
            cache.evict_confirmed(
                110,
                now + Duration::from_secs(600),
                Duration::from_secs(600),
                12
            ),
            0
        );
        assert_eq!(
            cache.evict_confirmed(
                111,
                now + Duration::from_secs(600),
                Duration::from_secs(600),
                12
            ),
            1
        );
        assert_eq!(cache.get_tx_data(&a), None);
        assert!(cache.contains(&b));
        assert_eq!(cache.wtxid_for_payload(&[1, 2, 3]), None);
        let snap = cache.snapshot();
        assert_eq!(snap.bytes, 2);
        assert_eq!(snap.confirmed_entries, 0);
        assert_eq!(snap.confirmed_evicted_entries_total, 1);
        assert_eq!(snap.evicted_entries_total, 1);
        assert_eq!(snap.evicted_bytes_total, 3);
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.order.len(), 1);
        assert_eq!(inner.payload_index.len(), 1);
    }

    #[test]
    fn duplicate_insert_and_repeated_confirmation_do_not_extend_grace() {
        let (cache, a, _) = retention_cache();
        let now = Instant::now();
        cache.mark_confirmed(&[*a.txid()], 100, now);
        cache.insert(a, vec![1, 2, 3]);
        cache.mark_confirmed(&[*a.txid()], 100, now + Duration::from_secs(599));
        assert_eq!(
            cache.evict_confirmed(
                111,
                now + Duration::from_secs(600),
                Duration::from_secs(600),
                12
            ),
            1
        );
    }

    #[test]
    fn mempool_reappearance_and_reorg_clear_retained_confirmation() {
        let (cache, a, b) = retention_cache();
        let now = Instant::now();
        cache.mark_confirmed(&[*a.txid(), *b.txid()], 100, now);
        cache.restore_pending(&[*a.txid()]);
        assert_eq!(cache.snapshot().confirmed_entries, 1);
        cache.clear_confirmations();
        assert_eq!(
            cache.evict_confirmed(
                111,
                now + Duration::from_secs(600),
                Duration::from_secs(600),
                12
            ),
            0
        );
        assert_eq!(cache.snapshot().confirmed_entries, 0);
        assert!(cache.contains(&a) && cache.contains(&b));
    }

    #[test]
    fn confirmations_match_all_auth_variants_and_reject_future_height_or_clock() {
        let (cache, a, _) = retention_cache();
        let variant = WtxId::new(*a.txid(), AuthDigest::from_bytes([3; 32]));
        cache.insert(variant, vec![8]);
        let now = Instant::now();
        cache.mark_confirmed(&[*a.txid()], 100, now);
        assert_eq!(cache.snapshot().confirmed_entries, 2);
        assert_eq!(
            cache.evict_confirmed(99, now + Duration::from_secs(600), Duration::ZERO, 1),
            0
        );
        assert_eq!(
            cache.evict_confirmed(111, now - Duration::from_secs(1), Duration::ZERO, 1),
            0
        );
        assert_eq!(
            cache.evict_confirmed(
                111,
                now + Duration::from_secs(600),
                Duration::from_secs(600),
                12
            ),
            2
        );
    }
    #[test]
    fn capacity_eviction_prefers_confirmation_maturing_between_maintenance_ticks() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 2,
            max_bytes: 100,
            max_tx_bytes: 100,
        });
        let a = WtxId::new(TxId::from_bytes([1; 32]), AuthDigest::from_bytes([1; 32]));
        let b = WtxId::new(TxId::from_bytes([2; 32]), AuthDigest::from_bytes([2; 32]));
        let c = WtxId::new(TxId::from_bytes([3; 32]), AuthDigest::from_bytes([3; 32]));
        let now = Instant::now();
        cache.insert_at(a, vec![1], now);
        cache.insert_at(b, vec![2], now);
        cache.mark_confirmed(&[*b.txid()], 100, now);
        assert_eq!(
            cache.evict_confirmed(
                111,
                now + Duration::from_secs(599),
                Duration::from_secs(600),
                12
            ),
            0
        );
        let result = cache.insert_at(c, vec![3], now + Duration::from_secs(600));
        assert_eq!(result.evicted_entries, 1);
        assert!(cache.contains(&a));
        assert!(!cache.contains(&b));
        assert!(cache.contains(&c));
        assert_eq!(cache.snapshot().confirmed_evicted_entries_total, 1);
        assert_eq!(cache.wtxid_for_payload(&[2]), None);
    }

    #[test]
    fn capacity_preference_context_is_invalidated_by_reorg_or_pending_reappearance() {
        for reorg in [false, true] {
            let cache = TxCache::new(TxCacheConfig {
                max_entries: 2,
                max_bytes: 100,
                max_tx_bytes: 100,
            });
            let a = WtxId::new(TxId::from_bytes([1; 32]), AuthDigest::from_bytes([1; 32]));
            let b = WtxId::new(TxId::from_bytes([2; 32]), AuthDigest::from_bytes([2; 32]));
            let c = WtxId::new(TxId::from_bytes([3; 32]), AuthDigest::from_bytes([3; 32]));
            let now = Instant::now();
            cache.insert_at(a, vec![1], now);
            cache.insert_at(b, vec![2], now);
            cache.mark_confirmed(&[*b.txid()], 100, now);
            cache.evict_confirmed(111, now, Duration::from_secs(600), 12);
            if reorg {
                cache.clear_confirmations();
            } else {
                cache.restore_pending(&[*b.txid()]);
            }
            cache.insert_at(c, vec![3], now + Duration::from_secs(600));
            assert!(!cache.contains(&a));
            assert!(cache.contains(&b));
            assert_eq!(cache.snapshot().confirmed_evicted_entries_total, 0);
        }
    }
}
