//! Mempool interface for compact block reconstruction
//!
//! Defines the trait that mempool implementations must satisfy
//! for compact block reconstruction to work.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::types::WtxId;

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
}

struct CachedTx {
    bytes: Vec<u8>,
    payload_digest: [u8; 32],
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

        remove_entry(&mut inner, &wtxid);

        let payload_digest = payload_digest(&tx_bytes);
        inner.bytes += tx_bytes.len();
        inner.entries.insert(
            wtxid,
            CachedTx {
                bytes: tx_bytes,
                payload_digest,
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
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some(entry) = remove_entry(&mut inner, &oldest) {
                evicted_entries += 1;
                evicted_bytes += entry.bytes.len();
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
    let entry = inner.entries.remove(wtxid)?;
    inner.bytes = inner.bytes.saturating_sub(entry.bytes.len());
    inner.order.retain(|candidate| candidate != wtxid);
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
            }
        );
    }
}
