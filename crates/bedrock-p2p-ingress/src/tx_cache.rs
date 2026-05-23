use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bedrock_forge::{AuthDigest, MempoolProvider, TxId, WtxId};
use sha2::{Digest, Sha256};

use crate::wire::{Inventory, MSG_TX, MSG_WTX};

#[derive(Debug, Clone, Copy)]
pub struct TxCacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_tx_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxInventoryKey {
    inv_type: u32,
    hash: [u8; 32],
    auth_digest: Option<[u8; 32]>,
}

impl TxInventoryKey {
    pub fn tx(hash: [u8; 32]) -> Self {
        Self {
            inv_type: MSG_TX,
            hash,
            auth_digest: None,
        }
    }

    pub fn wtx(hash: [u8; 32], auth_digest: [u8; 32]) -> Self {
        Self {
            inv_type: MSG_WTX,
            hash,
            auth_digest: Some(auth_digest),
        }
    }

    pub fn from_inventory(inv: &Inventory) -> Option<Self> {
        match inv.inv_type {
            MSG_TX => Some(Self::tx(inv.hash)),
            MSG_WTX => inv
                .auth_digest
                .map(|auth_digest| Self::wtx(inv.hash, auth_digest)),
            _ => None,
        }
    }

    pub fn to_inventory(self) -> Inventory {
        Inventory {
            inv_type: self.inv_type,
            hash: self.hash,
            auth_digest: self.auth_digest,
        }
    }

    pub fn to_wtxid(self) -> WtxId {
        WtxId::new(
            TxId::from_bytes(self.hash),
            AuthDigest::from_bytes(self.auth_digest.unwrap_or([0u8; 32])),
        )
    }

    pub fn display_hash(self) -> String {
        crate::hash::inventory_hash_to_display(&self.hash)
    }

    pub fn kind(self) -> &'static str {
        match self.inv_type {
            MSG_WTX => "wtx",
            _ => "tx",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TxCacheInsertOutcome {
    pub inserted: bool,
    pub entries: usize,
    pub bytes: usize,
    pub evicted_entries: usize,
    pub evicted_bytes: usize,
    pub dropped_too_large: usize,
}

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
    pub fn new(config: TxCacheConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(TxCacheInner::default())),
        }
    }

    pub fn insert(&self, key: TxInventoryKey, tx_bytes: Vec<u8>) -> TxCacheInsertOutcome {
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

        let wtxid = key.to_wtxid();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_wtx_inventory_as_mempool_provider() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let key = TxInventoryKey::wtx([0x11; 32], [0x22; 32]);
        let tx_bytes = vec![0xaa, 0xbb, 0xcc];

        let outcome = cache.insert(key, tx_bytes.clone());

        assert!(outcome.inserted);
        assert_eq!(outcome.entries, 1);
        assert_eq!(outcome.bytes, tx_bytes.len());
        let wtxid = key.to_wtxid();
        assert_eq!(cache.get_tx_data(&wtxid), Some(tx_bytes));
        assert_eq!(cache.get_wtxids(), vec![wtxid]);
    }

    #[test]
    fn evicts_oldest_entries_to_stay_under_bounds() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 2,
            max_bytes: 5,
            max_tx_bytes: 512,
        });
        let first = TxInventoryKey::tx([0x01; 32]);
        let second = TxInventoryKey::tx([0x02; 32]);
        let third = TxInventoryKey::tx([0x03; 32]);

        cache.insert(first, vec![1, 1]);
        cache.insert(second, vec![2, 2]);
        let outcome = cache.insert(third, vec![3, 3]);

        assert!(outcome.inserted);
        assert_eq!(outcome.evicted_entries, 1);
        assert_eq!(outcome.entries, 2);
        assert_eq!(outcome.bytes, 4);
        assert_eq!(cache.get_tx_data(&first.to_wtxid()), None);
        assert_eq!(cache.get_tx_data(&second.to_wtxid()), Some(vec![2, 2]));
        assert_eq!(cache.get_tx_data(&third.to_wtxid()), Some(vec![3, 3]));
    }

    #[test]
    fn rejects_transactions_larger_than_limit() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 2,
        });

        let outcome = cache.insert(TxInventoryKey::tx([0x44; 32]), vec![1, 2, 3]);

        assert!(!outcome.inserted);
        assert_eq!(outcome.dropped_too_large, 1);
        assert_eq!(outcome.entries, 0);
        assert_eq!(outcome.bytes, 0);
    }

    #[test]
    fn finds_wtxid_for_exact_cached_payload() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let key = TxInventoryKey::wtx([0x55; 32], [0x66; 32]);
        let tx_bytes = vec![0xde, 0xad, 0xbe, 0xef];

        cache.insert(key, tx_bytes.clone());

        assert_eq!(cache.wtxid_for_payload(&tx_bytes), Some(key.to_wtxid()));
        assert_eq!(cache.wtxid_for_payload(&[0xde, 0xad, 0xbe, 0x00]), None);
    }

    #[test]
    fn evicts_payload_lookup_with_oldest_entry() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 1,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let first = TxInventoryKey::tx([0x71; 32]);
        let second = TxInventoryKey::tx([0x72; 32]);
        let first_payload = vec![1, 2, 3];
        let second_payload = vec![4, 5, 6];

        cache.insert(first, first_payload.clone());
        cache.insert(second, second_payload.clone());

        assert_eq!(cache.wtxid_for_payload(&first_payload), None);
        assert_eq!(
            cache.wtxid_for_payload(&second_payload),
            Some(second.to_wtxid())
        );
    }

    #[test]
    fn duplicate_payload_with_multiple_wtxids_is_ambiguous() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let payload = vec![0xaa, 0xbb, 0xcc];

        cache.insert(TxInventoryKey::tx([0x81; 32]), payload.clone());
        cache.insert(TxInventoryKey::tx([0x82; 32]), payload.clone());

        assert_eq!(cache.wtxid_for_payload(&payload), None);
    }

    #[test]
    fn snapshot_reports_bounds_and_cumulative_evictions_and_drops() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 2,
            max_bytes: 5,
            max_tx_bytes: 4,
        });

        cache.insert(TxInventoryKey::tx([0x01; 32]), vec![1, 1]);
        cache.insert(TxInventoryKey::tx([0x02; 32]), vec![2, 2]);
        cache.insert(TxInventoryKey::tx([0x03; 32]), vec![3, 3]);
        cache.insert(TxInventoryKey::tx([0x04; 32]), vec![4, 4, 4, 4, 4]);

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
