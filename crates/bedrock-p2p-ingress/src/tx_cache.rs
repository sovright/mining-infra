use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bedrock_forge::{AuthDigest, MempoolProvider, TxId, WtxId};

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

#[derive(Clone)]
pub struct TxCache {
    config: TxCacheConfig,
    inner: Arc<Mutex<TxCacheInner>>,
}

#[derive(Default)]
struct TxCacheInner {
    entries: HashMap<WtxId, CachedTx>,
    order: VecDeque<WtxId>,
    bytes: usize,
}

struct CachedTx {
    bytes: Vec<u8>,
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
            return TxCacheInsertOutcome {
                inserted: false,
                entries: inner.entries.len(),
                bytes: inner.bytes,
                dropped_too_large: 1,
                ..TxCacheInsertOutcome::default()
            };
        }

        let wtxid = key.to_wtxid();
        if let Some(previous) = inner.entries.remove(&wtxid) {
            inner.bytes = inner.bytes.saturating_sub(previous.bytes.len());
            inner.order.retain(|candidate| candidate != &wtxid);
        }

        inner.bytes += tx_bytes.len();
        inner.entries.insert(wtxid, CachedTx { bytes: tx_bytes });
        inner.order.push_back(wtxid);

        let mut evicted_entries = 0;
        let mut evicted_bytes = 0;
        while inner.entries.len() > self.config.max_entries || inner.bytes > self.config.max_bytes {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some(entry) = inner.entries.remove(&oldest) {
                evicted_entries += 1;
                evicted_bytes += entry.bytes.len();
                inner.bytes = inner.bytes.saturating_sub(entry.bytes.len());
            }
        }

        TxCacheInsertOutcome {
            inserted: inner.entries.contains_key(&wtxid),
            entries: inner.entries.len(),
            bytes: inner.bytes,
            evicted_entries,
            evicted_bytes,
            dropped_too_large: 0,
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
}
