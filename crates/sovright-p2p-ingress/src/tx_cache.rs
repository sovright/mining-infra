use sovright_relay::{AuthDigest, TxId, WtxId};
pub use sovright_relay::{TxCache, TxCacheConfig};

use crate::wire::{Inventory, MSG_TX, MSG_WTX};

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

    /// The `MSG_WTX` key naming `wtxid`, for logging a transaction identified
    /// by its own payload rather than by a queued request.
    pub fn from_wtxid(wtxid: &WtxId) -> Self {
        Self::wtx(*wtxid.txid().as_bytes(), *wtxid.auth_digest().as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use sovright_relay::{MempoolProvider, TxCacheSnapshot};

    #[test]
    fn stores_wtx_inventory_as_mempool_provider() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        let key = TxInventoryKey::wtx([0x11; 32], [0x22; 32]);
        let tx_bytes = vec![0xaa, 0xbb, 0xcc];

        let outcome = cache.insert(key.to_wtxid(), tx_bytes.clone());

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

        cache.insert(first.to_wtxid(), vec![1, 1]);
        cache.insert(second.to_wtxid(), vec![2, 2]);
        let outcome = cache.insert(third.to_wtxid(), vec![3, 3]);

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

        let outcome = cache.insert(TxInventoryKey::tx([0x44; 32]).to_wtxid(), vec![1, 2, 3]);

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

        cache.insert(key.to_wtxid(), tx_bytes.clone());

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

        cache.insert(first.to_wtxid(), first_payload.clone());
        cache.insert(second.to_wtxid(), second_payload.clone());

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

        cache.insert(TxInventoryKey::tx([0x81; 32]).to_wtxid(), payload.clone());
        cache.insert(TxInventoryKey::tx([0x82; 32]).to_wtxid(), payload.clone());

        assert_eq!(cache.wtxid_for_payload(&payload), None);
    }

    #[test]
    fn snapshot_reports_bounds_and_cumulative_evictions_and_drops() {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 2,
            max_bytes: 5,
            max_tx_bytes: 4,
        });

        cache.insert(TxInventoryKey::tx([0x01; 32]).to_wtxid(), vec![1, 1]);
        cache.insert(TxInventoryKey::tx([0x02; 32]).to_wtxid(), vec![2, 2]);
        cache.insert(TxInventoryKey::tx([0x03; 32]).to_wtxid(), vec![3, 3]);
        cache.insert(
            TxInventoryKey::tx([0x04; 32]).to_wtxid(),
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
