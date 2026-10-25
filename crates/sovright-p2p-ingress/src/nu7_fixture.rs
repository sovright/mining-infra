//! The NU7 activation-block fixture, shared by the NU7 qualification tests.
//! The raw bytes are checked against the recorded SHA-256 and consensus hash
//! before any test uses them.
use sha2::{Digest, Sha256};
use sovright_relay::{WtxId, ZCASH_FULL_HEADER_SIZE};

use crate::block::compact_block_from_raw_block;
use crate::tx_cache::{TxCache, TxCacheConfig};
use crate::wtxid::{TX_READER_BRANCH_HINT, wtxid_from_tx_bytes};

pub(super) struct Nu7Fixture {
    pub raw: Vec<u8>,
    metadata: serde_json::Value,
}

impl Nu7Fixture {
    pub fn load() -> Self {
        let raw =
            hex::decode(include_str!("../tests/fixtures/testnet_nu7_4465026.hex").trim()).unwrap();
        let metadata: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/testnet_nu7_4465026.json"))
                .unwrap();
        assert_eq!(hex::encode(Sha256::digest(&raw)), metadata["raw_sha256"]);
        assert_eq!(
            sovright_relay::consensus_block_hash_display(&raw[..ZCASH_FULL_HEADER_SIZE]),
            metadata["hash"]
        );
        Self { raw, metadata }
    }

    /// Consensus block hash, display order, as both node oracles report it.
    pub fn consensus_hash(&self) -> &str {
        self.metadata["hash"].as_str().unwrap()
    }

    /// The block's non-coinbase transaction (slot 1): v5, NU7 branch.
    pub fn v5_transaction(&self) -> Vec<u8> {
        let compact = compact_block_from_raw_block(&self.raw).unwrap();
        compact.prefilled_txs[1].tx_data.clone()
    }

    pub fn v5_wtxid(&self) -> WtxId {
        wtxid_from_tx_bytes(&self.v5_transaction(), TX_READER_BRANCH_HINT).unwrap()
    }

    /// Slot 1's txid as both node oracles report it, display order.
    pub fn v5_txid_display(&self) -> &str {
        self.metadata["transactions"][1]["txid"].as_str().unwrap()
    }
}

pub(super) fn tx_cache() -> TxCache {
    TxCache::new(TxCacheConfig {
        max_entries: 64,
        max_bytes: 1 << 20,
        max_tx_bytes: 1 << 16,
    })
}
