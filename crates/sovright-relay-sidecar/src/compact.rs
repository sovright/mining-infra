//! Build CompactBlock from Zebra block templates

use crate::rpc::BlockTemplate;
use sovright_relay::{
    AuthDigest, CompactBlock, PrefilledTx, ShortId, TxId, WtxId, zcash_block_hash,
};
use tracing::warn;

/// Equihash solution size for Zcash (n=200, k=9)
const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Build a CompactBlock from a BlockTemplate
pub fn build_compact_block(
    template: &BlockTemplate,
    nonce: u64,
) -> Result<CompactBlock, CompactBlockError> {
    // Build the block header
    let header_bytes = build_header(template)?;

    // Compute header hash for short IDs
    let header_hash = compute_header_hash(&header_bytes);

    // Prefill coinbase
    let coinbase_data = template
        .coinbase_txn
        .as_ref()
        .map(|c| hex::decode(&c.data))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("coinbase".into()))?
        .unwrap_or_default();

    let prefilled = vec![PrefilledTx {
        index: 0,
        tx_data: coinbase_data,
    }];

    // Build short IDs for transactions
    let short_ids: Vec<ShortId> = template
        .transactions
        .iter()
        .filter_map(|tx| {
            match hex::decode(&tx.hash) {
                Ok(hash_bytes) if hash_bytes.len() == 32 => {
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&hash_bytes);
                    // Zebra returns little-endian hash, reverse for txid
                    txid_bytes.reverse();
                    let txid = TxId::from_bytes(txid_bytes);
                    // Zcash v4 transactions don't have auth digest
                    let wtxid = WtxId::new(txid, AuthDigest::from_bytes([0u8; 32]));
                    Some(ShortId::compute(&wtxid, &header_hash, nonce))
                }
                _ => {
                    warn!(tx_hash = %tx.hash, "Failed to decode transaction hash, skipping");
                    None
                }
            }
        })
        .collect();

    Ok(CompactBlock::new(header_bytes, nonce, short_ids, prefilled))
}

/// Build the full block header from template
fn build_header(template: &BlockTemplate) -> Result<Vec<u8>, CompactBlockError> {
    let mut header = Vec::with_capacity(140 + 3 + EQUIHASH_SOLUTION_SIZE);

    // Version (4 bytes, little-endian)
    header.extend_from_slice(&template.version.to_le_bytes());

    // Previous block hash (32 bytes)
    let prev_hash = hex::decode(&template.previous_block_hash)
        .map_err(|_| CompactBlockError::InvalidHex("previous_block_hash".into()))?;
    if prev_hash.len() != 32 {
        return Err(CompactBlockError::InvalidLength(
            "previous_block_hash".into(),
        ));
    }
    header.extend_from_slice(&prev_hash);

    // Merkle root (32 bytes)
    let merkle_root = template
        .default_roots
        .as_ref()
        .map(|r| hex::decode(&r.merkle_root))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("merkle_root".into()))?
        .unwrap_or_else(|| vec![0u8; 32]);
    if merkle_root.len() != 32 {
        return Err(CompactBlockError::InvalidLength("merkle_root".into()));
    }
    header.extend_from_slice(&merkle_root);

    // Reserved field / final sapling root (32 bytes) - use chain history root or zeros
    let reserved = template
        .default_roots
        .as_ref()
        .and_then(|r| r.chain_history_root.as_ref())
        .map(hex::decode)
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("chain_history_root".into()))?
        .unwrap_or_else(|| vec![0u8; 32]);
    if reserved.len() != 32 {
        return Err(CompactBlockError::InvalidLength("reserved".into()));
    }
    header.extend_from_slice(&reserved);

    // Time (4 bytes, little-endian)
    if template.cur_time > u32::MAX as u64 {
        return Err(CompactBlockError::InvalidLength(format!(
            "timestamp {} exceeds u32::MAX",
            template.cur_time
        )));
    }
    header.extend_from_slice(&(template.cur_time as u32).to_le_bytes());

    // Bits (4 bytes)
    let bits =
        hex::decode(&template.bits).map_err(|_| CompactBlockError::InvalidHex("bits".into()))?;
    if bits.len() != 4 {
        return Err(CompactBlockError::InvalidLength("bits".into()));
    }
    header.extend_from_slice(&bits);

    // Nonce (32 bytes) - placeholder for mining
    header.extend_from_slice(&[0u8; 32]);

    // Equihash solution - compactSize + placeholder
    header.push(0xfd); // compactSize prefix for 1344
    header.extend_from_slice(&(EQUIHASH_SOLUTION_SIZE as u16).to_le_bytes());
    header.extend(std::iter::repeat_n(0u8, EQUIHASH_SOLUTION_SIZE));

    Ok(header)
}

/// Compute the Zcash header hash.
fn compute_header_hash(header: &[u8]) -> [u8; 32] {
    zcash_block_hash(header)
}

#[derive(Debug)]
pub enum CompactBlockError {
    InvalidHex(String),
    InvalidLength(String),
}

impl std::fmt::Display for CompactBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompactBlockError::InvalidHex(field) => write!(f, "invalid hex in field: {}", field),
            CompactBlockError::InvalidLength(field) => {
                write!(f, "invalid length for field: {}", field)
            }
        }
    }
}

impl std::error::Error for CompactBlockError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{CoinbaseTxn, DefaultRoots};

    #[test]
    fn build_compact_from_template() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "00".repeat(32),
            cur_time: 1700000000,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![],
            coinbase_txn: Some(CoinbaseTxn {
                data: "01000000010000".to_string(),
            }),
            default_roots: Some(DefaultRoots {
                merkle_root: "ab".repeat(32),
                block_commitments_hash: None,
                chain_history_root: None,
                auth_data_root: None,
            }),
        };

        let compact = build_compact_block(&template, 0).unwrap();

        // Header should be 140 + 3 + 1344 = 1487 bytes
        assert_eq!(compact.header.len(), 1487);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.short_ids.len(), 0);
    }

    #[test]
    fn build_compact_with_transactions() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "00".repeat(32),
            cur_time: 1700000000,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![crate::rpc::TemplateTransaction {
                data: "deadbeef".to_string(),
                hash: "aa".repeat(32),
                fee: 1000,
            }],
            coinbase_txn: Some(CoinbaseTxn {
                data: "01000000010000".to_string(),
            }),
            default_roots: Some(DefaultRoots {
                merkle_root: "ab".repeat(32),
                block_commitments_hash: None,
                chain_history_root: None,
                auth_data_root: None,
            }),
        };

        let compact = build_compact_block(&template, 12345).unwrap();

        assert_eq!(compact.prefilled_txs.len(), 1); // coinbase
        assert_eq!(compact.short_ids.len(), 1); // 1 transaction
    }
}
