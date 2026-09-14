//! Zcash block header assembly for Equihash mining

use crate::commitments::calculate_block_commitments_hash;
use crate::error::{Error, Result};
use crate::types::{EquihashHeader, GetBlockTemplateResponse, Hash256};

/// Assemble an EquihashHeader from a getblocktemplate response
///
/// # Arguments
/// * `template` - The raw getblocktemplate response from Zebra
///
/// # Returns
/// An assembled header ready for Equihash mining (nonce will be zeroed)
pub fn assemble_header(template: &GetBlockTemplateResponse) -> Result<EquihashHeader> {
    let prev_hash = Hash256::from_hex(&template.previous_block_hash)
        .map_err(|e| Error::InvalidTemplate(format!("invalid prev_hash: {}", e)))?;

    // Zebra returns every 32-byte hash in getblocktemplate -- previousblockhash
    // above, and merkleroot, chainhistoryroot, authdataroot and
    // blockcommitmentshash here -- in display order: the internal bytes, reversed.
    // `from_hex` reverses them back into the internal order the header and the
    // commitments hash are built from.
    let merkle_root = Hash256::from_hex(&template.default_roots.merkle_root)
        .map_err(|e| Error::InvalidTemplate(format!("invalid merkle_root: {}", e)))?;

    let hash_block_commitments = match (
        Hash256::from_hex(&template.default_roots.chain_history_root),
        Hash256::from_hex(&template.default_roots.auth_data_root),
    ) {
        (Ok(history_root), Ok(auth_root)) => {
            calculate_block_commitments_hash(&history_root, &auth_root)
        }
        _ => Hash256::from_hex(&template.default_roots.block_commitments_hash).map_err(|e| {
            Error::InvalidTemplate(format!("invalid block_commitments_hash: {}", e))
        })?,
    };

    let bits = u32::from_str_radix(&template.bits, 16)
        .map_err(|e| Error::InvalidTemplate(format!("invalid bits: {}", e)))?;

    // Validate timestamp fits in u32 (won't overflow until year 2106)
    if template.cur_time > u32::MAX as u64 {
        return Err(Error::InvalidTemplate(format!(
            "timestamp {} exceeds u32::MAX",
            template.cur_time
        )));
    }

    Ok(EquihashHeader {
        version: template.version,
        prev_hash,
        merkle_root,
        hash_block_commitments,
        time: template.cur_time as u32,
        bits,
        nonce: [0u8; 32],
    })
}

/// Parse the getblocktemplate `target` into a `Hash256`.
///
/// Zebra sends `target` as a big-endian 256-bit integer. `from_hex` reverses it
/// into the little-endian bytes that `Target::from_le_bytes` and `is_met_by`
/// read.
pub fn parse_target(target_hex: &str) -> Result<Hash256> {
    Hash256::from_hex(target_hex)
        .map_err(|e| Error::InvalidTemplate(format!("invalid target: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DefaultRoots;

    fn make_test_template() -> GetBlockTemplateResponse {
        GetBlockTemplateResponse {
            version: 5,
            previous_block_hash: "0".repeat(64),
            default_roots: DefaultRoots {
                merkle_root: "0".repeat(64),
                chain_history_root: "0".repeat(64),
                auth_data_root: "0".repeat(64),
                block_commitments_hash: "0".repeat(64),
            },
            transactions: vec![],
            coinbase_txn: serde_json::Value::Null,
            target: "0".repeat(64),
            height: 1000000,
            bits: "1d00ffff".to_string(),
            cur_time: 1700000000,
        }
    }

    #[test]
    fn test_assemble_header_basic() {
        let template = make_test_template();
        let header = assemble_header(&template).unwrap();

        assert_eq!(header.version, 5);
        assert_eq!(header.time, 1700000000);
        assert_eq!(header.bits, 0x1d00ffff);
    }
}
