//! Template builder for JD Client
//!
//! Constructs custom block templates using the Template Provider
//! and adds the pool's required coinbase output.

use crate::error::{JdClientError, Result};
use sha2::{Digest, Sha256};
use zcash_coinbase::auth_digest::{compute_auth_data_root, compute_coinbase_auth_digest};
use zcash_coinbase::tx_parse::parse_transaction;
use zcash_template_provider::calculate_block_commitments_hash;
use zcash_template_provider::types::{BlockTemplate, Hash256};

struct TxOut {
    value: u64,
    script: Vec<u8>,
}

type CoinbaseOutputs = (Vec<u8>, u64, Vec<TxOut>, Vec<u8>);

/// Template builder that adds pool coinbase requirements
pub struct TemplateBuilder {
    /// Pool's required coinbase output script
    pool_coinbase_output: Vec<u8>,
    /// Maximum additional coinbase size allowed
    max_additional_size: u32,
    /// Optional miner payout address
    miner_payout_address: Option<String>,
}

impl TemplateBuilder {
    /// Create a new template builder
    pub fn new(
        pool_coinbase_output: Vec<u8>,
        max_additional_size: u32,
        miner_payout_address: Option<String>,
    ) -> Self {
        Self {
            pool_coinbase_output,
            max_additional_size,
            miner_payout_address,
        }
    }

    /// Build a custom coinbase transaction from a template
    ///
    /// For Phase 4 MVP, we use the template's coinbase directly.
    /// In production, we'd construct a proper coinbase with:
    /// 1. Pool's required output (for payout)
    /// 2. Miner's optional output
    /// 3. Funding stream outputs (handled by Zebra)
    pub fn build_coinbase(&self, template: &BlockTemplate) -> Result<Vec<u8>> {
        // Validate size
        let additional_size = self.pool_coinbase_output.len() as u32;
        if additional_size > self.max_additional_size {
            return Err(JdClientError::Protocol(format!(
                "Pool output too large: {} > {}",
                additional_size, self.max_additional_size
            )));
        }

        if self.pool_coinbase_output.is_empty() {
            return Ok(template.coinbase.clone());
        }

        if contains_script(&template.coinbase, &self.pool_coinbase_output) {
            return Ok(template.coinbase.clone());
        }

        let (prefix, mut vout_count, mut outputs, suffix) =
            parse_coinbase_outputs(&template.coinbase)?;

        if outputs.is_empty() {
            return Err(JdClientError::Protocol(
                "Template coinbase has no outputs".to_string(),
            ));
        }

        outputs[0].script = self.pool_coinbase_output.clone();

        if let Some(address) = &self.miner_payout_address {
            let miner_script = parse_script_hex(address)?;
            if !outputs.iter().any(|out| out.script == miner_script) {
                if outputs[0].value == 0 {
                    return Err(JdClientError::Protocol(
                        "Coinbase output value is zero; cannot split miner payout".to_string(),
                    ));
                }
                outputs[0].value -= 1;
                outputs.push(TxOut {
                    value: 1,
                    script: miner_script,
                });
                vout_count += 1;
            }
        }

        let mut rebuilt =
            Vec::with_capacity(template.coinbase.len() + self.pool_coinbase_output.len());
        rebuilt.extend_from_slice(&prefix);
        write_compact_size(vout_count, &mut rebuilt);
        for output in outputs {
            rebuilt.extend_from_slice(&output.value.to_le_bytes());
            write_compact_size(output.script.len() as u64, &mut rebuilt);
            rebuilt.extend_from_slice(&output.script);
        }
        rebuilt.extend_from_slice(&suffix);

        Ok(rebuilt)
    }

    /// Calculate merkle root for a modified coinbase
    ///
    /// For MVP, we use the template's merkle root directly
    /// since we're not modifying the coinbase.
    pub fn calculate_merkle_root(
        &self,
        template: &BlockTemplate,
        coinbase: &[u8],
    ) -> Result<[u8; 32]> {
        if coinbase == template.coinbase {
            return Ok(template.header.merkle_root.0);
        }

        let mut txids = Vec::with_capacity(1 + template.transactions.len());
        txids.push(compute_txid(coinbase));
        for tx in &template.transactions {
            let hash = Hash256::from_hex(&tx.hash)
                .map_err(|e| JdClientError::Protocol(format!("invalid tx hash: {}", e)))?;
            txids.push(hash.0);
        }

        Ok(merkle_root_from_txids(&txids))
    }

    /// Recompute the block commitments hash for a Coinbase-Only declaration.
    pub fn block_commitments(&self, template: &BlockTemplate, coinbase: &[u8]) -> Result<[u8; 32]> {
        let parsed = parse_transaction(coinbase).map_err(|e| {
            JdClientError::Protocol(format!(
                "invalid coinbase transaction for block commitments: {}",
                e
            ))
        })?;
        if parsed.inputs.is_empty() {
            return Err(JdClientError::Protocol(
                "coinbase has no transparent inputs for block commitments".to_string(),
            ));
        }

        let mut script_sigs = Vec::new();
        for input in parsed.inputs {
            script_sigs.extend_from_slice(&input.script_sig);
        }

        let coinbase_digest =
            compute_coinbase_auth_digest(&script_sigs, template.consensus_branch_id);
        let auth_data_root = compute_auth_data_root(&[coinbase_digest]);
        Ok(
            calculate_block_commitments_hash(
                &template.chain_history_root,
                &Hash256(auth_data_root),
            )
            .0,
        )
    }

    /// Return the template's copied block commitments hash.
    pub fn template_block_commitments(&self, template: &BlockTemplate) -> [u8; 32] {
        template.header.hash_block_commitments.0
    }

    /// Update pool coinbase output (when receiving new token)
    pub fn set_pool_output(&mut self, output: Vec<u8>, max_size: u32) {
        self.pool_coinbase_output = output;
        self.max_additional_size = max_size;
    }

    /// Get the current pool coinbase output
    pub fn pool_coinbase_output(&self) -> &[u8] {
        &self.pool_coinbase_output
    }

    /// Get the maximum additional size allowed
    pub fn max_additional_size(&self) -> u32 {
        self.max_additional_size
    }

    /// Get the miner payout address if set
    pub fn miner_payout_address(&self) -> Option<&str> {
        self.miner_payout_address.as_deref()
    }
}

fn contains_script(coinbase: &[u8], script: &[u8]) -> bool {
    if script.is_empty() {
        return true;
    }
    coinbase.windows(script.len()).any(|w| w == script)
}

fn parse_script_hex(address: &str) -> Result<Vec<u8>> {
    if let Some(hex_script) = address.strip_prefix("hex:") {
        hex::decode(hex_script)
            .map_err(|e| JdClientError::Protocol(format!("invalid script hex: {}", e)))
    } else {
        Err(JdClientError::Protocol(
            "miner payout address must be hex:<script>".to_string(),
        ))
    }
}

fn compute_txid(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&hash2);
    txid
}

fn merkle_root_from_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }

    let mut layer: Vec<[u8; 32]> = txids.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                left
            };
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&left);
            data[32..].copy_from_slice(&right);
            next.push(compute_txid(&data));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn read_compact_size(data: &[u8], cursor: &mut usize) -> Result<u64> {
    zcash_pool_common::read_compact_size(data, cursor)
        .map_err(|e| JdClientError::Protocol(e.to_string()))
}

fn write_compact_size(value: u64, out: &mut Vec<u8>) {
    zcash_pool_common::write_compact_size(value, out);
}

fn parse_coinbase_outputs(tx: &[u8]) -> Result<CoinbaseOutputs> {
    let mut cursor = 0usize;
    if tx.len() < 4 {
        return Err(JdClientError::Protocol("coinbase too short".to_string()));
    }
    let version = u32::from_le_bytes([tx[0], tx[1], tx[2], tx[3]]);
    cursor += 4;
    if (version & 0x8000_0000) != 0 {
        if cursor + 4 > tx.len() {
            return Err(JdClientError::Protocol(
                "coinbase missing version group id".to_string(),
            ));
        }
        cursor += 4;
    }

    let vin_count = read_compact_size(tx, &mut cursor)?;
    for _ in 0..vin_count {
        if cursor + 36 > tx.len() {
            return Err(JdClientError::Protocol(
                "coinbase input out of bounds".to_string(),
            ));
        }
        cursor += 36;
        let script_len = read_compact_size(tx, &mut cursor)? as usize;
        if cursor + script_len + 4 > tx.len() {
            return Err(JdClientError::Protocol(
                "coinbase scriptSig out of bounds".to_string(),
            ));
        }
        cursor += script_len;
        cursor += 4;
    }

    let vout_count_offset = cursor;
    let vout_count = read_compact_size(tx, &mut cursor)?;

    // Cap pre-allocation to remaining data length to prevent OOM from malicious compact_size
    let max_outputs = (tx.len() - cursor) / 9; // minimum output is 8 (value) + 1 (script_len)
    let mut outputs = Vec::with_capacity((vout_count as usize).min(max_outputs));
    for _ in 0..vout_count {
        if cursor + 8 > tx.len() {
            return Err(JdClientError::Protocol(
                "coinbase output value out of bounds".to_string(),
            ));
        }
        let value = u64::from_le_bytes([
            tx[cursor],
            tx[cursor + 1],
            tx[cursor + 2],
            tx[cursor + 3],
            tx[cursor + 4],
            tx[cursor + 5],
            tx[cursor + 6],
            tx[cursor + 7],
        ]);
        cursor += 8;

        let script_len = read_compact_size(tx, &mut cursor)? as usize;
        if cursor + script_len > tx.len() {
            return Err(JdClientError::Protocol(
                "coinbase output script out of bounds".to_string(),
            ));
        }
        let script = tx[cursor..cursor + script_len].to_vec();
        cursor += script_len;
        outputs.push(TxOut { value, script });
    }

    let prefix = tx[..vout_count_offset].to_vec();
    let suffix = tx[cursor..].to_vec();
    Ok((prefix, vout_count, outputs, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_coinbase::auth_digest::{compute_auth_data_root, compute_coinbase_auth_digest};
    use zcash_coinbase::tx_parse::parse_transaction;
    use zcash_template_provider::calculate_block_commitments_hash;
    use zcash_template_provider::types::{BlockTemplate, EquihashHeader};

    fn minimal_coinbase_with_script_sig(script_sig: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&5u32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        write_compact_size(script_sig.len() as u64, &mut tx);
        tx.extend_from_slice(script_sig);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&50_0000_0000u64.to_le_bytes());
        tx.push(1);
        tx.push(0x51);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn template_for_commitment_test(coinbase: Vec<u8>) -> BlockTemplate {
        BlockTemplate {
            template_id: 1,
            height: 2_000_000,
            header: EquihashHeader {
                version: 5,
                prev_hash: Hash256([0xaa; 32]),
                merkle_root: Hash256([0xbb; 32]),
                hash_block_commitments: Hash256([0xcc; 32]),
                time: 1_700_000_000,
                bits: 0x1d00ffff,
                nonce: [0; 32],
            },
            target: Hash256([0xff; 32]),
            transactions: vec![],
            coinbase,
            chain_history_root: Hash256([0x42; 32]),
            consensus_branch_id: 0xc8e7_1055,
            total_fees: 0,
        }
    }

    fn expected_commitments_for_coinbase(template: &BlockTemplate, coinbase: &[u8]) -> [u8; 32] {
        let parsed = parse_transaction(coinbase).unwrap();
        let mut script_sigs = Vec::new();
        for input in parsed.inputs {
            script_sigs.extend_from_slice(&input.script_sig);
        }
        let coinbase_digest =
            compute_coinbase_auth_digest(&script_sigs, template.consensus_branch_id);
        let auth_root = compute_auth_data_root(&[coinbase_digest]);
        calculate_block_commitments_hash(&template.chain_history_root, &Hash256(auth_root)).0
    }

    #[test]
    fn test_template_builder_creation() {
        let builder = TemplateBuilder::new(
            vec![0x76, 0xa9], // P2PKH prefix
            256,
            None,
        );

        assert_eq!(builder.max_additional_size(), 256);
        assert_eq!(builder.pool_coinbase_output(), &[0x76, 0xa9]);
        assert!(builder.miner_payout_address().is_none());
    }

    #[test]
    fn test_template_builder_with_miner_address() {
        let builder =
            TemplateBuilder::new(vec![0x76, 0xa9], 256, Some("t1exampleaddress".to_string()));

        assert_eq!(builder.miner_payout_address(), Some("t1exampleaddress"));
    }

    #[test]
    fn test_set_pool_output() {
        let mut builder = TemplateBuilder::new(vec![], 0, None);

        builder.set_pool_output(vec![0x01, 0x02, 0x03], 512);

        assert_eq!(builder.pool_coinbase_output(), &[0x01, 0x02, 0x03]);
        assert_eq!(builder.max_additional_size(), 512);
    }

    #[test]
    fn recomputes_coinbase_only_block_commitments_from_declared_coinbase() {
        let template = template_for_commitment_test(minimal_coinbase_with_script_sig(&[
            0x04, 0xff, 0xff, 0x10, 0x1d,
        ]));
        let builder = TemplateBuilder::new(vec![0x52], 256, None);
        let coinbase = builder.build_coinbase(&template).unwrap();

        let expected = expected_commitments_for_coinbase(&template, &coinbase);
        assert_ne!(expected, template.header.hash_block_commitments.0);
        assert_eq!(
            builder.block_commitments(&template, &coinbase).unwrap(),
            expected
        );
    }
}
