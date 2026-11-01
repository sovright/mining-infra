//! Template builder for JD Client
//!
//! Constructs custom block templates using the Template Provider
//! and adds the pool's required coinbase output.

use crate::error::{JdClientError, Result};
use sha2::{Digest, Sha256};
use zcash_coinbase::digest;
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
        txids.push(digest::txid(coinbase).map_err(|e| {
            JdClientError::Protocol(format!(
                "invalid coinbase transaction for merkle root: {}",
                e
            ))
        })?);
        for tx in &template.transactions {
            let hash = Hash256::from_hex(&tx.hash)
                .map_err(|e| JdClientError::Protocol(format!("invalid tx hash: {}", e)))?;
            txids.push(hash.0);
        }

        Ok(merkle_root_from_txids(&txids))
    }

    /// Recompute the block commitments hash for a Coinbase-Only declaration.
    pub fn block_commitments(&self, template: &BlockTemplate, coinbase: &[u8]) -> Result<[u8; 32]> {
        let auth_data_root =
            digest::coinbase_only_auth_data_root(coinbase, template.consensus_branch_id).map_err(
                |e| {
                    JdClientError::Protocol(format!(
                        "invalid coinbase transaction for block commitments: {}",
                        e
                    ))
                },
            )?;
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

/// SHA256d, the hash of block Merkle tree nodes (not of v5+ transactions).
fn sha256d(data: &[u8]) -> [u8; 32] {
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
            next.push(sha256d(&data));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn write_compact_size(value: u64, out: &mut Vec<u8>) {
    zcash_pool_common::write_compact_size(value, out);
}

/// Split a coinbase around its outputs: bytes before the output count, the
/// outputs, and every byte after them. The shared parser handles the v4 and
/// v5/v6 field orders, so the prefix and suffix are correct for either.
fn parse_coinbase_outputs(tx: &[u8]) -> Result<CoinbaseOutputs> {
    let parsed = parse_transaction(tx)
        .map_err(|e| JdClientError::Protocol(format!("invalid coinbase transaction: {}", e)))?;
    let (start, end) = parsed.outputs_span;
    let outputs = parsed
        .outputs
        .into_iter()
        .map(|out| TxOut {
            value: out.value,
            script: out.script_pubkey,
        })
        .collect::<Vec<_>>();
    Ok((
        tx[..start].to_vec(),
        outputs.len() as u64,
        outputs,
        tx[end..].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_coinbase::digest;
    use zcash_coinbase::fixtures::{
        NU7_BRANCH_ID, TESTNET_4465026_COINBASE_AUTHDIGEST_DISPLAY, internal_from_display,
        testnet_nu7_coinbase,
    };
    use zcash_coinbase::tx_parse::parse_transaction;
    use zcash_template_provider::calculate_block_commitments_hash;
    use zcash_template_provider::types::{BlockTemplate, EquihashHeader};

    /// Long enough not to occur by chance inside the fixture coinbase, which
    /// would make `build_coinbase` return it unchanged.
    const POOL_SCRIPT: &[u8] = &[0x76, 0xa9, 0x14, 0x5a, 0x5a, 0x5a, 0x5a, 0x88, 0xac];

    /// A template whose coinbase is the real NU7 activation-block coinbase: a
    /// v6 transaction with an Ironwood action.
    fn nu7_template() -> BlockTemplate {
        BlockTemplate {
            template_id: 1,
            height: 4_465_026,
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
            coinbase: testnet_nu7_coinbase(),
            chain_history_root: Hash256([0x42; 32]),
            consensus_branch_id: NU7_BRANCH_ID,
            total_fees: 0,
        }
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
    fn block_commitments_of_a_shielded_nu7_coinbase_use_the_node_auth_digest() {
        let template = nu7_template();
        let builder = TemplateBuilder::new(vec![], 256, None);
        // Zebra and Zakura reported this auth digest; with one leaf it is the
        // auth data root.
        let auth_root = internal_from_display(TESTNET_4465026_COINBASE_AUTHDIGEST_DISPLAY);
        let expected =
            calculate_block_commitments_hash(&template.chain_history_root, &Hash256(auth_root)).0;
        assert_eq!(
            builder
                .block_commitments(&template, &template.coinbase)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn block_commitments_refuse_a_coinbase_for_another_branch() {
        let mut template = nu7_template();
        template.consensus_branch_id = 0x4dec_4df0; // NU6.1
        let builder = TemplateBuilder::new(vec![], 256, None);
        let err = builder
            .block_commitments(&template, &template.coinbase)
            .unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn rewriting_a_v6_coinbase_output_keeps_it_a_valid_transaction() {
        let template = nu7_template();
        let pool_script = POOL_SCRIPT.to_vec();
        let builder = TemplateBuilder::new(pool_script.clone(), 256, None);
        let rebuilt = builder.build_coinbase(&template).unwrap();
        assert_ne!(rebuilt, template.coinbase);

        let before = parse_transaction(&template.coinbase).unwrap();
        let after = parse_transaction(&rebuilt).unwrap();
        assert_eq!(after.outputs[0].script_pubkey, pool_script);
        assert_eq!(after.outputs[0].value, before.outputs[0].value);
        assert_eq!(after.outputs.len(), before.outputs.len());

        // Bytes outside the outputs are unchanged, including the shielded bundles.
        let (o0, o1) = before.outputs_span;
        let (n0, n1) = after.outputs_span;
        assert_eq!(rebuilt[..n0], template.coinbase[..o0]);
        assert_eq!(rebuilt[n1..], template.coinbase[o1..]);

        // zcash_primitives reads the whole result.
        digest::txid(&rebuilt).expect("rebuilt coinbase is a readable transaction");
    }

    #[test]
    fn merkle_root_of_a_coinbase_only_v6_block_is_its_zip244_txid() {
        let template = nu7_template();
        let builder = TemplateBuilder::new(POOL_SCRIPT.to_vec(), 256, None);
        let rebuilt = builder.build_coinbase(&template).unwrap();
        assert_ne!(rebuilt, template.coinbase);
        assert_eq!(
            builder.calculate_merkle_root(&template, &rebuilt).unwrap(),
            digest::txid(&rebuilt).unwrap()
        );
    }

    #[test]
    fn rewriting_an_output_changes_the_txid_but_not_the_auth_digest() {
        // ZIP 244 commits to outputs in the txid and to scriptSigs, proofs and
        // signatures in the auth digest, so the declared block commitments of a
        // rewritten coinbase equal the template coinbase's.
        let template = nu7_template();
        let builder = TemplateBuilder::new(POOL_SCRIPT.to_vec(), 256, None);
        let rebuilt = builder.build_coinbase(&template).unwrap();
        assert_ne!(
            digest::txid(&rebuilt).unwrap(),
            digest::txid(&template.coinbase).unwrap()
        );
        assert_eq!(
            builder.block_commitments(&template, &rebuilt).unwrap(),
            builder
                .block_commitments(&template, &template.coinbase)
                .unwrap()
        );
    }
}
