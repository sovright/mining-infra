#![no_main]
use arbitrary::Arbitrary;
use forge_sidecar::compact::build_compact_block;
use forge_sidecar::rpc::{BlockTemplate, CoinbaseTxn, DefaultRoots, TemplateTransaction};
use libfuzzer_sys::fuzz_target;

/// Fuzzable block template that generates arbitrary strings for hex fields.
/// This exercises all hex::decode() paths and length validation in
/// build_compact_block() and build_header().
#[derive(Debug, Arbitrary)]
struct FuzzBlockTemplate {
    version: u32,
    previous_block_hash: String,
    cur_time: u64,
    bits: String,
    height: u64,
    has_coinbase: bool,
    coinbase_data: String,
    has_roots: bool,
    merkle_root: String,
    has_chain_history_root: bool,
    chain_history_root: String,
    nonce: u64,
    tx_count: u8,
    tx_hashes: Vec<String>,
}

impl FuzzBlockTemplate {
    fn to_block_template(&self) -> BlockTemplate {
        let coinbase_txn = if self.has_coinbase {
            Some(CoinbaseTxn {
                data: self.coinbase_data.clone(),
            })
        } else {
            None
        };

        let default_roots = if self.has_roots {
            Some(DefaultRoots {
                merkle_root: self.merkle_root.clone(),
                block_commitments_hash: None,
                chain_history_root: if self.has_chain_history_root {
                    Some(self.chain_history_root.clone())
                } else {
                    None
                },
                auth_data_root: None,
            })
        } else {
            None
        };

        let transactions: Vec<TemplateTransaction> = self
            .tx_hashes
            .iter()
            .take(self.tx_count as usize)
            .map(|h| TemplateTransaction {
                data: String::new(),
                hash: h.clone(),
                fee: 0,
            })
            .collect();

        BlockTemplate {
            version: self.version,
            previous_block_hash: self.previous_block_hash.clone(),
            cur_time: self.cur_time,
            bits: self.bits.clone(),
            height: self.height,
            transactions,
            coinbase_txn,
            default_roots,
        }
    }
}

fuzz_target!(|input: FuzzBlockTemplate| {
    let template = input.to_block_template();
    // Must never panic - should return Ok or Err gracefully
    let _ = build_compact_block(&template, input.nonce);
});
