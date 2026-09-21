#![no_main]
use arbitrary::Arbitrary;
use sovright_relay_sidecar::compact::build_compact_block;
use sovright_relay_sidecar::rpc::{BlockTemplate, CoinbaseTxn, DefaultRoots, TemplateTransaction};
use libfuzzer_sys::fuzz_target;

/// Fuzzable block template that generates arbitrary strings for hex fields.
/// This exercises all hex::decode() paths and length validation in
/// build_compact_block() and build_header().
///
/// The header fields stay raw strings, which is where malformed hex keeps being
/// exercised. A transaction's txid and auth digest are hex-encoded from bytes
/// instead: as raw strings they are valid 64-character hex only by chance, and
/// no committed seed reached the short-ID path or the auth-digest parse. A
/// 32-byte vector reaches both; a shorter one still hits the length check.
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
    has_block_commitments_hash: bool,
    block_commitments_hash: String,
    nonce: u64,
    tx_count: u8,
    tx_hashes: Vec<Vec<u8>>,
    tx_authdigests: Vec<Option<Vec<u8>>>,
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
                block_commitments_hash: if self.has_block_commitments_hash {
                    Some(self.block_commitments_hash.clone())
                } else {
                    None
                },
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
            .enumerate()
            .map(|(i, h)| TemplateTransaction {
                data: String::new(),
                hash: hex::encode(h),
                authdigest: self
                    .tx_authdigests
                    .get(i)
                    .cloned()
                    .flatten()
                    .map(hex::encode),
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
