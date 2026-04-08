#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zcash_template_provider::assemble_header;
use zcash_template_provider::types::{DefaultRoots, GetBlockTemplateResponse};

/// Generate arbitrary GetBlockTemplateResponse-like inputs
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    chain_history_root: String,
    auth_data_root: String,
    block_commitments_hash: String,
    target: String,
    bits: String,
    height: u64,
    cur_time: u64,
}

fuzz_target!(|input: FuzzInput| {
    let template = GetBlockTemplateResponse {
        version: input.version,
        previous_block_hash: input.prev_hash,
        default_roots: DefaultRoots {
            merkle_root: input.merkle_root,
            chain_history_root: input.chain_history_root,
            auth_data_root: input.auth_data_root,
            block_commitments_hash: input.block_commitments_hash,
        },
        transactions: vec![],
        coinbase_txn: serde_json::Value::Null,
        target: input.target,
        height: input.height,
        bits: input.bits,
        cur_time: input.cur_time,
    };

    // Must never panic, only return Ok or Err
    let result = assemble_header(&template);

    // If assembly succeeded, the header should serialize to exactly 140 bytes
    if let Ok(header) = result {
        let serialized = header.serialize();
        assert_eq!(serialized.len(), 140, "header must be exactly 140 bytes");
    }
});
