#![no_main]
use forge_sidecar::compact::build_compact_block;
use forge_sidecar::rpc::{BlockTemplate, CoinbaseTxn, DefaultRoots};
use libfuzzer_sys::fuzz_target;

// Fuzz build_header via build_compact_block using raw bytes as hex field values.
// This takes raw bytes and interprets them as hex-encoded strings of various
// lengths, exercising edge cases in length validation and hex parsing.
fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }

    // Use first 4 bytes for version
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // Use next 4 bytes for cur_time (as u32 to avoid overflow edge cases)
    let cur_time = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;

    // Use next byte for flags
    let flags = data[8];
    let has_roots = flags & 1 != 0;
    let has_chain_history = flags & 2 != 0;
    let has_coinbase = flags & 4 != 0;

    // Use remaining bytes to generate hex strings of varying lengths
    let rest = &data[9..];
    let chunk_size = rest.len() / 4;

    let prev_hash_hex = hex::encode(&rest[..chunk_size.min(rest.len())]);
    let bits_hex = hex::encode(&rest[chunk_size.min(rest.len())..chunk_size.saturating_mul(2).min(rest.len())]);
    let merkle_hex = hex::encode(&rest[chunk_size.saturating_mul(2).min(rest.len())..chunk_size.saturating_mul(3).min(rest.len())]);
    let chain_hex = hex::encode(&rest[chunk_size.saturating_mul(3).min(rest.len())..]);

    let default_roots = if has_roots {
        Some(DefaultRoots {
            merkle_root: merkle_hex,
            block_commitments_hash: None,
            chain_history_root: if has_chain_history {
                Some(chain_hex)
            } else {
                None
            },
            auth_data_root: None,
        })
    } else {
        None
    };

    let coinbase_txn = if has_coinbase {
        Some(CoinbaseTxn {
            data: hex::encode(&rest[..chunk_size.min(rest.len())]),
        })
    } else {
        None
    };

    let template = BlockTemplate {
        version,
        previous_block_hash: prev_hash_hex,
        cur_time,
        bits: bits_hex,
        height: 100,
        transactions: vec![],
        coinbase_txn,
        default_roots,
    };

    // Must never panic
    let _ = build_compact_block(&template, 0);
});
