#![no_main]
use sovright_relay_sidecar::compact::build_compact_block;
use sovright_relay_sidecar::rpc::{BlockTemplate, CoinbaseTxn, DefaultRoots};
use libfuzzer_sys::fuzz_target;

// Fuzz build_header via build_compact_block, choosing each header field's byte
// length independently so a fully valid header is reachable as well as the
// malformed ones. Cutting the input into equal chunks cannot reach a valid
// header at all: previousblockhash has to be 32 bytes and bits has to be 4.
//
// Layout, kept simple so a seed can be written by hand:
//
//   0..4   version, little-endian
//   4..8   curtime, little-endian
//   8      flags: bit0 defaultroots, bit1 chainhistoryroot, bit2 coinbasetxn,
//          bit3 blockcommitmentshash
//   9      previousblockhash length in bytes, modulo 65
//   10     merkleroot length
//   11     blockcommitmentshash length
//   12     bits length
//   13     chainhistoryroot length
//   14..   the bytes the fields are cut from, in that order; the coinbase takes
//          whatever is left
//
// Each field is hex-encoded, so a 32-byte cut becomes the 64 characters the
// parser accepts; a length past the end of the payload takes only what is left,
// which keeps the length checks exercised.
fuzz_target!(|data: &[u8]| {
    if data.len() < 14 {
        return;
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let cur_time = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;

    let flags = data[8];
    let has_roots = flags & 1 != 0;
    let has_chain_history = flags & 2 != 0;
    let has_coinbase = flags & 4 != 0;
    let has_commitments = flags & 8 != 0;

    let mut payload = &data[14..];
    let mut take_hex = |len_byte: u8| {
        let len = ((len_byte as usize) % 65).min(payload.len());
        let (field, rest) = payload.split_at(len);
        payload = rest;
        hex::encode(field)
    };
    let prev_hash_hex = take_hex(data[9]);
    let merkle_hex = take_hex(data[10]);
    let commitments_hex = take_hex(data[11]);
    let bits_hex = take_hex(data[12]);
    let chain_hex = take_hex(data[13]);
    let coinbase_hex = hex::encode(payload);

    let default_roots = if has_roots {
        Some(DefaultRoots {
            merkle_root: merkle_hex,
            block_commitments_hash: if has_commitments {
                Some(commitments_hex)
            } else {
                None
            },
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
        Some(CoinbaseTxn { data: coinbase_hex })
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
