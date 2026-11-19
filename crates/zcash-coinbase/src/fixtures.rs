//! Real NU7 coinbase test vectors, shared with the JD crates.
//!
//! Enable with the `test-support` feature to use these from another crate.

/// Coinbase (tx 0) of public-testnet block 4,465,026, the NU7 activation block.
/// A 6,104-byte v6 transaction with one Ironwood action, so its auth digest
/// covers real shielded authorization data, not empty-bundle sentinels.
///
/// Extracted from `sovright-p2p-ingress/tests/fixtures/testnet_nu7_4465026.hex`.
/// The txid and auth digest below come from that fixture's metadata, which was
/// cross-checked with `getblock` on Zebra 7.0.0-rc.0 and Zakura 1.6.0.
pub const TESTNET_4465026_COINBASE_HEX: &str =
    include_str!("../testdata/testnet_4465026_coinbase.hex");

/// Display (byte-reversed) txid of [`TESTNET_4465026_COINBASE_HEX`].
pub const TESTNET_4465026_COINBASE_TXID_DISPLAY: &str =
    "98ccf227cfa19e8ad89312500bf724090997443e6ae0656e33b2d5cec99bb608";

/// Display (byte-reversed) ZIP 244 auth digest of [`TESTNET_4465026_COINBASE_HEX`].
pub const TESTNET_4465026_COINBASE_AUTHDIGEST_DISPLAY: &str =
    "3daa0288e5677776d3a387e1eda4ca34c4669e8086fe695887f3ed33d26ae68d";

/// NU7 consensus branch ID (ZIP 259).
pub const NU7_BRANCH_ID: u32 = 0x7719_0AD9;

/// A minimal v5 coinbase that zcash_primitives can read: one null-prevout
/// input, one output, and empty Sapling and Orchard bundles. Synthetic, so not
/// consensus-valid; `branch_id` must be a known consensus branch.
pub fn v5_coinbase(branch_id: u32, script_sig: &[u8], output_script: &[u8]) -> Vec<u8> {
    use crate::tx_parse::push_compact_size;
    let mut tx = Vec::new();
    tx.extend_from_slice(&0x8000_0005u32.to_le_bytes());
    tx.extend_from_slice(&0x26A7_270Au32.to_le_bytes());
    tx.extend_from_slice(&branch_id.to_le_bytes());
    tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
    tx.extend_from_slice(&0u32.to_le_bytes()); // expiry_height
    push_compact_size(&mut tx, 1);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    push_compact_size(&mut tx, script_sig.len() as u64);
    tx.extend_from_slice(script_sig);
    tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    push_compact_size(&mut tx, 1);
    tx.extend_from_slice(&0u64.to_le_bytes());
    push_compact_size(&mut tx, output_script.len() as u64);
    tx.extend_from_slice(output_script);
    push_compact_size(&mut tx, 0); // Sapling spends
    push_compact_size(&mut tx, 0); // Sapling outputs
    push_compact_size(&mut tx, 0); // Orchard actions
    tx
}

pub fn testnet_nu7_coinbase() -> Vec<u8> {
    hex::decode(TESTNET_4465026_COINBASE_HEX.trim()).expect("coinbase fixture hex")
}

/// Reverse a display-order hex hash into internal byte order.
pub fn internal_from_display(display: &str) -> [u8; 32] {
    let mut bytes: [u8; 32] = hex::decode(display)
        .expect("hash hex")
        .try_into()
        .expect("32-byte hash");
    bytes.reverse();
    bytes
}
