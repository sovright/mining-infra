//! Real-chain test fixtures, shared across crates.
//!
//! Enable with the `test-support` feature to use these from another crate.
//!
//! These bytes previously lived in `sovright-relay/tests/fixtures/`, which is a
//! test-only module: nothing outside that crate's own test targets can `use`
//! it, so five other crates reached the file by relative `include_str!` path
//! instead. That made a rename break unrelated crates with a bare path error,
//! left the file outside every consuming package root, and let the helpers that
//! parsed it drift apart. Here the fixture sits in a package root that every
//! crate already depends on, with one loader.

use crate::block_hash::{BASE_HEADER_BYTES, SOLUTION_BYTES, ZCASH_FULL_HEADER_SIZE};
use crate::compact_size::write_compact_size;

/// Mainnet block 3470793: the 1487-byte serialized header on line 1, then its
/// seven transactions in block order.
///
/// Five of the transactions are v6 (ZIP-229, version group `0x98b684d8`) and
/// two are v4, so the fixture exercises both txid rules. Synthetic bytes cannot:
/// they parse as neither.
pub const MAINNET_BLOCK_3470793: &str = include_str!("../testdata/mainnet_block_3470793.txt");

/// The consensus block hash of block 3470793 in DISPLAY (big-endian) order, as
/// Zebra's `getblockhash` and block explorers report it. The internal-order
/// value used for target comparison is its byte reversal.
pub const MAINNET_BLOCK_3470793_HASH_DISPLAY: &str =
    "000000000030976123e65211bdfb288b21b4492f56bb1a42710588ca6b8c0d98";

/// The serialized header as hex, exactly as it appears on line 1.
pub fn mainnet_header_hex() -> &'static str {
    MAINNET_BLOCK_3470793
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .expect("fixture has a header line")
}

/// The full serialized header: 140-byte header, `CompactSize(1344)`, solution.
///
/// Checks the length **and** the `fd 40 05` solution-length prefix. A corrupted
/// fixture can keep its length while losing the prefix, and a length-only check
/// would pass it through to produce a silently wrong hash.
pub fn mainnet_serialized_header() -> Vec<u8> {
    let bytes = hex::decode(mainnet_header_hex()).expect("header hex");
    assert_eq!(
        bytes.len(),
        ZCASH_FULL_HEADER_SIZE,
        "fixture line 1 is the full serialized header"
    );
    assert_eq!(
        &bytes[BASE_HEADER_BYTES..BASE_HEADER_BYTES + 3],
        &[0xfd, 0x40, 0x05],
        "the solution must carry its CompactSize(1344) prefix"
    );
    bytes
}

/// The 140-byte header and the 1344-byte Equihash solution.
pub fn mainnet_header_and_solution() -> ([u8; BASE_HEADER_BYTES], Vec<u8>) {
    let full = mainnet_serialized_header();
    let mut header = [0u8; BASE_HEADER_BYTES];
    header.copy_from_slice(&full[..BASE_HEADER_BYTES]);
    let solution = full[BASE_HEADER_BYTES + 3..].to_vec();
    assert_eq!(solution.len(), SOLUTION_BYTES);
    (header, solution)
}

/// The block's transactions, in block order.
pub fn mainnet_transactions() -> Vec<Vec<u8>> {
    MAINNET_BLOCK_3470793
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .skip(1)
        .map(|line| hex::decode(line).expect("tx hex"))
        .collect()
}

/// The full serialized block: the header, the transaction count as CompactSize,
/// then the transactions.
pub fn mainnet_raw_block() -> Vec<u8> {
    let txs = mainnet_transactions();
    let mut block = mainnet_serialized_header();
    write_compact_size(txs.len() as u64, &mut block);
    for tx in &txs {
        block.extend_from_slice(tx);
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_hash::consensus_block_hash;

    #[test]
    fn the_fixture_hashes_to_the_block_id_it_claims() {
        let mut display = consensus_block_hash(&mainnet_serialized_header());
        display.reverse();
        assert_eq!(hex::encode(display), MAINNET_BLOCK_3470793_HASH_DISPLAY);
    }

    #[test]
    fn the_fixture_carries_its_transactions() {
        let txs = mainnet_transactions();
        assert_eq!(txs.len(), 7, "block 3470793 has seven transactions");
        assert!(txs.iter().all(|tx| !tx.is_empty()));
        assert!(mainnet_raw_block().len() > mainnet_serialized_header().len());
    }
}
