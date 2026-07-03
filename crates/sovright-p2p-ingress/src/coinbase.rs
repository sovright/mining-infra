//! Best-effort extraction of a block's coinbase miner payout script.
//!
//! On every block the ingress HEARS, we parse the coinbase transaction and log
//! the miner's payout `scriptPubKey` as hex. This identifies which mining pool
//! mined the block, and is needed to attribute ORPHAN blocks to pools: Zebra
//! will not serve non-canonical blocks after the fact, so the coinbase must be
//! captured at hear-time.
//!
//! JOIN KEY (load-bearing): the downstream join key is the coinbase output's
//! raw `scriptPubKey` in hex, with NO address (bs58) encoding. Zebra's
//! `getblock` verbosity-2 reports the SAME `scriptPubKey.hex` for canonical
//! blocks, so the ingress and the canonical-chain pool map share this identity
//! directly. The MINER output is the LARGEST-value coinbase output; the smaller
//! outputs are protocol funding streams (dev fund / funding streams).
//!
//! This is best-effort telemetry: ANY failure (short payload, unparseable tx,
//! no transparent outputs) returns `None` and MUST NEVER fail or slow the
//! block-relay path.

use std::io::Cursor;

use sovright_relay::ZCASH_FULL_HEADER_SIZE;

use crate::wire::decode_compact_size;
use crate::wtxid::SOVRIGHT_P2P_CONSENSUS_BRANCH_ID;
use zcash_primitives::transaction::Transaction;

/// Parse the coinbase of a raw Zcash block payload and return the hex-encoded
/// `scriptPubKey` of its largest-value transparent output (the miner payout).
///
/// Returns `None` on any failure: payload shorter than the header, unreadable
/// tx count, coinbase that will not parse, or a coinbase with no transparent
/// outputs. Never panics.
pub(crate) fn coinbase_miner_script(block_payload: &[u8]) -> Option<String> {
    // Skip the block header, then read the transaction count. The coinbase is
    // the first transaction immediately after the count.
    let mut cursor = ZCASH_FULL_HEADER_SIZE;
    let tx_count = decode_compact_size(block_payload, &mut cursor).ok()?;
    if tx_count == 0 {
        return None;
    }
    let coinbase_bytes = block_payload.get(cursor..)?;

    // `Transaction::read` reads exactly ONE transaction (the coinbase) and
    // stops, so handing it the rest of the block after the header is fine. The
    // branch id is ignored for the transparent portion we read here.
    let mut reader = Cursor::new(coinbase_bytes);
    let tx = Transaction::read(&mut reader, SOVRIGHT_P2P_CONSENSUS_BRANCH_ID).ok()?;

    // The miner payout is the largest-value transparent output. Smaller outputs
    // are protocol funding streams.
    let bundle = tx.transparent_bundle()?;
    let miner_out = bundle.vout.iter().max_by_key(|out| out.value())?;
    Some(hex::encode(&miner_out.script_pubkey().0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::encode_compact_size;

    const OVERWINTERED_FLAG: u32 = 1 << 31;
    const TX_V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
    const NU5_CONSENSUS_BRANCH_ID: u32 = 0xC2D6_D0B4;

    /// Build a minimal but valid v5 coinbase transaction with two transparent
    /// outputs: a large "miner" output and a small "funding stream" output,
    /// each carrying a distinct script. `zcash_primitives::Transaction::read`
    /// parses this into a transparent bundle with both outputs.
    fn v5_coinbase_two_outputs(
        miner_value: u64,
        miner_script: &[u8],
        funding_value: u64,
        funding_script: &[u8],
    ) -> Vec<u8> {
        let mut tx = Vec::new();
        // v5 header + version group + consensus branch id + lock_time + expiry.
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 5).to_le_bytes());
        tx.extend_from_slice(&TX_V5_VERSION_GROUP_ID.to_le_bytes());
        tx.extend_from_slice(&NU5_CONSENSUS_BRANCH_ID.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx.extend_from_slice(&0u32.to_le_bytes()); // expiry_height

        // Transparent inputs: a single coinbase input (null prevout).
        encode_compact_size(1, &mut tx);
        tx.extend_from_slice(&[0u8; 32]); // prevout hash
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        encode_compact_size(3, &mut tx); // script_sig (BIP34 height-ish filler)
        tx.extend_from_slice(&[0x03, 0x01, 0x02]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence

        // Transparent outputs: funding stream first, then the larger miner
        // output, to prove the parser picks by MAX value, not position.
        encode_compact_size(2, &mut tx);
        tx.extend_from_slice(&funding_value.to_le_bytes());
        encode_compact_size(funding_script.len() as u64, &mut tx);
        tx.extend_from_slice(funding_script);
        tx.extend_from_slice(&miner_value.to_le_bytes());
        encode_compact_size(miner_script.len() as u64, &mut tx);
        tx.extend_from_slice(miner_script);

        // Empty sapling + orchard bundles.
        encode_compact_size(0, &mut tx); // sapling spends
        encode_compact_size(0, &mut tx); // sapling outputs
        encode_compact_size(0, &mut tx); // orchard actions
        tx
    }

    fn block_from_coinbase(coinbase: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; ZCASH_FULL_HEADER_SIZE];
        encode_compact_size(1, &mut block);
        block.extend_from_slice(coinbase);
        block
    }

    #[test]
    fn extracts_largest_value_output_script() {
        let miner_script = [0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x88, 0xac];
        let funding_script = [0xa9, 0x14, 0x01, 0x02, 0x87];
        let coinbase =
            v5_coinbase_two_outputs(625_000_000, &miner_script, 156_250_000, &funding_script);
        let block = block_from_coinbase(&coinbase);

        let script = coinbase_miner_script(&block).expect("coinbase must parse");
        assert_eq!(script, hex::encode(miner_script));
    }

    #[test]
    fn ignores_output_order_when_picking_max() {
        // Same as above but with the miner output SMALLER than the funding one:
        // the funding script (now the largest) must be the one returned.
        let small_script = [0x11, 0x22];
        let large_script = [0x33, 0x44, 0x55];
        let coinbase = v5_coinbase_two_outputs(10, &small_script, 999, &large_script);
        let block = block_from_coinbase(&coinbase);

        let script = coinbase_miner_script(&block).expect("coinbase must parse");
        assert_eq!(script, hex::encode(large_script));
    }

    #[test]
    fn short_payload_returns_none_without_panicking() {
        assert_eq!(coinbase_miner_script(&[]), None);
        assert_eq!(coinbase_miner_script(&[0u8; 10]), None);
        // Header present but truncated right after: no tx count / coinbase.
        assert_eq!(
            coinbase_miner_script(&vec![0u8; ZCASH_FULL_HEADER_SIZE]),
            None
        );
    }

    #[test]
    fn coinbase_without_transparent_outputs_returns_none() {
        // A v5 tx with zero transparent inputs AND outputs has NO transparent
        // bundle, so there is no miner output to report.
        let mut tx = Vec::new();
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 5).to_le_bytes());
        tx.extend_from_slice(&TX_V5_VERSION_GROUP_ID.to_le_bytes());
        tx.extend_from_slice(&NU5_CONSENSUS_BRANCH_ID.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx.extend_from_slice(&0u32.to_le_bytes()); // expiry_height
        encode_compact_size(0, &mut tx); // no transparent inputs
        encode_compact_size(0, &mut tx); // no transparent outputs
        encode_compact_size(0, &mut tx); // sapling spends
        encode_compact_size(0, &mut tx); // sapling outputs
        encode_compact_size(0, &mut tx); // orchard actions

        let block = block_from_coinbase(&tx);
        assert_eq!(coinbase_miner_script(&block), None);
    }

    #[test]
    fn zero_tx_count_returns_none() {
        let mut block = vec![0u8; ZCASH_FULL_HEADER_SIZE];
        encode_compact_size(0, &mut block);
        assert_eq!(coinbase_miner_script(&block), None);
    }
}
