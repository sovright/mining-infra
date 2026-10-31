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
//! no transparent outputs) leaves a field `None` and MUST NEVER fail or slow the
//! block-relay path.
//!
//! A coinbase is whatever the peer sent, and reading one can cost as much as
//! reading a block, so none of this runs on an async worker. With a relay bridge
//! the fields come from the coinbase the strict reader already read while
//! preparing the forward, so a body that fails validation has none, and neither
//! does a copy of a known block, which is not read at all. Without a bridge,
//! [`coinbase_telemetry_off_workers`] reads it, one block at a time. Either way
//! they arrive after `p2p_block_received`, on a `p2p_block_coinbase` line.

use std::io::Cursor;

use sovright_relay::ZCASH_FULL_HEADER_SIZE;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::relay_bridge::run_holding_permit;
use crate::wire::decode_compact_size;
use crate::wtxid::TX_READER_BRANCH_HINT;
use zcash_primitives::transaction::Transaction;

/// Coinbases read at once for sessions with no relay bridge. Peer tasks each wait
/// for their own delivery, so `max_peers` limits how many queue here.
static OBSERVATION_PERMITS: Semaphore = Semaphore::const_new(1);

/// What a block's coinbase says about who mined it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CoinbaseTelemetry {
    pub(crate) miner_script: Option<String>,
    pub(crate) miner_tag: Option<String>,
}

impl CoinbaseTelemetry {
    pub(crate) fn of(coinbase: &Transaction) -> Self {
        Self {
            miner_script: miner_script(coinbase),
            miner_tag: miner_tag(coinbase),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.miner_script.is_none() && self.miner_tag.is_none()
    }
}

/// Read the first transaction of a raw block payload. `Transaction::read` reads
/// exactly ONE transaction and stops, so handing it the rest of the block after
/// the header is fine. The branch id is ignored for the transparent portion read
/// here. `None` on any failure: payload shorter than the header, unreadable tx
/// count, or a coinbase that will not parse. Never panics.
fn read_coinbase(block_payload: &[u8]) -> Option<Transaction> {
    let mut cursor = ZCASH_FULL_HEADER_SIZE;
    let tx_count = decode_compact_size(block_payload, &mut cursor).ok()?;
    if tx_count == 0 {
        return None;
    }
    let coinbase_bytes = block_payload.get(cursor..)?;
    Transaction::read(&mut Cursor::new(coinbase_bytes), TX_READER_BRANCH_HINT).ok()
}

fn coinbase_telemetry(block_payload: &[u8]) -> CoinbaseTelemetry {
    read_coinbase(block_payload)
        .as_ref()
        .map(CoinbaseTelemetry::of)
        .unwrap_or_default()
}

/// [`CoinbaseTelemetry`] for a block no forward will parse, off the async workers.
/// The permit stays with the read until it ends, even if the caller is cancelled.
pub(crate) async fn coinbase_telemetry_off_workers(block_payload: &[u8]) -> CoinbaseTelemetry {
    let Ok(permit) = OBSERVATION_PERMITS.acquire().await else {
        return CoinbaseTelemetry::default();
    };
    let block = block_payload.to_vec();
    match run_holding_permit(permit, move || coinbase_telemetry(&block)).await {
        Ok((telemetry, _permit)) => telemetry,
        Err(error) => {
            warn!(%error, "Coinbase telemetry read did not finish");
            CoinbaseTelemetry::default()
        }
    }
}

/// The hex-encoded `scriptPubKey` of a coinbase's largest-value transparent
/// output (the miner payout). `None` for a coinbase with no transparent outputs.
fn miner_script(coinbase: &Transaction) -> Option<String> {
    // The miner payout is the largest-value transparent output. Smaller outputs
    // are protocol funding streams.
    let bundle = coinbase.transparent_bundle()?;
    let miner_out = bundle.vout.iter().max_by_key(|out| out.value())?;
    Some(hex::encode(&miner_out.script_pubkey().0.0))
}

/// Maximum bytes of coinbase text retained. Pool tags are short; the cap bounds
/// what miner-chosen input can cost downstream regardless of what a block claims.
pub(crate) const MAX_COINBASE_TEXT: usize = 64;

/// Parse the coinbase of a raw Zcash block payload and return the printable
/// ASCII of its input script (the "coinbase tag"), truncated to
/// `MAX_COINBASE_TEXT`.
///
/// Pools stamp an identifying string here ("2Miners https://2miners.com",
/// "/NiceHash/"). It is the only signal that separates miners who take their
/// reward SHIELDED, since those blocks carry no payout address of their own and
/// all collapse onto the protocol funding-stream script.
///
/// SECURITY: this value is chosen by the miner and flows toward a public page.
/// Non-printable bytes are dropped and the result is capped HERE, at the parse
/// boundary, so nothing downstream has to trust the length or the contents. The
/// consumer maps it to a curated identifier and never renders it raw.
///
/// Returns `None` on any failure and on a script with no printable bytes. Never
/// panics: this is best-effort telemetry on the block-relay hot path.
fn miner_tag(coinbase: &Transaction) -> Option<String> {
    let bundle = coinbase.transparent_bundle()?;
    let input = bundle.vin.first()?;
    // NB: the `script_sig` FIELD is #[deprecated] in zcash_transparent 0.9.0
    // (bundle.rs:229); the accessor is not. Task 9 runs clippy with -D warnings,
    // so the field form fails the build. The accessor returns `&Script`, whose
    // own inner field is `zcash_script::script::Code`, itself `pub Vec<u8>` --
    // hence `.0.0`, matching the `.script_pubkey().0.0` pattern already used
    // above.
    let script = &input.script_sig().0.0;

    // Every valid coinbase scriptSig begins with a mandatory BIP34 push of the
    // block height (push-opcode byte N, followed by N height bytes). Skip it
    // before scanning for a pool tag: height bytes are essentially random and
    // occasionally land in the printable ASCII range, which would otherwise
    // leak a stray leading character into the tag. Anything that does not look
    // like a well-formed push (short script, out-of-range length byte) is left
    // as-is rather than rejected -- this is best-effort telemetry, not a
    // consensus check.
    let tag_bytes = match script.first() {
        Some(&len) if (1..=75).contains(&len) && script.len() > len as usize => {
            &script[1 + len as usize..]
        }
        _ => &script[..],
    };

    // Printable ASCII only. Filtering to ASCII also guarantees the result is
    // valid UTF-8 no matter where the byte cap lands.
    let text: String = tag_bytes
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b))
        .take(MAX_COINBASE_TEXT)
        .map(|b| *b as char)
        .collect();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn coinbase_miner_script(block_payload: &[u8]) -> Option<String> {
        coinbase_telemetry(block_payload).miner_script
    }

    fn coinbase_text(block_payload: &[u8]) -> Option<String> {
        coinbase_telemetry(block_payload).miner_tag
    }

    #[tokio::test]
    async fn the_off_worker_read_gives_the_same_answer() {
        let block = zcash_pool_common::fixtures::mainnet_raw_block();
        let telemetry = coinbase_telemetry_off_workers(&block).await;
        assert!(telemetry.miner_script.is_some());
        assert_eq!(telemetry, coinbase_telemetry(&block));
    }

    #[tokio::test]
    async fn an_unreadable_coinbase_gives_empty_telemetry_off_the_workers() {
        assert_eq!(
            coinbase_telemetry_off_workers(&[0u8; 10]).await,
            CoinbaseTelemetry::default()
        );
    }
    use crate::wire::encode_compact_size;

    const OVERWINTERED_FLAG: u32 = 1 << 31;
    const TX_V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
    const NU5_CONSENSUS_BRANCH_ID: u32 = 0xC2D6_D0B4;

    /// Real mainnet Ironwood coinbase, block 3431157. Post-NU6.3 coinbases are
    /// v6 (version_group_id 0xD884B698); zcash_primitives 0.28 defined its V6 as
    /// 0xFFFFFFFF (a different Nu7/ZFuture format) and so REJECTED every real
    /// coinbase. Transaction::read returned Err, coinbase_miner_script returned
    /// None, and 1097 of 1098 orphan-ledger rows carried no miner_script -- which
    /// is why the dashboard showed 3 orphans but an EMPTY "revenue lost by pool".
    /// This fixture fails if that regresses.
    const REAL_MAINNET_V6_COINBASE_HEX: &str = "0600008098b684d85b16a53700000000f55a3400010000000000000000000000000000000000\
         000000000000000000000000000000ffffffff0903f55a3404f09fa693ffffffff02d8047607\
         000000001976a91425db9091e9786867e536f70089a5102523ab1d6a88ac20bcbe0000000000\
         17a914c20cd5bdf7964ca61764db66bc2531b1792a084d8700000000";

    /// The largest transparent output's script, per Zebra's own parse of the same
    /// transaction. It is ViaBTC's payout script in pool_labels.json.
    const REAL_MAINNET_V6_MINER_SCRIPT: &str = "76a91425db9091e9786867e536f70089a5102523ab1d6a88ac";

    #[test]
    fn extracts_miner_script_from_a_real_v6_coinbase() {
        let cb = hex::decode(
            REAL_MAINNET_V6_COINBASE_HEX
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>(),
        )
        .expect("fixture is hex");

        // coinbase_miner_script takes a BLOCK payload: header, tx count, then txs.
        let mut block = vec![0u8; ZCASH_FULL_HEADER_SIZE];
        encode_compact_size(1, &mut block);
        block.extend_from_slice(&cb);

        assert_eq!(
            coinbase_miner_script(&block).as_deref(),
            Some(REAL_MAINNET_V6_MINER_SCRIPT),
            "v6 coinbase must yield the miner payout script"
        );
    }

    /// Before NU7 activates, a block's coinbase may still be v4, and the branch
    /// hint handed to the reader must not stop it from parsing, or orphans lose
    /// their pool attribution without any error. Block 3470793's v4 transaction
    /// stands in for a v4 coinbase: only the first transaction's transparent
    /// outputs are read. The expected script was decoded from the raw bytes
    /// independently of `zcash_primitives` (largest of two outputs, 41511520 zat).
    #[test]
    fn extracts_miner_script_from_a_real_v4_first_transaction() {
        let v4 = &zcash_pool_common::fixtures::mainnet_transactions()[3];
        assert_eq!(&v4[..4], &[0x04, 0x00, 0x00, 0x80], "fixture tx 3 is v4");
        assert_eq!(
            coinbase_miner_script(&block_from_coinbase(v4)).as_deref(),
            Some("76a91463920707d63c5033a09604b6e02c1d23449531c088ac"),
            "a real v4 first transaction must parse"
        );
    }

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

    /// A minimal valid v5 coinbase whose single input carries `script_sig`.
    /// Same shape as `v5_coinbase_two_outputs`, but the input script -- where a
    /// pool stamps its tag -- is caller-supplied instead of fixed filler.
    pub(crate) fn v5_coinbase_with_script_sig(script_sig: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 5).to_le_bytes());
        tx.extend_from_slice(&TX_V5_VERSION_GROUP_ID.to_le_bytes());
        tx.extend_from_slice(&NU5_CONSENSUS_BRANCH_ID.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx.extend_from_slice(&0u32.to_le_bytes()); // expiry_height

        encode_compact_size(1, &mut tx); // one coinbase input
        tx.extend_from_slice(&[0u8; 32]); // prevout hash
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        encode_compact_size(script_sig.len() as u64, &mut tx);
        tx.extend_from_slice(script_sig);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence

        encode_compact_size(1, &mut tx); // one output
        tx.extend_from_slice(&625_000_000u64.to_le_bytes());
        let script = [0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x88, 0xac];
        encode_compact_size(script.len() as u64, &mut tx);
        tx.extend_from_slice(&script);

        encode_compact_size(0, &mut tx); // sapling spends
        encode_compact_size(0, &mut tx); // sapling outputs
        encode_compact_size(0, &mut tx); // orchard actions
        tx
    }

    #[test]
    fn coinbase_text_is_none_for_a_real_v6_coinbase_with_no_printable_tag() {
        // The same real mainnet block-3431157 fixture the miner-script test
        // uses. Its scriptSig is `03 f5 5a 34 04 f0 9f a6 93`: a BIP34 push of
        // the block height (f5 5a 34, little-endian for 3431157) followed by a
        // 4-byte push (f0 9f a6 93) that is a single UTF-8 emoji codepoint --
        // not ASCII. After skipping the mandatory height push, nothing in this
        // particular block's extranonce is printable, so it legitimately
        // carries no coinbase tag.
        let cb = hex::decode(
            REAL_MAINNET_V6_COINBASE_HEX
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>(),
        )
        .expect("fixture is hex");
        let block = block_from_coinbase(&cb);
        assert_eq!(coinbase_text(&block), None);
    }

    #[test]
    fn coinbase_text_drops_non_printable_bytes() {
        // The BIP34 height and nonce live in the same script as any pool tag,
        // so a raw read is mostly control characters. Only printable ASCII
        // survives, which is what leaves a readable tag.
        let script = [
            0x03, 0x8c, 0x11, 0x35, b'2', b'M', b'i', b'n', 0x00, 0x1b, b'e', b'r',
        ];
        let block = block_from_coinbase(&v5_coinbase_with_script_sig(&script));
        assert_eq!(coinbase_text(&block).as_deref(), Some("2Miner"));
    }

    #[test]
    fn coinbase_text_is_truncated_to_the_cap() {
        // The leading 0x00 is deliberately OUTSIDE the BIP34-push guard's
        // `1..=75` range, so this exercises the plain "long tag, no push"
        // path rather than the skip branch. `b'A'` (0x41 = 65) would have
        // fallen inside that range and been misread as a push-length byte --
        // this test would still have passed (the run is homogeneous, so
        // skipping a prefix of it changes nothing observable), but for the
        // wrong reason, silently exercising BIP34-skip instead of the
        // no-push path its name promises.
        let mut script = vec![0x00];
        script.extend(vec![b'A'; 200]);
        let block = block_from_coinbase(&v5_coinbase_with_script_sig(&script));
        assert_eq!(coinbase_text(&block).unwrap().len(), MAX_COINBASE_TEXT);
    }

    #[test]
    fn coinbase_text_is_always_valid_ascii_even_across_the_cap() {
        // The cap counts retained characters, and only ASCII is retained, so a
        // multi-byte sequence can never be split across the boundary.
        //
        // This script's first byte, b'A' (0x41 = 65), DOES fall inside the
        // BIP34-push guard's `1..=75` range, but the guard also requires the
        // script to be longer than the claimed push (65 bytes need a 66-byte
        // script) -- and this script is exactly 65 bytes ((MAX_COINBASE_TEXT
        // - 1) 'A's + the 2-byte UTF-8 encoding of 'e'-acute), so the guard
        // is false and the skip correctly
        // does not fire. That is by construction here, not luck: any change
        // to MAX_COINBASE_TEXT that alters this length must re-check it.
        let mut script = vec![b'A'; MAX_COINBASE_TEXT - 1];
        script.extend_from_slice("é".as_bytes());
        let block = block_from_coinbase(&v5_coinbase_with_script_sig(&script));
        assert!(coinbase_text(&block).unwrap().is_ascii());
    }

    #[test]
    fn coinbase_text_returns_none_on_garbage() {
        // Same failure discipline as coinbase_miner_script: this runs on the
        // block-relay hot path and must never fail or panic.
        assert_eq!(coinbase_text(&[]), None);
        assert_eq!(coinbase_text(&[0u8; 10]), None);
        assert_eq!(coinbase_text(&vec![0u8; ZCASH_FULL_HEADER_SIZE]), None);
    }

    #[test]
    fn coinbase_text_returns_none_when_nothing_printable_remains() {
        let script = [0x03, 0x8c, 0x11, 0x35, 0x04, 0xf0, 0x9f, 0xa6];
        let block = block_from_coinbase(&v5_coinbase_with_script_sig(&script));
        assert_eq!(coinbase_text(&block), None);
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
