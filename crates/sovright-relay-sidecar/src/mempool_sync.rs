//! Background sync of the local Zebra mempool into the sidecar tx cache.
//!
//! The sidecar reconstructs compact blocks from its tx cache. That cache is fed
//! only by the relay tx-feed, which captures the subset of transactions the
//! ingress peers relayed -- so ~20% of blocks miss a short id and fall back to a
//! `getblocktxn` round-trip or the slow raw-segment path. The local Zebra node,
//! however, sees essentially every mempool transaction via its own P2P. This
//! task polls Zebra's mempool and folds it into the same cache, closing the
//! coverage gap while keeping reconstruction cache-fast.
//!
//! BYTE ORDER (critical): Zebra RPC returns `txid`/`authdigest` in DISPLAY order
//! (reversed), but short-id matching and the ingress tx-feed use WIRE order
//! (the ingress builds wtxids straight from the P2P `inv`, no reversal, and
//! `inventory_hash_to_display` reverses wire->display). We therefore reverse
//! BOTH fields when building the `WtxId`. A reversal mistake would silently stop
//! matches, so the caller increments a counter on each insert -- if inserts
//! climb while `compact_reconstruction_unresolved_short_ids` does not fall, the
//! byte order is wrong. Ship gated; verify on one canary before fleet-wide.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{AuthDigest, TxCache, TxId, WtxId};
use tracing::{debug, warn};

use crate::rpc::ZebraRpc;

/// Build a WIRE-order `WtxId` from Zebra RPC DISPLAY-order hex fields, reversing
/// both. Returns `None` if either field is not valid 32-byte hex.
pub fn wtxid_from_display_hex(txid_display: &str, authdigest_display: &str) -> Option<WtxId> {
    Some(WtxId::new(
        TxId::from_bytes(decode_reversed_32(txid_display)?),
        AuthDigest::from_bytes(decode_reversed_32(authdigest_display)?),
    ))
}

fn decode_reversed_32(display_hex: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(display_hex.trim(), &mut bytes).ok()?;
    bytes.reverse(); // display (reversed) -> wire (internal)
    Some(bytes)
}

/// Prepare the `(wtxid, tx_bytes)` to insert from a mempool txid and its raw
/// transaction. Returns `None` for pre-v5 transactions (no auth digest) or
/// malformed hex -- those are simply left to the relay tx-feed / getblocktxn.
pub fn prepare_insert(
    txid_display: &str,
    authdigest_display: Option<&str>,
    tx_hex: &str,
) -> Option<(WtxId, Vec<u8>)> {
    let wtxid = wtxid_from_display_hex(txid_display, authdigest_display?)?;
    let tx_bytes = hex::decode(tx_hex.trim()).ok()?;
    if tx_bytes.is_empty() {
        return None;
    }
    Some((wtxid, tx_bytes))
}

/// Mempool txids not yet processed in a prior pass.
pub fn select_new<'a>(mempool: &'a [String], seen: &HashSet<String>) -> Vec<&'a str> {
    mempool
        .iter()
        .filter(|txid| !seen.contains(*txid))
        .map(String::as_str)
        .collect()
}

/// Poll the local Zebra mempool forever, folding new transactions into `cache`.
/// `on_insert` is called once per newly cached transaction (metrics hook).
/// Incremental: only transactions not seen in the previous pass are fetched, and
/// `seen` is pruned to the current mempool each pass to bound memory.
pub async fn run_zebra_mempool_sync<F: Fn()>(
    rpc: Arc<ZebraRpc>,
    cache: TxCache,
    interval: Duration,
    on_insert: F,
) {
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        tokio::time::sleep(interval).await;
        let mempool = match rpc.get_raw_mempool().await {
            Ok(mempool) => mempool,
            Err(error) => {
                warn!(%error, "zebra mempool sync: getrawmempool failed");
                continue;
            }
        };
        for txid in select_new(&mempool, &seen) {
            match rpc.get_raw_transaction(txid).await {
                Ok(raw) => {
                    if let Some((wtxid, tx_bytes)) =
                        prepare_insert(txid, raw.authdigest.as_deref(), &raw.hex)
                        && cache.insert(wtxid, tx_bytes).inserted
                    {
                        on_insert();
                    }
                }
                Err(error) => {
                    debug!(%txid, %error, "zebra mempool sync: getrawtransaction failed")
                }
            }
        }
        seen = mempool.into_iter().collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // txid/authdigest as they appear in Zebra RPC (display order); the wtxid the
    // reconstructor matches uses wire order = the reverse of each.
    const TXID_DISPLAY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const AUTH_DISPLAY: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn wtxid_reverses_both_fields_to_wire_order() {
        let wtxid = wtxid_from_display_hex(TXID_DISPLAY, AUTH_DISPLAY).unwrap();
        let bytes = wtxid.to_bytes(); // wire txid (32) || wire authdigest (32)

        let mut expect_txid = [0u8; 32];
        hex::decode_to_slice(TXID_DISPLAY, &mut expect_txid).unwrap();
        expect_txid.reverse();
        let mut expect_auth = [0u8; 32];
        hex::decode_to_slice(AUTH_DISPLAY, &mut expect_auth).unwrap();
        expect_auth.reverse();

        assert_eq!(&bytes[..32], &expect_txid);
        assert_eq!(&bytes[32..], &expect_auth);
    }

    #[test]
    fn wtxid_rejects_malformed_hex() {
        assert!(wtxid_from_display_hex("not-hex", AUTH_DISPLAY).is_none());
        assert!(wtxid_from_display_hex(TXID_DISPLAY, "abcd").is_none()); // wrong length
    }

    #[test]
    fn prepare_insert_skips_pre_v5_without_authdigest() {
        assert!(prepare_insert(TXID_DISPLAY, None, "00").is_none());
    }

    #[test]
    fn prepare_insert_skips_empty_or_bad_tx_hex() {
        assert!(prepare_insert(TXID_DISPLAY, Some(AUTH_DISPLAY), "").is_none());
        assert!(prepare_insert(TXID_DISPLAY, Some(AUTH_DISPLAY), "zz").is_none());
    }

    #[test]
    fn prepare_insert_returns_wtxid_and_bytes() {
        let (wtxid, bytes) = prepare_insert(TXID_DISPLAY, Some(AUTH_DISPLAY), "deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            wtxid,
            wtxid_from_display_hex(TXID_DISPLAY, AUTH_DISPLAY).unwrap()
        );
    }

    #[test]
    fn select_new_returns_only_unseen() {
        let mempool = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let seen: HashSet<String> = ["a".to_string(), "c".to_string()].into_iter().collect();
        assert_eq!(select_new(&mempool, &seen), vec!["b"]);
    }

    #[test]
    fn select_new_empty_when_all_seen() {
        let mempool = vec!["a".to_string()];
        let seen: HashSet<String> = ["a".to_string()].into_iter().collect();
        assert!(select_new(&mempool, &seen).is_empty());
    }
}
