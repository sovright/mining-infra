use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use sovright_relay::BlockBodyError;

use crate::coinbase::CoinbaseTelemetry;
use crate::error::{IngressError, Result};

#[derive(Clone)]
pub struct EventSink {
    network: crate::wire::Network,
    target: EventTarget,
}

#[derive(Clone)]
enum EventTarget {
    Stdout,
    File(Arc<Mutex<File>>),
}

impl EventSink {
    #[cfg(test)]
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        Self::for_network(path, crate::wire::Network::Mainnet)
    }

    pub fn for_network(path: Option<PathBuf>, network: crate::wire::Network) -> Result<Self> {
        match path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new().create(true).append(true).open(path)?;
                Ok(Self {
                    network,
                    target: EventTarget::File(Arc::new(Mutex::new(file))),
                })
            }
            None => Ok(Self {
                network,
                target: EventTarget::Stdout,
            }),
        }
    }

    /// A sink whose writes fail: the file is open for reading only.
    #[cfg(test)]
    pub(crate) fn unwritable() -> Self {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        Self {
            network: crate::wire::Network::Mainnet,
            target: EventTarget::File(Arc::new(Mutex::new(file))),
        }
    }

    pub fn p2p_peer_connected(&self, peer: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_connected",
            "peer": peer,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_connect_timing(&self, peer: &str, connect_ms: u128) -> Result<()> {
        self.write(json!({
            "event": "p2p_connect_timing",
            "peer": peer,
            "connect_ms": connect_ms,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_handshake_timing(&self, peer: &str, handshake_ms: u128) -> Result<()> {
        self.write(json!({
            "event": "p2p_handshake_timing",
            "peer": peer,
            "handshake_ms": handshake_ms,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_ping_rtt(&self, peer: &str, nonce: u64, rtt_ms: u128) -> Result<()> {
        self.write(json!({
            "event": "p2p_ping_rtt",
            "peer": peer,
            "nonce": nonce,
            "rtt_ms": rtt_ms,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    #[allow(dead_code)]
    pub fn p2p_peer_score(&self, peer: &str, score: i64, reason: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_score",
            "peer": peer,
            "score": score,
            "reason": reason,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_peer_version(&self, peer: &str, remote_version: i32) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_version",
            "peer": peer,
            "remote_version": remote_version,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_handshake_complete(&self, peer: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_handshake_complete",
            "peer": peer,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_addr_received(&self, peer: &str, count: usize, accepted: usize) -> Result<()> {
        self.write(json!({
            "event": "p2p_addr_received",
            "peer": peer,
            "count": count,
            "accepted": accepted,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_peer_discovered(&self, source_peer: &str, peer: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_discovered",
            "source_peer": source_peer,
            "peer": peer,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_peer_rotation(
        &self,
        peer: &str,
        outcome: &str,
        cooldown_ms: u128,
        queue_len: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_rotation",
            "peer": peer,
            "outcome": outcome,
            "cooldown_ms": cooldown_ms,
            "queue_len": queue_len,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_reject(&self, peer: &str, bytes: usize) -> Result<()> {
        self.write(json!({
            "event": "p2p_reject",
            "peer": peer,
            "bytes": bytes,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_block_inv(&self, peer: &str, hash: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_block_inv",
            "peer": peer,
            "hash": hash,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_getdata_sent(&self, peer: &str, hash: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_getdata_sent",
            "peer": peer,
            "hash": hash,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_tx_inv(&self, peer: &str, kind: &str, hash: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_tx_inv",
            "peer": peer,
            "kind": kind,
            "hash": hash,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_tx_getdata_sent(&self, peer: &str, kind: &str, hash: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_tx_getdata_sent",
            "peer": peer,
            "kind": kind,
            "hash": hash,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_tx_feed_forwarded(
        &self,
        peer: &str,
        kind: &str,
        hash: &str,
        bytes: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_tx_feed_forwarded",
            "peer": peer,
            "kind": kind,
            "hash": hash,
            "bytes": bytes,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn p2p_tx_received(
        &self,
        peer: &str,
        kind: &str,
        hash: &str,
        bytes: usize,
        cache_entries: usize,
        cache_bytes: usize,
        evicted_entries: usize,
        evicted_bytes: usize,
        dropped_too_large: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_tx_received",
            "peer": peer,
            "kind": kind,
            "hash": hash,
            "bytes": bytes,
            "cache_entries": cache_entries,
            "cache_bytes": cache_bytes,
            "evicted_entries": evicted_entries,
            "evicted_bytes": evicted_bytes,
            "dropped_too_large": dropped_too_large,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn p2p_tx_cache_snapshot(
        &self,
        entries: usize,
        bytes: usize,
        max_entries: usize,
        max_bytes: usize,
        max_tx_bytes: usize,
        evicted_entries_total: usize,
        evicted_bytes_total: usize,
        dropped_too_large_total: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_tx_cache_snapshot",
            "entries": entries,
            "bytes": bytes,
            "max_entries": max_entries,
            "max_bytes": max_bytes,
            "max_tx_bytes": max_tx_bytes,
            "evicted_entries_total": evicted_entries_total,
            "evicted_bytes_total": evicted_bytes_total,
            "dropped_too_large_total": dropped_too_large_total,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    /// A block arrived. This takes no parsing, so it is written before anything can
    /// wait, and it stays in the log whatever happens to the block afterwards.
    pub fn p2p_block_received(
        &self,
        peer: &str,
        hash: &str,
        consensus_hash: &str,
        bytes: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_block_received",
            "peer": peer,
            "hash": hash,
            // Zcash consensus block hash (display order), matching the relay
            // arrival log so the dashboard can join block size to propagation
            // latency. Empty when the header could not be read.
            "consensus_hash": consensus_hash,
            "bytes": bytes,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    /// Who mined a block, once its coinbase has been read off the async workers and
    /// the body validated. Written before the send, so a failed send keeps it.
    /// It is best effort, with no exactly-once guarantee: join it on
    /// `consensus_hash`, per block and idempotently. It is not a receipt. A copy that
    /// takes over after a failed send writes another line, which can carry a
    /// different `miner_tag`, because one hash does not mean one body. With nothing
    /// to report it writes nothing.
    pub fn p2p_block_coinbase(
        &self,
        peer: &str,
        hash: &str,
        consensus_hash: &str,
        coinbase: &CoinbaseTelemetry,
    ) -> Result<()> {
        self.write_coinbase_event("p2p_block_coinbase", peer, hash, consensus_hash, coinbase)
    }

    /// Coinbase observed without validating that the body matches the header.
    pub fn p2p_block_coinbase_unverified(
        &self,
        peer: &str,
        hash: &str,
        consensus_hash: &str,
        coinbase: &CoinbaseTelemetry,
    ) -> Result<()> {
        self.write_coinbase_event(
            "p2p_block_coinbase_unverified",
            peer,
            hash,
            consensus_hash,
            coinbase,
        )
    }

    fn write_coinbase_event(
        &self,
        event: &str,
        peer: &str,
        hash: &str,
        consensus_hash: &str,
        coinbase: &CoinbaseTelemetry,
    ) -> Result<()> {
        if coinbase.is_empty() {
            return Ok(());
        }
        let mut value = json!({
            "event": event,
            "peer": peer,
            "hash": hash,
            "consensus_hash": consensus_hash,
            "observed_at_unix_ms": now_unix_ms(),
        });
        // Best-effort coinbase miner payout scriptPubKey (hex). Present only
        // when the coinbase parsed and had a transparent output; the join key
        // downstream against Zebra's getblock verbosity-2 scriptPubKey.hex.
        if let Some(miner_script) = &coinbase.miner_script {
            value["miner_script"] = json!(miner_script);
        }
        // Best-effort coinbase tag (printable ASCII, capped at parse time).
        // Miner-CHOSEN text: the consumer maps it to a curated identifier and
        // never renders it raw. Absent when the coinbase did not parse or
        // carried nothing printable.
        if let Some(miner_tag) = &coinbase.miner_tag {
            value["miner_tag"] = json!(miner_tag);
        }
        self.write(value)
    }

    /// A body the reader could not read, sent on under the emergency bypass. The size,
    /// header and proof-of-work checks ran. The Merkle and duplicate checks could not,
    /// so nothing here says the body belongs to this header. A repeat among the
    /// transactions read before the failure is refused, but that does not cover the
    /// body, so `duplicate_txid` is listed as skipped.
    pub fn p2p_block_unverified_forwarded(
        &self,
        peer: &str,
        hash: &str,
        consensus_hash: &str,
        error: &BlockBodyError,
        bytes: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_block_unverified_forwarded",
            "peer": peer,
            "hash": hash,
            "consensus_hash": consensus_hash,
            "reason": error.label(),
            "detail": error.to_string(),
            "checks_run": ["size", "header", "proof_of_work"],
            "checks_skipped": ["merkle", "duplicate_txid"],
            "bytes": bytes,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_relay_block_forwarded(
        &self,
        peer: &str,
        hash: &str,
        bytes: usize,
        tx_count: usize,
        mode: &str,
        relay_objects: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_relay_block_forwarded",
            "peer": peer,
            "hash": hash,
            "bytes": bytes,
            "tx_count": tx_count,
            "mode": mode,
            "relay_objects": relay_objects,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    /// One refused body. `reason` is the metric's label. A hash that later appears
    /// on chain is only a lead, because a bad body can carry a real block's header:
    /// it was a false rejection only if the node accepted these same bytes.
    pub fn p2p_block_body_rejected(
        &self,
        peer: &str,
        hash: &str,
        consensus_hash: &str,
        error: &BlockBodyError,
        bytes: usize,
    ) -> Result<()> {
        self.write(json!({
            "event": "p2p_block_body_rejected",
            "peer": peer,
            "hash": hash,
            "consensus_hash": consensus_hash,
            "reason": error.label(),
            "detail": error.to_string(),
            "bytes": bytes,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_peer_error(&self, peer: &str, error: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_error",
            "peer": peer,
            "error": error,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    fn write(&self, mut value: serde_json::Value) -> Result<()> {
        value["network"] = serde_json::json!(self.network.name());
        let line = serde_json::to_string(&value)
            .map_err(|e| IngressError::Wire(format!("event serialization failed: {e}")))?;
        match &self.target {
            EventTarget::Stdout => {
                let mut stdout = io::stdout().lock();
                stdout.write_all(line.as_bytes())?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
            }
            EventTarget::File(file) => {
                let mut file = file
                    .lock()
                    .map_err(|_| IngressError::Wire("event log mutex poisoned".to_string()))?;
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
                file.flush()?;
            }
        }
        Ok(())
    }
}

fn now_unix_ms() -> u128 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_log_path(name: &str) -> PathBuf {
        let unique = format!(
            "sovright-p2p-ingress-{name}-{}-{}.jsonl",
            std::process::id(),
            now_unix_ms()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn a_refused_body_is_logged_with_its_reason_and_hashes() {
        let path = temp_log_path("body-rejected");
        let events = EventSink::new(Some(path.clone())).unwrap();

        events
            .p2p_block_body_rejected(
                "127.0.0.1:8233",
                "aaaa",
                "bbbb",
                &BlockBodyError::Transaction { index: 3 },
                1234,
            )
            .unwrap();

        let line = fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(event["event"], "p2p_block_body_rejected");
        assert_eq!(event["peer"], "127.0.0.1:8233");
        assert_eq!(event["hash"], "aaaa");
        assert_eq!(event["consensus_hash"], "bbbb");
        assert_eq!(event["reason"], "transaction");
        assert_eq!(event["detail"], "transaction 3 does not parse");
        assert_eq!(event["bytes"], 1234);
        assert_eq!(event["network"], "mainnet");
        assert!(event["observed_at_unix_ms"].is_u64());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn writes_peer_timing_events() {
        let path = temp_log_path("timing-events");
        let events = EventSink::new(Some(path.clone())).unwrap();

        events.p2p_connect_timing("127.0.0.1:8233", 12).unwrap();
        events.p2p_handshake_timing("127.0.0.1:8233", 34).unwrap();
        events.p2p_ping_rtt("127.0.0.1:8233", 42, 56).unwrap();
        events
            .p2p_peer_score("127.0.0.1:8233", 100, "first_block")
            .unwrap();
        events
            .p2p_peer_rotation("127.0.0.1:8233", "rotated", 78, 9)
            .unwrap();
        events
            .p2p_relay_block_forwarded("127.0.0.1:8233", "abcd", 1234, 2, "compact_block", 1)
            .unwrap();
        events
            .p2p_tx_cache_snapshot(7, 700, 10, 1_000, 100, 2, 200, 1)
            .unwrap();
        events
            .p2p_tx_feed_forwarded("127.0.0.1:8233", "wtx", "feedhash", 321)
            .unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let rows: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(rows[0]["event"], "p2p_connect_timing");
        assert_eq!(rows[0]["connect_ms"], 12);
        assert_eq!(rows[1]["event"], "p2p_handshake_timing");
        assert_eq!(rows[1]["handshake_ms"], 34);
        assert_eq!(rows[2]["event"], "p2p_ping_rtt");
        assert_eq!(rows[2]["nonce"], 42);
        assert_eq!(rows[2]["rtt_ms"], 56);
        assert_eq!(rows[3]["event"], "p2p_peer_score");
        assert_eq!(rows[3]["score"], 100);
        assert_eq!(rows[3]["reason"], "first_block");
        assert_eq!(rows[4]["event"], "p2p_peer_rotation");
        assert_eq!(rows[4]["outcome"], "rotated");
        assert_eq!(rows[4]["cooldown_ms"], 78);
        assert_eq!(rows[4]["queue_len"], 9);
        assert_eq!(rows[5]["event"], "p2p_relay_block_forwarded");
        assert_eq!(rows[5]["hash"], "abcd");
        assert_eq!(rows[5]["bytes"], 1234);
        assert_eq!(rows[5]["tx_count"], 2);
        assert_eq!(rows[5]["mode"], "compact_block");
        assert_eq!(rows[5]["relay_objects"], 1);
        assert_eq!(rows[6]["event"], "p2p_tx_cache_snapshot");
        assert_eq!(rows[6]["entries"], 7);
        assert_eq!(rows[6]["bytes"], 700);
        assert_eq!(rows[6]["max_entries"], 10);
        assert_eq!(rows[6]["max_bytes"], 1_000);
        assert_eq!(rows[6]["max_tx_bytes"], 100);
        assert_eq!(rows[6]["evicted_entries_total"], 2);
        assert_eq!(rows[6]["evicted_bytes_total"], 200);
        assert_eq!(rows[6]["dropped_too_large_total"], 1);
        assert_eq!(rows[7]["event"], "p2p_tx_feed_forwarded");
        assert_eq!(rows[7]["kind"], "wtx");
        assert_eq!(rows[7]["hash"], "feedhash");
        assert_eq!(rows[7]["bytes"], 321);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_receipt_is_a_receipt_and_the_miner_comes_on_its_own_line() {
        let path = temp_log_path("block-coinbase");
        let events = EventSink::new(Some(path.clone())).unwrap();

        events
            .p2p_block_received("127.0.0.1:8233", "abcd", "ef01", 1234)
            .unwrap();
        let coinbase = |miner_tag: Option<&str>| CoinbaseTelemetry {
            miner_script: Some("76a914aa".to_string()),
            miner_tag: miner_tag.map(str::to_string),
        };
        events
            .p2p_block_coinbase(
                "127.0.0.1:8233",
                "abcd",
                "ef01",
                &coinbase(Some("/NiceHash/")),
            )
            .unwrap();
        // Absent, not null: a missing key and a null mean the same thing to the
        // consumer, and omitting keeps the hot-path log line smaller.
        events
            .p2p_block_coinbase("127.0.0.1:8233", "abcd", "ef01", &coinbase(None))
            .unwrap();
        events
            .p2p_block_coinbase(
                "127.0.0.1:8233",
                "abcd",
                "ef01",
                &CoinbaseTelemetry::default(),
            )
            .unwrap();

        let body = fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        fs::remove_file(&path).ok();

        assert_eq!(lines.len(), 3, "nothing to report writes nothing");
        assert_eq!(lines[0]["event"], "p2p_block_received");
        assert!(lines[0].get("miner_script").is_none());
        assert_eq!(lines[1]["event"], "p2p_block_coinbase");
        assert_eq!(lines[1]["hash"], "abcd");
        assert_eq!(lines[1]["miner_tag"], serde_json::json!("/NiceHash/"));
        assert_eq!(lines[1]["miner_script"], serde_json::json!("76a914aa"));
        assert!(lines[2].get("miner_tag").is_none());
    }
}
