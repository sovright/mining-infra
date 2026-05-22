use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::error::{IngressError, Result};

#[derive(Clone)]
pub struct EventSink {
    target: EventTarget,
}

#[derive(Clone)]
enum EventTarget {
    Stdout,
    File(Arc<Mutex<File>>),
}

impl EventSink {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        match path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new().create(true).append(true).open(path)?;
                Ok(Self {
                    target: EventTarget::File(Arc::new(Mutex::new(file))),
                })
            }
            None => Ok(Self {
                target: EventTarget::Stdout,
            }),
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

    pub fn p2p_block_received(&self, peer: &str, hash: &str, bytes: usize) -> Result<()> {
        self.write(json!({
            "event": "p2p_block_received",
            "peer": peer,
            "hash": hash,
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

    fn write(&self, value: serde_json::Value) -> Result<()> {
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
            "bedrock-p2p-ingress-{name}-{}-{}.jsonl",
            std::process::id(),
            now_unix_ms()
        );
        std::env::temp_dir().join(unique)
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

        let _ = fs::remove_file(path);
    }
}
