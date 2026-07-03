//! Per-block relay arrival logging.
//!
//! When the relay node reconstructs a PoW-valid block from the raw-segment
//! stream, it appends one JSON line to an arrival log. The observatory timing
//! collector tails this log and joins `hash` -- the Zcash *consensus* block hash
//! (double-SHA256 of the header, big-endian display, matching Zebra
//! `getblockhash`, explorers, and the native-P2P ingress `hash` field) -- against
//! the P2P block arrivals to measure relay-vs-P2P propagation per region.
//!
//! The relay's internal BLAKE2b object id is deliberately *not* used here: it is
//! a different function than the consensus id and cannot be cross-referenced in
//! any byte order (see [`crate::hash::consensus_block_hash_display`]).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Append-only JSONL sink for relay block-arrival events.
#[derive(Clone)]
pub struct ArrivalSink {
    file: Arc<Mutex<File>>,
}

impl ArrivalSink {
    /// Open the arrival log in append mode, creating parent directories and the
    /// file if needed.
    pub fn new(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    /// Record that the relay reconstructed a PoW-valid block whose Zcash
    /// consensus block hash (display/big-endian hex) is `consensus_hash_display`.
    ///
    /// Best-effort: I/O and lock failures are swallowed so the relay receive
    /// path is never disrupted by arrival logging.
    pub fn relay_block_received(&self, consensus_hash_display: &str) {
        // The hash is hex from consensus_block_hash_display and the event name is
        // a constant, so manual JSON formatting needs no escaping and avoids a
        // serde_json dependency on the relay receive path.
        let line = format!(
            "{{\"event\":\"relay_block_received\",\"hash\":\"{}\",\"observed_at_unix_ms\":{}}}",
            consensus_hash_display,
            now_unix_ms()
        );
        if let Ok(mut file) = self.file.lock() {
            use std::io::Write;
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let unique = format!(
            "sovright-relay-arrival-{tag}-{}-{}.jsonl",
            std::process::id(),
            now_unix_ms()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn writes_relay_block_received_line() {
        let path = temp_path("write");
        let sink = ArrivalSink::new(&path).unwrap();
        let hash = "00000000000000010f3b0387e3415d5fd6b60d9ccbb3c7795b5cb98734e5d471";
        sink.relay_block_received(hash);

        let contents = fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().expect("one arrival line");
        assert!(
            line.contains("\"event\":\"relay_block_received\""),
            "got: {line}"
        );
        assert!(
            line.contains(&format!("\"hash\":\"{hash}\"")),
            "got: {line}"
        );

        let marker = "\"observed_at_unix_ms\":";
        let idx = line.find(marker).expect("observed_at_unix_ms field");
        let tail = &line[idx + marker.len()..];
        let num: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        assert!(num.parse::<u128>().unwrap() > 0, "got: {line}");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn appends_multiple_lines() {
        let path = temp_path("append");
        let sink = ArrivalSink::new(&path).unwrap();
        sink.relay_block_received("aa");
        sink.relay_block_received("bb");

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2, "got: {contents}");

        let _ = fs::remove_file(path);
    }
}
