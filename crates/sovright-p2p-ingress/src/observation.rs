//! Opt-in, bounded, best-effort observation. Never performs filesystem I/O on a peer task.
use crate::hash::inventory_hash_to_display;
use crate::wire::{Inventory, Network};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Default window after which a sensor that has decoded no transaction or block
/// payload reports itself unhealthy (24 blocks at the 25 s NU7 spacing).
pub const DEFAULT_PAYLOAD_STALE_MS: u64 = 600_000;

#[derive(Debug, Clone)]
pub struct ObservationConfig {
    pub path: PathBuf,
    pub sensor_id: String,
    pub network: Network,
    pub queue_capacity: usize,
    pub max_bytes: u64,
    pub max_files: usize,
    pub heartbeat_interval: Duration,
    /// No decoded tx or block payload within this window makes heartbeats unhealthy.
    pub payload_stale_after: Duration,
}

impl ObservationConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.sensor_id.trim().is_empty()
            || self.sensor_id.len() > 128
            || self.sensor_id.chars().any(char::is_control)
            || self.queue_capacity == 0
            || self.queue_capacity > 1_000_000
            || self.max_bytes < 4096
            || self.max_files == 0
            || self.max_files > 100
            || self.heartbeat_interval.is_zero()
            || self.heartbeat_interval > Duration::from_secs(3600)
            || self.payload_stale_after.is_zero()
            || self.payload_stale_after > Duration::from_secs(86_400)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid observation identity or bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObservationTime {
    wall_ms: u64,
    monotonic_ms: u64,
}

#[derive(Debug)]
struct Inner {
    sender: SyncSender<Value>,
    sequence: Mutex<u64>,
    sensor_id: String,
    network: &'static str,
    boot_id: String,
    started: Instant,
    dropped: AtomicU64,
    /// Writer health. Clearing it stops the stream, so staleness never touches it.
    healthy: AtomicBool,
    active_peers: AtomicUsize,
    /// Monotonic ms of the last decoded tx or block payload (0 = process start,
    /// which gives a startup grace of one stale window).
    last_payload_ms: AtomicU64,
    payload_stale_after_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Observer {
    inner: Arc<Inner>,
}

impl Observer {
    fn channel(config: &ObservationConfig) -> (Self, Receiver<Value>) {
        let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
        static BOOT_COUNTER: AtomicU64 = AtomicU64::new(0);
        let boot_id = format!(
            "{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            BOOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        (
            Self {
                inner: Arc::new(Inner {
                    sender,
                    sequence: Mutex::new(0),
                    sensor_id: config.sensor_id.clone(),
                    network: config.network.name(),
                    boot_id,
                    started: Instant::now(),
                    dropped: AtomicU64::new(0),
                    healthy: AtomicBool::new(true),
                    active_peers: AtomicUsize::new(0),
                    last_payload_ms: AtomicU64::new(0),
                    payload_stale_after_ms: config.payload_stale_after.as_millis() as u64,
                }),
            },
            receiver,
        )
    }

    pub fn start(config: ObservationConfig) -> io::Result<Self> {
        config.validate()?;
        let (observer, receiver) = Self::channel(&config);
        let weak = Arc::downgrade(&observer.inner);
        std::thread::Builder::new()
            .name("ingress-observation".into())
            .spawn(move || {
                let mut in_flight = false;
                let mut run = || -> io::Result<()> {
                    let mut writer = RotatingWriter::open(&config)?;
                    let mut next_heartbeat = Instant::now();
                    loop {
                        if Instant::now() >= next_heartbeat {
                            if let Some(inner) = weak.upgrade() {
                                Observer { inner }.heartbeat();
                            }
                            next_heartbeat = Instant::now() + config.heartbeat_interval;
                        }
                        match receiver
                            .recv_timeout(next_heartbeat.saturating_duration_since(Instant::now()))
                        {
                            Ok(event) => {
                                in_flight = true;
                                let mut record = serde_json::to_vec(&event)?;
                                record.push(b'\n');
                                writer.write_record(&record)?;
                                in_flight = false;
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                        }
                    }
                };
                if let Err(error) = run() {
                    if let Some(inner) = weak.upgrade() {
                        let _sequence = inner.sequence.lock().unwrap_or_else(|e| e.into_inner());
                        inner.healthy.store(false, Ordering::Relaxed);
                        // The failing record and all queued records have been lost.
                        inner.dropped.fetch_add(
                            u64::from(in_flight) + receiver.try_iter().count() as u64,
                            Ordering::Relaxed,
                        );
                    }
                    tracing::error!(%error, "observation writer stopped; coverage unavailable");
                }
            })?;
        Ok(observer)
    }

    pub fn capture(&self) -> ObservationTime {
        ObservationTime {
            wall_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            monotonic_ms: self.inner.started.elapsed().as_millis() as u64,
        }
    }

    fn emit(&self, mut event: Value, stamp: ObservationTime) {
        // Keep source sequence in enqueue order across all peers and heartbeat.
        let mut sequence = self
            .inner
            .sequence
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        event["schema_version"] = json!(1);
        event["network"] = json!(self.inner.network);
        event["sensor_id"] = json!(self.inner.sensor_id);
        event["boot_id"] = json!(self.inner.boot_id);
        event["sequence"] = json!(*sequence);
        event["observed_at_ms"] = json!(stamp.wall_ms);
        event["monotonic_ms"] = json!(stamp.monotonic_ms);
        *sequence += 1;
        if event["event"] == "sensor_heartbeat" {
            event["dropped_events"] = json!(self.inner.dropped.load(Ordering::Relaxed));
        }
        if !self.inner.healthy.load(Ordering::Relaxed) || self.inner.sender.try_send(event).is_err()
        {
            let count = self.inner.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if count == 1 || count.is_power_of_two() {
                tracing::warn!(dropped_events = count, "observation event dropped");
            }
        }
    }

    /// `healthy` is false when the writer failed or when no tx/block payload has
    /// been decoded within the stale window (announcements alone do not count).
    pub fn heartbeat(&self) {
        let stamp = self.capture();
        let age = stamp
            .monotonic_ms
            .saturating_sub(self.inner.last_payload_ms.load(Ordering::Relaxed));
        let stale = age > self.inner.payload_stale_after_ms;
        let writer_ok = self.inner.healthy.load(Ordering::Relaxed);
        self.emit(json!({"event":"sensor_heartbeat", "healthy":writer_ok && !stale, "payload_stale":stale, "last_payload_age_ms":age, "dropped_events":self.inner.dropped.load(Ordering::Relaxed), "clock_uncertainty_ms":null, "active_peers":self.inner.active_peers.load(Ordering::Relaxed)}), stamp);
    }

    fn payload_decoded(&self, stamp: ObservationTime) {
        self.inner
            .last_payload_ms
            .fetch_max(stamp.monotonic_ms, Ordering::Relaxed);
    }

    pub fn peer_active(&self) -> ActivePeer {
        self.inner.active_peers.fetch_add(1, Ordering::Relaxed);
        ActivePeer(self.clone())
    }

    pub fn inventory(&self, inv: &Inventory, stamp: ObservationTime) {
        if inv.is_transaction() {
            let mut event = json!({"event":"tx_seen", "source_kind":"p2p", "stage":"announcement", "txid":inventory_hash_to_display(&inv.hash)});
            if let Some(auth) = inv.auth_digest {
                event["auth_digest"] = json!(inventory_hash_to_display(&auth));
            }
            self.emit(event, stamp);
        } else if inv.is_block() {
            self.block(&inventory_hash_to_display(&inv.hash), "announcement", stamp);
        }
    }

    pub fn block(&self, hash: &str, stage: &str, stamp: ObservationTime) {
        if stage == "payload" {
            self.payload_decoded(stamp);
        }
        self.emit(
            json!({"event":"block_seen", "block_hash":hash, "stage":stage}),
            stamp,
        );
    }

    pub fn payload(&self, payload: &[u8], stamp: ObservationTime) {
        if let Some(metadata) = crate::wtxid::metadata_from_tx_bytes(payload) {
            self.payload_decoded(stamp);
            self.emit(json!({"event":"tx_seen", "source_kind":"p2p", "stage":"payload", "txid":metadata.txid, "auth_digest":metadata.auth_digest, "size_bytes":payload.len(), "tx_version":metadata.version, "expiry_height":metadata.expiry_height, "action_count":metadata.action_count}), stamp);
        }
    }
}

pub struct ActivePeer(Observer);
impl Drop for ActivePeer {
    fn drop(&mut self) {
        self.0.inner.active_peers.fetch_sub(1, Ordering::Relaxed);
    }
}

struct RotatingWriter {
    config: ObservationConfig,
    file: Option<File>,
    bytes: u64,
}
fn archive_path(path: &Path, index: usize) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}"));
    value.into()
}
impl RotatingWriter {
    fn open(config: &ObservationConfig) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.path)?;
        // A dedicated observation path owns its numeric archive namespace.
        // Prune archives from a previous configuration if retention shrank.
        let parent = config
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let prefix = format!(
            "{}.",
            config
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            if let Some(index) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix(&prefix))
                .and_then(|suffix| suffix.parse::<usize>().ok())
                && (index >= config.max_files || entry.metadata()?.len() > config.max_bytes)
            {
                std::fs::remove_file(entry.path())?;
            }
        }
        let mut bytes = file.metadata()?.len();
        if bytes > config.max_bytes {
            file.set_len(0)?;
            bytes = 0;
        }
        Ok(Self {
            config: config.clone(),
            file: Some(file),
            bytes,
        })
    }
    fn write_record(&mut self, record: &[u8]) -> io::Result<()> {
        if record.len() > MAX_RECORD_BYTES || record.len() as u64 > self.config.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "observation record exceeds bounds",
            ));
        }
        if self.bytes + record.len() as u64 > self.config.max_bytes {
            self.file.take();
            for index in (1..self.config.max_files).rev() {
                let source = if index == 1 {
                    self.config.path.clone()
                } else {
                    archive_path(&self.config.path, index - 1)
                };
                let dest = archive_path(&self.config.path, index);
                match std::fs::rename(source, dest) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                };
            }
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&self.config.path)?,
            );
            self.bytes = 0;
        }
        self.file.as_mut().unwrap().write_all(record)?;
        self.bytes += record.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Inventory, MSG_TX, MSG_WTX};
    use serde_json::Value;

    fn config(name: &str) -> ObservationConfig {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        ObservationConfig {
            path: std::env::temp_dir()
                .join(format!("observation-{name}-{}-{id}", std::process::id())),
            sensor_id: "independent-1".into(),
            network: Network::Mainnet,
            queue_capacity: 2,
            max_bytes: 4096,
            max_files: 2,
            heartbeat_interval: Duration::from_millis(20),
            payload_stale_after: Duration::from_secs(600),
        }
    }

    #[test]
    fn announcements_survive_fetch_selection_and_capture_time() {
        let cfg = config("inv");
        let (observer, rx) = Observer::channel(&cfg);
        let stamp = observer.capture();
        std::thread::sleep(Duration::from_millis(3));
        observer.inventory(
            &Inventory {
                inv_type: MSG_WTX,
                hash: [0x11; 32],
                auth_digest: Some([0x22; 32]),
            },
            stamp,
        );
        let event = rx.try_recv().unwrap();
        assert_eq!(event["event"], "tx_seen");
        assert_eq!(event["stage"], "announcement");
        assert_eq!(event["txid"], "11".repeat(32));
        assert_eq!(event["auth_digest"], "22".repeat(32));
        assert_eq!(event["observed_at_ms"], stamp.wall_ms);
        assert_eq!(event["monotonic_ms"], stamp.monotonic_ms);
        assert_eq!(event["network"], "mainnet");
        assert!(event.get("peer").is_none());
    }

    #[test]
    fn concurrent_peers_and_heartbeats_preserve_source_sequence_order() {
        let mut cfg = config("concurrent");
        cfg.queue_capacity = 1024;
        let (observer, rx) = Observer::channel(&cfg);
        let mut workers = Vec::new();
        for _ in 0..4 {
            let observer = observer.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    observer.inventory(
                        &Inventory {
                            inv_type: MSG_TX,
                            hash: [1; 32],
                            auth_digest: None,
                        },
                        observer.capture(),
                    );
                }
            }));
        }
        for _ in 0..20 {
            observer.heartbeat();
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let events: Vec<Value> = rx.try_iter().collect();
        assert_eq!(events.len(), 420);
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event["sequence"], index);
        }
        assert_eq!(observer.inner.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bounded_queue_reports_cumulative_drops_and_sequence_gaps() {
        let mut cfg = config("drops");
        cfg.queue_capacity = 1;
        let (observer, rx) = Observer::channel(&cfg);
        let inv = Inventory {
            inv_type: MSG_TX,
            hash: [1; 32],
            auth_digest: None,
        };
        observer.inventory(&inv, observer.capture());
        observer.inventory(&inv, observer.capture());
        assert_eq!(rx.try_recv().unwrap()["sequence"], 0);
        observer.heartbeat();
        let health = rx.try_recv().unwrap();
        assert_eq!(health["sequence"], 2);
        assert_eq!(health["dropped_events"], 1);
        assert_eq!(health["clock_uncertainty_ms"], Value::Null);
    }

    #[test]
    fn payload_metadata_is_derived_and_malformed_payloads_are_not_claimed() {
        let cfg = config("payload");
        let (observer, rx) = Observer::channel(&cfg);
        let payload =
            hex::decode(include_str!("../tests/fixtures/mainnet_v6_tx.hex").trim()).unwrap();
        observer.payload(&payload, observer.capture());
        let event = rx.try_recv().unwrap();
        assert_eq!(event["tx_version"], 6);
        assert_eq!(event["size_bytes"], payload.len());
        assert_eq!(event["expiry_height"], 3470797);
        assert!(event["action_count"].as_u64().unwrap() > 0);
        assert_eq!(
            event["txid"],
            "b5e84a20ed799a4242f9f98a65f5654f02ab0e7dcd5ee6d5f54bee2d11affa63"
        );
        observer.payload(&[0xff; 3], observer.capture());
        let mut trailing = payload.clone();
        trailing.push(0);
        observer.payload(&trailing, observer.capture());
        assert!(rx.try_recv().is_err());
    }

    fn heartbeat_health(observer: &Observer, rx: &Receiver<Value>) -> Value {
        observer.heartbeat();
        rx.try_recv()
            .expect("heartbeats are emitted even when stale")
    }

    #[test]
    fn heartbeat_turns_unhealthy_without_decoded_payloads() {
        // Post-NU7 the deployed observer decoded nothing for days while every
        // heartbeat said healthy. Announcements alone must not keep it healthy.
        let mut cfg = config("stale");
        cfg.queue_capacity = 64;
        cfg.payload_stale_after = Duration::from_millis(250);
        let (observer, rx) = Observer::channel(&cfg);
        let beat = heartbeat_health(&observer, &rx);
        assert_eq!(beat["healthy"], true, "startup grace");
        assert_eq!(beat["payload_stale"], false);
        std::thread::sleep(Duration::from_millis(300));
        observer.inventory(
            &Inventory {
                inv_type: MSG_TX,
                hash: [1; 32],
                auth_digest: None,
            },
            observer.capture(),
        );
        observer.block(&"ab".repeat(32), "announcement", observer.capture());
        let _ = rx.try_iter().count();
        let beat = heartbeat_health(&observer, &rx);
        assert_eq!(beat["healthy"], false);
        assert_eq!(beat["payload_stale"], true);
        assert!(beat["last_payload_age_ms"].as_u64().unwrap() >= 250);
        // Staleness must not stop the stream (unlike a writer failure).
        assert!(observer.inner.healthy.load(Ordering::Relaxed));
        assert_eq!(observer.inner.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn decoded_block_or_tx_payload_restores_heartbeat_health() {
        let mut cfg = config("fresh");
        cfg.queue_capacity = 64;
        cfg.payload_stale_after = Duration::from_millis(250);
        let (observer, rx) = Observer::channel(&cfg);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(heartbeat_health(&observer, &rx)["healthy"], false);
        observer.block(&"ab".repeat(32), "payload", observer.capture());
        let _ = rx.try_iter().count();
        assert_eq!(heartbeat_health(&observer, &rx)["healthy"], true);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(heartbeat_health(&observer, &rx)["healthy"], false);
        // An undecodable tx payload does not count; a decodable one does.
        observer.payload(&[0xff; 3], observer.capture());
        assert_eq!(heartbeat_health(&observer, &rx)["healthy"], false);
        let tx = hex::decode(include_str!("../tests/fixtures/mainnet_v6_tx.hex").trim()).unwrap();
        observer.payload(&tx, observer.capture());
        let _ = rx.try_iter().count();
        let beat = heartbeat_health(&observer, &rx);
        assert_eq!(beat["healthy"], true);
        assert_eq!(beat["payload_stale"], false);
    }

    #[test]
    fn payload_stale_window_must_be_positive_and_bounded() {
        let mut cfg = config("stale-bounds");
        cfg.payload_stale_after = Duration::ZERO;
        assert!(cfg.validate().is_err());
        cfg.payload_stale_after = Duration::from_secs(86_401);
        assert!(cfg.validate().is_err());
        cfg.payload_stale_after = Duration::from_millis(DEFAULT_PAYLOAD_STALE_MS);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn events_carry_the_configured_network() {
        let mut cfg = config("testnet");
        cfg.network = Network::Testnet;
        let (observer, rx) = Observer::channel(&cfg);
        observer.heartbeat();
        assert_eq!(rx.try_recv().unwrap()["network"], "testnet");
    }

    #[test]
    fn decreasing_retention_removes_old_numeric_archives() {
        let cfg = config("retention");
        std::fs::write(archive_path(&cfg.path, 2), b"old\n").unwrap();
        std::fs::write(archive_path(&cfg.path, 3), b"older\n").unwrap();
        let writer = RotatingWriter::open(&cfg).unwrap();
        assert!(!archive_path(&cfg.path, 2).exists());
        assert!(!archive_path(&cfg.path, 3).exists());
        drop(writer);
        let _ = std::fs::remove_file(&cfg.path);
    }

    #[test]
    fn blank_sensor_identity_is_rejected() {
        let mut cfg = config("blank");
        cfg.sensor_id = "   ".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rotation_bounds_retained_files_and_never_splits_records() {
        let mut cfg = config("rotation");
        cfg.max_bytes = 8;
        let mut writer = RotatingWriter::open(&cfg).unwrap();
        writer.write_record(b"1111\n").unwrap();
        writer.write_record(b"2222\n").unwrap();
        writer.write_record(b"3333\n").unwrap();
        assert_eq!(std::fs::read(&cfg.path).unwrap(), b"3333\n");
        assert_eq!(
            std::fs::read(archive_path(&cfg.path, 1)).unwrap(),
            b"2222\n"
        );
        assert!(!archive_path(&cfg.path, 2).exists());
        assert!(writer.write_record(b"123456789\n").is_err());
        let _ = std::fs::remove_file(&cfg.path);
        let _ = std::fs::remove_file(archive_path(&cfg.path, 1));
    }

    #[test]
    fn unhealthy_observer_drops_events_even_before_receiver_disconnects() {
        let (observer, rx) = Observer::channel(&config("unhealthy"));
        observer.inner.healthy.store(false, Ordering::Relaxed);
        observer.inventory(
            &Inventory {
                inv_type: MSG_TX,
                hash: [1; 32],
                auth_digest: None,
            },
            observer.capture(),
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(observer.inner.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn writer_failure_marks_unhealthy_and_does_not_escape_to_producers() {
        let mut cfg = config("failure");
        cfg.path = cfg.path.join("missing-parent");
        let observer = Observer::start(cfg).unwrap();
        for _ in 0..100 {
            if !observer.inner.healthy.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!observer.inner.healthy.load(Ordering::Relaxed));
        observer.inventory(
            &Inventory {
                inv_type: MSG_TX,
                hash: [1; 32],
                auth_digest: None,
            },
            observer.capture(),
        );
        assert!(observer.inner.dropped.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn worker_emits_periodic_heartbeats_without_gossip() {
        let cfg = config("heartbeat");
        let path = cfg.path.clone();
        let observer = Observer::start(cfg).unwrap();
        let mut events = Vec::new();
        for _ in 0..100 {
            events = std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .filter_map(|s| serde_json::from_str::<Value>(s).ok())
                .collect();
            if events.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(3));
        }
        assert!(events.len() >= 2);
        assert!(
            events
                .iter()
                .all(|e| e["event"] == "sensor_heartbeat" && e["active_peers"] == 0)
        );
        assert_eq!(events[0]["boot_id"], events[1]["boot_id"]);
        drop(observer);
        let _ = std::fs::remove_file(path);
    }
}
