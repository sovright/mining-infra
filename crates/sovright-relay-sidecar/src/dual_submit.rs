//! Submit the same block to a second node, and log every call.
//!
//! WHY A DECORATOR AND NOT A HELPER
//! --------------------------------
//! There are five `submit_block` call sites in `submit.rs`. PR #88 added
//! rejection classification to exactly one of them and the other four --
//! including the raw-segment path, which carries almost all traffic -- silently
//! did nothing for a week. #92 fixed that by funnelling every site through one
//! helper, which works but still relies on a future change remembering to call
//! it.
//!
//! This wraps the `SubmitBlock` implementation instead. Every path that submits
//! a block does so *through the submitter it was handed*, so a second target is
//! covered by construction. There is no per-call-site wiring to forget, and no
//! signature to thread through five public entry points.
//!
//! THE SECONDARY MUST NEVER AFFECT THE PRIMARY
//! -------------------------------------------
//! The primary is production: its result decides metrics, dedup, the safety
//! gate and arrival logging. The secondary exists only to be measured. So the
//! secondary submit is `tokio::spawn`ed and never awaited on the primary path.
//! A secondary that is slow, hung, erroring or unreachable cannot delay the
//! primary by more than the cost of spawning a task, and cannot change what the
//! primary returns.
//!
//! Spawning also keeps the two submits near-simultaneous, which matters for the
//! comparison: submitting sequentially would hand the second node a block the
//! network has had longer to propagate, inflating its share of cheap `duplicate`
//! responses (~2ms) against expensive real validations (~250ms) and quietly
//! flattering its mean.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sovright_relay::{ZCASH_FULL_HEADER_SIZE, consensus_block_hash_display};
use tracing::warn;

use crate::submit::{BlockKnownFuture, SubmitBlock, SubmitFuture};

/// One submitblock call, as written to the JSONL log.
///
/// JSONL rather than tracing fields on purpose: journald preserves the ANSI
/// colour escapes the sidecar emits, and they sit *between* a field name and its
/// `=`, so every naive field regex silently matches nothing. A file sidesteps
/// that entirely and is directly joinable by `consensus_block_hash`.
#[derive(Debug, Clone, PartialEq)]
pub struct SubmitCallRecord {
    /// Zcash consensus block hash, DISPLAY order -- the value Zebra's
    /// `getblockhash` reports. NOT the relay's internal BLAKE2b object id; they
    /// are different values and conflating them yields zero join matches.
    pub consensus_block_hash: String,
    /// "primary" or "secondary".
    pub target: String,
    pub target_url: String,
    pub latency_ms: u64,
    /// accepted | duplicate | duplicate_inconclusive | rejected | error
    pub outcome: String,
    /// Raw node response for a rejection, or the transport error.
    pub detail: Option<String>,
    pub block_bytes: usize,
}

impl SubmitCallRecord {
    /// Serialise to one JSON line.
    ///
    /// Hand-rolled to avoid pulling serde onto the submit path; every field is
    /// either a number or a string we escape below.
    pub fn to_json_line(&self) -> String {
        let detail = match &self.detail {
            Some(d) => format!("\"{}\"", escape(d)),
            None => "null".to_string(),
        };
        format!(
            "{{\"event\":\"submitblock_call\",\"consensus_block_hash\":\"{}\",\
\"target\":\"{}\",\"target_url\":\"{}\",\"latency_ms\":{},\"outcome\":\"{}\",\
\"detail\":{},\"block_bytes\":{},\"observed_at_unix_ms\":{}}}",
            escape(&self.consensus_block_hash),
            escape(&self.target),
            escape(&self.target_url),
            self.latency_ms,
            escape(&self.outcome),
            detail,
            self.block_bytes,
            now_unix_ms(),
        )
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Classify a raw submitblock response for the log.
///
/// Deliberately mirrors the node's own vocabulary rather than reusing
/// `classify_submitblock_result`: that function returns a `Result` shaped for
/// control flow (a rejection is an `Err` that aborts the submit), whereas the
/// log needs a flat label for every call including ones the primary path treats
/// as failures. Keeping them separate means logging cannot change submit
/// behaviour.
pub fn outcome_label(result: &Result<Option<String>, String>) -> (&'static str, Option<String>) {
    match result {
        Ok(None) => ("accepted", None),
        Ok(Some(s)) if s == "duplicate" => ("duplicate", None),
        Ok(Some(s)) if s == "duplicate-inconclusive" => ("duplicate_inconclusive", None),
        Ok(Some(s)) => ("rejected", Some(s.clone())),
        Err(e) => ("error", Some(e.clone())),
    }
}

/// Consensus block hash (display order) read from a block's hex.
///
/// Returns None when the hex is malformed or shorter than a Zcash header, so a
/// bad block is logged with an empty hash rather than panicking on the submit
/// path.
pub fn consensus_hash_from_block_hex(block_hex: &str) -> Option<String> {
    let header_hex_len = ZCASH_FULL_HEADER_SIZE * 2;
    let header_hex = block_hex.get(..header_hex_len)?;
    let header = hex::decode(header_hex).ok()?;
    Some(consensus_block_hash_display(&header))
}

/// Append-only JSONL sink for submitblock calls.
#[derive(Clone)]
pub struct SubmitLogSink {
    file: Arc<Mutex<File>>,
}

impl SubmitLogSink {
    pub fn new(path: &Path) -> std::io::Result<Self> {
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

    /// Best-effort append. I/O and lock failures are swallowed: a measurement
    /// log must never disrupt block submission.
    pub fn record(&self, record: &SubmitCallRecord) {
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{}", record.to_json_line());
            let _ = file.flush();
        }
    }
}

/// A `SubmitBlock` that submits to a primary node and, optionally, mirrors the
/// same block to a secondary node for comparison.
pub struct DualSubmit<P> {
    primary: P,
    primary_url: String,
    secondary: Option<Arc<dyn SubmitBlock + Send + Sync>>,
    secondary_url: String,
    log: Option<SubmitLogSink>,
}

impl<P> DualSubmit<P> {
    /// Primary only: byte-for-byte the existing behaviour plus optional logging.
    pub fn primary_only(
        primary: P,
        primary_url: impl Into<String>,
        log: Option<SubmitLogSink>,
    ) -> Self {
        Self {
            primary,
            primary_url: primary_url.into(),
            secondary: None,
            secondary_url: String::new(),
            log,
        }
    }

    pub fn with_secondary(
        primary: P,
        primary_url: impl Into<String>,
        secondary: Arc<dyn SubmitBlock + Send + Sync>,
        secondary_url: impl Into<String>,
        log: Option<SubmitLogSink>,
    ) -> Self {
        Self {
            primary,
            primary_url: primary_url.into(),
            secondary: Some(secondary),
            secondary_url: secondary_url.into(),
            log,
        }
    }

    pub fn has_secondary(&self) -> bool {
        self.secondary.is_some()
    }
}

impl<P: SubmitBlock + Send + Sync> SubmitBlock for DualSubmit<P> {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async move {
            let hash = consensus_hash_from_block_hex(block_hex).unwrap_or_default();
            let block_bytes = block_hex.len() / 2;

            // Fire the secondary FIRST but do not await it: spawning is cheap
            // and returns immediately, so the primary is not delayed, while both
            // nodes receive the block within microseconds of each other.
            if let Some(secondary) = &self.secondary {
                let secondary = Arc::clone(secondary);
                let hex = block_hex.to_string();
                let url = self.secondary_url.clone();
                let log = self.log.clone();
                let hash_for_task = hash.clone();
                tokio::spawn(async move {
                    let started = Instant::now();
                    let result = secondary.submit_block(&hex).await;
                    let latency_ms = started.elapsed().as_millis() as u64;
                    let normalised = result.map_err(|e| e.to_string());
                    let (outcome, detail) = outcome_label(&normalised);
                    if let Some(log) = log {
                        log.record(&SubmitCallRecord {
                            consensus_block_hash: hash_for_task,
                            target: "secondary".to_string(),
                            target_url: url,
                            latency_ms,
                            outcome: outcome.to_string(),
                            detail,
                            block_bytes: hex.len() / 2,
                        });
                    }
                });
            }

            let started = Instant::now();
            let result = self.primary.submit_block(block_hex).await;
            let latency_ms = started.elapsed().as_millis() as u64;

            if let Some(log) = &self.log {
                let normalised = match &result {
                    Ok(v) => Ok(v.clone()),
                    Err(e) => Err(e.to_string()),
                };
                let (outcome, detail) = outcome_label(&normalised);
                log.record(&SubmitCallRecord {
                    consensus_block_hash: hash,
                    target: "primary".to_string(),
                    target_url: self.primary_url.clone(),
                    latency_ms,
                    outcome: outcome.to_string(),
                    detail,
                    block_bytes,
                });
            }

            result
        })
    }

    /// Delegated to the primary only. `block_known` classifies a PRIMARY
    /// rejection; asking the secondary would answer a question about the wrong
    /// node and could mislabel a production rejection.
    fn block_known<'a>(&'a self, block_hash_hex: &'a str) -> BlockKnownFuture<'a> {
        self.primary.block_known(block_hash_hex)
    }
}

/// Build the submitter for the sidecar from config.
///
/// Returns primary-only when no secondary URL is configured, so an unset
/// secondary is exactly today's behaviour.
pub fn build_submitter<P: SubmitBlock + Send + Sync>(
    primary: P,
    primary_url: &str,
    secondary: Option<(Arc<dyn SubmitBlock + Send + Sync>, &str)>,
    log_path: Option<&Path>,
) -> DualSubmit<P> {
    let log = match log_path {
        Some(path) => match SubmitLogSink::new(path) {
            Ok(sink) => Some(sink),
            Err(error) => {
                warn!(%error, path = %path.display(), "submit log unavailable; continuing without it");
                None
            }
        },
        None => None,
    };
    match secondary {
        Some((node, url)) => DualSubmit::with_secondary(primary, primary_url, node, url, log),
        None => DualSubmit::primary_only(primary, primary_url, log),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A real mainnet block header (line 1 of the shared fixture in
    /// `zcash-pool-common`), so the consensus hash path is exercised against
    /// bytes Zebra actually produced rather than a synthetic header that could
    /// hide an offset or byte-order bug.
    fn real_header_hex() -> String {
        zcash_pool_common::fixtures::mainnet_header_hex().to_string()
    }

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<String>>,
        calls: AtomicUsize,
        response: Option<String>,
        fail: bool,
        delay: Option<Duration>,
    }

    impl SubmitBlock for Recorder {
        fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
            Box::pin(async move {
                if let Some(d) = self.delay {
                    tokio::time::sleep(d).await;
                }
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.seen.lock().unwrap().push(block_hex.to_string());
                if self.fail {
                    return Err("secondary exploded".into());
                }
                Ok(self.response.clone())
            })
        }
    }

    fn sink(dir: &std::path::Path) -> (SubmitLogSink, std::path::PathBuf) {
        let path = dir.join("submit.jsonl");
        (SubmitLogSink::new(&path).unwrap(), path)
    }

    // ---------------------------------------------------------------
    // The secondary must never affect the primary.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn secondary_receives_the_same_block_as_the_primary() {
        let secondary = Arc::new(Recorder::default());
        let dual = DualSubmit::with_secondary(
            Recorder::default(),
            "http://primary:8232",
            secondary.clone() as Arc<dyn SubmitBlock + Send + Sync>,
            "http://secondary:8232",
            None,
        );
        let hex = real_header_hex();
        dual.submit_block(&hex).await.unwrap();
        // The spawned task needs a scheduling turn.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let seen = secondary.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "secondary should get exactly one submit");
        assert_eq!(seen[0], hex, "secondary must receive the identical block");
    }

    #[tokio::test]
    async fn a_failing_secondary_does_not_change_the_primary_result() {
        let secondary = Arc::new(Recorder {
            fail: true,
            ..Default::default()
        });
        let dual = DualSubmit::with_secondary(
            Recorder {
                response: Some("duplicate".into()),
                ..Default::default()
            },
            "http://primary:8232",
            secondary as Arc<dyn SubmitBlock + Send + Sync>,
            "http://secondary:8232",
            None,
        );
        let out = dual.submit_block(&real_header_hex()).await;
        assert_eq!(out.unwrap(), Some("duplicate".to_string()));
    }

    #[tokio::test]
    async fn a_slow_secondary_does_not_delay_the_primary() {
        // The production hazard: a wedged second node must not hold up block
        // submission. Ten seconds of secondary delay against a primary that
        // must still return promptly.
        let secondary = Arc::new(Recorder {
            delay: Some(Duration::from_secs(10)),
            ..Default::default()
        });
        let dual = DualSubmit::with_secondary(
            Recorder::default(),
            "http://primary:8232",
            secondary as Arc<dyn SubmitBlock + Send + Sync>,
            "http://secondary:8232",
            None,
        );
        let started = Instant::now();
        dual.submit_block(&real_header_hex()).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "primary took {elapsed:?}; a slow secondary must not block it"
        );
    }

    #[tokio::test]
    async fn without_a_secondary_only_the_primary_is_called() {
        let dual = DualSubmit::primary_only(Recorder::default(), "http://primary:8232", None);
        assert!(!dual.has_secondary());
        assert_eq!(dual.submit_block(&real_header_hex()).await.unwrap(), None);
    }

    // ---------------------------------------------------------------
    // The log record.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn log_carries_the_consensus_hash_not_the_internal_object_id() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = sink(dir.path());
        let hex = real_header_hex();
        let expected = consensus_hash_from_block_hex(&hex).unwrap();

        let dual = DualSubmit::primary_only(Recorder::default(), "http://primary:8232", Some(log));
        dual.submit_block(&hex).await.unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains(&format!("\"consensus_block_hash\":\"{expected}\"")),
            "log must carry the consensus hash; got {body}"
        );
        // The relay's internal BLAKE2b object id must NOT be what we logged.
        let internal = hex::encode(sovright_relay::zcash_block_hash(
            &hex::decode(&hex[..ZCASH_FULL_HEADER_SIZE * 2]).unwrap(),
        ));
        assert!(
            !body.contains(&internal),
            "logged the internal object id instead of the consensus hash"
        );
    }

    #[tokio::test]
    async fn both_targets_are_logged_and_labelled() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = sink(dir.path());
        let dual = DualSubmit::with_secondary(
            Recorder::default(),
            "http://primary:8232",
            Arc::new(Recorder::default()) as Arc<dyn SubmitBlock + Send + Sync>,
            "http://secondary:8232",
            Some(log),
        );
        dual.submit_block(&real_header_hex()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "one record per target; got {body}");
        assert!(body.contains("\"target\":\"primary\""));
        assert!(body.contains("\"target\":\"secondary\""));
        assert!(body.contains("\"target_url\":\"http://secondary:8232\""));
    }

    #[test]
    fn outcome_labels_cover_every_node_response() {
        assert_eq!(outcome_label(&Ok(None)).0, "accepted");
        assert_eq!(outcome_label(&Ok(Some("duplicate".into()))).0, "duplicate");
        assert_eq!(
            outcome_label(&Ok(Some("duplicate-inconclusive".into()))).0,
            "duplicate_inconclusive"
        );
        let (label, detail) = outcome_label(&Ok(Some("rejected".into())));
        assert_eq!(label, "rejected");
        assert_eq!(detail.as_deref(), Some("rejected"));
        let (label, detail) = outcome_label(&Err("connect refused".into()));
        assert_eq!(label, "error");
        assert_eq!(detail.as_deref(), Some("connect refused"));
    }

    #[test]
    fn a_rejection_keeps_the_node_response_for_diagnosis() {
        // "rejected" is opaque; without the raw string a later reader cannot
        // tell a race-loss from a genuinely invalid block.
        let (_, detail) = outcome_label(&Ok(Some("rejected".into())));
        assert!(detail.is_some());
    }

    #[test]
    fn malformed_block_hex_yields_no_hash_rather_than_panicking() {
        assert!(consensus_hash_from_block_hex("").is_none());
        assert!(consensus_hash_from_block_hex("zzzz").is_none());
        assert!(consensus_hash_from_block_hex("abcd").is_none(), "too short");
    }

    /// THE STRUCTURAL GUARANTEE.
    ///
    /// This drives a real public submit entry point -- the raw-segment path,
    /// which is the one that carried almost all traffic and was left inert for a
    /// week by #88 -- and asserts the secondary still received the block.
    ///
    /// Nothing in `submit.rs` knows a secondary exists. It cannot, because the
    /// second target lives inside the `SubmitBlock` it was handed. That is the
    /// whole point of the decorator: a sixth call site added tomorrow is covered
    /// without anyone remembering to wire it.
    #[tokio::test]
    async fn a_real_submit_entry_point_reaches_the_secondary_without_knowing_it_exists() {
        use crate::submit::{SubmissionOutcome, SubmitBlockMode, handle_relay_raw_block};

        let dir = tempfile::tempdir().unwrap();
        let (log, path) = sink(dir.path());
        let secondary = Arc::new(Recorder::default());
        let dual = DualSubmit::with_secondary(
            Recorder::default(),
            "http://primary:8232",
            secondary.clone() as Arc<dyn SubmitBlock + Send + Sync>,
            "http://secondary:8232",
            Some(log),
        );

        // A real mainnet block: header plus its transactions, as the raw path
        // receives it. Assembled by the shared loader, which writes the
        // transaction count as CompactSize rather than a bare byte.
        let raw = zcash_pool_common::fixtures::mainnet_raw_block();

        let outcome = handle_relay_raw_block(&dual, &raw, None, SubmitBlockMode::Live)
            .await
            .expect("raw block should submit");
        assert!(matches!(outcome, SubmissionOutcome::Submitted { .. }));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            secondary.calls.load(Ordering::SeqCst),
            1,
            "the secondary must receive the block through the ordinary submit path"
        );
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"target\":\"primary\""));
        assert!(body.contains("\"target\":\"secondary\""));
    }

    #[test]
    fn json_line_escapes_quotes_in_the_detail() {
        let rec = SubmitCallRecord {
            consensus_block_hash: "aa".into(),
            target: "primary".into(),
            target_url: "http://x".into(),
            latency_ms: 5,
            outcome: "rejected".into(),
            detail: Some("bad \"thing\"".into()),
            block_bytes: 10,
        };
        let line = rec.to_json_line();
        assert!(line.contains("\\\"thing\\\""), "unescaped quote in {line}");
        // Must remain one line -- a newline would corrupt the JSONL stream.
        assert_eq!(line.lines().count(), 1);
    }
}
