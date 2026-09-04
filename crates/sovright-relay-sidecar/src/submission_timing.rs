//! Per-attempt submission timing. Monotonic durations are authoritative; wall
//! timestamps exist only for cross-host joins and require synchronized clocks.
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::submit::{
    BlockKnownFuture, RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitFuture,
};

#[derive(Clone, Copy, Serialize)]
struct RpcTiming {
    receive_to_rpc_ms: u64,
    rpc_ms: u64,
}

/// Wraps the real RPC without changing its result or rejection classification.
/// One instance covers one handler attempt, including gate/lookup time.
pub struct TimedSubmitter<'a, S> {
    inner: &'a S,
    received: Instant,
    received_unix_ms: u64,
    consensus_block_hash: String,
    path: &'static str,
    rpc: Mutex<Option<RpcTiming>>,
}

#[derive(Serialize)]
pub struct SubmissionTiming {
    pub event: &'static str,
    pub schema_version: u8,
    pub consensus_block_hash: String,
    pub path: &'static str,
    pub outcome: &'static str,
    pub received_unix_ms: u64,
    pub receive_to_outcome_ms: u64,
    #[serde(flatten)]
    rpc: Option<RpcTiming>,
}

impl<'a, S> TimedSubmitter<'a, S> {
    pub fn new(inner: &'a S, received: Instant, header: &[u8], path: &'static str) -> Self {
        let now = Instant::now();
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            inner,
            received,
            received_unix_ms: unix_ms
                .saturating_sub(now.saturating_duration_since(received).as_millis() as u64),
            consensus_block_hash: sovright_relay::consensus_block_hash_display(header),
            path,
            rpc: Mutex::new(None),
        }
    }

    pub fn finish(&self, outcome: &Result<SubmissionOutcome, RelayBlockError>) -> SubmissionTiming {
        let outcome = match outcome {
            Ok(SubmissionOutcome::Submitted { status, .. }) => status.as_str(),
            Ok(SubmissionOutcome::DryRun(_)) => "dry_run",
            Ok(SubmissionOutcome::NeedsTransactions { .. }) => "needs_transactions",
            Ok(SubmissionOutcome::GateRejected { .. }) => "gate_rejected",
            Err(RelayBlockError::SubmitRejected(_, class)) => class.as_str(),
            Err(RelayBlockError::SubmitFailed(_)) => "rpc_failed",
            Err(_) => "not_candidate",
        };
        let timing = SubmissionTiming {
            event: "relay_submission_timing",
            schema_version: 1,
            consensus_block_hash: self.consensus_block_hash.clone(),
            path: self.path,
            outcome,
            received_unix_ms: self.received_unix_ms,
            receive_to_outcome_ms: self.received.elapsed().as_millis() as u64,
            rpc: *self.rpc.lock().expect("timing mutex poisoned"),
        };
        // A JSON message works with both the current text journal and a JSON
        // tracing subscriber. No block bytes or RPC credentials are recorded.
        tracing::info!(
            "relay_submission_timing {}",
            serde_json::to_string(&timing).expect("timing serialization")
        );
        timing
    }
}

impl<S: SubmitBlock + Sync> SubmitBlock for TimedSubmitter<'_, S> {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        Box::pin(async move {
            let started = Instant::now();
            let result = self.inner.submit_block(block_hex).await;
            *self.rpc.lock().expect("timing mutex poisoned") = Some(RpcTiming {
                receive_to_rpc_ms: started.saturating_duration_since(self.received).as_millis()
                    as u64,
                rpc_ms: started.elapsed().as_millis() as u64,
            });
            result
        })
    }

    fn block_known<'a>(&'a self, hash: &'a str) -> BlockKnownFuture<'a> {
        self.inner.block_known(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct Fake {
        calls: AtomicUsize,
    }
    impl SubmitBlock for Fake {
        fn submit_block<'a>(&'a self, _: &'a str) -> SubmitFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(Some("rejected".into()))
            })
        }
        fn block_known<'a>(&'a self, _: &'a str) -> BlockKnownFuture<'a> {
            Box::pin(async { Some(true) })
        }
    }

    #[tokio::test]
    async fn preserves_rpc_and_lookup_results_and_separates_rpc_time() {
        let fake = Fake {
            calls: AtomicUsize::new(0),
        };
        let timing = TimedSubmitter::new(
            &fake,
            Instant::now() - Duration::from_millis(20),
            &[0; 1487],
            "skeleton",
        );
        assert_eq!(
            timing.submit_block("abcd").await.unwrap(),
            Some("rejected".into())
        );
        assert_eq!(timing.block_known("hash").await, Some(true));
        let record = timing.finish(&Err(RelayBlockError::SubmitRejected(
            "rejected".into(),
            crate::submit::SubmitRejectionClass::RaceLost,
        )));
        let rpc = record.rpc.unwrap();
        assert!(rpc.receive_to_rpc_ms >= 20);
        assert!(rpc.rpc_ms >= 5);
        assert!(record.receive_to_outcome_ms >= rpc.receive_to_rpc_ms + rpc.rpc_ms);
        assert_eq!(record.outcome, "race_lost");
        assert_eq!(fake.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            record.consensus_block_hash,
            sovright_relay::consensus_block_hash_display(&[0; 1487])
        );
    }

    #[test]
    fn no_rpc_is_not_reported_as_zero_latency_rpc() {
        let fake = Fake {
            calls: AtomicUsize::new(0),
        };
        let timing = TimedSubmitter::new(&fake, Instant::now(), &[0; 1487], "compact");
        let record = timing.finish(&Err(RelayBlockError::EmptyTransactions));
        assert_eq!(record.outcome, "not_candidate");
        let value = serde_json::to_value(record).unwrap();
        assert!(value.get("rpc_ms").is_none());
        assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
    }
}
