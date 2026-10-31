//! The ingress's Prometheus textfile, in the form the sidecar writes for its
//! collector. Reasons are the only label: peers and block hashes are unbounded,
//! so they stay in the `p2p_block_body_rejected` event.

use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use sovright_relay::BlockBodyError;
use sovright_relay_sidecar::metrics_textfile::write_metrics_textfile;
use tokio::time::MissedTickBehavior;
use tracing::warn;

/// How often the textfile is rewritten, the same as the sidecar's.
pub const METRICS_WRITE_INTERVAL: Duration = Duration::from_secs(30);

const BLOCK_BODY_REJECTED: &str = "sovright_p2p_ingress_block_body_rejected_total";
const UNVERIFIED_FORWARDED: &str = "sovright_p2p_ingress_block_body_unverified_forwarded_total";
const UNVERIFIED_FORWARD_ENABLED: &str = "sovright_p2p_ingress_unreadable_block_forward_enabled";

/// Block bodies refused at ingress, by reason. Counting is one atomic add, so a
/// burst of refusals does no file work: the file has its own schedule.
#[derive(Debug, Default)]
pub struct BlockBodyRejections {
    counts: [AtomicU64; BlockBodyError::ALL.len()],
    unverified_forwards: AtomicU64,
    unverified_forward_enabled: AtomicBool,
}

impl BlockBodyRejections {
    pub fn record(&self, error: &BlockBodyError) {
        self.counts[error.kind_index()].fetch_add(1, Ordering::Relaxed);
    }

    /// One body sent on without the Merkle and duplicate checks.
    pub fn record_unverified_forward(&self) {
        self.unverified_forwards.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_unverified_forward_enabled(&self) {
        self.unverified_forward_enabled
            .store(true, Ordering::Relaxed);
    }

    fn render(&self) -> String {
        let mut text = format!(
            "# HELP {BLOCK_BODY_REJECTED} Block bodies refused at ingress, by reason.\n\
             # TYPE {BLOCK_BODY_REJECTED} counter\n"
        );
        for (kind, count) in BlockBodyError::ALL.iter().zip(&self.counts) {
            let label = kind.label();
            let count = count.load(Ordering::Relaxed);
            writeln!(text, "{BLOCK_BODY_REJECTED}{{reason=\"{label}\"}} {count}")
                .expect("writing to a String cannot fail");
        }
        let unverified = self.unverified_forwards.load(Ordering::Relaxed);
        let enabled = u8::from(self.unverified_forward_enabled.load(Ordering::Relaxed));
        write!(
            text,
            "# HELP {UNVERIFIED_FORWARDED} Bodies forwarded without the Merkle and duplicate checks.\n\
             # TYPE {UNVERIFIED_FORWARDED} counter\n\
             {UNVERIFIED_FORWARDED} {unverified}\n\
             # HELP {UNVERIFIED_FORWARD_ENABLED} 1 while the emergency bypass is on.\n\
             # TYPE {UNVERIFIED_FORWARD_ENABLED} gauge\n\
             {UNVERIFIED_FORWARD_ENABLED} {enabled}\n"
        )
        .expect("writing to a String cannot fail");
        text
    }
}

/// Rewrite `path` every `every`, starting now so the series exist at zero. The
/// write runs on the blocking pool, one at a time, never on an async worker.
pub fn spawn_metrics_textfile_writer(
    rejections: Arc<BlockBodyRejections>,
    path: PathBuf,
    every: Duration,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let text = rejections.render();
            let target = path.clone();
            let written =
                tokio::task::spawn_blocking(move || write_metrics_textfile(&target, &text)).await;
            match written {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!(%error, path = %path.display(), "Failed to write ingress metrics textfile");
                }
                Err(error) => {
                    warn!(%error, path = %path.display(), "Ingress metrics textfile write did not finish");
                }
            }
        }
    });
}

#[cfg(test)]
impl BlockBodyRejections {
    pub fn count(&self, label: &str) -> u64 {
        let index = BlockBodyError::ALL
            .iter()
            .position(|kind| kind.label() == label)
            .expect("a known label");
        self.counts[index].load(Ordering::Relaxed)
    }

    pub fn unverified_forwards(&self) -> u64 {
        self.unverified_forwards.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn every_reason_is_rendered_and_is_the_only_label() {
        let text = BlockBodyRejections::default().render();
        let series: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with(BLOCK_BODY_REJECTED))
            .collect();
        let expected: Vec<String> = BlockBodyError::ALL
            .iter()
            .map(|kind| format!("{BLOCK_BODY_REJECTED}{{reason=\"{}\"}} 0", kind.label()))
            .collect();
        assert_eq!(series, expected);
        assert!(text.contains(&format!("# TYPE {BLOCK_BODY_REJECTED} counter\n")));
    }

    #[test]
    fn a_refusal_counts_under_its_own_reason() {
        let rejections = BlockBodyRejections::default();
        rejections.record(&BlockBodyError::Transaction { index: 3 });
        rejections.record(&BlockBodyError::Transaction { index: 9 });
        rejections.record(&BlockBodyError::MerkleMismatch);

        let text = rejections.render();

        assert!(text.contains(&format!(
            "{BLOCK_BODY_REJECTED}{{reason=\"transaction\"}} 2\n"
        )));
        assert!(text.contains(&format!(
            "{BLOCK_BODY_REJECTED}{{reason=\"merkle_mismatch\"}} 1\n"
        )));
        assert!(text.contains(&format!(
            "{BLOCK_BODY_REJECTED}{{reason=\"duplicate_txid\"}} 0\n"
        )));
    }

    /// The first write comes straight away, and later ones pick up new counts.
    /// Only a hang is timed: the writer's own interval here is a few milliseconds.
    #[tokio::test]
    async fn the_writer_starts_at_zero_and_keeps_the_file_current() {
        let path = std::env::temp_dir().join(format!(
            "sovright-p2p-ingress-metrics-{}.prom",
            std::process::id()
        ));
        let rejections = Arc::new(BlockBodyRejections::default());
        spawn_metrics_textfile_writer(
            Arc::clone(&rejections),
            path.clone(),
            Duration::from_millis(5),
        );
        let shows = |line: String| {
            let path = path.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(30), async {
                    while !fs::read_to_string(&path).is_ok_and(|text| text.contains(&line)) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("the file never showed the count");
            }
        };

        shows(format!("{BLOCK_BODY_REJECTED}{{reason=\"too_large\"}} 0\n")).await;
        rejections.record(&BlockBodyError::TooLarge { bytes: 1 });
        shows(format!("{BLOCK_BODY_REJECTED}{{reason=\"too_large\"}} 1\n")).await;

        let _ = fs::remove_file(&path);
    }
}

#[cfg(test)]
mod bypass_tests {
    use super::*;

    #[test]
    fn the_bypass_has_its_own_counter_and_shows_when_it_is_on() {
        let rejections = BlockBodyRejections::default();
        assert!(
            rejections
                .render()
                .contains(&format!("{UNVERIFIED_FORWARD_ENABLED} 0\n"))
        );

        rejections.set_unverified_forward_enabled();
        rejections.record_unverified_forward();
        let text = rejections.render();

        assert!(text.contains(&format!("{UNVERIFIED_FORWARDED} 1\n")));
        assert!(text.contains(&format!("# TYPE {UNVERIFIED_FORWARDED} counter\n")));
        assert!(text.contains(&format!("{UNVERIFIED_FORWARD_ENABLED} 1\n")));
        assert!(text.contains(&format!("# TYPE {UNVERIFIED_FORWARD_ENABLED} gauge\n")));
    }
}
