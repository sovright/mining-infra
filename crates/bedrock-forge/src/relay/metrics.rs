//! Relay metrics for operational monitoring

use std::sync::atomic::{AtomicU64, Ordering};

/// Relay node metrics
#[derive(Debug, Default)]
pub struct RelayMetrics {
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Total packets forwarded
    pub packets_forwarded: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Invalid chunks rejected
    pub invalid_chunks: AtomicU64,
    /// Sessions created
    pub sessions_created: AtomicU64,
    /// Sessions expired
    pub sessions_expired: AtomicU64,
}

impl RelayMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment packets received
    pub fn inc_packets_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment packets forwarded
    pub fn inc_packets_forwarded(&self, count: u64) {
        self.packets_forwarded.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment auth failures
    pub fn inc_auth_failures(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment invalid chunks
    pub fn inc_invalid_chunks(&self) {
        self.invalid_chunks.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment sessions created
    pub fn inc_sessions_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to sessions expired count
    pub fn add_sessions_expired(&self, count: u64) {
        self.sessions_expired.fetch_add(count, Ordering::Relaxed);
    }

    /// Get snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            invalid_chunks: self.invalid_chunks.load(Ordering::Relaxed),
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_expired: self.sessions_expired.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub auth_failures: u64,
    pub invalid_chunks: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
}

/// Render relay metrics in Prometheus text exposition format.
pub fn render_prometheus_text(snapshot: &MetricsSnapshot, sessions: usize) -> String {
    let mut text = String::new();
    push_metric(
        &mut text,
        "bedrock_forge_relay_sessions",
        "Current relay sessions.",
        "gauge",
        sessions as u64,
    );
    push_metric(
        &mut text,
        "bedrock_forge_relay_packets_received_total",
        "Total relay packets received.",
        "counter",
        snapshot.packets_received,
    );
    push_metric(
        &mut text,
        "bedrock_forge_relay_packets_forwarded_total",
        "Total relay packets forwarded.",
        "counter",
        snapshot.packets_forwarded,
    );
    push_metric(
        &mut text,
        "bedrock_forge_relay_auth_failures_total",
        "Total relay authentication failures.",
        "counter",
        snapshot.auth_failures,
    );
    push_metric(
        &mut text,
        "bedrock_forge_relay_invalid_chunks_total",
        "Total invalid chunks rejected by the relay.",
        "counter",
        snapshot.invalid_chunks,
    );
    push_metric(
        &mut text,
        "bedrock_forge_relay_sessions_created_total",
        "Total relay sessions created.",
        "counter",
        snapshot.sessions_created,
    );
    push_metric(
        &mut text,
        "bedrock_forge_relay_sessions_expired_total",
        "Total relay sessions expired.",
        "counter",
        snapshot.sessions_expired,
    );
    text
}

fn push_metric(text: &mut String, name: &str, help: &str, metric_type: &str, value: u64) {
    text.push_str("# HELP ");
    text.push_str(name);
    text.push(' ');
    text.push_str(help);
    text.push('\n');
    text.push_str("# TYPE ");
    text.push_str(name);
    text.push(' ');
    text.push_str(metric_type);
    text.push('\n');
    text.push_str(name);
    text.push(' ');
    text.push_str(&value.to_string());
    text.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_increment() {
        let metrics = RelayMetrics::new();

        metrics.inc_packets_received();
        metrics.inc_packets_received();
        metrics.inc_auth_failures();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.packets_received, 2);
        assert_eq!(snapshot.auth_failures, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }

    #[test]
    fn prometheus_text_includes_relay_counters_and_sessions() {
        let snapshot = MetricsSnapshot {
            packets_received: 12,
            packets_forwarded: 7,
            auth_failures: 1,
            invalid_chunks: 2,
            sessions_created: 3,
            sessions_expired: 4,
        };

        let text = render_prometheus_text(&snapshot, 5);

        assert!(text.contains("# HELP bedrock_forge_relay_sessions Current relay sessions."));
        assert!(text.contains("# TYPE bedrock_forge_relay_sessions gauge"));
        assert!(text.contains("bedrock_forge_relay_sessions 5\n"));
        assert!(text.contains("bedrock_forge_relay_packets_received_total 12\n"));
        assert!(text.contains("bedrock_forge_relay_packets_forwarded_total 7\n"));
        assert!(text.contains("bedrock_forge_relay_auth_failures_total 1\n"));
        assert!(text.contains("bedrock_forge_relay_invalid_chunks_total 2\n"));
        assert!(text.contains("bedrock_forge_relay_sessions_created_total 3\n"));
        assert!(text.contains("bedrock_forge_relay_sessions_expired_total 4\n"));
    }
}
