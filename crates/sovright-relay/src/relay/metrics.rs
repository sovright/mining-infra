//! Relay metrics for operational monitoring

use std::sync::atomic::{AtomicU64, Ordering};

/// Relay node metrics
#[derive(Debug, Default)]
pub struct RelayMetrics {
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Total packets forwarded
    pub packets_forwarded: AtomicU64,
    /// Socket receive errors
    pub socket_receive_errors: AtomicU64,
    /// Packet send errors while forwarding
    pub packet_send_errors: AtomicU64,
    /// Forward-ready chunks with no eligible peer session
    pub forward_no_peer_chunks: AtomicU64,
    /// Compact block data chunks received
    pub compact_block_chunks_received: AtomicU64,
    /// Compact block data chunks forwarded
    pub compact_block_chunks_forwarded: AtomicU64,
    /// Raw block segment data chunks received
    pub raw_segment_chunks_received: AtomicU64,
    /// Raw block segment data chunks forwarded
    pub raw_segment_chunks_forwarded: AtomicU64,
    /// Raw block segment chunks ignored as recent duplicates
    pub raw_segment_duplicate_chunks: AtomicU64,
    /// Raw segment validation attempts that were not yet reconstructable or conclusive
    pub raw_segment_validation_deferred: AtomicU64,
    /// Raw segment validation attempts that returned true
    pub raw_segment_validation_successes: AtomicU64,
    /// Raw segment validation attempts that returned false
    pub raw_segment_validation_failures: AtomicU64,
    /// Previously buffered nonzero raw segment objects promoted after segment zero validates
    pub raw_segment_cached_promotions: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Invalid chunks rejected
    pub invalid_chunks: AtomicU64,
    /// Sessions created
    pub sessions_created: AtomicU64,
    /// Sessions expired
    pub sessions_expired: AtomicU64,
    /// Incoming packets rejected because the session limit was reached
    pub session_limit_rejections: AtomicU64,
    /// Raw-segment reconstructions observed (first chunk -> PoW validated).
    pub reconstruct_latency_count: AtomicU64,
    /// Sum of reconstruction latencies, milliseconds (with count -> average).
    pub reconstruct_latency_sum_ms: AtomicU64,
    /// Reconstructions that took longer than 2s (tail: loss forced retransmits).
    pub reconstruct_latency_over_2s: AtomicU64,
    /// Reconstructions that took longer than 10s (severe tail).
    pub reconstruct_latency_over_10s: AtomicU64,
    /// Block assemblies dropped after timing out without reconstructing
    /// (delivery misses -- the tail cause, since reconstruction itself is fast).
    pub assembly_misses: AtomicU64,
    /// Of those misses, ones that had >= 90% of data_shards when dropped
    /// (marginal: a parity bump / retransmit would likely have saved them).
    pub assembly_misses_near: AtomicU64,
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

    /// Increment socket receive errors
    pub fn inc_socket_receive_errors(&self) {
        self.socket_receive_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment packet send errors
    pub fn inc_packet_send_errors(&self) {
        self.packet_send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment forward-ready chunks that had no eligible receive peer
    pub fn inc_forward_no_peer_chunks(&self, count: u64) {
        self.forward_no_peer_chunks
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment compact block chunks received
    pub fn inc_compact_block_chunks_received(&self) {
        self.compact_block_chunks_received
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment compact block chunks forwarded
    pub fn inc_compact_block_chunks_forwarded(&self, count: u64) {
        self.compact_block_chunks_forwarded
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment raw segment chunks received
    pub fn inc_raw_segment_chunks_received(&self) {
        self.raw_segment_chunks_received
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment raw segment chunks forwarded
    pub fn inc_raw_segment_chunks_forwarded(&self, count: u64) {
        self.raw_segment_chunks_forwarded
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment duplicate raw segment chunks
    pub fn inc_raw_segment_duplicate_chunks(&self) {
        self.raw_segment_duplicate_chunks
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment deferred raw segment validation attempts
    pub fn inc_raw_segment_validation_deferred(&self) {
        self.raw_segment_validation_deferred
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment successful raw segment validation attempts
    pub fn inc_raw_segment_validation_successes(&self) {
        self.raw_segment_validation_successes
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed raw segment validation attempts
    pub fn inc_raw_segment_validation_failures(&self) {
        self.raw_segment_validation_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment cached raw segment promotions
    pub fn inc_raw_segment_cached_promotions(&self) {
        self.raw_segment_cached_promotions
            .fetch_add(1, Ordering::Relaxed);
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

    /// Increment session limit rejections
    pub fn inc_session_limit_rejections(&self) {
        self.session_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one reconstruction latency (first chunk -> PoW validated), ms.
    /// Feeds the average plus the >2s / >10s tail counters that indicate loss
    /// beyond the FEC parity margin forcing retransmits.
    pub fn record_reconstruct_latency_ms(&self, ms: u64) {
        self.reconstruct_latency_count
            .fetch_add(1, Ordering::Relaxed);
        self.reconstruct_latency_sum_ms
            .fetch_add(ms, Ordering::Relaxed);
        if ms > 2_000 {
            self.reconstruct_latency_over_2s
                .fetch_add(1, Ordering::Relaxed);
        }
        if ms > 10_000 {
            self.reconstruct_latency_over_10s
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record assemblies that timed out without reconstructing (delivery misses)
    /// and how many were near the reconstruction threshold.
    pub fn add_assembly_misses(&self, total: u64, near: u64) {
        self.assembly_misses.fetch_add(total, Ordering::Relaxed);
        self.assembly_misses_near.fetch_add(near, Ordering::Relaxed);
    }

    /// Get snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            socket_receive_errors: self.socket_receive_errors.load(Ordering::Relaxed),
            packet_send_errors: self.packet_send_errors.load(Ordering::Relaxed),
            forward_no_peer_chunks: self.forward_no_peer_chunks.load(Ordering::Relaxed),
            compact_block_chunks_received: self
                .compact_block_chunks_received
                .load(Ordering::Relaxed),
            compact_block_chunks_forwarded: self
                .compact_block_chunks_forwarded
                .load(Ordering::Relaxed),
            raw_segment_chunks_received: self.raw_segment_chunks_received.load(Ordering::Relaxed),
            raw_segment_chunks_forwarded: self.raw_segment_chunks_forwarded.load(Ordering::Relaxed),
            raw_segment_duplicate_chunks: self.raw_segment_duplicate_chunks.load(Ordering::Relaxed),
            raw_segment_validation_deferred: self
                .raw_segment_validation_deferred
                .load(Ordering::Relaxed),
            raw_segment_validation_successes: self
                .raw_segment_validation_successes
                .load(Ordering::Relaxed),
            raw_segment_validation_failures: self
                .raw_segment_validation_failures
                .load(Ordering::Relaxed),
            raw_segment_cached_promotions: self
                .raw_segment_cached_promotions
                .load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            invalid_chunks: self.invalid_chunks.load(Ordering::Relaxed),
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_expired: self.sessions_expired.load(Ordering::Relaxed),
            session_limit_rejections: self.session_limit_rejections.load(Ordering::Relaxed),
            reconstruct_latency_count: self.reconstruct_latency_count.load(Ordering::Relaxed),
            reconstruct_latency_sum_ms: self.reconstruct_latency_sum_ms.load(Ordering::Relaxed),
            reconstruct_latency_over_2s: self.reconstruct_latency_over_2s.load(Ordering::Relaxed),
            reconstruct_latency_over_10s: self.reconstruct_latency_over_10s.load(Ordering::Relaxed),
            assembly_misses: self.assembly_misses.load(Ordering::Relaxed),
            assembly_misses_near: self.assembly_misses_near.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub socket_receive_errors: u64,
    pub packet_send_errors: u64,
    pub forward_no_peer_chunks: u64,
    pub compact_block_chunks_received: u64,
    pub compact_block_chunks_forwarded: u64,
    pub raw_segment_chunks_received: u64,
    pub raw_segment_chunks_forwarded: u64,
    pub raw_segment_duplicate_chunks: u64,
    pub raw_segment_validation_deferred: u64,
    pub raw_segment_validation_successes: u64,
    pub raw_segment_validation_failures: u64,
    pub raw_segment_cached_promotions: u64,
    pub auth_failures: u64,
    pub invalid_chunks: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
    pub session_limit_rejections: u64,
    pub reconstruct_latency_count: u64,
    pub reconstruct_latency_sum_ms: u64,
    pub reconstruct_latency_over_2s: u64,
    pub reconstruct_latency_over_10s: u64,
    pub assembly_misses: u64,
    pub assembly_misses_near: u64,
}

/// Render relay metrics in Prometheus text exposition format.
pub fn render_prometheus_text(snapshot: &MetricsSnapshot, sessions: usize) -> String {
    let mut text = String::new();
    push_metric(
        &mut text,
        "sovright_relay_relay_sessions",
        "Current relay sessions.",
        "gauge",
        sessions as u64,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_packets_received_total",
        "Total relay packets received.",
        "counter",
        snapshot.packets_received,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_packets_forwarded_total",
        "Total relay packets forwarded.",
        "counter",
        snapshot.packets_forwarded,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_socket_receive_errors_total",
        "Total relay socket receive errors.",
        "counter",
        snapshot.socket_receive_errors,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_packet_send_errors_total",
        "Total relay packet send errors while forwarding.",
        "counter",
        snapshot.packet_send_errors,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_forward_no_peer_chunks_total",
        "Total forward-ready chunks with no eligible peer session.",
        "counter",
        snapshot.forward_no_peer_chunks,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_compact_block_chunks_received_total",
        "Total compact block data chunks received.",
        "counter",
        snapshot.compact_block_chunks_received,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_compact_block_chunks_forwarded_total",
        "Total compact block data chunks forwarded.",
        "counter",
        snapshot.compact_block_chunks_forwarded,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_chunks_received_total",
        "Total raw block segment data chunks received.",
        "counter",
        snapshot.raw_segment_chunks_received,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_chunks_forwarded_total",
        "Total raw block segment data chunks forwarded.",
        "counter",
        snapshot.raw_segment_chunks_forwarded,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_duplicate_chunks_total",
        "Total raw block segment chunks ignored as recent duplicates.",
        "counter",
        snapshot.raw_segment_duplicate_chunks,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_validation_deferred_total",
        "Total raw block segment validation attempts deferred.",
        "counter",
        snapshot.raw_segment_validation_deferred,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_validation_successes_total",
        "Total raw block segment validation attempts that succeeded.",
        "counter",
        snapshot.raw_segment_validation_successes,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_validation_failures_total",
        "Total raw block segment validation attempts that failed.",
        "counter",
        snapshot.raw_segment_validation_failures,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_raw_segment_cached_promotions_total",
        "Total cached raw block segment objects promoted after segment zero validation.",
        "counter",
        snapshot.raw_segment_cached_promotions,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_auth_failures_total",
        "Total relay authentication failures.",
        "counter",
        snapshot.auth_failures,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_invalid_chunks_total",
        "Total invalid chunks rejected by the relay.",
        "counter",
        snapshot.invalid_chunks,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_sessions_created_total",
        "Total relay sessions created.",
        "counter",
        snapshot.sessions_created,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_sessions_expired_total",
        "Total relay sessions expired.",
        "counter",
        snapshot.sessions_expired,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_session_limit_rejections_total",
        "Total incoming packets rejected because the relay session limit was reached.",
        "counter",
        snapshot.session_limit_rejections,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_reconstruct_latency_count",
        "Raw-segment reconstructions timed (first chunk -> PoW validated).",
        "counter",
        snapshot.reconstruct_latency_count,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_reconstruct_latency_sum_ms",
        "Sum of raw-segment reconstruction latencies in milliseconds.",
        "counter",
        snapshot.reconstruct_latency_sum_ms,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_reconstruct_latency_over_2s_total",
        "Raw-segment reconstructions slower than 2s (loss-induced retransmit tail).",
        "counter",
        snapshot.reconstruct_latency_over_2s,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_reconstruct_latency_over_10s_total",
        "Raw-segment reconstructions slower than 10s (severe tail).",
        "counter",
        snapshot.reconstruct_latency_over_10s,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_assembly_misses_total",
        "Block assemblies dropped after timing out without reconstructing (delivery misses).",
        "counter",
        snapshot.assembly_misses,
    );
    push_metric(
        &mut text,
        "sovright_relay_relay_assembly_misses_near_total",
        "Delivery misses that had >= 90% of data_shards when dropped (marginal, near-reconstructable).",
        "counter",
        snapshot.assembly_misses_near,
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
        metrics.inc_raw_segment_chunks_received();
        metrics.inc_packet_send_errors();
        metrics.inc_forward_no_peer_chunks(2);
        metrics.inc_raw_segment_validation_deferred();
        metrics.inc_raw_segment_validation_successes();
        metrics.inc_auth_failures();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.packets_received, 2);
        assert_eq!(snapshot.raw_segment_chunks_received, 1);
        assert_eq!(snapshot.raw_segment_validation_deferred, 1);
        assert_eq!(snapshot.raw_segment_validation_successes, 1);
        assert_eq!(snapshot.auth_failures, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
        assert_eq!(snapshot.packet_send_errors, 1);
        assert_eq!(snapshot.forward_no_peer_chunks, 2);
    }

    #[test]
    fn prometheus_text_includes_relay_counters_and_sessions() {
        let snapshot = MetricsSnapshot {
            packets_received: 12,
            packets_forwarded: 7,
            socket_receive_errors: 13,
            packet_send_errors: 14,
            forward_no_peer_chunks: 15,
            compact_block_chunks_received: 5,
            compact_block_chunks_forwarded: 4,
            raw_segment_chunks_received: 3,
            raw_segment_chunks_forwarded: 2,
            raw_segment_duplicate_chunks: 1,
            raw_segment_validation_deferred: 8,
            raw_segment_validation_successes: 9,
            raw_segment_validation_failures: 10,
            raw_segment_cached_promotions: 11,
            auth_failures: 1,
            invalid_chunks: 2,
            sessions_created: 3,
            sessions_expired: 4,
            session_limit_rejections: 6,
            reconstruct_latency_count: 20,
            reconstruct_latency_sum_ms: 8000,
            reconstruct_latency_over_2s: 2,
            reconstruct_latency_over_10s: 1,
            assembly_misses: 7,
            assembly_misses_near: 3,
        };

        let text = render_prometheus_text(&snapshot, 5);

        assert!(text.contains("# HELP sovright_relay_relay_sessions Current relay sessions."));
        assert!(text.contains("# TYPE sovright_relay_relay_sessions gauge"));
        assert!(text.contains("sovright_relay_relay_sessions 5\n"));
        assert!(text.contains("sovright_relay_relay_packets_received_total 12\n"));
        assert!(text.contains("sovright_relay_relay_packets_forwarded_total 7\n"));
        assert!(text.contains("sovright_relay_relay_socket_receive_errors_total 13\n"));
        assert!(text.contains("sovright_relay_relay_packet_send_errors_total 14\n"));
        assert!(text.contains("sovright_relay_relay_forward_no_peer_chunks_total 15\n"));
        assert!(text.contains("sovright_relay_relay_compact_block_chunks_received_total 5\n"));
        assert!(text.contains("sovright_relay_relay_compact_block_chunks_forwarded_total 4\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_chunks_received_total 3\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_chunks_forwarded_total 2\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_duplicate_chunks_total 1\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_validation_deferred_total 8\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_validation_successes_total 9\n"));
        assert!(text.contains("sovright_relay_relay_reconstruct_latency_count 20\n"));
        assert!(text.contains("sovright_relay_relay_reconstruct_latency_sum_ms 8000\n"));
        assert!(text.contains("sovright_relay_relay_reconstruct_latency_over_2s_total 2\n"));
        assert!(text.contains("sovright_relay_relay_reconstruct_latency_over_10s_total 1\n"));
        assert!(text.contains("sovright_relay_relay_assembly_misses_total 7\n"));
        assert!(text.contains("sovright_relay_relay_assembly_misses_near_total 3\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_validation_failures_total 10\n"));
        assert!(text.contains("sovright_relay_relay_raw_segment_cached_promotions_total 11\n"));
        assert!(text.contains("sovright_relay_relay_auth_failures_total 1\n"));
        assert!(text.contains("sovright_relay_relay_invalid_chunks_total 2\n"));
        assert!(text.contains("sovright_relay_relay_sessions_created_total 3\n"));
        assert!(text.contains("sovright_relay_relay_sessions_expired_total 4\n"));
        assert!(text.contains("sovright_relay_relay_session_limit_rejections_total 6\n"));
    }

    #[test]
    fn record_reconstruct_latency_tracks_count_sum_and_tails() {
        let metrics = RelayMetrics::new();
        metrics.record_reconstruct_latency_ms(300); // fast
        metrics.record_reconstruct_latency_ms(2_000); // exactly 2s: NOT over_2s (strict >)
        metrics.record_reconstruct_latency_ms(3_500); // over_2s
        metrics.record_reconstruct_latency_ms(25_000); // over_2s AND over_10s

        let s = metrics.snapshot();
        assert_eq!(s.reconstruct_latency_count, 4);
        assert_eq!(s.reconstruct_latency_sum_ms, 300 + 2_000 + 3_500 + 25_000);
        assert_eq!(s.reconstruct_latency_over_2s, 2);
        assert_eq!(s.reconstruct_latency_over_10s, 1);
    }
}
