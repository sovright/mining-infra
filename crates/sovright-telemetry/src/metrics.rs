//! Prometheus metrics for pool monitoring
//!
//! Provides comprehensive metrics for monitoring Sovright mining infrastructure pool operations
//! including connections, shares, blocks, hashrate, and latency measurements.

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

/// Pool metrics collection for Prometheus monitoring
///
/// This struct contains all metrics tracked by the pool server,
/// organized by category: connections, shares, blocks, hashrate, and latency.
#[derive(Clone)]
pub struct PoolMetrics {
    registry: Registry,

    // Connection metrics
    /// Total number of miner connections established
    pub connections_total: IntCounter,
    /// Currently active miner connections
    pub connections_active: IntGauge,
    /// Total number of Job Declarator connections established
    pub jd_connections_total: IntCounter,
    /// Currently active Job Declarator connections
    pub jd_connections_active: IntGauge,

    // Share metrics
    /// Total shares submitted by miners, labeled by difficulty tier
    pub shares_submitted: IntCounterVec,
    /// Total accepted shares
    pub shares_accepted: IntCounter,
    /// Total rejected shares, labeled by rejection reason
    pub shares_rejected: IntCounterVec,

    // Per-worker metrics (for Sovright API ingest)
    /// Per-worker hashrate in sol/s
    pub worker_hashrate: prometheus::GaugeVec,
    /// Per-worker accepted shares (counter)
    pub worker_shares_accepted: IntCounterVec,
    /// Per-worker rejected shares (counter)
    pub worker_shares_rejected: IntCounterVec,
    /// Per-worker blocks found (counter)
    pub worker_blocks_found: IntCounterVec,
    /// Pool-level aggregate hashrate
    pub pool_total_hashrate: Gauge,
    /// Pool-level connected miners count
    pub pool_connected_miners: IntGauge,
    /// Pool-level connected workers count
    pub pool_connected_workers: IntGauge,
    /// Network difficulty
    pub network_difficulty: Gauge,

    // Block metrics
    /// Total blocks found by the pool
    pub blocks_found: IntCounter,
    /// Total blocks submitted to the network
    pub blocks_submitted: IntCounter,

    // Hashrate
    /// Estimated pool hashrate in H/s
    pub estimated_hashrate: Gauge,

    // Latency metrics
    /// Histogram of share validation durations in seconds
    pub share_validation_duration: Histogram,
    /// Histogram of template fetch durations in seconds
    pub template_fetch_duration: Histogram,

    // Noise/encryption metrics
    /// Total Noise handshakes initiated
    pub noise_handshakes_total: IntCounter,
    /// Total failed Noise handshakes
    pub noise_handshakes_failed: IntCounter,

    // Security metrics (attack detection and monitoring)
    /// Total decryption failures (potential EROSION attack indicator)
    pub decryption_failures: IntCounter,
    /// Total replay attempts detected
    pub replay_attempts: IntCounter,
    /// Total sequence anomalies detected
    pub sequence_anomalies: IntCounter,
    /// Currently flagged suspicious addresses
    pub flagged_addresses: IntGauge,
    /// Total short-lived connections (potential attack indicator)
    pub short_lived_connections: IntCounter,
    /// Histogram of connection durations in seconds
    pub connection_duration: Histogram,
}

impl PoolMetrics {
    /// Create a new PoolMetrics instance with all metrics registered
    pub fn new() -> Self {
        let registry = Registry::new();

        // Connection metrics
        let connections_total = IntCounter::with_opts(
            Opts::new(
                "pool_connections_total",
                "Total miner connections established",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let connections_active = IntGauge::with_opts(
            Opts::new(
                "pool_connections_active",
                "Currently active miner connections",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let jd_connections_total = IntCounter::with_opts(
            Opts::new(
                "pool_jd_connections_total",
                "Total Job Declarator connections established",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let jd_connections_active = IntGauge::with_opts(
            Opts::new(
                "pool_jd_connections_active",
                "Currently active Job Declarator connections",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        // Share metrics
        let shares_submitted = IntCounterVec::new(
            Opts::new("pool_shares_submitted_total", "Total shares submitted")
                .namespace("sovright"),
            &["difficulty_tier"],
        )
        .expect("metric can be created");

        let shares_accepted = IntCounter::with_opts(
            Opts::new("pool_shares_accepted_total", "Total accepted shares").namespace("sovright"),
        )
        .expect("metric can be created");

        let shares_rejected = IntCounterVec::new(
            Opts::new("pool_shares_rejected_total", "Total rejected shares").namespace("sovright"),
            &["reason"],
        )
        .expect("metric can be created");

        // Per-worker metrics (names match what Sovright API ingest expects)
        let worker_hashrate = prometheus::GaugeVec::new(
            Opts::new("hashrate_sol_s", "Worker hashrate in solutions per second"),
            &["worker"],
        )
        .expect("metric can be created");

        // Per-worker share/block counters use a `worker_` prefix to distinguish
        // them from the pool-level `pool_shares_*` / `pool_blocks_*` counters.
        // Each metric carries a `worker` label for per-miner breakdowns.
        let worker_shares_accepted = IntCounterVec::new(
            Opts::new("worker_shares_accepted_total", "Per-worker accepted shares"),
            &["worker"],
        )
        .expect("metric can be created");

        let worker_shares_rejected = IntCounterVec::new(
            Opts::new("worker_shares_rejected_total", "Per-worker rejected shares"),
            &["worker"],
        )
        .expect("metric can be created");

        let worker_blocks_found = IntCounterVec::new(
            Opts::new("worker_blocks_found_total", "Per-worker blocks found"),
            &["worker"],
        )
        .expect("metric can be created");

        let pool_total_hashrate = Gauge::with_opts(Opts::new(
            "pool_total_hashrate_sol_s",
            "Pool aggregate hashrate in sol/s",
        ))
        .expect("metric can be created");

        let pool_connected_miners = IntGauge::with_opts(Opts::new(
            "pool_connected_miners",
            "Number of connected miners",
        ))
        .expect("metric can be created");

        let pool_connected_workers = IntGauge::with_opts(Opts::new(
            "pool_connected_workers",
            "Number of connected workers",
        ))
        .expect("metric can be created");

        let network_difficulty = Gauge::with_opts(Opts::new(
            "network_difficulty",
            "Current network difficulty",
        ))
        .expect("metric can be created");

        // Block metrics
        let blocks_found = IntCounter::with_opts(
            Opts::new("pool_blocks_found_total", "Total blocks found by the pool")
                .namespace("sovright"),
        )
        .expect("metric can be created");

        let blocks_submitted = IntCounter::with_opts(
            Opts::new(
                "pool_blocks_submitted_total",
                "Total blocks submitted to the network",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        // Hashrate
        let estimated_hashrate = Gauge::with_opts(
            Opts::new("pool_estimated_hashrate", "Estimated pool hashrate in H/s")
                .namespace("sovright"),
        )
        .expect("metric can be created");

        // Latency metrics
        let share_validation_duration = Histogram::with_opts(
            HistogramOpts::new(
                "pool_share_validation_duration_seconds",
                "Share validation duration in seconds",
            )
            .namespace("sovright")
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
            ]),
        )
        .expect("metric can be created");

        let template_fetch_duration = Histogram::with_opts(
            HistogramOpts::new(
                "pool_template_fetch_duration_seconds",
                "Template fetch duration in seconds",
            )
            .namespace("sovright")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
        )
        .expect("metric can be created");

        // Noise/encryption metrics
        let noise_handshakes_total = IntCounter::with_opts(
            Opts::new(
                "pool_noise_handshakes_total",
                "Total Noise handshakes initiated",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let noise_handshakes_failed = IntCounter::with_opts(
            Opts::new(
                "pool_noise_handshakes_failed_total",
                "Total failed Noise handshakes",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        // Security metrics
        let decryption_failures = IntCounter::with_opts(
            Opts::new(
                "pool_decryption_failures_total",
                "Total decryption failures (potential EROSION attack indicator)",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let replay_attempts = IntCounter::with_opts(
            Opts::new(
                "pool_replay_attempts_total",
                "Total replay attempts detected",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let sequence_anomalies = IntCounter::with_opts(
            Opts::new(
                "pool_sequence_anomalies_total",
                "Total sequence anomalies detected",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let flagged_addresses = IntGauge::with_opts(
            Opts::new(
                "pool_flagged_addresses",
                "Currently flagged suspicious addresses",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let short_lived_connections = IntCounter::with_opts(
            Opts::new(
                "pool_short_lived_connections_total",
                "Total short-lived connections (potential attack indicator)",
            )
            .namespace("sovright"),
        )
        .expect("metric can be created");

        let connection_duration = Histogram::with_opts(
            HistogramOpts::new(
                "pool_connection_duration_seconds",
                "Connection duration in seconds",
            )
            .namespace("sovright")
            .buckets(vec![
                0.1, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0,
            ]),
        )
        .expect("metric can be created");

        // Register per-worker and pool-level metrics
        registry
            .register(Box::new(worker_hashrate.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(worker_shares_accepted.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(worker_shares_rejected.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(worker_blocks_found.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(pool_total_hashrate.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(pool_connected_miners.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(pool_connected_workers.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(network_difficulty.clone()))
            .expect("metric can be registered");

        // Register all metrics
        registry
            .register(Box::new(connections_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(connections_active.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(jd_connections_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(jd_connections_active.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(shares_submitted.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(shares_accepted.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(shares_rejected.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(blocks_found.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(blocks_submitted.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(estimated_hashrate.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(share_validation_duration.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(template_fetch_duration.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(noise_handshakes_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(noise_handshakes_failed.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(decryption_failures.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(replay_attempts.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(sequence_anomalies.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(flagged_addresses.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(short_lived_connections.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(connection_duration.clone()))
            .expect("metric can be registered");

        Self {
            registry,
            connections_total,
            connections_active,
            jd_connections_total,
            jd_connections_active,
            shares_submitted,
            shares_accepted,
            shares_rejected,
            worker_hashrate,
            worker_shares_accepted,
            worker_shares_rejected,
            worker_blocks_found,
            pool_total_hashrate,
            pool_connected_miners,
            pool_connected_workers,
            network_difficulty,
            blocks_found,
            blocks_submitted,
            estimated_hashrate,
            share_validation_duration,
            template_fetch_duration,
            noise_handshakes_total,
            noise_handshakes_failed,
            decryption_failures,
            replay_attempts,
            sequence_anomalies,
            flagged_addresses,
            short_lived_connections,
            connection_duration,
        }
    }

    /// Encode all metrics in Prometheus text format
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("encoding should succeed");
        String::from_utf8(buffer).expect("metrics should be valid UTF-8")
    }

    /// Record a new miner connection
    pub fn record_connection(&self) {
        self.connections_total.inc();
        self.connections_active.inc();
    }

    /// Record a miner disconnection
    pub fn record_disconnection(&self) {
        self.connections_active.dec();
    }

    /// Record a new JD connection
    pub fn record_jd_connection(&self) {
        self.jd_connections_total.inc();
        self.jd_connections_active.inc();
    }

    /// Record a JD disconnection
    pub fn record_jd_disconnection(&self) {
        self.jd_connections_active.dec();
    }

    /// Record a share submission with the given difficulty tier
    pub fn record_share_submitted(&self, difficulty_tier: &str) {
        self.shares_submitted
            .with_label_values(&[difficulty_tier])
            .inc();
    }

    /// Record an accepted share
    pub fn record_share_accepted(&self) {
        self.shares_accepted.inc();
    }

    /// Record a rejected share with the given reason
    pub fn record_share_rejected(&self, reason: &str) {
        self.shares_rejected.with_label_values(&[reason]).inc();
    }

    /// Record an accepted share for a specific worker
    pub fn record_worker_share_accepted(&self, worker: &str) {
        self.worker_shares_accepted
            .with_label_values(&[worker])
            .inc();
    }

    /// Record a rejected share for a specific worker
    pub fn record_worker_share_rejected(&self, worker: &str) {
        self.worker_shares_rejected
            .with_label_values(&[worker])
            .inc();
    }

    /// Record a block found for a specific worker
    pub fn record_worker_block_found(&self, worker: &str) {
        self.worker_blocks_found.with_label_values(&[worker]).inc();
    }

    /// Set the hashrate for a specific worker
    pub fn set_worker_hashrate(&self, worker: &str, hashrate: f64) {
        self.worker_hashrate
            .with_label_values(&[worker])
            .set(hashrate);
    }

    /// Update pool-level aggregate metrics
    pub fn set_pool_aggregates(&self, hashrate: f64, miners: i64, workers: i64) {
        self.pool_total_hashrate.set(hashrate);
        self.pool_connected_miners.set(miners);
        self.pool_connected_workers.set(workers);
    }

    /// Set network difficulty
    pub fn set_network_difficulty(&self, difficulty: f64) {
        self.network_difficulty.set(difficulty);
    }

    /// Record a block found
    pub fn record_block_found(&self) {
        self.blocks_found.inc();
    }

    /// Record a block submitted
    pub fn record_block_submitted(&self) {
        self.blocks_submitted.inc();
    }

    /// Update the estimated hashrate
    pub fn set_hashrate(&self, hashrate: f64) {
        self.estimated_hashrate.set(hashrate);
    }

    /// Record share validation duration
    pub fn observe_share_validation(&self, duration_secs: f64) {
        self.share_validation_duration.observe(duration_secs);
    }

    /// Record template fetch duration
    pub fn observe_template_fetch(&self, duration_secs: f64) {
        self.template_fetch_duration.observe(duration_secs);
    }

    /// Record a Noise handshake attempt
    pub fn record_noise_handshake(&self) {
        self.noise_handshakes_total.inc();
    }

    /// Record a failed Noise handshake
    pub fn record_noise_handshake_failed(&self) {
        self.noise_handshakes_failed.inc();
    }

    // ========== Security Metrics ==========

    /// Record a decryption failure (potential EROSION attack indicator)
    pub fn record_decryption_failure(&self) {
        self.decryption_failures.inc();
    }

    /// Record a replay attempt detected
    pub fn record_replay_attempt(&self) {
        self.replay_attempts.inc();
    }

    /// Record a sequence anomaly
    pub fn record_sequence_anomaly(&self) {
        self.sequence_anomalies.inc();
    }

    /// Update the count of flagged suspicious addresses
    pub fn set_flagged_addresses(&self, count: i64) {
        self.flagged_addresses.set(count);
    }

    /// Increment flagged addresses count
    pub fn inc_flagged_addresses(&self) {
        self.flagged_addresses.inc();
    }

    /// Decrement flagged addresses count
    pub fn dec_flagged_addresses(&self) {
        self.flagged_addresses.dec();
    }

    /// Record a short-lived connection (potential attack indicator)
    pub fn record_short_lived_connection(&self) {
        self.short_lived_connections.inc();
    }

    /// Record connection duration when a connection ends
    pub fn observe_connection_duration(&self, duration_secs: f64) {
        self.connection_duration.observe(duration_secs);
    }
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle HTTP requests for metrics and health endpoints
async fn handle_request(
    req: Request<Body>,
    metrics: Arc<PoolMetrics>,
) -> Result<Response<Body>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let body = metrics.encode();
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Body::from(body))
                .unwrap()
        }
        (&Method::GET, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"status":"healthy"}"#))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap(),
    };

    Ok(response)
}

/// Start the metrics HTTP server
///
/// Exposes:
/// - `/metrics` - Prometheus metrics in text format
/// - `/health` - Health check endpoint returning JSON status
///
/// # Arguments
///
/// * `addr` - Socket address to bind the server to
/// * `metrics` - Shared PoolMetrics instance
pub async fn start_metrics_server(addr: SocketAddr, metrics: Arc<PoolMetrics>) {
    let make_svc = make_service_fn(move |_conn| {
        let metrics = Arc::clone(&metrics);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, Arc::clone(&metrics))
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    info!("Metrics server listening on http://{}", addr);

    if let Err(e) = server.await {
        error!("Metrics server error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = PoolMetrics::new();
        // Verify metrics are created and can be encoded
        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_connections_total"));
        assert!(encoded.contains("sovright_pool_connections_active"));
        assert!(encoded.contains("sovright_pool_shares_accepted_total"));
    }

    #[test]
    fn test_connection_metrics() {
        let metrics = PoolMetrics::new();

        metrics.record_connection();
        metrics.record_connection();
        metrics.record_disconnection();

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_connections_total 2"));
        assert!(encoded.contains("sovright_pool_connections_active 1"));
    }

    #[test]
    fn test_share_metrics() {
        let metrics = PoolMetrics::new();

        metrics.record_share_submitted("low");
        metrics.record_share_submitted("high");
        metrics.record_share_accepted();
        metrics.record_share_rejected("invalid_solution");

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_shares_submitted_total"));
        assert!(encoded.contains("sovright_pool_shares_accepted_total 1"));
        assert!(encoded.contains("sovright_pool_shares_rejected_total"));
    }

    #[test]
    fn test_block_metrics() {
        let metrics = PoolMetrics::new();

        metrics.record_block_found();
        metrics.record_block_submitted();

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_blocks_found_total 1"));
        assert!(encoded.contains("sovright_pool_blocks_submitted_total 1"));
    }

    #[test]
    fn test_hashrate_metric() {
        let metrics = PoolMetrics::new();

        metrics.set_hashrate(1_000_000.0);

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_estimated_hashrate 1000000"));
    }

    #[test]
    fn test_latency_metrics() {
        let metrics = PoolMetrics::new();

        metrics.observe_share_validation(0.001);
        metrics.observe_template_fetch(0.05);

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_share_validation_duration_seconds"));
        assert!(encoded.contains("sovright_pool_template_fetch_duration_seconds"));
    }

    #[test]
    fn test_noise_metrics() {
        let metrics = PoolMetrics::new();

        metrics.record_noise_handshake();
        metrics.record_noise_handshake();
        metrics.record_noise_handshake_failed();

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_noise_handshakes_total 2"));
        assert!(encoded.contains("sovright_pool_noise_handshakes_failed_total 1"));
    }

    #[test]
    fn test_jd_connection_metrics() {
        let metrics = PoolMetrics::new();

        metrics.record_jd_connection();
        metrics.record_jd_disconnection();

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_jd_connections_total 1"));
        assert!(encoded.contains("sovright_pool_jd_connections_active 0"));
    }

    #[test]
    fn test_default_impl() {
        let metrics = PoolMetrics::default();
        let encoded = metrics.encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_security_metrics() {
        let metrics = PoolMetrics::new();

        metrics.record_decryption_failure();
        metrics.record_decryption_failure();
        metrics.record_replay_attempt();
        metrics.record_sequence_anomaly();
        metrics.record_short_lived_connection();
        metrics.inc_flagged_addresses();

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_decryption_failures_total 2"));
        assert!(encoded.contains("sovright_pool_replay_attempts_total 1"));
        assert!(encoded.contains("sovright_pool_sequence_anomalies_total 1"));
        assert!(encoded.contains("sovright_pool_short_lived_connections_total 1"));
        assert!(encoded.contains("sovright_pool_flagged_addresses 1"));
    }

    #[test]
    fn test_connection_duration_metric() {
        let metrics = PoolMetrics::new();

        metrics.observe_connection_duration(30.5);
        metrics.observe_connection_duration(120.0);

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_connection_duration_seconds"));
    }

    #[test]
    fn test_flagged_addresses_gauge() {
        let metrics = PoolMetrics::new();

        metrics.inc_flagged_addresses();
        metrics.inc_flagged_addresses();
        metrics.dec_flagged_addresses();

        let encoded = metrics.encode();
        assert!(encoded.contains("sovright_pool_flagged_addresses 1"));
    }
}
