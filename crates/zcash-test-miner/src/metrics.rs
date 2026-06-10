//! Shared, cumulative miner metrics.
//!
//! A single [`MinerMetrics`] is created in `main`, wrapped in an `Arc`, and
//! cloned into every worker session and solver thread. Counters are cumulative
//! across reconnects so the live stats panel shows session-spanning totals.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters shared across all workers and solver threads.
#[derive(Default)]
pub struct MinerMetrics {
    /// Equihash solution attempts (one per nonce fed to the solver).
    nonces_attempted: AtomicU64,
    shares_submitted: AtomicU64,
    shares_accepted: AtomicU64,
    shares_rejected: AtomicU64,
    blocks_found: AtomicU64,
    /// Workers currently holding an established session.
    connected_workers: AtomicU64,
}

/// A point-in-time copy of every counter, for rendering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub nonces_attempted: u64,
    pub shares_submitted: u64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub blocks_found: u64,
    pub connected_workers: u64,
}

impl MinerMetrics {
    /// Create a fresh, zeroed metrics handle.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record `n` solution attempts. Called hot from solver loops, so Relaxed.
    pub fn add_attempts(&self, n: u64) {
        self.nonces_attempted.fetch_add(n, Ordering::Relaxed);
    }

    pub fn incr_submitted(&self) {
        self.shares_submitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_accepted(&self) {
        self.shares_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_rejected(&self) {
        self.shares_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_blocks(&self) {
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_connected(&self) {
        self.connected_workers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_disconnected(&self) {
        // Saturating: never wrap below zero even if connect/disconnect pairing
        // is ever skewed by an early error path.
        let mut cur = self.connected_workers.load(Ordering::Relaxed);
        while cur > 0 {
            match self.connected_workers.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Take a consistent-enough snapshot of all counters for rendering.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            nonces_attempted: self.nonces_attempted.load(Ordering::Relaxed),
            shares_submitted: self.shares_submitted.load(Ordering::Relaxed),
            shares_accepted: self.shares_accepted.load(Ordering::Relaxed),
            shares_rejected: self.shares_rejected.load(Ordering::Relaxed),
            blocks_found: self.blocks_found.load(Ordering::Relaxed),
            connected_workers: self.connected_workers.load(Ordering::Relaxed),
        }
    }
}

/// Solution attempts per second over an elapsed window.
///
/// Guards against a zero/negative window (the very first tick) by returning 0.0
/// rather than dividing by zero.
pub fn sol_per_sec(delta_attempts: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        delta_attempts as f64 / secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_zero() {
        let m = MinerMetrics::new();
        assert_eq!(m.snapshot(), MetricsSnapshot::default());
    }

    #[test]
    fn increments_accumulate() {
        let m = MinerMetrics::new();
        m.add_attempts(5);
        m.add_attempts(3);
        m.incr_submitted();
        m.incr_accepted();
        m.incr_accepted();
        m.incr_rejected();
        m.incr_blocks();
        m.worker_connected();
        m.worker_connected();
        m.worker_disconnected();

        let s = m.snapshot();
        assert_eq!(s.nonces_attempted, 8);
        assert_eq!(s.shares_submitted, 1);
        assert_eq!(s.shares_accepted, 2);
        assert_eq!(s.shares_rejected, 1);
        assert_eq!(s.blocks_found, 1);
        assert_eq!(s.connected_workers, 1);
    }

    #[test]
    fn worker_disconnect_saturates_at_zero() {
        let m = MinerMetrics::new();
        m.worker_disconnected();
        m.worker_disconnected();
        assert_eq!(m.snapshot().connected_workers, 0);
    }

    #[test]
    fn sol_per_sec_basic() {
        assert_eq!(sol_per_sec(10, 2.0), 5.0);
    }

    #[test]
    fn sol_per_sec_guards_zero_window() {
        assert_eq!(sol_per_sec(10, 0.0), 0.0);
        assert_eq!(sol_per_sec(10, -1.0), 0.0);
    }
}
