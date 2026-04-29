//! Client reconnection logic with exponential backoff
//!
//! Implements automatic reconnection to mitigate EROSION (BGP hijacking) attacks.
//! When connections fail (especially due to decryption errors), clients should
//! automatically reconnect with exponential backoff to maintain availability.
//!
//! ## Attack Context
//!
//! The EROSION attack (ETH Zurich, 2024) shows that BGP hijacking can:
//! - Intercept traffic between miners and pools
//! - Corrupt encrypted packets to cause persistent disconnections
//! - Achieve ~91% coverage of mining pools
//!
//! Automatic reconnection mitigates this by:
//! - Quickly restoring connections after single-packet corruption
//! - Using exponential backoff to avoid overwhelming the network
//! - Detecting attack patterns through connection failure analysis

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Configuration for reconnection behavior
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Initial delay before first reconnection attempt
    pub initial_delay: Duration,
    /// Maximum delay between reconnection attempts
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (typically 2.0)
    pub backoff_multiplier: f64,
    /// Maximum number of reconnection attempts (None = unlimited)
    pub max_attempts: Option<u32>,
    /// Add random jitter to delays (0.0-1.0, fraction of delay)
    pub jitter_factor: f64,
    /// Reset backoff after successful connection lasting this long
    pub reset_after_stable: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            max_attempts: None, // Unlimited retries by default
            jitter_factor: 0.25,
            reset_after_stable: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Reason for connection failure (used for attack pattern detection)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Normal closure (miner shutdown)
    Normal,
    /// Network error (timeout, connection reset)
    NetworkError,
    /// Decryption failure (potential attack indicator)
    DecryptionError,
    /// Handshake failure
    HandshakeError,
    /// Server explicitly closed connection
    ServerClosed,
    /// Unknown/other error
    Unknown,
}

impl DisconnectReason {
    /// Check if this reason could indicate an attack
    pub fn is_potential_attack(&self) -> bool {
        matches!(self, DisconnectReason::DecryptionError)
    }
}

/// Connection failure record for pattern analysis
#[derive(Debug, Clone)]
pub struct ConnectionFailure {
    /// When the failure occurred
    pub timestamp: Instant,
    /// How long the connection lasted before failing
    pub connection_duration: Duration,
    /// Reason for the failure
    pub reason: DisconnectReason,
}

/// Reconnection state manager
///
/// Tracks connection attempts, failures, and manages backoff timing.
/// Also detects potential attack patterns from failure data.
#[derive(Debug)]
pub struct ReconnectManager {
    /// Configuration
    config: ReconnectConfig,
    /// Current reconnection attempt number
    attempt_count: u32,
    /// Current delay for next attempt
    current_delay: Duration,
    /// When the last successful connection was established
    last_connected_at: Option<Instant>,
    /// Recent connection failures for pattern analysis
    recent_failures: VecDeque<ConnectionFailure>,
    /// Maximum failures to keep for analysis
    max_failure_history: usize,
}

impl ReconnectManager {
    /// Create a new reconnection manager with given config
    pub fn new(config: ReconnectConfig) -> Self {
        Self {
            config,
            attempt_count: 0,
            current_delay: Duration::ZERO,
            last_connected_at: None,
            recent_failures: VecDeque::with_capacity(100),
            max_failure_history: 100,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ReconnectConfig::default())
    }

    /// Record a successful connection
    ///
    /// If the previous connection was stable (lasted longer than reset_after_stable),
    /// resets the backoff state.
    pub fn on_connected(&mut self) {
        let now = Instant::now();

        // Check if we should reset backoff
        if let Some(last) = self.last_connected_at
            && now.duration_since(last) > self.config.reset_after_stable {
                debug!("Connection was stable, resetting backoff");
                self.reset();
            }

        self.last_connected_at = Some(now);
    }

    /// Record a connection failure
    ///
    /// Returns the delay before the next reconnection attempt, or None if
    /// max attempts have been exceeded.
    pub fn on_disconnected(&mut self, reason: DisconnectReason) -> Option<Duration> {
        let now = Instant::now();

        // Calculate connection duration
        let connection_duration = self
            .last_connected_at
            .map(|t| now.duration_since(t))
            .unwrap_or(Duration::ZERO);
        let was_stable = self.last_connected_at.is_some()
            && connection_duration >= self.config.reset_after_stable;

        // Record failure for pattern analysis
        self.record_failure(ConnectionFailure {
            timestamp: now,
            connection_duration,
            reason,
        });

        self.last_connected_at = None;
        if was_stable {
            debug!("Connection was stable, resetting backoff");
            self.reset();
        }

        // Check if we've exceeded max attempts
        if let Some(max) = self.config.max_attempts
            && self.attempt_count >= max {
                warn!(
                    "Maximum reconnection attempts ({}) exceeded",
                    max
                );
                return None;
            }

        // Calculate next delay with exponential backoff
        self.attempt_count += 1;

        if self.attempt_count == 1 {
            self.current_delay = self.config.initial_delay;
        } else {
            let new_delay = self.current_delay.mul_f64(self.config.backoff_multiplier);
            self.current_delay = new_delay.min(self.config.max_delay);
        }

        // Add jitter
        let jittered_delay = self.add_jitter(self.current_delay);

        info!(
            "Connection failed ({:?}), attempt {}, retrying in {:?}",
            reason, self.attempt_count, jittered_delay
        );

        // Log warning if potential attack detected
        if reason.is_potential_attack() {
            warn!(
                "Decryption error after {:?} - potential EROSION attack indicator",
                connection_duration
            );
        }

        Some(jittered_delay)
    }

    /// Get the delay for the next reconnection attempt
    pub fn next_delay(&self) -> Duration {
        self.add_jitter(self.current_delay)
    }

    /// Reset the reconnection state
    pub fn reset(&mut self) {
        self.attempt_count = 0;
        self.current_delay = Duration::ZERO;
    }

    /// Get current attempt count
    pub fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    /// Check if max attempts have been exceeded
    pub fn is_exhausted(&self) -> bool {
        self.config
            .max_attempts
            .map(|max| self.attempt_count >= max)
            .unwrap_or(false)
    }

    /// Add random jitter to a delay
    fn add_jitter(&self, delay: Duration) -> Duration {
        if self.config.jitter_factor <= 0.0 {
            return delay;
        }

        // Use a simple deterministic jitter based on attempt count
        // In production, you'd want actual randomness
        let jitter_factor = self.config.jitter_factor;
        let pseudo_random = (self.attempt_count as f64 * 0.618033988749) % 1.0;

        // Calculate jitter as a fraction of delay: range is [-jitter_factor, +jitter_factor]
        let jitter_multiplier = (pseudo_random * 2.0 - 1.0) * jitter_factor;

        // Ensure the final multiplier stays positive (1.0 + jitter_multiplier > 0)
        // and never reduces the delay below initial_delay (delayMinimum invariant)
        let final_multiplier = (1.0 + jitter_multiplier).max(0.1);
        let jittered = delay.mul_f64(final_multiplier);

        // Clamp to initial_delay: jitter should never reduce delay below
        // the configured minimum, per the Quint ReconnectBackoff spec's
        // delayMinimum invariant
        jittered.max(self.config.initial_delay)
    }

    /// Record a failure for pattern analysis
    fn record_failure(&mut self, failure: ConnectionFailure) {
        self.recent_failures.push_back(failure);

        // Trim old failures (O(1) with VecDeque)
        while self.recent_failures.len() > self.max_failure_history {
            self.recent_failures.pop_front();
        }
    }

    /// Analyze recent failures for attack patterns
    ///
    /// Returns an attack likelihood score (0.0 = unlikely, 1.0 = very likely)
    pub fn analyze_attack_likelihood(&self) -> f64 {
        if self.recent_failures.is_empty() {
            return 0.0;
        }

        let window = Duration::from_secs(300); // 5 minute window
        let now = Instant::now();

        // Count recent failures by type
        let recent: Vec<_> = self
            .recent_failures
            .iter()
            .filter(|f| now.duration_since(f.timestamp) < window)
            .collect();

        if recent.is_empty() {
            return 0.0;
        }

        let total = recent.len() as f64;
        let decryption_errors = recent
            .iter()
            .filter(|f| f.reason == DisconnectReason::DecryptionError)
            .count() as f64;

        let short_lived = recent
            .iter()
            .filter(|f| f.connection_duration < Duration::from_secs(10))
            .count() as f64;

        // High ratio of decryption errors is suspicious
        let decrypt_ratio = decryption_errors / total;

        // High ratio of short-lived connections is suspicious
        let short_lived_ratio = short_lived / total;

        // Frequent failures (more than 10 in 5 minutes) is suspicious
        let frequency_score = (total / 10.0).min(1.0);

        // Weighted combination
        let score = decrypt_ratio * 0.5 + short_lived_ratio * 0.3 + frequency_score * 0.2;

        score.min(1.0)
    }

    /// Get statistics about recent connection failures
    pub fn failure_stats(&self) -> FailureStats {
        let window = Duration::from_secs(300);
        let now = Instant::now();

        let recent: Vec<_> = self
            .recent_failures
            .iter()
            .filter(|f| now.duration_since(f.timestamp) < window)
            .collect();

        FailureStats {
            total_failures: recent.len(),
            decryption_errors: recent
                .iter()
                .filter(|f| f.reason == DisconnectReason::DecryptionError)
                .count(),
            network_errors: recent
                .iter()
                .filter(|f| f.reason == DisconnectReason::NetworkError)
                .count(),
            handshake_errors: recent
                .iter()
                .filter(|f| f.reason == DisconnectReason::HandshakeError)
                .count(),
            short_lived_connections: recent
                .iter()
                .filter(|f| f.connection_duration < Duration::from_secs(10))
                .count(),
            attack_likelihood: self.analyze_attack_likelihood(),
        }
    }
}

/// Statistics about recent connection failures
#[derive(Debug, Clone)]
pub struct FailureStats {
    /// Total failures in the analysis window
    pub total_failures: usize,
    /// Decryption errors (potential attack indicator)
    pub decryption_errors: usize,
    /// Network errors
    pub network_errors: usize,
    /// Handshake errors
    pub handshake_errors: usize,
    /// Connections that lasted less than 10 seconds
    pub short_lived_connections: usize,
    /// Calculated attack likelihood (0.0 - 1.0)
    pub attack_likelihood: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ReconnectConfig::default();
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(60));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_exponential_backoff() {
        let config = ReconnectConfig {
            jitter_factor: 0.0, // Disable jitter for predictable testing
            ..Default::default()
        };
        let mut manager = ReconnectManager::new(config);

        // First attempt: 1 second
        let delay1 = manager.on_disconnected(DisconnectReason::NetworkError).unwrap();
        assert_eq!(delay1, Duration::from_secs(1));

        // Second attempt: 2 seconds
        let delay2 = manager.on_disconnected(DisconnectReason::NetworkError).unwrap();
        assert_eq!(delay2, Duration::from_secs(2));

        // Third attempt: 4 seconds
        let delay3 = manager.on_disconnected(DisconnectReason::NetworkError).unwrap();
        assert_eq!(delay3, Duration::from_secs(4));
    }

    #[test]
    fn test_max_delay_cap() {
        let config = ReconnectConfig {
            initial_delay: Duration::from_secs(30),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
            ..Default::default()
        };
        let mut manager = ReconnectManager::new(config);

        manager.on_disconnected(DisconnectReason::NetworkError); // 30s
        manager.on_disconnected(DisconnectReason::NetworkError); // 60s (would be 60)
        let delay = manager.on_disconnected(DisconnectReason::NetworkError).unwrap(); // capped at 60s
        assert_eq!(delay, Duration::from_secs(60));
    }

    #[test]
    fn test_max_attempts() {
        let config = ReconnectConfig {
            max_attempts: Some(3),
            jitter_factor: 0.0,
            ..Default::default()
        };
        let mut manager = ReconnectManager::new(config);

        assert!(manager.on_disconnected(DisconnectReason::NetworkError).is_some());
        assert!(manager.on_disconnected(DisconnectReason::NetworkError).is_some());
        assert!(manager.on_disconnected(DisconnectReason::NetworkError).is_some());
        assert!(manager.on_disconnected(DisconnectReason::NetworkError).is_none());
        assert!(manager.is_exhausted());
    }

    #[test]
    fn test_reset() {
        let config = ReconnectConfig {
            jitter_factor: 0.0,
            ..Default::default()
        };
        let mut manager = ReconnectManager::new(config);

        manager.on_disconnected(DisconnectReason::NetworkError);
        manager.on_disconnected(DisconnectReason::NetworkError);
        assert_eq!(manager.attempt_count(), 2);

        manager.reset();
        assert_eq!(manager.attempt_count(), 0);
    }

    #[test]
    fn test_stable_disconnect_resets_next_delay() {
        let config = ReconnectConfig {
            jitter_factor: 0.0,
            reset_after_stable: Duration::from_secs(50),
            ..Default::default()
        };
        let mut manager = ReconnectManager::new(config);

        manager.on_connected();
        assert_eq!(
            manager.on_disconnected(DisconnectReason::NetworkError),
            Some(Duration::from_secs(1))
        );
        manager.on_connected();
        assert_eq!(
            manager.on_disconnected(DisconnectReason::NetworkError),
            Some(Duration::from_secs(2))
        );

        manager.on_connected();
        manager.last_connected_at = Some(Instant::now() - Duration::from_secs(60));
        assert_eq!(
            manager.on_disconnected(DisconnectReason::Normal),
            Some(Duration::from_secs(1))
        );
        assert_eq!(manager.attempt_count(), 1);
    }

    #[test]
    fn test_disconnect_reason_attack_detection() {
        assert!(DisconnectReason::DecryptionError.is_potential_attack());
        assert!(!DisconnectReason::NetworkError.is_potential_attack());
        assert!(!DisconnectReason::Normal.is_potential_attack());
    }

    #[test]
    fn test_attack_likelihood_no_failures() {
        let manager = ReconnectManager::with_defaults();
        assert_eq!(manager.analyze_attack_likelihood(), 0.0);
    }

    #[test]
    fn test_failure_stats() {
        let mut manager = ReconnectManager::with_defaults();

        manager.on_disconnected(DisconnectReason::DecryptionError);
        manager.on_disconnected(DisconnectReason::NetworkError);

        let stats = manager.failure_stats();
        assert_eq!(stats.total_failures, 2);
        assert_eq!(stats.decryption_errors, 1);
        assert_eq!(stats.network_errors, 1);
    }
}
