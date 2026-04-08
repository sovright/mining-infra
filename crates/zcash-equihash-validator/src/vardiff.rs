//! Adaptive Variable Difficulty (Vardiff) Controller
//!
//! Adjusts share difficulty per-miner to maintain a target share rate.
//! Designed for Equihash's ~15-30 second solve times on ASICs.

use crate::difficulty::{difficulty_to_target, Target};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Configuration for the vardiff algorithm
#[derive(Debug, Clone)]
pub struct VardiffConfig {
    /// Target shares per minute from each miner
    pub target_shares_per_minute: f64,
    /// Initial difficulty for new miners (clamped to [min, max])
    pub initial_difficulty: f64,
    /// Minimum allowed difficulty
    pub min_difficulty: f64,
    /// Maximum allowed difficulty
    pub max_difficulty: f64,
    /// How often to recalculate difficulty
    pub retarget_interval: Duration,
    /// Tolerance for share rate variance (0.25 = 25%)
    pub variance_tolerance: f64,
    /// Ratio threshold for ramp-up mode. When share rate ratio exceeds this
    /// (or falls below 1/threshold), use aggressive adjustment without smoothing.
    pub ramp_threshold: f64,
    /// Dead zone lower bound. No adjustment when ratio is above this.
    pub dead_zone_lower: f64,
    /// Dead zone upper bound. No adjustment when ratio is below this.
    pub dead_zone_upper: f64,
    /// EMA smoothing factor for steady-state adjustments (0.0 to 1.0).
    pub ema_alpha: f64,
}

impl Default for VardiffConfig {
    fn default() -> Self {
        Self {
            // For Equihash ASICs (~420 KSol/s), target 4-6 shares/min
            target_shares_per_minute: 5.0,
            initial_difficulty: 1.0,
            min_difficulty: 1.0,
            max_difficulty: 1_000_000_000.0,
            retarget_interval: Duration::from_secs(60),
            variance_tolerance: 0.25,
            ramp_threshold: 4.0,
            dead_zone_lower: 0.8,
            dead_zone_upper: 1.2,
            ema_alpha: 0.3,
        }
    }
}

impl VardiffConfig {
    /// Validate config, clamping invalid values to safe defaults.
    ///
    /// Prevents the division-by-zero bugs identified by the Quint spec's
    /// VardiffDivZero module: zero target_shares_per_minute causes Infinity,
    /// zero retarget_interval causes NaN.
    pub fn validated(mut self) -> Self {
        if !self.target_shares_per_minute.is_finite() || self.target_shares_per_minute <= 0.0 {
            tracing::warn!(
                "Invalid target_shares_per_minute {}, using default 5.0",
                self.target_shares_per_minute
            );
            self.target_shares_per_minute = 5.0;
        }
        if self.retarget_interval.is_zero() {
            tracing::warn!("Zero retarget_interval, using default 60s");
            self.retarget_interval = Duration::from_secs(60);
        }
        if !self.min_difficulty.is_finite() || self.min_difficulty <= 0.0 {
            tracing::warn!(
                "Invalid min_difficulty {}, using default 1.0",
                self.min_difficulty
            );
            self.min_difficulty = 1.0;
        }
        if !self.max_difficulty.is_finite() || self.max_difficulty <= 0.0 {
            tracing::warn!(
                "Invalid max_difficulty {}, using default 1e9",
                self.max_difficulty
            );
            self.max_difficulty = 1_000_000_000.0;
        }
        if self.min_difficulty > self.max_difficulty {
            tracing::warn!(
                "min_difficulty {} > max_difficulty {}, swapping",
                self.min_difficulty, self.max_difficulty
            );
            std::mem::swap(&mut self.min_difficulty, &mut self.max_difficulty);
        }
        if !self.variance_tolerance.is_finite() || self.variance_tolerance <= 0.0 || self.variance_tolerance >= 1.0 {
            tracing::warn!(
                "Invalid variance_tolerance {}, using default 0.25",
                self.variance_tolerance
            );
            self.variance_tolerance = 0.25;
        }
        if !self.ramp_threshold.is_finite() || self.ramp_threshold <= 1.0 {
            tracing::warn!(
                "Invalid ramp_threshold {}, using default 4.0",
                self.ramp_threshold
            );
            self.ramp_threshold = 4.0;
        }
        if !self.dead_zone_lower.is_finite() || self.dead_zone_lower <= 0.0 || self.dead_zone_lower >= 1.0 {
            tracing::warn!(
                "Invalid dead_zone_lower {}, using default 0.8",
                self.dead_zone_lower
            );
            self.dead_zone_lower = 0.8;
        }
        if !self.dead_zone_upper.is_finite() || self.dead_zone_upper <= 1.0 {
            tracing::warn!(
                "Invalid dead_zone_upper {}, using default 1.2",
                self.dead_zone_upper
            );
            self.dead_zone_upper = 1.2;
        }
        if !self.ema_alpha.is_finite() || self.ema_alpha <= 0.0 || self.ema_alpha >= 1.0 {
            tracing::warn!(
                "Invalid ema_alpha {}, using default 0.3",
                self.ema_alpha
            );
            self.ema_alpha = 0.3;
        }
        if self.dead_zone_lower >= self.dead_zone_upper {
            tracing::warn!(
                "dead_zone_lower {} >= dead_zone_upper {}, using defaults",
                self.dead_zone_lower, self.dead_zone_upper
            );
            self.dead_zone_lower = 0.8;
            self.dead_zone_upper = 1.2;
        }
        self
    }
}

/// Phase of the vardiff controller's operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VardiffPhase {
    /// Aggressive adjustment without smoothing for fast convergence
    RampUp,
    /// EMA-smoothed adjustments for stability
    SteadyState,
}

/// Per-miner vardiff state
#[derive(Debug)]
pub struct VardiffController {
    config: VardiffConfig,
    current_difficulty: f64,
    shares_since_retarget: u32,
    last_retarget: Instant,
    window_start: Instant,
    phase: VardiffPhase,
}

impl VardiffController {
    /// Create a new vardiff controller.
    ///
    /// Validates config to prevent division-by-zero and NaN/Infinity propagation.
    pub fn new(config: VardiffConfig) -> Self {
        let config = config.validated();
        let now = Instant::now();
        let initial = config.initial_difficulty.clamp(
            config.min_difficulty,
            config.max_difficulty,
        );
        Self {
            current_difficulty: initial,
            config,
            shares_since_retarget: 0,
            last_retarget: now,
            window_start: now,
            phase: VardiffPhase::RampUp,
        }
    }

    /// Get current difficulty
    pub fn current_difficulty(&self) -> f64 {
        self.current_difficulty
    }

    /// Get current target as 256-bit value
    pub fn current_target(&self) -> Target {
        difficulty_to_target(self.current_difficulty)
    }

    /// Set difficulty directly (for initial connection setup)
    pub fn set_difficulty(&mut self, difficulty: f64) {
        self.current_difficulty = difficulty.clamp(
            self.config.min_difficulty,
            self.config.max_difficulty,
        );
        self.reset_window();
        info!("Difficulty set to {:.2}", self.current_difficulty);
    }

    /// Record a submitted share
    pub fn record_share(&mut self) {
        self.shares_since_retarget += 1;
    }

    /// Get the current phase of the controller
    pub fn phase(&self) -> VardiffPhase {
        self.phase
    }

    /// Check if retargeting is needed and adjust difficulty
    ///
    /// Uses a two-phase approach:
    /// - **RampUp**: Aggressive adjustment without smoothing for fast convergence
    /// - **SteadyState**: EMA-smoothed adjustments for stability
    ///
    /// Returns `Some(new_difficulty)` if difficulty changed, `None` otherwise
    pub fn maybe_retarget(&mut self) -> Option<f64> {
        let elapsed = self.last_retarget.elapsed();

        // Early retarget: if shares far exceed expected count, retarget now
        let expected_shares_in_interval = self.config.target_shares_per_minute
            * (self.config.retarget_interval.as_secs_f64() / 60.0);
        let early_retarget = self.shares_since_retarget as f64 > 4.0 * expected_shares_in_interval;

        if elapsed < self.config.retarget_interval && !early_retarget {
            return None;
        }

        let minutes = elapsed.as_secs_f64() / 60.0;
        let actual_rate = if minutes > 0.0 {
            self.shares_since_retarget as f64 / minutes
        } else {
            0.0
        };
        let target_rate = self.config.target_shares_per_minute;

        debug!(
            "Vardiff check: {} shares in {:.1}s = {:.2}/min (target: {:.2}/min, phase: {:?})",
            self.shares_since_retarget,
            elapsed.as_secs_f64(),
            actual_rate,
            target_rate,
            self.phase
        );

        let ratio = if target_rate > 0.0 {
            actual_rate / target_rate
        } else {
            0.0
        };

        // Zero shares: full 50% cut regardless of phase (preserve regression fix)
        if self.shares_since_retarget == 0 {
            let new_difficulty = (self.current_difficulty * 0.5).clamp(
                self.config.min_difficulty,
                self.config.max_difficulty,
            );
            if (new_difficulty - self.current_difficulty).abs() > 0.01 {
                info!(
                    "Vardiff adjustment (zero shares): {:.2} -> {:.2}",
                    self.current_difficulty, new_difficulty
                );
                self.current_difficulty = new_difficulty;
                self.reset_window();
                return Some(new_difficulty);
            }
            self.reset_window();
            return None;
        }

        // Dead zone: no adjustment when ratio is close to 1.0
        if ratio >= self.config.dead_zone_lower && ratio <= self.config.dead_zone_upper {
            self.reset_window();
            return None;
        }

        // Phase-dependent adjustment
        let final_difficulty = match self.phase {
            VardiffPhase::RampUp => {
                if ratio > self.config.ramp_threshold
                    || ratio < 1.0 / self.config.ramp_threshold
                {
                    // Aggressive jump, no smoothing
                    self.current_difficulty * ratio
                } else {
                    // Transition to steady state, apply EMA
                    self.phase = VardiffPhase::SteadyState;
                    let raw = self.current_difficulty * ratio;
                    self.config.ema_alpha * raw
                        + (1.0 - self.config.ema_alpha) * self.current_difficulty
                }
            }
            VardiffPhase::SteadyState => {
                // Re-enter RampUp if the share rate has diverged wildly,
                // e.g. after a miner reconnects with very different hashrate.
                if ratio > self.config.ramp_threshold
                    || ratio < 1.0 / self.config.ramp_threshold
                {
                    info!(
                        "Vardiff re-entering RampUp: ratio {:.2} exceeds ramp_threshold {:.2}",
                        ratio, self.config.ramp_threshold
                    );
                    self.phase = VardiffPhase::RampUp;
                    self.current_difficulty * ratio
                } else {
                    let raw = self.current_difficulty * ratio;
                    self.config.ema_alpha * raw
                        + (1.0 - self.config.ema_alpha) * self.current_difficulty
                }
            }
        };

        let final_difficulty = final_difficulty.clamp(
            self.config.min_difficulty,
            self.config.max_difficulty,
        );

        if (final_difficulty - self.current_difficulty).abs() > 0.01 {
            info!(
                "Vardiff adjustment ({:?}): {:.2} -> {:.2} (share rate: {:.2}/min)",
                self.phase, self.current_difficulty, final_difficulty, actual_rate
            );
            self.current_difficulty = final_difficulty;
            self.reset_window();
            return Some(final_difficulty);
        }

        self.reset_window();
        None
    }

    /// Reset the measurement window
    fn reset_window(&mut self) {
        let now = Instant::now();
        self.shares_since_retarget = 0;
        self.last_retarget = now;
        self.window_start = now;
    }

    /// Get statistics about current window
    pub fn stats(&self) -> VardiffStats {
        let elapsed = self.window_start.elapsed();
        let minutes = elapsed.as_secs_f64() / 60.0;
        let rate = if minutes > 0.0 {
            self.shares_since_retarget as f64 / minutes
        } else {
            0.0
        };

        VardiffStats {
            current_difficulty: self.current_difficulty,
            shares_in_window: self.shares_since_retarget,
            window_duration: elapsed,
            current_rate: rate,
            target_rate: self.config.target_shares_per_minute,
        }
    }
}

/// Statistics from vardiff controller
#[derive(Debug, Clone)]
pub struct VardiffStats {
    pub current_difficulty: f64,
    pub shares_in_window: u32,
    pub window_duration: Duration,
    pub current_rate: f64,
    pub target_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VardiffConfig::default();
        assert!(config.target_shares_per_minute > 0.0);
        assert!(config.min_difficulty > 0.0);
        assert!(config.max_difficulty > config.min_difficulty);
    }

    #[test]
    fn test_difficulty_clamping() {
        let config = VardiffConfig {
            min_difficulty: 10.0,
            max_difficulty: 100.0,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);

        controller.set_difficulty(5.0);
        assert_eq!(controller.current_difficulty(), 10.0);

        controller.set_difficulty(500.0);
        assert_eq!(controller.current_difficulty(), 100.0);
    }

    #[test]
    fn test_target_generation() {
        let config = VardiffConfig::default();
        let controller = VardiffController::new(config);

        let target = controller.current_target();
        // Target should be non-zero
        assert!(target.0.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_config_validation_zero_target_spm() {
        // Quint VardiffDivZero module: TARGET_SPM=0 causes division by zero
        let config = VardiffConfig {
            target_shares_per_minute: 0.0,
            ..Default::default()
        };
        let validated = config.validated();
        assert!(validated.target_shares_per_minute > 0.0);
    }

    #[test]
    fn test_config_validation_zero_retarget_interval() {
        // Quint VardiffDivZero module: RETARGET_INT=0 causes NaN (0/0)
        let config = VardiffConfig {
            retarget_interval: Duration::ZERO,
            ..Default::default()
        };
        let validated = config.validated();
        assert!(!validated.retarget_interval.is_zero());
    }

    #[test]
    fn test_config_validation_nan_values() {
        let config = VardiffConfig {
            target_shares_per_minute: f64::NAN,
            min_difficulty: f64::INFINITY,
            max_difficulty: f64::NEG_INFINITY,
            variance_tolerance: f64::NAN,
            ..Default::default()
        };
        let validated = config.validated();
        assert!(validated.target_shares_per_minute.is_finite() && validated.target_shares_per_minute > 0.0);
        assert!(validated.min_difficulty.is_finite() && validated.min_difficulty > 0.0);
        assert!(validated.max_difficulty.is_finite() && validated.max_difficulty > 0.0);
        assert!(validated.variance_tolerance.is_finite() && validated.variance_tolerance > 0.0);
    }

    #[test]
    fn test_config_validation_swapped_min_max() {
        let config = VardiffConfig {
            min_difficulty: 1000.0,
            max_difficulty: 1.0,
            ..Default::default()
        };
        let validated = config.validated();
        assert!(validated.min_difficulty <= validated.max_difficulty);
    }

    #[test]
    fn test_zero_shares_full_difficulty_cut() {
        // Regression: smoothing on top of the zero-share halving produced only
        // a 25% drop (current*0.75) instead of the intended 50% (current*0.5).
        let config = VardiffConfig {
            initial_difficulty: 100.0,
            min_difficulty: 1.0,
            max_difficulty: 1000.0,
            retarget_interval: Duration::from_millis(1),
            target_shares_per_minute: 5.0,
            variance_tolerance: 0.25,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        assert_eq!(controller.current_difficulty(), 100.0);

        // Wait for retarget interval to elapse with zero shares
        std::thread::sleep(Duration::from_millis(5));
        let new_diff = controller.maybe_retarget();

        // With zero shares, difficulty should drop by 50% (to 50.0), not 25%
        assert!(new_diff.is_some(), "retarget should trigger");
        let diff = new_diff.unwrap();
        assert!(
            (diff - 50.0).abs() < 1.0,
            "Expected ~50.0 after zero-share retarget, got {:.2}",
            diff
        );
    }

    #[test]
    fn dead_zone_prevents_adjustment_when_close_to_target() {
        let config = VardiffConfig {
            initial_difficulty: 100.0,
            min_difficulty: 1.0,
            max_difficulty: 1000.0,
            retarget_interval: Duration::from_secs(60),
            target_shares_per_minute: 5.0,
            dead_zone_lower: 0.8,
            dead_zone_upper: 1.2,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        for _ in 0..5 {
            controller.record_share();
        }
        // 5 shares is below early-retarget threshold (4 * 5 = 20)
        // Interval hasn't elapsed either
        let result = controller.maybe_retarget();
        assert!(result.is_none(), "should not retarget before interval elapses");
        assert_eq!(controller.current_difficulty(), 100.0);
    }

    #[test]
    fn ramp_up_converges_fast_for_high_ratio() {
        let config = VardiffConfig {
            initial_difficulty: 1.0,
            min_difficulty: 1.0,
            max_difficulty: 100_000.0,
            retarget_interval: Duration::from_millis(1),
            target_shares_per_minute: 5.0,
            ramp_threshold: 4.0,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        for _ in 0..50 {
            controller.record_share();
        }
        std::thread::sleep(Duration::from_millis(5));
        let new_diff = controller.maybe_retarget();
        assert!(new_diff.is_some(), "should retarget with high share rate");
        let diff = new_diff.unwrap();
        assert!(diff > 10.0, "ramp-up should produce large jump, got {}", diff);
    }

    #[test]
    fn early_retarget_triggers_on_share_flood() {
        let config = VardiffConfig {
            initial_difficulty: 1.0,
            min_difficulty: 1.0,
            max_difficulty: 100_000.0,
            retarget_interval: Duration::from_secs(60),
            target_shares_per_minute: 5.0,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        for _ in 0..21 { // > 4 * 5 = 20
            controller.record_share();
        }
        let new_diff = controller.maybe_retarget();
        assert!(new_diff.is_some(), "early retarget should trigger at 4x shares");
    }

    #[test]
    fn phase_transitions_from_ramp_up_to_steady_state() {
        // Use a high target rate so that a small number of shares produces
        // a ratio within [1/ramp_threshold, ramp_threshold], triggering transition.
        let config = VardiffConfig {
            initial_difficulty: 100.0,
            min_difficulty: 1.0,
            max_difficulty: 100_000.0,
            retarget_interval: Duration::from_millis(1),
            // With ~5ms elapsed, 1 share = ~12000 shares/min.
            // target of 6000 gives ratio ~2.0, within ramp_threshold of 4.0.
            target_shares_per_minute: 6000.0,
            ramp_threshold: 4.0,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        assert_eq!(controller.phase(), VardiffPhase::RampUp);

        // Submit just 1 share so the ratio is moderate (~2x)
        controller.record_share();
        std::thread::sleep(Duration::from_millis(5));
        let _ = controller.maybe_retarget();
        // Ratio ~2x is within ramp_threshold of 4.0, so should transition
        assert_eq!(controller.phase(), VardiffPhase::SteadyState);
    }

    #[test]
    fn new_config_fields_validation() {
        let config = VardiffConfig {
            ramp_threshold: 0.5, // invalid: <= 1.0
            dead_zone_lower: -1.0, // invalid: <= 0.0
            dead_zone_upper: 0.5, // invalid: <= 1.0
            ema_alpha: 2.0, // invalid: >= 1.0
            ..Default::default()
        };
        let validated = config.validated();
        assert_eq!(validated.ramp_threshold, 4.0);
        assert_eq!(validated.dead_zone_lower, 0.8);
        assert_eq!(validated.dead_zone_upper, 1.2);
        assert_eq!(validated.ema_alpha, 0.3);
    }
}
