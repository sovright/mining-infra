use proptest::prelude::*;
use std::time::Duration;
use zcash_equihash_validator::{VardiffConfig, VardiffController};

proptest! {
    #[test]
    fn validated_config_always_sane(
        spm in prop::num::f64::ANY,
        min_diff in prop::num::f64::ANY,
        max_diff in prop::num::f64::ANY,
        variance in prop::num::f64::ANY,
        retarget_ms in 0u64..10_000,
    ) {
        let config = VardiffConfig {
            target_shares_per_minute: spm,
            min_difficulty: min_diff,
            max_difficulty: max_diff,
            variance_tolerance: variance,
            retarget_interval: Duration::from_millis(retarget_ms),
            initial_difficulty: 1.0,
        };
        let v = config.validated();
        prop_assert!(v.target_shares_per_minute.is_finite() && v.target_shares_per_minute > 0.0);
        prop_assert!(v.min_difficulty.is_finite() && v.min_difficulty > 0.0);
        prop_assert!(v.max_difficulty.is_finite() && v.max_difficulty > 0.0);
        prop_assert!(v.min_difficulty <= v.max_difficulty);
        prop_assert!(v.variance_tolerance.is_finite() && v.variance_tolerance > 0.0);
        prop_assert!(!v.retarget_interval.is_zero());
    }

    #[test]
    fn difficulty_always_in_bounds(
        initial in 0.001f64..1e12,
        min_diff in 0.001f64..1e6,
        max_diff_delta in 1.0f64..1e6,
    ) {
        let min = min_diff;
        let max = min + max_diff_delta;
        let config = VardiffConfig {
            initial_difficulty: initial,
            min_difficulty: min,
            max_difficulty: max,
            ..Default::default()
        };
        let controller = VardiffController::new(config);
        let d = controller.current_difficulty();
        prop_assert!(d >= min && d <= max, "difficulty {} not in [{}, {}]", d, min, max);
    }

    #[test]
    fn set_difficulty_clamps(
        set_to in prop::num::f64::ANY,
    ) {
        let config = VardiffConfig {
            min_difficulty: 10.0,
            max_difficulty: 1000.0,
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        controller.set_difficulty(set_to);
        let d = controller.current_difficulty();
        prop_assert!(d >= 10.0 && d <= 1000.0, "difficulty {} not in [10, 1000]", d);
    }

    #[test]
    fn stats_always_finite(
        n_shares in 0u32..100,
    ) {
        let config = VardiffConfig {
            retarget_interval: Duration::from_millis(1),
            ..Default::default()
        };
        let mut controller = VardiffController::new(config);
        for _ in 0..n_shares {
            controller.record_share();
        }
        let stats = controller.stats();
        prop_assert!(stats.current_difficulty.is_finite());
        prop_assert!(stats.current_rate.is_finite());
        prop_assert!(stats.target_rate.is_finite());
    }
}
