use zcash_equihash_validator::vardiff::{VardiffController, VardiffConfig};
use std::time::Duration;

#[test]
fn test_vardiff_creation() {
    let config = VardiffConfig::default();
    let controller = VardiffController::new(config);

    assert!(controller.current_difficulty() > 0.0);
}

#[test]
fn test_vardiff_adjusts_up_on_fast_shares() {
    let config = VardiffConfig {
        target_shares_per_minute: 6.0,
        initial_difficulty: 1.0,
        min_difficulty: 1.0,
        max_difficulty: 1_000_000.0,
        retarget_interval: Duration::from_millis(50), // Very short for testing
        variance_tolerance: 0.25,
        ..Default::default()
    };
    let mut controller = VardiffController::new(config);

    // Simulate very fast share submission (many shares in short time)
    let initial_diff = controller.current_difficulty();
    for _ in 0..100 {
        controller.record_share();
    }

    // Wait for retarget interval to pass
    std::thread::sleep(Duration::from_millis(60));

    controller.maybe_retarget();
    let new_diff = controller.current_difficulty();

    // Difficulty should increase because shares are coming faster than target
    // 100 shares in 60ms = 100000 shares/min vs target of 6/min
    assert!(new_diff > initial_diff,
        "Expected difficulty to increase from {} but got {}", initial_diff, new_diff);
}

#[test]
fn test_vardiff_adjusts_down_on_slow_shares() {
    let config = VardiffConfig {
        target_shares_per_minute: 60.0, // Expect 1 share per second
        initial_difficulty: 1.0,
        min_difficulty: 1.0,
        max_difficulty: 1_000_000.0,
        retarget_interval: Duration::from_millis(100), // Short interval for testing
        variance_tolerance: 0.25,
        ..Default::default()
    };
    let mut controller = VardiffController::new(config);

    // Start at higher difficulty
    controller.set_difficulty(100.0);

    // Simulate slow share submission: 1 share then wait
    // At 60 shares/min target, in 0.1 second we expect 0.1 shares
    // But we submit 0 shares for first 100ms to get below threshold
    std::thread::sleep(Duration::from_millis(110));

    controller.maybe_retarget();
    let new_diff = controller.current_difficulty();

    // Difficulty should decrease because no shares were submitted
    // 0 shares in 110ms = 0 shares/min vs target of 60/min
    assert!(new_diff < 100.0,
        "Expected difficulty to decrease from 100.0 but got {}", new_diff);
}

#[test]
fn test_vardiff_respects_min_difficulty() {
    let config = VardiffConfig {
        target_shares_per_minute: 60.0,
        initial_difficulty: 10.0,
        min_difficulty: 10.0,
        max_difficulty: 1_000_000.0,
        retarget_interval: Duration::from_millis(50),
        variance_tolerance: 0.25,
        ..Default::default()
    };
    let mut controller = VardiffController::new(config);

    // Initial difficulty should be at min
    assert_eq!(controller.current_difficulty(), 10.0);

    // Try to set below min
    controller.set_difficulty(5.0);
    assert_eq!(controller.current_difficulty(), 10.0);
}

#[test]
fn test_vardiff_respects_max_difficulty() {
    let config = VardiffConfig {
        target_shares_per_minute: 60.0,
        initial_difficulty: 1.0,
        min_difficulty: 1.0,
        max_difficulty: 100.0,
        retarget_interval: Duration::from_millis(50),
        variance_tolerance: 0.25,
        ..Default::default()
    };
    let mut controller = VardiffController::new(config);

    // Try to set above max
    controller.set_difficulty(500.0);
    assert_eq!(controller.current_difficulty(), 100.0);
}

#[test]
fn test_vardiff_stats() {
    let config = VardiffConfig {
        target_shares_per_minute: 6.0,
        initial_difficulty: 1.0,
        min_difficulty: 1.0,
        max_difficulty: 1_000_000.0,
        retarget_interval: Duration::from_secs(60),
        variance_tolerance: 0.25,
        ..Default::default()
    };
    let mut controller = VardiffController::new(config);

    // Record some shares
    controller.record_share();
    controller.record_share();
    controller.record_share();

    let stats = controller.stats();
    assert_eq!(stats.shares_in_window, 3);
    assert_eq!(stats.current_difficulty, 1.0);
    assert_eq!(stats.target_rate, 6.0);
}
