#![no_main]

use libfuzzer_sys::fuzz_target;
use zcash_pool_common::PayoutTracker;

fuzz_target!(|data: &[u8]| {
    // Interpret bytes as a sequence of f64 difficulty values.
    // Exercises record_share's input validation against all bit patterns.
    if data.len() < 8 {
        return;
    }

    let tracker = PayoutTracker::default();
    let miner = "fuzz_miner".to_string();

    for chunk in data.chunks_exact(8) {
        let difficulty = f64::from_le_bytes(chunk.try_into().unwrap());
        // Must not panic on any f64 bit pattern
        tracker.record_share(&miner, difficulty);
    }

    // Exercise stats retrieval -- must not panic
    let _ = tracker.get_stats(&miner);
    let _ = tracker.get_all_stats();
    let _ = tracker.estimate_pool_hashrate();
    let _ = tracker.active_miner_count();
});
