#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_equihash_validator::{compact_to_target, difficulty_to_target, target_to_difficulty};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let bits = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let difficulty = f64::from_bits(bits);

    // difficulty_to_target must never panic for any f64 (including NaN, Inf)
    let target = difficulty_to_target(difficulty);

    // target_to_difficulty must never panic
    let recovered = target_to_difficulty(&target);

    // recovered must always be non-negative (or infinity)
    assert!(
        recovered >= 0.0 || recovered.is_infinite(),
        "negative recovered difficulty for input {:?}",
        difficulty
    );

    // For valid positive finite difficulties in a reasonable range,
    // roundtrip should be approximate. Very small difficulties (<1.0) produce
    // targets near max_target where f64 precision loss is extreme, and very
    // large difficulties (>1e20) produce targets near zero with similar issues.
    if difficulty.is_finite() && difficulty >= 1.0 && difficulty < 1e20 {
        if recovered.is_finite() && recovered > 0.0 {
            let ratio = recovered / difficulty;
            // Allow 1% tolerance, matching the existing unit test
            assert!(
                ratio > 0.99 && ratio < 1.01,
                "roundtrip diverged: input={}, recovered={}, ratio={}",
                difficulty, recovered, ratio
            );
        }
    }

    // Also test compact_to_target with the first 4 bytes
    let compact = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let _ = compact_to_target(compact);
});
