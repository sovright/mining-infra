#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_equihash_validator::{compact_to_target, target_to_difficulty};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let compact = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // Must never panic
    let target = compact_to_target(compact);

    // Difficulty must be finite and non-negative (or infinity for zero target)
    let difficulty = target_to_difficulty(&target);
    assert!(
        difficulty >= 0.0 || difficulty.is_infinite(),
        "negative difficulty for compact {:#010x}",
        compact
    );
});
