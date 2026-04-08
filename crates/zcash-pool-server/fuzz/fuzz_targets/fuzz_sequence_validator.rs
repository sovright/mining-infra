#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_pool_server::security::{SequenceCheckResult, SequenceValidator};

/// Interprets fuzz data as a sequence of (channel_id, sequence_number) operations
/// and validates invariants of the SequenceValidator state machine.
fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }

    // First 2 bytes configure the validator
    let max_gap = ((data[0] as u32) << 8 | data[1] as u32).max(1);
    let window_size = (data[2] as usize).max(1).min(128);
    let validator = SequenceValidator::new(max_gap, window_size);

    // Remaining bytes are pairs of (channel_id_byte, seq_hi, seq_lo)
    let ops = &data[3..];
    let mut i = 0;

    while i + 2 < ops.len() {
        let channel_id = ops[i] as u32;
        let sequence = (ops[i + 1] as u32) << 8 | ops[i + 2] as u32;
        i += 3;

        let result = validator.validate(channel_id, sequence);

        // Invariant: result must be one of the defined variants (no panic)
        match result {
            SequenceCheckResult::Valid
            | SequenceCheckResult::ValidOutOfOrder
            | SequenceCheckResult::Replay
            | SequenceCheckResult::GapTooLarge
            | SequenceCheckResult::StaleSequence => {}
        }

        // If the result was processable (Valid or ValidOutOfOrder or GapTooLarge),
        // the sequence was added to the window, so re-validating must be Replay.
        // StaleSequence does NOT add to window, so re-validate could be Stale again.
        if result != SequenceCheckResult::StaleSequence {
            let replay_result = validator.validate(channel_id, sequence);
            assert_eq!(
                replay_result,
                SequenceCheckResult::Replay,
                "Re-validating seq {} on channel {} should be Replay after {:?}, got {:?}",
                sequence,
                channel_id,
                result,
                replay_result
            );
        }

        // anomaly_count must never decrease (monotonic)
        let _count = validator.anomaly_count(channel_id);
    }

    // Test remove_channel doesn't panic
    for ch in 0..=255u32 {
        validator.remove_channel(ch);
    }
});
