#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_equihash_validator::EquihashValidator;

fuzz_target!(|data: &[u8]| {
    let validator = EquihashValidator::new();

    // Split fuzz data into header and solution at various points
    // This exercises length validation and ensures no panics

    // Case 1: Use entire input as header, empty solution
    let _ = validator.verify_solution(data, &[]);

    // Case 2: Use entire input as solution, empty header
    let _ = validator.verify_solution(&[], data);

    // Case 3: If we have enough bytes, split at 140 (correct header length)
    if data.len() >= 140 {
        let (header, rest) = data.split_at(140);
        let _ = validator.verify_solution(header, rest);

        // Case 4: Also test verify_share with a target
        if rest.len() >= 32 {
            let target: [u8; 32] = rest[..32].try_into().unwrap();
            let solution = &rest[32..];
            let _ = validator.verify_share(header, solution, &target);
        }
    }

    // Case 5: Split in half
    if data.len() >= 2 {
        let mid = data.len() / 2;
        let _ = validator.verify_solution(&data[..mid], &data[mid..]);
    }
});
