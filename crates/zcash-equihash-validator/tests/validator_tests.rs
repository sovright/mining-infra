use zcash_equihash_validator::difficulty::{compact_to_target, difficulty_to_target};
use zcash_equihash_validator::{EquihashValidator, ValidationError};

#[test]
fn test_validator_creation() {
    let validator = EquihashValidator::new();
    assert_eq!(validator.n(), 200);
    assert_eq!(validator.k(), 9);
}

#[test]
fn test_invalid_solution_rejected() {
    let validator = EquihashValidator::new();

    // All-zero header and solution should fail verification
    let header = [0u8; 140];
    let solution = [0u8; 1344];

    let result = validator.verify_solution(&header, &solution);
    assert!(result.is_err());
}

#[test]
fn test_wrong_solution_length_rejected() {
    let validator = EquihashValidator::new();

    let header = [0u8; 140];
    let bad_solution = [0u8; 100]; // Wrong length

    let result = validator.verify_solution(&header, &bad_solution);
    assert!(matches!(
        result,
        Err(ValidationError::InvalidSolutionLength(_))
    ));
}

#[test]
fn test_compact_to_target() {
    // Standard testnet difficulty
    let compact = 0x1d00ffff_u32;
    let target = compact_to_target(compact);

    // Should produce a target with leading zeros
    assert!(target.0[31] == 0x00);
}

#[test]
fn test_difficulty_to_target() {
    // Difficulty 1 should give max target
    // Zcash max target is 0007ffff... which has high byte at position 28 (little-endian)
    let target = difficulty_to_target(1.0);
    assert!(
        target.0[28] > 0,
        "Expected non-zero byte at position 28 for difficulty 1"
    );

    // Higher difficulty = lower target
    let harder = difficulty_to_target(2.0);
    assert!(harder < target);
}
