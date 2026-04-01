//! Difficulty and target calculations for Zcash mining
//!
//! Zcash uses a 256-bit target. A valid share must have a hash <= target.
//! Difficulty is inversely proportional to target.

use std::cmp::Ordering;

/// 256-bit target value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target(pub [u8; 32]);

impl Target {
    /// Create a target from bytes (little-endian)
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get bytes as little-endian
    pub fn to_le_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Maximum target for Zcash mainnet (difficulty 1)
    pub fn max_mainnet() -> Self {
        // Zcash's powLimit for mainnet
        // 0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        let mut target = [0xff; 32];
        target[28] = 0x07;
        target[29] = 0x00;
        target[30] = 0x00;
        target[31] = 0x00;
        Self(target)
    }

    /// Maximum target from a little-endian 256-bit pow limit
    pub fn max_from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Check if a hash meets this target (hash <= target)
    pub fn is_met_by(&self, hash: &[u8; 32]) -> bool {
        // Compare as little-endian 256-bit integers
        for i in (0..32).rev() {
            match hash[i].cmp(&self.0[i]) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        true // Equal is valid
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare as little-endian 256-bit integers
        for i in (0..32).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

/// Convert compact "bits" representation to full target
///
/// The compact format is: mantissa * 256^(exponent-3)
/// where exponent is the first byte and mantissa is the next 3 bytes
pub fn compact_to_target(compact: u32) -> Target {
    let bytes = compact.to_be_bytes();
    let exponent = bytes[0] as usize;
    let mantissa = ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32);

    let mut target = [0u8; 32];

    if exponent <= 3 {
        // Mantissa fits in lower bytes: shift right to discard bytes that
        // fall below byte index 0
        let shift = 3 - exponent;
        let value = mantissa >> (8 * shift);
        // Always write all 3 bytes; upper bytes will be zero if shifted away
        target[0] = (value & 0xff) as u8;
        target[1] = ((value >> 8) & 0xff) as u8;
        target[2] = ((value >> 16) & 0xff) as u8;
    } else {
        // Place mantissa at exponent-3 position
        let pos = exponent - 3;
        if pos < 32 {
            target[pos] = (mantissa & 0xff) as u8;
        }
        if pos + 1 < 32 {
            target[pos + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if pos + 2 < 32 {
            target[pos + 2] = ((mantissa >> 16) & 0xff) as u8;
        }
    }

    Target(target)
}

/// Convert target to difficulty
///
/// Difficulty = max_target / target
pub fn target_to_difficulty_with_max(target: &Target, max: &Target) -> f64 {
    // Convert to f64 for division (approximate but sufficient for display)
    let max_val = target_to_f64(max);
    let target_val = target_to_f64(target);

    if target_val == 0.0 {
        return f64::INFINITY;
    }

    max_val / target_val
}

/// Convert target to difficulty using mainnet powLimit
pub fn target_to_difficulty(target: &Target) -> f64 {
    target_to_difficulty_with_max(target, &Target::max_mainnet())
}

/// Convert difficulty to target
///
/// Target = max_target / difficulty
pub fn difficulty_to_target_with_max(difficulty: f64, max: &Target) -> Target {
    // Guard against NaN (bypasses <= 0.0 since NaN comparisons are always false)
    // and Infinity (max_val / Infinity = 0.0, producing all-zeros target)
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return *max;
    }

    let max_val = target_to_f64(max);
    let target_val = max_val / difficulty;

    // When difficulty < 1.0, target exceeds max which can overflow 256 bits
    // in f64_to_target. Clamp to all-ones (easiest possible target).
    let max_256 = target_to_f64(&Target([0xff; 32]));
    if target_val >= max_256 {
        return Target([0xff; 32]);
    }

    f64_to_target(target_val)
}

/// Convert difficulty to target using mainnet powLimit
pub fn difficulty_to_target(difficulty: f64) -> Target {
    difficulty_to_target_with_max(difficulty, &Target::max_mainnet())
}

/// Convert target to approximate f64 (loses precision for very large values)
fn target_to_f64(target: &Target) -> f64 {
    let mut result = 0.0f64;
    for i in (0..32).rev() {
        result = result * 256.0 + (target.0[i] as f64);
    }
    result
}

/// Convert f64 to target (approximate)
fn f64_to_target(mut value: f64) -> Target {
    let mut target = [0u8; 32];
    for out in &mut target {
        let value_byte = (value % 256.0) as u8;
        *out = value_byte;
        value = (value - value_byte as f64) / 256.0;
    }
    Target(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_comparison() {
        let low = Target([0x01; 32]);
        let high = Target([0xff; 32]);

        assert!(low < high);
        assert!(high > low);
    }

    #[test]
    fn test_is_met_by() {
        let target = Target([0x10; 32]);
        let good_hash = [0x0f; 32];
        let bad_hash = [0x11; 32];

        assert!(target.is_met_by(&good_hash));
        assert!(!target.is_met_by(&bad_hash));
    }

    #[test]
    fn test_difficulty_roundtrip() {
        let difficulties = [1.0, 2.0, 100.0, 1000.0, 1_000_000.0];

        for &diff in &difficulties {
            let target = difficulty_to_target(diff);
            let recovered = target_to_difficulty(&target);
            // Allow 1% error due to floating point
            let ratio = recovered / diff;
            assert!(ratio > 0.99 && ratio < 1.01, "diff={}, recovered={}", diff, recovered);
        }
    }

    #[test]
    fn test_difficulty_to_target_nan_infinity() {
        let max = Target::max_mainnet();

        // NaN should return max target (not corrupt to all-zeros)
        let nan_target = difficulty_to_target_with_max(f64::NAN, &max);
        assert_eq!(nan_target, max);

        // +Infinity should return max target
        let inf_target = difficulty_to_target_with_max(f64::INFINITY, &max);
        assert_eq!(inf_target, max);

        // -Infinity should return max target
        let neg_inf_target = difficulty_to_target_with_max(f64::NEG_INFINITY, &max);
        assert_eq!(neg_inf_target, max);

        // Negative values should return max target
        let neg_target = difficulty_to_target_with_max(-1.0, &max);
        assert_eq!(neg_target, max);

        // Zero should return max target
        let zero_target = difficulty_to_target_with_max(0.0, &max);
        assert_eq!(zero_target, max);

        // Valid positive difficulty should NOT return max target
        let valid_target = difficulty_to_target_with_max(100.0, &max);
        assert_ne!(valid_target, max);
    }
}
