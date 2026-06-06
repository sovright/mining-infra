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

    // Fractional difficulties produce targets above max_target; that is
    // fine as long as the result still fits in 256 bits. Saturate to
    // all-ones (accept any valid Equihash solution) only when it does not
    // -- f64_to_target silently overflows past 2^256, producing garbage.
    //
    // Do NOT clamp at difficulty < 1.0: that created a cliff between
    // "accept everything" and mainnet diff 1 with no expressible target in
    // between, which broke vardiff for CPU-class workers (sub-unity
    // adjustments were no-ops, then one step jumped past feasibility).
    if target_val >= 2f64.powi(256) {
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
            assert!(
                ratio > 0.99 && ratio < 1.01,
                "diff={}, recovered={}",
                diff,
                recovered
            );
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

    #[test]
    fn test_difficulty_to_target_sub_one() {
        // At difficulty < 1.0, target should overflow and clamp to all-ones
        let diffs = [0.5, 0.1, 0.01, 0.001, 0.0001];
        for d in diffs {
            let t = difficulty_to_target(d);
            let bytes = t.to_le_bytes();
            println!("diff={}: target={}", d, hex::encode(bytes));
        }
        // Difficulty 1.0 should equal max_mainnet
        let t1 = difficulty_to_target(1.0);
        let max = Target::max_mainnet();
        println!("diff=1.0: target={}", hex::encode(t1.to_le_bytes()));
        println!("max_mainnet:     {}", hex::encode(max.to_le_bytes()));

        // At difficulty 0.0001 (the testnet initial difficulty), the target
        // is expressible in 256 bits and must roundtrip -- NOT clamp to
        // all-ones. The old clamp at difficulty < 1.0 made every sub-unity
        // vardiff adjustment a no-op (see test_fractional_difficulty_is_continuous).
        let t_low = difficulty_to_target(0.0001);
        assert_ne!(
            t_low.to_le_bytes(),
            [0xff; 32],
            "diff=0.0001 must be expressible, got all-ones"
        );
        let roundtrip = target_to_difficulty(&t_low);
        assert!(
            (roundtrip - 0.0001).abs() / 0.0001 < 0.01,
            "diff=0.0001 roundtripped to {roundtrip}"
        );
    }

    #[test]
    fn test_fractional_difficulty_is_continuous() {
        // Regression: difficulties in (saturation, 1.0) used to clamp to
        // all-ones, creating a cliff between "accept everything" and
        // mainnet diff 1 with no CPU-feasible target in between
        // (live incident 2026-06-05: vardiff 0.0001 -> 0.0126 was a no-op,
        // then the next step jumped past feasibility and shares hit zero).
        for d in [0.5, 0.1, 0.01, 0.001] {
            let t = difficulty_to_target(d);
            assert_ne!(
                t.to_le_bytes(),
                [0xff; 32],
                "diff={d} must be expressible, not clamped to all-ones"
            );
            let roundtrip = target_to_difficulty(&t);
            assert!(
                (roundtrip - d).abs() / d < 0.01,
                "diff={d} roundtripped to {roundtrip}"
            );
        }
    }

    #[test]
    fn test_difficulty_monotonic_across_unity() {
        // Halving difficulty must exactly double the target on both sides
        // of 1.0 -- no discontinuity at the unity boundary.
        let pairs = [(0.25, 0.5), (0.5, 1.0), (1.0, 2.0), (2.0, 4.0)];
        for (easier, harder) in pairs {
            let t_easier = target_to_f64(&difficulty_to_target(easier));
            let t_harder = target_to_f64(&difficulty_to_target(harder));
            assert!(
                t_easier > t_harder,
                "target({easier}) must be larger (easier) than target({harder})"
            );
            let ratio = t_easier / t_harder;
            assert!(
                (ratio - 2.0).abs() < 0.02,
                "halving difficulty {harder}->{easier} should double target, ratio={ratio}"
            );
        }
    }

    #[test]
    fn test_saturation_only_below_representable_bound() {
        let max = Target::max_mainnet();
        let max_val = target_to_f64(&max);
        let saturation = max_val / 2f64.powi(256);

        // Far below the bound: all-ones (accept any valid solution).
        let t_tiny = difficulty_to_target(saturation * 0.5);
        assert_eq!(t_tiny.to_le_bytes(), [0xff; 32]);

        // Just above the bound: expressible.
        let t_above = difficulty_to_target(saturation * 2.0);
        assert_ne!(t_above.to_le_bytes(), [0xff; 32]);
    }

    #[test]
    fn test_vardiff_adjustment_takes_effect_sub_unity() {
        // The live-incident arithmetic: vardiff multiplied 0.0001 by ~126.
        // Before the fix both values clamped to the same all-ones target,
        // so the adjustment was a no-op and the controller re-measured the
        // same flood, compounding past feasibility.
        let before = difficulty_to_target(0.0001);
        let after = difficulty_to_target(0.0001 * 126.0);
        assert_ne!(
            before.to_le_bytes(),
            after.to_le_bytes(),
            "a 126x difficulty increase must change the effective target"
        );
    }

    #[test]
    fn test_f64_to_target_overflow() {
        // Test what f64_to_target does with a value > 2^256
        let huge = 1.0e78; // way bigger than 2^256
        let t = f64_to_target(huge);
        println!("f64_to_target(1e78) = {}", hex::encode(t.to_le_bytes()));

        let max_256_f64 = target_to_f64(&Target([0xff; 32]));
        println!("max_256 as f64 = {:.6e}", max_256_f64);
        println!("1e78 >= max_256? {}", huge >= max_256_f64);
    }
}
