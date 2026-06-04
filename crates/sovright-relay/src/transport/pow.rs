//! Proof-of-work validation for block headers
//!
//! Provides a trait for PoW validation with a stub implementation.
//! Real Equihash validation can be plugged in later.

/// Minimum block header size in bytes for validation
/// The basic Zcash block header (without Equihash solution) is 140 bytes
const MIN_HEADER_SIZE: usize = 140;

/// Result of PoW validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowResult {
    /// Header has valid proof-of-work - accept and forward the block
    Valid,
    /// Header has invalid proof-of-work - reject and drop the block
    Invalid,
    /// Cannot validate (e.g., header too short) - buffer until more data arrives
    Indeterminate,
}

/// Trait for validating proof-of-work on block headers
pub trait PowValidator: Send + Sync {
    /// Validate the PoW for a block header
    fn validate(&self, header: &[u8]) -> PowResult;
}

/// Stub validator that accepts all headers
#[derive(Debug, Clone, Default)]
pub struct StubPowValidator;

impl PowValidator for StubPowValidator {
    fn validate(&self, header: &[u8]) -> PowResult {
        if header.len() >= MIN_HEADER_SIZE {
            PowResult::Valid
        } else {
            PowResult::Indeterminate
        }
    }
}

/// Validator that rejects all headers (for testing)
#[derive(Debug, Clone, Default)]
pub struct RejectAllValidator;

impl PowValidator for RejectAllValidator {
    fn validate(&self, _header: &[u8]) -> PowResult {
        PowResult::Invalid
    }
}

/// Zcash Equihash parameters
pub const EQUIHASH_N: u32 = 200;
pub const EQUIHASH_K: u32 = 9;

/// Zcash block header size (without Equihash solution)
pub const ZCASH_HEADER_SIZE: usize = 140;

/// Equihash solution size for n=200, k=9
pub const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Full Zcash block header size (with Equihash solution)
pub const ZCASH_FULL_HEADER_SIZE: usize = ZCASH_HEADER_SIZE + 3 + EQUIHASH_SOLUTION_SIZE; // 3 bytes for compactSize

/// Validator using real Equihash proof-of-work verification
///
/// Validates Zcash block headers with Equihash parameters (n=200, k=9).
#[derive(Debug, Clone, Default)]
pub struct EquihashPowValidator;

impl PowValidator for EquihashPowValidator {
    fn validate(&self, header: &[u8]) -> PowResult {
        // Need at least the base header (140 bytes) plus solution
        if header.len() < ZCASH_FULL_HEADER_SIZE {
            return PowResult::Indeterminate;
        }

        // Extract nonce (bytes 108-140, 32 bytes in Zcash)
        let nonce = &header[108..140];

        // The Equihash input is the header up to and including the nonce (140 bytes)
        let input = &header[..140];

        // Extract solution (after the compactSize prefix)
        // CompactSize for 1344 bytes is 0xfd 0x40 0x05 (3 bytes)
        let solution_start = 140 + 3; // Skip compactSize
        if header.len() < solution_start + EQUIHASH_SOLUTION_SIZE {
            return PowResult::Indeterminate;
        }
        let solution = &header[solution_start..solution_start + EQUIHASH_SOLUTION_SIZE];

        // Validate using equihash crate
        match equihash::is_valid_solution(EQUIHASH_N, EQUIHASH_K, input, nonce, solution) {
            Ok(()) => PowResult::Valid,
            Err(_) => PowResult::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_validator_accepts_valid_header() {
        let validator = StubPowValidator;
        let header = vec![0u8; 2189];
        assert_eq!(validator.validate(&header), PowResult::Valid);
    }

    #[test]
    fn stub_validator_rejects_short_header() {
        let validator = StubPowValidator;
        let header = vec![0u8; 100];
        assert_eq!(validator.validate(&header), PowResult::Indeterminate);
    }

    #[test]
    fn reject_all_validator_rejects() {
        let validator = RejectAllValidator;
        let header = vec![0u8; 2189];
        assert_eq!(validator.validate(&header), PowResult::Invalid);
    }

    #[test]
    fn equihash_validator_rejects_short_header() {
        let validator = EquihashPowValidator;
        let header = vec![0u8; 100]; // Too short
        assert_eq!(validator.validate(&header), PowResult::Indeterminate);
    }

    #[test]
    fn equihash_validator_rejects_invalid_solution() {
        let validator = EquihashPowValidator;
        // Create a header with all zeros (invalid Equihash solution)
        let mut header = vec![0u8; ZCASH_FULL_HEADER_SIZE];
        // Set compactSize for solution (0xfd 0x40 0x05 for 1344 bytes)
        header[140] = 0xfd;
        header[141] = 0x40;
        header[142] = 0x05;

        assert_eq!(validator.validate(&header), PowResult::Invalid);
    }
}
