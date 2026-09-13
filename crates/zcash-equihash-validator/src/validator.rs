//! Equihash solution validator
//!
//! Wraps the `equihash` crate to provide verification for Zcash's (200,9) parameters.

use crate::error::{Result, ValidationError};
use tracing::{debug, trace};

/// Zcash Equihash parameters
pub const EQUIHASH_N: u32 = 200;
pub const EQUIHASH_K: u32 = 9;

/// Expected solution size for (200,9): 512 * 21 bits / 8 = 1344 bytes
pub const SOLUTION_SIZE: usize = 1344;

/// Equihash solution validator for Zcash
#[derive(Debug, Clone)]
pub struct EquihashValidator {
    n: u32,
    k: u32,
}

impl Default for EquihashValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl EquihashValidator {
    /// Create a new validator with Zcash parameters (200,9)
    pub fn new() -> Self {
        Self {
            n: EQUIHASH_N,
            k: EQUIHASH_K,
        }
    }

    /// Get the n parameter
    pub fn n(&self) -> u32 {
        self.n
    }

    /// Get the k parameter
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Verify an Equihash solution
    ///
    /// # Arguments
    /// * `header` - The 140-byte block header (including nonce, excluding solution)
    /// * `solution` - The 1344-byte Equihash solution
    ///
    /// # Returns
    /// * `Ok(())` if the solution is valid
    /// * `Err(ValidationError)` if verification fails
    pub fn verify_solution(&self, header: &[u8], solution: &[u8]) -> Result<()> {
        // Validate input lengths
        if header.len() != 140 {
            return Err(ValidationError::InvalidHeaderLength(header.len()));
        }
        if solution.len() != SOLUTION_SIZE {
            return Err(ValidationError::InvalidSolutionLength(solution.len()));
        }

        trace!(
            "Verifying Equihash solution: header_len={}, solution_len={}",
            header.len(),
            solution.len()
        );

        // The equihash crate expects:
        // - input: the 108-byte header prefix (before nonce)
        // - nonce: the 32-byte nonce
        // - solution: the 1344-byte solution
        let input = &header[..108];
        let nonce = &header[108..140];

        equihash::is_valid_solution(self.n, self.k, input, nonce, solution)
            .map_err(|e| ValidationError::InvalidSolution(format!("{:?}", e)))?;

        debug!("Equihash solution verified successfully");
        Ok(())
    }

    /// Verify a solution and check if it meets the target difficulty
    ///
    /// # Arguments
    /// * `header` - The 140-byte block header
    /// * `solution` - The 1344-byte Equihash solution
    /// * `target` - The 256-bit target (solution hash must be <= target)
    ///
    /// # Returns
    /// * `Ok(hash)` if valid and meets target, returns the solution hash
    /// * `Err(ValidationError)` if verification fails or target not met
    pub fn verify_share(
        &self,
        header: &[u8],
        solution: &[u8],
        target: &[u8; 32],
    ) -> Result<[u8; 32]> {
        // First verify the solution is valid
        self.verify_solution(header, solution)?;

        // Compute the hash of header + solution
        let hash = self.compute_solution_hash(header, solution);

        // Check if hash meets target (hash <= target, little-endian comparison)
        if !self.meets_target(&hash, target) {
            return Err(ValidationError::TargetNotMet);
        }

        Ok(hash)
    }

    /// Compute Zcash's proof-of-work hash: the double-SHA256 of the full
    /// 1487-byte serialized header, in internal byte order.
    ///
    /// This is the value the target must be compared against, and the block id
    /// Zebra reports (explorers display its byte reversal). It is deliberately
    /// NOT the BLAKE2b-256 digest personalised `"ZcashBlockHash"`, which is the
    /// relay's internal object id over the same bytes; comparing that digest to
    /// an nBits-derived target accepts a genuine block only by coincidence.
    ///
    /// The rule itself lives in `zcash_pool_common::block_hash`, which is the
    /// single implementation shared with the test miner and the relay.
    /// `tests/consensus_pow_hash.rs` pins the result against mainnet block
    /// 3470793.
    fn compute_solution_hash(&self, header: &[u8], solution: &[u8]) -> [u8; 32] {
        zcash_pool_common::consensus_block_hash_parts(header, solution)
    }

    /// Check if a hash meets the target (hash <= target, little-endian)
    fn meets_target(&self, hash: &[u8; 32], target: &[u8; 32]) -> bool {
        // Compare as little-endian 256-bit integers
        // Start from the most significant byte (index 31) and work down
        for i in (0..32).rev() {
            if hash[i] < target[i] {
                return true;
            }
            if hash[i] > target[i] {
                return false;
            }
        }
        true // Equal is also valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meets_target() {
        let validator = EquihashValidator::new();

        // Hash is less than target
        let hash = [0x00; 32];
        let target = [0xff; 32];
        assert!(validator.meets_target(&hash, &target));

        // Hash equals target
        let same = [0x42; 32];
        assert!(validator.meets_target(&same, &same));

        // Hash is greater than target
        let high_hash = [0xff; 32];
        let low_target = [0x00; 32];
        assert!(!validator.meets_target(&high_hash, &low_target));
    }

    #[test]
    fn test_parameter_values() {
        let validator = EquihashValidator::new();
        assert_eq!(validator.n(), 200);
        assert_eq!(validator.k(), 9);
    }
}
