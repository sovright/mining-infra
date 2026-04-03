//! Coinbase validation for JD Server.
//!
//! Validates that a coinbase transaction contains the required pool payout output
//! with a sufficient value.

use crate::tx_parse::{self, ParseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoinbaseError {
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("missing pool payout output (expected script: {})", hex::encode(.0))]
    MissingPoolPayout(Vec<u8>),
    #[error("pool payout too low: {actual} < {minimum} zat")]
    InsufficientPayout { actual: u64, minimum: u64 },
}

pub struct CoinbaseValidator {
    pool_payout_script: Vec<u8>,
    min_pool_payout: u64,
}

impl CoinbaseValidator {
    pub fn new(pool_payout_script: Vec<u8>, min_pool_payout: u64) -> Self {
        Self {
            pool_payout_script,
            min_pool_payout,
        }
    }

    /// Validate that the coinbase transaction contains a pool payout output
    /// with the expected script and sufficient value.
    ///
    /// If `pool_payout_script` is empty, validation is skipped (always passes).
    pub fn validate_payout_outputs(&self, coinbase_tx: &[u8]) -> Result<(), CoinbaseError> {
        if self.pool_payout_script.is_empty() {
            return Ok(());
        }

        let parsed = tx_parse::parse_transaction(coinbase_tx)?;

        // Check outputs for matching script with sufficient value
        for output in &parsed.outputs {
            if output.script_pubkey == self.pool_payout_script
                && output.value >= self.min_pool_payout
            {
                return Ok(());
            }
        }

        // Check if script exists but value too low
        for output in &parsed.outputs {
            if output.script_pubkey == self.pool_payout_script {
                return Err(CoinbaseError::InsufficientPayout {
                    actual: output.value,
                    minimum: self.min_pool_payout,
                });
            }
        }

        Err(CoinbaseError::MissingPoolPayout(
            self.pool_payout_script.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_parse::push_compact_size;

    /// Build a minimal v4 coinbase with a single output using the given script and value.
    fn make_coinbase_with_output(script: &[u8], value: u64) -> Vec<u8> {
        let mut tx = Vec::new();

        // Version 4 with overwinter flag
        tx.extend_from_slice(&0x8000_0004u32.to_le_bytes());
        // Version group ID (Sapling)
        tx.extend_from_slice(&0x892F_2085u32.to_le_bytes());

        // 1 coinbase input
        push_compact_size(&mut tx, 1);
        tx.extend_from_slice(&[0u8; 32]); // prevout hash (all zeros)
        tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        let script_sig = vec![0x01, 0x01]; // minimal height push
        push_compact_size(&mut tx, script_sig.len() as u64);
        tx.extend_from_slice(&script_sig);
        tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence

        // 1 output
        push_compact_size(&mut tx, 1);
        tx.extend_from_slice(&value.to_le_bytes());
        push_compact_size(&mut tx, script.len() as u64);
        tx.extend_from_slice(script);

        // Lock time
        tx.extend_from_slice(&0u32.to_le_bytes());
        // Expiry height
        tx.extend_from_slice(&0u32.to_le_bytes());

        tx
    }

    #[test]
    fn valid_payout_passes() {
        let script = vec![0x76, 0xa9, 0x14, 0x01, 0x02, 0x03];
        let coinbase = make_coinbase_with_output(&script, 250_000_000);
        let validator = CoinbaseValidator::new(script, 100_000_000);
        validator.validate_payout_outputs(&coinbase).unwrap();
    }

    #[test]
    fn missing_payout_script_fails() {
        let pool_script = vec![0x76, 0xa9, 0x14, 0x01, 0x02, 0x03];
        let wrong_script = vec![0xa9, 0x14, 0xff, 0xfe];
        let coinbase = make_coinbase_with_output(&wrong_script, 250_000_000);
        let validator = CoinbaseValidator::new(pool_script, 100_000_000);
        let err = validator.validate_payout_outputs(&coinbase).unwrap_err();
        assert!(matches!(err, CoinbaseError::MissingPoolPayout(_)));
    }

    #[test]
    fn insufficient_payout_fails() {
        let script = vec![0x76, 0xa9, 0x14, 0x01, 0x02, 0x03];
        let coinbase = make_coinbase_with_output(&script, 50_000);
        let validator = CoinbaseValidator::new(script, 100_000_000);
        let err = validator.validate_payout_outputs(&coinbase).unwrap_err();
        assert!(matches!(
            err,
            CoinbaseError::InsufficientPayout {
                actual: 50_000,
                minimum: 100_000_000
            }
        ));
    }

    #[test]
    fn empty_pool_script_accepts_anything() {
        let coinbase = make_coinbase_with_output(&[0xde, 0xad], 1);
        let validator = CoinbaseValidator::new(vec![], 999_999_999);
        validator.validate_payout_outputs(&coinbase).unwrap();
    }
}
