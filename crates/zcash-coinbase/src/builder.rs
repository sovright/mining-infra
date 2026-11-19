//! Pool-side coinbase construction.
//!
//! Injects a pool tag into the coinbase scriptSig.
//!
//! Only input 0's scriptSig bytes are replaced; every other byte of the
//! transaction, including any shielded bundles, is copied unchanged. That keeps
//! one code path for v4, v5 and v6, whose field orders differ.

use crate::digest;
use crate::tx_parse::{self, push_compact_size};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("parse error: {0}")]
    Parse(#[from] tx_parse::ParseError),
    #[error("tagged coinbase has no valid txid: {0}")]
    Digest(#[from] digest::DigestError),
    #[error("coinbase has no inputs")]
    NoInputs,
    #[error("coinbase scriptSig too large after tag injection: {0} bytes")]
    ScriptSigTooLarge(usize),
    #[error("coinbase scriptSig is empty (missing height push)")]
    EmptyScriptSig,
    #[error("coinbase scriptSig too short: need {expected} bytes for height push, got {actual}")]
    ScriptSigTooShort { expected: usize, actual: usize },
}

#[derive(Debug, Clone)]
pub struct BuiltCoinbase {
    pub tx_bytes: Vec<u8>,
    pub txid: [u8; 32],
}

/// Build a coinbase transaction with a pool tag injected into the scriptSig.
///
/// The pool tag is appended after the height push in input 0's scriptSig.
/// The resulting scriptSig must be <= 100 bytes (consensus limit).
pub fn build_coinbase(raw_coinbase: &[u8], pool_tag: &[u8]) -> Result<BuiltCoinbase, BuilderError> {
    let parsed = tx_parse::parse_transaction(raw_coinbase)?;

    if parsed.inputs.is_empty() {
        return Err(BuilderError::NoInputs);
    }

    // Extract the height push from the original scriptSig.
    // The first byte is the push length, followed by that many bytes of height data.
    let original_script = &parsed.inputs[0].script_sig;
    if original_script.is_empty() {
        return Err(BuilderError::EmptyScriptSig);
    }
    let height_push_len = original_script[0] as usize;
    let needed = 1 + height_push_len;
    if original_script.len() < needed {
        return Err(BuilderError::ScriptSigTooShort {
            expected: needed,
            actual: original_script.len(),
        });
    }
    let height_bytes = &original_script[..needed];

    // Build new scriptSig: height_bytes + pool_tag
    let mut new_script = Vec::with_capacity(height_bytes.len() + pool_tag.len());
    new_script.extend_from_slice(height_bytes);
    new_script.extend_from_slice(pool_tag);

    if new_script.len() > 100 {
        return Err(BuilderError::ScriptSigTooLarge(new_script.len()));
    }

    let (script_start, script_end) = parsed
        .input0_script_span
        .expect("a parsed input 0 has a scriptSig span");
    let raw = &parsed.raw;
    let mut tx_bytes = Vec::with_capacity(raw.len() + pool_tag.len());
    tx_bytes.extend_from_slice(&raw[..script_start]);
    push_compact_size(&mut tx_bytes, new_script.len() as u64);
    tx_bytes.extend_from_slice(&new_script);
    tx_bytes.extend_from_slice(&raw[script_end..]);

    let txid = digest::txid(&tx_bytes)?;

    Ok(BuiltCoinbase { tx_bytes, txid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_parse;

    #[test]
    fn inject_tag_into_coinbase_scriptsig() {
        let original = tx_parse::minimal_v4_coinbase();
        let result = build_coinbase(&original, b"/Sovright/").unwrap();
        assert!(
            result
                .tx_bytes
                .windows(b"/Sovright/".len())
                .any(|w| w == b"/Sovright/")
        );
    }

    #[test]
    fn built_coinbase_has_valid_txid() {
        let original = tx_parse::minimal_v4_coinbase();
        let result = build_coinbase(&original, b"/Sovright/").unwrap();
        let expected = digest::txid(&result.tx_bytes).unwrap();
        assert_eq!(result.txid, expected);
    }

    #[test]
    fn reserialize_preserves_trailing_data() {
        let original = tx_parse::minimal_v4_coinbase();
        let parsed_original = tx_parse::parse_transaction(&original).unwrap();
        let result = build_coinbase(&original, b"/Test/").unwrap();
        let parsed_result = tx_parse::parse_transaction(&result.tx_bytes).unwrap();
        // Output values should be preserved
        assert_eq!(
            parsed_original.outputs[0].value,
            parsed_result.outputs[0].value
        );
    }

    #[test]
    fn script_sig_too_large_returns_error() {
        let original = tx_parse::minimal_v4_coinbase();
        let big_tag = vec![0x42u8; 100]; // height push + 100 bytes > 100
        let result = build_coinbase(&original, &big_tag);
        assert!(matches!(result, Err(BuilderError::ScriptSigTooLarge(_))));
    }
}
