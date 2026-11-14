//! Zcash coinbase transaction construction and validation
pub mod auth_digest;
pub mod builder;
pub mod digest;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
#[cfg(test)]
mod nu7_tests;
pub mod reward;
pub mod tx_parse;
pub mod validator;
