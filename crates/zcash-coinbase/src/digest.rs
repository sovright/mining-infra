//! Transaction IDs and ZIP 244 auth digests, from zcash_primitives.
//!
//! v5 and later txids are ZIP 244 BLAKE2b digests, not SHA256d, and a coinbase
//! auth digest covers its real shielded authorization (mainnet coinbases carry
//! funding-stream outputs; NU7 coinbases can carry Ironwood actions). Both are
//! taken from `zcash_primitives` rather than recomputed here.

use std::io::Cursor;

use sha2::{Digest, Sha256};
use thiserror::Error;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::auth_digest::compute_auth_data_root;

/// Passed to `Transaction::read`. Only v4 and earlier use it (for the Sapling
/// sighash); v5 and later read their branch from their own bytes.
const READER_BRANCH_HINT: BranchId = BranchId::Nu7;

#[derive(Error, Debug)]
pub enum DigestError {
    #[error("transaction too short to carry a version")]
    TooShort,
    #[error("transaction does not parse: {0}")]
    Parse(String),
    #[error("{bytes} bytes follow the transaction")]
    TrailingBytes { bytes: usize },
    #[error("v{version} transactions have no ZIP 244 auth digest, and are invalid after NU7")]
    NoAuthDigest { version: u32 },
    #[error(
        "coinbase consensus branch {coinbase:#010x} does not match the template's {template:#010x}"
    )]
    BranchMismatch { coinbase: u32, template: u32 },
}

fn version(raw: &[u8]) -> Result<u32, DigestError> {
    let header: [u8; 4] = raw
        .get(..4)
        .ok_or(DigestError::TooShort)?
        .try_into()
        .expect("four bytes");
    Ok(u32::from_le_bytes(header) & 0x7fff_ffff)
}

/// Read exactly one transaction, refusing trailing bytes.
fn read_exact(raw: &[u8]) -> Result<Transaction, DigestError> {
    let mut cursor = Cursor::new(raw);
    let tx = Transaction::read(&mut cursor, READER_BRANCH_HINT)
        .map_err(|e| DigestError::Parse(e.to_string()))?;
    let trailing = raw.len() - cursor.position() as usize;
    if trailing != 0 {
        return Err(DigestError::TrailingBytes { bytes: trailing });
    }
    Ok(tx)
}

fn auth_commitment(tx: &Transaction) -> [u8; 32] {
    tx.auth_commitment()
        .as_bytes()
        .try_into()
        .expect("ZIP 244 auth digests are 32 bytes")
}

/// Internal-order txid: SHA256d for v4 and earlier, ZIP 244 for v5 and later.
///
/// v4 and earlier stay SHA256d of the bytes, which is their txid by definition,
/// so a v4 transaction does not have to be fully parseable to get one.
pub fn txid(raw: &[u8]) -> Result<[u8; 32], DigestError> {
    if version(raw)? < 5 {
        return Ok(Sha256::digest(Sha256::digest(raw)).into());
    }
    Ok(*read_exact(raw)?.txid().as_ref())
}

/// Internal-order ZIP 244 auth digest of a v5 or later transaction.
pub fn auth_digest(raw: &[u8]) -> Result<[u8; 32], DigestError> {
    let version = version(raw)?;
    if version < 5 {
        return Err(DigestError::NoAuthDigest { version });
    }
    Ok(auth_commitment(&read_exact(raw)?))
}

/// The auth data root of a block whose only transaction is `coinbase`, as used
/// for Coinbase-Only job declarations.
///
/// The coinbase must carry the template's consensus branch: a coinbase built
/// for another network upgrade commits to the wrong branch and Zebra rejects
/// the block.
pub fn coinbase_only_auth_data_root(
    coinbase: &[u8],
    template_branch_id: u32,
) -> Result<[u8; 32], DigestError> {
    let version = version(coinbase)?;
    if version < 5 {
        return Err(DigestError::NoAuthDigest { version });
    }
    let tx = read_exact(coinbase)?;
    let branch = u32::from(tx.consensus_branch_id());
    if branch != template_branch_id {
        return Err(DigestError::BranchMismatch {
            coinbase: branch,
            template: template_branch_id,
        });
    }
    Ok(compute_auth_data_root(&[auth_commitment(&tx)]))
}
