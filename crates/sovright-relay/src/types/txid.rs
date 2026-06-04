//! Transaction identifier types following ZIP 244
//!
//! ZIP 244 defines two transaction identifiers for v5 transactions:
//! - txid: commits to "effecting data" (transaction effects)
//! - wtxid: concatenates txid with auth_digest for witness commitment

use std::fmt;

/// Transaction ID - 32-byte hash of transaction effecting data (ZIP 244)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Create TxId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create TxId from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({})", hex::encode(self.0))
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Authorization digest - 32-byte hash of transaction authorization data
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthDigest([u8; 32]);

impl AuthDigest {
    /// Create AuthDigest from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuthDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthDigest({})", hex::encode(self.0))
    }
}

/// Witness Transaction ID - combines txid and auth_digest (ZIP 239)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WtxId {
    txid: TxId,
    auth_digest: AuthDigest,
}

impl WtxId {
    /// Create WtxId from txid and auth_digest
    pub fn new(txid: TxId, auth_digest: AuthDigest) -> Self {
        Self { txid, auth_digest }
    }

    /// Get the transaction ID component
    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    /// Get the authorization digest component
    pub fn auth_digest(&self) -> &AuthDigest {
        &self.auth_digest
    }

    /// Serialize to 64-byte array (txid || auth_digest)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.txid.as_bytes());
        bytes[32..].copy_from_slice(self.auth_digest.as_bytes());
        bytes
    }
}

impl fmt::Debug for WtxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WtxId({:?}, {:?})", self.txid, self.auth_digest)
    }
}
