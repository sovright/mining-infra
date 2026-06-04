//! Keypair generation and management for Noise Protocol

use std::fmt;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte Curve25519 public key
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let bytes = hex::decode(hex).map_err(|_| KeyError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A Curve25519 keypair (public + private).
/// Private key bytes are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    /// Public key (can be shared)
    #[zeroize(skip)]
    pub public: PublicKey,
    /// Private key (keep secret) - zeroized on drop
    private: [u8; 32],
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let builder = snow::Builder::new(crate::NOISE_PATTERN.parse().unwrap());
        let snow_keypair = builder.generate_keypair().unwrap();

        let mut public = [0u8; 32];
        let mut private = [0u8; 32];
        public.copy_from_slice(&snow_keypair.public);
        private.copy_from_slice(&snow_keypair.private);

        Self {
            public: PublicKey(public),
            private,
        }
    }

    /// Create from existing private key bytes
    pub fn from_private(private: [u8; 32]) -> Self {
        // Derive public key from private using x25519-dalek
        let secret = StaticSecret::from(private);
        let x25519_public = X25519PublicKey::from(&secret);
        let public = PublicKey(*x25519_public.as_bytes());

        Self { public, private }
    }

    /// Load from hex-encoded private key
    pub fn from_private_hex(hex: &str) -> Result<Self, KeyError> {
        let bytes = hex::decode(hex).map_err(|_| KeyError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_private(arr))
    }

    /// Export private key as hex (for config storage)
    pub fn private_hex(&self) -> String {
        hex::encode(self.private)
    }

    /// Get private key bytes (for snow)
    pub(crate) fn private_bytes(&self) -> &[u8; 32] {
        &self.private
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .field("private", &"[redacted]")
            .finish()
    }
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid hex encoding")]
    InvalidHex,
    #[error("Invalid key length: expected 32, got {0}")]
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();

        // Different keypairs should have different public keys
        assert_ne!(kp1.public.0, kp2.public.0);
    }

    #[test]
    fn test_keypair_roundtrip() {
        let kp = Keypair::generate();
        let hex = kp.private_hex();
        let restored = Keypair::from_private_hex(&hex).unwrap();

        assert_eq!(kp.public.0, restored.public.0);
    }

    #[test]
    fn test_public_key_hex() {
        let kp = Keypair::generate();
        let hex = kp.public.to_hex();
        let restored = PublicKey::from_hex(&hex).unwrap();

        assert_eq!(kp.public.0, restored.0);
    }

    #[test]
    fn test_invalid_hex() {
        let result = PublicKey::from_hex("not-valid-hex");
        assert!(matches!(result, Err(KeyError::InvalidHex)));
    }

    #[test]
    fn test_invalid_length() {
        let result = PublicKey::from_hex("0102030405");
        assert!(matches!(result, Err(KeyError::InvalidLength(5))));
    }
}
