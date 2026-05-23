//! Local transaction-feed wire format shared by P2P ingress and sidecar.

use thiserror::Error;

use crate::{AuthDigest, TxId, WtxId};

/// One newline-delimited transaction feed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFeedRecord {
    pub wtxid: WtxId,
    pub tx_bytes: Vec<u8>,
}

impl TxFeedRecord {
    pub fn new(wtxid: WtxId, tx_bytes: Vec<u8>) -> Result<Self, TxFeedError> {
        if tx_bytes.is_empty() {
            return Err(TxFeedError::EmptyTx);
        }
        Ok(Self { wtxid, tx_bytes })
    }

    pub fn encode_line(wtxid: WtxId, tx_bytes: &[u8]) -> String {
        format!(
            "{} {}\n",
            hex::encode(wtxid.to_bytes()),
            hex::encode(tx_bytes)
        )
    }

    pub fn parse_line(line: &str) -> Result<Self, TxFeedError> {
        let mut parts = line.split_whitespace();
        let wtxid_hex = parts.next().ok_or(TxFeedError::MissingWtxId)?;
        let tx_hex = parts.next().ok_or(TxFeedError::MissingTx)?;
        if parts.next().is_some() {
            return Err(TxFeedError::UnexpectedExtraField);
        }

        let mut wtxid_bytes = [0u8; 64];
        hex::decode_to_slice(wtxid_hex, &mut wtxid_bytes).map_err(TxFeedError::InvalidWtxIdHex)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&wtxid_bytes[..32]);
        let mut auth_digest = [0u8; 32];
        auth_digest.copy_from_slice(&wtxid_bytes[32..]);

        let tx_bytes = hex::decode(tx_hex).map_err(TxFeedError::InvalidTxHex)?;
        Self::new(
            WtxId::new(TxId::from_bytes(txid), AuthDigest::from_bytes(auth_digest)),
            tx_bytes,
        )
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum TxFeedError {
    #[error("missing wtxid hex field")]
    MissingWtxId,
    #[error("missing transaction hex field")]
    MissingTx,
    #[error("unexpected extra transaction feed field")]
    UnexpectedExtraField,
    #[error("invalid wtxid hex: {0}")]
    InvalidWtxIdHex(hex::FromHexError),
    #[error("invalid transaction hex: {0}")]
    InvalidTxHex(hex::FromHexError),
    #[error("empty transaction payload")]
    EmptyTx,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[test]
    fn tx_feed_record_roundtrips_line_format() {
        let wtxid = make_wtxid(0x42);
        let tx = vec![0xde, 0xad, 0xbe, 0xef];

        let line = TxFeedRecord::encode_line(wtxid, &tx);
        let parsed = TxFeedRecord::parse_line(&line).unwrap();

        assert_eq!(
            line,
            format!("{} deadbeef\n", hex::encode(wtxid.to_bytes()))
        );
        assert_eq!(
            parsed,
            TxFeedRecord {
                wtxid,
                tx_bytes: tx,
            }
        );
    }

    #[test]
    fn tx_feed_record_rejects_missing_and_extra_fields() {
        let wtxid = make_wtxid(0x42);

        assert!(matches!(
            TxFeedRecord::parse_line(""),
            Err(TxFeedError::MissingWtxId)
        ));
        assert!(matches!(
            TxFeedRecord::parse_line(&format!("{}\n", hex::encode(wtxid.to_bytes()))),
            Err(TxFeedError::MissingTx)
        ));
        assert!(matches!(
            TxFeedRecord::parse_line(&format!(
                "{} deadbeef extra\n",
                hex::encode(wtxid.to_bytes())
            )),
            Err(TxFeedError::UnexpectedExtraField)
        ));
    }

    #[test]
    fn tx_feed_record_rejects_invalid_hex_and_empty_payload() {
        let wtxid = make_wtxid(0x42);

        assert!(matches!(
            TxFeedRecord::parse_line("not-hex deadbeef\n"),
            Err(TxFeedError::InvalidWtxIdHex(_))
        ));
        assert!(matches!(
            TxFeedRecord::parse_line(&format!("{} zz\n", hex::encode(wtxid.to_bytes()))),
            Err(TxFeedError::InvalidTxHex(_))
        ));
        assert_eq!(
            TxFeedRecord::new(wtxid, Vec::new()),
            Err(TxFeedError::EmptyTx)
        );
    }
}
