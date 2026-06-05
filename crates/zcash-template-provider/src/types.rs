//! Core types for Zcash block templates

use serde::Deserialize;

/// 32-byte hash type used throughout Zcash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Parse from display-order hex (big-endian, as used by `previousblockhash`).
    /// Reverses bytes to convert from display order to internal little-endian order.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        bytes.reverse();
        Ok(Self(bytes))
    }

    /// Parse from internal-order hex (little-endian, as used by Zebra's
    /// `merkleroot`, `chainhistoryroot`, `authdataroot`, `blockcommitmentshash`).
    /// Does NOT reverse bytes -- hex is already in internal byte order.
    pub fn from_hex_le(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Encode as display-order hex (big-endian, reversed from internal).
    pub fn to_hex(&self) -> String {
        let mut bytes = self.0;
        bytes.reverse();
        hex::encode(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Zcash block header for Equihash mining (140 bytes before solution)
#[derive(Debug, Clone)]
pub struct EquihashHeader {
    /// Block version (4 bytes)
    pub version: u32,
    /// Hash of previous block (32 bytes)
    pub prev_hash: Hash256,
    /// Merkle root of transactions (32 bytes)
    pub merkle_root: Hash256,
    /// Block commitments hash (32 bytes) - post-NU5
    pub hash_block_commitments: Hash256,
    /// Block timestamp (4 bytes)
    pub time: u32,
    /// Difficulty target (4 bytes, compact format)
    pub bits: u32,
    /// Full 32-byte nonce space
    pub nonce: [u8; 32],
}

impl EquihashHeader {
    /// Serialize header to 140 bytes for Equihash input
    pub fn serialize(&self) -> [u8; 140] {
        let mut out = [0u8; 140];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(self.prev_hash.as_bytes());
        out[36..68].copy_from_slice(self.merkle_root.as_bytes());
        out[68..100].copy_from_slice(self.hash_block_commitments.as_bytes());
        out[100..104].copy_from_slice(&self.time.to_le_bytes());
        out[104..108].copy_from_slice(&self.bits.to_le_bytes());
        out[108..140].copy_from_slice(&self.nonce);
        out
    }
}

/// Transaction data from getblocktemplate
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateTransaction {
    /// Raw transaction hex
    pub data: String,
    /// Transaction hash
    pub hash: String,
    /// Transaction fee in zatoshis
    pub fee: i64,
    /// Indices of transactions this depends on
    #[serde(default)]
    pub depends: Vec<u32>,
}

/// Default roots from Zebra getblocktemplate
#[derive(Debug, Clone, Deserialize)]
pub struct DefaultRoots {
    #[serde(rename = "merkleroot")]
    pub merkle_root: String,
    #[serde(rename = "chainhistoryroot")]
    pub chain_history_root: String,
    #[serde(rename = "authdataroot")]
    pub auth_data_root: String,
    #[serde(rename = "blockcommitmentshash")]
    pub block_commitments_hash: String,
}

/// Raw getblocktemplate response from Zebra
#[derive(Debug, Clone, Deserialize)]
pub struct GetBlockTemplateResponse {
    pub version: u32,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: String,
    #[serde(rename = "defaultroots")]
    pub default_roots: DefaultRoots,
    pub transactions: Vec<TemplateTransaction>,
    #[serde(rename = "coinbasetxn")]
    pub coinbase_txn: serde_json::Value,
    pub target: String,
    pub height: u64,
    pub bits: String,
    #[serde(rename = "curtime")]
    pub cur_time: u64,
}

/// Consensus metadata from Zebra `getblockchaininfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfoConsensus {
    /// Consensus branch ID for the next block, encoded as hex by Zebra.
    #[serde(rename = "nextblock")]
    pub next_block: String,
}

/// Raw getblockchaininfo response subset needed by template processing.
#[derive(Debug, Clone, Deserialize)]
pub struct GetBlockchainInfoResponse {
    pub consensus: BlockchainInfoConsensus,
}

impl GetBlockchainInfoResponse {
    /// Parse `consensus.nextblock` as the branch ID for the block being mined.
    pub fn next_block_branch_id(&self) -> Result<u32, std::num::ParseIntError> {
        u32::from_str_radix(self.consensus.next_block.trim_start_matches("0x"), 16)
    }
}

/// Processed block template ready for mining
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Template ID for tracking
    pub template_id: u64,
    /// Block height
    pub height: u64,
    /// Assembled header (without nonce/solution)
    pub header: EquihashHeader,
    /// Difficulty target as 256-bit value
    pub target: Hash256,
    /// Transactions to include
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase transaction
    pub coinbase: Vec<u8>,
    /// Chain history root from Zebra's `defaultroots.chainhistoryroot`.
    pub chain_history_root: Hash256,
    /// Consensus branch ID from Zebra's `getblockchaininfo.consensus.nextblock`.
    pub consensus_branch_id: u32,
    /// Total fees available
    pub total_fees: i64,
}
