//! Zebra JSON-RPC client for getblocktemplate and submitblock

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Zebra RPC client
pub struct ZebraRpc {
    client: HttpClient,
    request_id: AtomicU64,
}

/// Transaction in block template
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateTransaction {
    /// Transaction data (hex)
    #[allow(dead_code)] // Part of API, used for full block reconstruction
    pub data: String,
    /// Transaction hash (hex, little-endian)
    pub hash: String,
    /// Transaction fee in zatoshis
    #[allow(dead_code)] // Part of API, used for fee calculations
    #[serde(default)]
    pub fee: i64,
}

/// Block template response from getblocktemplate
#[derive(Debug, Clone, Deserialize)]
pub struct BlockTemplate {
    /// Block version
    pub version: u32,
    /// Previous block hash (hex)
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: String,
    /// Block time
    #[serde(rename = "curtime")]
    pub cur_time: u64,
    /// Target bits (hex)
    pub bits: String,
    /// Block height
    pub height: u64,
    /// Transactions to include
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase transaction (hex)
    #[serde(rename = "coinbasetxn")]
    pub coinbase_txn: Option<CoinbaseTxn>,
    /// Default commitment (hex) for block header
    #[serde(rename = "defaultroots")]
    pub default_roots: Option<DefaultRoots>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CoinbaseTxn {
    pub data: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultRoots {
    /// Merkle root (hex)
    #[serde(rename = "merkleroot")]
    pub merkle_root: String,
    /// Block commitments hash (hex)
    #[allow(dead_code)] // Part of Zebra API response
    #[serde(rename = "blockcommitmentshash")]
    pub block_commitments_hash: Option<String>,
    /// Chain history root (hex)
    #[serde(rename = "chainhistoryroot")]
    pub chain_history_root: Option<String>,
    /// Auth data root (hex)
    #[allow(dead_code)] // Part of Zebra API response
    #[serde(rename = "authdataroot")]
    pub auth_data_root: Option<String>,
}

/// Parameters for getblocktemplate
#[derive(Debug, Serialize)]
pub struct GetBlockTemplateParams {
    pub mode: String,
}

impl ZebraRpc {
    /// Create a new Zebra RPC client
    pub async fn new(url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = HttpClientBuilder::default().build(url)?;
        Ok(Self {
            client,
            request_id: AtomicU64::new(1),
        })
    }

    /// Get a block template from Zebra
    pub async fn get_block_template(
        &self,
    ) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
        let params = GetBlockTemplateParams {
            mode: "template".to_string(),
        };
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let template: BlockTemplate = self
            .client
            .request("getblocktemplate", rpc_params![params])
            .await?;

        Ok(template)
    }

    /// Submit a block to Zebra
    #[allow(dead_code)] // Will be used when sidecar handles block submission
    pub async fn submit_block(
        &self,
        block_hex: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);

        // submitblock returns null on success, or an error string
        let result: Option<String> = self
            .client
            .request("submitblock", rpc_params![block_hex])
            .await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_deserialize() {
        let json = r#"{
            "version": 4,
            "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
            "curtime": 1700000000,
            "bits": "1f07ffff",
            "height": 100,
            "transactions": [],
            "coinbasetxn": {"data": "01000000010000"},
            "defaultroots": {"merkleroot": "abcd1234"}
        }"#;

        let template: BlockTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(template.version, 4);
        assert_eq!(template.height, 100);
    }
}
