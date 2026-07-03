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

/// Subset of `getblockchaininfo` we care about for sidecar safety checks.
///
/// Zebra's `getblockchaininfo` returns more fields; we only deserialize the
/// ones the submit gate and adjacent components need. `serde(default)` on the
/// rest means future Zebra additions do not break this client.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfo {
    /// Best-chain tip height (`blocks` field in Zebra's RPC).
    pub blocks: u64,
    /// Best block hash (hex).
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: String,
    /// Number of headers (`headers` field, usually equal to `blocks`).
    #[serde(default)]
    pub headers: Option<u64>,
}

/// Subset of `getblockheader` we use to confirm a block hash exists locally.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeaderInfo {
    /// Hex-encoded block hash that was queried.
    pub hash: String,
    /// Block height.
    pub height: u64,
    /// Parent block hash (hex, big-endian).
    #[serde(rename = "previousblockhash")]
    #[serde(default)]
    pub previous_block_hash: Option<String>,
}

/// Subset of verbose `getrawtransaction` used by the mempool-sync task. Extra
/// fields are ignored. `authdigest` is absent for pre-v5 transactions.
#[derive(Debug, Clone, Deserialize)]
pub struct RawTransaction {
    /// Raw transaction bytes (hex).
    pub hex: String,
    /// ZIP-244 auth digest (hex, display order). Absent for pre-v5 txs.
    #[serde(default)]
    pub authdigest: Option<String>,
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

    /// List the transaction ids currently in the local Zebra mempool (display
    /// order). Used by the mempool-sync task to fold Zebra's fuller mempool into
    /// the compact-reconstruction tx cache.
    pub async fn get_raw_mempool(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let txids: Vec<String> = self.client.request("getrawmempool", rpc_params![]).await?;
        Ok(txids)
    }

    /// Fetch one transaction verbosely (`authdigest` + raw `hex`) by txid.
    pub async fn get_raw_transaction(
        &self,
        txid: &str,
    ) -> Result<RawTransaction, Box<dyn std::error::Error + Send + Sync>> {
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let tx: RawTransaction = self
            .client
            .request("getrawtransaction", rpc_params![txid, 1])
            .await?;
        Ok(tx)
    }

    /// Fetch the current chain info (best tip + best hash).
    ///
    /// The submit gate uses this to compute the height-window check. Used by
    /// the staging service to poll tip on a short cadence.
    pub async fn get_blockchain_info(
        &self,
    ) -> Result<BlockchainInfo, Box<dyn std::error::Error + Send + Sync>> {
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let info: BlockchainInfo = self
            .client
            .request("getblockchaininfo", rpc_params![])
            .await?;
        Ok(info)
    }

    /// Fetch a block header by hash. Returns `Ok(Some(_))` if known, `Ok(None)`
    /// if Zebra reports the block is unknown, `Err(_)` for transport errors.
    ///
    /// The submit gate uses this to validate `parent_known` before allowing a
    /// relay-received block to reach `submitblock`.
    pub async fn get_block_header(
        &self,
        block_hash_hex: &str,
    ) -> Result<Option<BlockHeaderInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);
        // Verbosity 1 returns the JSON object form; 0 returns hex.
        let result: Result<BlockHeaderInfo, _> = self
            .client
            .request("getblockheader", rpc_params![block_hash_hex, true])
            .await;
        match result {
            Ok(info) => Ok(Some(info)),
            Err(jsonrpsee::core::ClientError::Call(call_err)) => {
                // Zebra returns -5 ("Block not found") for unknown hashes; treat
                // every -5 / "not found" call error as a negative result rather
                // than propagating an error.
                let msg = call_err.message().to_lowercase();
                if call_err.code() == -5 || msg.contains("not found") {
                    Ok(None)
                } else {
                    Err(Box::new(jsonrpsee::core::ClientError::Call(call_err)))
                }
            }
            Err(other) => Err(Box::new(other)),
        }
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

    #[test]
    fn blockchain_info_deserialize() {
        // Minimal shape: Zebra returns many more fields; we only consume a few.
        let json = r#"{
            "blocks": 3370892,
            "bestblockhash": "00000000000000000000000000000000000000000000000000000000abcd1234",
            "headers": 3370892
        }"#;
        let info: BlockchainInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.blocks, 3370892);
        assert_eq!(
            info.best_block_hash,
            "00000000000000000000000000000000000000000000000000000000abcd1234"
        );
        assert_eq!(info.headers, Some(3370892));
    }

    #[test]
    fn blockchain_info_tolerates_missing_optional_fields() {
        // The headers field is optional; the rest are required.
        let json = r#"{
            "blocks": 3370892,
            "bestblockhash": "ff"
        }"#;
        let info: BlockchainInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.blocks, 3370892);
        assert_eq!(info.headers, None);
    }

    #[test]
    fn block_header_info_deserialize() {
        let json = r#"{
            "hash": "abcd",
            "height": 100,
            "previousblockhash": "9999"
        }"#;
        let info: BlockHeaderInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.hash, "abcd");
        assert_eq!(info.height, 100);
        assert_eq!(info.previous_block_hash, Some("9999".to_string()));
    }

    #[test]
    fn block_header_info_tolerates_no_parent() {
        // Genesis block has no previousblockhash.
        let json = r#"{
            "hash": "abcd",
            "height": 0
        }"#;
        let info: BlockHeaderInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.previous_block_hash, None);
    }
}
