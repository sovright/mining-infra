//! Zebra JSON-RPC client

use async_trait::async_trait;
use crate::error::{Error, Result};
use crate::types::GetBlockTemplateResponse;
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// Trait abstracting RPC calls to a Zcash node, enabling mock implementations for testing.
#[async_trait]
pub trait RpcProvider: Send + Sync {
    /// Get a block template from the node
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse>;
    /// Submit a solved block to the node
    async fn submit_block(&self, block_hex: &str) -> Result<Option<String>>;
    /// Get the best block hash
    async fn get_best_block_hash(&self) -> Result<String>;
}

/// Zebra RPC client
pub struct ZebraRpc {
    client: Client,
    url: String,
    request_id: AtomicU64,
    /// Optional HTTP basic auth credentials
    auth: Option<(String, String)>,
}

impl ZebraRpc {
    /// Create a new RPC client
    pub fn new(url: &str, user: Option<&str>, pass: Option<&str>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let auth = match (user, pass) {
            (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
            _ => None,
        };

        Ok(Self {
            client,
            url: url.to_string(),
            request_id: AtomicU64::new(1),
            auth,
        })
    }

    /// Make a JSON-RPC request
    async fn request<T: DeserializeOwned, P: Serialize>(
        &self,
        method: &str,
        params: P,
    ) -> Result<T> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id.to_string(),
            "method": method,
            "params": params,
        });

        let mut req_builder = self.client.post(&self.url).json(&request);
        if let Some((ref user, ref pass)) = self.auth {
            req_builder = req_builder.basic_auth(user, Some(pass));
        }
        let response = req_builder.send().await?;

        let body: Value = response.json().await?;

        if let Some(error) = body.get("error") {
            if !error.is_null() {
                return Err(Error::Rpc(error.to_string()));
            }
        }

        let result = body
            .get("result")
            .ok_or_else(|| Error::Rpc("missing result field".into()))?;

        serde_json::from_value(result.clone()).map_err(Error::Json)
    }

}

#[async_trait]
impl RpcProvider for ZebraRpc {
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse> {
        self.request("getblocktemplate", serde_json::json!([])).await
    }

    async fn submit_block(&self, block_hex: &str) -> Result<Option<String>> {
        self.request("submitblock", vec![block_hex]).await
    }

    async fn get_best_block_hash(&self) -> Result<String> {
        self.request("getbestblockhash", serde_json::json!([])).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let rpc = ZebraRpc::new("http://127.0.0.1:8232", None, None);
        assert!(rpc.is_ok());
    }
}
