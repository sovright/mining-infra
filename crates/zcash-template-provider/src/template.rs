//! Template Provider - fetches and manages block templates from Zebra

use crate::error::{Error, Result};
use crate::header::{assemble_header, parse_target};
use crate::rpc::{RpcProvider, ZebraRpc};
use crate::types::{BlockTemplate, GetBlockTemplateResponse};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Configuration for the Template Provider
#[derive(Debug, Clone)]
pub struct TemplateProviderConfig {
    /// Zebra RPC URL (e.g., "http://127.0.0.1:8232")
    pub zebra_url: String,
    /// Poll interval in milliseconds
    pub poll_interval_ms: u64,
}

impl Default for TemplateProviderConfig {
    fn default() -> Self {
        Self {
            zebra_url: "http://127.0.0.1:8232".to_string(),
            poll_interval_ms: 1000,
        }
    }
}

/// Template Provider that interfaces with Zebra and pushes templates to subscribers
pub struct TemplateProvider {
    config: TemplateProviderConfig,
    rpc: Box<dyn RpcProvider>,
    template_id: AtomicU64,
    current_template: Arc<RwLock<Option<BlockTemplate>>>,
    sender: broadcast::Sender<BlockTemplate>,
}

impl TemplateProvider {
    /// Create a new Template Provider
    pub fn new(config: TemplateProviderConfig) -> Result<Self> {
        let rpc = ZebraRpc::new(&config.zebra_url, None, None)?;
        let (sender, _) = broadcast::channel(16);

        Ok(Self {
            config,
            rpc: Box::new(rpc),
            template_id: AtomicU64::new(1),
            current_template: Arc::new(RwLock::new(None)),
            sender,
        })
    }

    /// Create with a custom RPC provider (for testing)
    pub fn with_rpc(config: TemplateProviderConfig, rpc: Box<dyn RpcProvider>) -> Self {
        let (sender, _) = broadcast::channel(16);
        Self {
            config,
            rpc,
            template_id: AtomicU64::new(1),
            current_template: Arc::new(RwLock::new(None)),
            sender,
        }
    }

    /// Subscribe to template updates
    pub fn subscribe(&self) -> broadcast::Receiver<BlockTemplate> {
        self.sender.subscribe()
    }

    /// Get the current template
    pub async fn get_current_template(&self) -> Option<BlockTemplate> {
        self.current_template.read().await.clone()
    }

    /// Fetch a new template from Zebra
    pub async fn fetch_template(&self) -> Result<BlockTemplate> {
        let response = self.rpc.get_block_template().await?;
        self.process_template(response)
    }

    /// Submit a solved block to Zebra
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>> {
        self.rpc.submit_block(block_hex).await
    }

    /// Process a getblocktemplate response into a BlockTemplate
    fn process_template(&self, response: GetBlockTemplateResponse) -> Result<BlockTemplate> {
        let header = assemble_header(&response)?;
        let target = parse_target(&response.target)?;

        let total_fees: i64 = response.transactions.iter().map(|tx| tx.fee).sum();

        // Parse coinbase transaction - reject if missing or empty
        let coinbase = if let Some(data) = response.coinbase_txn.get("data") {
            if let Some(hex_str) = data.as_str() {
                let cb = hex::decode(hex_str).map_err(|e| Error::InvalidTemplate(format!("invalid coinbase hex: {}", e)))?;
                if cb.is_empty() {
                    return Err(Error::InvalidTemplate("coinbase transaction is empty".into()));
                }
                cb
            } else {
                return Err(Error::InvalidTemplate("coinbase data field is not a string".into()));
            }
        } else {
            return Err(Error::InvalidTemplate("coinbase_txn missing data field".into()));
        };

        Ok(BlockTemplate {
            template_id: self.template_id.fetch_add(1, Ordering::SeqCst),
            height: response.height,
            header,
            target,
            transactions: response.transactions,
            coinbase,
            total_fees,
        })
    }

    /// Start the polling loop (call this in a spawned task)
    pub async fn run(&self) -> Result<()> {
        let mut poll_interval = interval(Duration::from_millis(self.config.poll_interval_ms));
        let mut last_fingerprint: Option<String> = None;

        info!(
            "Template provider starting, polling {} every {}ms",
            self.config.zebra_url, self.config.poll_interval_ms
        );

        loop {
            poll_interval.tick().await;

            match self.rpc.get_block_template().await {
                Ok(response) => {
                    let fingerprint = format!(
                        "{}:{}:{}:{}:{}:{}:{}:{}",
                        response.previous_block_hash,
                        response.height,
                        response.default_roots.merkle_root,
                        response.default_roots.block_commitments_hash,
                        response.bits,
                        response.cur_time,
                        response.target,
                        response.transactions.len(),
                    );

                    if last_fingerprint.as_deref() != Some(&fingerprint) {
                        match self.process_template(response) {
                            Ok(template) => {
                                // Only commit the fingerprint AFTER successful processing.
                                // Previously, fingerprint was set before process_template(),
                                // so a processing failure would cause the next identical
                                // template to be skipped (fingerprint already matched).
                                last_fingerprint = Some(fingerprint);

                                info!(
                                    "New template: height={}, fees={}",
                                    template.height, template.total_fees
                                );

                                // Update current template
                                *self.current_template.write().await = Some(template.clone());

                                // Broadcast to subscribers
                                if self.sender.send(template).is_err() {
                                    debug!("No active subscribers");
                                }
                            }
                            Err(e) => {
                                error!("Failed to process template: {}", e);
                                // fingerprint is NOT updated, so next poll will retry
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch template: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TemplateProviderConfig::default();
        assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
        assert_eq!(config.poll_interval_ms, 1000);
    }

    #[test]
    fn test_provider_creation() {
        let config = TemplateProviderConfig::default();
        let provider = TemplateProvider::new(config);
        assert!(provider.is_ok());
    }
}
