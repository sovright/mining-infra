//! Template Provider - fetches and manages block templates from Zebra

use crate::error::{Error, Result};
use crate::header::{assemble_header, parse_target};
use crate::rpc::{self, RpcProvider, ZebraRpc};
use crate::types::{BlockTemplate, GetBlockTemplateResponse, Hash256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{RwLock, broadcast};
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

/// Configuration for the Template Provider
#[derive(Debug, Clone)]
pub struct TemplateProviderConfig {
    /// Zebra RPC URL (e.g., "http://127.0.0.1:8232"), used for
    /// `getblocktemplate` and, unless `submit_url` is set, `submitblock`.
    pub zebra_url: String,
    /// Optional separate endpoint for `submitblock` only. Point this at the
    /// `sovright-p2p-ingress` submitblock relay gateway to fan solved blocks
    /// into the relay mesh; `getblocktemplate` still uses `zebra_url`. When
    /// `None`, `submitblock` goes to `zebra_url`.
    pub submit_url: Option<String>,
    /// Poll interval in milliseconds
    pub poll_interval_ms: u64,
}

impl Default for TemplateProviderConfig {
    fn default() -> Self {
        Self {
            zebra_url: "http://127.0.0.1:8232".to_string(),
            submit_url: None,
            poll_interval_ms: 1000,
        }
    }
}

/// Template Provider that interfaces with Zebra and pushes templates to subscribers
pub struct TemplateProvider {
    config: TemplateProviderConfig,
    rpc: Box<dyn RpcProvider>,
    /// Separate client for `submitblock` when `config.submit_url` is set;
    /// `None` means `submitblock` shares `rpc` (the template endpoint).
    submit_rpc: Option<Box<dyn RpcProvider>>,
    template_id: AtomicU64,
    consensus_branch_cache: Mutex<Option<(u64, u32)>>,
    current_template: Arc<RwLock<Option<BlockTemplate>>>,
    sender: broadcast::Sender<BlockTemplate>,
}

impl TemplateProvider {
    /// Create a new Template Provider
    pub fn new(config: TemplateProviderConfig) -> Result<Self> {
        let rpc = ZebraRpc::new(&config.zebra_url, None, None)?;
        let submit_rpc = match &config.submit_url {
            Some(url) if url != &config.zebra_url => {
                info!("submitblock routed to separate endpoint {url}");
                Some(Box::new(ZebraRpc::new(url, None, None)?) as Box<dyn RpcProvider>)
            }
            _ => None,
        };
        let (sender, _) = broadcast::channel(16);

        Ok(Self {
            config,
            rpc: Box::new(rpc),
            submit_rpc,
            template_id: AtomicU64::new(1),
            consensus_branch_cache: Mutex::new(None),
            current_template: Arc::new(RwLock::new(None)),
            sender,
        })
    }

    /// Create with a custom RPC provider (for testing)
    pub fn with_rpc(config: TemplateProviderConfig, rpc: Box<dyn RpcProvider>) -> Self {
        Self::with_rpcs(config, rpc, None)
    }

    /// Create with custom template and (optional) submit RPC providers (testing).
    pub fn with_rpcs(
        config: TemplateProviderConfig,
        rpc: Box<dyn RpcProvider>,
        submit_rpc: Option<Box<dyn RpcProvider>>,
    ) -> Self {
        let (sender, _) = broadcast::channel(16);
        Self {
            config,
            rpc,
            submit_rpc,
            template_id: AtomicU64::new(1),
            consensus_branch_cache: Mutex::new(None),
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
        let consensus_branch_id = self.consensus_branch_id_for_height(response.height).await?;
        self.process_template(response, consensus_branch_id)
    }

    /// Submit a solved block. Uses the dedicated submit endpoint (relay gateway)
    /// when configured, otherwise the template endpoint.
    pub async fn submit_block(
        &self,
        block_hex: &str,
        mode: Option<rpc::SubmitMode>,
    ) -> Result<rpc::SubmitBlockResult> {
        let rpc = self.submit_rpc.as_ref().unwrap_or(&self.rpc);
        rpc.submit_block(block_hex, mode).await
    }

    /// Process a getblocktemplate response into a BlockTemplate
    async fn consensus_branch_id_for_height(&self, height: u64) -> Result<u32> {
        if let Some((cached_height, branch_id)) = *self.consensus_branch_cache.lock().unwrap()
            && cached_height == height
        {
            return Ok(branch_id);
        }

        let info = self.rpc.get_blockchain_info().await?;
        let branch_id = info.next_block_branch_id().map_err(|e| {
            Error::InvalidTemplate(format!(
                "invalid getblockchaininfo consensus.nextblock branch id: {}",
                e
            ))
        })?;

        *self.consensus_branch_cache.lock().unwrap() = Some((height, branch_id));
        Ok(branch_id)
    }

    fn process_template(
        &self,
        response: GetBlockTemplateResponse,
        consensus_branch_id: u32,
    ) -> Result<BlockTemplate> {
        let header = assemble_header(&response)?;
        let target = parse_target(&response.target)?;
        let chain_history_root =
            Hash256::from_hex_le(&response.default_roots.chain_history_root)
                .map_err(|e| Error::InvalidTemplate(format!("invalid chainhistoryroot: {}", e)))?;

        let total_fees: i64 = response.transactions.iter().map(|tx| tx.fee).sum();

        // Parse coinbase transaction - reject if missing or empty
        let coinbase = if let Some(data) = response.coinbase_txn.get("data") {
            if let Some(hex_str) = data.as_str() {
                let cb = hex::decode(hex_str)
                    .map_err(|e| Error::InvalidTemplate(format!("invalid coinbase hex: {}", e)))?;
                if cb.is_empty() {
                    return Err(Error::InvalidTemplate(
                        "coinbase transaction is empty".into(),
                    ));
                }
                cb
            } else {
                return Err(Error::InvalidTemplate(
                    "coinbase data field is not a string".into(),
                ));
            }
        } else {
            return Err(Error::InvalidTemplate(
                "coinbase_txn missing data field".into(),
            ));
        };

        Ok(BlockTemplate {
            template_id: self.template_id.fetch_add(1, Ordering::SeqCst),
            height: response.height,
            header,
            target,
            transactions: response.transactions,
            coinbase,
            chain_history_root,
            consensus_branch_id,
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
                        let consensus_branch_id =
                            match self.consensus_branch_id_for_height(response.height).await {
                                Ok(branch_id) => branch_id,
                                Err(e) => {
                                    error!("Failed to fetch consensus branch id: {}", e);
                                    continue;
                                }
                            };

                        match self.process_template(response, consensus_branch_id) {
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
    use crate::testutil::{MockZebraRpc, TestTemplateFactory};
    use crate::types::Hash256;

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

    #[tokio::test]
    async fn submit_block_uses_separate_submit_endpoint_when_configured() {
        use std::sync::Arc;
        let template_rpc = Arc::new(MockZebraRpc::new());
        let submit_rpc = Arc::new(MockZebraRpc::new());

        let provider = TemplateProvider::with_rpcs(
            TemplateProviderConfig::default(),
            Box::new(template_rpc.clone()),
            Some(Box::new(submit_rpc.clone())),
        );

        provider.submit_block("deadbeef", None).await.unwrap();

        assert_eq!(
            submit_rpc.submitted_blocks(),
            vec!["deadbeef".to_string()],
            "submitblock must go to the configured submit endpoint (the gateway)"
        );
        assert!(
            template_rpc.submitted_blocks().is_empty(),
            "the template endpoint must not receive submitblock"
        );
    }

    #[tokio::test]
    async fn submit_block_falls_back_to_template_endpoint_when_unset() {
        use std::sync::Arc;
        let template_rpc = Arc::new(MockZebraRpc::new());

        let provider = TemplateProvider::with_rpcs(
            TemplateProviderConfig::default(),
            Box::new(template_rpc.clone()),
            None,
        );

        provider.submit_block("cafe", None).await.unwrap();

        assert_eq!(
            template_rpc.submitted_blocks(),
            vec!["cafe".to_string()],
            "with no submit endpoint configured, submitblock uses the template endpoint"
        );
    }

    #[tokio::test]
    async fn fetch_template_threads_chain_history_root_and_branch_id() {
        let chain_history_root = "daea4adddaea4adddaea4adddaea4adddaea4adddaea4adddaea4adddaea4add";
        let rpc = MockZebraRpc::new();
        rpc.enqueue_template(
            TestTemplateFactory::new()
                .chain_history_root(chain_history_root)
                .height(2_000_000)
                .build(),
        );
        rpc.enqueue_blockchain_info("c8e71055");

        let provider = TemplateProvider::with_rpc(TemplateProviderConfig::default(), Box::new(rpc));
        let template = provider.fetch_template().await.unwrap();

        assert_eq!(
            template.chain_history_root,
            Hash256::from_hex_le(chain_history_root).unwrap()
        );
        assert_eq!(template.consensus_branch_id, 0xc8e7_1055);
    }
}
