//! JD Client implementation
//!
//! The JD Client connects to a pool's JD Server to declare custom mining jobs.
//! It fetches block templates from a local Zebra node via the Template Provider,
//! constructs custom coinbase transactions, and declares jobs to the pool.

use crate::block_submitter::BlockSubmitter;
use crate::config::JdClientConfig;
use crate::error::{JdClientError, Result};
use crate::full_template::FullTemplateBuilder;
use crate::template_builder::TemplateBuilder;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zcash_jd_server::codec::*;
use zcash_jd_server::messages::*;
use zcash_mining_protocol::codec::MessageFrame;
use sovright_noise::{NoiseInitiator, NoiseStream, PublicKey};
use zcash_template_provider::types::{BlockTemplate, Hash256};
use zcash_template_provider::{TemplateProvider, TemplateProviderConfig};

enum JdClientTransport {
    Plain(TcpStream),
    Noise(NoiseStream<TcpStream>),
}

impl JdClientTransport {
    async fn read_full_message(&mut self) -> Result<Option<Vec<u8>>> {
        match self {
            JdClientTransport::Plain(stream) => {
                let mut header_buf = [0u8; MessageFrame::HEADER_SIZE];
                match stream.read_exact(&mut header_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(e) => return Err(JdClientError::Io(e)),
                }

                let frame = MessageFrame::decode(&header_buf)
                    .map_err(|e| JdClientError::Protocol(e.to_string()))?;

                const MAX_FRAME_SIZE: usize = 1_048_576;
                if frame.length as usize > MAX_FRAME_SIZE {
                    return Err(JdClientError::Protocol(format!(
                        "frame too large: {} bytes (max {})",
                        frame.length, MAX_FRAME_SIZE
                    )));
                }

                let mut payload = vec![0u8; frame.length as usize];
                if frame.length > 0 {
                    stream.read_exact(&mut payload).await?;
                }

                let mut full_message = header_buf.to_vec();
                full_message.extend(payload);
                Ok(Some(full_message))
            }
            JdClientTransport::Noise(stream) => match stream.read_message().await {
                Ok(message) => {
                    const MAX_FRAME_SIZE: usize = 1_048_576;
                    if message.len() > MAX_FRAME_SIZE {
                        return Err(JdClientError::Protocol(format!(
                            "frame too large: {} bytes (max {})",
                            message.len(), MAX_FRAME_SIZE
                        )));
                    }
                    Ok(Some(message))
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                Err(e) => Err(JdClientError::Io(e)),
            },
        }
    }

    async fn write_full_message(&mut self, data: &[u8]) -> Result<()> {
        match self {
            JdClientTransport::Plain(stream) => {
                stream.write_all(data).await?;
                stream.flush().await?;
                Ok(())
            }
            JdClientTransport::Noise(stream) => {
                stream.write_message(data).await?;
                stream.flush().await?;
                Ok(())
            }
        }
    }
}

/// JD Client for declaring custom mining jobs to a pool
pub struct JdClient {
    /// Client configuration
    config: JdClientConfig,
    /// Template provider for fetching blocks from Zebra
    template_provider: Arc<TemplateProvider>,
    /// Template builder for constructing custom coinbase
    template_builder: Arc<RwLock<TemplateBuilder>>,
    /// Full template builder for Full-Template mode (optional)
    full_template_builder: Option<FullTemplateBuilder>,
    /// Block submitter for submitting found blocks to Zebra
    #[allow(dead_code)]
    block_submitter: BlockSubmitter,
    /// Current mining job token from the pool
    current_token: Arc<RwLock<Option<Vec<u8>>>>,
    /// Current job ID assigned by the pool
    current_job_id: Arc<RwLock<Option<u32>>>,
    /// Mode granted by the pool (may differ from requested)
    granted_mode: Arc<RwLock<JobDeclarationMode>>,
    /// Transaction data cache for Full-Template mode (txid -> raw tx)
    tx_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl JdClient {
    /// Create a new JD Client
    pub fn new(config: JdClientConfig) -> Result<Self> {
        let template_config = TemplateProviderConfig {
            zebra_url: config.zebra_url.clone(),
            poll_interval_ms: config.template_poll_ms,
        };

        let template_provider = TemplateProvider::new(template_config)?;

        // Create full template builder if in Full-Template mode
        let full_template_builder = if config.full_template_mode {
            Some(FullTemplateBuilder::new(config.tx_selection))
        } else {
            None
        };

        Ok(Self {
            template_builder: Arc::new(RwLock::new(TemplateBuilder::new(
                vec![],
                0,
                config.miner_payout_address.clone(),
            ))),
            full_template_builder,
            block_submitter: BlockSubmitter::new(config.zebra_url.clone()),
            config,
            template_provider: Arc::new(template_provider),
            current_token: Arc::new(RwLock::new(None)),
            current_job_id: Arc::new(RwLock::new(None)),
            granted_mode: Arc::new(RwLock::new(JobDeclarationMode::CoinbaseOnly)),
            tx_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if the client is operating in Full-Template mode
    pub fn is_full_template_mode(&self) -> bool {
        self.full_template_builder.is_some()
    }

    /// Get a reference to the full template builder (if in Full-Template mode)
    pub fn full_template_builder(&self) -> Option<&FullTemplateBuilder> {
        self.full_template_builder.as_ref()
    }

    /// Run the JD Client
    ///
    /// This connects to the pool's JD Server, allocates a mining job token,
    /// and then continuously declares jobs as new templates arrive from Zebra.
    pub async fn run(self) -> Result<()> {
        info!("Starting JD Client");

        // Connect to pool JD Server
        let mut transport = if self.config.noise_enabled {
            let public_key = PublicKey::from_hex(
                self.config
                    .pool_public_key
                    .as_ref()
                    .ok_or_else(|| JdClientError::Protocol("Missing pool public key".into()))?,
            )
            .map_err(|e| JdClientError::Protocol(e.to_string()))?;

            let tcp_stream = TcpStream::connect(&self.config.pool_jd_addr)
                .await
                .map_err(|e| JdClientError::ConnectionFailed(e.to_string()))?;
            let initiator = NoiseInitiator::new(public_key);
            let noise_stream = initiator
                .connect(tcp_stream)
                .await
                .map_err(|e| JdClientError::Protocol(e.to_string()))?;
            JdClientTransport::Noise(noise_stream)
        } else {
            let tcp_stream = TcpStream::connect(self.config.pool_jd_addr)
                .await
                .map_err(|e| JdClientError::ConnectionFailed(e.to_string()))?;
            JdClientTransport::Plain(tcp_stream)
        };

        info!(
            "Connected to pool JD Server at {}",
            self.config.pool_jd_addr
        );

        // Allocate initial token
        self.allocate_token(&mut transport).await?;

        // Subscribe to template updates
        let mut template_rx = self.template_provider.subscribe();

        // Spawn template provider
        let provider = self.template_provider.clone();
        tokio::spawn(async move {
            if let Err(e) = provider.run().await {
                error!("Template provider error: {}", e);
            }
        });

        info!("JD Client running");

        // Main loop - handle template updates
        loop {
            tokio::select! {
                template_result = template_rx.recv() => {
                    match template_result {
                        Ok(template) => {
                            if let Err(e) = self.handle_new_template(&mut transport, template).await {
                                error!("Template handling error: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Template channel error: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Allocate a mining job token from the pool
    async fn allocate_token(&self, transport: &mut JdClientTransport) -> Result<()> {
        let request = AllocateMiningJobToken {
            request_id: 1,
            user_identifier: self.config.user_identifier.clone(),
            requested_mode: if self.config.full_template_mode {
                JobDeclarationMode::FullTemplate
            } else {
                JobDeclarationMode::CoinbaseOnly
            },
        };

        let encoded = encode_allocate_token(&request)?;
        transport.write_full_message(&encoded).await?;
        debug!("Sent AllocateMiningJobToken request");

        let full_message = transport
            .read_full_message()
            .await?
            .ok_or_else(|| JdClientError::Protocol("JD server disconnected".to_string()))?;
        let frame = MessageFrame::decode(&full_message)
            .map_err(|e| JdClientError::Protocol(e.to_string()))?;

        if frame.msg_type != message_types::ALLOCATE_MINING_JOB_TOKEN_SUCCESS {
            return Err(JdClientError::TokenAllocationFailed(format!(
                "Unexpected response type: 0x{:02x}",
                frame.msg_type
            )));
        }

        let response = decode_allocate_token_success(&full_message)?;

        info!(
            "Token allocated: {} bytes, coinbase output: {} bytes (granted mode: {})",
            response.mining_job_token.len(),
            response.coinbase_output.len(),
            response.granted_mode
        );

        // Update granted mode
        {
            let mut mode = self.granted_mode.write().await;
            *mode = response.granted_mode;
        }

        if self.config.full_template_mode && response.granted_mode != JobDeclarationMode::FullTemplate {
            warn!(
                "Full-Template mode requested but not granted; falling back to {}",
                response.granted_mode
            );
        }

        // Update template builder with pool requirements
        {
            let mut builder = self.template_builder.write().await;
            builder.set_pool_output(
                response.coinbase_output.clone(),
                response.coinbase_output_max_additional_size,
            );
        }

        // Store token
        {
            let mut token = self.current_token.write().await;
            *token = Some(response.mining_job_token);
        }

        Ok(())
    }

    /// Handle a new template from Zebra
    async fn handle_new_template(
        &self,
        transport: &mut JdClientTransport,
        template: BlockTemplate,
    ) -> Result<()> {
        let token = {
            let guard = self.current_token.read().await;
            guard
                .clone()
                .ok_or_else(|| JdClientError::Protocol("No token allocated".to_string()))?
        };

        let granted_mode = *self.granted_mode.read().await;
        match granted_mode {
            JobDeclarationMode::FullTemplate => {
                self.handle_full_template_job(transport, template, token).await
            }
            _ => self.handle_coinbase_only_job(transport, template, token).await,
        }
    }

    async fn handle_coinbase_only_job(
        &self,
        transport: &mut JdClientTransport,
        template: BlockTemplate,
        token: Vec<u8>,
    ) -> Result<()> {
        let builder = self.template_builder.read().await;

        let coinbase = builder.build_coinbase(&template)?;
        let merkle_root = builder.calculate_merkle_root(&template, &coinbase)?;
        let block_commitments = builder.block_commitments(&template);

        debug!(
            "Declaring Coinbase-Only job for height {} with {} byte coinbase",
            template.height,
            coinbase.len()
        );

        let request = SetCustomMiningJob {
            channel_id: 1,
            request_id: template.height as u32,
            mining_job_token: token,
            version: template.header.version,
            prev_hash: template.header.prev_hash.0,
            merkle_root,
            block_commitments,
            coinbase_tx: coinbase,
            time: template.header.time,
            bits: template.header.bits,
        };

        let encoded = encode_set_custom_job(&request)?;
        transport.write_full_message(&encoded).await?;

        let full_message = transport
            .read_full_message()
            .await?
            .ok_or_else(|| JdClientError::Protocol("JD server disconnected".to_string()))?;
        let frame = MessageFrame::decode(&full_message)
            .map_err(|e| JdClientError::Protocol(e.to_string()))?;

        match frame.msg_type {
            message_types::SET_CUSTOM_MINING_JOB_SUCCESS => {
                let response = decode_set_custom_job_success(&full_message)?;
                info!(
                    "Job declared: job_id={}, height={}",
                    response.job_id, template.height
                );

                let mut job_id = self.current_job_id.write().await;
                *job_id = Some(response.job_id);
            }
            message_types::SET_CUSTOM_MINING_JOB_ERROR => {
                let error = decode_set_custom_job_error(&full_message)?;
                warn!(
                    "Job rejected: {:?} - {}",
                    error.error_code, error.error_message
                );

                if error.error_code == SetCustomMiningJobErrorCode::TokenExpired {
                    info!("Token expired, requesting new token");
                    self.allocate_token(transport).await?;
                }

                return Err(JdClientError::JobRejected(error.error_message));
            }
            _ => {
                return Err(JdClientError::Protocol(format!(
                    "Unexpected message type: 0x{:02x}",
                    frame.msg_type
                )));
            }
        }

        Ok(())
    }

    async fn handle_full_template_job(
        &self,
        transport: &mut JdClientTransport,
        template: BlockTemplate,
        token: Vec<u8>,
    ) -> Result<()> {
        let builder = self.template_builder.read().await;
        let full_builder = self.full_template_builder.as_ref().ok_or_else(|| {
            JdClientError::Protocol("Full-Template mode enabled but builder missing".to_string())
        })?;

        let coinbase = builder.build_coinbase(&template)?;
        let merkle_root = builder.calculate_merkle_root(&template, &coinbase)?;
        let block_commitments = builder.block_commitments(&template);

        let transactions = self.extract_template_transactions(&template)?;
        self.cache_transactions(transactions.clone()).await;

        debug!(
            "Declaring Full-Template job for height {} with {} transactions",
            template.height,
            transactions.len()
        );

        let request = full_builder.build_job(
            1,
            template.height as u32,
            token.clone(),
            template.header.version,
            template.header.prev_hash.0,
            merkle_root,
            block_commitments,
            coinbase,
            template.header.time,
            template.header.bits,
            transactions,
        )?;

        let mut attempt = 0;
        loop {
            attempt += 1;
            let encoded = encode_set_full_template_job(&request)?;
            transport.write_full_message(&encoded).await?;

            let full_message = transport
                .read_full_message()
                .await?
                .ok_or_else(|| JdClientError::Protocol("JD server disconnected".to_string()))?;
            let frame = MessageFrame::decode(&full_message)
                .map_err(|e| JdClientError::Protocol(e.to_string()))?;

            match frame.msg_type {
                message_types::SET_FULL_TEMPLATE_JOB_SUCCESS => {
                    let response = decode_set_full_template_job_success(&full_message)?;
                    info!(
                        "Full-Template job declared: job_id={}, height={}",
                        response.job_id, template.height
                    );
                    let mut job_id = self.current_job_id.write().await;
                    *job_id = Some(response.job_id);
                    return Ok(());
                }
                message_types::SET_FULL_TEMPLATE_JOB_ERROR => {
                    let error = decode_set_full_template_job_error(&full_message)?;
                    warn!(
                        "Full-Template job rejected: {:?} - {}",
                        error.error_code, error.error_message
                    );

                    if error.error_code == SetFullTemplateJobErrorCode::TokenExpired {
                        info!("Token expired, requesting new token");
                        self.allocate_token(transport).await?;
                    }

                    return Err(JdClientError::JobRejected(error.error_message));
                }
                message_types::GET_MISSING_TRANSACTIONS => {
                    if attempt > 1 {
                        return Err(JdClientError::Protocol(
                            "Server requested missing transactions multiple times".to_string(),
                        ));
                    }

                    let request = decode_get_missing_transactions(&full_message)?;
                    let response = self.handle_get_missing_transactions(request).await;
                    let encoded = encode_provide_missing_transactions(&response)?;
                    transport.write_full_message(&encoded).await?;
                    // Re-submit the job after providing transactions.
                    continue;
                }
                _ => {
                    return Err(JdClientError::Protocol(format!(
                        "Unexpected message type: 0x{:02x}",
                        frame.msg_type
                    )));
                }
            }
        }
    }

    fn extract_template_transactions(
        &self,
        template: &BlockTemplate,
    ) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        let mut transactions = Vec::with_capacity(template.transactions.len());
        for tx in &template.transactions {
            let txid = Hash256::from_hex(&tx.hash)
                .map_err(|e| JdClientError::Protocol(format!("invalid tx hash: {}", e)))?;
            let data = hex::decode(&tx.data)
                .map_err(|e| JdClientError::Protocol(format!("invalid tx data: {}", e)))?;
            transactions.push((txid.0, data));
        }
        Ok(transactions)
    }

    /// Get the current job ID
    pub async fn current_job_id(&self) -> Option<u32> {
        *self.current_job_id.read().await
    }

    /// Get the current template from the provider
    pub async fn current_template(&self) -> Option<BlockTemplate> {
        self.template_provider.get_current_template().await
    }

    /// Maximum number of transactions to cache
    const MAX_TX_CACHE_ENTRIES: usize = 10_000;
    /// Maximum total bytes in transaction cache (100MB)
    const MAX_TX_CACHE_BYTES: usize = 100_000_000;

    /// Add a transaction to the cache for Full-Template mode
    ///
    /// The cache stores raw transaction data keyed by txid, allowing the client
    /// to respond to GetMissingTransactions requests from the server.
    /// Cache is automatically pruned when limits are exceeded.
    pub async fn cache_transaction(&self, txid: [u8; 32], data: Vec<u8>) {
        let mut cache = self.tx_cache.write().await;

        // Check if we need to prune the cache
        if cache.len() >= Self::MAX_TX_CACHE_ENTRIES {
            tracing::warn!("Transaction cache entry limit reached, evicting oldest half");
            let to_remove: Vec<_> = cache.keys().take(cache.len() / 2).cloned().collect();
            for key in to_remove {
                cache.remove(&key);
            }
        }

        // Check total byte size
        let total_bytes: usize = cache.values().map(|v| v.len()).sum();
        if total_bytes + data.len() > Self::MAX_TX_CACHE_BYTES {
            tracing::warn!("Transaction cache byte limit reached, evicting oldest half");
            let to_remove: Vec<_> = cache.keys().take(cache.len() / 2).cloned().collect();
            for key in to_remove {
                cache.remove(&key);
            }
        }

        cache.insert(txid, data);
    }

    /// Add multiple transactions to the cache
    /// Cache is automatically pruned when limits are exceeded.
    pub async fn cache_transactions(&self, transactions: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>) {
        let mut cache = self.tx_cache.write().await;
        let mut total_bytes: usize = cache.values().map(|v| v.len()).sum();

        for (txid, data) in transactions {
            // Check entry count limit before each insert
            if cache.len() >= Self::MAX_TX_CACHE_ENTRIES {
                tracing::warn!("Transaction cache entry limit reached, evicting oldest half");
                let to_remove: Vec<_> = cache.keys().take(cache.len() / 2).cloned().collect();
                for key in &to_remove {
                    if let Some(removed) = cache.remove(key) {
                        total_bytes = total_bytes.saturating_sub(removed.len());
                    }
                }
            }

            // Check byte size limit before each insert
            if total_bytes + data.len() > Self::MAX_TX_CACHE_BYTES {
                tracing::warn!("Transaction cache byte limit reached, evicting oldest half");
                let to_remove: Vec<_> = cache.keys().take(cache.len() / 2).cloned().collect();
                for key in &to_remove {
                    if let Some(removed) = cache.remove(key) {
                        total_bytes = total_bytes.saturating_sub(removed.len());
                    }
                }
            }

            total_bytes += data.len();
            cache.insert(txid, data);
        }
    }

    /// Get a transaction from the cache
    pub async fn get_cached_transaction(&self, txid: &[u8; 32]) -> Option<Vec<u8>> {
        let cache = self.tx_cache.read().await;
        cache.get(txid).cloned()
    }

    /// Clear the transaction cache
    pub async fn clear_tx_cache(&self) {
        let mut cache = self.tx_cache.write().await;
        cache.clear();
    }

    /// Get the number of cached transactions
    pub async fn tx_cache_size(&self) -> usize {
        let cache = self.tx_cache.read().await;
        cache.len()
    }

    /// Handle GetMissingTransactions request from the server
    ///
    /// This method looks up the requested transaction IDs in the local cache
    /// and returns a ProvideMissingTransactions response with the available data.
    pub async fn handle_get_missing_transactions(
        &self,
        msg: GetMissingTransactions,
    ) -> ProvideMissingTransactions {
        let cache = self.tx_cache.read().await;

        let transactions: Vec<Vec<u8>> = msg
            .missing_tx_ids
            .iter()
            .filter_map(|txid| cache.get(txid).cloned())
            .collect();

        debug!(
            "Responding to GetMissingTransactions: requested {} txids, found {} in cache",
            msg.missing_tx_ids.len(),
            transactions.len()
        );

        ProvideMissingTransactions {
            channel_id: msg.channel_id,
            request_id: msg.request_id,
            transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TxSelectionStrategy;

    #[test]
    fn test_jd_client_config() {
        let config = JdClientConfig::default();
        assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
        assert_eq!(config.user_identifier, "zcash-jd-client");
    }

    #[test]
    fn test_jd_client_creation() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_jd_client_initial_state() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Initially no job ID
        assert!(client.current_job_id().await.is_none());

        // Initially no template
        assert!(client.current_template().await.is_none());
    }

    #[test]
    fn test_jd_client_coinbase_only_mode() {
        let config = JdClientConfig {
            full_template_mode: false,
            ..Default::default()
        };
        let client = JdClient::new(config).unwrap();

        // Should not have full template builder
        assert!(!client.is_full_template_mode());
        assert!(client.full_template_builder().is_none());
    }

    #[test]
    fn test_jd_client_full_template_mode() {
        let config = JdClientConfig {
            full_template_mode: true,
            tx_selection: TxSelectionStrategy::All,
            ..Default::default()
        };
        let client = JdClient::new(config).unwrap();

        // Should have full template builder
        assert!(client.is_full_template_mode());
        assert!(client.full_template_builder().is_some());

        let builder = client.full_template_builder().unwrap();
        assert_eq!(builder.strategy(), TxSelectionStrategy::All);
    }

    #[test]
    fn test_jd_client_full_template_mode_by_fee_rate() {
        let config = JdClientConfig {
            full_template_mode: true,
            tx_selection: TxSelectionStrategy::ByFeeRate,
            ..Default::default()
        };
        let client = JdClient::new(config).unwrap();

        assert!(client.is_full_template_mode());
        let builder = client.full_template_builder().unwrap();
        assert_eq!(builder.strategy(), TxSelectionStrategy::ByFeeRate);
    }

    // =========================================================================
    // Transaction Cache Tests
    // =========================================================================

    #[tokio::test]
    async fn test_tx_cache_basic_operations() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Cache should start empty
        assert_eq!(client.tx_cache_size().await, 0);

        // Add a transaction
        let txid = [0x11; 32];
        let tx_data = vec![0x01, 0x00, 0x00, 0x00];
        client.cache_transaction(txid, tx_data.clone()).await;

        // Should be cached
        assert_eq!(client.tx_cache_size().await, 1);
        let cached = client.get_cached_transaction(&txid).await;
        assert_eq!(cached, Some(tx_data));

        // Unknown txid should return None
        let unknown_txid = [0x22; 32];
        assert!(client.get_cached_transaction(&unknown_txid).await.is_none());
    }

    #[tokio::test]
    async fn test_tx_cache_multiple_transactions() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Add multiple transactions at once
        let transactions = vec![
            ([0x11; 32], vec![0x01, 0x00]),
            ([0x22; 32], vec![0x02, 0x00]),
            ([0x33; 32], vec![0x03, 0x00]),
        ];
        client.cache_transactions(transactions.clone()).await;

        assert_eq!(client.tx_cache_size().await, 3);
        for (txid, data) in transactions {
            assert_eq!(client.get_cached_transaction(&txid).await, Some(data));
        }
    }

    #[tokio::test]
    async fn test_tx_cache_clear() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Add some transactions
        client.cache_transaction([0x11; 32], vec![0x01]).await;
        client.cache_transaction([0x22; 32], vec![0x02]).await;
        assert_eq!(client.tx_cache_size().await, 2);

        // Clear the cache
        client.clear_tx_cache().await;
        assert_eq!(client.tx_cache_size().await, 0);
    }

    #[tokio::test]
    async fn test_tx_cache_overwrite() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        let txid = [0x11; 32];
        client.cache_transaction(txid, vec![0x01, 0x00]).await;
        client.cache_transaction(txid, vec![0x02, 0x00]).await;

        // Should have overwritten with new data
        assert_eq!(client.tx_cache_size().await, 1);
        assert_eq!(
            client.get_cached_transaction(&txid).await,
            Some(vec![0x02, 0x00])
        );
    }

    // =========================================================================
    // GetMissingTransactions Handler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_get_missing_transactions_all_found() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Pre-cache some transactions
        let txid1 = [0x11; 32];
        let txid2 = [0x22; 32];
        let tx_data1 = vec![0x01, 0x00, 0x00, 0x00];
        let tx_data2 = vec![0x02, 0x00, 0x00, 0x00];
        client.cache_transaction(txid1, tx_data1.clone()).await;
        client.cache_transaction(txid2, tx_data2.clone()).await;

        // Request both transactions
        let request = GetMissingTransactions {
            channel_id: 1,
            request_id: 42,
            missing_tx_ids: vec![txid1, txid2],
        };

        let response = client.handle_get_missing_transactions(request).await;

        assert_eq!(response.channel_id, 1);
        assert_eq!(response.request_id, 42);
        assert_eq!(response.transactions.len(), 2);
        assert!(response.transactions.contains(&tx_data1));
        assert!(response.transactions.contains(&tx_data2));
    }

    #[tokio::test]
    async fn test_handle_get_missing_transactions_partial_found() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Only cache one transaction
        let txid1 = [0x11; 32];
        let txid2 = [0x22; 32];
        let tx_data1 = vec![0x01, 0x00, 0x00, 0x00];
        client.cache_transaction(txid1, tx_data1.clone()).await;

        // Request both transactions (one missing)
        let request = GetMissingTransactions {
            channel_id: 1,
            request_id: 42,
            missing_tx_ids: vec![txid1, txid2],
        };

        let response = client.handle_get_missing_transactions(request).await;

        assert_eq!(response.channel_id, 1);
        assert_eq!(response.request_id, 42);
        // Only one transaction found
        assert_eq!(response.transactions.len(), 1);
        assert_eq!(response.transactions[0], tx_data1);
    }

    #[tokio::test]
    async fn test_handle_get_missing_transactions_none_found() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Don't cache anything

        // Request transactions
        let request = GetMissingTransactions {
            channel_id: 1,
            request_id: 42,
            missing_tx_ids: vec![[0x11; 32], [0x22; 32]],
        };

        let response = client.handle_get_missing_transactions(request).await;

        assert_eq!(response.channel_id, 1);
        assert_eq!(response.request_id, 42);
        // No transactions found
        assert_eq!(response.transactions.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_get_missing_transactions_empty_request() {
        let config = JdClientConfig::default();
        let client = JdClient::new(config).unwrap();

        // Empty request
        let request = GetMissingTransactions {
            channel_id: 1,
            request_id: 42,
            missing_tx_ids: vec![],
        };

        let response = client.handle_get_missing_transactions(request).await;

        assert_eq!(response.channel_id, 1);
        assert_eq!(response.request_id, 42);
        assert_eq!(response.transactions.len(), 0);
    }
}
