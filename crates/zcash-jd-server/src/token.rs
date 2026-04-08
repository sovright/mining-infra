//! Mining job token allocation and tracking

use crate::config::JdServerConfig;
use crate::error::{JdServerError, Result};
use crate::messages::JobDeclarationMode;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A mining job token
#[derive(Debug, Clone)]
pub struct MiningJobToken {
    /// Unique token bytes
    pub token: Vec<u8>,
    /// When the token was issued
    pub issued_at: Instant,
    /// Token lifetime
    pub lifetime: Duration,
    /// Client identifier
    pub client_id: String,
    /// Granted job declaration mode for this token
    pub granted_mode: JobDeclarationMode,
    /// Associated job info (set when job declared)
    pub job_info: Option<DeclaredJobInfo>,
}

/// Information about a declared job
#[derive(Debug, Clone)]
pub struct DeclaredJobInfo {
    /// Pool-assigned job ID
    pub job_id: u32,
    /// Declaring client identifier
    pub client_id: String,
    /// Declared mode
    pub mode: JobDeclarationMode,
    /// Channel ID associated with the job
    pub channel_id: u32,
    /// Block version
    pub version: u32,
    /// Previous block hash
    pub prev_hash: [u8; 32],
    /// Merkle root
    pub merkle_root: [u8; 32],
    /// Block commitments
    pub block_commitments: [u8; 32],
    /// Compact target bits
    pub bits: u32,
    /// Declared template time
    pub time: u32,
    /// Coinbase transaction
    pub coinbase_tx: Vec<u8>,
}

impl MiningJobToken {
    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        self.issued_at.elapsed() > self.lifetime
    }
}

/// Token allocation manager
pub struct TokenManager {
    /// Configuration
    config: JdServerConfig,
    /// Active tokens (token bytes -> token info)
    tokens: RwLock<HashMap<Vec<u8>, MiningJobToken>>,
    /// Counter for generating unique tokens
    token_counter: AtomicU64,
}

impl TokenManager {
    pub fn new(config: JdServerConfig) -> Self {
        Self {
            config,
            tokens: RwLock::new(HashMap::new()),
            token_counter: AtomicU64::new(1),
        }
    }

    /// Allocate a new token for a client with CoinbaseOnly mode (default)
    pub fn allocate_token(&self, client_id: &str) -> Result<MiningJobToken> {
        self.allocate_token_with_mode(client_id, JobDeclarationMode::CoinbaseOnly)
    }

    /// Maximum total tokens across all clients to prevent memory exhaustion
    const MAX_TOTAL_TOKENS: usize = 100_000;

    /// Allocate a new token for a client with a specific mode
    pub fn allocate_token_with_mode(
        &self,
        client_id: &str,
        granted_mode: JobDeclarationMode,
    ) -> Result<MiningJobToken> {
        // Cleanup expired tokens first to free up capacity
        self.cleanup_expired();

        // Check rate limits
        {
            let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());

            // Check global limit to prevent memory exhaustion
            if tokens.len() >= Self::MAX_TOTAL_TOKENS {
                return Err(JdServerError::Protocol(
                    "Server at capacity: too many active tokens".to_string(),
                ));
            }

            // Check per-client limit
            let client_token_count = tokens
                .values()
                .filter(|t| t.client_id == client_id && !t.is_expired())
                .count();
            if client_token_count >= self.config.max_tokens_per_client {
                return Err(JdServerError::Protocol(format!(
                    "Max tokens per client exceeded ({})",
                    self.config.max_tokens_per_client
                )));
            }
        }

        let counter = self.token_counter.fetch_add(1, Ordering::SeqCst);

        // Generate token: 8 bytes counter + 16 bytes cryptographic randomness
        // This prevents token forgery even if counter/timestamp are guessed
        let mut token = Vec::with_capacity(24);
        token.extend_from_slice(&counter.to_le_bytes());
        let mut random_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        token.extend_from_slice(&random_bytes);

        let mining_token = MiningJobToken {
            token: token.clone(),
            issued_at: Instant::now(),
            lifetime: self.config.token_lifetime,
            client_id: client_id.to_string(),
            granted_mode,
            job_info: None,
        };

        // Store token (handle poisoned lock gracefully)
        {
            let mut tokens = self.tokens.write().unwrap_or_else(|e| e.into_inner());
            tokens.insert(token, mining_token.clone());
        }

        Ok(mining_token)
    }

    /// Validate a token and return its info
    pub fn validate_token(&self, token: &[u8]) -> Result<MiningJobToken> {
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        let mining_token = tokens.get(token).ok_or(JdServerError::InvalidToken)?;

        if mining_token.is_expired() {
            return Err(JdServerError::TokenExpired);
        }

        Ok(mining_token.clone())
    }

    /// Associate a declared job with a token
    pub fn set_job_info(&self, token: &[u8], job_info: DeclaredJobInfo) -> Result<()> {
        let mut tokens = self.tokens.write().unwrap_or_else(|e| e.into_inner());
        let mining_token = tokens.get_mut(token).ok_or(JdServerError::InvalidToken)?;

        if mining_token.is_expired() {
            return Err(JdServerError::TokenExpired);
        }

        mining_token.job_info = Some(job_info);
        Ok(())
    }

    /// Get job info for a token
    pub fn get_job_info(&self, token: &[u8]) -> Result<DeclaredJobInfo> {
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        let mining_token = tokens.get(token).ok_or(JdServerError::InvalidToken)?;

        mining_token
            .job_info
            .clone()
            .ok_or(JdServerError::Protocol("Job not declared".to_string()))
    }

    /// Look up a declared job by server-assigned job ID.
    pub fn find_job_by_id(&self, job_id: u32) -> Result<DeclaredJobInfo> {
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());

        tokens
            .values()
            .filter(|token| !token.is_expired())
            .filter_map(|token| token.job_info.as_ref())
            .find(|job| job.job_id == job_id)
            .cloned()
            .ok_or(JdServerError::Protocol(format!("unknown job id {}", job_id)))
    }

    /// Remove expired tokens
    fn cleanup_expired(&self) {
        let mut tokens = self.tokens.write().unwrap_or_else(|e| e.into_inner());
        tokens.retain(|_, t| !t.is_expired());
    }

    /// Get config values for token response
    pub fn coinbase_output_max_additional_size(&self) -> u32 {
        self.config.coinbase_output_max_additional_size
    }

    pub fn pool_payout_script(&self) -> &[u8] {
        &self.config.pool_payout_script
    }

    pub fn async_mining_allowed(&self) -> bool {
        self.config.async_mining_allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_allocation() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        let token = manager.allocate_token("miner-01").unwrap();
        assert!(!token.is_expired());
        assert_eq!(token.client_id, "miner-01");
        // 8 bytes counter + 16 bytes random = 24 bytes
        assert_eq!(token.token.len(), 24);
        // Default allocation should be CoinbaseOnly mode
        assert_eq!(token.granted_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[test]
    fn test_token_allocation_with_mode() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        // Test allocating with FullTemplate mode
        let token = manager
            .allocate_token_with_mode("miner-01", JobDeclarationMode::FullTemplate)
            .unwrap();
        assert!(!token.is_expired());
        assert_eq!(token.client_id, "miner-01");
        assert_eq!(token.granted_mode, JobDeclarationMode::FullTemplate);

        // Test allocating with CoinbaseOnly mode
        let token2 = manager
            .allocate_token_with_mode("miner-02", JobDeclarationMode::CoinbaseOnly)
            .unwrap();
        assert_eq!(token2.granted_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[test]
    fn test_token_validation() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        let token = manager.allocate_token("miner-01").unwrap();
        let validated = manager.validate_token(&token.token).unwrap();
        assert_eq!(validated.client_id, "miner-01");
        assert_eq!(validated.granted_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[test]
    fn test_token_validation_preserves_mode() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        let token = manager
            .allocate_token_with_mode("miner-01", JobDeclarationMode::FullTemplate)
            .unwrap();
        let validated = manager.validate_token(&token.token).unwrap();
        assert_eq!(validated.granted_mode, JobDeclarationMode::FullTemplate);
    }

    #[test]
    fn test_invalid_token() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        let result = manager.validate_token(&[0x00, 0x01, 0x02]);
        assert!(matches!(result, Err(JdServerError::InvalidToken)));
    }

    #[test]
    fn test_job_info() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        let token = manager.allocate_token("miner-01").unwrap();

        let job_info = DeclaredJobInfo {
            job_id: 42,
            client_id: "miner-01".to_string(),
            mode: JobDeclarationMode::CoinbaseOnly,
            channel_id: 7,
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            bits: 0x1d00ffff,
            time: 1_700_000_000,
            coinbase_tx: vec![0x01; 100],
        };

        manager.set_job_info(&token.token, job_info.clone()).unwrap();

        let retrieved = manager.get_job_info(&token.token).unwrap();
        assert_eq!(retrieved.job_id, 42);
    }

    #[test]
    fn test_token_rate_limiting() {
        let mut config = JdServerConfig::default();
        config.max_tokens_per_client = 3;
        let manager = TokenManager::new(config);

        // Should succeed: tokens 1, 2, 3
        manager.allocate_token("miner-01").unwrap();
        manager.allocate_token("miner-01").unwrap();
        manager.allocate_token("miner-01").unwrap();

        // Should fail: exceeds max_tokens_per_client
        let result = manager.allocate_token("miner-01");
        assert!(result.is_err());

        // Different client should still work
        manager.allocate_token("miner-02").unwrap();
    }

    #[test]
    fn test_token_uniqueness() {
        let config = JdServerConfig::default();
        let manager = TokenManager::new(config);

        // Allocate multiple tokens and verify they're all unique
        let token1 = manager.allocate_token("miner-01").unwrap();
        let token2 = manager.allocate_token("miner-01").unwrap();
        let token3 = manager.allocate_token("miner-02").unwrap();

        assert_ne!(token1.token, token2.token);
        assert_ne!(token2.token, token3.token);
        assert_ne!(token1.token, token3.token);
    }
}
