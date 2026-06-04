//! Job Declaration Protocol message types
//!
//! Message types for the JD protocol in Coinbase-Only mode:
//! - AllocateMiningJobToken: Client requests a token for job declaration
//! - AllocateMiningJobTokenSuccess: Server returns token and coinbase requirements
//! - SetCustomMiningJob: Client declares a custom mining job
//! - SetCustomMiningJobSuccess: Server confirms job acceptance
//! - SetCustomMiningJobError: Server rejects job with error code
//! - PushSolution: Client submits a block solution

#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

/// Message type identifiers for JD protocol (0x50-0x5F range)
pub mod message_types {
    /// AllocateMiningJobToken message type
    pub const ALLOCATE_MINING_JOB_TOKEN: u8 = 0x50;
    /// AllocateMiningJobTokenSuccess message type
    pub const ALLOCATE_MINING_JOB_TOKEN_SUCCESS: u8 = 0x51;
    /// SetCustomMiningJob message type
    pub const SET_CUSTOM_MINING_JOB: u8 = 0x52;
    /// SetCustomMiningJobSuccess message type
    pub const SET_CUSTOM_MINING_JOB_SUCCESS: u8 = 0x53;
    /// SetCustomMiningJobError message type
    pub const SET_CUSTOM_MINING_JOB_ERROR: u8 = 0x54;
    /// PushSolution message type
    pub const PUSH_SOLUTION: u8 = 0x55;
    /// SetFullTemplateJob message type
    pub const SET_FULL_TEMPLATE_JOB: u8 = 0x56;
    /// SetFullTemplateJobSuccess message type
    pub const SET_FULL_TEMPLATE_JOB_SUCCESS: u8 = 0x57;
    /// SetFullTemplateJobError message type
    pub const SET_FULL_TEMPLATE_JOB_ERROR: u8 = 0x58;
    /// GetMissingTransactions message type
    pub const GET_MISSING_TRANSACTIONS: u8 = 0x59;
    /// ProvideMissingTransactions message type
    pub const PROVIDE_MISSING_TRANSACTIONS: u8 = 0x5A;
}

/// Job declaration mode
///
/// Determines what level of control the miner has over block construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JobDeclarationMode {
    /// Miner customizes coinbase only; pool provides tx set
    #[default]
    CoinbaseOnly = 0,
    /// Miner provides full template including transaction selection
    FullTemplate = 1,
}

impl JobDeclarationMode {
    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Try to convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CoinbaseOnly),
            1 => Some(Self::FullTemplate),
            _ => None,
        }
    }
}

impl std::fmt::Display for JobDeclarationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoinbaseOnly => write!(f, "CoinbaseOnly"),
            Self::FullTemplate => write!(f, "FullTemplate"),
        }
    }
}

/// Client -> Server: Request a token for job declaration
///
/// The client sends this message to request a token that will be used
/// to declare custom mining jobs. The token prevents replay attacks
/// and allows the server to track job allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocateMiningJobToken {
    /// Request identifier for matching response
    pub request_id: u32,
    /// Human-readable identifier for the mining device (UTF-8)
    pub user_identifier: String,
    /// Requested job declaration mode
    pub requested_mode: JobDeclarationMode,
}

impl AllocateMiningJobToken {
    /// Create a new token allocation request
    ///
    /// Defaults to CoinbaseOnly mode for backward compatibility.
    pub fn new(request_id: u32, user_identifier: impl Into<String>) -> Self {
        Self {
            request_id,
            user_identifier: user_identifier.into(),
            requested_mode: JobDeclarationMode::CoinbaseOnly,
        }
    }

    /// Create a new token allocation request with a specific mode
    pub fn with_mode(
        request_id: u32,
        user_identifier: impl Into<String>,
        requested_mode: JobDeclarationMode,
    ) -> Self {
        Self {
            request_id,
            user_identifier: user_identifier.into(),
            requested_mode,
        }
    }
}

/// Server -> Client: Token allocation success response
///
/// Contains the allocated token and constraints for coinbase transactions
/// that will be accepted by the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocateMiningJobTokenSuccess {
    /// Request identifier matching the request
    pub request_id: u32,
    /// Allocated token for job declaration (unique identifier)
    pub mining_job_token: Vec<u8>,
    /// Pool's required coinbase output script (scriptPubKey)
    pub coinbase_output: Vec<u8>,
    /// Maximum additional size allowed in coinbase (bytes)
    pub coinbase_output_max_additional_size: u32,
    /// Whether async mining (starting before job confirmation) is allowed
    pub async_mining_allowed: bool,
    /// Granted mode (may differ from requested if pool doesn't support)
    pub granted_mode: JobDeclarationMode,
}

/// Client -> Server: Declare a custom mining job
///
/// The client uses a previously allocated token to declare a custom
/// mining job with their own coinbase transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCustomMiningJob {
    /// Channel ID for this job declaration
    pub channel_id: u32,
    /// Request identifier for matching response
    pub request_id: u32,
    /// Token from AllocateMiningJobTokenSuccess
    pub mining_job_token: Vec<u8>,
    /// Block version
    pub version: u32,
    /// Previous block hash (32 bytes)
    pub prev_hash: [u8; 32],
    /// Merkle root of transactions (32 bytes)
    pub merkle_root: [u8; 32],
    /// hashBlockCommitments for NU5+ (32 bytes)
    pub block_commitments: [u8; 32],
    /// Complete coinbase transaction (serialized)
    pub coinbase_tx: Vec<u8>,
    /// Block timestamp
    pub time: u32,
    /// Compact difficulty target (nBits)
    pub bits: u32,
}

impl SetCustomMiningJob {
    /// Construct the 140-byte block header for Equihash input
    /// (version || prev_hash || merkle_root || block_commitments || time || bits || nonce)
    pub fn build_header(&self, nonce: &[u8; 32]) -> [u8; 140] {
        let mut header = [0u8; 140];
        header[0..4].copy_from_slice(&self.version.to_le_bytes());
        header[4..36].copy_from_slice(&self.prev_hash);
        header[36..68].copy_from_slice(&self.merkle_root);
        header[68..100].copy_from_slice(&self.block_commitments);
        header[100..104].copy_from_slice(&self.time.to_le_bytes());
        header[104..108].copy_from_slice(&self.bits.to_le_bytes());
        header[108..140].copy_from_slice(nonce);
        header
    }

    /// Validate basic structure
    pub fn validate(&self) -> Result<(), SetCustomMiningJobErrorCode> {
        if self.mining_job_token.is_empty() {
            return Err(SetCustomMiningJobErrorCode::InvalidToken);
        }
        if self.coinbase_tx.is_empty() {
            return Err(SetCustomMiningJobErrorCode::InvalidCoinbase);
        }
        Ok(())
    }
}

/// Server -> Client: Custom job accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCustomMiningJobSuccess {
    /// Channel ID for this job
    pub channel_id: u32,
    /// Request identifier matching the request
    pub request_id: u32,
    /// Server-assigned job identifier
    pub job_id: u32,
    /// Pool-granted share target for this declared job.
    ///
    /// The pool (never the client) chooses this so fake-easy shares cannot
    /// inflate payout credit. It is easier than the block target and is used by
    /// the per-share validation path for declared jobs.
    pub share_target: [u8; 32],
}

impl SetCustomMiningJobSuccess {
    /// Create a new success response
    pub fn new(channel_id: u32, request_id: u32, job_id: u32, share_target: [u8; 32]) -> Self {
        Self {
            channel_id,
            request_id,
            job_id,
            share_target,
        }
    }
}

/// Server -> Client: Custom job rejected
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCustomMiningJobError {
    /// Channel ID for this job
    pub channel_id: u32,
    /// Request identifier matching the request
    pub request_id: u32,
    /// Error code indicating the reason for rejection
    pub error_code: SetCustomMiningJobErrorCode,
    /// Human-readable error message
    pub error_message: String,
}

impl SetCustomMiningJobError {
    /// Create a new error response
    pub fn new(
        channel_id: u32,
        request_id: u32,
        error_code: SetCustomMiningJobErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            channel_id,
            request_id,
            error_code,
            error_message: message.into(),
        }
    }

    /// Create error for invalid token
    pub fn invalid_token(channel_id: u32, request_id: u32) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetCustomMiningJobErrorCode::InvalidToken,
            "Invalid or unknown mining job token",
        )
    }

    /// Create error for expired token
    pub fn token_expired(channel_id: u32, request_id: u32) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetCustomMiningJobErrorCode::TokenExpired,
            "Mining job token has expired",
        )
    }

    /// Create error for invalid coinbase
    pub fn invalid_coinbase(channel_id: u32, request_id: u32, reason: impl Into<String>) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetCustomMiningJobErrorCode::InvalidCoinbase,
            reason,
        )
    }
}

/// Error codes for SetCustomMiningJob rejection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetCustomMiningJobErrorCode {
    /// Token is invalid or unknown
    InvalidToken = 0x01,
    /// Token has expired
    TokenExpired = 0x02,
    /// Coinbase transaction is invalid
    InvalidCoinbase = 0x03,
    /// Coinbase doesn't meet output constraints
    CoinbaseConstraintViolation = 0x04,
    /// Previous block hash is stale (doesn't match current chain tip)
    StalePrevHash = 0x05,
    /// Merkle root is invalid
    InvalidMerkleRoot = 0x06,
    /// Block version is not supported
    InvalidVersion = 0x07,
    /// nBits doesn't match network difficulty
    InvalidBits = 0x08,
    /// Server is overloaded
    ServerOverloaded = 0x09,
    /// Other error
    Other = 0xFF,
}

impl SetCustomMiningJobErrorCode {
    /// Convert error code to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Try to convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::InvalidToken),
            0x02 => Some(Self::TokenExpired),
            0x03 => Some(Self::InvalidCoinbase),
            0x04 => Some(Self::CoinbaseConstraintViolation),
            0x05 => Some(Self::StalePrevHash),
            0x06 => Some(Self::InvalidMerkleRoot),
            0x07 => Some(Self::InvalidVersion),
            0x08 => Some(Self::InvalidBits),
            0x09 => Some(Self::ServerOverloaded),
            0xFF => Some(Self::Other),
            _ => None,
        }
    }
}

impl std::fmt::Display for SetCustomMiningJobErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "invalid token"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::InvalidCoinbase => write!(f, "invalid coinbase"),
            Self::CoinbaseConstraintViolation => write!(f, "coinbase constraint violation"),
            Self::StalePrevHash => write!(f, "stale previous hash"),
            Self::InvalidMerkleRoot => write!(f, "invalid merkle root"),
            Self::InvalidVersion => write!(f, "invalid version"),
            Self::InvalidBits => write!(f, "invalid bits"),
            Self::ServerOverloaded => write!(f, "server overloaded"),
            Self::Other => write!(f, "other error"),
        }
    }
}

/// Client -> Server: Submit a block solution
///
/// When a miner finds a valid solution for a custom job,
/// they submit it to the server for block propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSolution {
    /// Channel ID this solution belongs to
    pub channel_id: u32,
    /// Job ID from SetCustomMiningJobSuccess
    pub job_id: u32,
    /// Block version
    pub version: u32,
    /// Block timestamp (may differ from job time)
    pub time: u32,
    /// Full 32-byte nonce
    pub nonce: [u8; 32],
    /// Equihash (200,9) solution (1344 bytes)
    pub solution: [u8; 1344],
}

impl PushSolution {
    /// Equihash (200,9) solution size
    pub const SOLUTION_SIZE: usize = 1344;

    /// Create a new solution submission
    pub fn new(
        channel_id: u32,
        job_id: u32,
        version: u32,
        time: u32,
        nonce: [u8; 32],
        solution: [u8; 1344],
    ) -> Self {
        Self {
            channel_id,
            job_id,
            version,
            time,
            nonce,
            solution,
        }
    }

    /// Validate solution length
    ///
    /// Note: This always returns true since `solution` is a fixed-size
    /// `[u8; 1344]` array. Retained for API compatibility.
    pub fn validate_solution_len(&self) -> bool {
        // Compile-time guarantee: solution is always SOLUTION_SIZE bytes
        true
    }
}

// NOTE: The following types are not in the JD protocol spec and have been removed:
// - PushSolutionResponse
// - SolutionResult
// - SolutionRejectReason
// PushSolution is a one-way message; the server does not respond to it per spec.

// =============================================================================
// Full-Template Mode Messages (0x56-0x5A)
// =============================================================================

/// Client -> Server: Declare a full template job (Full-Template mode)
///
/// The client provides the complete block template including transaction selection.
/// This message is used when the miner has been granted FullTemplate mode in the
/// AllocateMiningJobTokenSuccess response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetFullTemplateJob {
    /// Channel ID for this job declaration
    pub channel_id: u32,
    /// Request identifier for matching response
    pub request_id: u32,
    /// Token from AllocateMiningJobTokenSuccess
    pub mining_job_token: Vec<u8>,
    /// Block version
    pub version: u32,
    /// Previous block hash (32 bytes)
    pub prev_hash: [u8; 32],
    /// Merkle root of all transactions (32 bytes)
    pub merkle_root: [u8; 32],
    /// hashBlockCommitments for NU5+ (32 bytes)
    pub block_commitments: [u8; 32],
    /// Complete coinbase transaction (serialized)
    pub coinbase_tx: Vec<u8>,
    /// Block timestamp
    pub time: u32,
    /// Compact difficulty target (nBits)
    pub bits: u32,
    /// Transaction IDs (excluding coinbase) - full 32-byte txids
    pub tx_short_ids: Vec<[u8; 32]>,
    /// Full transaction data for txs pool may not have
    pub tx_data: Vec<Vec<u8>>,
}

impl SetFullTemplateJob {
    /// Construct the 140-byte block header for Equihash input
    /// (version || prev_hash || merkle_root || block_commitments || time || bits || nonce)
    pub fn build_header(&self, nonce: &[u8; 32]) -> [u8; 140] {
        let mut header = [0u8; 140];
        header[0..4].copy_from_slice(&self.version.to_le_bytes());
        header[4..36].copy_from_slice(&self.prev_hash);
        header[36..68].copy_from_slice(&self.merkle_root);
        header[68..100].copy_from_slice(&self.block_commitments);
        header[100..104].copy_from_slice(&self.time.to_le_bytes());
        header[104..108].copy_from_slice(&self.bits.to_le_bytes());
        header[108..140].copy_from_slice(nonce);
        header
    }

    /// Validate basic structure
    pub fn validate(&self) -> Result<(), SetFullTemplateJobErrorCode> {
        if self.mining_job_token.is_empty() {
            return Err(SetFullTemplateJobErrorCode::InvalidToken);
        }
        if self.coinbase_tx.is_empty() {
            return Err(SetFullTemplateJobErrorCode::InvalidCoinbase);
        }
        Ok(())
    }
}

/// Server -> Client: Full template job accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetFullTemplateJobSuccess {
    /// Channel ID for this job
    pub channel_id: u32,
    /// Request identifier matching the request
    pub request_id: u32,
    /// Server-assigned job identifier
    pub job_id: u32,
}

impl SetFullTemplateJobSuccess {
    /// Create a new success response
    pub fn new(channel_id: u32, request_id: u32, job_id: u32) -> Self {
        Self {
            channel_id,
            request_id,
            job_id,
        }
    }
}

/// Server -> Client: Full template job rejected
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetFullTemplateJobError {
    /// Channel ID for this job
    pub channel_id: u32,
    /// Request identifier matching the request
    pub request_id: u32,
    /// Error code indicating the reason for rejection
    pub error_code: SetFullTemplateJobErrorCode,
    /// Human-readable error message
    pub error_message: String,
}

impl SetFullTemplateJobError {
    /// Create a new error response
    pub fn new(
        channel_id: u32,
        request_id: u32,
        error_code: SetFullTemplateJobErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            channel_id,
            request_id,
            error_code,
            error_message: message.into(),
        }
    }

    /// Create error for invalid token
    pub fn invalid_token(channel_id: u32, request_id: u32) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetFullTemplateJobErrorCode::InvalidToken,
            "Invalid or unknown mining job token",
        )
    }

    /// Create error for mode mismatch
    pub fn mode_mismatch(channel_id: u32, request_id: u32) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetFullTemplateJobErrorCode::ModeMismatch,
            "Token was not granted FullTemplate mode",
        )
    }

    /// Create error for invalid coinbase
    pub fn invalid_coinbase(channel_id: u32, request_id: u32, reason: impl Into<String>) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetFullTemplateJobErrorCode::InvalidCoinbase,
            reason,
        )
    }

    /// Create error for invalid transactions
    pub fn invalid_transactions(
        channel_id: u32,
        request_id: u32,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            channel_id,
            request_id,
            SetFullTemplateJobErrorCode::InvalidTransactions,
            reason,
        )
    }
}

/// Error codes for SetFullTemplateJob rejection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetFullTemplateJobErrorCode {
    /// Token is invalid or unknown
    InvalidToken = 0x01,
    /// Token has expired
    TokenExpired = 0x02,
    /// Coinbase transaction is invalid
    InvalidCoinbase = 0x03,
    /// Coinbase doesn't meet output constraints
    CoinbaseConstraintViolation = 0x04,
    /// Previous block hash is stale (doesn't match current chain tip)
    StalePrevHash = 0x05,
    /// Merkle root is invalid
    InvalidMerkleRoot = 0x06,
    /// Block version is not supported
    InvalidVersion = 0x07,
    /// nBits doesn't match network difficulty
    InvalidBits = 0x08,
    /// Server is overloaded
    ServerOverloaded = 0x09,
    /// Token was granted CoinbaseOnly mode, not FullTemplate
    ModeMismatch = 0x0A,
    /// Transaction set is invalid (malformed, invalid, or missing)
    InvalidTransactions = 0x0B,
    /// Too many transactions in template
    TooManyTransactions = 0x0C,
    /// Other error
    Other = 0xFF,
}

impl SetFullTemplateJobErrorCode {
    /// Convert error code to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Try to convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::InvalidToken),
            0x02 => Some(Self::TokenExpired),
            0x03 => Some(Self::InvalidCoinbase),
            0x04 => Some(Self::CoinbaseConstraintViolation),
            0x05 => Some(Self::StalePrevHash),
            0x06 => Some(Self::InvalidMerkleRoot),
            0x07 => Some(Self::InvalidVersion),
            0x08 => Some(Self::InvalidBits),
            0x09 => Some(Self::ServerOverloaded),
            0x0A => Some(Self::ModeMismatch),
            0x0B => Some(Self::InvalidTransactions),
            0x0C => Some(Self::TooManyTransactions),
            0xFF => Some(Self::Other),
            _ => None,
        }
    }
}

impl std::fmt::Display for SetFullTemplateJobErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "invalid token"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::InvalidCoinbase => write!(f, "invalid coinbase"),
            Self::CoinbaseConstraintViolation => write!(f, "coinbase constraint violation"),
            Self::StalePrevHash => write!(f, "stale previous hash"),
            Self::InvalidMerkleRoot => write!(f, "invalid merkle root"),
            Self::InvalidVersion => write!(f, "invalid version"),
            Self::InvalidBits => write!(f, "invalid bits"),
            Self::ServerOverloaded => write!(f, "server overloaded"),
            Self::ModeMismatch => write!(f, "mode mismatch"),
            Self::InvalidTransactions => write!(f, "invalid transactions"),
            Self::TooManyTransactions => write!(f, "too many transactions"),
            Self::Other => write!(f, "other error"),
        }
    }
}

/// Server -> Client: Request missing transactions
///
/// Sent when pool needs full transaction data for txids it doesn't have
/// in its mempool. The client should respond with ProvideMissingTransactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetMissingTransactions {
    /// Channel ID for this request
    pub channel_id: u32,
    /// Request identifier for matching response
    pub request_id: u32,
    /// List of transaction IDs that the server needs
    pub missing_tx_ids: Vec<[u8; 32]>,
}

impl GetMissingTransactions {
    /// Create a new missing transactions request
    pub fn new(channel_id: u32, request_id: u32, missing_tx_ids: Vec<[u8; 32]>) -> Self {
        Self {
            channel_id,
            request_id,
            missing_tx_ids,
        }
    }
}

/// Client -> Server: Provide requested transactions
///
/// Response to GetMissingTransactions containing the full serialized
/// transaction data for each requested txid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvideMissingTransactions {
    /// Channel ID matching the request
    pub channel_id: u32,
    /// Request identifier matching the request
    pub request_id: u32,
    /// Full serialized transaction data (in the same order as requested)
    pub transactions: Vec<Vec<u8>>,
}

impl ProvideMissingTransactions {
    /// Create a new provide missing transactions response
    pub fn new(channel_id: u32, request_id: u32, transactions: Vec<Vec<u8>>) -> Self {
        Self {
            channel_id,
            request_id,
            transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_token_request() {
        let request = AllocateMiningJobToken::new(1, "miner-001");
        assert_eq!(request.request_id, 1);
        assert_eq!(request.user_identifier, "miner-001");
        assert_eq!(request.requested_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[test]
    fn test_allocate_token_request_with_mode() {
        let request =
            AllocateMiningJobToken::with_mode(1, "miner-001", JobDeclarationMode::FullTemplate);
        assert_eq!(request.request_id, 1);
        assert_eq!(request.user_identifier, "miner-001");
        assert_eq!(request.requested_mode, JobDeclarationMode::FullTemplate);
    }

    #[test]
    fn test_allocate_token_success() {
        let response = AllocateMiningJobTokenSuccess {
            request_id: 1,
            mining_job_token: vec![0x01, 0x02, 0x03],
            coinbase_output: vec![0x76, 0xa9, 0x14], // P2PKH prefix
            coinbase_output_max_additional_size: 1000,
            async_mining_allowed: true,
            granted_mode: JobDeclarationMode::CoinbaseOnly,
        };

        assert_eq!(response.coinbase_output_max_additional_size, 1000);
        assert!(response.async_mining_allowed);
        assert!(!response.coinbase_output.is_empty());
        assert_eq!(response.granted_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[test]
    fn test_job_declaration_mode() {
        // Test default
        assert_eq!(
            JobDeclarationMode::default(),
            JobDeclarationMode::CoinbaseOnly
        );

        // Test conversion roundtrip
        for mode in [
            JobDeclarationMode::CoinbaseOnly,
            JobDeclarationMode::FullTemplate,
        ] {
            let byte = mode.as_u8();
            let recovered = JobDeclarationMode::from_u8(byte).unwrap();
            assert_eq!(mode, recovered);
        }

        // Test invalid value
        assert!(JobDeclarationMode::from_u8(2).is_none());
        assert!(JobDeclarationMode::from_u8(0xFF).is_none());

        // Test display
        assert_eq!(
            format!("{}", JobDeclarationMode::CoinbaseOnly),
            "CoinbaseOnly"
        );
        assert_eq!(
            format!("{}", JobDeclarationMode::FullTemplate),
            "FullTemplate"
        );
    }

    #[test]
    fn test_set_custom_mining_job_validation() {
        let job = SetCustomMiningJob {
            channel_id: 1,
            request_id: 1,
            mining_job_token: vec![0x01, 0x02, 0x03],
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: vec![0x01, 0x00, 0x00, 0x00], // minimal tx
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        assert!(job.validate().is_ok());

        // Test with empty token
        let bad_job = SetCustomMiningJob {
            mining_job_token: vec![],
            ..job.clone()
        };
        assert_eq!(
            bad_job.validate().unwrap_err(),
            SetCustomMiningJobErrorCode::InvalidToken
        );

        // Test with empty coinbase
        let bad_job = SetCustomMiningJob {
            coinbase_tx: vec![],
            ..job
        };
        assert_eq!(
            bad_job.validate().unwrap_err(),
            SetCustomMiningJobErrorCode::InvalidCoinbase
        );
    }

    #[test]
    fn test_build_header() {
        let job = SetCustomMiningJob {
            channel_id: 1,
            request_id: 1,
            mining_job_token: vec![0x01],
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: vec![0x01],
            time: 0x12345678,
            bits: 0xaabbccdd,
        };

        let nonce = [0xff; 32];
        let header = job.build_header(&nonce);

        assert_eq!(header.len(), 140);
        // Version at offset 0 (little-endian)
        assert_eq!(&header[0..4], &[0x05, 0x00, 0x00, 0x00]);
        // prev_hash at offset 4
        assert_eq!(&header[4..36], &[0xaa; 32]);
        // merkle_root at offset 36
        assert_eq!(&header[36..68], &[0xbb; 32]);
        // block_commitments at offset 68
        assert_eq!(&header[68..100], &[0xcc; 32]);
        // time at offset 100 (little-endian)
        assert_eq!(&header[100..104], &[0x78, 0x56, 0x34, 0x12]);
        // bits at offset 104 (little-endian)
        assert_eq!(&header[104..108], &[0xdd, 0xcc, 0xbb, 0xaa]);
        // nonce at offset 108
        assert_eq!(&header[108..140], &[0xff; 32]);
    }

    #[test]
    fn test_error_codes() {
        // Test conversion roundtrip
        for code in [
            SetCustomMiningJobErrorCode::InvalidToken,
            SetCustomMiningJobErrorCode::TokenExpired,
            SetCustomMiningJobErrorCode::InvalidCoinbase,
            SetCustomMiningJobErrorCode::CoinbaseConstraintViolation,
            SetCustomMiningJobErrorCode::StalePrevHash,
            SetCustomMiningJobErrorCode::InvalidMerkleRoot,
            SetCustomMiningJobErrorCode::InvalidVersion,
            SetCustomMiningJobErrorCode::InvalidBits,
            SetCustomMiningJobErrorCode::ServerOverloaded,
            SetCustomMiningJobErrorCode::Other,
        ] {
            let byte = code.as_u8();
            let recovered = SetCustomMiningJobErrorCode::from_u8(byte).unwrap();
            assert_eq!(code, recovered);
        }

        // Test invalid code
        assert!(SetCustomMiningJobErrorCode::from_u8(0x00).is_none());
        assert!(SetCustomMiningJobErrorCode::from_u8(0x10).is_none());
    }

    #[test]
    fn test_error_helpers() {
        let error = SetCustomMiningJobError::invalid_token(1, 42);
        assert_eq!(error.channel_id, 1);
        assert_eq!(error.request_id, 42);
        assert_eq!(error.error_code, SetCustomMiningJobErrorCode::InvalidToken);

        let error = SetCustomMiningJobError::token_expired(2, 43);
        assert_eq!(error.channel_id, 2);
        assert_eq!(error.request_id, 43);
        assert_eq!(error.error_code, SetCustomMiningJobErrorCode::TokenExpired);

        let error = SetCustomMiningJobError::invalid_coinbase(3, 44, "missing pool output");
        assert_eq!(error.channel_id, 3);
        assert_eq!(error.request_id, 44);
        assert_eq!(
            error.error_code,
            SetCustomMiningJobErrorCode::InvalidCoinbase
        );
        assert_eq!(error.error_message, "missing pool output");
    }

    #[test]
    fn test_push_solution() {
        let solution = PushSolution::new(
            1,            // channel_id
            100,          // job_id
            5,            // version
            1700000000,   // time
            [0x11; 32],   // nonce
            [0x22; 1344], // solution
        );

        assert_eq!(solution.channel_id, 1);
        assert_eq!(solution.job_id, 100);
        assert_eq!(solution.version, 5);
        assert!(solution.validate_solution_len());
    }

    #[test]
    fn test_message_type_constants() {
        // Verify message types are in the 0x50-0x5F range
        assert_eq!(message_types::ALLOCATE_MINING_JOB_TOKEN, 0x50);
        assert_eq!(message_types::ALLOCATE_MINING_JOB_TOKEN_SUCCESS, 0x51);
        assert_eq!(message_types::SET_CUSTOM_MINING_JOB, 0x52);
        assert_eq!(message_types::SET_CUSTOM_MINING_JOB_SUCCESS, 0x53);
        assert_eq!(message_types::SET_CUSTOM_MINING_JOB_ERROR, 0x54);
        assert_eq!(message_types::PUSH_SOLUTION, 0x55);
        // Full-Template mode message types
        assert_eq!(message_types::SET_FULL_TEMPLATE_JOB, 0x56);
        assert_eq!(message_types::SET_FULL_TEMPLATE_JOB_SUCCESS, 0x57);
        assert_eq!(message_types::SET_FULL_TEMPLATE_JOB_ERROR, 0x58);
        assert_eq!(message_types::GET_MISSING_TRANSACTIONS, 0x59);
        assert_eq!(message_types::PROVIDE_MISSING_TRANSACTIONS, 0x5A);
    }

    // =========================================================================
    // Full-Template Mode Tests
    // =========================================================================

    #[test]
    fn test_set_full_template_job() {
        let job = SetFullTemplateJob {
            channel_id: 1,
            request_id: 42,
            mining_job_token: vec![0x01, 0x02, 0x03],
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: vec![0x01, 0x00, 0x00, 0x00],
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![[0x11; 32], [0x22; 32]],
            tx_data: vec![vec![0x01, 0x00], vec![0x02, 0x00]],
        };

        assert_eq!(job.channel_id, 1);
        assert_eq!(job.request_id, 42);
        assert_eq!(job.tx_short_ids.len(), 2);
        assert_eq!(job.tx_data.len(), 2);
    }

    #[test]
    fn test_set_full_template_job_validation() {
        let job = SetFullTemplateJob {
            channel_id: 1,
            request_id: 1,
            mining_job_token: vec![0x01, 0x02, 0x03],
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: vec![0x01, 0x00, 0x00, 0x00],
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![],
            tx_data: vec![],
        };

        assert!(job.validate().is_ok());

        // Test with empty token
        let bad_job = SetFullTemplateJob {
            mining_job_token: vec![],
            ..job.clone()
        };
        assert_eq!(
            bad_job.validate().unwrap_err(),
            SetFullTemplateJobErrorCode::InvalidToken
        );

        // Test with empty coinbase
        let bad_job = SetFullTemplateJob {
            coinbase_tx: vec![],
            ..job
        };
        assert_eq!(
            bad_job.validate().unwrap_err(),
            SetFullTemplateJobErrorCode::InvalidCoinbase
        );
    }

    #[test]
    fn test_set_full_template_job_build_header() {
        let job = SetFullTemplateJob {
            channel_id: 1,
            request_id: 1,
            mining_job_token: vec![0x01],
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: vec![0x01],
            time: 0x12345678,
            bits: 0xaabbccdd,
            tx_short_ids: vec![],
            tx_data: vec![],
        };

        let nonce = [0xff; 32];
        let header = job.build_header(&nonce);

        assert_eq!(header.len(), 140);
        assert_eq!(&header[0..4], &[0x05, 0x00, 0x00, 0x00]);
        assert_eq!(&header[4..36], &[0xaa; 32]);
        assert_eq!(&header[36..68], &[0xbb; 32]);
        assert_eq!(&header[68..100], &[0xcc; 32]);
        assert_eq!(&header[100..104], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(&header[104..108], &[0xdd, 0xcc, 0xbb, 0xaa]);
        assert_eq!(&header[108..140], &[0xff; 32]);
    }

    #[test]
    fn test_set_full_template_job_success() {
        let success = SetFullTemplateJobSuccess::new(1, 42, 100);
        assert_eq!(success.channel_id, 1);
        assert_eq!(success.request_id, 42);
        assert_eq!(success.job_id, 100);
    }

    #[test]
    fn test_set_full_template_job_error() {
        let error = SetFullTemplateJobError::new(
            1,
            42,
            SetFullTemplateJobErrorCode::InvalidToken,
            "Token is invalid",
        );
        assert_eq!(error.channel_id, 1);
        assert_eq!(error.request_id, 42);
        assert_eq!(error.error_code, SetFullTemplateJobErrorCode::InvalidToken);
        assert_eq!(error.error_message, "Token is invalid");
    }

    #[test]
    fn test_set_full_template_job_error_helpers() {
        let error = SetFullTemplateJobError::invalid_token(1, 42);
        assert_eq!(error.error_code, SetFullTemplateJobErrorCode::InvalidToken);

        let error = SetFullTemplateJobError::mode_mismatch(1, 42);
        assert_eq!(error.error_code, SetFullTemplateJobErrorCode::ModeMismatch);

        let error = SetFullTemplateJobError::invalid_coinbase(1, 42, "bad coinbase");
        assert_eq!(
            error.error_code,
            SetFullTemplateJobErrorCode::InvalidCoinbase
        );
        assert_eq!(error.error_message, "bad coinbase");

        let error = SetFullTemplateJobError::invalid_transactions(1, 42, "malformed tx");
        assert_eq!(
            error.error_code,
            SetFullTemplateJobErrorCode::InvalidTransactions
        );
        assert_eq!(error.error_message, "malformed tx");
    }

    #[test]
    fn test_full_template_error_codes() {
        // Test conversion roundtrip for all error codes
        for code in [
            SetFullTemplateJobErrorCode::InvalidToken,
            SetFullTemplateJobErrorCode::TokenExpired,
            SetFullTemplateJobErrorCode::InvalidCoinbase,
            SetFullTemplateJobErrorCode::CoinbaseConstraintViolation,
            SetFullTemplateJobErrorCode::StalePrevHash,
            SetFullTemplateJobErrorCode::InvalidMerkleRoot,
            SetFullTemplateJobErrorCode::InvalidVersion,
            SetFullTemplateJobErrorCode::InvalidBits,
            SetFullTemplateJobErrorCode::ServerOverloaded,
            SetFullTemplateJobErrorCode::ModeMismatch,
            SetFullTemplateJobErrorCode::InvalidTransactions,
            SetFullTemplateJobErrorCode::TooManyTransactions,
            SetFullTemplateJobErrorCode::Other,
        ] {
            let byte = code.as_u8();
            let recovered = SetFullTemplateJobErrorCode::from_u8(byte).unwrap();
            assert_eq!(code, recovered);
        }

        // Test invalid code
        assert!(SetFullTemplateJobErrorCode::from_u8(0x00).is_none());
        assert!(SetFullTemplateJobErrorCode::from_u8(0x10).is_none());
    }

    #[test]
    fn test_full_template_error_code_display() {
        assert_eq!(
            format!("{}", SetFullTemplateJobErrorCode::InvalidToken),
            "invalid token"
        );
        assert_eq!(
            format!("{}", SetFullTemplateJobErrorCode::ModeMismatch),
            "mode mismatch"
        );
        assert_eq!(
            format!("{}", SetFullTemplateJobErrorCode::InvalidTransactions),
            "invalid transactions"
        );
        assert_eq!(
            format!("{}", SetFullTemplateJobErrorCode::TooManyTransactions),
            "too many transactions"
        );
    }

    #[test]
    fn test_get_missing_transactions() {
        let msg = GetMissingTransactions::new(1, 42, vec![[0x11; 32], [0x22; 32], [0x33; 32]]);

        assert_eq!(msg.channel_id, 1);
        assert_eq!(msg.request_id, 42);
        assert_eq!(msg.missing_tx_ids.len(), 3);
        assert_eq!(msg.missing_tx_ids[0], [0x11; 32]);
        assert_eq!(msg.missing_tx_ids[1], [0x22; 32]);
        assert_eq!(msg.missing_tx_ids[2], [0x33; 32]);
    }

    #[test]
    fn test_provide_missing_transactions() {
        let msg = ProvideMissingTransactions::new(
            1,
            42,
            vec![vec![0x01, 0x00, 0x00, 0x00], vec![0x02, 0x00, 0x00, 0x00]],
        );

        assert_eq!(msg.channel_id, 1);
        assert_eq!(msg.request_id, 42);
        assert_eq!(msg.transactions.len(), 2);
        assert_eq!(msg.transactions[0], vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(msg.transactions[1], vec![0x02, 0x00, 0x00, 0x00]);
    }
}
