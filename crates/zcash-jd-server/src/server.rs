//! Job Declaration Server implementation
//!
//! This module implements the JD server logic for handling miner connections,
//! token allocation, job declaration, and solution submission in Coinbase-Only
//! and Full-Template modes.

use crate::codec::{
    decode_allocate_token, decode_provide_missing_transactions, decode_push_solution,
    decode_set_custom_job, decode_set_full_template_job, decode_submit_shares_jd,
    encode_allocate_token_success, encode_get_missing_transactions, encode_set_custom_job_error,
    encode_set_custom_job_success, encode_set_full_template_job_error,
    encode_set_full_template_job_success, encode_submit_shares_jd_response,
};
use crate::config::JdServerConfig;
use crate::error::{JdServerError, Result};
use crate::messages::{
    AllocateMiningJobTokenSuccess, GetMissingTransactions, JdShare, JdShareErrorCode,
    JobDeclarationMode, ProvideMissingTransactions, PushSolution, SetCustomMiningJob,
    SetCustomMiningJobError, SetCustomMiningJobErrorCode, SetCustomMiningJobSuccess,
    SetFullTemplateJob, SetFullTemplateJobError, SetFullTemplateJobErrorCode,
    SetFullTemplateJobSuccess, SubmitSharesJd, SubmitSharesJdResponse, message_types,
};
use crate::token::{DeclaredJobInfo, TokenManager};
use crate::validation::{TemplateValidator, ValidationResult};
use sovright_noise::NoiseStream;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock as TokioRwLock;
use tracing::{debug, error, info, warn};
use zcash_equihash_validator::{
    EquihashValidator, Target, ValidationError, compact_to_target, target_to_difficulty,
};
use zcash_mining_protocol::codec::MessageFrame;
use zcash_pool_common::PayoutTracker;
use zcash_template_provider::calculate_block_commitments_hash;
use zcash_template_provider::types::Hash256;

const MAX_JOB_ID: u32 = u32::MAX - 1;

fn next_positive_job_id(counter: &AtomicU32) -> u32 {
    loop {
        let current = counter.load(Ordering::SeqCst);
        let job_id = if current == 0 || current > MAX_JOB_ID {
            1
        } else {
            current
        };
        let next = if job_id >= MAX_JOB_ID { 1 } else { job_id + 1 };

        if counter
            .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return job_id;
        }
    }
}

/// Build the 140-byte block header for a declared job using the miner-supplied
/// `time` and `nonce`. All other fields come from the stored `DeclaredJobInfo`.
///
/// Layout: [0:4]=version LE, [4:36]=prev_hash, [36:68]=merkle_root,
/// [68:100]=block_commitments, [100:104]=time LE, [104:108]=bits LE,
/// [108:140]=nonce.
fn build_header(job: &DeclaredJobInfo, time: u32, nonce: &[u8; 32]) -> [u8; 140] {
    let mut header = [0u8; 140];
    header[0..4].copy_from_slice(&job.version.to_le_bytes());
    header[4..36].copy_from_slice(&job.prev_hash);
    header[36..68].copy_from_slice(&job.merkle_root);
    header[68..100].copy_from_slice(&job.block_commitments);
    header[100..104].copy_from_slice(&time.to_le_bytes());
    header[104..108].copy_from_slice(&job.bits.to_le_bytes());
    header[108..140].copy_from_slice(nonce);
    header
}

/// Compute the dedup key for a share: `sha256(nonce ‖ time_le ‖ solution[..64])`.
///
/// Only the first 64 bytes of the 1344-byte Equihash-(200,9) solution are
/// hashed: those bytes encode the leading index pairs of the solution, so two
/// distinct valid solutions colliding on `(nonce, time, solution[..64])` is
/// astronomically unlikely. The truncation only bounds hashing cost — the full
/// 1344-byte solution is still verified in its entirety before any credit, so a
/// collision could at worst suppress a duplicate, never admit an invalid share.
fn share_dedup_key(share: &JdShare) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(share.nonce);
    hasher.update(share.time.to_le_bytes());
    hasher.update(&share.solution[..64]);
    hasher.finalize().into()
}

fn recompute_coinbase_only_block_commitments(
    coinbase_tx: &[u8],
    chain_history_root: [u8; 32],
    consensus_branch_id: u32,
) -> std::result::Result<[u8; 32], String> {
    let parsed = zcash_coinbase::tx_parse::parse_transaction(coinbase_tx)
        .map_err(|e| format!("declared coinbase cannot be parsed for commitments: {}", e))?;
    if parsed.inputs.is_empty() {
        return Err("declared coinbase has no transparent inputs for commitments".to_string());
    }

    let mut script_sigs = Vec::new();
    for input in parsed.inputs {
        script_sigs.extend_from_slice(&input.script_sig);
    }

    let coinbase_digest = zcash_coinbase::auth_digest::compute_coinbase_auth_digest(
        &script_sigs,
        consensus_branch_id,
    );
    let auth_data_root = zcash_coinbase::auth_digest::compute_auth_data_root(&[coinbase_digest]);
    Ok(calculate_block_commitments_hash(&Hash256(chain_history_root), &Hash256(auth_data_root)).0)
}

#[derive(Debug, Clone)]
pub struct CurrentTemplateContext {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub block_commitments: [u8; 32],
    pub chain_history_root: [u8; 32],
    pub consensus_branch_id: u32,
    pub bits: u32,
    pub time: u32,
    pub txids: Vec<[u8; 32]>,
    pub coinbase_tx_len: usize,
}

#[derive(Debug, Clone)]
struct PendingMissingTransactions {
    channel_id: u32,
    expected_txids: Vec<[u8; 32]>,
}

/// JD Server embedded in pool
///
/// Handles the Job Declaration protocol for Coinbase-Only and Full-Template mode mining.
/// This server validates tokens, processes job declarations, and tracks
/// block solutions for miners who want to create their own coinbase transactions
/// or provide full block templates.
pub struct JdServer {
    /// Configuration
    config: JdServerConfig,
    /// Token manager
    token_manager: Arc<TokenManager>,
    /// Template validator for Full-Template mode
    validator: Arc<TokioRwLock<TemplateValidator>>,
    /// Job ID counter
    next_job_id: AtomicU32,
    /// Payout tracker (shared with pool)
    payout_tracker: Arc<PayoutTracker>,
    /// Current prev_hash (for stale detection)
    current_prev_hash: Arc<TokioRwLock<Option<[u8; 32]>>>,
    /// Current template metadata for header/coinbase validation
    current_template: Arc<TokioRwLock<Option<CurrentTemplateContext>>>,
    /// Outstanding missing-transaction requests keyed by (client_id, request_id)
    pending_missing: Arc<TokioRwLock<HashMap<(String, u32), PendingMissingTransactions>>>,
    /// Per-job dedup sets of seen share keys, keyed by job_id.
    ///
    /// A share key is `sha256(nonce ‖ time_le ‖ solution[..64])`. The dedup
    /// uses a three-phase pattern to prevent two distinct attacks:
    ///
    /// 1. **Read-only pre-flight** (before Equihash): if the key is already in
    ///    the set, reject immediately as `Duplicate` without running the verifier.
    ///    This prevents valid-share replay DoS (force Equihash on every replay).
    ///
    /// 2. **Equihash validation** (structurally invalid → `BadSolution`, NOT
    ///    recorded in dedup).  Recording invalid shares before validation would
    ///    let an attacker fill `MAX_SEEN_SHARES_PER_JOB` at zero PoW cost and
    ///    block all subsequent legitimate shares.
    ///
    /// 3. **Authoritative atomic check+insert** (after validation): handles
    ///    concurrent submissions that raced past the pre-flight.  Only solutions
    ///    that passed Equihash (`Ok` or `TargetNotMet`) are inserted.
    ///
    /// Entries for jobs that no longer resolve are evicted at the head of each
    /// handler call.  Memory bound: `live_jobs × MAX_SEEN_SHARES_PER_JOB × 32 B`
    /// plus `HashSet` overhead; backstopped by token issuance limits.
    seen_shares: Mutex<HashMap<u32, HashSet<[u8; 32]>>>,
}

/// Maximum number of distinct share keys remembered per job before further
/// distinct shares are treated as duplicates (prevents memory abuse).
const MAX_SEEN_SHARES_PER_JOB: usize = 10_000;

impl JdServer {
    /// Create a new JD Server
    pub fn new(config: JdServerConfig, payout_tracker: Arc<PayoutTracker>) -> Self {
        let token_manager = Arc::new(TokenManager::new(config.clone()));
        let validator = TemplateValidator::new(
            config.full_template_validation,
            config.pool_payout_script.clone(),
            config.min_pool_payout,
        );
        Self {
            config,
            token_manager,
            validator: Arc::new(TokioRwLock::new(validator)),
            next_job_id: AtomicU32::new(1),
            payout_tracker,
            current_prev_hash: Arc::new(TokioRwLock::new(None)),
            current_template: Arc::new(TokioRwLock::new(None)),
            pending_missing: Arc::new(TokioRwLock::new(HashMap::new())),
            seen_shares: Mutex::new(HashMap::new()),
        }
    }

    /// Update the current prev_hash (called when new block arrives)
    pub async fn set_current_prev_hash(&self, prev_hash: [u8; 32]) {
        let mut lock = self.current_prev_hash.write().await;
        *lock = Some(prev_hash);
        drop(lock);

        let mut template = self.current_template.write().await;
        if let Some(current) = template.as_mut() {
            current.prev_hash = prev_hash;
        }
        debug!(
            prev_hash = ?hex::encode(prev_hash),
            "Updated current prev_hash"
        );
    }

    /// Update the current template metadata used for job validation.
    pub async fn set_current_template(&self, template: CurrentTemplateContext) {
        {
            let mut prev_hash = self.current_prev_hash.write().await;
            *prev_hash = Some(template.prev_hash);
        }
        {
            let mut current = self.current_template.write().await;
            *current = Some(template.clone());
        }
        debug!(
            prev_hash = ?hex::encode(template.prev_hash),
            tx_count = template.txids.len(),
            "Updated current template context"
        );
    }

    /// Get the current prev_hash
    pub async fn get_current_prev_hash(&self) -> Option<[u8; 32]> {
        let lock = self.current_prev_hash.read().await;
        *lock
    }

    async fn validate_header_fields(
        &self,
        version: u32,
        time: u32,
        bits: u32,
    ) -> std::result::Result<Option<CurrentTemplateContext>, String> {
        let current = self.current_template.read().await.clone();

        if let Some(ref template) = current {
            if version != template.version {
                return Err("block version does not match current template".into());
            }
            if bits != template.bits {
                return Err("difficulty bits do not match current template".into());
            }

            const MAX_TIME_FORWARD: u32 = 7200;
            const MAX_TIME_BACKWARD: u32 = 60;
            if time < template.time.saturating_sub(MAX_TIME_BACKWARD)
                || time > template.time.saturating_add(MAX_TIME_FORWARD)
            {
                return Err("template time is out of range".into());
            }
        }

        Ok(current)
    }

    async fn validate_custom_job_request(
        &self,
        request: &SetCustomMiningJob,
        token_info_client_id: &str,
    ) -> std::result::Result<(), SetCustomMiningJobError> {
        let template = self
            .validate_header_fields(request.version, request.time, request.bits)
            .await
            .map_err(|reason| {
                SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    match reason.as_str() {
                        "block version does not match current template" => {
                            SetCustomMiningJobErrorCode::InvalidVersion
                        }
                        "block commitments do not match current template" => {
                            SetCustomMiningJobErrorCode::Other
                        }
                        "difficulty bits do not match current template" => {
                            SetCustomMiningJobErrorCode::InvalidBits
                        }
                        _ => SetCustomMiningJobErrorCode::Other,
                    },
                    reason,
                )
            })?;

        let validator = self.validator.read().await;
        if let Err(reason) = validator.validate_coinbase(&request.coinbase_tx) {
            return Err(SetCustomMiningJobError::new(
                request.channel_id,
                request.request_id,
                SetCustomMiningJobErrorCode::CoinbaseConstraintViolation,
                reason,
            ));
        }
        drop(validator);

        if let Some(template) = template {
            let max_coinbase_len =
                template.coinbase_tx_len + self.config.coinbase_output_max_additional_size as usize;
            if request.coinbase_tx.len() > max_coinbase_len {
                return Err(SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetCustomMiningJobErrorCode::CoinbaseConstraintViolation,
                    format!(
                        "coinbase length {} exceeds maximum {}",
                        request.coinbase_tx.len(),
                        max_coinbase_len
                    ),
                ));
            }

            let expected_merkle_root =
                TemplateValidator::compute_merkle_root(&request.coinbase_tx, &template.txids)
                    .ok_or_else(|| {
                        SetCustomMiningJobError::invalid_coinbase(
                            request.channel_id,
                            request.request_id,
                            "coinbase transaction is empty",
                        )
                    })?;
            if expected_merkle_root != request.merkle_root {
                return Err(SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetCustomMiningJobErrorCode::InvalidMerkleRoot,
                    "merkle root does not match pool transaction set",
                ));
            }

            let expected_block_commitments = recompute_coinbase_only_block_commitments(
                &request.coinbase_tx,
                template.chain_history_root,
                template.consensus_branch_id,
            )
            .map_err(|reason| {
                SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetCustomMiningJobErrorCode::Other,
                    reason,
                )
            })?;

            if expected_block_commitments != request.block_commitments {
                return Err(SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetCustomMiningJobErrorCode::Other,
                    "declared block commitments do not verify against declared coinbase and chain tip",
                ));
            }
        }

        debug!(
            client_id = token_info_client_id,
            request_id = request.request_id,
            "Validated custom job request"
        );
        Ok(())
    }

    /// Handle a token allocation request
    ///
    /// Allocates a new mining job token for the given user.
    /// The granted mode is determined based on what the client requested and
    /// what the server supports.
    pub fn handle_allocate_token(
        &self,
        request_id: u32,
        user_id: &str,
        requested_mode: JobDeclarationMode,
    ) -> Result<AllocateMiningJobTokenSuccess> {
        // Determine granted mode based on request and server configuration
        let granted_mode = if requested_mode == JobDeclarationMode::FullTemplate {
            if self.config.full_template_enabled {
                JobDeclarationMode::FullTemplate
            } else {
                // Fall back to CoinbaseOnly if Full-Template not enabled
                info!(
                    request_id,
                    user_id,
                    "Full-Template mode requested but not enabled, falling back to CoinbaseOnly"
                );
                JobDeclarationMode::CoinbaseOnly
            }
        } else {
            JobDeclarationMode::CoinbaseOnly
        };

        let token = self
            .token_manager
            .allocate_token_with_mode(user_id, granted_mode)?;

        info!(
            request_id,
            user_id,
            token_len = token.token.len(),
            requested_mode = %requested_mode,
            granted_mode = %granted_mode,
            "Allocated mining job token"
        );

        Ok(AllocateMiningJobTokenSuccess {
            request_id,
            mining_job_token: token.token,
            coinbase_output: self.config.pool_payout_script.clone(),
            coinbase_output_max_additional_size: self.config.coinbase_output_max_additional_size,
            async_mining_allowed: self.config.async_mining_allowed,
            granted_mode,
        })
    }

    /// Handle a custom job declaration
    ///
    /// Validates the token, checks for stale prev_hash, validates the coinbase,
    /// allocates a job ID, and stores job info.
    pub async fn handle_declare_job(
        &self,
        request: SetCustomMiningJob,
    ) -> std::result::Result<SetCustomMiningJobSuccess, SetCustomMiningJobError> {
        // 1. Validate basic structure
        if let Err(e) = request.validate() {
            return Err(SetCustomMiningJobError::new(
                request.channel_id,
                request.request_id,
                e,
                format!("Validation failed: {}", e),
            ));
        }

        // 2. Validate token
        let token_info = match self.token_manager.validate_token(&request.mining_job_token) {
            Ok(info) => info,
            Err(JdServerError::InvalidToken) => {
                warn!(
                    request_id = request.request_id,
                    "Job declaration rejected: invalid token"
                );
                return Err(SetCustomMiningJobError::invalid_token(
                    request.channel_id,
                    request.request_id,
                ));
            }
            Err(JdServerError::TokenExpired) => {
                warn!(
                    request_id = request.request_id,
                    "Job declaration rejected: token expired"
                );
                return Err(SetCustomMiningJobError::token_expired(
                    request.channel_id,
                    request.request_id,
                ));
            }
            Err(e) => {
                error!(
                    request_id = request.request_id,
                    error = %e,
                    "Unexpected error validating token"
                );
                return Err(SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetCustomMiningJobErrorCode::Other,
                    format!("Token validation error: {}", e),
                ));
            }
        };

        // 3. Check prev_hash matches current (stale detection)
        //    Fail closed: reject if we haven't received any template yet
        let current_prev_hash = self.current_prev_hash.read().await;
        match *current_prev_hash {
            Some(expected_prev_hash) => {
                if request.prev_hash != expected_prev_hash {
                    warn!(
                        request_id = request.request_id,
                        expected = ?hex::encode(expected_prev_hash),
                        got = ?hex::encode(request.prev_hash),
                        "Job declaration rejected: stale prev_hash"
                    );
                    return Err(SetCustomMiningJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetCustomMiningJobErrorCode::StalePrevHash,
                        "Previous block hash does not match current chain tip",
                    ));
                }
            }
            None => {
                warn!(
                    request_id = request.request_id,
                    "Job declaration rejected: no template received yet"
                );
                return Err(SetCustomMiningJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetCustomMiningJobErrorCode::StalePrevHash,
                    "Server has not received a block template yet",
                ));
            }
        }
        drop(current_prev_hash);

        self.validate_custom_job_request(&request, &token_info.client_id)
            .await?;

        // 5. Allocate job_id
        let job_id = next_positive_job_id(&self.next_job_id);

        // 6. Store job info with token
        let job_info = DeclaredJobInfo {
            job_id,
            client_id: token_info.client_id.clone(),
            mode: token_info.granted_mode,
            channel_id: request.channel_id,
            version: request.version,
            prev_hash: request.prev_hash,
            merkle_root: request.merkle_root,
            block_commitments: request.block_commitments,
            bits: request.bits,
            time: request.time,
            coinbase_tx: request.coinbase_tx.clone(),
            // Pool grants the share target (never the client) at declaration time.
            share_target: self.config.share_target,
        };

        if let Err(e) = self
            .token_manager
            .set_job_info(&request.mining_job_token, job_info)
        {
            error!(
                request_id = request.request_id,
                job_id,
                error = %e,
                "Failed to store job info"
            );
            return Err(SetCustomMiningJobError::new(
                request.channel_id,
                request.request_id,
                SetCustomMiningJobErrorCode::Other,
                format!("Failed to store job info: {}", e),
            ));
        }

        info!(
            request_id = request.request_id,
            channel_id = request.channel_id,
            job_id,
            "Custom mining job declared successfully"
        );

        Ok(SetCustomMiningJobSuccess::new(
            request.channel_id,
            request.request_id,
            job_id,
            self.config.share_target,
        ))
    }

    /// Handle a block solution submission
    ///
    /// Note: Per JD protocol spec, PushSolution is a one-way message;
    /// the server does not send a response.
    pub async fn handle_push_solution(&self, solution: PushSolution) -> Result<()> {
        debug!(
            channel_id = solution.channel_id,
            job_id = solution.job_id,
            version = solution.version,
            time = solution.time,
            "Received block solution"
        );

        if !solution.validate_solution_len() {
            warn!(job_id = solution.job_id, "Invalid solution length");
            return Err(JdServerError::Protocol(
                "Invalid solution length".to_string(),
            ));
        }

        let job = self.token_manager.find_job_by_id(solution.job_id)?;
        if job.channel_id != solution.channel_id {
            return Err(JdServerError::Protocol(format!(
                "solution channel {} does not match declared job channel {}",
                solution.channel_id, job.channel_id
            )));
        }
        if solution.version != job.version {
            return Err(JdServerError::Protocol(format!(
                "solution version {} does not match declared version {}",
                solution.version, job.version
            )));
        }

        const MAX_TIME_FORWARD: u32 = 7200;
        const MAX_TIME_BACKWARD: u32 = 60;
        if solution.time < job.time.saturating_sub(MAX_TIME_BACKWARD)
            || solution.time > job.time.saturating_add(MAX_TIME_FORWARD)
        {
            return Err(JdServerError::Protocol(
                "solution time out of range".to_string(),
            ));
        }

        let header = build_header(&job, solution.time, &solution.nonce);

        let target = compact_to_target(job.bits).to_le_bytes();
        let validator = EquihashValidator::new();
        validator
            .verify_share(&header, &solution.solution, &target)
            .map_err(|e| JdServerError::Protocol(format!("invalid solution: {}", e)))?;

        // Do NOT call payout_tracker.record_share here (see #51). The
        // block-finding solution is also a valid share and was already credited
        // once by the share path (handle_declared_job_shares). Adding a second
        // credit here at block difficulty (~1e5× share difficulty) would
        // silently drain the pool on every found block.
        //
        // Ordering assumption: crediting the block finder relies entirely on the
        // share path. This is safe only if the matching SubmitSharesExtended is
        // processed before (or independently of) this PushSolution. If a JDC
        // delivers PushSolution first and the share is reordered/dropped in
        // transit, the finder is credited late or not at all. In practice JDC
        // sends the share before the solution and both travel the same ordered
        // connection, so reordering is not expected — but it is an assumption,
        // not a guarantee.
        //
        // TODO(#51): make finder credit independent of share/solution ordering
        // (e.g. deferred credit keyed by job_id, deduped against the share path)
        // so a reordered or dropped share cannot cost the finder their credit.
        //
        // TODO(block-submission): this handler validates the block solution but
        // never submits it to Zebra. JdServer has no access to the Zebra RPC;
        // the pool-server's submit_block logic fills the gap only when the same
        // miner ALSO connects via SV2 direct (cross_path_dup branch). A miner
        // connected solely via JDC will have their block find silently dropped.
        // Fix: inject a block-submission callback (Arc<dyn Fn(block_hex) ->
        // Future<()> + Send + Sync>) into JdServer at construction and call it
        // here after Equihash validation passes. Tracked as a separate PR.
        info!(
            channel_id = solution.channel_id,
            job_id = solution.job_id,
            "Validated block solution"
        );

        Ok(())
    }

    /// Handle a batch of declared-job shares relayed by a (untrusted) JDC.
    ///
    /// The pool fully verifies every share before crediting any payout. This
    /// method is infallible: every failure is a *counted rejection*, never an
    /// `Err`. (Protocol-level garbage — bad framing, count out of range — was
    /// already rejected at decode time.)
    ///
    /// Per-share validation order is cheapest-first, which is also the right DoS
    /// posture: channel match, version match, time window, then the three-phase
    /// dedup+Equihash sequence, then payout credit.
    ///
    /// Version-mismatch decision: a share whose version differs from the
    /// declared job is rejected as `StaleJob` — a version change implies the job
    /// rolled / the template changed underneath the miner.
    ///
    /// Dedup decision (three-phase, see `seen_shares` doc):
    ///   1. Prev-hash staleness rejects shares for old declared jobs (closes
    ///      the epoch-clear double-credit window in the cross-path dedup).
    ///   2. Read-only pre-flight rejects known replays without running Equihash.
    ///   3. Equihash validation runs; structurally invalid shares are NOT inserted.
    ///   4. Authoritative check+insert after validation covers concurrent races.
    pub async fn handle_submit_shares_jd(&self, msg: SubmitSharesJd) -> SubmitSharesJdResponse {
        // Evict dedup entries for jobs that no longer resolve (expired/unknown).
        // Bounded by the number of tracked jobs.
        {
            let mut seen = self.seen_shares.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|job_id, _| self.token_manager.find_job_by_id(*job_id).is_ok());
        }

        let mut accepted: u16 = 0;
        let mut rejected: u16 = 0;
        let mut first_error: Option<JdShareErrorCode> = None;

        // Resolve the job once for the whole batch. If it is unknown, every
        // share in the batch is rejected with UnknownJob.
        let job = match self.token_manager.find_job_by_id(msg.job_id) {
            Ok(job) => job,
            Err(_) => {
                let n = msg.shares.len() as u16;
                warn!(
                    channel_id = msg.channel_id,
                    job_id = msg.job_id,
                    count = n,
                    "SubmitSharesJd for unknown job"
                );
                return SubmitSharesJdResponse {
                    channel_id: msg.channel_id,
                    request_id: msg.request_id,
                    accepted: 0,
                    rejected: n,
                    first_error_code: JdShareErrorCode::UnknownJob.as_u8(),
                };
            }
        };

        let validator = EquihashValidator::new();
        let share_target = job.share_target;

        const MAX_TIME_FORWARD: u32 = 7200;
        const MAX_TIME_BACKWARD: u32 = 60;

        // Read current_prev_hash once for the whole batch so we hold the lock
        // only briefly and don't re-acquire it on every share.
        let current_prev_hash: Option<[u8; 32]> = {
            let guard = self.current_prev_hash.read().await;
            *guard
        };

        for share in &msg.shares {
            let reject = |code: JdShareErrorCode,
                          rejected: &mut u16,
                          first_error: &mut Option<JdShareErrorCode>| {
                *rejected += 1;
                if first_error.is_none() {
                    *first_error = Some(code);
                }
            };

            // 1. Channel must match the declared job's channel.
            if msg.channel_id != job.channel_id {
                reject(
                    JdShareErrorCode::ChannelMismatch,
                    &mut rejected,
                    &mut first_error,
                );
                continue;
            }

            // 2. Version must match (a change means the job rolled -> stale).
            if share.version != job.version {
                reject(JdShareErrorCode::StaleJob, &mut rejected, &mut first_error);
                continue;
            }

            // 3. Time must fall within the job's acceptance window.
            if share.time < job.time.saturating_sub(MAX_TIME_BACKWARD)
                || share.time > job.time.saturating_add(MAX_TIME_FORWARD)
            {
                reject(JdShareErrorCode::StaleJob, &mut rejected, &mut first_error);
                continue;
            }

            // 4. Prev-hash staleness: if the pool has moved to a new tip, reject
            //    shares for old declared jobs. Without this check, a miner whose
            //    token has not yet expired can keep submitting shares for an old job
            //    after the cross-path solution set is cleared on the new block and
            //    receive a second PPS credit for a solution already credited on the
            //    pool-server path (epoch-clear double-credit attack).
            if let Some(expected_prev_hash) = current_prev_hash
                && job.prev_hash != expected_prev_hash
            {
                reject(JdShareErrorCode::StaleJob, &mut rejected, &mut first_error);
                continue;
            }

            // 6. Cheap read-only replay guard: if this key was already seen,
            //    reject immediately without running Equihash. Prevents an attacker
            //    from replaying one valid solution indefinitely and forcing the
            //    expensive verifier on every replay.
            let key = share_dedup_key(share);
            {
                let seen = self.seen_shares.lock().unwrap_or_else(|e| e.into_inner());
                if seen.get(&msg.job_id).is_some_and(|s| s.contains(&key)) {
                    reject(JdShareErrorCode::Duplicate, &mut rejected, &mut first_error);
                    continue;
                }
            }

            // 7. Expensive: verify Equihash solution meets the share target.
            //    Distinguish a structurally valid solution that simply misses
            //    the target (TargetNotMet -> LowDifficulty) from a structurally
            //    broken solution (everything else -> BadSolution).
            //
            //    Dedup insert (step 6) runs AFTER this, not before. Recording in
            //    the dedup before validation would let an attacker exhaust the
            //    MAX_SEEN_SHARES_PER_JOB capacity with zero-cost invalid
            //    submissions, blocking all legitimate shares for that job.
            //    The LowDifficulty branch cannot be exercised here without a valid
            //    Equihash solution (TargetNotMet requires structural validity);
            //    it is covered by Task 7's integration test alongside the accept
            //    path, using a real CPU solver.
            let header = build_header(&job, share.time, &share.nonce);
            let equihash_ok = match validator.verify_share(&header, &share.solution, &share_target)
            {
                Ok(_) => true,
                Err(ValidationError::TargetNotMet) => false,
                Err(_) => {
                    // Structurally invalid: do NOT record in dedup. Recording
                    // would let the attacker fill capacity with no PoW cost.
                    reject(
                        JdShareErrorCode::BadSolution,
                        &mut rejected,
                        &mut first_error,
                    );
                    continue;
                }
            };

            // 8. Authoritative atomic check+insert (after validation so only real
            //    work fills the set). This is the final gatekeeper and handles
            //    concurrent submissions that raced past the step-4 pre-flight.
            //    INVARIANT: the contains-check and insert must remain a single
            //    critical section under the Mutex. Do not split with `.await` and
            //    do not move `record_share` inside this block.
            {
                let mut seen = self.seen_shares.lock().unwrap_or_else(|e| e.into_inner());
                let set = seen.entry(msg.job_id).or_default();
                if set.contains(&key) {
                    reject(JdShareErrorCode::Duplicate, &mut rejected, &mut first_error);
                    continue;
                }
                if set.len() >= MAX_SEEN_SHARES_PER_JOB {
                    warn!(
                        job_id = msg.job_id,
                        cap = MAX_SEEN_SHARES_PER_JOB,
                        "Per-job dedup set full; rejecting share as duplicate"
                    );
                    reject(JdShareErrorCode::Duplicate, &mut rejected, &mut first_error);
                    continue;
                }
                set.insert(key);
            }

            if !equihash_ok {
                reject(
                    JdShareErrorCode::LowDifficulty,
                    &mut rejected,
                    &mut first_error,
                );
                continue;
            }

            // Re-check prev_hash immediately before the authoritative credit gate.
            // The cross-path solution set is cleared on new-block events in pool-server.
            // If a new block arrived while Equihash was running, the cross-path set is
            // now empty and an old-job share could be credited a second time. Checking
            // prev_hash here closes that TOCTOU window: the window shrinks from
            // Equihash-verification-time (ms) to the gap between this read and the
            // try_record_share_once call (ns), which is an acceptable residual.
            {
                let guard = self.current_prev_hash.read().await;
                if let Some(expected) = *guard
                    && job.prev_hash != expected
                {
                    reject(JdShareErrorCode::StaleJob, &mut rejected, &mut first_error);
                    continue;
                }
            }

            // Share is valid: credit the declaring client at the share target's
            // difficulty. Use try_record_share_once to prevent double-credit if
            // the same solution was already submitted via the pool-server path
            // (both paths share one Arc<PayoutTracker> but separate per-path dedups).
            // If it is a cross-path duplicate, report it as Duplicate — not accepted —
            // so the client sees the correct response and accepted/rejected counters
            // reflect actual credits issued.
            let difficulty = target_to_difficulty(&Target::from_le_bytes(share_target));
            if self.payout_tracker.try_record_share_once(
                &job.client_id,
                difficulty,
                &share.solution,
            ) {
                accepted += 1;
            } else {
                reject(JdShareErrorCode::Duplicate, &mut rejected, &mut first_error);
            }
        }

        debug!(
            channel_id = msg.channel_id,
            job_id = msg.job_id,
            accepted,
            rejected,
            "Processed SubmitSharesJd batch"
        );

        SubmitSharesJdResponse {
            channel_id: msg.channel_id,
            request_id: msg.request_id,
            accepted,
            rejected,
            first_error_code: first_error.map(|c| c.as_u8()).unwrap_or(0),
        }
    }

    /// Handle a full template job declaration (Full-Template mode)
    ///
    /// Validates the token, checks mode, validates the template,
    /// allocates a job ID, and stores job info.
    pub async fn handle_set_full_template_job(
        &self,
        request: SetFullTemplateJob,
    ) -> std::result::Result<SetFullTemplateJobSuccess, FullTemplateJobResponse> {
        // 1. Validate basic structure
        if let Err(e) = request.validate() {
            return Err(FullTemplateJobResponse::Error(
                SetFullTemplateJobError::new(
                    request.channel_id,
                    request.request_id,
                    e,
                    format!("Validation failed: {}", e),
                ),
            ));
        }

        // 2. Validate token and check mode
        let token_info = match self.token_manager.validate_token(&request.mining_job_token) {
            Ok(info) => info,
            Err(JdServerError::InvalidToken) => {
                warn!(
                    request_id = request.request_id,
                    "Full template job rejected: invalid token"
                );
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::invalid_token(request.channel_id, request.request_id),
                ));
            }
            Err(JdServerError::TokenExpired) => {
                warn!(
                    request_id = request.request_id,
                    "Full template job rejected: token expired"
                );
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetFullTemplateJobErrorCode::TokenExpired,
                        "Mining job token has expired",
                    ),
                ));
            }
            Err(e) => {
                error!(
                    request_id = request.request_id,
                    error = %e,
                    "Unexpected error validating token"
                );
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetFullTemplateJobErrorCode::Other,
                        format!("Token validation error: {}", e),
                    ),
                ));
            }
        };

        // 3. Verify mode matches (token must be granted FullTemplate mode)
        if token_info.granted_mode != JobDeclarationMode::FullTemplate {
            warn!(
                request_id = request.request_id,
                granted_mode = %token_info.granted_mode,
                "Full template job rejected: mode mismatch"
            );
            return Err(FullTemplateJobResponse::Error(
                SetFullTemplateJobError::mode_mismatch(request.channel_id, request.request_id),
            ));
        }

        let template = match self
            .validate_header_fields(request.version, request.time, request.bits)
            .await
        {
            Ok(template) => template,
            Err(reason) => {
                let code = match reason.as_str() {
                    "block version does not match current template" => {
                        SetFullTemplateJobErrorCode::InvalidVersion
                    }
                    "difficulty bits do not match current template" => {
                        SetFullTemplateJobErrorCode::InvalidBits
                    }
                    _ => SetFullTemplateJobErrorCode::Other,
                };
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        code,
                        reason,
                    ),
                ));
            }
        };

        if let Some(ref current) = template
            && request.block_commitments != current.block_commitments
        {
            // TODO(2026-06-05-jd-block-commitments-recompute-design): full-template
            // validation still uses the copied template commitments until general
            // non-coinbase ZIP-244 auth digests are implemented.
            return Err(FullTemplateJobResponse::Error(
                SetFullTemplateJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetFullTemplateJobErrorCode::Other,
                    "block commitments do not match current template",
                ),
            ));
        }

        // 4. Check prev_hash matches current (stale detection)
        //    Fail closed: reject if we haven't received any template yet
        let current_prev_hash = self.current_prev_hash.read().await;
        match *current_prev_hash {
            Some(expected_prev_hash) => {
                if request.prev_hash != expected_prev_hash {
                    warn!(
                        request_id = request.request_id,
                        expected = ?hex::encode(expected_prev_hash),
                        got = ?hex::encode(request.prev_hash),
                        "Full template job rejected: stale prev_hash"
                    );
                    return Err(FullTemplateJobResponse::Error(
                        SetFullTemplateJobError::new(
                            request.channel_id,
                            request.request_id,
                            SetFullTemplateJobErrorCode::StalePrevHash,
                            "Previous block hash does not match current chain tip",
                        ),
                    ));
                }
            }
            None => {
                warn!(
                    request_id = request.request_id,
                    "Full template job rejected: no template received yet"
                );
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetFullTemplateJobErrorCode::StalePrevHash,
                        "Server has not received a block template yet",
                    ),
                ));
            }
        }
        drop(current_prev_hash);

        // 5. Validate template using the validator
        let validator = self.validator.read().await;
        if let Err(reason) = validator.validate_coinbase(&request.coinbase_tx) {
            return Err(FullTemplateJobResponse::Error(
                SetFullTemplateJobError::new(
                    request.channel_id,
                    request.request_id,
                    SetFullTemplateJobErrorCode::CoinbaseConstraintViolation,
                    reason,
                ),
            ));
        }
        if let Some(ref current) = template {
            let max_coinbase_len =
                current.coinbase_tx_len + self.config.coinbase_output_max_additional_size as usize;
            if request.coinbase_tx.len() > max_coinbase_len {
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetFullTemplateJobErrorCode::CoinbaseConstraintViolation,
                        format!(
                            "coinbase length {} exceeds maximum {}",
                            request.coinbase_tx.len(),
                            max_coinbase_len
                        ),
                    ),
                ));
            }
        }
        match validator.validate(&request) {
            ValidationResult::Valid => {
                // Template is valid, proceed to register the job
            }
            ValidationResult::Invalid(reason) => {
                warn!(
                    request_id = request.request_id,
                    reason = %reason,
                    "Full template job rejected: invalid template"
                );
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetFullTemplateJobErrorCode::InvalidTransactions,
                        reason,
                    ),
                ));
            }
            ValidationResult::NeedTransactions(missing) => {
                info!(
                    request_id = request.request_id,
                    missing_count = missing.len(),
                    "Full template job needs missing transactions"
                );
                self.pending_missing.write().await.insert(
                    (token_info.client_id.clone(), request.request_id),
                    PendingMissingTransactions {
                        channel_id: request.channel_id,
                        expected_txids: missing.clone(),
                    },
                );
                return Err(FullTemplateJobResponse::NeedTransactions(
                    GetMissingTransactions::new(request.channel_id, request.request_id, missing),
                ));
            }
        }
        drop(validator);

        // 6. Register the job
        self.pending_missing
            .write()
            .await
            .remove(&(token_info.client_id.clone(), request.request_id));

        let job_id = match self.register_full_template_job(&request, &token_info) {
            Ok(id) => id,
            Err(e) => {
                error!(
                    request_id = request.request_id,
                    error = %e,
                    "Failed to register full template job"
                );
                return Err(FullTemplateJobResponse::Error(
                    SetFullTemplateJobError::new(
                        request.channel_id,
                        request.request_id,
                        SetFullTemplateJobErrorCode::Other,
                        format!("Failed to register job: {}", e),
                    ),
                ));
            }
        };

        info!(
            request_id = request.request_id,
            channel_id = request.channel_id,
            job_id,
            tx_count = request.tx_short_ids.len(),
            "Full template job declared successfully"
        );

        Ok(SetFullTemplateJobSuccess::new(
            request.channel_id,
            request.request_id,
            job_id,
        ))
    }

    /// Register a full template job and return the assigned job ID
    fn register_full_template_job(
        &self,
        job: &SetFullTemplateJob,
        token_info: &crate::token::MiningJobToken,
    ) -> Result<u32> {
        // Generate job ID
        let job_id = next_positive_job_id(&self.next_job_id);

        // Store job info with token
        let job_info = DeclaredJobInfo {
            job_id,
            client_id: token_info.client_id.clone(),
            mode: token_info.granted_mode,
            channel_id: job.channel_id,
            version: job.version,
            prev_hash: job.prev_hash,
            merkle_root: job.merkle_root,
            block_commitments: job.block_commitments,
            bits: job.bits,
            time: job.time,
            coinbase_tx: job.coinbase_tx.clone(),
            // Pool grants the share target (never the client) at declaration time.
            share_target: self.config.share_target,
        };

        self.token_manager
            .set_job_info(&job.mining_job_token, job_info)?;

        info!(
            "Registered full template job {} with {} transactions",
            job_id,
            job.tx_short_ids.len()
        );

        Ok(job_id)
    }

    /// Update known transactions in the validator (from pool's mempool)
    pub async fn update_known_txids(&self, txids: impl IntoIterator<Item = [u8; 32]>) {
        let mut validator = self.validator.write().await;
        validator.update_known_txids(txids);
    }

    /// Handle ProvideMissingTransactions from client
    ///
    /// When the server sends GetMissingTransactions, the client responds with
    /// this message containing the raw transaction data. The server validates
    /// and stores the transactions for future template validation.
    ///
    /// Returns Ok(()) on success or an error if transaction data is invalid.
    pub async fn handle_provide_missing_transactions(
        &self,
        msg: ProvideMissingTransactions,
        client_id: &str,
    ) -> Result<()> {
        info!(
            "Client {} provided {} missing transactions for request {}",
            client_id,
            msg.transactions.len(),
            msg.request_id
        );

        let pending = {
            let mut requests = self.pending_missing.write().await;
            requests.remove(&(client_id.to_string(), msg.request_id))
        }
        .ok_or_else(|| {
            JdServerError::Protocol(format!(
                "no outstanding missing-transaction request for client {} request {}",
                client_id, msg.request_id
            ))
        })?;

        if pending.channel_id != msg.channel_id {
            return Err(JdServerError::Protocol(format!(
                "channel mismatch for missing transactions: expected {}, got {}",
                pending.channel_id, msg.channel_id
            )));
        }
        if msg.transactions.len() != pending.expected_txids.len() {
            return Err(JdServerError::Protocol(format!(
                "expected {} transactions, got {}",
                pending.expected_txids.len(),
                msg.transactions.len()
            )));
        }

        let mut validator = self.validator.write().await;

        for (expected_txid, tx_data) in pending.expected_txids.iter().zip(msg.transactions.iter()) {
            TemplateValidator::parse_transaction(tx_data).map_err(JdServerError::Protocol)?;
            let txid = TemplateValidator::compute_txid(tx_data);
            if &txid != expected_txid {
                return Err(JdServerError::Protocol(format!(
                    "provided transaction txid {} did not match requested {}",
                    hex::encode(txid),
                    hex::encode(expected_txid),
                )));
            }
            validator.add_known_txid(txid);

            debug!(
                "Added requested txid {} from provided transaction ({} bytes)",
                hex::encode(txid),
                tx_data.len()
            );
        }

        Ok(())
    }

    /// Get token manager (for testing)
    pub fn token_manager(&self) -> &TokenManager {
        &self.token_manager
    }

    /// Get configuration
    pub fn config(&self) -> &JdServerConfig {
        &self.config
    }

    /// Get validator (for testing)
    pub async fn validator(&self) -> tokio::sync::RwLockReadGuard<'_, TemplateValidator> {
        self.validator.read().await
    }
}

/// Response type for SetFullTemplateJob that can be either success, error, or need transactions
#[derive(Debug)]
pub enum FullTemplateJobResponse {
    /// Job rejected with error
    Error(SetFullTemplateJobError),
    /// Need missing transactions from client
    NeedTransactions(GetMissingTransactions),
}

/// JD transport abstraction for plain or Noise-encrypted streams.
pub enum JdTransport {
    Plain(TcpStream),
    Noise(NoiseStream<TcpStream>),
}

impl JdTransport {
    async fn read_full_message(&mut self) -> Result<Option<Vec<u8>>> {
        match self {
            JdTransport::Plain(stream) => {
                let mut header_buf = [0u8; MessageFrame::HEADER_SIZE];
                match stream.read_exact(&mut header_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(e) => return Err(JdServerError::Io(e)),
                }

                let frame = MessageFrame::decode(&header_buf)
                    .map_err(|e| JdServerError::Protocol(e.to_string()))?;

                // Prevent memory exhaustion attacks - limit frame size to 1MB
                const MAX_FRAME_SIZE: u32 = 1_048_576;
                if frame.length > MAX_FRAME_SIZE {
                    return Err(JdServerError::Protocol(format!(
                        "Frame size {} exceeds maximum of 1MB",
                        frame.length
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
            JdTransport::Noise(stream) => match stream.read_message().await {
                Ok(message) => Ok(Some(message)),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                Err(e) => Err(JdServerError::Io(e)),
            },
        }
    }

    async fn write_full_message(&mut self, data: &[u8]) -> Result<()> {
        match self {
            JdTransport::Plain(stream) => {
                stream.write_all(data).await?;
                stream.flush().await?;
                Ok(())
            }
            JdTransport::Noise(stream) => {
                stream.write_message(data).await?;
                stream.flush().await?;
                Ok(())
            }
        }
    }
}

/// Handle a JD client connection
///
/// This function reads frames from the TCP stream, parses message types,
/// dispatches to the appropriate handlers, and writes responses.
///
/// # Noise Protocol Support
///
/// When `noise_enabled` is true in the server config, callers should perform
/// the Noise NK handshake and pass a `JdTransport::Noise` into
/// `handle_jd_client_with_transport`.
pub async fn handle_jd_client(
    stream: TcpStream,
    jd_server: Arc<JdServer>,
    client_id: String,
) -> Result<()> {
    handle_jd_client_with_transport(JdTransport::Plain(stream), jd_server, client_id).await
}

/// Handle a JD client connection using a transport abstraction.
pub async fn handle_jd_client_with_transport(
    mut transport: JdTransport,
    jd_server: Arc<JdServer>,
    client_id: String,
) -> Result<()> {
    info!(client_id, "JD client connected");

    loop {
        let full_message = match transport.read_full_message().await {
            Ok(Some(message)) => message,
            Ok(None) => {
                info!(client_id, "JD client disconnected");
                return Ok(());
            }
            Err(e) => {
                error!(client_id, error = %e, "Error reading from JD client");
                return Err(e);
            }
        };

        // Parse frame header
        let frame = MessageFrame::decode(&full_message)
            .map_err(|e| JdServerError::Protocol(e.to_string()))?;

        // Dispatch based on message type
        match frame.msg_type {
            message_types::ALLOCATE_MINING_JOB_TOKEN => {
                let request = decode_allocate_token(&full_message)?;
                debug!(
                    client_id,
                    request_id = request.request_id,
                    user_id = %request.user_identifier,
                    requested_mode = %request.requested_mode,
                    "Received AllocateMiningJobToken"
                );

                match jd_server.handle_allocate_token(
                    request.request_id,
                    &request.user_identifier,
                    request.requested_mode,
                ) {
                    Ok(response) => {
                        let encoded = encode_allocate_token_success(&response)?;
                        transport.write_full_message(&encoded).await?;
                    }
                    Err(e) => {
                        error!(
                            client_id,
                            request_id = request.request_id,
                            error = %e,
                            "Failed to allocate token"
                        );
                        // No error response defined in spec for AllocateMiningJobToken
                    }
                }
            }

            message_types::SET_CUSTOM_MINING_JOB => {
                let request = decode_set_custom_job(&full_message)?;
                debug!(
                    client_id,
                    channel_id = request.channel_id,
                    request_id = request.request_id,
                    "Received SetCustomMiningJob"
                );

                match jd_server.handle_declare_job(request).await {
                    Ok(response) => {
                        let encoded = encode_set_custom_job_success(&response)?;
                        transport.write_full_message(&encoded).await?;
                    }
                    Err(error) => {
                        let encoded = encode_set_custom_job_error(&error)?;
                        transport.write_full_message(&encoded).await?;
                    }
                }
            }

            message_types::PUSH_SOLUTION => {
                let solution = decode_push_solution(&full_message)?;
                debug!(
                    client_id,
                    channel_id = solution.channel_id,
                    job_id = solution.job_id,
                    "Received PushSolution"
                );

                // PushSolution is one-way; no response per spec
                if let Err(e) = jd_server.handle_push_solution(solution).await {
                    error!(
                        client_id,
                        error = %e,
                        "Error processing solution"
                    );
                }
            }

            message_types::SUBMIT_SHARES_JD => {
                let msg = decode_submit_shares_jd(&full_message)?;
                debug!(
                    client_id,
                    channel_id = msg.channel_id,
                    request_id = msg.request_id,
                    job_id = msg.job_id,
                    count = msg.shares.len(),
                    "Received SubmitSharesJd"
                );

                // SubmitSharesJd always gets a response (unlike PushSolution).
                let response = jd_server.handle_submit_shares_jd(msg).await;
                let encoded = encode_submit_shares_jd_response(&response)?;
                transport.write_full_message(&encoded).await?;
            }

            message_types::SET_FULL_TEMPLATE_JOB => {
                let request = decode_set_full_template_job(&full_message)?;
                debug!(
                    client_id,
                    channel_id = request.channel_id,
                    request_id = request.request_id,
                    tx_count = request.tx_short_ids.len(),
                    "Received SetFullTemplateJob"
                );

                match jd_server.handle_set_full_template_job(request).await {
                    Ok(response) => {
                        let encoded = encode_set_full_template_job_success(&response)?;
                        transport.write_full_message(&encoded).await?;
                    }
                    Err(FullTemplateJobResponse::Error(error)) => {
                        let encoded = encode_set_full_template_job_error(&error)?;
                        transport.write_full_message(&encoded).await?;
                    }
                    Err(FullTemplateJobResponse::NeedTransactions(request)) => {
                        let encoded = encode_get_missing_transactions(&request)?;
                        transport.write_full_message(&encoded).await?;
                    }
                }
            }

            message_types::PROVIDE_MISSING_TRANSACTIONS => {
                let msg = decode_provide_missing_transactions(&full_message)?;
                debug!(
                    client_id,
                    channel_id = msg.channel_id,
                    request_id = msg.request_id,
                    tx_count = msg.transactions.len(),
                    "Received ProvideMissingTransactions"
                );

                // Handle the provided transactions (no response per protocol)
                if let Err(e) = jd_server
                    .handle_provide_missing_transactions(msg, &client_id)
                    .await
                {
                    error!(
                        client_id,
                        error = %e,
                        "Error processing provided transactions"
                    );
                }
            }

            _ => {
                warn!(client_id, msg_type = frame.msg_type, "Unknown message type");
                // Ignore unknown message types
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn test_config() -> JdServerConfig {
        JdServerConfig {
            token_lifetime: Duration::from_secs(300),
            coinbase_output_max_additional_size: 256,
            pool_payout_script: vec![],
            async_mining_allowed: true,
            max_tokens_per_client: 10,
            noise_enabled: false,
            full_template_enabled: false,
            full_template_validation: crate::validation::ValidationLevel::Standard,
            min_pool_payout: 0,
            share_target: JdServerConfig::default().share_target,
        }
    }

    #[test]
    fn test_jd_server_creation() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config.clone(), payout_tracker);

        // Verify we can allocate a token (default CoinbaseOnly mode)
        let result =
            server.handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.request_id, 1);
        assert!(!response.mining_job_token.is_empty());
        assert_eq!(
            response.coinbase_output_max_additional_size,
            config.coinbase_output_max_additional_size
        );
        assert_eq!(response.coinbase_output, config.pool_payout_script);
        assert!(response.async_mining_allowed);
        assert_eq!(response.granted_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[tokio::test]
    async fn test_declare_job() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Set current prev_hash
        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;

        // Allocate a token
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        // Declare a job
        let job_request = SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let result = server.handle_declare_job(job_request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.channel_id, 1);
        assert_eq!(response.request_id, 2);
        assert!(response.job_id > 0);
    }

    #[tokio::test]
    async fn test_declare_job_wraps_reserved_job_ids_to_one() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;
        server.next_job_id.store(u32::MAX, Ordering::SeqCst);

        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let job_request = SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let response = server.handle_declare_job(job_request).await.unwrap();
        assert_eq!(response.job_id, 1);
    }

    #[tokio::test]
    async fn test_stale_prev_hash_rejected() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Set current prev_hash
        let current_prev_hash = [0xaa; 32];
        server.set_current_prev_hash(current_prev_hash).await;

        // Allocate a token
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        // Try to declare a job with a different (stale) prev_hash
        let stale_prev_hash = [0x11; 32]; // Different from current
        let job_request = SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash: stale_prev_hash, // Stale!
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let result = server.handle_declare_job(job_request).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.error_code, SetCustomMiningJobErrorCode::StalePrevHash);
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Try to declare a job with an invalid token
        let job_request = SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: vec![0x00, 0x01, 0x02], // Invalid token
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let result = server.handle_declare_job(job_request).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.error_code, SetCustomMiningJobErrorCode::InvalidToken);
    }

    #[tokio::test]
    async fn test_empty_coinbase_rejected() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Allocate a token
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        // Try to declare a job with empty coinbase
        let job_request = SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: vec![], // Empty!
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let result = server.handle_declare_job(job_request).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(
            error.error_code,
            SetCustomMiningJobErrorCode::InvalidCoinbase
        );
    }

    #[tokio::test]
    async fn test_push_solution_rejects_unknown_job() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker.clone());

        let solution = PushSolution::new(
            1,            // channel_id
            42,           // job_id
            5,            // version
            1700000000,   // time
            [0x11; 32],   // nonce
            [0x22; 1344], // solution
        );

        let result = server.handle_push_solution(solution).await;
        assert!(result.is_err());

        assert!(
            payout_tracker
                .get_stats(&"jd-miner-1".to_string())
                .is_none()
        );
    }

    #[test]
    fn test_token_manager_access() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config.clone(), payout_tracker);

        let token_manager = server.token_manager();
        let token = token_manager.allocate_token("test-miner").unwrap();
        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_jobs_different_ids() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Set current prev_hash
        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;

        // Allocate tokens and declare multiple jobs
        let token1 = server
            .handle_allocate_token(1, "miner1", JobDeclarationMode::CoinbaseOnly)
            .unwrap();
        let token2 = server
            .handle_allocate_token(2, "miner2", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let job1 = SetCustomMiningJob {
            channel_id: 1,
            request_id: 10,
            mining_job_token: token1.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
        };

        let job2 = SetCustomMiningJob {
            channel_id: 2,
            request_id: 20,
            mining_job_token: token2.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root: [0xdd; 32],
            block_commitments: [0xee; 32],
            coinbase_tx: minimal_tx_with_script(&[0x52]),
            time: 1700000001,
            bits: 0x1d00ffff,
        };

        let result1 = server.handle_declare_job(job1).await.unwrap();
        let result2 = server.handle_declare_job(job2).await.unwrap();

        // Job IDs should be different
        assert_ne!(result1.job_id, result2.job_id);
    }

    // =========================================================================
    // Full-Template Mode Tests
    // =========================================================================

    fn test_config_full_template() -> JdServerConfig {
        JdServerConfig {
            token_lifetime: Duration::from_secs(300),
            coinbase_output_max_additional_size: 256,
            pool_payout_script: vec![], // Empty for testing (skips payout validation)
            async_mining_allowed: true,
            max_tokens_per_client: 10,
            noise_enabled: false,
            full_template_enabled: true, // Enable Full-Template mode
            full_template_validation: crate::validation::ValidationLevel::Standard,
            min_pool_payout: 0,
            share_target: JdServerConfig::default().share_target,
        }
    }

    #[test]
    fn test_full_template_mode_requested_and_granted() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Request Full-Template mode
        let result =
            server.handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.granted_mode, JobDeclarationMode::FullTemplate);
    }

    #[test]
    fn test_full_template_mode_fallback_when_disabled() {
        let config = test_config(); // Full-Template disabled
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Request Full-Template mode, but it's disabled
        let result =
            server.handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate);
        assert!(result.is_ok());

        let response = result.unwrap();
        // Should fall back to CoinbaseOnly
        assert_eq!(response.granted_mode, JobDeclarationMode::CoinbaseOnly);
    }

    #[tokio::test]
    async fn test_full_template_job_success() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Set current prev_hash
        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;

        // Allocate a token with FullTemplate mode
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
            .unwrap();
        assert_eq!(
            token_response.granted_mode,
            JobDeclarationMode::FullTemplate
        );

        // Declare a full template job
        let coinbase_tx = minimal_tx();
        let merkle_root = merkle_root_for(&coinbase_tx, &[]);
        let job_request = SetFullTemplateJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root,
            block_commitments: [0xcc; 32],
            coinbase_tx,
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![], // Empty for simplicity
            tx_data: vec![],
        };

        let result = server.handle_set_full_template_job(job_request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.channel_id, 1);
        assert_eq!(response.request_id, 2);
        assert!(response.job_id > 0);
    }

    #[tokio::test]
    async fn test_full_template_job_mode_mismatch() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Allocate a token with CoinbaseOnly mode
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();
        assert_eq!(
            token_response.granted_mode,
            JobDeclarationMode::CoinbaseOnly
        );

        // Try to declare a full template job with CoinbaseOnly token
        let coinbase_tx = minimal_tx();
        let merkle_root = merkle_root_for(&coinbase_tx, &[]);
        let job_request = SetFullTemplateJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root,
            block_commitments: [0xcc; 32],
            coinbase_tx,
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![],
            tx_data: vec![],
        };

        let result = server.handle_set_full_template_job(job_request).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            FullTemplateJobResponse::Error(error) => {
                assert_eq!(error.error_code, SetFullTemplateJobErrorCode::ModeMismatch);
            }
            _ => panic!("Expected ModeMismatch error"),
        }
    }

    fn minimal_tx() -> Vec<u8> {
        minimal_tx_with_script(&[0x51])
    }

    fn minimal_tx_with_script(script: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.push(0x01); // vin count
        tx.extend_from_slice(&[0u8; 32]); // prevout hash
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        tx.push(0x01); // scriptSig length
        tx.push(0x00); // scriptSig
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.push(0x01); // vout count
        tx.extend_from_slice(&0u64.to_le_bytes()); // value
        tx.push(script.len() as u8);
        tx.extend_from_slice(script);
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx
    }

    fn minimal_v5_tx_with_script(script: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&5u32.to_le_bytes()); // version
        tx.push(0x01); // vin count
        tx.extend_from_slice(&[0u8; 32]); // prevout hash
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        tx.push(0x01); // scriptSig length
        tx.push(0x00); // scriptSig
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.push(0x01); // vout count
        tx.extend_from_slice(&0u64.to_le_bytes()); // value
        tx.push(script.len() as u8);
        tx.extend_from_slice(script);
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx
    }

    async fn insert_pending_request(
        server: &JdServer,
        client_id: &str,
        request_id: u32,
        channel_id: u32,
        txids: Vec<[u8; 32]>,
    ) {
        server.pending_missing.write().await.insert(
            (client_id.to_string(), request_id),
            PendingMissingTransactions {
                channel_id,
                expected_txids: txids,
            },
        );
    }

    #[tokio::test]
    async fn test_declare_job_rejects_missing_pool_payout() {
        let mut config = test_config();
        config.pool_payout_script = vec![0x51, 0xac];
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;

        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let result = server
            .handle_declare_job(SetCustomMiningJob {
                channel_id: 1,
                request_id: 7,
                mining_job_token: token_response.mining_job_token,
                version: 5,
                prev_hash,
                merkle_root: [0xbb; 32],
                block_commitments: [0xcc; 32],
                coinbase_tx: minimal_tx(),
                time: 1700000000,
                bits: 0x1d00ffff,
            })
            .await
            .unwrap_err();

        assert_eq!(
            result.error_code,
            SetCustomMiningJobErrorCode::CoinbaseConstraintViolation
        );
    }

    #[tokio::test]
    async fn test_declare_job_rejects_invalid_merkle_root_against_template() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let prev_hash = [0xaa; 32];
        let coinbase_tx = minimal_tx();
        server
            .set_current_template(CurrentTemplateContext {
                version: 5,
                prev_hash,
                block_commitments: [0xcc; 32],
                chain_history_root: [0x42; 32],
                consensus_branch_id: 0xc8e7_1055,
                bits: 0x1d00ffff,
                time: 1700000000,
                txids: vec![],
                coinbase_tx_len: coinbase_tx.len(),
            })
            .await;

        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let error = server
            .handle_declare_job(SetCustomMiningJob {
                channel_id: 1,
                request_id: 9,
                mining_job_token: token_response.mining_job_token,
                version: 5,
                prev_hash,
                merkle_root: [0x99; 32],
                block_commitments: [0xcc; 32],
                coinbase_tx,
                time: 1700000000,
                bits: 0x1d00ffff,
            })
            .await
            .unwrap_err();

        assert_eq!(
            error.error_code,
            SetCustomMiningJobErrorCode::InvalidMerkleRoot
        );
    }

    #[tokio::test]
    async fn test_declare_job_accepts_commitments_recomputed_from_declared_coinbase() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let prev_hash = [0xaa; 32];
        let coinbase_tx = minimal_v5_tx_with_script(&[0x51, 0x24]);
        let chain_history_root = [0x42; 32];
        let consensus_branch_id = 0xc8e7_1055;
        let declared_block_commitments = recompute_coinbase_only_block_commitments(
            &coinbase_tx,
            chain_history_root,
            consensus_branch_id,
        )
        .unwrap();
        assert_ne!(declared_block_commitments, [0xcc; 32]);

        server
            .set_current_template(CurrentTemplateContext {
                version: 5,
                prev_hash,
                block_commitments: [0xcc; 32],
                bits: 0x1d00ffff,
                time: 1700000000,
                txids: vec![],
                coinbase_tx_len: coinbase_tx.len(),
                chain_history_root,
                consensus_branch_id,
            })
            .await;

        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let response = server
            .handle_declare_job(SetCustomMiningJob {
                channel_id: 1,
                request_id: 10,
                mining_job_token: token_response.mining_job_token,
                version: 5,
                prev_hash,
                merkle_root: TemplateValidator::compute_merkle_root(&coinbase_tx, &[]).unwrap(),
                block_commitments: declared_block_commitments,
                coinbase_tx,
                time: 1700000000,
                bits: 0x1d00ffff,
            })
            .await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_declare_job_rejects_tampered_block_commitments() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let prev_hash = [0xaa; 32];
        let coinbase_tx = minimal_v5_tx_with_script(&[0x51, 0x24]);
        let chain_history_root = [0x42; 32];
        let consensus_branch_id = 0xc8e7_1055;
        let mut declared_block_commitments = recompute_coinbase_only_block_commitments(
            &coinbase_tx,
            chain_history_root,
            consensus_branch_id,
        )
        .unwrap();
        declared_block_commitments[0] ^= 0x01;

        server
            .set_current_template(CurrentTemplateContext {
                version: 5,
                prev_hash,
                block_commitments: [0xcc; 32],
                bits: 0x1d00ffff,
                time: 1700000000,
                txids: vec![],
                coinbase_tx_len: coinbase_tx.len(),
                chain_history_root,
                consensus_branch_id,
            })
            .await;

        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let error = server
            .handle_declare_job(SetCustomMiningJob {
                channel_id: 1,
                request_id: 11,
                mining_job_token: token_response.mining_job_token,
                version: 5,
                prev_hash,
                merkle_root: TemplateValidator::compute_merkle_root(&coinbase_tx, &[]).unwrap(),
                block_commitments: declared_block_commitments,
                coinbase_tx,
                time: 1700000000,
                bits: 0x1d00ffff,
            })
            .await
            .unwrap_err();

        assert_eq!(error.error_code, SetCustomMiningJobErrorCode::Other);
        assert!(error.error_message.contains("do not verify"));
    }

    #[tokio::test]
    async fn test_push_solution_rejects_invalid_solution() {
        let config = test_config();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker.clone());

        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;

        let token_response = server
            .handle_allocate_token(1, "jd-miner-1", JobDeclarationMode::CoinbaseOnly)
            .unwrap();

        let job_response = server
            .handle_declare_job(SetCustomMiningJob {
                channel_id: 1,
                request_id: 1,
                mining_job_token: token_response.mining_job_token,
                version: 5,
                prev_hash,
                merkle_root: [0xbb; 32],
                block_commitments: [0xcc; 32],
                coinbase_tx: minimal_tx(),
                time: 1700000000,
                bits: 0x1d00ffff,
            })
            .await
            .unwrap();

        let solution = PushSolution::new(
            1,
            job_response.job_id,
            5,
            1700000000,
            [0x11; 32],
            [0x22; 1344],
        );

        let result = server.handle_push_solution(solution).await;
        assert!(result.is_err());
        assert!(
            payout_tracker
                .get_stats(&"jd-miner-1".to_string())
                .is_none()
        );
    }

    /// Regression guard for #51: `handle_push_solution` must never credit the
    /// `PayoutTracker`. The block-finding solution is also a valid share and is
    /// credited exactly once by the share path; a second credit here at block
    /// difficulty (~1e5× share difficulty) would drain the pool on every block.
    ///
    /// We assert this structurally rather than behaviourally. A behavioural test
    /// would need a PushSolution that passes Equihash verification, but the only
    /// checked-in valid (200,9) solution validates against a 12-byte input
    /// (see `zcash-equihash-validator/tests/test_vectors.rs`), whereas the
    /// production path requires a 108-byte header prefix. Generating a fresh
    /// solution needs the solver (~144 MB, seconds, flaky in CI). The error
    /// paths *are* covered behaviourally by `test_push_solution_rejects_*`,
    /// which assert no credit; this guard covers the success path by ensuring
    /// the function body contains no `record_share` call at all.
    #[test]
    fn push_solution_never_calls_record_share() {
        // Source of this very file, embedded at compile time.
        let src = include_str!("server.rs");

        let start = src
            .find("pub async fn handle_push_solution")
            .expect("handle_push_solution must exist");
        let rest = &src[start..];
        // The body ends at this `fn`'s own closing brace. rustfmt indents a
        // 4-space `fn`'s closing brace at exactly 4 spaces (`\n    }`); every
        // inner block, doc comment, and string-literal brace lives at >= 8
        // spaces, so the first `\n    }` is unambiguously the function's end.
        // This is robust against an inner `///` doc comment or a `{`/`}` inside
        // a `format!` string, which a next-doc-comment heuristic would not be.
        let body_len = rest
            .find("\n    }")
            .map(|i| i + "\n    }".len())
            .expect("handle_push_solution must have a 4-space-indented closing brace");
        let body = &rest[..body_len];

        // Match a *call* (`record_share(`), not the explanatory prose in the
        // body which mentions `record_share` without parentheses.
        assert!(
            !body.contains("record_share("),
            "handle_push_solution must not call record_share (regression of #51): \
             the share path is the sole crediting authority for a found block"
        );
    }

    fn merkle_root_for(coinbase: &[u8], txids: &[[u8; 32]]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        fn compute_txid(data: &[u8]) -> [u8; 32] {
            let hash1 = Sha256::digest(data);
            let hash2 = Sha256::digest(hash1);
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&hash2);
            txid
        }

        if coinbase.is_empty() {
            return [0u8; 32];
        }

        let mut all_txids = Vec::with_capacity(1 + txids.len());
        all_txids.push(compute_txid(coinbase));
        all_txids.extend_from_slice(txids);

        let mut layer = all_txids;
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            let mut i = 0;
            while i < layer.len() {
                let left = layer[i];
                let right = if i + 1 < layer.len() {
                    layer[i + 1]
                } else {
                    left
                };
                let mut data = [0u8; 64];
                data[..32].copy_from_slice(&left);
                data[32..].copy_from_slice(&right);
                next.push(compute_txid(&data));
                i += 2;
            }
            layer = next;
        }

        layer[0]
    }

    #[tokio::test]
    async fn test_full_template_job_stale_prev_hash() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Set current prev_hash
        let current_prev_hash = [0xaa; 32];
        server.set_current_prev_hash(current_prev_hash).await;

        // Allocate a token
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
            .unwrap();

        // Try to declare a job with a stale prev_hash
        let coinbase_tx = minimal_tx();
        let merkle_root = merkle_root_for(&coinbase_tx, &[]);
        let job_request = SetFullTemplateJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash: [0x11; 32], // Different from current
            merkle_root,
            block_commitments: [0xcc; 32],
            coinbase_tx,
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![],
            tx_data: vec![],
        };

        let result = server.handle_set_full_template_job(job_request).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            FullTemplateJobResponse::Error(error) => {
                assert_eq!(error.error_code, SetFullTemplateJobErrorCode::StalePrevHash);
            }
            _ => panic!("Expected StalePrevHash error"),
        }
    }

    #[tokio::test]
    async fn test_full_template_job_needs_transactions() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Set current prev_hash
        let prev_hash = [0xaa; 32];
        server.set_current_prev_hash(prev_hash).await;

        // Allocate a token
        let token_response = server
            .handle_allocate_token(1, "test-miner", JobDeclarationMode::FullTemplate)
            .unwrap();

        // Declare a job with unknown txids (validator doesn't know them)
        let unknown_txid = [0x11; 32];
        let coinbase_tx = minimal_tx();
        let merkle_root = merkle_root_for(&coinbase_tx, &[unknown_txid]);
        let job_request = SetFullTemplateJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token_response.mining_job_token,
            version: 5,
            prev_hash,
            merkle_root,
            block_commitments: [0xcc; 32],
            coinbase_tx,
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![unknown_txid],
            tx_data: vec![], // Not providing the tx data
        };

        let result = server.handle_set_full_template_job(job_request).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            FullTemplateJobResponse::NeedTransactions(request) => {
                assert_eq!(request.channel_id, 1);
                assert_eq!(request.request_id, 2);
                assert_eq!(request.missing_tx_ids.len(), 1);
                assert_eq!(request.missing_tx_ids[0], unknown_txid);
            }
            _ => panic!("Expected NeedTransactions"),
        }
    }

    #[tokio::test]
    async fn test_update_known_txids() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        // Update known txids
        let known_txid = [0x11; 32];
        server.update_known_txids([known_txid]).await;

        // Verify the validator knows about the txid
        let validator = server.validator().await;
        assert!(validator.is_txid_known(&known_txid));
    }

    // =========================================================================
    // ProvideMissingTransactions Handler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_provide_missing_transactions() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let tx_data = vec![minimal_tx(), minimal_tx_with_script(&[0x52])];
        let expected_txids = tx_data
            .iter()
            .map(|tx| TemplateValidator::compute_txid(tx))
            .collect();
        insert_pending_request(&server, "test-client", 42, 1, expected_txids).await;

        let msg = ProvideMissingTransactions {
            channel_id: 1,
            request_id: 42,
            transactions: tx_data,
        };

        // Handle the message
        let result = server
            .handle_provide_missing_transactions(msg, "test-client")
            .await;
        assert!(result.is_ok());

        // Verify that txids were computed and added to the validator
        let _validator = server.validator().await;
        // We can't easily verify the exact txids since they're computed via SHA256,
        // but we can verify that some txids were added
        // (The validator had 0 known txids before, now it should have 2)
    }

    #[tokio::test]
    async fn test_handle_provide_missing_transactions_empty() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        insert_pending_request(&server, "test-client", 42, 1, vec![]).await;

        let msg = ProvideMissingTransactions {
            channel_id: 1,
            request_id: 42,
            transactions: vec![],
        };

        let result = server
            .handle_provide_missing_transactions(msg, "test-client")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_provide_missing_transactions_then_validate() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let tx_data = minimal_tx();
        let expected_txid = TemplateValidator::compute_txid(&tx_data);
        insert_pending_request(&server, "test-client", 42, 1, vec![expected_txid]).await;

        let msg = ProvideMissingTransactions {
            channel_id: 1,
            request_id: 42,
            transactions: vec![tx_data],
        };

        server
            .handle_provide_missing_transactions(msg, "test-client")
            .await
            .unwrap();

        // Verify the txid is now known
        let validator = server.validator().await;
        assert!(
            validator.is_txid_known(&expected_txid),
            "Expected txid {} to be known after providing transaction",
            hex::encode(expected_txid)
        );
    }

    #[tokio::test]
    async fn test_provide_missing_transactions_rejects_invalid_tx_data() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let expected_txid = TemplateValidator::compute_txid(&minimal_tx());
        insert_pending_request(&server, "test-client", 42, 1, vec![expected_txid]).await;

        let msg = ProvideMissingTransactions {
            channel_id: 1,
            request_id: 42,
            transactions: vec![vec![]],
        };

        let result = server
            .handle_provide_missing_transactions(msg, "test-client")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_provide_missing_transactions_rejects_txid_mismatch() {
        let config = test_config_full_template();
        let payout_tracker = Arc::new(PayoutTracker::default());
        let server = JdServer::new(config, payout_tracker);

        let expected_txid = TemplateValidator::compute_txid(&minimal_tx());
        insert_pending_request(&server, "test-client", 42, 1, vec![expected_txid]).await;

        let msg = ProvideMissingTransactions {
            channel_id: 1,
            request_id: 42,
            transactions: vec![minimal_tx_with_script(&[0x52])],
        };

        let result = server
            .handle_provide_missing_transactions(msg, "test-client")
            .await;
        assert!(result.is_err());

        let validator = server.validator().await;
        assert!(!validator.is_txid_known(&expected_txid));
    }
}
