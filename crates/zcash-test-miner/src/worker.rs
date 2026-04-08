use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use blake2b_simd::Params as Blake2bParams;
use rand::Rng;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use bedrock_noise::PublicKey;
use zcash_mining_protocol::codec::encode_submit_share;
use zcash_mining_protocol::messages::{NewEquihashJob, ShareResult, SubmitEquihashShare};

/// Simple hex encoding (avoids adding `hex` crate dependency).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

use crate::protocol::{decode_server_message, ServerMessage};
use crate::transport::MinerTransport;

/// Configuration for a single worker connection.
pub struct WorkerConfig {
    pub pool_addr: String,
    pub worker_name: String,
    pub solver_threads: u32,
    pub server_pubkey: Option<PublicKey>,
}

/// A found share ready for submission.
struct FoundShare {
    /// The full 32-byte nonce that produced this solution.
    nonce: [u8; 32],
    /// The compressed 1344-byte Equihash solution.
    solution: [u8; 1344],
}

/// Session-level statistics.
struct SessionStats {
    shares_submitted: u64,
    shares_accepted: u64,
    shares_rejected: u64,
    blocks_found: u64,
}

impl SessionStats {
    fn new() -> Self {
        Self {
            shares_submitted: 0,
            shares_accepted: 0,
            shares_rejected: 0,
            blocks_found: 0,
        }
    }
}

/// Top-level worker loop that reconnects on errors with jitter.
pub async fn run_worker(config: WorkerConfig, mut shutdown: watch::Receiver<bool>) {
    loop {
        // Check shutdown before connecting
        if *shutdown.borrow() {
            info!(worker = %config.worker_name, "Shutdown signal received, exiting worker");
            return;
        }

        info!(worker = %config.worker_name, pool = %config.pool_addr, "Connecting to pool");

        match run_worker_session(&config, &mut shutdown).await {
            Ok(stats) => {
                info!(
                    worker = %config.worker_name,
                    submitted = stats.shares_submitted,
                    accepted = stats.shares_accepted,
                    rejected = stats.shares_rejected,
                    blocks = stats.blocks_found,
                    "Session ended cleanly"
                );
            }
            Err(e) => {
                warn!(worker = %config.worker_name, error = %e, "Session error");
            }
        }

        // Check shutdown before reconnect delay
        if *shutdown.borrow() {
            info!(worker = %config.worker_name, "Shutdown signal received, exiting worker");
            return;
        }

        // Wait 2s + random jitter (0-1s) before reconnecting.
        // Scope the rng so it does not live across an await point (ThreadRng is !Send).
        let jitter_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(0..1000u64)
        };
        let delay = Duration::from_millis(2000 + jitter_ms);
        info!(worker = %config.worker_name, delay_ms = delay.as_millis(), "Reconnecting after delay");

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!(worker = %config.worker_name, "Shutdown during reconnect delay");
                    return;
                }
            }
        }
    }
}

/// Run a single session: connect, receive jobs, solve, submit shares.
async fn run_worker_session(
    config: &WorkerConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<SessionStats, Box<dyn std::error::Error + Send + Sync>> {
    let mut transport =
        MinerTransport::connect(&config.pool_addr, config.server_pubkey.as_ref()).await?;

    info!(worker = %config.worker_name, "Connected to pool");

    let mut stats = SessionStats::new();
    let mut next_seq: u32 = 0;
    let mut current_target: Option<[u8; 32]> = None;

    // Channel for solver threads to send found shares back to the session loop.
    let (share_tx, mut share_rx) = mpsc::channel::<(FoundShare, NewEquihashJob)>(64);

    // Cancellation flag for active solvers.
    let solving = Arc::new(AtomicBool::new(false));

    loop {
        tokio::select! {
            // Receive a message from the pool
            msg_result = transport.read_message() => {
                let data = msg_result?;
                match decode_server_message(&data) {
                    Ok(ServerMessage::NewJob(job)) => {
                        info!(
                            worker = %config.worker_name,
                            job_id = job.job_id,
                            channel_id = job.channel_id,
                            clean = job.clean_jobs,
                            nonce_1_len = job.nonce_1.len(),
                            nonce_2_len = job.nonce_2_len,
                            "Received new job"
                        );

                        if !job.validate_nonce_len() {
                            warn!(
                                worker = %config.worker_name,
                                nonce_1_len = job.nonce_1.len(),
                                nonce_2_len = job.nonce_2_len,
                                "Invalid nonce lengths (must sum to 32), skipping job"
                            );
                            continue;
                        }

                        // Cancel any active solvers
                        solving.store(false, Ordering::Release);

                        // Update share target if job carries one, or use SetTarget value
                        let share_target = if let Some(ref t) = current_target {
                            *t
                        } else {
                            job.target
                        };

                        // Start new solver threads
                        solving.store(true, Ordering::Release);
                        let solver_threads = config.solver_threads;

                        for thread_id in 0..solver_threads {
                            let job_clone = job.clone();
                            let solving_clone = solving.clone();
                            let share_tx_clone = share_tx.clone();
                            let share_target_copy = share_target;

                            tokio::task::spawn_blocking(move || {
                                run_solver_thread(
                                    thread_id,
                                    solver_threads,
                                    &job_clone,
                                    &share_target_copy,
                                    &solving_clone,
                                    &share_tx_clone,
                                );
                            });
                        }
                    }
                    Ok(ServerMessage::ShareResponse(resp)) => {
                        match resp.result {
                            ShareResult::Accepted => {
                                stats.shares_accepted += 1;
                                info!(
                                    worker = %config.worker_name,
                                    seq = resp.sequence_number,
                                    "Share accepted"
                                );
                            }
                            ShareResult::Rejected(ref reason) => {
                                stats.shares_rejected += 1;
                                warn!(
                                    worker = %config.worker_name,
                                    seq = resp.sequence_number,
                                    reason = ?reason,
                                    "Share rejected"
                                );
                            }
                        }
                    }
                    Ok(ServerMessage::SetTarget(set_target)) => {
                        info!(
                            worker = %config.worker_name,
                            channel_id = set_target.channel_id,
                            "Target updated"
                        );
                        current_target = Some(set_target.target);
                    }
                    Err(e) => {
                        warn!(worker = %config.worker_name, error = %e, "Failed to decode message");
                    }
                }
            }

            // Receive shares from solver threads
            share_opt = share_rx.recv() => {
                if let Some((found, job)) = share_opt {
                    let nonce_1_len = job.nonce_1.len();
                    let nonce_2 = found.nonce[nonce_1_len..].to_vec();

                    let share = SubmitEquihashShare {
                        channel_id: job.channel_id,
                        sequence_number: next_seq,
                        job_id: job.job_id,
                        nonce_2,
                        time: job.time,
                        solution: found.solution,
                    };

                    match encode_submit_share(&share) {
                        Ok(encoded) => {
                            if let Err(e) = transport.write_message(&encoded).await {
                                error!(worker = %config.worker_name, error = %e, "Failed to send share");
                                return Err(e.into());
                            }
                            stats.shares_submitted += 1;
                            next_seq += 1;
                            info!(
                                worker = %config.worker_name,
                                job_id = job.job_id,
                                seq = share.sequence_number,
                                "Submitted share"
                            );

                            // Check if this is a block-level solution
                            let network_target = nbits_to_target(job.bits);
                            let header = job.build_header(&found.nonce);
                            let block_hash = compute_block_hash(&header, &found.solution);
                            if hash_le_target(&block_hash, &network_target) {
                                stats.blocks_found += 1;
                                info!(
                                    worker = %config.worker_name,
                                    job_id = job.job_id,
                                    hash = to_hex(&block_hash),
                                    "BLOCK FOUND!"
                                );
                            }
                        }
                        Err(e) => {
                            error!(worker = %config.worker_name, error = %e, "Failed to encode share");
                        }
                    }
                }
            }

            // Shutdown signal
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!(worker = %config.worker_name, "Shutdown signal received during session");
                    solving.store(false, Ordering::Release);
                    return Ok(stats);
                }
            }
        }
    }
}

/// Run the Equihash solver on a single thread.
///
/// Each thread works with interleaved nonces: thread 0 uses nonces 0, N, 2N, ...
/// thread 1 uses nonces 1, N+1, 2N+1, ... where N is the total number of threads.
fn run_solver_thread(
    thread_id: u32,
    total_threads: u32,
    job: &NewEquihashJob,
    share_target: &[u8; 32],
    solving: &AtomicBool,
    share_tx: &mpsc::Sender<(FoundShare, NewEquihashJob)>,
) {
    let nonce_1 = &job.nonce_1;
    let nonce_1_len = nonce_1.len();
    let nonce_2_len = job.nonce_2_len as usize;

    debug!(
        thread_id,
        job_id = job.job_id,
        "Solver thread starting"
    );

    // The solver input is the first 108 bytes of the header (everything before the nonce).
    // We construct it once: version(4) + prev_hash(32) + merkle_root(32) + block_commitments(32) + time(4) + bits(4) = 108
    let mut input = [0u8; 108];
    input[0..4].copy_from_slice(&job.version.to_le_bytes());
    input[4..36].copy_from_slice(&job.prev_hash);
    input[36..68].copy_from_slice(&job.merkle_root);
    input[68..100].copy_from_slice(&job.block_commitments);
    input[100..104].copy_from_slice(&job.time.to_le_bytes());
    input[104..108].copy_from_slice(&job.bits.to_le_bytes());

    // Counter for interleaved nonce assignment
    let mut counter: u64 = thread_id as u64;

    loop {
        if !solving.load(Ordering::Acquire) {
            debug!(thread_id, job_id = job.job_id, "Solver cancelled");
            return;
        }

        // We run solve_200_9 which loops internally calling next_nonce.
        // We give it a batch of nonces to try before checking cancellation.
        let solving_ref = solving;
        let mut local_counter = counter;

        let solutions = equihash::tromp::solve_200_9::<32>(&input, || {
            if !solving_ref.load(Ordering::Acquire) {
                return None;
            }

            // Build full 32-byte nonce from nonce_1 + counter
            let mut nonce = [0u8; 32];
            nonce[..nonce_1_len].copy_from_slice(nonce_1);
            let counter_bytes = local_counter.to_le_bytes();
            let copy_len = 8.min(nonce_2_len);
            nonce[nonce_1_len..nonce_1_len + copy_len]
                .copy_from_slice(&counter_bytes[..copy_len]);
            local_counter += total_threads as u64;

            Some(nonce)
        });

        // The nonce that produced solutions is `local_counter - total_threads`
        // because local_counter was incremented after the last yield.
        // But we need to reconstruct the exact nonce that worked.
        // The solver breaks on the first nonce that produces solutions,
        // so the winning nonce is `local_counter - total_threads`.
        if !solutions.is_empty() {
            let winning_counter = local_counter - total_threads as u64;
            let mut winning_nonce = [0u8; 32];
            winning_nonce[..nonce_1_len].copy_from_slice(nonce_1);
            let counter_bytes = winning_counter.to_le_bytes();
            let copy_len = 8.min(nonce_2_len);
            winning_nonce[nonce_1_len..nonce_1_len + copy_len]
                .copy_from_slice(&counter_bytes[..copy_len]);

            for sol_bytes in &solutions {
                if sol_bytes.len() != 1344 {
                    warn!(
                        thread_id,
                        len = sol_bytes.len(),
                        "Unexpected solution length, skipping"
                    );
                    continue;
                }

                // Check if the solution meets the share target
                let header = job.build_header(&winning_nonce);
                let block_hash = compute_block_hash(&header, sol_bytes);

                if hash_le_target(&block_hash, share_target) {
                    let mut solution = [0u8; 1344];
                    solution.copy_from_slice(sol_bytes);

                    let found = FoundShare {
                        nonce: winning_nonce,
                        solution,
                    };

                    info!(
                        thread_id,
                        job_id = job.job_id,
                        hash = to_hex(&block_hash),
                        "Found share meeting target"
                    );

                    // Send share to the session loop (non-blocking; drop if channel full)
                    if share_tx.try_send((found, job.clone())).is_err() {
                        warn!(thread_id, "Share channel full, dropping share");
                    }
                } else {
                    debug!(
                        thread_id,
                        job_id = job.job_id,
                        "Solution found but does not meet share target"
                    );
                }
            }
        }

        // Update counter for next solve_200_9 call
        counter = local_counter;

        // Small random delay between solve cycles (50-200ms)
        let delay_ms = rand::thread_rng().gen_range(50..=200);
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
}

/// Compute the block hash: BLAKE2b-256 of header(140) || compact_size(1344) || solution(1344)
/// with personalization "ZcashBlockHash\0\0" (16 bytes, null-padded).
fn compute_block_hash(header: &[u8; 140], solution: &[u8]) -> [u8; 32] {
    // Compact size encoding for 1344: 0xfd followed by 1344 as u16 LE
    // 1344 = 0x0540
    let compact_size: [u8; 3] = [0xfd, 0x40, 0x05];

    let mut personalization = [0u8; 16];
    personalization[..14].copy_from_slice(b"ZcashBlockHash");
    // bytes 14 and 15 are already 0

    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(&personalization)
        .to_state()
        .update(header)
        .update(&compact_size)
        .update(solution)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Compare a hash against a target in little-endian 256-bit representation.
/// Returns true if hash <= target.
/// Both hash and target are little-endian with MSB at index 31.
fn hash_le_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    // Compare from MSB (index 31) down to LSB (index 0)
    for i in (0..32).rev() {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    // Equal
    true
}

/// Convert compact nbits to a 256-bit target (little-endian byte array).
fn nbits_to_target(nbits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];

    let exponent = ((nbits >> 24) & 0xff) as usize;
    let mantissa = nbits & 0x007fffff;

    if exponent == 0 {
        return target;
    }

    // The mantissa is a 3-byte big-endian value placed at byte position (exponent - 3)
    // in big-endian representation. We need to convert to little-endian.
    let mantissa_bytes = [
        ((mantissa >> 16) & 0xff) as u8,
        ((mantissa >> 8) & 0xff) as u8,
        (mantissa & 0xff) as u8,
    ];

    // In big-endian, mantissa goes at position (32 - exponent) .. (32 - exponent + 3)
    // In little-endian byte array, this maps to position (exponent - 3) .. exponent
    if exponent >= 3 {
        let start = exponent - 3;
        for (i, &b) in mantissa_bytes.iter().enumerate() {
            let pos = start + (2 - i); // reverse for LE
            if pos < 32 {
                target[pos] = b;
            }
        }
    } else {
        // exponent < 3: shift mantissa right
        let shift = 3 - exponent;
        let shifted = mantissa >> (8 * shift);
        target[0] = (shifted & 0xff) as u8;
    }

    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_le_target_equal() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(hash_le_target(&a, &b));
    }

    #[test]
    fn test_hash_le_target_less() {
        let mut hash = [0u8; 32];
        let mut target = [0u8; 32];
        target[31] = 1; // target has higher MSB
        assert!(hash_le_target(&hash, &target));

        hash[31] = 2;
        assert!(!hash_le_target(&hash, &target));
    }

    #[test]
    fn test_nbits_to_target_basic() {
        // nbits = 0x2007ffff => exponent=0x20=32, mantissa=0x07ffff
        // (high bit of first mantissa byte is sign, masked by 0x007fffff)
        // Value = 0x07ffff * 256^29, placed at LE bytes 29..=31
        let target = nbits_to_target(0x2007ffff);
        assert_eq!(target[31], 0x07);
        assert_eq!(target[30], 0xff);
        assert_eq!(target[29], 0xff);
        // All other bytes should be zero
        for i in 0..29 {
            assert_eq!(target[i], 0, "byte {i} should be zero");
        }
    }

    #[test]
    fn test_nbits_to_target_smaller() {
        // nbits = 0x1d00ffff => exponent=29, mantissa=0x00ffff
        // Value = 0x00ffff * 256^26, placed at LE bytes 26..=28
        let target = nbits_to_target(0x1d00ffff);
        assert_eq!(target[28], 0x00);
        assert_eq!(target[27], 0xff);
        assert_eq!(target[26], 0xff);
    }

    #[test]
    fn test_compact_size_1344() {
        // 1344 in hex is 0x0540
        // compact_size encoding: 0xfd, low byte, high byte => 0xfd, 0x40, 0x05
        let cs: [u8; 3] = [0xfd, 0x40, 0x05];
        let val = u16::from_le_bytes([cs[1], cs[2]]);
        assert_eq!(val, 1344);
    }
}
