//! Bedrock Test Miner
//!
//! A Stratum V2 test client with CPU Equihash solver that:
//! 1. Connects to the pool server via TCP
//! 2. Reads NewEquihashJob messages
//! 3. Solves Equihash (200,9) using the tromp CPU solver
//! 4. Submits valid shares
//!
//! Usage:
//!   cargo run -p zcash-test-miner --release -- --pool 127.0.0.1:3333

use clap::Parser;
use rand::RngCore;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zcash_mining_protocol::codec::{
    decode_new_equihash_job, decode_set_target, encode_submit_share, MessageFrame,
};
use zcash_mining_protocol::messages::{message_types, NewEquihashJob, SubmitEquihashShare};

#[derive(Parser, Debug)]
#[command(name = "zcash-test-miner", about = "Bedrock CPU testnet miner (Equihash 200,9)")]
struct Args {
    /// Pool server address
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool: String,

    /// Worker name (for logging)
    #[arg(long, default_value = "testminer.worker1")]
    worker: String,
}

/// Read exactly one framed SV2 message from the stream.
async fn read_message(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    loop {
        if buf.len() >= MessageFrame::HEADER_SIZE {
            let frame = MessageFrame::decode(&buf[..MessageFrame::HEADER_SIZE])?;
            let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
            if buf.len() >= total_len {
                let msg = buf[..total_len].to_vec();
                buf.drain(..total_len);
                return Ok(Some(msg));
            }
        }
        let mut temp = [0u8; 4096];
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&temp[..n]);
    }
}

/// Solve Equihash for a single nonce attempt. Returns solutions if found.
fn try_solve_nonce(header_prefix: &[u8; 108], full_nonce: [u8; 32]) -> Vec<Vec<u8>> {
    let mut used = false;
    equihash::tromp::solve_200_9::<32>(header_prefix, || {
        if used {
            return None;
        }
        used = true;
        Some(full_nonce)
    })
}

/// Solve Equihash for the given job, checking for cancellation between nonce attempts.
/// Returns (nonce_2, solution) pairs, or empty vec if cancelled.
fn solve_job(
    job: &NewEquihashJob,
    current_job_id: &AtomicU32,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let nonce_1_len = job.nonce_1.len();
    let nonce_2_len = job.nonce_2_len as usize;
    let nonce_1 = &job.nonce_1;
    let my_job_id = job.job_id;

    let mut header_prefix = [0u8; 108];
    header_prefix[0..4].copy_from_slice(&job.version.to_le_bytes());
    header_prefix[4..36].copy_from_slice(&job.prev_hash);
    header_prefix[36..68].copy_from_slice(&job.merkle_root);
    header_prefix[68..100].copy_from_slice(&job.block_commitments);
    header_prefix[100..104].copy_from_slice(&job.time.to_le_bytes());
    header_prefix[104..108].copy_from_slice(&job.bits.to_le_bytes());

    let mut rng = rand::thread_rng();
    let mut nonce_counter: u64 = {
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    };

    loop {
        // Check if job has changed (new block arrived)
        if current_job_id.load(Ordering::Relaxed) != my_job_id {
            debug!("Job {} superseded, aborting solve", my_job_id);
            return vec![];
        }

        nonce_counter = nonce_counter.wrapping_add(1);

        let mut nonce_2 = vec![0u8; nonce_2_len];
        let counter_bytes = nonce_counter.to_le_bytes();
        for i in 0..nonce_2_len {
            nonce_2[i] = counter_bytes[i % 8];
        }

        let mut full_nonce = [0u8; 32];
        full_nonce[..nonce_1_len].copy_from_slice(nonce_1);
        full_nonce[nonce_1_len..nonce_1_len + nonce_2_len].copy_from_slice(&nonce_2);

        let solutions = try_solve_nonce(&header_prefix, full_nonce);

        if !solutions.is_empty() {
            // Check again that job is still current before returning
            if current_job_id.load(Ordering::Relaxed) != my_job_id {
                debug!("Job {} superseded after solving, discarding solutions", my_job_id);
                return vec![];
            }
            return solutions
                .into_iter()
                .map(|sol| (nonce_2.clone(), sol))
                .collect();
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Connecting to pool at {}", args.pool);
    let mut stream = TcpStream::connect(&args.pool).await?;
    info!("Connected to pool");

    let mut read_buf = Vec::with_capacity(4096);
    let mut sequence_number: u32 = 0;

    // (channel_id, job_id, nonce_2, time, solution)
    let (solution_tx, mut solution_rx) = mpsc::channel::<(u32, u32, Vec<u8>, u32, Vec<u8>)>(32);

    // Current job for the solver thread
    let current_job: Arc<tokio::sync::Mutex<Option<NewEquihashJob>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    // Atomic job ID for fast cancellation checks
    let current_job_id = Arc::new(AtomicU32::new(0));

    // Spawn solver thread
    let solver_job = current_job.clone();
    let solver_job_id = current_job_id.clone();
    let solver_tx = solution_tx.clone();
    std::thread::spawn(move || {
        loop {
            let job = {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async { solver_job.lock().await.clone() })
            };

            let Some(job) = job else {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            };

            let job_id = job.job_id;
            let channel_id = job.channel_id;
            let start = Instant::now();
            debug!("Solving job_id={}", job_id);

            let results = solve_job(&job, &solver_job_id);
            let elapsed = start.elapsed();

            if results.is_empty() {
                debug!("No solution for job_id={} in {:?} (may be cancelled)", job_id, elapsed);
            } else {
                info!(
                    "Found {} solution(s) for job_id={} in {:?}",
                    results.len(),
                    job_id,
                    elapsed
                );
                for (nonce_2, solution) in results {
                    // Use the job's timestamp, not current time.
                    // The pool rejects shares with timestamps outside ±2h of the job time.
                    let time = job.time;
                    if solver_tx
                        .blocking_send((channel_id, job_id, nonce_2, time, solution))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });

    drop(solution_tx);

    loop {
        // Biased: always check pool messages first so we don't miss new jobs
        tokio::select! {
            biased;
            msg_result = read_message(&mut stream, &mut read_buf) => {
                match msg_result {
                    Ok(Some(msg)) => {
                        if msg.len() < MessageFrame::HEADER_SIZE {
                            warn!("Message too short: {} bytes", msg.len());
                            continue;
                        }
                        let msg_type = msg[2];

                        match msg_type {
                            message_types::NEW_EQUIHASH_JOB => {
                                match decode_new_equihash_job(&msg) {
                                    Ok(job) => {
                                        info!(
                                            "New job: id={}, channel={}, nonce_1={}, nonce_2_len={}, clean={}",
                                            job.job_id,
                                            job.channel_id,
                                            hex::encode(&job.nonce_1),
                                            job.nonce_2_len,
                                            job.clean_jobs,
                                        );
                                        // Update atomic job ID FIRST to cancel solver
                                        current_job_id.store(job.job_id, Ordering::Relaxed);
                                        // Then update the full job
                                        *current_job.lock().await = Some(job);
                                    }
                                    Err(e) => {
                                        error!("Failed to decode NewEquihashJob: {}", e);
                                    }
                                }
                            }
                            message_types::SET_TARGET => {
                                match decode_set_target(&msg) {
                                    Ok(target_msg) => {
                                        info!(
                                            "Target updated for channel {}",
                                            target_msg.channel_id,
                                        );
                                    }
                                    Err(e) => {
                                        warn!("Failed to decode SetTarget: {}", e);
                                    }
                                }
                            }
                            message_types::SUBMIT_SHARES_RESPONSE => {
                                info!("Share response received (seq={})", sequence_number.wrapping_sub(1));
                            }
                            _ => {
                                warn!("Unknown message type: 0x{:02x}", msg_type);
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Pool connection closed");
                        break;
                    }
                    Err(e) => {
                        error!("Read error: {}", e);
                        break;
                    }
                }
            }

            Some((chan_id, job_id, nonce_2, time, solution)) = solution_rx.recv() => {
                // Only submit if this job is still current
                if current_job_id.load(Ordering::Relaxed) != job_id {
                    debug!("Discarding stale solution for job_id={}", job_id);
                    continue;
                }

                let solution_arr: [u8; 1344] = match solution.as_slice().try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        warn!("Solution wrong length: {} (expected 1344)", solution.len());
                        continue;
                    }
                };

                let share = SubmitEquihashShare {
                    channel_id: chan_id,
                    sequence_number,
                    job_id,
                    nonce_2,
                    time,
                    solution: solution_arr,
                };

                match encode_submit_share(&share) {
                    Ok(encoded) => {
                        match stream.write_all(&encoded).await {
                            Ok(()) => {
                                info!(
                                    "Submitted share: seq={}, job_id={}",
                                    sequence_number, job_id,
                                );
                                sequence_number = sequence_number.wrapping_add(1);
                            }
                            Err(e) => {
                                error!("Failed to send share: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to encode share: {}", e);
                    }
                }
            }
        }
    }

    info!("Test miner shutting down");
    Ok(())
}
