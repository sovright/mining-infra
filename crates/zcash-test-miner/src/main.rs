//! Bedrock Test Miner
//!
//! A minimal Stratum V2 test client that:
//! 1. Connects to the pool server via TCP
//! 2. Reads NewEquihashJob messages
//! 3. Submits SubmitEquihashShare with dummy solutions
//!
//! This is for internal testnet use only — the solutions are not valid
//! Equihash solutions. Use with a PoW-disabled Zebra testnet where the
//! pool's share validation can accept any solution that meets the share
//! difficulty target.
//!
//! Usage:
//!   cargo run -p zcash-test-miner -- --pool 127.0.0.1:3333 --rate 5

use clap::Parser;
use rand::RngCore;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info, warn};
use zcash_mining_protocol::codec::{
    decode_new_equihash_job, decode_set_target, encode_submit_share, MessageFrame,
};
use zcash_mining_protocol::messages::{message_types, SubmitEquihashShare};

#[derive(Parser, Debug)]
#[command(name = "zcash-test-miner", about = "Bedrock internal testnet miner")]
struct Args {
    /// Pool server address
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool: String,

    /// Target shares per minute (controls submission rate)
    #[arg(long, default_value = "5")]
    rate: f64,

    /// Worker name (for logging)
    #[arg(long, default_value = "testminer.worker1")]
    worker: String,
}

/// Read exactly one framed SV2 message from the stream.
/// Returns the full message bytes (header + payload).
async fn read_message(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    loop {
        // Try to parse a complete frame from the buffer
        if buf.len() >= MessageFrame::HEADER_SIZE {
            let frame = MessageFrame::decode(&buf[..MessageFrame::HEADER_SIZE])?;
            let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
            if buf.len() >= total_len {
                let msg = buf[..total_len].to_vec();
                buf.drain(..total_len);
                return Ok(Some(msg));
            }
        }

        // Need more data
        let mut temp = [0u8; 4096];
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(None); // Connection closed
        }
        buf.extend_from_slice(&temp[..n]);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let share_interval = Duration::from_secs_f64(60.0 / args.rate);

    info!("Connecting to pool at {}", args.pool);
    let mut stream = TcpStream::connect(&args.pool).await?;
    info!("Connected to pool");

    let mut read_buf = Vec::with_capacity(4096);
    let mut sequence_number: u32 = 0;
    let mut current_job_id: Option<u32> = None;
    let mut current_nonce_2_len: u8 = 28; // default, updated from job
    let mut rng = rand::thread_rng();

    // Main loop: read jobs from pool, submit shares on a timer
    let mut share_timer = tokio::time::interval(share_interval);

    loop {
        tokio::select! {
            // Read messages from pool
            msg_result = read_message(&mut stream, &mut read_buf) => {
                match msg_result {
                    Ok(Some(msg)) => {
                        if msg.len() < MessageFrame::HEADER_SIZE {
                            warn!("Message too short: {} bytes", msg.len());
                            continue;
                        }
                        let msg_type = msg[2]; // msg_type is at byte offset 2

                        match msg_type {
                            message_types::NEW_EQUIHASH_JOB => {
                                match decode_new_equihash_job(&msg) {
                                    Ok(job) => {
                                        info!(
                                            "New job: id={}, version={}, nonce_1_len={}, nonce_2_len={}, clean={}",
                                            job.job_id,
                                            job.version,
                                            job.nonce_1.len(),
                                            job.nonce_2_len,
                                            job.clean_jobs,
                                        );
                                        current_job_id = Some(job.job_id);
                                        current_nonce_2_len = job.nonce_2_len;
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
                                // We could decode and log accepted/rejected, but for now
                                // just note we got a response
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

            // Submit shares on timer
            _ = share_timer.tick() => {
                if let Some(job_id) = current_job_id {
                    // Generate random nonce_2
                    let mut nonce_2 = vec![0u8; current_nonce_2_len as usize];
                    rng.fill_bytes(&mut nonce_2);

                    // Generate dummy solution (1344 bytes of random data)
                    // On a PoW-disabled testnet this won't pass Equihash validation,
                    // but it tests the full protocol flow up to the validator.
                    let mut solution = [0u8; 1344];
                    rng.fill_bytes(&mut solution);

                    let share = SubmitEquihashShare {
                        channel_id: 1, // TODO: get from OpenMiningChannel response
                        sequence_number,
                        job_id,
                        nonce_2,
                        time: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as u32,
                        solution,
                    };

                    match encode_submit_share(&share) {
                        Ok(encoded) => {
                            match stream.write_all(&encoded).await {
                                Ok(()) => {
                                    info!(
                                        "Submitted share: seq={}, job_id={}, nonce_2_len={}",
                                        sequence_number, job_id, current_nonce_2_len,
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
                } else {
                    info!("No job received yet, waiting...");
                }
            }
        }
    }

    info!("Test miner shutting down");
    Ok(())
}
