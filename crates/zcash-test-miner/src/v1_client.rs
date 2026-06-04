//! Stratum V1 client for testing the sovright-v1-stratum-proxy.
//!
//! Connects using JSON-RPC over TCP (newline-delimited), implements:
//! - mining.subscribe
//! - mining.authorize
//! - mining.notify (receive jobs)
//! - mining.submit (send shares)
//! - mining.set_target / mining.set_difficulty
//! - mining.set_extranonce

use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Parsed V1 job from mining.notify
#[derive(Debug, Clone)]
pub struct V1Job {
    pub job_id: String,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub block_commitments: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub clean_jobs: bool,
}

/// Run the test miner in V1 mode.
pub async fn run_v1(pool_addr: &str, worker: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to pool at {} (V1 mode)", pool_addr);
    let stream = TcpStream::connect(pool_addr).await?;
    info!("Connected to pool (V1)");

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut next_id: u64 = 1;

    // Step 1: mining.subscribe
    let subscribe_id = next_id;
    next_id += 1;
    send_json(
        &mut writer,
        &serde_json::json!({
            "id": subscribe_id,
            "method": "mining.subscribe",
            "params": ["zcash-test-miner/1.0", null, pool_addr, 3334]
        }),
    )
    .await?;

    // Step 2: mining.authorize
    let authorize_id = next_id;
    next_id += 1;
    send_json(
        &mut writer,
        &serde_json::json!({
            "id": authorize_id,
            "method": "mining.authorize",
            "params": [worker, "x"]
        }),
    )
    .await?;

    // Step 3: mining.extranonce.subscribe
    let extranonce_id = next_id;
    next_id += 1;
    send_json(
        &mut writer,
        &serde_json::json!({
            "id": extranonce_id,
            "method": "mining.extranonce.subscribe",
            "params": []
        }),
    )
    .await?;

    // State
    let mut nonce_1: Vec<u8> = Vec::new();
    let mut nonce_2_size: usize = 28; // default
    let mut current_target: [u8; 32] = [0xff; 32];
    let mut job_map: HashMap<String, V1Job> = HashMap::new();

    // Solver channel
    let (solution_tx, mut solution_rx) =
        mpsc::channel::<(String, Vec<u8>, u32, Vec<u8>)>(32);

    // Current job for solver thread
    let current_job: Arc<std::sync::Mutex<Option<(V1Job, Vec<u8>, usize)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let current_job_id = Arc::new(AtomicU32::new(0));

    // Spawn solver thread (reuses same Equihash logic as V2 mode)
    let solver_job = current_job.clone();
    let solver_job_id = current_job_id.clone();
    let solver_tx = solution_tx.clone();
    std::thread::spawn(move || {
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        let mut nonce_counter: u64 = {
            let mut buf = [0u8; 8];
            rng.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        };

        loop {
            let data = { solver_job.lock().unwrap().clone() };

            let Some((job, nonce_1, nonce_2_len)) = data else {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            };

            let my_job_id = hash_job_id(&job.job_id);
            let start = Instant::now();
            debug!("Solving V1 job_id={}", job.job_id);

            // Build header prefix (108 bytes: version + prev_hash + merkle_root + block_commitments + time + bits)
            let mut header_prefix = [0u8; 108];
            header_prefix[0..4].copy_from_slice(&job.version.to_le_bytes());
            header_prefix[4..36].copy_from_slice(&job.prev_hash);
            header_prefix[36..68].copy_from_slice(&job.merkle_root);
            header_prefix[68..100].copy_from_slice(&job.block_commitments);
            header_prefix[100..104].copy_from_slice(&job.time.to_le_bytes());
            header_prefix[104..108].copy_from_slice(&job.bits.to_le_bytes());

            let nonce_1_len = nonce_1.len();

            loop {
                if solver_job_id.load(Ordering::Relaxed) != my_job_id {
                    debug!("V1 job {} superseded", job.job_id);
                    break;
                }

                nonce_counter = nonce_counter.wrapping_add(1);

                let mut nonce_2 = vec![0u8; nonce_2_len];
                let counter_bytes = nonce_counter.to_le_bytes();
                for i in 0..nonce_2_len {
                    nonce_2[i] = counter_bytes[i % 8];
                }

                let mut full_nonce = [0u8; 32];
                full_nonce[..nonce_1_len].copy_from_slice(&nonce_1);
                full_nonce[nonce_1_len..nonce_1_len + nonce_2_len].copy_from_slice(&nonce_2);

                let mut used = false;
                let solutions =
                    equihash::tromp::solve_200_9::<32>(&header_prefix, || {
                        if used {
                            return None;
                        }
                        used = true;
                        Some(full_nonce)
                    });

                if !solutions.is_empty() {
                    if solver_job_id.load(Ordering::Relaxed) != my_job_id {
                        break;
                    }
                    let elapsed = start.elapsed();
                    info!(
                        "Found {} V1 solution(s) for job_id={} in {:?}",
                        solutions.len(),
                        job.job_id,
                        elapsed
                    );
                    for sol in solutions {
                        if solver_tx
                            .blocking_send((
                                job.job_id.clone(),
                                nonce_2.clone(),
                                job.time,
                                sol,
                            ))
                            .is_err()
                        {
                            return;
                        }
                    }
                    break;
                }
            }
        }
    });

    drop(solution_tx);

    // Main loop: read V1 messages, submit solutions
    let mut line_buf = String::new();

    loop {
        tokio::select! {
            biased;

            line_result = reader.read_line(&mut line_buf) => {
                let n = line_result?;
                if n == 0 {
                    info!("Pool connection closed (V1)");
                    break;
                }

                let trimmed = line_buf.trim();
                if trimmed.is_empty() {
                    line_buf.clear();
                    continue;
                }

                match serde_json::from_str::<Value>(trimmed) {
                    Ok(msg) => {
                        // Is it a notification (no id or id=null)?
                        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                            let params = msg.get("params").cloned().unwrap_or(Value::Array(vec![]));
                            match method {
                                "mining.notify" => {
                                    match parse_notify(&params) {
                                        Ok(job) => {
                                            info!(
                                                "V1 job: id={}, version={:#x}, clean={}",
                                                job.job_id, job.version, job.clean_jobs
                                            );
                                            // Only preempt the solver on clean_jobs=true. A clean=false
                                            // notify means previous work is still valid (Stratum V1 spec);
                                            // preempting mid-solve on every refresh starves the solver.
                                            // We still record the job so a later submit can reference it.
                                            let should_preempt = job.clean_jobs
                                                || current_job.lock().unwrap().is_none();
                                            if job.clean_jobs {
                                                job_map.clear();
                                            }
                                            if should_preempt {
                                                let jid = hash_job_id(&job.job_id);
                                                current_job_id.store(jid, Ordering::Relaxed);
                                                *current_job.lock().unwrap() = Some((
                                                    job.clone(),
                                                    nonce_1.clone(),
                                                    nonce_2_size,
                                                ));
                                            }
                                            job_map.insert(job.job_id.clone(), job);
                                        }
                                        Err(e) => warn!("Bad mining.notify: {}", e),
                                    }
                                }
                                "mining.set_target" => {
                                    if let Some(target_hex) = params.get(0).and_then(|v| v.as_str()) {
                                        match hex_to_32_reversed(target_hex) {
                                            Ok(t) => {
                                                info!("V1 target updated");
                                                current_target = t;
                                            }
                                            Err(e) => warn!("Bad set_target: {}", e),
                                        }
                                    }
                                }
                                "mining.set_difficulty" => {
                                    if let Some(diff) = params.get(0).and_then(|v| v.as_f64()) {
                                        info!("V1 difficulty set to {}", diff);
                                    }
                                }
                                "mining.set_extranonce" => {
                                    if let (Some(n1_hex), Some(n2_sz)) = (
                                        params.get(0).and_then(|v| v.as_str()),
                                        params.get(1).and_then(|v| v.as_u64()),
                                    ) {
                                        match hex_decode(n1_hex) {
                                            Ok(n1) => {
                                                info!("V1 extranonce updated: nonce_1={} bytes, nonce_2_size={}", n1.len(), n2_sz);
                                                nonce_1 = n1;
                                                nonce_2_size = n2_sz as usize;
                                            }
                                            Err(e) => warn!("Bad set_extranonce: {}", e),
                                        }
                                    }
                                }
                                _ => debug!("V1 notification: {}", method),
                            }
                        } else if let Some(id) = msg.get("id") {
                            // Response to our request
                            if id.as_u64() == Some(subscribe_id) {
                                match parse_subscribe_response(&msg) {
                                    Ok((n1, _session_id)) => {
                                        nonce_1 = n1;
                                        info!("Subscribed: nonce_1={} ({} bytes)", hex::encode(&nonce_1), nonce_1.len());
                                    }
                                    Err(e) => error!("Subscribe failed: {}", e),
                                }
                            } else if id.as_u64() == Some(authorize_id) {
                                let result = msg.get("result").and_then(|v| v.as_bool()).unwrap_or(false);
                                if result {
                                    info!("Authorized as {}", worker);
                                } else {
                                    let err = msg.get("error").cloned().unwrap_or(Value::Null);
                                    error!("Authorization failed: {}", err);
                                }
                            } else {
                                // Share response
                                let result = msg.get("result").and_then(|v| v.as_bool()).unwrap_or(false);
                                if result {
                                    info!("Share accepted (id={})", id);
                                } else {
                                    let err = msg.get("error").cloned().unwrap_or(Value::Null);
                                    warn!("Share rejected (id={}): {}", id, err);
                                }
                            }
                        }
                    }
                    Err(e) => warn!("Failed to parse V1 JSON: {}", e),
                }

                line_buf.clear();
            }

            Some((job_id, nonce_2, time, solution)) = solution_rx.recv() => {
                let jid = hash_job_id(&job_id);
                if current_job_id.load(Ordering::Relaxed) != jid {
                    debug!("Discarding stale V1 solution for job_id={}", job_id);
                    continue;
                }

                let submit_id = next_id;
                next_id += 1;

                let nonce_2_hex = hex::encode(&nonce_2);
                let time_hex = format!("{:08x}", time);
                let solution_hex = hex::encode(&solution);

                send_json(
                    &mut writer,
                    &serde_json::json!({
                        "id": submit_id,
                        "method": "mining.submit",
                        "params": [worker, job_id, time_hex, nonce_2_hex, solution_hex]
                    }),
                )
                .await?;

                info!("Submitted V1 share: id={}, job_id={}", submit_id, job_id);
            }
        }
    }

    info!("V1 test miner shutting down");
    let _ = current_target; // suppress unused warning
    Ok(())
}

async fn send_json(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    value: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = serde_json::to_vec(value)?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

fn parse_subscribe_response(msg: &Value) -> Result<(Vec<u8>, String), String> {
    let result = msg
        .get("result")
        .ok_or("missing result field")?;

    // result = [["mining.notify", "session_id"], "nonce_1_hex"]
    let arr = result.as_array().ok_or("result is not an array")?;
    if arr.len() < 2 {
        return Err("result array too short".into());
    }

    let session_id = arr[0]
        .as_array()
        .and_then(|a| a.get(1))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let nonce_1_hex = arr[1].as_str().ok_or("nonce_1 is not a string")?;
    let nonce_1 = hex_decode(nonce_1_hex).map_err(|e| format!("bad nonce_1 hex: {}", e))?;

    Ok((nonce_1, session_id))
}

fn parse_notify(params: &Value) -> Result<V1Job, String> {
    let arr = params.as_array().ok_or("notify params not an array")?;
    if arr.len() < 8 {
        return Err(format!("notify needs 8 params, got {}", arr.len()));
    }

    let job_id = arr[0].as_str().ok_or("job_id not string")?.to_string();
    let version = parse_hex_u32(arr[1].as_str().ok_or("version not string")?)?;
    let prev_hash = hex_to_32_reversed(arr[2].as_str().ok_or("prev_hash not string")?)?;
    let merkle_root = hex_to_32_reversed(arr[3].as_str().ok_or("merkle_root not string")?)?;
    let block_commitments = hex_to_32_reversed(arr[4].as_str().ok_or("reserved not string")?)?;
    let time = parse_hex_u32(arr[5].as_str().ok_or("time not string")?)?;
    let bits = parse_hex_u32(arr[6].as_str().ok_or("bits not string")?)?;
    let clean_jobs = arr[7].as_bool().unwrap_or(false);

    Ok(V1Job {
        job_id,
        version,
        prev_hash,
        merkle_root,
        block_commitments,
        time,
        bits,
        clean_jobs,
    })
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let stripped = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or(input.trim());
    hex::decode(stripped).map_err(|e| e.to_string())
}

fn hex_to_32_reversed(input: &str) -> Result<[u8; 32], String> {
    let mut bytes = hex_decode(input)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    bytes.reverse(); // V1 big-endian hex -> V2 little-endian bytes
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_u32(input: &str) -> Result<u32, String> {
    let stripped = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or(input.trim());
    u32::from_str_radix(stripped, 16).map_err(|e| format!("bad hex u32 '{}': {}", input, e))
}

/// Simple hash of a string job_id to a u32 for the AtomicU32 cancellation check.
fn hash_job_id(job_id: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in job_id.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}
