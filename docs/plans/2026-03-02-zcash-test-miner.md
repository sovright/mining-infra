# zcash-test-miner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a CPU Equihash test miner binary that opens N SV2 connections to a Bedrock pool server, receives jobs, solves Equihash on CPU, and submits valid shares.

**Architecture:** Single binary with a main orchestrator that spawns N worker tasks. Each worker holds its own TCP/Noise connection to the pool. Workers share nothing -- each has its own connection, channel_id, solver loop, and sequence counter. The solver runs `equihash::tromp::solve_200_9()` in blocking threads (via `tokio::task::spawn_blocking`).

**Tech Stack:** Rust, tokio, clap, equihash (solver feature), bedrock-noise, zcash-mining-protocol, tracing

---

### Task 1: Scaffold the crate and workspace integration

**Files:**
- Create: `crates/zcash-test-miner/Cargo.toml`
- Create: `crates/zcash-test-miner/src/main.rs` (minimal)
- Modify: root `Cargo.toml` (no change needed -- `crates/*` glob already includes it)

**Step 1: Create the directory**

```bash
mkdir -p crates/zcash-test-miner/src
```

**Step 2: Create Cargo.toml**

Create `crates/zcash-test-miner/Cargo.toml`:

```toml
[package]
name = "zcash-test-miner"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "CPU Equihash test miner for Bedrock pool testing"

[[bin]]
name = "zcash-test-miner"
path = "src/main.rs"

[dependencies]
zcash-mining-protocol = { path = "../zcash-mining-protocol" }
bedrock-noise = { path = "../bedrock-noise" }
equihash = { version = "0.2", features = ["solver"] }
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
clap = { version = "4", features = ["derive"] }
rand = "0.8"
blake2b_simd = { workspace = true }
```

**Step 3: Create minimal main.rs**

Create `crates/zcash-test-miner/src/main.rs`:

```rust
fn main() {
    println!("zcash-test-miner placeholder");
}
```

**Step 4: Verify it compiles**

```bash
cargo check -p zcash-test-miner
```

Expected: success, no errors.

**Step 5: Commit**

```bash
git add crates/zcash-test-miner/
git commit -m "scaffold: add zcash-test-miner crate to workspace"
```

---

### Task 2: CLI argument parsing

**Files:**
- Modify: `crates/zcash-test-miner/src/main.rs`

**Step 1: Implement CLI args with clap**

Replace `main.rs` with:

```rust
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "zcash-test-miner")]
#[command(about = "CPU Equihash test miner for Bedrock pool testing")]
struct Args {
    /// Pool SV2 endpoint
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool_addr: String,

    /// Number of simulated worker connections
    #[arg(long, default_value = "1")]
    workers: u32,

    /// Worker name prefix (names: {prefix}-1, {prefix}-2, ...)
    #[arg(long, default_value = "worker")]
    worker_prefix: String,

    /// CPU threads per worker for Equihash solving
    #[arg(long, default_value = "1")]
    solver_threads: u32,

    /// Pool's Noise public key (hex). If omitted, connects without encryption.
    #[arg(long)]
    pool_public_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    tracing::info!(
        pool_addr = %args.pool_addr,
        workers = args.workers,
        prefix = %args.worker_prefix,
        solver_threads = args.solver_threads,
        noise = args.pool_public_key.is_some(),
        "Starting zcash-test-miner"
    );

    Ok(())
}
```

**Step 2: Verify it compiles and runs with --help**

```bash
cargo run -p zcash-test-miner -- --help
```

Expected: usage output showing all flags.

**Step 3: Commit**

```bash
git add crates/zcash-test-miner/src/main.rs
git commit -m "feat: add CLI argument parsing for test miner"
```

---

### Task 3: Transport connection (plain + Noise)

**Files:**
- Create: `crates/zcash-test-miner/src/transport.rs`
- Modify: `crates/zcash-test-miner/src/main.rs` (add mod)

This task implements the transport layer -- connecting to the pool with either plain TCP or Noise_NK encryption, and reading/writing SV2 frames.

**Step 1: Create transport.rs**

The transport needs to:
1. Connect TCP to pool
2. Optionally run Noise_NK handshake (using `NoiseInitiator`)
3. Provide `read_message()` and `write_message()` methods that handle SV2 framing

```rust
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};
use zcash_mining_protocol::codec::MessageFrame;

use bedrock_noise::{NoiseInitiator, NoiseStream, PublicKey};

/// Transport for miner connections (plain or Noise-encrypted).
pub enum MinerTransport {
    Plain {
        stream: TcpStream,
        read_buf: Vec<u8>,
    },
    Noise(NoiseStream<TcpStream>),
}

impl MinerTransport {
    /// Connect to the pool, optionally upgrading to Noise_NK.
    pub async fn connect(
        addr: &str,
        server_pubkey: Option<&PublicKey>,
    ) -> io::Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        info!(addr, "TCP connected");

        match server_pubkey {
            Some(pk) => {
                let initiator = NoiseInitiator::new(pk.clone());
                let noise_stream = initiator
                    .connect(tcp)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
                info!("Noise_NK handshake complete");
                Ok(MinerTransport::Noise(noise_stream))
            }
            None => Ok(MinerTransport::Plain {
                stream: tcp,
                read_buf: Vec::with_capacity(4096),
            }),
        }
    }

    /// Read the next complete SV2-framed message.
    /// Returns the full frame bytes (header + payload).
    pub async fn read_message(&mut self) -> io::Result<Vec<u8>> {
        match self {
            MinerTransport::Noise(noise) => {
                let msg = noise.read_message().await?;
                if msg.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection closed",
                    ));
                }
                Ok(msg)
            }
            MinerTransport::Plain { stream, read_buf } => {
                loop {
                    // Try parsing a complete frame from the buffer
                    if read_buf.len() >= MessageFrame::HEADER_SIZE {
                        if let Ok(frame) = MessageFrame::decode(read_buf) {
                            let total = MessageFrame::HEADER_SIZE + frame.length as usize;
                            if read_buf.len() >= total {
                                let msg: Vec<u8> = read_buf.drain(..total).collect();
                                return Ok(msg);
                            }
                        }
                    }
                    // Need more data
                    let mut tmp = [0u8; 4096];
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "connection closed",
                        ));
                    }
                    read_buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }

    /// Write a complete SV2-framed message.
    pub async fn write_message(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            MinerTransport::Noise(noise) => {
                noise.write_message(data).await?;
                noise.flush().await?;
            }
            MinerTransport::Plain { stream, .. } => {
                stream.write_all(data).await?;
                stream.flush().await?;
            }
        }
        Ok(())
    }
}
```

**Step 2: Add mod to main.rs**

Add `mod transport;` to main.rs.

**Step 3: Verify it compiles**

```bash
cargo check -p zcash-test-miner
```

**Step 4: Commit**

```bash
git add crates/zcash-test-miner/src/transport.rs crates/zcash-test-miner/src/main.rs
git commit -m "feat: add transport layer with plain TCP and Noise_NK support"
```

---

### Task 4: Message dispatch (reading server messages)

**Files:**
- Create: `crates/zcash-test-miner/src/protocol.rs`
- Modify: `crates/zcash-test-miner/src/main.rs` (add mod)

This task implements parsing of incoming server messages (`NewEquihashJob`, `SubmitSharesResponse`, `SetTarget`) from raw frame bytes.

**Step 1: Create protocol.rs**

```rust
use zcash_mining_protocol::{
    codec::{decode_new_equihash_job, decode_set_target, decode_submit_shares_response, MessageFrame},
    messages::{message_types, NewEquihashJob, SetTarget, SubmitSharesResponse},
};

/// A message received from the pool server.
pub enum ServerMessage {
    NewJob(NewEquihashJob),
    ShareResponse(SubmitSharesResponse),
    SetTarget(SetTarget),
}

/// Decode raw frame bytes into a typed server message.
pub fn decode_server_message(data: &[u8]) -> Result<ServerMessage, String> {
    let frame = MessageFrame::decode(data).map_err(|e| format!("frame decode: {e}"))?;

    match frame.msg_type {
        message_types::NEW_EQUIHASH_JOB => {
            let job = decode_new_equihash_job(data).map_err(|e| format!("job decode: {e}"))?;
            Ok(ServerMessage::NewJob(job))
        }
        message_types::SUBMIT_SHARES_RESPONSE => {
            let resp =
                decode_submit_shares_response(data).map_err(|e| format!("response decode: {e}"))?;
            Ok(ServerMessage::ShareResponse(resp))
        }
        message_types::SET_TARGET => {
            let target = decode_set_target(data).map_err(|e| format!("set_target decode: {e}"))?;
            Ok(ServerMessage::SetTarget(target))
        }
        other => Err(format!("unknown message type: 0x{other:02x}")),
    }
}
```

**Step 2: Add mod to main.rs**

Add `mod protocol;` to main.rs.

**Step 3: Verify it compiles**

```bash
cargo check -p zcash-test-miner
```

**Step 4: Commit**

```bash
git add crates/zcash-test-miner/src/protocol.rs crates/zcash-test-miner/src/main.rs
git commit -m "feat: add server message decoding for test miner"
```

---

### Task 5: Worker loop (core mining logic)

**Files:**
- Create: `crates/zcash-test-miner/src/worker.rs`
- Modify: `crates/zcash-test-miner/src/main.rs` (add mod)

This is the main mining loop. Each worker:
1. Connects to pool (plain/Noise)
2. Waits for `NewEquihashJob`
3. Runs `solve_200_9()` in a blocking task
4. Submits shares that meet target
5. Handles `SubmitSharesResponse` and `SetTarget`
6. Repeats

**Step 1: Create worker.rs**

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use blake2b_simd::Params;
use rand::Rng;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use bedrock_noise::PublicKey;
use zcash_mining_protocol::{
    codec::encode_submit_share,
    messages::{NewEquihashJob, ShareResult, SubmitEquihashShare},
};

use crate::protocol::{decode_server_message, ServerMessage};
use crate::transport::MinerTransport;

/// Configuration for a single worker.
pub struct WorkerConfig {
    pub pool_addr: String,
    pub worker_name: String,
    pub solver_threads: u32,
    pub server_pubkey: Option<PublicKey>,
}

/// Run a single worker loop.
pub async fn run_worker(config: WorkerConfig, shutdown: watch::Receiver<bool>) {
    let name = &config.worker_name;
    info!(worker = %name, "Starting worker");

    loop {
        if *shutdown.borrow() {
            info!(worker = %name, "Shutdown received");
            return;
        }

        match run_worker_session(&config, shutdown.clone()).await {
            Ok(()) => {
                info!(worker = %name, "Session ended cleanly");
            }
            Err(e) => {
                error!(worker = %name, error = %e, "Session error");
            }
        }

        if *shutdown.borrow() {
            return;
        }

        // Reconnect delay with jitter
        let delay = Duration::from_secs(2) + Duration::from_millis(rand::thread_rng().gen_range(0..1000));
        info!(worker = %name, delay_ms = delay.as_millis(), "Reconnecting...");
        tokio::time::sleep(delay).await;
    }
}

async fn run_worker_session(
    config: &WorkerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let name = &config.worker_name;
    let mut transport = MinerTransport::connect(&config.pool_addr, config.server_pubkey.as_ref()).await?;
    info!(worker = %name, "Connected to pool");

    let mut sequence_number: u32 = 0;
    let mut current_target: Option<[u8; 32]> = None;
    let mut shares_submitted: u64 = 0;
    let mut shares_accepted: u64 = 0;
    let mut shares_rejected: u64 = 0;
    let mut blocks_found: u64 = 0;

    // Mining state: cancel flag for current solve
    let solving = Arc::new(AtomicBool::new(false));

    loop {
        // Read next message from pool
        let msg_data = tokio::select! {
            result = transport.read_message() => result?,
            _ = shutdown.changed() => {
                info!(worker = %name, "Shutdown during read");
                return Ok(());
            }
        };

        match decode_server_message(&msg_data) {
            Ok(ServerMessage::NewJob(job)) => {
                info!(
                    worker = %name,
                    channel_id = job.channel_id,
                    job_id = job.job_id,
                    clean = job.clean_jobs,
                    "Received job"
                );

                // Update target if job carries one
                current_target = Some(job.target);

                // Cancel any ongoing solve
                solving.store(false, Ordering::Release);

                // Solve in a blocking task
                let solving_flag = Arc::clone(&solving);
                solving_flag.store(true, Ordering::Release);

                let solver_threads = config.solver_threads;
                let worker_name = name.clone();
                let share_target = job.target;

                // Spawn solver tasks
                let (share_tx, mut share_rx) = tokio::sync::mpsc::channel::<SubmitEquihashShare>(16);

                for thread_idx in 0..solver_threads {
                    let job_clone = job.clone();
                    let solving_flag = Arc::clone(&solving_flag);
                    let share_tx = share_tx.clone();
                    let worker_name = worker_name.clone();

                    tokio::task::spawn_blocking(move || {
                        solve_and_submit(
                            &job_clone,
                            &share_target,
                            thread_idx,
                            solver_threads,
                            &solving_flag,
                            &share_tx,
                            &worker_name,
                        );
                    });
                }
                drop(share_tx); // Close sender so share_rx ends when all solvers finish

                // Collect shares and submit them
                // We need to interleave reading new messages while submitting shares
                loop {
                    tokio::select! {
                        share = share_rx.recv() => {
                            match share {
                                Some(mut share) => {
                                    sequence_number += 1;
                                    share.sequence_number = sequence_number;
                                    share.channel_id = job.channel_id;

                                    let encoded = encode_submit_share(&share)?;
                                    transport.write_message(&encoded).await?;
                                    shares_submitted += 1;

                                    // Check if this share also meets the network target (block found)
                                    let nonce = job.build_nonce(&share.nonce_2).unwrap();
                                    let header = job.build_header(&nonce);
                                    let hash = block_hash(&header, &share.solution);
                                    let bits_target = target_from_bits(job.bits);
                                    if meets_target(&hash, &bits_target) {
                                        blocks_found += 1;
                                        info!(
                                            worker = %worker_name,
                                            job_id = job.job_id,
                                            blocks_found,
                                            "BLOCK FOUND!"
                                        );
                                    }

                                    info!(
                                        worker = %worker_name,
                                        job_id = job.job_id,
                                        seq = sequence_number,
                                        total_submitted = shares_submitted,
                                        "Share submitted"
                                    );
                                }
                                None => {
                                    // All solver threads done for this job
                                    debug!(worker = %worker_name, "Solver threads done");
                                    break;
                                }
                            }
                        }
                        msg_result = transport.read_message() => {
                            let msg_data = msg_result?;
                            match decode_server_message(&msg_data) {
                                Ok(ServerMessage::ShareResponse(resp)) => {
                                    match resp.result {
                                        ShareResult::Accepted => {
                                            shares_accepted += 1;
                                            info!(
                                                worker = %name,
                                                seq = resp.sequence_number,
                                                accepted = shares_accepted,
                                                "Share accepted"
                                            );
                                        }
                                        ShareResult::Rejected(reason) => {
                                            shares_rejected += 1;
                                            warn!(
                                                worker = %name,
                                                seq = resp.sequence_number,
                                                rejected = shares_rejected,
                                                reason = ?reason,
                                                "Share rejected"
                                            );
                                        }
                                    }
                                }
                                Ok(ServerMessage::NewJob(new_job)) => {
                                    info!(
                                        worker = %name,
                                        job_id = new_job.job_id,
                                        clean = new_job.clean_jobs,
                                        "New job during solve - restarting"
                                    );
                                    solving_flag.store(false, Ordering::Release);
                                    current_target = Some(new_job.target);
                                    // Break out to handle the new job in the outer loop
                                    // We need to re-process this job -- but for simplicity,
                                    // the outer loop will read the next message.
                                    // Since we got a new job while solving, cancel and continue.
                                    break;
                                }
                                Ok(ServerMessage::SetTarget(st)) => {
                                    info!(worker = %name, "Target updated");
                                    current_target = Some(st.target);
                                }
                                Err(e) => {
                                    warn!(worker = %name, error = %e, "Unknown message during solve");
                                }
                            }
                        }
                        _ = shutdown.changed() => {
                            solving_flag.store(false, Ordering::Release);
                            return Ok(());
                        }
                    }
                }

                // Add small random delay between solve cycles for natural-looking hashrate
                let jitter = Duration::from_millis(rand::thread_rng().gen_range(50..200));
                tokio::time::sleep(jitter).await;
            }
            Ok(ServerMessage::ShareResponse(resp)) => {
                match resp.result {
                    ShareResult::Accepted => {
                        shares_accepted += 1;
                        info!(
                            worker = %name,
                            seq = resp.sequence_number,
                            accepted = shares_accepted,
                            "Share accepted"
                        );
                    }
                    ShareResult::Rejected(reason) => {
                        shares_rejected += 1;
                        warn!(
                            worker = %name,
                            seq = resp.sequence_number,
                            rejected = shares_rejected,
                            reason = ?reason,
                            "Share rejected"
                        );
                    }
                }
            }
            Ok(ServerMessage::SetTarget(st)) => {
                info!(worker = %name, "Target updated");
                current_target = Some(st.target);
            }
            Err(e) => {
                warn!(worker = %name, error = %e, "Unknown message");
            }
        }
    }
}

/// Run the tromp solver for a single job, submitting shares that meet target.
fn solve_and_submit(
    job: &NewEquihashJob,
    share_target: &[u8; 32],
    thread_idx: u32,
    total_threads: u32,
    solving: &AtomicBool,
    share_tx: &tokio::sync::mpsc::Sender<SubmitEquihashShare>,
    worker_name: &str,
) {
    let nonce_1 = &job.nonce_1;
    let nonce_2_len = job.nonce_2_len as usize;

    // Build the 108-byte input prefix (everything before nonce in the 140-byte header)
    let dummy_nonce = [0u8; 32];
    let full_header = job.build_header(&dummy_nonce);
    let input_prefix = &full_header[..108];

    // Each thread gets a different nonce range by using thread_idx as high bytes
    let mut nonce_counter: u64 = thread_idx as u64;

    loop {
        if !solving.load(Ordering::Acquire) {
            return;
        }

        // Build the full 32-byte nonce for this iteration
        let mut nonce_2 = vec![0u8; nonce_2_len];
        // Put counter bytes into nonce_2
        let counter_bytes = nonce_counter.to_le_bytes();
        let copy_len = counter_bytes.len().min(nonce_2_len);
        nonce_2[..copy_len].copy_from_slice(&counter_bytes[..copy_len]);

        let mut full_nonce = [0u8; 32];
        full_nonce[..nonce_1.len()].copy_from_slice(nonce_1);
        full_nonce[nonce_1.len()..nonce_1.len() + nonce_2_len].copy_from_slice(&nonce_2);

        // Call the tromp solver -- it processes one nonce at a time
        let solutions = equihash::tromp::solve_200_9(input_prefix, || {
            if !solving.load(Ordering::Acquire) {
                return None;
            }
            let n = full_nonce;
            // Only yield one nonce per call to solve_200_9 so we can check cancellation
            Some(n)
        });

        for sol_bytes in solutions {
            if !solving.load(Ordering::Acquire) {
                return;
            }

            // Check if solution meets share target
            let header = job.build_header(&full_nonce);
            let hash = block_hash(&header, &sol_bytes);

            if meets_target(&hash, share_target) {
                let solution: [u8; 1344] = sol_bytes
                    .try_into()
                    .expect("solver should produce 1344-byte solutions");

                let share = SubmitEquihashShare {
                    channel_id: 0, // filled in by caller
                    sequence_number: 0, // filled in by caller
                    job_id: job.job_id,
                    nonce_2: nonce_2.clone(),
                    time: job.time,
                    solution,
                };

                debug!(
                    worker = worker_name,
                    job_id = job.job_id,
                    "Found valid share"
                );

                if share_tx.blocking_send(share).is_err() {
                    // Channel closed, session ended
                    return;
                }
            }
        }

        // Advance nonce by total_threads so threads don't overlap
        nonce_counter += total_threads as u64;

        // Small sleep to let cancellation propagate (tromp solver is CPU-heavy)
        if nonce_counter % 4 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Compute the Zcash block hash: BLAKE2b-256 of (header || compact_size(1344) || solution)
/// with personalization "ZcashBlockHash\0\0".
fn block_hash(header: &[u8; 140], solution: &[u8]) -> [u8; 32] {
    // compact_size for 1344 = 0xfd 0x40 0x05 (3 bytes)
    let compact_size: [u8; 3] = [0xfd, 0x40, 0x05];

    let hash = Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockHash\0\0")
        .to_state()
        .update(header)
        .update(&compact_size)
        .update(solution)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Check if hash meets target (both little-endian 256-bit, MSB at index 31).
fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true // equal
}

/// Convert compact bits (nBits) to a 256-bit target.
fn target_from_bits(bits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = ((bits >> 24) & 0xff) as usize;
    let mantissa = bits & 0x007fffff;

    if exponent >= 3 {
        let start = exponent - 3;
        if start < 32 {
            target[start] = (mantissa & 0xff) as u8;
        }
        if start + 1 < 32 {
            target[start + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if start + 2 < 32 {
            target[start + 2] = ((mantissa >> 16) & 0xff) as u8;
        }
    }

    target
}
```

**Step 2: Add mod to main.rs**

Add `mod worker;` to main.rs.

**Step 3: Verify it compiles**

```bash
cargo check -p zcash-test-miner
```

Note: The `equihash` solver feature requires C compilation. If this fails on the tromp solver build, it means the C toolchain is available (it should be since the crate already exists in the workspace's Cargo.lock). Check that `cc` build dependency is satisfied.

**Step 4: Commit**

```bash
git add crates/zcash-test-miner/src/worker.rs crates/zcash-test-miner/src/main.rs
git commit -m "feat: add worker mining loop with Equihash solving and share submission"
```

---

### Task 6: Main orchestrator (spawn workers, handle shutdown)

**Files:**
- Modify: `crates/zcash-test-miner/src/main.rs`

**Step 1: Implement the full main.rs**

```rust
mod protocol;
mod transport;
mod worker;

use clap::Parser;
use tokio::sync::watch;
use tracing::info;

use bedrock_noise::PublicKey;

use crate::worker::{run_worker, WorkerConfig};

#[derive(Parser, Debug)]
#[command(name = "zcash-test-miner")]
#[command(about = "CPU Equihash test miner for Bedrock pool testing")]
struct Args {
    /// Pool SV2 endpoint
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool_addr: String,

    /// Number of simulated worker connections
    #[arg(long, default_value = "1")]
    workers: u32,

    /// Worker name prefix (names: {prefix}-1, {prefix}-2, ...)
    #[arg(long, default_value = "worker")]
    worker_prefix: String,

    /// CPU threads per worker for Equihash solving
    #[arg(long, default_value = "1")]
    solver_threads: u32,

    /// Pool's Noise public key (hex). If omitted, connects without encryption.
    #[arg(long)]
    pool_public_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let server_pubkey = match &args.pool_public_key {
        Some(hex_key) => Some(PublicKey::from_hex(hex_key)?),
        None => None,
    };

    info!(
        pool_addr = %args.pool_addr,
        workers = args.workers,
        prefix = %args.worker_prefix,
        solver_threads = args.solver_threads,
        noise = server_pubkey.is_some(),
        "Starting zcash-test-miner"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn worker tasks
    let mut handles = Vec::new();
    for i in 1..=args.workers {
        let worker_name = format!("{}-{}", args.worker_prefix, i);
        let config = WorkerConfig {
            pool_addr: args.pool_addr.clone(),
            worker_name,
            solver_threads: args.solver_threads,
            server_pubkey: server_pubkey.clone(),
        };
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            run_worker(config, rx).await;
        }));
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping workers...");
    let _ = shutdown_tx.send(true);

    // Wait for all workers to finish
    for handle in handles {
        let _ = handle.await;
    }

    info!("All workers stopped. Goodbye.");
    Ok(())
}
```

**Step 2: Verify it compiles**

```bash
cargo check -p zcash-test-miner
```

**Step 3: Commit**

```bash
git add crates/zcash-test-miner/src/main.rs
git commit -m "feat: add main orchestrator with multi-worker spawning and graceful shutdown"
```

---

### Task 7: Full build verification

**Step 1: Run cargo build (release)**

```bash
cargo build -p zcash-test-miner --release
```

This compiles the tromp C solver and links it. Should succeed.

**Step 2: Run clippy**

```bash
cargo clippy -p zcash-test-miner -- -D warnings
```

Fix any warnings.

**Step 3: Commit any fixes**

```bash
git add crates/zcash-test-miner/
git commit -m "fix: address clippy warnings in test miner"
```

---

### Task 8: Dockerfile

**Files:**
- Create: `crates/zcash-test-miner/Dockerfile`

**Step 1: Create the Dockerfile**

Multi-stage build:

```dockerfile
# Stage 1: Build
FROM rust:1.77-bookworm AS builder

# Install C/C++ toolchain for equihash tromp solver
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary
RUN cargo build -p zcash-test-miner --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zcash-test-miner /usr/local/bin/

ENTRYPOINT ["zcash-test-miner"]
```

**Step 2: Commit**

```bash
git add crates/zcash-test-miner/Dockerfile
git commit -m "feat: add Dockerfile for test miner"
```

---

### Task 9: Fix issues found during compilation and integration

This is a buffer task. During Tasks 3-7, compilation may reveal:
- Type mismatches (e.g., `NewEquihashJob` fields may not implement `Clone`)
- Missing trait implementations
- API differences from what the exploration agents reported

Handle these as they arise. Common fixes:
- Add `#[derive(Clone)]` to message types if needed, or clone fields manually
- Adjust `solve_200_9` call signature if the const generic doesn't match
- Handle any `Result` vs `Option` mismatches

**After all fixes, final commit:**

```bash
git add -A
git commit -m "fix: resolve compilation issues in test miner integration"
```
