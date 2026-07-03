//! `sovright-inject-block` (PoC CLI)
//!
//! Reads a hex-encoded serialized Zcash block from a file or stdin and POSTs it
//! to a relay's block-injection endpoint, authenticated with a per-miner
//! HMAC-SHA256 key. See `docs/miner-direct-injection.md`.
//!
//! Usage:
//!   sovright-inject-block \
//!     --relay 10.0.0.1:8645 \
//!     --miner-id pool-alpha \
//!     --key-hex <64-hex-chars> \
//!     --block-file block.hex        # or omit to read hex from stdin
//!
//! Env fallbacks: SOVRIGHT_INJECT_RELAY, SOVRIGHT_INJECT_MINER_ID,
//! SOVRIGHT_INJECT_KEY_HEX.
//!
//! This is a proof-of-concept: plaintext HTTP, no TLS, no retry/backoff. It is
//! deliberately minimal; production hardening is described in the design doc.

use std::io::Read;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sovright_miner_injector::{DEFAULT_INJECT_PATH, InjectionRequest, MinerCredentials};

struct Args {
    relay: String,
    miner_id: String,
    key_hex: String,
    block_file: Option<String>,
    path: String,
    dry_run: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut relay = std::env::var("SOVRIGHT_INJECT_RELAY").ok();
    let mut miner_id = std::env::var("SOVRIGHT_INJECT_MINER_ID").ok();
    let mut key_hex = std::env::var("SOVRIGHT_INJECT_KEY_HEX").ok();
    let mut block_file = None;
    let mut path = DEFAULT_INJECT_PATH.to_string();
    let mut dry_run = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--relay" => relay = Some(next(&mut it, "--relay")?),
            "--miner-id" => miner_id = Some(next(&mut it, "--miner-id")?),
            "--key-hex" => key_hex = Some(next(&mut it, "--key-hex")?),
            "--block-file" => block_file = Some(next(&mut it, "--block-file")?),
            "--path" => path = next(&mut it, "--path")?,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown argument: {other}\n\n{}", usage())),
        }
    }

    Ok(Args {
        relay: relay.ok_or_else(|| format!("--relay is required\n\n{}", usage()))?,
        miner_id: miner_id.ok_or_else(|| format!("--miner-id is required\n\n{}", usage()))?,
        key_hex: key_hex.ok_or_else(|| format!("--key-hex is required\n\n{}", usage()))?,
        block_file,
        path,
        dry_run,
    })
}

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn usage() -> String {
    "sovright-inject-block --relay HOST:PORT --miner-id ID --key-hex HEX32 \
     [--block-file PATH] [--path /v1/inject/block] [--dry-run]\n\
     If --block-file is omitted, the hex block is read from stdin."
        .to_string()
}

fn read_block_hex(args: &Args) -> Result<Vec<u8>, String> {
    let hex_text = match &args.block_file {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?
        }
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            buf
        }
    };
    let cleaned: String = hex_text.split_whitespace().collect();
    hex::decode(&cleaned).map_err(|e| format!("block is not valid hex: {e}"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort 16-byte nonce from OS-ish entropy. PoC only: mixes time and the
/// process id. Production should use a CSPRNG (getrandom); avoided here to keep
/// the PoC dependency-free.
fn poc_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nonce[..8].copy_from_slice(&(t as u64).to_le_bytes());
    nonce[8..].copy_from_slice(&(std::process::id() as u64).to_le_bytes());
    nonce
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let creds =
        MinerCredentials::from_hex_key(&args.miner_id, &args.key_hex).map_err(|e| e.to_string())?;
    let body = read_block_hex(&args)?;

    let req = InjectionRequest::build(
        &creds,
        &args.relay,
        &args.path,
        now_unix(),
        poc_nonce(),
        body,
    )
    .map_err(|e| e.to_string())?;

    eprintln!(
        "prepared injection: miner_id={} bytes={} auth={}…",
        req.miner_id,
        req.body.len(),
        &req.auth_hex[..16.min(req.auth_hex.len())]
    );

    if args.dry_run {
        // Print the raw HTTP request instead of sending it.
        print!("{}", String::from_utf8_lossy(&req.to_http_bytes()));
        return Ok(());
    }

    let resp = req.send_tcp(&args.relay).map_err(|e| e.to_string())?;
    println!("relay accepted injection: {resp}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
