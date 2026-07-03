//! PoC miner-side onboarding client (see docs/miner-onboarding.md §4).
//!
//! Run on the miner's own host. Generates a fresh 32-byte mesh key locally,
//! persists it (the relay node loads it to sign mesh traffic), and registers it
//! with the enroll service using a one-time invite code. On success the key is
//! auto-added to the mesh and the node can connect to the returned peers.
//!
//! Usage:
//!   mesh-enroll --server 127.0.0.1:8088 --invite <code> \
//!               --miner-id pool-alpha --endpoint 203.0.113.7:9000 \
//!               [--key-out mesh-key.hex] [--dry-run]
//!
//! NOTE: the key is transmitted once, in the enroll request. Production MUST
//! send this over TLS (server-authenticated HTTPS). This PoC uses plain HTTP.

use std::process::ExitCode;

use sovright_mesh_enroll::{build_enroll_request, http};

struct Args {
    server: String,
    invite: String,
    miner_id: String,
    endpoint: String,
    key_out: String,
    dry_run: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut server = "127.0.0.1:8088".to_string();
    let mut invite = String::new();
    let mut miner_id = String::new();
    let mut endpoint = String::new();
    let mut key_out = "mesh-key.hex".to_string();
    let mut dry_run = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--server" => server = next()?,
            "--invite" => invite = next()?,
            "--miner-id" => miner_id = next()?,
            "--endpoint" => endpoint = next()?,
            "--key-out" => key_out = next()?,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => return Err("help".into()),
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    for (name, v) in [
        ("--invite", &invite),
        ("--miner-id", &miner_id),
        ("--endpoint", &endpoint),
    ] {
        if v.is_empty() {
            return Err(format!("missing required {name}"));
        }
    }
    Ok(Args {
        server,
        invite,
        miner_id,
        endpoint,
        key_out,
        dry_run,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "usage: mesh-enroll --server <ip:port> --invite <code> --miner-id <id> \
                 --endpoint <ip:port> [--key-out <file>] [--dry-run]"
            );
            if e != "help" {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
            return ExitCode::SUCCESS;
        }
    };

    // Generate the key locally and build the request.
    let (key, req) = build_enroll_request(&args.invite, &args.miner_id, &args.endpoint);
    let body = serde_json::to_string(&req).expect("serialize request");

    if args.dry_run {
        println!("generated mesh key fingerprint: {:?}", key);
        println!("would POST http://{}/v1/enroll:", args.server);
        println!("{body}");
        return ExitCode::SUCCESS;
    }

    // Persist the key BEFORE sending, so a crash after the server registers it
    // never leaves the node unable to sign with the key the mesh now trusts.
    if let Err(e) = std::fs::write(&args.key_out, key.to_hex()) {
        eprintln!("error: could not write key to {}: {e}", args.key_out);
        return ExitCode::FAILURE;
    }

    match http::post_json(&args.server, "/v1/enroll", &body) {
        Ok((200, resp)) => {
            println!("enrolled. mesh key saved to {}", args.key_out);
            println!("server response: {resp}");
            println!(
                "next: start relay-node with this key and connect to the returned mesh_peers."
            );
            ExitCode::SUCCESS
        }
        Ok((status, resp)) => {
            eprintln!("enroll rejected (HTTP {status}): {resp}");
            // The key we wrote is useless without registration; remove it.
            let _ = std::fs::remove_file(&args.key_out);
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("enroll request failed: {e}");
            let _ = std::fs::remove_file(&args.key_out);
            ExitCode::FAILURE
        }
    }
}
