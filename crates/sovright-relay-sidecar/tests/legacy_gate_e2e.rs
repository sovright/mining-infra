//! The legacy loop end to end with every #130 switch off, on a real sidecar binary with its
//! submit gate on (review item 2 on #134). A legacy block goes node -> sidecar -> gate ->
//! Zebra and is taken, and the gate on this path is the legacy one: it holds its lock across
//! the Zebra call and marks the block when the copy passes. How the legacy gate decides is
//! pinned at the submit path in `block_body.rs`
//! (`the_legacy_gate_still_lets_a_refused_body_close_the_block`), since the relay client
//! drops a block's later copies before they reach the gate.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::json;
use sovright_relay::{
    AuthKey, ClientConfig, RelayClient, RelayConfig, RelayNode, StubPowValidator,
    ZCASH_FULL_HEADER_SIZE, split_raw_block, zcash_block_hash,
};
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

const SWITCH: &str = "SOVRIGHT_RELAY_BOUND_RAW";
const KEY: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(10);

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Every `submitblock` call. Zebra takes every block.
type Calls = Arc<Mutex<Vec<String>>>;

async fn zebra() -> (SocketAddr, Calls, ServerHandle) {
    let calls = Calls::default();
    let mut module = RpcModule::new(Arc::clone(&calls));
    module
        .register_method("submitblock", |params, calls, _| {
            let (block_hex,): (String,) = params.parse()?;
            calls.lock().unwrap().push(block_hex);
            Ok::<Option<String>, ErrorObjectOwned>(None)
        })
        .unwrap();
    // Every parent is known, one below the tip.
    module
        .register_method("getblockheader", |params, _, _| {
            let (hash, _verbose): (String, bool) = params.parse()?;
            Ok::<_, ErrorObjectOwned>(json!({
                "hash": hash,
                "height": 100,
                "confirmations": 1,
            }))
        })
        .unwrap();
    module
        .register_method("getblockchaininfo", |_, _, _| {
            Ok::<_, ErrorObjectOwned>(json!({
                "blocks": 100,
                "bestblockhash": "00".repeat(32),
            }))
        })
        .unwrap();
    let server = ServerBuilder::default()
        .http_only()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    (addr, calls, server.start(module))
}

#[tokio::test]
async fn with_every_switch_off_a_legacy_block_crosses_the_gate_to_zebra() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
        .with_fec(10, 3);
    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
    node.bind().await.unwrap();
    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let running = Arc::clone(&node);
    tokio::spawn(async move { running.run().await });

    let (zebra_addr, calls, _zebra) = zebra().await;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("sidecar.toml");
    std::fs::write(
        &config_path,
        format!(
            "zebra_url = \"http://{zebra_addr}\"\n\
             relay_peers = [\"{node_addr}\"]\n\
             auth_key = \"{}\"\n\
             bind_addr = \"127.0.0.1:0\"\n\
             data_shards = 10\n\
             parity_shards = 3\n\
             announce_templates = false\n\
             receive_relay_blocks = true\n\
             enable_submitblock = true\n\
             \n\
             [submit_gate]\n\
             enabled = true\n",
            hex::encode(KEY)
        ),
    )
    .unwrap();
    let _sidecar = Running(
        Command::new(env!("CARGO_BIN_EXE_relay-sidecar"))
            .env_remove("RUST_LOG")
            .env_remove(SWITCH)
            .arg("--config")
            .arg(&config_path)
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let mut sending = RelayClient::new(
        ClientConfig::new(vec![node_addr], KEY)
            .with_bind_addr("127.0.0.1:0".parse().unwrap())
            .with_auth_required(true)
            .with_fec(10, 3),
    )
    .unwrap();
    sending.bind().await.unwrap();
    let sender = sending.sender();
    tokio::spawn(async move { sending.run().await });
    let sessions = async {
        while node.session_count().await < 2 {
            sleep(Duration::from_millis(5)).await;
        }
    };
    timeout(WAIT, sessions).await.expect("no sidecar came");

    let raw = fixtures::mainnet_raw_block();
    let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
    for segment in split_raw_block(hash, &raw, 10 * 1124 - 4).unwrap() {
        sender.send_raw_block_segment(segment).await.unwrap();
    }

    let wanted = hex::encode(&raw);
    let taken = async {
        while !calls.lock().unwrap().contains(&wanted) {
            sleep(Duration::from_millis(5)).await;
        }
    };
    timeout(WAIT, taken)
        .await
        .expect("Zebra never got the block");
    sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.lock().unwrap().len(), 1);
}
