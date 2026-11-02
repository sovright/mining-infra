//! `SOVRIGHT_RELAY_BOUND_RAW` on a real sidecar. What a value does is shown by what the sidecar
//! does: a body sent the bound way reaches its Zebra or does not, with a legacy block behind
//! it to show the sidecar is working. Zebra is a stand-in that takes everything, and the node
//! always has the path on, so the sidecar's switch is the only one in question.

use std::net::SocketAddr;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use sovright_relay::test_support::{committed_header, parseable_transaction, raw_block};
use sovright_relay::{
    AuthKey, BlockSender, ClientConfig, RelayClient, RelayConfig, RelayNode, StubPowValidator,
    ZCASH_FULL_HEADER_SIZE, split_raw_block, zcash_block_hash,
};
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

const SWITCH: &str = "SOVRIGHT_RELAY_BOUND_RAW";
const KEY: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(10);

fn sidecar(value: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_relay-sidecar"));
    command.env_remove("RUST_LOG").env_remove(SWITCH);
    if let Some(value) = value {
        command.env(SWITCH, value);
    }
    command
}

/// A run that has to end by itself. It gets as long as any wait here.
fn ends_by_itself(mut command: Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + WAIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("it never stopped");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

/// A sidecar from its own binary, which goes when this does.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

type Taken = Arc<Mutex<Vec<String>>>;

/// A Zebra that takes every block and remembers it.
async fn zebra() -> (SocketAddr, Taken, ServerHandle) {
    let taken = Taken::default();
    let mut module = RpcModule::new(Arc::clone(&taken));
    module
        .register_method("submitblock", |params, taken, _| {
            let (block_hex,): (String,) = params.parse()?;
            taken.lock().unwrap().push(block_hex);
            Ok::<Option<String>, ErrorObjectOwned>(None)
        })
        .unwrap();
    let server = ServerBuilder::default()
        .http_only()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    (addr, taken, server.start(module))
}

/// A node, a sender and a real sidecar behind it, with whatever the switch says.
struct Path {
    _sidecar: Running,
    _zebra: ServerHandle,
    taken: Taken,
    sender: BlockSender,
}

impl Path {
    async fn start(value: Option<&str>) -> Self {
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
            .with_fec(10, 3)
            .with_bound_raw(Default::default());
        let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
        node.bind().await.unwrap();
        let addr = node.local_addr().unwrap();
        let node = Arc::new(node);
        let running = Arc::clone(&node);
        tokio::spawn(async move { running.run().await });

        let (zebra_addr, taken, zebra) = zebra().await;
        let mut command = sidecar(value);
        command
            .args(["--relay-peer", &addr.to_string()])
            .args(["--auth-key", &hex::encode(KEY)])
            .args(["--bind-addr", "127.0.0.1:0"])
            .args(["--zebra-url", &format!("http://{zebra_addr}")])
            .args(["--data-shards", "10", "--parity-shards", "3"])
            .args(["--receive-relay-blocks", "--enable-submitblock"])
            .arg("--disable-template-announcements")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let running = Running(command.spawn().unwrap());

        let mut sending = RelayClient::new(
            ClientConfig::new(vec![addr], KEY)
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

        Self {
            _sidecar: running,
            _zebra: zebra,
            taken,
            sender,
        }
    }

    async fn send_bound(&self, raw: &[u8]) {
        let send = self.sender.send_bound_raw_block(Arc::new(raw.to_vec()));
        timeout(WAIT, send).await.unwrap().unwrap();
    }

    async fn send_legacy(&self, raw: &[u8]) {
        let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
        for segment in split_raw_block(hash, raw, 10 * 1124 - 4).unwrap() {
            self.sender.send_raw_block_segment(segment).await.unwrap();
        }
    }

    fn took(&self, raw: &[u8]) -> bool {
        let wanted = hex::encode(raw);
        self.taken.lock().unwrap().contains(&wanted)
    }

    async fn zebra_takes(&self, raw: &[u8]) {
        let takes = async {
            while !self.took(raw) {
                sleep(Duration::from_millis(5)).await;
            }
        };
        timeout(WAIT, takes).await.expect("Zebra never got it");
    }
}

fn a_legacy_block() -> Vec<u8> {
    let txs = vec![parseable_transaction(400), parseable_transaction(401)];
    raw_block(&committed_header(200, &txs), &txs)
}

#[tokio::test]
async fn one_opens_the_path_on_a_real_sidecar() {
    let raw = fixtures::mainnet_raw_block();
    for value in ["1", "true"] {
        let path = Path::start(Some(value)).await;

        path.send_bound(&raw).await;

        path.zebra_takes(&raw).await;
    }
}

/// Packets stay in order on loopback and each task takes them in turn, so a body that was going
/// to cross has crossed once the legacy block behind it reaches Zebra.
#[tokio::test]
async fn zero_leaves_the_path_shut_on_a_real_sidecar() {
    let (raw, legacy) = (fixtures::mainnet_raw_block(), a_legacy_block());
    for value in [None, Some("0"), Some("false"), Some("")] {
        let path = Path::start(value).await;

        path.send_bound(&raw).await;
        path.send_legacy(&legacy).await;

        path.zebra_takes(&legacy).await;
        assert!(!path.took(&raw), "{value:?}");
    }
}

#[test]
fn a_sidecar_refuses_an_invalid_bound_switch() {
    let mut command = sidecar(Some("maybe"));
    command.args(["--relay-peer", "127.0.0.1:1"]);
    let output = ends_by_itself(command);

    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(SWITCH) && error.contains("maybe"), "{error}");
}

/// What an operator sees under the default log filter. With no relay peer it stops right after
/// the switch is read.
fn log_of(value: &str) -> String {
    let output = ends_by_itself(sidecar(Some(value)));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn an_empty_switch_says_so() {
    let log = log_of("");
    assert!(log.contains("is set and empty"), "{log}");
}

#[test]
fn a_switch_that_is_on_says_so() {
    let log = log_of("1");
    assert!(log.contains("Bound raw switch on"), "{log}");
}
