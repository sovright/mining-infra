//! `SOVRIGHT_RELAY_BOUND_RAW` on a real `relay-node`. What a value does is shown by what a
//! node does: a real body from a real client crosses it or does not, with legacy crossing to
//! show the node is working. A value it cannot read has to stop the start.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};

use sovright_relay::{
    BlockReceiver, BlockSender, BoundBlock, BoundRawConfig, ClientConfig, RelayClient,
    ZCASH_FULL_HEADER_SIZE, split_raw_block, zcash_block_hash,
};
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use zcash_pool_common::fixtures;

const SWITCH: &str = "SOVRIGHT_RELAY_BOUND_RAW";
const KEY: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(10);

fn relay_node(value: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_relay-node"));
    command
        .env("SOVRIGHT_RELAY_AUTH_KEY_HEX", hex::encode(KEY))
        .env("SOVRIGHT_RELAY_LISTEN_ADDR", "127.0.0.1:0")
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .env_remove(SWITCH);
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

/// A node from its own binary, which goes when this does.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_node(value: Option<&str>) -> (Node, SocketAddr) {
    let mut command = relay_node(value);
    command
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    let (found, listening) = channel();
    thread::spawn(move || {
        for line in out.lines().map_while(Result::ok) {
            let addr = line.split_once("local_addr=");
            let addr = addr.and_then(|(_, rest)| rest.split_whitespace().next()?.parse().ok());
            if let Some(addr) = addr {
                let _ = found.send(addr);
            }
        }
    });
    let node = Node(child);
    let addr = listening.recv_timeout(WAIT).expect("it never listened");
    (node, addr)
}

fn config(node: SocketAddr) -> ClientConfig {
    ClientConfig::new(vec![node], KEY)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true)
        .with_fec(10, 3)
}

/// Bodies with real proof of work, each new to everybody, for a real check on a real node.
fn legacy_bodies() -> Vec<Vec<u8>> {
    let listed: Vec<serde_json::Value> =
        serde_json::from_str(fixtures::EQUIHASH_MAINNET_HEADERS).unwrap();
    listed
        .iter()
        .map(|entry| {
            let mut raw = hex::decode(entry["header"].as_str().unwrap()).unwrap();
            raw.resize(5000, 7);
            raw
        })
        .collect()
}

/// A sender and a receiver with the bound path on, through a node with whatever the switch says.
struct Path {
    _node: Node,
    sender: BlockSender,
    receiver: BlockReceiver,
    blocks: Receiver<BoundBlock>,
    legacy: Vec<Vec<u8>>,
}

impl Path {
    async fn start(value: Option<&str>) -> Self {
        let (node, addr) = start_node(value);
        let with_bound = config(addr).with_bound_raw(BoundRawConfig::default());
        let mut receiving = RelayClient::new(with_bound).unwrap();
        receiving.bind().await.unwrap();
        let (mut receiver, outgoing) = receiving.take_receiver().unwrap();
        let blocks = receiver.take_bound_blocks().unwrap();
        tokio::spawn(async move { receiving.run_with_outgoing(outgoing).await });
        let mut sending = RelayClient::new(config(addr)).unwrap();
        sending.bind().await.unwrap();
        let sender = sending.sender();
        tokio::spawn(async move { sending.run().await });
        let mut path = Self {
            _node: node,
            sender,
            receiver,
            blocks,
            legacy: legacy_bodies(),
        };
        path.legacy_crosses().await;
        path
    }

    /// A new body each try, as a session can come after the first, and a node sends one
    /// object once. Packets stay in order on loopback and a node takes them in turn, so
    /// anything sent before this that was going to cross has crossed once this does.
    async fn legacy_crosses(&mut self) {
        while let Some(raw) = self.legacy.pop() {
            let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
            for segment in split_raw_block(hash, &raw, 10 * 1124 - 4).unwrap() {
                self.sender.send_raw_block_segment(segment).await.unwrap();
            }
            let crossed = self.receiver.recv_raw_block_segment();
            if timeout(Duration::from_millis(300), crossed).await.is_ok() {
                return;
            }
        }
        panic!("legacy never crossed");
    }

    async fn send_bound(&self, raw: &[u8]) {
        let send = self.sender.send_bound_raw_block(Arc::new(raw.to_vec()));
        timeout(WAIT, send).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn one_opens_the_path_on_a_real_node() {
    let raw = fixtures::mainnet_raw_block();
    for value in ["1", "true"] {
        let mut path = Path::start(Some(value)).await;

        path.send_bound(&raw).await;

        let block = timeout(WAIT, path.blocks.recv()).await;
        assert_eq!(block.expect(value).unwrap().raw(), raw);
    }
}

#[tokio::test]
async fn zero_leaves_the_path_shut_on_a_real_node() {
    let raw = fixtures::mainnet_raw_block();
    for value in [None, Some("0"), Some("false"), Some("")] {
        let mut path = Path::start(value).await;

        path.send_bound(&raw).await;
        path.legacy_crosses().await;

        assert!(path.blocks.try_recv().is_err(), "{value:?}");
    }
}

#[test]
fn relay_node_refuses_an_invalid_bound_switch() {
    let output = ends_by_itself(relay_node(Some("maybe")));

    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(SWITCH) && error.contains("maybe"), "{error}");
}

/// What an operator sees under the default log filter. An address it cannot use stops it
/// right after the switch is read.
fn log_of(value: &str) -> String {
    let mut command = relay_node(Some(value));
    command.env("SOVRIGHT_RELAY_LISTEN_ADDR", "not an address");
    let output = ends_by_itself(command);
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
