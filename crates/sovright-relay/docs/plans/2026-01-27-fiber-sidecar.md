# Forge Sidecar Implementation Plan

> Note: This document was written before the rename from fiber-zcash to bedrock-forge. Some internal references may still use the old name.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a standalone binary that enables Stratum V1 mining pools to use bedrock-forge for low-latency block relay without modifying their existing pool software.

**Architecture:** The sidecar polls Zebra RPC for new block templates, builds CompactBlocks, and announces them to the Forge relay network. It also receives blocks from the relay network and submits them to Zebra. This allows any V1 pool (NOMP, etc.) to benefit from compact block relay.

**Tech Stack:** Rust, tokio, bedrock-forge library, jsonrpsee for Zebra RPC

---

## Overview

```
┌─────────────────┐
│  STRATUM V1     │  (unmodified - NOMP, etc.)
│  POOL SERVER    │
└────────┬────────┘
         │ getblocktemplate / submitblock
         ▼
┌─────────────────┐
│   ZEBRA NODE    │◄───────────────────────┐
│  (JSON-RPC)     │                        │
└────────┬────────┘                        │
         │ poll / notify                   │ submitblock
         ▼                                 │
┌─────────────────┐                        │
│  FORGE SIDECAR  │────────────────────────┘
│  (new binary)   │
│                 │
│ • Poll templates│
│ • Build compact │
│ • Announce/recv │
└────────┬────────┘
         │ UDP/FEC
         ▼
┌─────────────────┐
│  FORGE RELAY    │
│    NETWORK      │
└─────────────────┘
```

---

### Task 1: Create sidecar crate structure

**Files:**
- Create: `forge-sidecar/Cargo.toml`
- Create: `forge-sidecar/src/main.rs`
- Modify: `Cargo.toml` (workspace)

**Step 1: Create sidecar directory**

```bash
mkdir -p forge-sidecar/src
```

**Step 2: Create Cargo.toml**

```toml
[package]
name = "forge-sidecar"
version = "0.1.0"
edition = "2021"
description = "Forge relay sidecar for Stratum V1 mining pools"
license = "MIT OR Apache-2.0"

[[bin]]
name = "forge-sidecar"
path = "src/main.rs"

[dependencies]
bedrock-forge = { path = ".." }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
hex = "0.4"
sha2 = "0.10"

# Zebra RPC client
jsonrpsee = { version = "0.24", features = ["http-client"] }
```

**Step 3: Create minimal main.rs**

```rust
//! Forge sidecar for Stratum V1 mining pools

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "forge-sidecar")]
#[command(about = "Forge relay sidecar for Stratum V1 mining pools")]
struct Args {
    /// Zebra RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8232")]
    zebra_url: String,

    /// Forge relay peer addresses
    #[arg(long, required = true)]
    relay_peer: Vec<String>,

    /// Authentication key (hex)
    #[arg(long)]
    auth_key: Option<String>,

    /// Local bind address for Forge
    #[arg(long, default_value = "0.0.0.0:0")]
    bind_addr: String,

    /// Poll interval in milliseconds
    #[arg(long, default_value = "100")]
    poll_interval_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!(zebra_url = %args.zebra_url, "Starting Forge sidecar");

    // TODO: Implement sidecar logic

    Ok(())
}
```

**Step 4: Add to workspace**

Add `"forge-sidecar"` to members in root `Cargo.toml`.

**Step 5: Verify build**

Run: `cargo build -p forge-sidecar`
Expected: Build succeeds

**Step 6: Commit**

```bash
git add forge-sidecar Cargo.toml
git commit -m "feat(sidecar): add forge-sidecar crate structure"
```

---

### Task 2: Implement Zebra RPC client

**Files:**
- Create: `forge-sidecar/src/rpc.rs`
- Modify: `forge-sidecar/src/main.rs`

**Step 1: Create rpc.rs**

```rust
//! Zebra JSON-RPC client for getblocktemplate and submitblock

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Zebra RPC client
pub struct ZebraRpc {
    client: HttpClient,
    request_id: AtomicU64,
}

/// Transaction in block template
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateTransaction {
    /// Transaction data (hex)
    pub data: String,
    /// Transaction hash (hex, little-endian)
    pub hash: String,
    /// Transaction fee in zatoshis
    #[serde(default)]
    pub fee: i64,
}

/// Block template response from getblocktemplate
#[derive(Debug, Clone, Deserialize)]
pub struct BlockTemplate {
    /// Block version
    pub version: u32,
    /// Previous block hash (hex)
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: String,
    /// Block time
    #[serde(rename = "curtime")]
    pub cur_time: u64,
    /// Target bits (hex)
    pub bits: String,
    /// Block height
    pub height: u64,
    /// Transactions to include
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase transaction (hex)
    #[serde(rename = "coinbasetxn")]
    pub coinbase_txn: Option<CoinbaseTxn>,
    /// Default commitment (hex) for block header
    #[serde(rename = "defaultroots")]
    pub default_roots: Option<DefaultRoots>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CoinbaseTxn {
    pub data: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultRoots {
    /// Merkle root (hex)
    #[serde(rename = "merkleroot")]
    pub merkle_root: String,
    /// Block commitments hash (hex)
    #[serde(rename = "blockcommitmentshash")]
    pub block_commitments_hash: Option<String>,
    /// Chain history root (hex)
    #[serde(rename = "chainhistoryroot")]
    pub chain_history_root: Option<String>,
    /// Auth data root (hex)
    #[serde(rename = "authdataroot")]
    pub auth_data_root: Option<String>,
}

/// Parameters for getblocktemplate
#[derive(Debug, Serialize)]
pub struct GetBlockTemplateParams {
    pub mode: String,
}

impl ZebraRpc {
    /// Create a new Zebra RPC client
    pub async fn new(url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = HttpClientBuilder::default()
            .build(url)?;
        Ok(Self {
            client,
            request_id: AtomicU64::new(1),
        })
    }

    /// Get a block template from Zebra
    pub async fn get_block_template(&self) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
        let params = GetBlockTemplateParams {
            mode: "template".to_string(),
        };
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let template: BlockTemplate = self.client
            .request("getblocktemplate", rpc_params![params])
            .await?;

        Ok(template)
    }

    /// Submit a block to Zebra
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let _id = self.request_id.fetch_add(1, Ordering::SeqCst);

        // submitblock returns null on success, or an error string
        let result: Option<String> = self.client
            .request("submitblock", rpc_params![block_hex])
            .await?;

        Ok(result)
    }
}
```

**Step 2: Add module to main.rs**

Add `mod rpc;` at the top of main.rs.

**Step 3: Write test for RPC client**

Create `forge-sidecar/src/rpc.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_deserialize() {
        let json = r#"{
            "version": 4,
            "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
            "curtime": 1700000000,
            "bits": "1f07ffff",
            "height": 100,
            "transactions": [],
            "coinbasetxn": {"data": "01000000010000"},
            "defaultroots": {"merkleroot": "abcd1234"}
        }"#;

        let template: BlockTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(template.version, 4);
        assert_eq!(template.height, 100);
    }
}
```

**Step 4: Verify build and test**

Run: `cargo test -p forge-sidecar`
Expected: Tests pass

**Step 5: Commit**

```bash
git add forge-sidecar/src/rpc.rs forge-sidecar/src/main.rs
git commit -m "feat(sidecar): add Zebra RPC client"
```

---

### Task 3: Implement template polling and change detection

**Files:**
- Create: `forge-sidecar/src/poller.rs`
- Modify: `forge-sidecar/src/main.rs`

**Step 1: Create poller.rs**

```rust
//! Template polling with change detection

use crate::rpc::{BlockTemplate, ZebraRpc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Template change event
#[derive(Debug, Clone)]
pub struct TemplateUpdate {
    pub template: BlockTemplate,
    pub prev_hash_changed: bool,
}

/// Template poller that detects new blocks
pub struct TemplatePoller {
    rpc: Arc<ZebraRpc>,
    poll_interval: Duration,
    last_prev_hash: Option<String>,
    last_height: Option<u64>,
}

impl TemplatePoller {
    pub fn new(rpc: Arc<ZebraRpc>, poll_interval: Duration) -> Self {
        Self {
            rpc,
            poll_interval,
            last_prev_hash: None,
            last_height: None,
        }
    }

    /// Run the polling loop, sending updates to the channel
    pub async fn run(mut self, tx: mpsc::Sender<TemplateUpdate>) {
        loop {
            match self.rpc.get_block_template().await {
                Ok(template) => {
                    let prev_hash_changed = self.last_prev_hash.as_ref() != Some(&template.previous_block_hash);
                    let height_changed = self.last_height != Some(template.height);

                    if prev_hash_changed || height_changed {
                        info!(
                            height = template.height,
                            tx_count = template.transactions.len(),
                            prev_hash_changed,
                            "New block template"
                        );

                        self.last_prev_hash = Some(template.previous_block_hash.clone());
                        self.last_height = Some(template.height);

                        let update = TemplateUpdate {
                            template,
                            prev_hash_changed,
                        };

                        if tx.send(update).await.is_err() {
                            warn!("Template receiver dropped, stopping poller");
                            break;
                        }
                    } else {
                        debug!(height = template.height, "Template unchanged");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to get block template");
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}
```

**Step 2: Add module to main.rs**

Add `mod poller;` to main.rs.

**Step 3: Write test**

Add to poller.rs:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_update_creation() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "abc".to_string(),
            cur_time: 0,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![],
            coinbase_txn: None,
            default_roots: None,
        };

        let update = TemplateUpdate {
            template: template.clone(),
            prev_hash_changed: true,
        };

        assert!(update.prev_hash_changed);
        assert_eq!(update.template.height, 100);
    }
}
```

**Step 4: Verify build and test**

Run: `cargo test -p forge-sidecar`
Expected: Tests pass

**Step 5: Commit**

```bash
git add forge-sidecar/src/poller.rs forge-sidecar/src/main.rs
git commit -m "feat(sidecar): add template polling with change detection"
```

---

### Task 4: Implement CompactBlock builder from template

**Files:**
- Create: `forge-sidecar/src/compact.rs`
- Modify: `forge-sidecar/src/main.rs`

**Step 1: Create compact.rs**

```rust
//! Build CompactBlock from Zebra block templates

use crate::rpc::BlockTemplate;
use bedrock_forge::{AuthDigest, CompactBlock, PrefilledTx, ShortId, TxId, WtxId};
use sha2::{Digest, Sha256};
use tracing::warn;

/// Equihash solution size for Zcash (n=200, k=9)
const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Build a CompactBlock from a BlockTemplate
pub fn build_compact_block(template: &BlockTemplate, nonce: u64) -> Result<CompactBlock, CompactBlockError> {
    // Build the block header
    let header_bytes = build_header(template)?;

    // Compute header hash for short IDs
    let header_hash = compute_header_hash(&header_bytes);

    // Prefill coinbase
    let coinbase_data = template.coinbase_txn
        .as_ref()
        .map(|c| hex::decode(&c.data))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("coinbase".into()))?
        .unwrap_or_default();

    let prefilled = vec![PrefilledTx {
        index: 0,
        tx_data: coinbase_data,
    }];

    // Build short IDs for transactions
    let short_ids: Vec<ShortId> = template.transactions.iter()
        .filter_map(|tx| {
            match hex::decode(&tx.hash) {
                Ok(hash_bytes) if hash_bytes.len() == 32 => {
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&hash_bytes);
                    // Zebra returns little-endian hash, reverse for txid
                    txid_bytes.reverse();
                    let txid = TxId::from_bytes(txid_bytes);
                    // Zcash v4 transactions don't have auth digest
                    let wtxid = WtxId::new(txid, AuthDigest::from_bytes([0u8; 32]));
                    Some(ShortId::compute(&wtxid, &header_hash, nonce))
                }
                _ => {
                    warn!(tx_hash = %tx.hash, "Failed to decode transaction hash, skipping");
                    None
                }
            }
        })
        .collect();

    Ok(CompactBlock::new(
        header_bytes,
        nonce,
        short_ids,
        prefilled,
    ))
}

/// Build the full block header from template
fn build_header(template: &BlockTemplate) -> Result<Vec<u8>, CompactBlockError> {
    let mut header = Vec::with_capacity(140 + 3 + EQUIHASH_SOLUTION_SIZE);

    // Version (4 bytes, little-endian)
    header.extend_from_slice(&template.version.to_le_bytes());

    // Previous block hash (32 bytes)
    let prev_hash = hex::decode(&template.previous_block_hash)
        .map_err(|_| CompactBlockError::InvalidHex("previous_block_hash".into()))?;
    if prev_hash.len() != 32 {
        return Err(CompactBlockError::InvalidLength("previous_block_hash".into()));
    }
    header.extend_from_slice(&prev_hash);

    // Merkle root (32 bytes)
    let merkle_root = template.default_roots
        .as_ref()
        .map(|r| hex::decode(&r.merkle_root))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("merkle_root".into()))?
        .unwrap_or_else(|| vec![0u8; 32]);
    if merkle_root.len() != 32 {
        return Err(CompactBlockError::InvalidLength("merkle_root".into()));
    }
    header.extend_from_slice(&merkle_root);

    // Reserved field / final sapling root (32 bytes) - use chain history root or zeros
    let reserved = template.default_roots
        .as_ref()
        .and_then(|r| r.chain_history_root.as_ref())
        .map(|h| hex::decode(h))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("chain_history_root".into()))?
        .unwrap_or_else(|| vec![0u8; 32]);
    if reserved.len() != 32 {
        return Err(CompactBlockError::InvalidLength("reserved".into()));
    }
    header.extend_from_slice(&reserved);

    // Time (4 bytes, little-endian)
    header.extend_from_slice(&(template.cur_time as u32).to_le_bytes());

    // Bits (4 bytes)
    let bits = hex::decode(&template.bits)
        .map_err(|_| CompactBlockError::InvalidHex("bits".into()))?;
    if bits.len() != 4 {
        return Err(CompactBlockError::InvalidLength("bits".into()));
    }
    header.extend_from_slice(&bits);

    // Nonce (32 bytes) - placeholder for mining
    header.extend_from_slice(&[0u8; 32]);

    // Equihash solution - compactSize + placeholder
    header.push(0xfd); // compactSize prefix for 1344
    header.extend_from_slice(&(EQUIHASH_SOLUTION_SIZE as u16).to_le_bytes());
    header.extend(std::iter::repeat_n(0u8, EQUIHASH_SOLUTION_SIZE));

    Ok(header)
}

/// Compute double-SHA256 header hash
fn compute_header_hash(header: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&second);
    hash
}

#[derive(Debug)]
pub enum CompactBlockError {
    InvalidHex(String),
    InvalidLength(String),
}

impl std::fmt::Display for CompactBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompactBlockError::InvalidHex(field) => write!(f, "invalid hex in field: {}", field),
            CompactBlockError::InvalidLength(field) => write!(f, "invalid length for field: {}", field),
        }
    }
}

impl std::error::Error for CompactBlockError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{CoinbaseTxn, DefaultRoots};

    #[test]
    fn build_compact_from_template() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "00".repeat(32),
            cur_time: 1700000000,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![],
            coinbase_txn: Some(CoinbaseTxn {
                data: "01000000010000".to_string(),
            }),
            default_roots: Some(DefaultRoots {
                merkle_root: "ab".repeat(32),
                block_commitments_hash: None,
                chain_history_root: None,
                auth_data_root: None,
            }),
        };

        let compact = build_compact_block(&template, 0).unwrap();

        // Header should be 140 + 3 + 1344 = 1487 bytes
        assert_eq!(compact.header.len(), 1487);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.short_ids.len(), 0);
    }

    #[test]
    fn build_compact_with_transactions() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "00".repeat(32),
            cur_time: 1700000000,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![
                crate::rpc::TemplateTransaction {
                    data: "deadbeef".to_string(),
                    hash: "aa".repeat(32),
                    fee: 1000,
                },
            ],
            coinbase_txn: Some(CoinbaseTxn {
                data: "01000000010000".to_string(),
            }),
            default_roots: Some(DefaultRoots {
                merkle_root: "ab".repeat(32),
                block_commitments_hash: None,
                chain_history_root: None,
                auth_data_root: None,
            }),
        };

        let compact = build_compact_block(&template, 12345).unwrap();

        assert_eq!(compact.prefilled_txs.len(), 1); // coinbase
        assert_eq!(compact.short_ids.len(), 1); // 1 transaction
    }
}
```

**Step 2: Add module to main.rs**

Add `mod compact;` to main.rs.

**Step 3: Verify build and test**

Run: `cargo test -p forge-sidecar`
Expected: Tests pass

**Step 4: Commit**

```bash
git add forge-sidecar/src/compact.rs forge-sidecar/src/main.rs
git commit -m "feat(sidecar): add CompactBlock builder from template"
```

---

### Task 5: Implement Forge relay integration

**Files:**
- Create: `forge-sidecar/src/relay.rs`
- Modify: `forge-sidecar/src/main.rs`

**Step 1: Create relay.rs**

```rust
//! Forge relay client wrapper for sidecar

use bedrock_forge::{BlockSender, ClientConfig, CompactBlock, RelayClient};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Forge relay wrapper
pub struct ForgeRelay {
    client: Arc<RwLock<RelayClient>>,
    sender: BlockSender,
}

impl ForgeRelay {
    /// Create a new Forge relay
    pub fn new(
        relay_peers: Vec<SocketAddr>,
        auth_key: [u8; 32],
        bind_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = ClientConfig::new(relay_peers, auth_key)
            .with_bind_addr(bind_addr);

        let client = RelayClient::new(config)?;
        let sender = client.sender();

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            sender,
        })
    }

    /// Initialize the relay (bind socket)
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = self.client.write().await;
        client.bind().await?;
        info!(addr = ?client.local_addr(), "Forge relay bound");
        Ok(())
    }

    /// Start the relay run loop
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = self.client.write().await;
        if client.take_receiver().is_none() {
            warn!("Forge relay receiver already taken");
        }
        Ok(())
    }

    /// Announce a compact block to the relay network
    pub async fn announce(&self, compact: CompactBlock) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sender.send(compact).await?;
        debug!("Announced compact block to Forge relay");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_creation() {
        let peers = vec!["127.0.0.1:8333".parse().unwrap()];
        let auth_key = [0u8; 32];
        let bind_addr = "0.0.0.0:0".parse().unwrap();

        let relay = ForgeRelay::new(peers, auth_key, bind_addr);
        assert!(relay.is_ok());
    }
}
```

**Step 2: Add module to main.rs**

Add `mod relay;` to main.rs.

**Step 3: Verify build and test**

Run: `cargo test -p forge-sidecar`
Expected: Tests pass

**Step 4: Commit**

```bash
git add forge-sidecar/src/relay.rs forge-sidecar/src/main.rs
git commit -m "feat(sidecar): add Forge relay client wrapper"
```

---

### Task 6: Wire up main.rs with full sidecar logic

**Files:**
- Modify: `forge-sidecar/src/main.rs`

**Step 1: Implement full main.rs**

```rust
//! Forge sidecar for Stratum V1 mining pools

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

mod compact;
mod poller;
mod relay;
mod rpc;

use compact::build_compact_block;
use poller::{TemplatePoller, TemplateUpdate};
use relay::ForgeRelay;
use rpc::ZebraRpc;

#[derive(Parser, Debug)]
#[command(name = "forge-sidecar")]
#[command(about = "Forge relay sidecar for Stratum V1 mining pools")]
struct Args {
    /// Zebra RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8232")]
    zebra_url: String,

    /// Forge relay peer addresses
    #[arg(long, required = true)]
    relay_peer: Vec<String>,

    /// Authentication key (hex, 32 bytes)
    #[arg(long)]
    auth_key: Option<String>,

    /// Local bind address for Forge
    #[arg(long, default_value = "0.0.0.0:0")]
    bind_addr: String,

    /// Poll interval in milliseconds
    #[arg(long, default_value = "100")]
    poll_interval_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("forge_sidecar=info".parse()?)
        )
        .init();

    let args = Args::parse();

    info!(zebra_url = %args.zebra_url, "Starting Forge sidecar");

    // Parse relay peers
    let relay_peers: Vec<SocketAddr> = args.relay_peer
        .iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()?;

    // Parse auth key
    let auth_key: [u8; 32] = if let Some(key_hex) = &args.auth_key {
        let bytes = hex::decode(key_hex)?;
        if bytes.len() != 32 {
            return Err("auth_key must be 32 bytes (64 hex characters)".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        [0u8; 32]
    };

    // Parse bind address
    let bind_addr: SocketAddr = args.bind_addr.parse()?;

    // Initialize Zebra RPC client
    let rpc = Arc::new(ZebraRpc::new(&args.zebra_url).await?);
    info!("Connected to Zebra RPC");

    // Initialize Forge relay
    let relay = ForgeRelay::new(relay_peers.clone(), auth_key, bind_addr)?;
    relay.init().await?;
    relay.start().await?;
    let relay = Arc::new(relay);

    // Create template channel
    let (tx, mut rx) = mpsc::channel::<TemplateUpdate>(16);

    // Start template poller
    let poll_interval = Duration::from_millis(args.poll_interval_ms);
    let poller = TemplatePoller::new(Arc::clone(&rpc), poll_interval);
    tokio::spawn(async move {
        poller.run(tx).await;
    });

    info!(
        relay_peers = ?relay_peers,
        poll_interval_ms = args.poll_interval_ms,
        "Sidecar running"
    );

    // Main loop: receive template updates and announce
    while let Some(update) = rx.recv().await {
        match build_compact_block(&update.template, 0) {
            Ok(compact) => {
                let tx_count = compact.tx_count();
                if let Err(e) = relay.announce(compact).await {
                    error!(error = %e, "Failed to announce compact block");
                } else {
                    info!(
                        height = update.template.height,
                        tx_count,
                        "Announced compact block"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to build compact block");
            }
        }
    }

    Ok(())
}
```

**Step 2: Verify build**

Run: `cargo build -p forge-sidecar`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add forge-sidecar/src/main.rs
git commit -m "feat(sidecar): wire up main with full sidecar logic"
```

---

### Task 7: Add configuration file support

**Files:**
- Create: `forge-sidecar/src/config.rs`
- Modify: `forge-sidecar/src/main.rs`
- Modify: `forge-sidecar/Cargo.toml`

**Step 1: Add toml dependency to Cargo.toml**

Add to `[dependencies]`:
```toml
toml = "0.8"
```

**Step 2: Create config.rs**

```rust
//! Configuration file support

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

/// Configuration loaded from file
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Zebra RPC URL
    #[serde(default = "default_zebra_url")]
    pub zebra_url: String,

    /// Forge relay peer addresses
    pub relay_peers: Vec<String>,

    /// Authentication key (hex)
    pub auth_key: Option<String>,

    /// Local bind address
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Poll interval in milliseconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
}

fn default_zebra_url() -> String {
    "http://127.0.0.1:8232".to_string()
}

fn default_bind_addr() -> String {
    "0.0.0.0:0".to_string()
}

fn default_poll_interval() -> u64 {
    100
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Parse relay peers to SocketAddr
    pub fn parsed_relay_peers(&self) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
        self.relay_peers
            .iter()
            .map(|s| s.parse().map_err(|e| format!("invalid relay peer '{}': {}", s, e).into()))
            .collect()
    }

    /// Parse auth key to bytes
    pub fn parsed_auth_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if let Some(key_hex) = &self.auth_key {
            let bytes = hex::decode(key_hex)?;
            if bytes.len() != 32 {
                return Err("auth_key must be 32 bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        } else {
            Ok([0u8; 32])
        }
    }

    /// Parse bind address
    pub fn parsed_bind_addr(&self) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        Ok(self.bind_addr.parse()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let toml = r#"
            zebra_url = "http://localhost:8232"
            relay_peers = ["192.168.1.1:8333", "192.168.1.2:8333"]
            auth_key = "0000000000000000000000000000000000000000000000000000000000000000"
            poll_interval_ms = 50
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.zebra_url, "http://localhost:8232");
        assert_eq!(config.relay_peers.len(), 2);
        assert_eq!(config.poll_interval_ms, 50);
    }

    #[test]
    fn config_defaults() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
        assert_eq!(config.bind_addr, "0.0.0.0:0");
        assert_eq!(config.poll_interval_ms, 100);
    }
}
```

**Step 3: Update main.rs to support config file**

Add `--config` argument and integrate:

```rust
    /// Configuration file path (TOML)
    #[arg(long, short = 'c')]
    config: Option<String>,
```

And in main(), add config file loading before argument processing:
```rust
    // Load config file if specified
    if let Some(config_path) = &args.config {
        let config = config::Config::from_file(std::path::Path::new(config_path))?;
        // Use config values as defaults, CLI args override
        // ... implementation details
    }
```

**Step 4: Add module to main.rs**

Add `mod config;` to main.rs.

**Step 5: Verify build and test**

Run: `cargo test -p forge-sidecar`
Expected: Tests pass

**Step 6: Commit**

```bash
git add forge-sidecar/src/config.rs forge-sidecar/src/main.rs forge-sidecar/Cargo.toml
git commit -m "feat(sidecar): add configuration file support"
```

---

### Task 8: Add example configuration and documentation

**Files:**
- Create: `forge-sidecar/config.example.toml`
- Create: `forge-sidecar/README.md`

**Step 1: Create config.example.toml**

```toml
# Forge Sidecar Configuration Example
# Copy to config.toml and modify as needed

# Zebra JSON-RPC URL
zebra_url = "http://127.0.0.1:8232"

# Forge relay peer addresses (at least one required)
relay_peers = [
    "forge-relay.example.com:8333",
    # "backup-relay.example.com:8333",
]

# Authentication key (32 bytes hex, optional)
# Generate with: openssl rand -hex 32
# auth_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Local bind address for UDP socket
bind_addr = "0.0.0.0:0"

# Template poll interval in milliseconds
# Lower = faster detection, higher CPU usage
poll_interval_ms = 100
```

**Step 2: Create README.md**

```markdown
# Forge Sidecar

A standalone sidecar binary that enables Stratum V1 mining pools to use bedrock-forge for low-latency block relay.

## Overview

The Forge sidecar:
- Polls Zebra for new block templates
- Builds compact blocks when templates change
- Announces compact blocks to the Forge relay network

This allows any V1 pool (NOMP, etc.) to benefit from compact block relay without modification.

## Usage

### Command Line

```bash
forge-sidecar \
    --zebra-url http://127.0.0.1:8232 \
    --relay-peer forge-relay.example.com:8333 \
    --auth-key 0123456789abcdef... \
    --poll-interval-ms 100
```

### Configuration File

```bash
forge-sidecar --config config.toml
```

See `config.example.toml` for all options.

## Architecture

```
STRATUM V1 POOL (unmodified)
        │
        ▼ getblocktemplate/submitblock
    ZEBRA NODE ◄──────────────────────┐
        │                             │
        │ poll templates              │ (future: submitblock)
        ▼                             │
   FORGE SIDECAR ─────────────────────┘
        │
        ▼ UDP/FEC
   FORGE RELAY NETWORK
```

## Requirements

- Zebra node with JSON-RPC enabled
- Network connectivity to Forge relay nodes

## Building

```bash
cargo build --release -p forge-sidecar
```

Binary will be at `target/release/forge-sidecar`.
```

**Step 3: Commit**

```bash
git add forge-sidecar/config.example.toml forge-sidecar/README.md
git commit -m "docs(sidecar): add example config and README"
```

---

### Task 9: Add integration test with mock RPC

**Files:**
- Create: `forge-sidecar/tests/integration_test.rs`

**Step 1: Create integration test**

```rust
//! Integration tests for forge-sidecar

use std::time::Duration;

/// Test that the sidecar binary compiles and shows help
#[test]
fn sidecar_help() {
    let output = std::process::Command::new("cargo")
        .args(["run", "-p", "forge-sidecar", "--", "--help"])
        .output()
        .expect("failed to run sidecar");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Forge relay sidecar"));
    assert!(stdout.contains("--zebra-url"));
    assert!(stdout.contains("--relay-peer"));
}

/// Test configuration parsing
#[test]
fn config_parsing() {
    use std::io::Write;

    let config = r#"
        zebra_url = "http://localhost:8232"
        relay_peers = ["127.0.0.1:8333"]
        poll_interval_ms = 50
    "#;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(config.as_bytes()).unwrap();

    // Just verify it parses - actual runtime would need Zebra
    let _config: toml::Value = toml::from_str(config).unwrap();
}
```

**Step 2: Add tempfile dev-dependency**

Add to Cargo.toml `[dev-dependencies]`:
```toml
tempfile = "3"
```

**Step 3: Verify tests**

Run: `cargo test -p forge-sidecar`
Expected: Tests pass

**Step 4: Commit**

```bash
git add forge-sidecar/tests forge-sidecar/Cargo.toml
git commit -m "test(sidecar): add integration tests"
```

---

### Task 10: Final build verification and cleanup

**Files:**
- All forge-sidecar files

**Step 1: Run full test suite**

Run: `cargo test -p forge-sidecar`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy -p forge-sidecar -- -D warnings`
Expected: No warnings

**Step 3: Build release binary**

Run: `cargo build --release -p forge-sidecar`
Expected: Build succeeds

**Step 4: Verify binary runs**

Run: `./target/release/forge-sidecar --help`
Expected: Shows help text

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat(sidecar): complete forge-sidecar implementation"
```

---

## Summary

The forge-sidecar provides:

1. **Zero modification to V1 pools** - Works alongside existing NOMP/etc. installations
2. **Automatic template detection** - Polls Zebra and detects new blocks
3. **Compact block relay** - Builds and announces CompactBlocks via bedrock-forge
4. **Simple deployment** - Single binary with config file support
5. **Low latency** - 100ms default poll interval, immediate announcement on change

Future enhancements (not in this plan):
- Block reception from relay network
- submitblock forwarding to Zebra
- Metrics endpoint
- Systemd service file
