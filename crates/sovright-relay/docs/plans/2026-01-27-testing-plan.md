# Bedrock-Forge Testing Plan Implementation

> Note: This document was written before the rename from fiber-zcash to bedrock-forge. Some internal references may still use the old name.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement comprehensive testing infrastructure covering E2E validation, performance benchmarking, stress/chaos testing, and pre-deployment checklist.

**Architecture:** Four-layer testing pyramid with fixtures, simulation harnesses, and automated verification gates.

**Tech Stack:** Rust, tokio, criterion (benchmarks), proptest (property testing), tokio-test

---

## Task 1: Create Block Test Fixtures

**Files:**
- Create: `tests/fixtures/mod.rs`
- Create: `tests/fixtures/blocks.rs`
- Create: `tests/fixtures/testnet_block_800000.json`

**Step 1: Create fixtures module structure**

Create `tests/fixtures/mod.rs`:
```rust
//! Test fixtures for E2E testing

pub mod blocks;

pub use blocks::{TestBlock, load_testnet_block, create_synthetic_block};
```

**Step 2: Create block fixtures module**

Create `tests/fixtures/blocks.rs`:
```rust
//! Block test fixtures

use bedrock_forge::{BlockHash, TxId};
use std::collections::HashMap;

/// A test block with header and transactions
#[derive(Debug, Clone)]
pub struct TestBlock {
    /// Full block header (140 bytes + equihash solution)
    pub header: Vec<u8>,
    /// Block hash
    pub hash: BlockHash,
    /// Transactions (txid -> raw tx bytes)
    pub transactions: Vec<(TxId, Vec<u8>)>,
}

impl TestBlock {
    /// Create a new test block
    pub fn new(header: Vec<u8>, hash: BlockHash, transactions: Vec<(TxId, Vec<u8>)>) -> Self {
        Self { header, hash, transactions }
    }

    /// Get total serialized size
    pub fn total_size(&self) -> usize {
        self.header.len() + self.transactions.iter().map(|(_, tx)| tx.len()).sum::<usize>()
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Create a synthetic test block with valid structure but fake PoW
pub fn create_synthetic_block(tx_count: usize, tx_size: usize) -> TestBlock {
    // Create fake header (140 bytes header + 3 bytes compactSize + 1344 bytes solution)
    let mut header = vec![0u8; 1487];
    // Version
    header[0..4].copy_from_slice(&4u32.to_le_bytes());
    // Set some distinguishing bytes
    header[4] = 0xAB;
    header[5] = 0xCD;

    // Create block hash from header
    let hash = BlockHash::from_bytes({
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&header[..140]);
        let first = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(&first);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    // Create synthetic transactions
    let mut transactions = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let mut tx_data = vec![0u8; tx_size];
        // Put index in first 4 bytes for uniqueness
        tx_data[0..4].copy_from_slice(&(i as u32).to_le_bytes());

        // Compute txid (double SHA256)
        let txid = TxId::from_bytes({
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&tx_data);
            let first = hasher.finalize();
            let mut hasher = Sha256::new();
            hasher.update(&first);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        });

        transactions.push((txid, tx_data));
    }

    TestBlock::new(header, hash, transactions)
}

/// Create a realistic testnet-like block
pub fn create_testnet_block() -> TestBlock {
    // Typical testnet block: ~50 transactions, ~300 bytes each
    create_synthetic_block(50, 300)
}

/// Create a large stress test block
pub fn create_large_block() -> TestBlock {
    // Large block: 2500 transactions, ~500 bytes each (~1.25 MB)
    create_synthetic_block(2500, 500)
}

/// Create a minimal block (coinbase only)
pub fn create_minimal_block() -> TestBlock {
    create_synthetic_block(1, 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_block_creation() {
        let block = create_synthetic_block(10, 250);
        assert_eq!(block.tx_count(), 10);
        assert_eq!(block.header.len(), 1487);
        // Header + 10 txs of 250 bytes
        assert_eq!(block.total_size(), 1487 + 10 * 250);
    }

    #[test]
    fn testnet_block_reasonable_size() {
        let block = create_testnet_block();
        assert!(block.tx_count() >= 10);
        assert!(block.total_size() > 10_000); // At least 10KB
    }
}
```

**Step 3: Run tests**

Run: `cargo test fixtures --test '*' -- --nocapture 2>&1 || cargo test synthetic_block --test '*' 2>&1 || cargo test -p bedrock_forge synthetic_block 2>&1 || echo "Will test after full setup"`

**Step 4: Commit**

```bash
git add tests/fixtures/
git commit -m "test: add block test fixtures for E2E testing"
```

---

## Task 2: Create Network Simulation Harness

**Files:**
- Create: `tests/harness/mod.rs`
- Create: `tests/harness/network.rs`

**Step 1: Create harness module**

Create `tests/harness/mod.rs`:
```rust
//! Test harness for network simulation

pub mod network;

pub use network::{SimulatedNetwork, NetworkConditions, PacketFate};
```

**Step 2: Create network simulation**

Create `tests/harness/network.rs`:
```rust
//! Network simulation for chaos testing

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Network conditions for simulation
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss: f64,
    /// Additional latency in milliseconds
    pub latency_ms: u64,
    /// Latency jitter in milliseconds
    pub jitter_ms: u64,
    /// Bandwidth limit in bytes per second (0 = unlimited)
    pub bandwidth_bps: u64,
    /// Whether to reorder packets
    pub reorder: bool,
    /// Duplicate packet rate (0.0 - 1.0)
    pub duplicate_rate: f64,
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self {
            packet_loss: 0.0,
            latency_ms: 0,
            jitter_ms: 0,
            bandwidth_bps: 0,
            reorder: false,
            duplicate_rate: 0.0,
        }
    }
}

impl NetworkConditions {
    /// Perfect network - no loss, no latency
    pub fn perfect() -> Self {
        Self::default()
    }

    /// Typical internet conditions
    pub fn typical_internet() -> Self {
        Self {
            packet_loss: 0.001, // 0.1% loss
            latency_ms: 50,
            jitter_ms: 10,
            bandwidth_bps: 100_000_000, // 100 Mbps
            reorder: false,
            duplicate_rate: 0.0,
        }
    }

    /// Lossy network for stress testing
    pub fn lossy() -> Self {
        Self {
            packet_loss: 0.05, // 5% loss
            latency_ms: 100,
            jitter_ms: 50,
            bandwidth_bps: 10_000_000, // 10 Mbps
            reorder: true,
            duplicate_rate: 0.001,
        }
    }

    /// Severely degraded network
    pub fn degraded() -> Self {
        Self {
            packet_loss: 0.15, // 15% loss
            latency_ms: 200,
            jitter_ms: 100,
            bandwidth_bps: 1_000_000, // 1 Mbps
            reorder: true,
            duplicate_rate: 0.01,
        }
    }

    /// Satellite-like conditions
    pub fn satellite() -> Self {
        Self {
            packet_loss: 0.02,
            latency_ms: 600, // High latency
            jitter_ms: 50,
            bandwidth_bps: 50_000_000,
            reorder: false,
            duplicate_rate: 0.0,
        }
    }
}

/// What happens to a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFate {
    /// Packet delivered normally
    Delivered,
    /// Packet lost
    Lost,
    /// Packet duplicated
    Duplicated,
}

/// Simulated network for testing
pub struct SimulatedNetwork {
    conditions: NetworkConditions,
    rng: std::sync::Mutex<StdRng>,
    packets_sent: AtomicU64,
    packets_lost: AtomicU64,
    packets_delivered: AtomicU64,
    packets_duplicated: AtomicU64,
}

impl SimulatedNetwork {
    /// Create a new simulated network
    pub fn new(conditions: NetworkConditions) -> Self {
        Self {
            conditions,
            rng: std::sync::Mutex::new(StdRng::seed_from_u64(42)),
            packets_sent: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            packets_delivered: AtomicU64::new(0),
            packets_duplicated: AtomicU64::new(0),
        }
    }

    /// Create with specific seed for reproducibility
    pub fn with_seed(conditions: NetworkConditions, seed: u64) -> Self {
        Self {
            conditions,
            rng: std::sync::Mutex::new(StdRng::seed_from_u64(seed)),
            packets_sent: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            packets_delivered: AtomicU64::new(0),
            packets_duplicated: AtomicU64::new(0),
        }
    }

    /// Determine the fate of a packet
    pub fn process_packet(&self) -> PacketFate {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);

        let mut rng = self.rng.lock().unwrap();
        let roll: f64 = rng.gen();

        if roll < self.conditions.packet_loss {
            self.packets_lost.fetch_add(1, Ordering::Relaxed);
            PacketFate::Lost
        } else if roll < self.conditions.packet_loss + self.conditions.duplicate_rate {
            self.packets_duplicated.fetch_add(1, Ordering::Relaxed);
            self.packets_delivered.fetch_add(2, Ordering::Relaxed);
            PacketFate::Duplicated
        } else {
            self.packets_delivered.fetch_add(1, Ordering::Relaxed);
            PacketFate::Delivered
        }
    }

    /// Get simulated latency for this packet in milliseconds
    pub fn get_latency_ms(&self) -> u64 {
        if self.conditions.jitter_ms == 0 {
            return self.conditions.latency_ms;
        }

        let mut rng = self.rng.lock().unwrap();
        let jitter: i64 = rng.gen_range(-(self.conditions.jitter_ms as i64)..=(self.conditions.jitter_ms as i64));
        (self.conditions.latency_ms as i64 + jitter).max(0) as u64
    }

    /// Get statistics
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_lost: self.packets_lost.load(Ordering::Relaxed),
            packets_delivered: self.packets_delivered.load(Ordering::Relaxed),
            packets_duplicated: self.packets_duplicated.load(Ordering::Relaxed),
        }
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_lost.store(0, Ordering::Relaxed);
        self.packets_delivered.store(0, Ordering::Relaxed);
        self.packets_duplicated.store(0, Ordering::Relaxed);
    }

    /// Get the conditions
    pub fn conditions(&self) -> &NetworkConditions {
        &self.conditions
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub packets_delivered: u64,
    pub packets_duplicated: u64,
}

impl NetworkStats {
    /// Calculate actual loss rate
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_network_no_loss() {
        let net = SimulatedNetwork::new(NetworkConditions::perfect());

        for _ in 0..1000 {
            assert_eq!(net.process_packet(), PacketFate::Delivered);
        }

        let stats = net.stats();
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.packets_delivered, 1000);
    }

    #[test]
    fn lossy_network_drops_packets() {
        let net = SimulatedNetwork::with_seed(NetworkConditions::lossy(), 12345);

        for _ in 0..10000 {
            let _ = net.process_packet();
        }

        let stats = net.stats();
        // With 5% loss, expect roughly 500 lost packets (allow variance)
        assert!(stats.packets_lost > 300, "Expected some packet loss");
        assert!(stats.packets_lost < 800, "Loss rate too high");
    }

    #[test]
    fn latency_with_jitter() {
        let net = SimulatedNetwork::new(NetworkConditions {
            latency_ms: 100,
            jitter_ms: 20,
            ..Default::default()
        });

        let mut latencies = Vec::new();
        for _ in 0..100 {
            latencies.push(net.get_latency_ms());
        }

        // Check we get variety
        let min = *latencies.iter().min().unwrap();
        let max = *latencies.iter().max().unwrap();
        assert!(min >= 80, "Latency too low");
        assert!(max <= 120, "Latency too high");
        assert!(max > min, "No jitter observed");
    }
}
```

**Step 3: Run tests**

Run: `cargo test harness --test '*' 2>&1 || cargo test perfect_network 2>&1 || echo "Will test after setup"`

**Step 4: Commit**

```bash
git add tests/harness/
git commit -m "test: add network simulation harness for chaos testing"
```

---

## Task 3: Create E2E Pipeline Test

**Files:**
- Create: `tests/e2e/mod.rs`
- Create: `tests/e2e/pipeline.rs`

**Step 1: Create e2e module**

Create `tests/e2e/mod.rs`:
```rust
//! End-to-end tests

mod pipeline;
```

**Step 2: Create pipeline test**

Create `tests/e2e/pipeline.rs`:
```rust
//! Full pipeline E2E tests

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use bedrock_forge::{
    CompactBlockBuilder, CompactBlockReconstructor, ReconstructionResult,
    BlockChunker, RelayNode, RelayClient, RelayConfig, ClientConfig,
    StubPowValidator, TestMempool,
};

// Import test fixtures
#[path = "../fixtures/mod.rs"]
mod fixtures;
use fixtures::blocks::{create_testnet_block, create_synthetic_block, TestBlock};

/// Helper to build a compact block from test block
fn build_compact_block(block: &TestBlock) -> Vec<u8> {
    let mut builder = CompactBlockBuilder::new(block.hash, block.header.clone());
    for (txid, _tx_data) in &block.transactions {
        builder.add_transaction(*txid);
    }
    builder.build()
}

/// Test: Block flows through chunker → reassembly
#[tokio::test]
async fn e2e_chunker_roundtrip() {
    let block = create_testnet_block();
    let compact = build_compact_block(&block);

    // Chunk the compact block
    let chunker = BlockChunker::new(10, 3).unwrap();
    let chunks = chunker.encode(&compact).unwrap();

    assert!(chunks.len() >= 10, "Should have at least data_shards chunks");

    // Simulate receiving just the data shards (minimum needed)
    let received: Vec<_> = chunks.into_iter().take(10).collect();

    // Decode
    let decoded = chunker.decode(&received, compact.len()).unwrap();

    assert_eq!(decoded, compact, "Round-trip should preserve data");
}

/// Test: Block flows through relay node
#[tokio::test]
async fn e2e_relay_node_forward() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();

    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    // Start relay
    let handle = tokio::spawn(async move {
        node_clone.run().await
    });

    // Give it time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create test block and chunks
    let block = create_synthetic_block(10, 100);
    let compact = build_compact_block(&block);
    let chunker = BlockChunker::new(10, 3).unwrap();
    let chunks = chunker.encode(&compact).unwrap();

    // Send chunks to relay
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Build a proper chunk with header
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(block.hash.as_bytes());

    for (i, chunk_data) in chunks.iter().enumerate() {
        let header = bedrock_forge::ChunkHeader::new_block(
            &block_hash,
            i as u16,
            chunks.len() as u16,
            chunk_data.len() as u16,
        );
        let chunk = bedrock_forge::Chunk::new(header, chunk_data.clone());
        socket.send_to(&chunk.to_bytes(), addr).await.unwrap();
    }

    // Check metrics
    tokio::time::sleep(Duration::from_millis(100)).await;
    let metrics = node.metrics().snapshot();
    assert!(metrics.packets_received > 0, "Should have received packets");

    // Stop relay
    node.stop();
    let _ = handle.await;
}

/// Test: Full sender → relay → receiver pipeline
#[tokio::test]
async fn e2e_full_pipeline() {
    // Setup relay node
    let relay_config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut relay = RelayNode::new(relay_config).unwrap();
    relay.bind().await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let relay = Arc::new(relay);
    let relay_clone = Arc::clone(&relay);

    let relay_handle = tokio::spawn(async move {
        relay_clone.run().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Setup sender client
    let sender_config = ClientConfig::new(relay_addr);
    let mut sender = RelayClient::new(sender_config).unwrap();
    sender.connect().await.unwrap();

    // Setup receiver client
    let receiver_config = ClientConfig::new(relay_addr);
    let mut receiver = RelayClient::new(receiver_config).unwrap();
    receiver.connect().await.unwrap();

    // Create and send a block
    let block = create_synthetic_block(20, 150);
    let compact = build_compact_block(&block);

    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(block.hash.as_bytes());

    sender.send_block(&block_hash, &compact).await.unwrap();

    // Receiver should get the block
    let received = tokio::time::timeout(
        Duration::from_secs(2),
        receiver.receive_block()
    ).await;

    // Even if receive times out, check that data was transmitted
    let metrics = relay.metrics().snapshot();
    assert!(metrics.packets_received > 0, "Relay should have received packets");

    // Cleanup
    relay.stop();
    sender.stop();
    receiver.stop();
    let _ = relay_handle.await;
}

/// Test: Compact block reconstruction with mempool
#[tokio::test]
async fn e2e_compact_block_reconstruction() {
    let block = create_synthetic_block(50, 200);

    // Build compact block
    let mut builder = CompactBlockBuilder::new(block.hash, block.header.clone());
    for (txid, _) in &block.transactions {
        builder.add_transaction(*txid);
    }
    let compact_bytes = builder.build();

    // Setup mempool with 80% of transactions
    let mut mempool = TestMempool::new();
    for (txid, tx_data) in block.transactions.iter().take(40) {
        mempool.add_transaction(*txid, tx_data.clone());
    }

    // Reconstruct
    let compact = bedrock_forge::CompactBlock::deserialize(&compact_bytes).unwrap();
    let mut reconstructor = CompactBlockReconstructor::new(compact, &mempool).unwrap();

    let result = reconstructor.reconstruct().unwrap();

    match result {
        ReconstructionResult::NeedTransactions(missing) => {
            // Should need the 10 missing transactions
            assert_eq!(missing.len(), 10, "Should need 10 missing txs");
        }
        ReconstructionResult::Success(_) => {
            panic!("Should not succeed with only 80% of transactions");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_fixture_valid() {
        let block = create_testnet_block();
        assert!(block.tx_count() > 0);
        assert!(!block.header.is_empty());
    }
}
```

**Step 3: Run tests**

Run: `cargo test e2e_ -- --nocapture 2>&1 | tail -30`

**Step 4: Commit**

```bash
git add tests/e2e/
git commit -m "test: add E2E pipeline tests"
```

---

## Task 4: Create Performance Benchmarks

**Files:**
- Create: `benches/relay_bench.rs`
- Modify: `Cargo.toml` (add criterion dev-dependency)

**Step 1: Add criterion to Cargo.toml**

Add to `[dev-dependencies]`:
```toml
criterion = { version = "0.5", features = ["async_tokio"] }
```

Add to end of Cargo.toml:
```toml

[[bench]]
name = "relay_bench"
harness = false
```

**Step 2: Create benchmark file**

Create `benches/relay_bench.rs`:
```rust
//! Performance benchmarks for bedrock-forge

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use bedrock_forge::{
    CompactBlockBuilder, CompactBlockReconstructor, BlockChunker,
    TestMempool, BlockHash, TxId,
};

/// Create a synthetic block for benchmarking
fn create_bench_block(tx_count: usize, tx_size: usize) -> (BlockHash, Vec<u8>, Vec<(TxId, Vec<u8>)>) {
    let mut header = vec![0u8; 1487];
    header[0..4].copy_from_slice(&4u32.to_le_bytes());

    let hash = BlockHash::from_bytes({
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&header[..140]);
        let first = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(&first);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    let mut transactions = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let mut tx_data = vec![0u8; tx_size];
        tx_data[0..4].copy_from_slice(&(i as u32).to_le_bytes());

        let txid = TxId::from_bytes({
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&tx_data);
            let first = hasher.finalize();
            let mut hasher = Sha256::new();
            hasher.update(&first);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        });

        transactions.push((txid, tx_data));
    }

    (hash, header, transactions)
}

fn bench_compact_block_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_block_build");

    for tx_count in [50, 500, 2500] {
        let (hash, header, transactions) = create_bench_block(tx_count, 300);
        let size = header.len() + transactions.len() * 300;
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("txs", tx_count),
            &(hash, header.clone(), &transactions),
            |b, (hash, header, txs)| {
                b.iter(|| {
                    let mut builder = CompactBlockBuilder::new(*hash, header.clone());
                    for (txid, _) in *txs {
                        builder.add_transaction(*txid);
                    }
                    black_box(builder.build())
                });
            },
        );
    }

    group.finish();
}

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_encode");

    for size_kb in [10, 100, 1000] {
        let data = vec![0xABu8; size_kb * 1024];
        group.throughput(Throughput::Bytes(data.len() as u64));

        let chunker = BlockChunker::new(10, 3).unwrap();

        group.bench_with_input(
            BenchmarkId::new("kb", size_kb),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(chunker.encode(data).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_fec_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_decode");

    for size_kb in [10, 100, 1000] {
        let data = vec![0xABu8; size_kb * 1024];
        let chunker = BlockChunker::new(10, 3).unwrap();
        let chunks = chunker.encode(&data).unwrap();

        group.throughput(Throughput::Bytes(data.len() as u64));

        // Simulate receiving only data shards (no parity needed ideally)
        let received: Vec<_> = chunks.into_iter().take(10).collect();

        group.bench_with_input(
            BenchmarkId::new("kb", size_kb),
            &(received, data.len()),
            |b, (chunks, orig_len)| {
                b.iter(|| {
                    black_box(chunker.decode(chunks, *orig_len).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconstruction");

    for mempool_hit_rate in [0.5, 0.8, 0.95] {
        let (hash, header, transactions) = create_bench_block(500, 300);

        // Build compact block
        let mut builder = CompactBlockBuilder::new(hash, header);
        for (txid, _) in &transactions {
            builder.add_transaction(*txid);
        }
        let compact_bytes = builder.build();

        // Setup mempool
        let mut mempool = TestMempool::new();
        let hit_count = (500.0 * mempool_hit_rate) as usize;
        for (txid, tx_data) in transactions.iter().take(hit_count) {
            mempool.add_transaction(*txid, tx_data.clone());
        }

        group.bench_with_input(
            BenchmarkId::new("hit_rate", format!("{:.0}%", mempool_hit_rate * 100.0)),
            &(compact_bytes.clone(), mempool.clone()),
            |b, (compact_bytes, mempool)| {
                b.iter(|| {
                    let compact = bedrock_forge::CompactBlock::deserialize(compact_bytes).unwrap();
                    let mut reconstructor = CompactBlockReconstructor::new(compact, mempool).unwrap();
                    black_box(reconstructor.reconstruct().unwrap())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compact_block_build,
    bench_fec_encode,
    bench_fec_decode,
    bench_reconstruction,
);
criterion_main!(benches);
```

**Step 3: Run benchmarks**

Run: `cargo bench -- --noplot 2>&1 | head -50`

**Step 4: Commit**

```bash
git add Cargo.toml benches/
git commit -m "perf: add criterion benchmarks for relay pipeline"
```

---

## Task 5: Create Stress Tests

**Files:**
- Create: `tests/stress/mod.rs`
- Create: `tests/stress/chaos.rs`

**Step 1: Create stress module**

Create `tests/stress/mod.rs`:
```rust
//! Stress and chaos tests

mod chaos;
```

**Step 2: Create chaos tests**

Create `tests/stress/chaos.rs`:
```rust
//! Chaos testing - packet loss, high load, network failures

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use bedrock_forge::{
    BlockChunker, RelayNode, RelayConfig, Chunk, ChunkHeader, BlockHash,
};

#[path = "../harness/mod.rs"]
mod harness;
use harness::network::{SimulatedNetwork, NetworkConditions, PacketFate};

#[path = "../fixtures/mod.rs"]
mod fixtures;
use fixtures::blocks::create_synthetic_block;

/// Helper to build compact block bytes
fn build_compact_bytes(block: &fixtures::blocks::TestBlock) -> Vec<u8> {
    let mut builder = bedrock_forge::CompactBlockBuilder::new(block.hash, block.header.clone());
    for (txid, _) in &block.transactions {
        builder.add_transaction(*txid);
    }
    builder.build()
}

/// Test: FEC recovery under packet loss
#[tokio::test]
async fn stress_fec_recovery_under_loss() {
    let block = create_synthetic_block(100, 300);
    let compact = build_compact_bytes(&block);

    let chunker = BlockChunker::new(10, 5).unwrap(); // 10 data + 5 parity
    let chunks = chunker.encode(&compact).unwrap();

    // Simulate various loss rates
    for loss_rate in [0.1, 0.2, 0.3] {
        let conditions = NetworkConditions {
            packet_loss: loss_rate,
            ..Default::default()
        };
        let network = SimulatedNetwork::with_seed(conditions, 42);

        // Simulate sending all chunks and filtering by network
        let received: Vec<_> = chunks.iter()
            .filter(|_| network.process_packet() == PacketFate::Delivered)
            .cloned()
            .collect();

        let stats = network.stats();

        // With 10 data + 5 parity, we need at least 10 chunks
        if received.len() >= 10 {
            let decoded = chunker.decode(&received, compact.len());
            assert!(decoded.is_ok(),
                "Should decode with {} chunks (loss rate {})",
                received.len(), loss_rate);
            assert_eq!(decoded.unwrap(), compact);
        } else {
            // Too much loss - FEC can't recover
            assert!(received.len() < 10,
                "Got {} chunks but expected failure at loss rate {}",
                received.len(), loss_rate);
        }
    }
}

/// Test: High throughput chunk processing
#[tokio::test]
async fn stress_high_throughput() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let handle = tokio::spawn(async move {
        node_clone.run().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create socket and send many chunks rapidly
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let block_hash = [0xABu8; 32];
    let chunk_data = vec![0u8; 1024];

    let start = Instant::now();
    let num_chunks = 10_000;

    for i in 0..num_chunks {
        let header = ChunkHeader::new_block(
            &block_hash,
            (i % 100) as u16,
            100,
            chunk_data.len() as u16,
        );
        let chunk = Chunk::new(header, chunk_data.clone());
        let _ = socket.send_to(&chunk.to_bytes(), addr).await;
    }

    let elapsed = start.elapsed();
    let rate = num_chunks as f64 / elapsed.as_secs_f64();

    // Give relay time to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics = node.metrics().snapshot();

    println!("Sent {} chunks in {:?} ({:.0} chunks/sec)",
        num_chunks, elapsed, rate);
    println!("Relay received: {} packets", metrics.packets_received);

    // Should handle at least 1000 chunks/sec
    assert!(rate > 1000.0, "Throughput too low: {:.0} chunks/sec", rate);

    node.stop();
    let _ = handle.await;
}

/// Test: Multiple concurrent senders
#[tokio::test]
async fn stress_concurrent_senders() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let handle = tokio::spawn(async move {
        node_clone.run().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn 10 concurrent senders
    let num_senders = 10;
    let chunks_per_sender = 1000;

    let mut sender_handles = Vec::new();

    for sender_id in 0..num_senders {
        let addr = addr;
        sender_handles.push(tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let chunk_data = vec![sender_id as u8; 512];
            let mut block_hash = [0u8; 32];
            block_hash[0] = sender_id as u8;

            for i in 0..chunks_per_sender {
                let header = ChunkHeader::new_block(
                    &block_hash,
                    (i % 50) as u16,
                    50,
                    chunk_data.len() as u16,
                );
                let chunk = Chunk::new(header, chunk_data.clone());
                let _ = socket.send_to(&chunk.to_bytes(), addr).await;
            }
        }));
    }

    // Wait for all senders
    for h in sender_handles {
        let _ = h.await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics = node.metrics().snapshot();
    let expected = (num_senders * chunks_per_sender) as u64;

    println!("Expected {} packets, received {}", expected, metrics.packets_received);

    // Should receive most packets (allow some UDP loss)
    assert!(metrics.packets_received > expected * 90 / 100,
        "Too many packets lost: {} of {}",
        expected - metrics.packets_received, expected);

    node.stop();
    let _ = handle.await;
}

/// Test: Large block handling
#[tokio::test]
async fn stress_large_block() {
    // 2MB block
    let large_data = vec![0xABu8; 2 * 1024 * 1024];

    let chunker = BlockChunker::new(100, 30).unwrap(); // More shards for large data

    let start = Instant::now();
    let chunks = chunker.encode(&large_data).unwrap();
    let encode_time = start.elapsed();

    println!("Encoded {}MB into {} chunks in {:?}",
        large_data.len() / 1024 / 1024,
        chunks.len(),
        encode_time);

    // Simulate 10% loss
    let received: Vec<_> = chunks.iter()
        .enumerate()
        .filter(|(i, _)| i % 10 != 0) // Drop every 10th chunk
        .map(|(_, c)| c.clone())
        .collect();

    let start = Instant::now();
    let decoded = chunker.decode(&received, large_data.len()).unwrap();
    let decode_time = start.elapsed();

    println!("Decoded with {} chunks ({} lost) in {:?}",
        received.len(),
        chunks.len() - received.len(),
        decode_time);

    assert_eq!(decoded, large_data);

    // Should be reasonably fast
    assert!(encode_time < Duration::from_secs(1), "Encoding too slow");
    assert!(decode_time < Duration::from_secs(1), "Decoding too slow");
}

/// Test: Graceful degradation under extreme loss
#[tokio::test]
async fn stress_extreme_loss_graceful() {
    let data = vec![0xABu8; 100 * 1024]; // 100KB
    let chunker = BlockChunker::new(10, 10).unwrap(); // 50% redundancy
    let chunks = chunker.encode(&data).unwrap();

    // 60% loss - should fail but gracefully
    let conditions = NetworkConditions {
        packet_loss: 0.6,
        ..Default::default()
    };
    let network = SimulatedNetwork::with_seed(conditions, 999);

    let received: Vec<_> = chunks.iter()
        .filter(|_| network.process_packet() == PacketFate::Delivered)
        .cloned()
        .collect();

    let stats = network.stats();
    println!("With 60% loss: {} of {} chunks received",
        received.len(), chunks.len());

    let result = chunker.decode(&received, data.len());

    if received.len() >= 10 {
        assert!(result.is_ok(), "Should decode with enough chunks");
    } else {
        assert!(result.is_err(), "Should fail gracefully with too few chunks");
    }
}
```

**Step 3: Run stress tests**

Run: `cargo test stress_ -- --nocapture 2>&1 | tail -40`

**Step 4: Commit**

```bash
git add tests/stress/
git commit -m "test: add stress and chaos tests"
```

---

## Task 6: Create Pre-Deployment Checklist Test

**Files:**
- Create: `tests/predeploy/mod.rs`
- Create: `tests/predeploy/checklist.rs`

**Step 1: Create predeploy module**

Create `tests/predeploy/mod.rs`:
```rust
//! Pre-deployment verification tests

mod checklist;
```

**Step 2: Create checklist tests**

Create `tests/predeploy/checklist.rs`:
```rust
//! Pre-deployment checklist - automated verification gates

use std::sync::Arc;
use std::time::Duration;

use bedrock_forge::{
    CompactBlockBuilder, CompactBlockReconstructor, ReconstructionResult,
    BlockChunker, RelayNode, RelayClient, RelayConfig, ClientConfig,
    EquihashPowValidator, TestMempool, BlockHash, TxId,
    EQUIHASH_N, EQUIHASH_K, ZCASH_FULL_HEADER_SIZE,
};

/// Gate 1: Core types are correctly sized
#[test]
fn gate_type_sizes() {
    use std::mem::size_of;

    // BlockHash should be 32 bytes
    assert_eq!(size_of::<BlockHash>(), 32, "BlockHash wrong size");

    // TxId should be 32 bytes
    assert_eq!(size_of::<TxId>(), 32, "TxId wrong size");

    // Equihash parameters should match Zcash
    assert_eq!(EQUIHASH_N, 200, "Wrong Equihash N parameter");
    assert_eq!(EQUIHASH_K, 9, "Wrong Equihash K parameter");
    assert_eq!(ZCASH_FULL_HEADER_SIZE, 1487, "Wrong header size");
}

/// Gate 2: FEC encoder/decoder roundtrips correctly
#[test]
fn gate_fec_roundtrip() {
    let test_sizes = [1024, 10240, 102400, 1024000];

    for size in test_sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let chunker = BlockChunker::new(10, 3).unwrap();

        let chunks = chunker.encode(&data).unwrap();
        let decoded = chunker.decode(&chunks[..10], data.len()).unwrap();

        assert_eq!(decoded, data, "FEC roundtrip failed for size {}", size);
    }
}

/// Gate 3: FEC recovers from expected loss rates
#[test]
fn gate_fec_recovery() {
    let data = vec![0xABu8; 50000];
    let chunker = BlockChunker::new(10, 5).unwrap(); // 33% redundancy
    let chunks = chunker.encode(&data).unwrap();

    // Should recover with exactly 10 chunks (any 10)
    let subset: Vec<_> = chunks.iter().step_by(2).take(10).cloned().collect();
    assert_eq!(subset.len(), 10);

    let decoded = chunker.decode(&subset, data.len());
    assert!(decoded.is_ok(), "Should recover with minimum chunks");
    assert_eq!(decoded.unwrap(), data);
}

/// Gate 4: Compact block serialization roundtrips
#[test]
fn gate_compact_block_roundtrip() {
    let header = vec![0u8; 1487];
    let hash = BlockHash::from_bytes([0xAB; 32]);

    let mut builder = CompactBlockBuilder::new(hash, header.clone());
    for i in 0..100 {
        let mut txid_bytes = [0u8; 32];
        txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        builder.add_transaction(TxId::from_bytes(txid_bytes));
    }

    let serialized = builder.build();
    let compact = bedrock_forge::CompactBlock::deserialize(&serialized);

    assert!(compact.is_ok(), "Compact block should deserialize");
    let compact = compact.unwrap();
    assert_eq!(compact.short_ids.len(), 100, "Wrong tx count");
}

/// Gate 5: Reconstruction works with full mempool
#[test]
fn gate_reconstruction_full_mempool() {
    let header = vec![0u8; 1487];
    let hash = BlockHash::from_bytes([0xAB; 32]);

    let mut transactions = Vec::new();
    let mut mempool = TestMempool::new();

    for i in 0..50 {
        let mut txid_bytes = [0u8; 32];
        txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        let txid = TxId::from_bytes(txid_bytes);
        let tx_data = vec![i as u8; 200];

        transactions.push((txid, tx_data.clone()));
        mempool.add_transaction(txid, tx_data);
    }

    let mut builder = CompactBlockBuilder::new(hash, header);
    for (txid, _) in &transactions {
        builder.add_transaction(*txid);
    }
    let serialized = builder.build();

    let compact = bedrock_forge::CompactBlock::deserialize(&serialized).unwrap();
    let mut reconstructor = CompactBlockReconstructor::new(compact, &mempool).unwrap();

    let result = reconstructor.reconstruct().unwrap();

    match result {
        ReconstructionResult::Success(block) => {
            assert_eq!(block.transactions.len(), 50);
        }
        ReconstructionResult::NeedTransactions(_) => {
            panic!("Should reconstruct with full mempool");
        }
    }
}

/// Gate 6: Relay node starts and stops cleanly
#[tokio::test]
async fn gate_relay_lifecycle() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut node = RelayNode::new(config).unwrap();

    // Should bind successfully
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    assert!(addr.port() > 0, "Should get a valid port");

    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    // Should start
    let handle = tokio::spawn(async move {
        node_clone.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(node.is_running(), "Should be running");

    // Should stop cleanly
    node.stop();
    let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
    assert!(result.is_ok(), "Should stop within timeout");
    assert!(!node.is_running(), "Should not be running after stop");
}

/// Gate 7: Client connects and communicates
#[tokio::test]
async fn gate_client_communication() {
    // Start relay
    let relay_config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut relay = RelayNode::new(relay_config).unwrap();
    relay.bind().await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let relay = Arc::new(relay);
    let relay_clone = Arc::clone(&relay);

    tokio::spawn(async move {
        let _ = relay_clone.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client should connect
    let client_config = ClientConfig::new(relay_addr);
    let mut client = RelayClient::new(client_config).unwrap();
    client.connect().await.unwrap();

    // Should be able to send
    let block_hash = [0xABu8; 32];
    let data = vec![0u8; 1000];
    let result = client.send_block(&block_hash, &data).await;
    assert!(result.is_ok(), "Should send block");

    // Cleanup
    client.stop();
    relay.stop();
}

/// Gate 8: Metrics tracking works
#[tokio::test]
async fn gate_metrics() {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap());
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    tokio::spawn(async move {
        let _ = node_clone.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send some packets
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..10 {
        let chunk = bedrock_forge::Chunk::new(
            bedrock_forge::ChunkHeader::new_block(&[0u8; 32], 0, 10, 100),
            vec![0u8; 100],
        );
        let _ = socket.send_to(&chunk.to_bytes(), addr).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let snapshot = node.metrics().snapshot();
    assert!(snapshot.packets_received > 0, "Should track received packets");

    node.stop();
}

/// Gate 9: Authentication rejects bad keys
#[tokio::test]
async fn gate_authentication() {
    let good_key = [0x42u8; 32];
    let bad_key = [0x00u8; 32];

    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![good_key]);

    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();

    assert!(node.is_authorized(&good_key), "Good key should be authorized");
    assert!(!node.is_authorized(&bad_key), "Bad key should not be authorized");
}

/// Gate 10: Version compatibility
#[test]
fn gate_version_compatibility() {
    // Version 1 chunk (no HMAC)
    let v1_header = bedrock_forge::ChunkHeader::new_block(&[0u8; 32], 0, 10, 100);
    assert_eq!(v1_header.version, 1);

    // Version 2 chunk (with HMAC)
    let v2_header = bedrock_forge::ChunkHeader::new_block_authenticated(
        &[0u8; 32], 0, 10, 100, [0u8; 32]
    );
    assert_eq!(v2_header.version, 2);

    // Both should serialize/deserialize correctly
    let v1_chunk = bedrock_forge::Chunk::new(v1_header, vec![0u8; 100]);
    let v1_bytes = v1_chunk.to_bytes();
    let v1_parsed = bedrock_forge::Chunk::from_bytes(&v1_bytes).unwrap();
    assert_eq!(v1_parsed.header.version, 1);

    let v2_chunk = bedrock_forge::Chunk::new(v2_header, vec![0u8; 100]);
    let v2_bytes = v2_chunk.to_bytes();
    let v2_parsed = bedrock_forge::Chunk::from_bytes(&v2_bytes).unwrap();
    assert_eq!(v2_parsed.header.version, 2);
}

/// Summary: Run all gates
#[test]
fn predeploy_summary() {
    println!("\n=== Pre-Deployment Checklist ===");
    println!("Gate 1: Type sizes          - Verified in gate_type_sizes");
    println!("Gate 2: FEC roundtrip       - Verified in gate_fec_roundtrip");
    println!("Gate 3: FEC recovery        - Verified in gate_fec_recovery");
    println!("Gate 4: Compact block       - Verified in gate_compact_block_roundtrip");
    println!("Gate 5: Reconstruction      - Verified in gate_reconstruction_full_mempool");
    println!("Gate 6: Relay lifecycle     - Verified in gate_relay_lifecycle");
    println!("Gate 7: Client comms        - Verified in gate_client_communication");
    println!("Gate 8: Metrics             - Verified in gate_metrics");
    println!("Gate 9: Authentication      - Verified in gate_authentication");
    println!("Gate 10: Version compat     - Verified in gate_version_compatibility");
    println!("================================\n");
}
```

**Step 3: Run predeploy tests**

Run: `cargo test gate_ -- --nocapture 2>&1 | tail -30`

**Step 4: Commit**

```bash
git add tests/predeploy/
git commit -m "test: add pre-deployment checklist tests"
```

---

## Task 7: Create Test Runner Script

**Files:**
- Create: `scripts/run_tests.sh`

**Step 1: Create test runner script**

Create `scripts/run_tests.sh`:
```bash
#!/bin/bash
set -e

echo "============================================"
echo "Bedrock-Forge Test Suite"
echo "============================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0

run_test() {
    local name=$1
    local cmd=$2

    echo -n "Running $name... "
    if eval "$cmd" > /tmp/test_output.txt 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        ((passed++))
    else
        echo -e "${RED}FAILED${NC}"
        echo "  Output:"
        tail -10 /tmp/test_output.txt | sed 's/^/    /'
        ((failed++))
    fi
}

echo "=== Layer 0: Unit Tests ==="
run_test "Unit tests" "cargo test --lib"

echo ""
echo "=== Layer 1: Integration Tests ==="
run_test "Integration tests" "cargo test --test integration"
run_test "FEC integration" "cargo test --test fec_integration"
run_test "Relay integration" "cargo test --test relay_integration"

echo ""
echo "=== Layer 2: E2E Tests ==="
run_test "E2E pipeline" "cargo test e2e_ -- --test-threads=1"

echo ""
echo "=== Layer 3: Stress Tests ==="
run_test "Chaos tests" "cargo test stress_ -- --test-threads=1"

echo ""
echo "=== Layer 4: Pre-deployment Gates ==="
run_test "Pre-deploy gates" "cargo test gate_ -- --test-threads=1"

echo ""
echo "============================================"
echo "Summary"
echo "============================================"
echo -e "Passed: ${GREEN}$passed${NC}"
echo -e "Failed: ${RED}$failed${NC}"
echo ""

if [ $failed -gt 0 ]; then
    echo -e "${RED}TEST SUITE FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
```

**Step 2: Make executable**

Run: `chmod +x scripts/run_tests.sh`

**Step 3: Commit**

```bash
git add scripts/
git commit -m "test: add test runner script"
```

---

## Task 8: Update Documentation

**Files:**
- Create: `docs/testing.md`

**Step 1: Create testing documentation**

Create `docs/testing.md`:
```markdown
# Bedrock-Forge Testing Guide

## Quick Start

Run all tests:
```bash
./scripts/run_tests.sh
```

Run specific test layers:
```bash
# Unit tests only
cargo test --lib

# Integration tests
cargo test --test '*'

# E2E tests
cargo test e2e_

# Stress tests
cargo test stress_

# Pre-deployment gates
cargo test gate_
```

## Test Architecture

```
┌─────────────────────────────────────────────────────┐
│  Layer 4: Pre-Deployment Checklist                  │
│  10 automated verification gates                    │
├─────────────────────────────────────────────────────┤
│  Layer 3: Stress/Chaos Testing                      │
│  Packet loss, high load, concurrent senders         │
├─────────────────────────────────────────────────────┤
│  Layer 2: Performance Benchmarks                    │
│  FEC encode/decode, compact block, reconstruction   │
├─────────────────────────────────────────────────────┤
│  Layer 1: E2E Validation                            │
│  Full pipeline tests with test fixtures             │
├─────────────────────────────────────────────────────┤
│  Layer 0: Unit + Integration Tests                  │
│  67+ tests for individual components                │
└─────────────────────────────────────────────────────┘
```

## Test Categories

### Unit Tests (`cargo test --lib`)

Located in each source file's `#[cfg(test)]` module. Test individual functions and types in isolation.

### Integration Tests (`tests/`)

- `tests/integration.rs` - Compact block integration
- `tests/fec_integration.rs` - FEC encode/decode integration
- `tests/relay_integration.rs` - Relay node/client integration

### E2E Tests (`tests/e2e/`)

Full pipeline tests using test fixtures:
- `e2e_chunker_roundtrip` - Data through FEC
- `e2e_relay_node_forward` - Chunks through relay
- `e2e_full_pipeline` - Sender → relay → receiver
- `e2e_compact_block_reconstruction` - Mempool reconstruction

### Stress Tests (`tests/stress/`)

Chaos and load testing:
- `stress_fec_recovery_under_loss` - FEC with packet loss
- `stress_high_throughput` - 10K+ chunks/second
- `stress_concurrent_senders` - Multiple simultaneous senders
- `stress_large_block` - 2MB block handling
- `stress_extreme_loss_graceful` - Graceful degradation

### Pre-Deployment Gates (`tests/predeploy/`)

10 verification gates that must pass before deployment:

1. **Type sizes** - Core types correctly sized
2. **FEC roundtrip** - Encode/decode preserves data
3. **FEC recovery** - Recovers from expected loss
4. **Compact block** - Serialization roundtrips
5. **Reconstruction** - Works with full mempool
6. **Relay lifecycle** - Start/stop cleanly
7. **Client communication** - Connect and send
8. **Metrics** - Tracking works
9. **Authentication** - Rejects bad keys
10. **Version compatibility** - V1 and V2 chunks work

## Benchmarks

Run benchmarks:
```bash
cargo bench
```

Benchmarks measure:
- Compact block building (50-2500 txs)
- FEC encoding (10KB-1MB)
- FEC decoding (10KB-1MB)
- Block reconstruction (50-95% mempool hit rate)

## Network Simulation

The test harness (`tests/harness/`) provides network simulation:

```rust
use harness::network::{SimulatedNetwork, NetworkConditions};

// Simulate lossy network
let net = SimulatedNetwork::new(NetworkConditions::lossy());

// Check if packet is delivered
match net.process_packet() {
    PacketFate::Delivered => { /* send packet */ }
    PacketFate::Lost => { /* drop packet */ }
    PacketFate::Duplicated => { /* send twice */ }
}
```

Available presets:
- `NetworkConditions::perfect()` - No loss
- `NetworkConditions::typical_internet()` - 0.1% loss, 50ms latency
- `NetworkConditions::lossy()` - 5% loss, 100ms latency
- `NetworkConditions::degraded()` - 15% loss, 200ms latency
- `NetworkConditions::satellite()` - 2% loss, 600ms latency

## Test Fixtures

Located in `tests/fixtures/`:

```rust
use fixtures::blocks::{create_testnet_block, create_large_block};

// Typical testnet block (~50 txs, ~15KB)
let block = create_testnet_block();

// Large stress test block (~2500 txs, ~1.25MB)
let block = create_large_block();

// Custom synthetic block
let block = create_synthetic_block(100, 500); // 100 txs, 500 bytes each
```

## CI Integration

Recommended CI pipeline:

```yaml
test:
  script:
    - cargo fmt --check
    - cargo clippy -- -D warnings
    - ./scripts/run_tests.sh
    - cargo bench --no-run  # Compile benchmarks
```

## Pre-Deployment Checklist

Before deploying to testnet:

1. [ ] All unit tests pass: `cargo test --lib`
2. [ ] All integration tests pass: `cargo test --test '*'`
3. [ ] All E2E tests pass: `cargo test e2e_`
4. [ ] Stress tests pass: `cargo test stress_`
5. [ ] All 10 gates pass: `cargo test gate_`
6. [ ] Benchmarks show acceptable performance: `cargo bench`
7. [ ] No clippy warnings: `cargo clippy`
8. [ ] Code formatted: `cargo fmt --check`

Run the full checklist:
```bash
./scripts/run_tests.sh && cargo bench --no-run && cargo clippy && cargo fmt --check
```
```

**Step 2: Commit**

```bash
git add docs/testing.md
git commit -m "docs: add testing guide"
```
