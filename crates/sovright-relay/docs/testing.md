# Sovright Relay Testing Guide

> Note: This document was written before the rename from fiber-zcash to sovright-relay. Some internal references may still use the old name.

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
cargo test --test integration
cargo test --test fec_integration
cargo test --test relay_integration

# E2E tests
cargo test --test e2e_test

# Stress tests
cargo test --test stress_test

# Pre-deployment gates
cargo test --test predeploy_test
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
│  Layer 2: E2E Validation                            │
│  Full pipeline tests with test fixtures             │
├─────────────────────────────────────────────────────┤
│  Layer 1: Integration Tests                         │
│  Component integration (compact blocks, FEC, relay) │
├─────────────────────────────────────────────────────┤
│  Layer 0: Unit Tests                                │
│  Individual component tests                         │
└─────────────────────────────────────────────────────┘
```

## Test Categories

### Unit Tests (`cargo test --lib`)

Located in each source file's `#[cfg(test)]` module. Test individual functions and types in isolation.

### Integration Tests (`tests/`)

- `tests/integration.rs` - Compact block round-trip integration
- `tests/fec_integration.rs` - FEC encode/decode integration
- `tests/relay_integration.rs` - Relay node/client integration

### E2E Tests (`tests/e2e/`)

Full pipeline tests using test fixtures:
- `e2e_fec_roundtrip` - Data through FEC encoder/decoder
- `e2e_chunker_roundtrip` - Compact blocks through chunker
- `e2e_relay_node_forward` - Chunks through relay node
- `e2e_compact_block_reconstruction` - Mempool reconstruction
- `e2e_large_block` - Large block handling

### Stress Tests (`tests/stress/`)

Chaos and load testing:
- `stress_fec_recovery_under_loss` - FEC with simulated packet loss
- `stress_high_throughput` - 10K+ chunks/second throughput
- `stress_concurrent_senders` - Multiple simultaneous senders
- `stress_large_block` - 2MB block encoding/decoding
- `stress_extreme_loss_graceful` - Graceful degradation under 60% loss
- `stress_rapid_blocks` - 100+ blocks in rapid succession

### Pre-Deployment Gates (`tests/predeploy/`)

10 verification gates that must pass before deployment:

1. **Type sizes** - Core types (BlockHash, TxId) correctly sized
2. **FEC roundtrip** - Encode/decode preserves data for various sizes
3. **FEC recovery** - Recovers from maximum expected loss
4. **Compact block** - Serialization roundtrips through chunker
5. **Reconstruction** - Works with full mempool
6. **Relay lifecycle** - Node starts and stops cleanly
7. **Metrics** - Packet tracking works
8. **Authentication** - Key-based auth works correctly
9. **Version compatibility** - V1 and V2 chunks serialize correctly
10. **Config validation** - Invalid configs are rejected

## Benchmarks

Run benchmarks:
```bash
cargo bench
```

Benchmarks measure:
- `compact_block_build` - Building compact blocks (50-2500 txs)
- `fec_encode` - FEC encoding (10KB-1MB)
- `fec_decode` - FEC decoding with all shards (10KB-1MB)
- `fec_decode_loss` - FEC decoding with 3 lost shards
- `reconstruction` - Block reconstruction (50-95% mempool hit rate)
- `chunker_roundtrip` - Full chunker encode/decode cycle

## Test Fixtures

Located in `tests/fixtures/`:

```rust
use fixtures::blocks::{create_testnet_block, create_large_block, create_synthetic_block};

// Typical testnet block (~50 txs, ~15KB)
let block = create_testnet_block();

// Large stress test block (~2500 txs, ~1.25MB)
let block = create_large_block();

// Custom synthetic block
let block = create_synthetic_block(100, 500); // 100 txs, 500 bytes each
```

## Network Simulation

The test harness (`tests/harness/`) provides network simulation:

```rust
use harness::network::{SimulatedNetwork, NetworkConditions, PacketFate};

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
- `NetworkConditions::perfect()` - No loss, no latency
- `NetworkConditions::typical_internet()` - 0.1% loss, 50ms latency
- `NetworkConditions::lossy()` - 5% loss, 100ms latency
- `NetworkConditions::degraded()` - 15% loss, 200ms latency
- `NetworkConditions::satellite()` - 2% loss, 600ms latency

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
2. [ ] All integration tests pass: `cargo test --test integration --test fec_integration --test relay_integration`
3. [ ] All E2E tests pass: `cargo test --test e2e_test`
4. [ ] Stress tests pass: `cargo test --test stress_test`
5. [ ] All 10 gates pass: `cargo test --test predeploy_test`
6. [ ] Benchmarks compile and run: `cargo bench`
7. [ ] No clippy warnings: `cargo clippy -- -D warnings`
8. [ ] Code formatted: `cargo fmt --check`

Run the full checklist:
```bash
./scripts/run_tests.sh && cargo bench --no-run && cargo clippy -- -D warnings && cargo fmt --check
```

## Adding New Tests

### Adding a Unit Test

Add a `#[test]` function in the source file's `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_new_test() {
        // test code
    }
}
```

### Adding an Integration Test

Create or modify files in `tests/`:

```rust
// tests/my_integration.rs
use sovright_relay::*;

#[test]
fn my_integration_test() {
    // test code
}
```

### Adding a Stress Test

Add to `tests/stress/chaos.rs`:

```rust
#[tokio::test]
async fn stress_my_scenario() {
    // stress test code
}
```

### Adding a Pre-deployment Gate

Add to `tests/predeploy/checklist.rs`:

```rust
#[test]
fn gate_my_new_check() {
    // verification code
}
```

Update the `predeploy_summary` test to document the new gate.
