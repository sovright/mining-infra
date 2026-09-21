# Job Declaration Client Guide

> **Full-Template is unavailable:** FullTemplate instructions below describe the planned client protocol. Current servers reject FullTemplate opt-in and declarations; clients must honor a CoinbaseOnly fallback. See [mode status](./full-template-mode.md).

The JD Client enables decentralized mining by letting you construct your own block templates while still mining with a pool.

## Why Use JD Client?

| Standard Pool Mining | With JD Client |
|---------------------|----------------|
| Pool selects transactions | You select transactions |
| Pool constructs coinbase | You construct coinbase |
| Pool could censor txs | Censorship resistant |
| Trust pool completely | Verify your own blocks |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Infrastructure                       │
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐  │
│  │  Zebra Node  │◀────▶│  JD Client   │─────▶│   Mining     │  │
│  │  (your node) │      │              │      │   Hardware   │  │
│  └──────────────┘      └──────┬───────┘      └──────────────┘  │
│                               │                                 │
└───────────────────────────────┼─────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Pool JD Server     │
                    │  (pool.example.com)   │
                    └───────────────────────┘
```

## Prerequisites

1. **Zebra Node** - Running with RPC enabled
2. **Pool that supports JD** - Not all pools support Job Declaration
3. **Network connectivity** - To both Zebra and pool

## Installation

```bash
# Build from source
git clone https://github.com/iqlusioninc/stratum-zcash
cd stratum-zcash
cargo build --release -p zcash-jd-client

# Binary will be at: target/release/zcash-jd-client
```

## Quick Start

### Coinbase-Only Mode (Default)

Customize your coinbase transaction while pool provides transactions:

```bash
zcash-jd-client \
  --zebra-url http://127.0.0.1:8232 \
  --pool-jd-addr pool.example.com:3334 \
  --user-id my-miner-001 \
  --payout-address t1YourZcashAddress
```

### Full-Template Mode

Select your own transactions (requires pool support):

```bash
zcash-jd-client \
  --zebra-url http://127.0.0.1:8232 \
  --pool-jd-addr pool.example.com:3334 \
  --user-id my-miner-001 \
  --full-template \
  --tx-selection all
```

## Configuration Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--zebra-url` | `http://127.0.0.1:8232` | Your Zebra node RPC endpoint |
| `--pool-jd-addr` | `127.0.0.1:3334` | Pool's JD Server address |
| `--user-id` | `zcash-jd-client` | Your miner identifier |
| `--poll-interval` | `1000` | Template polling interval (ms) |
| `--payout-address` | None | Optional additional payout output |
| `--full-template` | `false` | Enable Full-Template mode |
| `--tx-selection` | `all` | Transaction selection strategy |
| `--noise-enabled` | `false` | Use Noise encryption |
| `--pool-public-key` | None | Pool's Noise public key (hex) |

## Transaction Selection Strategies

### `all` (Default)

Include all transactions from your Zebra mempool:

```bash
--tx-selection all
```

### `by-fee-rate`

Prioritize transactions by fee rate (ZEC/byte):

```bash
--tx-selection by-fee-rate
```

## Protocol Flow

### Coinbase-Only Mode

```
JD Client                         Pool JD Server
    |                                   |
    |-- AllocateMiningJobToken -------->|
    |   (mode: CoinbaseOnly)            |
    |                                   |
    |<- AllocateMiningJobToken.Success -|
    |   (token, coinbase_output)        |
    |                                   |
    |-- SetCustomMiningJob ------------>|
    |   (token, custom_coinbase)        |
    |                                   |
    |<- SetCustomMiningJob.Success -----|
    |   (job_id)                        |
    |                                   |
    |  [Mine with job_id]               |
    |                                   |
    |-- PushSolution ------------------>|
    |   (when block found)              |
```

### Full-Template Mode

```
JD Client                         Pool JD Server
    |                                   |
    |-- AllocateMiningJobToken -------->|
    |   (mode: FullTemplate)            |
    |                                   |
    |<- AllocateMiningJobToken.Success -|
    |   (token, granted: FullTemplate)  |
    |                                   |
    |-- SetFullTemplateJob ------------>|
    |   (token, coinbase, txids, ...)   |
    |                                   |
    |  [If pool needs tx data]          |
    |<- GetMissingTransactions ---------|
    |-- ProvideMissingTransactions ---->|
    |                                   |
    |<- SetFullTemplateJob.Success -----|
    |   (job_id)                        |
```

## Zebra Node Setup

### Enable RPC

In `zebrad.toml`:

```toml
[rpc]
listen_addr = "127.0.0.1:8232"
```

### Required RPC Methods

The JD Client uses these Zebra RPC methods:

| Method | Purpose |
|--------|---------|
| `getblocktemplate` | Fetch new block template |
| `submitblock` | Submit found blocks |
| `getblockchaininfo` | Check sync status |

### Verify Zebra is Ready

```bash
# Check Zebra is synced
curl -X POST http://127.0.0.1:8232 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'

# Verify getblocktemplate works
curl -X POST http://127.0.0.1:8232 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblocktemplate","params":[],"id":1}'
```

## Running in Production

### Systemd Service

Create `/etc/systemd/system/zcash-jd-client.service`:

```ini
[Unit]
Description=Zcash JD Client
After=network.target zebrad.service

[Service]
Type=simple
User=mining
ExecStart=/usr/local/bin/zcash-jd-client \
  --zebra-url http://127.0.0.1:8232 \
  --pool-jd-addr pool.example.com:3334 \
  --user-id production-miner \
  --full-template \
  --noise-enabled \
  --pool-public-key YOUR_POOL_PUBLIC_KEY
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable zcash-jd-client
sudo systemctl start zcash-jd-client
sudo journalctl -u zcash-jd-client -f
```

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p zcash-jd-client

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/zcash-jd-client /usr/local/bin/
ENTRYPOINT ["zcash-jd-client"]
```

```bash
docker run -d \
  --name jd-client \
  --network host \
  zcash-jd-client \
  --zebra-url http://127.0.0.1:8232 \
  --pool-jd-addr pool.example.com:3334 \
  --user-id docker-miner
```

## Monitoring

### Logs

```bash
# View logs
journalctl -u zcash-jd-client -f

# Expected output:
# INFO Connected to Zebra at http://127.0.0.1:8232
# INFO Connected to pool JD server at pool.example.com:3334
# INFO Allocated token (mode: FullTemplate)
# INFO Declared job 42 with 150 transactions
# INFO New block template at height 2000001
```

### Metrics

The JD Client exposes Prometheus metrics on port 9100:

```
# Template updates
jd_client_templates_received_total
jd_client_template_transactions_count

# Job declarations
jd_client_jobs_declared_total
jd_client_jobs_accepted_total
jd_client_jobs_rejected_total

# Blocks
jd_client_blocks_found_total
jd_client_blocks_submitted_total
```

## Troubleshooting

### "Failed to connect to Zebra"

```bash
# Check Zebra is running
systemctl status zebrad

# Check RPC is accessible
curl http://127.0.0.1:8232

# Check firewall
sudo iptables -L | grep 8232
```

### "Token allocation failed"

- Pool may not support Job Declaration
- Your user ID may be invalid
- Pool may have rate limiting

### "Job declaration rejected: stale"

- Your Zebra node may be behind
- Network latency to pool is high
- Check Zebra sync status

### "Full-Template mode not granted"

Pool doesn't support Full-Template mode. You'll be downgraded to Coinbase-Only:

```
WARN Full-Template requested but pool granted CoinbaseOnly
```

Either:
1. Use Coinbase-Only mode
2. Find a pool that supports Full-Template

### "GetMissingTransactions received"

Normal in Full-Template mode. The pool doesn't have some transactions in its mempool. Your client will provide them automatically.

## Security Considerations

### Use Noise Encryption

Always enable Noise when connecting over the internet:

```bash
--noise-enabled --pool-public-key <POOL_KEY>
```

### Verify Pool Public Key

Get the pool's public key from a trusted source (their website over HTTPS, not from the pool itself during connection).

### Run Your Own Zebra Node

Don't use a third-party Zebra node - run your own to ensure you're mining on valid blocks.

## Advanced: Custom Transaction Selection

For advanced users who want custom transaction selection logic:

```rust
use zcash_jd_client::TxSelectionStrategy;

// Implement custom strategy
pub struct MyCustomStrategy {
    min_fee_rate: u64,
    excluded_addresses: Vec<String>,
}

impl TxSelectionStrategy for MyCustomStrategy {
    fn select(&self, mempool: &[Transaction]) -> Vec<Transaction> {
        mempool.iter()
            .filter(|tx| tx.fee_rate() >= self.min_fee_rate)
            .filter(|tx| !self.is_excluded(tx))
            .collect()
    }
}
```

## Next Steps

- [Full-Template Mode](./full-template-mode.md) - Deep dive into transaction selection
- [Pool Operator Guide](./pool-operator-guide.md) - If you're running a pool
- [Security Guide](./security-guide.md) - Hardening your setup
