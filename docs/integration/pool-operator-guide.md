# Pool Operator Guide

This guide covers setting up and running a Zcash Stratum V2 mining pool.

## Architecture

```
                                    ┌─────────────────────────────────┐
                                    │         Zebra Node              │
                                    │    http://127.0.0.1:8232        │
                                    └──────────────┬──────────────────┘
                                                   │
                                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Pool Infrastructure                                 │
│                                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐          │
│  │ Template Provider│───▶│   Pool Server    │◀───│   JD Server      │          │
│  │ (fetches blocks) │    │   (port 3333)    │    │   (port 3334)    │          │
│  └──────────────────┘    └────────┬─────────┘    └────────┬─────────┘          │
│                                   │                       │                     │
│                                   ▼                       ▼                     │
│                          ┌──────────────────┐    ┌──────────────────┐          │
│                          │ Share Processor  │    │  Token Manager   │          │
│                          └────────┬─────────┘    └──────────────────┘          │
│                                   │                                             │
│                                   ▼                                             │
│                          ┌──────────────────┐                                   │
│                          │  Payout Tracker  │                                   │
│                          │     (PPS)        │                                   │
│                          └──────────────────┘                                   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
            ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
            │   Miners    │     │   Miners    │     │ JD Clients  │
            │  (direct)   │     │  (direct)   │     │(decentralized)│
            └─────────────┘     └─────────────┘     └─────────────┘
```

## Quick Start

### 1. Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repository
git clone https://github.com/iqlusioninc/stratum-zcash
cd stratum-zcash

# Build all components
cargo build --release
```

### 2. Setup Zebra Node

Ensure Zebra is running with RPC enabled:

```toml
# zebrad.toml
[rpc]
listen_addr = "127.0.0.1:8232"

[network]
network = "Mainnet"
```

### 3. Generate Noise Keypair

```bash
cargo run --release -p sovright-noise --example generate_keys

# Output:
# Private key: 7a8b9c...  (KEEP SECRET)
# Public key:  a1b2c3...  (share with miners)
```

### 4. Configure Pool

Create `pool.toml`:

```toml
[server]
listen_addr = "0.0.0.0:3333"
jd_listen_addr = "0.0.0.0:3334"

[zebra]
url = "http://127.0.0.1:8232"

[mining]
initial_difficulty = 1.0
target_shares_per_minute = 5.0
nonce_1_len = 4

[payout]
pool_address = "t1YourPoolPayoutAddress"
pool_fee_percent = 1.0

[security]
noise_enabled = true
noise_private_key = "7a8b9c..."
max_connections = 10000

[jd]
enabled = true
full_template_enabled = true
full_template_validation = "Standard"
token_lifetime_secs = 300
```

### 5. Run Pool

```bash
cargo run --release -p zcash-pool-server -- --config pool.toml
```

## Configuration Reference

### Server Settings

| Option | Default | Description |
|--------|---------|-------------|
| `listen_addr` | `0.0.0.0:3333` | Miner connection endpoint |
| `jd_listen_addr` | `0.0.0.0:3334` | JD Client endpoint |
| `payout_state_path` | `payout-state.json` | Durable PPS payout state file |
| `max_connections` | `10000` | Maximum concurrent miners |

### Zebra Settings

| Option | Default | Description |
|--------|---------|-------------|
| `url` | `http://127.0.0.1:8232` | Zebra RPC endpoint |
| `poll_interval_ms` | `500` | Template polling interval |

### Mining Settings

| Option | Default | Description |
|--------|---------|-------------|
| `initial_difficulty` | `1.0` | Starting share difficulty |
| `min_difficulty` | `0.001` | Minimum difficulty floor |
| `max_difficulty` | `1000000.0` | Maximum difficulty ceiling |
| `target_shares_per_minute` | `5.0` | Vardiff target |
| `nonce_1_len` | `4` | NONCE_1 size (bytes) |
| `validation_threads` | `4` | Equihash validation threads |

### Payout Settings

| Option | Default | Description |
|--------|---------|-------------|
| `pool_address` | Required | Pool payout address |
| `pool_fee_percent` | `1.0` | Pool fee percentage |
| `min_payout` | `0.01` | Minimum payout threshold (ZEC) |
| `payout_interval_hours` | `24` | Payout frequency |

### Security Settings

| Option | Default | Description |
|--------|---------|-------------|
| `noise_enabled` | `false` | Enable Noise encryption |
| `noise_private_key` | None | Pool's Noise private key (hex) |
| `require_noise` | `false` | Reject unencrypted connections |

### JD Server Settings

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable Job Declaration |
| `full_template_enabled` | `false` | Allow Full-Template mode |
| `full_template_validation` | `Standard` | Validation level |
| `token_lifetime_secs` | `300` | Token expiration time |
| `max_tokens_per_client` | `10` | Max active tokens per client |
| `coinbase_output_max_additional_size` | `256` | Max extra coinbase bytes |

## Direct Block Submission to the Relay Network

By default a solved block reaches the network only through your local `zebrad`
and native Zcash P2P gossip. You can additionally fan each solved block straight
into the Sovright relay mesh — reaching connected peers faster than native
gossip — by routing your pool's `submitblock` call through the
`sovright-p2p-ingress` **submitblock relay gateway**.

### How it works

```
 getblocktemplate ─────────────────────────────▶  your local zebrad (unchanged)

 submitblock ──▶  sovright-p2p-ingress gateway ──┬──▶  relay mesh fanout (best effort)
                  (loopback JSON-RPC)            └──▶  your local zebrad  (authoritative)
```

- The gateway validates the block (structure, compact target, Equihash, PoW)
  before amplification, then starts relay fanout **and** local Zebra submission
  concurrently.
- **Zebra remains the consensus authority.** The gateway returns Zebra's exact
  `submitblock` result to your pool. Relay failure, timeout, or a rate-limited
  relay is logged but **never** turns a Zebra-accepted block into a pool-visible
  failure — a found block is never lost by using the gateway.
- Native Zebra P2P remains active as a fallback and deduplication path, so this
  is strictly additive.

### 1. Run `sovright-p2p-ingress` with the gateway enabled

Co-locate `sovright-p2p-ingress` with your pool's `zebrad` and enable the
gateway (it is **off** unless a bind address is set). The listener must be
loopback; for remote pools put an authenticated TLS proxy in front of it.

```bash
# Enable the loopback submitblock gateway
export SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR=127.0.0.1:8235
# Local zebrad the gateway submits to (default shown; loopback http only)
export SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL=http://127.0.0.1:8232
# Authenticated relay peers to fan blocks into (Sovright provides these)
export SOVRIGHT_P2P_RELAY_PEERS=10.40.0.3:8333,10.40.16.2:8333
export SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX=<key provided by Sovright>

sovright-p2p-ingress
```

Gateway tuning knobs (all optional):

| Env var | Default | Description |
|---------|---------|-------------|
| `SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR` | unset (gateway off) | Loopback address the pool sends `submitblock` to |
| `SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL` | `http://127.0.0.1:8232` | Local `zebrad` RPC (loopback `http://` only) |
| `SOVRIGHT_P2P_SUBMITBLOCK_MAX_BLOCK_BYTES` | `4194304` (4 MiB) | Max accepted block size |
| `SOVRIGHT_P2P_SUBMITBLOCK_MAX_REQUESTS_PER_MINUTE` | `4` (1–120) | Bounds **relay amplification** only; over the limit the block still goes to Zebra, just without mesh fanout |
| `SOVRIGHT_P2P_SUBMITBLOCK_RELAY_TIMEOUT_MILLIS` | `1000` (1–10000) | Max time to wait on relay fanout before falling back to the Zebra-only result |

### 2. Point the pool's `submitblock` at the gateway

The gateway serves **only** the `submitblock` method — it does not proxy
`getblocktemplate` or anything else. So the integration keeps template polling on
your local `zebrad` and sends only `submitblock` to the gateway:

- **`getblocktemplate` (and all other RPC)** → your local `zebrad`
  (`http://127.0.0.1:8232`).
- **`submitblock`** → the gateway (`http://127.0.0.1:8235`), which validates,
  fans the block into the mesh, submits to your `zebrad`, and returns Zebra's
  result.

Do **not** point your whole Zebra RPC URL at the gateway — `getblocktemplate`
would fail, because the gateway implements `submitblock` only.

If your pool software lets you configure the `submitblock` RPC endpoint
separately from the template endpoint, set it to the gateway address and you are
done.

> **Note for `zcash-pool-server` operators:** the bundled pool server currently
> uses a single `[zebra] url` for both `getblocktemplate` and `submitblock`, so
> it cannot split them by config alone yet. Until a dedicated submit-endpoint
> option lands, front `zebrad` with a small loopback JSON-RPC router that sends
> the `submitblock` method to the gateway (`127.0.0.1:8235`) and every other
> method to `zebrad` (`127.0.0.1:8232`), then set `[zebra] url` to that router.
> The gateway's own `submitblock -> zebrad` submission still makes Zebra
> authoritative.

### 3. Verify

```bash
# The gateway logs each accepted block with its relay + Zebra outcome:
journalctl -u sovright-p2p-ingress -f | grep "Pool submitblock"
# "forwarded directly into relay mesh"  -> block fanned into the mesh
# "completed" with zebra_result=accepted -> Zebra accepted (authoritative)
```

A rate-limited or failed relay logs a warning but still reports Zebra's result;
confirm your pool sees the same `submitblock` response it did before.

## Job Declaration Support

### Coinbase-Only Mode

Default mode where miners customize their coinbase but pool provides transactions.

**Configuration:**
```toml
[jd]
enabled = true
full_template_enabled = false
```

**Validation:**
- Pool verifies coinbase includes pool payout
- Pool provides transaction set

### Full-Template Mode

Advanced mode where miners select their own transactions.

**Configuration:**
```toml
[jd]
enabled = true
full_template_enabled = true
full_template_validation = "Standard"  # or "Minimal" or "Strict"
min_pool_payout = 10000  # zatoshis
```

**Validation Levels:**

| Level | Checks | Performance |
|-------|--------|-------------|
| `Minimal` | Pool payout only | Fastest |
| `Standard` | Payout + known txids, request missing | Balanced |
| `Strict` | Full transaction validation | Slowest |

## Monitoring

### Prometheus Metrics

The pool exposes metrics on port 9090:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'zcash-pool'
    static_configs:
      - targets: ['localhost:9090']
```

**Key Metrics:**

```
# Connections
pool_connections_active
pool_connections_total
pool_connections_noise_total

# Mining
pool_shares_accepted_total
pool_shares_rejected_total{reason="stale|duplicate|invalid|low_diff"}
pool_blocks_found_total
pool_hashrate_estimated

# JD Server
jd_tokens_allocated_total
jd_jobs_declared_total
jd_full_template_jobs_total

# Performance
pool_share_validation_duration_seconds
pool_template_age_seconds
```

### Logging

Configure structured logging:

```toml
[logging]
level = "info"  # debug, info, warn, error
format = "json"  # or "pretty"
file = "/var/log/zcash-pool/pool.log"
```

### Alerts

Recommended alerts:

```yaml
# Alertmanager rules
groups:
  - name: zcash-pool
    rules:
      - alert: HighStaleShareRate
        expr: rate(pool_shares_rejected_total{reason="stale"}[5m]) / rate(pool_shares_accepted_total[5m]) > 0.1
        for: 5m

      - alert: NoBlocksFound
        expr: increase(pool_blocks_found_total[24h]) == 0
        for: 1h

      - alert: ZebraDisconnected
        expr: pool_zebra_connected == 0
        for: 1m

      - alert: HighTemplateAge
        expr: pool_template_age_seconds > 30
        for: 5m
```

## High Availability

### Load Balancing

Run multiple pool instances behind a load balancer:

```
                    ┌─────────────────────┐
                    │    HAProxy/Nginx    │
                    │    (TCP mode)       │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │ Pool Node 1 │     │ Pool Node 2 │     │ Pool Node 3 │
    └─────────────┘     └─────────────┘     └─────────────┘
           │                   │                   │
           └───────────────────┼───────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Shared Redis      │
                    │  (share dedup)      │
                    └─────────────────────┘
```

**HAProxy config:**
```
frontend stratum
    bind *:3333
    mode tcp
    default_backend pool_nodes

backend pool_nodes
    mode tcp
    balance leastconn
    option tcp-check
    server pool1 10.0.0.1:3333 check
    server pool2 10.0.0.2:3333 check
    server pool3 10.0.0.3:3333 check
```

### Share Deduplication

For multiple pool instances, use Redis for share deduplication:

```toml
[dedup]
enabled = true
redis_url = "redis://10.0.0.100:6379"
window_seconds = 60
```

### Zebra Redundancy

Run multiple Zebra nodes:

```toml
[zebra]
urls = [
    "http://10.0.0.10:8232",
    "http://10.0.0.11:8232",
    "http://10.0.0.12:8232"
]
failover_timeout_ms = 5000
```

## Security Hardening

### Network Security

```bash
# Firewall rules
sudo ufw allow 3333/tcp   # Stratum
sudo ufw allow 3334/tcp   # JD Server
sudo ufw deny 8232/tcp    # Block external Zebra access

# Rate limiting (iptables)
sudo iptables -A INPUT -p tcp --dport 3333 -m connlimit --connlimit-above 100 -j DROP
```

### TLS Termination

For additional security, terminate TLS at the load balancer:

```
# HAProxy with TLS
frontend stratum_tls
    bind *:3334 ssl crt /etc/ssl/pool.pem
    mode tcp
    default_backend pool_nodes
```

### Connection Limits

```toml
[security]
max_connections = 10000
max_connections_per_ip = 100
connection_timeout_secs = 30
idle_timeout_secs = 300
```

### DDoS Protection

```toml
[security]
# Require valid handshake within timeout
handshake_timeout_secs = 10

# Rate limit share submissions
max_shares_per_second = 100

# Ban repeated invalid submissions
ban_threshold = 50  # invalid shares
ban_duration_secs = 3600
```

## Payout System

### PPS (Pay Per Share)

Default payout scheme:

```
Miner Payment = (Miner Shares / Total Shares) × Block Reward × (1 - Pool Fee)
```

```toml
[payout]
scheme = "pps"
pool_fee_percent = 1.0
```

### PPLNS (Pay Per Last N Shares)

Alternative scheme based on recent shares:

```toml
[payout]
scheme = "pplns"
pplns_window = 100000  # shares
pool_fee_percent = 0.5
```

### Database Integration

For production, integrate with a database:

```toml
[database]
url = "postgres://user:pass@localhost/pool"
```

Schema:
```sql
CREATE TABLE shares (
    id BIGSERIAL PRIMARY KEY,
    miner_id VARCHAR(255) NOT NULL,
    difficulty DOUBLE PRECISION NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    job_id INTEGER NOT NULL,
    is_block BOOLEAN DEFAULT FALSE
);

CREATE TABLE payouts (
    id BIGSERIAL PRIMARY KEY,
    miner_id VARCHAR(255) NOT NULL,
    amount BIGINT NOT NULL,  -- zatoshis
    txid VARCHAR(64),
    timestamp TIMESTAMP DEFAULT NOW()
);
```

## Operational Procedures

### Starting the Pool

```bash
# Verify Zebra is synced
curl -s http://127.0.0.1:8232 -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' | jq .result.blocks

# Start pool
systemctl start zcash-pool

# Monitor logs
journalctl -u zcash-pool -f
```

### Graceful Shutdown

```bash
# Signal graceful shutdown
kill -SIGTERM $(pidof zcash-pool-server)

# Pool will:
# 1. Stop accepting new connections
# 2. Finish processing pending shares
# 3. Save state
# 4. Exit
```

### Updating the Pool

```bash
# Build new version
git pull
cargo build --release

# Deploy with rolling restart
systemctl stop zcash-pool
cp target/release/zcash-pool-server /usr/local/bin/
systemctl start zcash-pool
```

> **PPS difficulty fix (#50/#51) — one-time migration.** Builds prior to this
> fix credited shares at the hash-derived difficulty (inflated and
> high-variance) instead of the job-target difficulty, and credited a found
> block a second time via `PushSolution`. After deploying a build that includes
> the fix:
>
> - **Restart the pool process** (the rolling restart above is sufficient). The
>   in-memory `PayoutTracker` carries the inflated balances forward until the
>   process is restarted; a config reload alone does not clear them.
> - **Review pre-fix payout DB records before paying out on mainnet.** Any rows
>   written before the fix reflect inflated per-share credit and a double-counted
>   block credit. Reconcile or quarantine them before settling real payouts.
>   Testnet pools can simply restart and discard prior balances.

### Emergency Procedures

**Zebra disconnected:**
```bash
# Check Zebra status
systemctl status zebrad

# Restart if needed
systemctl restart zebrad

# Pool will auto-reconnect
```

**High stale rate:**
```bash
# Check template freshness
curl localhost:9090/metrics | grep template_age

# Reduce poll interval if needed
# Edit pool.toml: poll_interval_ms = 250
systemctl restart zcash-pool
```

## Compliance Considerations

### Logging Requirements

Maintain logs for regulatory compliance:

```toml
[logging]
retention_days = 90
include_miner_ips = true
include_share_details = true
```

### Payout Records

Keep detailed payout records:

```sql
-- All payouts with miner identity
SELECT
    miner_id,
    SUM(amount) as total_paid,
    COUNT(*) as payout_count
FROM payouts
WHERE timestamp > NOW() - INTERVAL '1 year'
GROUP BY miner_id;
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

### "High share rejection rate"

1. Check for outdated mining software
2. Verify network latency
3. Review vardiff settings
4. Check for stale template issues

### "Memory usage growing"

```bash
# Check for connection leaks
ss -s | grep ESTABLISHED

# Review pool metrics
curl localhost:9090/metrics | grep connections
```

### "Blocks not submitting"

```bash
# Check Zebra connectivity
curl http://127.0.0.1:8232 -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'

# Check recent block submissions
journalctl -u zcash-pool | grep "block found"
```

## Next Steps

- [Security Guide](./security-guide.md) - Detailed security hardening
- [JD Server Configuration](./jd-server-config.md) - Advanced JD settings
- [Monitoring Guide](./monitoring-guide.md) - Comprehensive monitoring setup
