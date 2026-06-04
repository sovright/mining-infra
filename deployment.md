# Sovright Pool Server — Testnet Deployment

This documents the internal testnet deployment of the Sovright Zcash Stratum V2 mining pool on GCP.

## Breaking changes from the Bedrock-era naming

The project was rebranded from Bedrock/Forge to Sovright. The rename touches operationally significant surfaces. Anything deployed against the old names must be migrated:

**Config keys (`forge_*` → `relay_*`)** — update pool server config files:

| Old key | New key |
|---------|---------|
| `forge_relay_enabled` | `relay_enabled` |
| `forge_relay_peers` | `relay_peers` |
| `forge_bind_addr` | `relay_bind_addr` |
| `forge_auth_key` | `relay_auth_key` |
| `forge_data_shards` | `relay_data_shards` |
| `forge_parity_shards` | `relay_parity_shards` |

(The `noise_*` keys are unchanged.)

**Prometheus metrics** — `bedrock_pool_*` → `sovright_pool_*` (and in the V1 proxy, `bedrock_v1_proxy_*` → `sovright_v1_stratum_proxy_*`). All Grafana dashboards and alerting rules referencing the old metric names must be updated.

**Binary** — `forge-sidecar` → `relay-sidecar` (built from the `sovright-relay-sidecar` crate). Update any systemd units, Dockerfiles, or process supervisors that invoke the old binary name.

**Testnet network name** — `BedrockTestnet` → `SovrightTestnet`. Nodes on different network names will not peer; all nodes must be redeployed together so they share the new `network_name`.

## Infrastructure

| Resource | Details |
|----------|---------|
| GCP Project | `mining-pool-491623` |
| VM | `zebra-testnet` |
| IP | `34.72.217.47` |
| Zone | `us-central1-a` |
| Branch | `internal-testnet` |

### SSH Access

```bash
gcloud compute ssh zebra-testnet --project mining-pool-491623 --zone us-central1-a
```

## Services

### 1. Zebra Node

Zcash testnet full node with internal miner enabled. Runs as a Docker container.

| Port | Service |
|------|---------|
| 18232 | JSON-RPC |
| 18233 | P2P (no peers configured) |

**Status:**
```bash
# Check block height
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
  http://127.0.0.1:18232

# Check block template availability
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblocktemplate","params":[],"id":1}' \
  http://127.0.0.1:18232
```

**Rebuild:**
```bash
cd ~/mining-infra
docker build -t zebra-internal-miner testnet/
docker stop zebra-testnet && docker rm zebra-testnet
docker run -d --name zebra-testnet \
  -v /data/zebra:/data/zebra \
  -p 18232:18232 -p 18233:18233 \
  zebra-internal-miner start --config /config/zebrad.toml
```

**Config:** `testnet/zebrad.toml`

---

### 2. Pool Server

Stratum V2 mining pool. Runs as a native binary in a screen session (not containerized) for fast iteration.

| Port | Service |
|------|---------|
| 3333 | Stratum V2 (miners connect here) |
| 9090 | Prometheus metrics (localhost only) |

**Status:**
```bash
# Attach to screen session
screen -r pool

# Check Prometheus metrics
curl -s http://127.0.0.1:9090/metrics | head -20
```

**Rebuild:**
```bash
# Kill existing session
screen -X -S pool quit

# Rebuild and restart
cd ~/mining-infra
git pull
screen -dmS pool bash -c 'cargo run --release --example run_pool_testnet -p zcash-pool-server 2>&1 | tee /tmp/pool.log'
```

**Config:** `crates/zcash-pool-server/examples/run_pool_testnet.rs`

---

### 3. Test Miner

Submits dummy shares to the pool server for protocol-level testing.

**Run on the VM (Docker):**
```bash
cd ~/mining-infra
docker build -f testnet/Dockerfile.test-miner -t sovright-test-miner .
docker run -d --name test-miner --network host \
  sovright-test-miner --pool 127.0.0.1:3333 --rate 5

# View output
docker logs -f test-miner
```

**Run from a dev machine:**
```bash
cargo run --release -p zcash-test-miner -- --pool 34.72.217.47:3333 --rate 5
```

**Options:**
- `--pool <addr>` — Pool server address (default: 127.0.0.1:3333)
- `--rate <n>` — Target shares per minute (default: 5)
- `--worker <name>` — Worker name for logging (default: testminer.worker1)

**Verify:**
```bash
# Pool should log share submissions
screen -r pool

# Prometheus counters should increment
curl -s http://127.0.0.1:9090/metrics | grep pool_shares
```

---

## GCP Firewall Rules

Currently open ports:

| Port | Purpose | Rule |
|------|---------|------|
| 18232 | Zebra RPC | Opened during initial setup |
| 3333 | Stratum V2 | Opened during initial setup |
| 8080 | Sovright API | `sovright-product-testnet` |
| 3000 | Frontend | `sovright-product-testnet` |

```bash
# Add product stack ports (run once)
gcloud compute firewall-rules create sovright-product-testnet \
  --allow tcp:3000,tcp:8080 \
  --source-ranges 0.0.0.0/0 \
  --target-tags sovright-testnet \
  --project mining-pool-491623
```

## Full System Architecture

```
GCP VM: zebra-testnet (34.72.217.47)
│
├── Zebra Node (Docker)
│   ├── RPC: 127.0.0.1:18232
│   └── Internal miner producing testnet blocks
│
├── Pool Server (native binary, screen session)
│   ├── Stratum: 0.0.0.0:3333
│   ├── Prometheus: 127.0.0.1:9090
│   └── Polls Zebra RPC for block templates
│
├── Test Miner (Docker)
│   └── Connects to pool at 127.0.0.1:3333
│
└── Product Stack (see Sovright-product/deployment.md)
    ├── TimescaleDB: 127.0.0.1:5433
    ├── Sovright API: 0.0.0.0:8080
    │   ├── Polls pool Prometheus (127.0.0.1:9090)
    │   └── Calls Zebra RPC (127.0.0.1:18232) for payouts
    └── Frontend: 0.0.0.0:3000
```

## Troubleshooting

**Zebra not producing templates:**
```bash
# Check if Zebra is synced and the internal miner is active
docker logs zebra-testnet --tail 50
```

**Pool not receiving templates:**
```bash
# Check pool can reach Zebra RPC
curl -s http://127.0.0.1:18232 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

**Test miner not connecting:**
```bash
# Check pool is listening
ss -tlnp | grep 3333

# Check firewall (for external connections)
gcloud compute firewall-rules list --project mining-pool-491623 | grep 3333
```

**Disk space:**
```bash
df -h /data
docker system df
```
