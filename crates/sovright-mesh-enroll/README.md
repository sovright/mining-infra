# sovright-mesh-enroll (PoC)

Enrollment proof-of-concept for **miner relay onboarding** — see
`docs/miner-onboarding.md`. Demonstrates the flow: a miner runs their own relay
node, it **generates a mesh key locally**, and registers that key with a single-use
**invite code** over HTTP(S); on a valid invite the key is **auto-added to the
authorized-key store** the relays read into `RelayConfig.authorized_keys`, admitting
the miner's node to the mesh.

Deliberately dep-light (only `serde`, `serde_json`, `thiserror`, `hex`, `getrandom` —
all already vendored) and std TCP. **PoC caveats:** plain HTTP on loopback (production
terminates TLS, §4.1/§5); in-memory stores (production is durable + transactional);
`now` is injected so the invite lifecycle is deterministically tested.

## What's here

- **Library** (`src/lib.rs`) — the pure logic, unit-tested:
  - `MeshKey` — CSPRNG generation, hex round-trip, all-zero rejection, non-leaking `Debug`.
  - `InviteStore` — single-use + expiring invites; non-mutating `check` then atomic `consume`.
  - `KeyStore` — the mesh bridge: `authorized_keys()` is exactly the `Vec<[u8;32]>` a
    relay loads (`node.rs:138`); `peers()` is the fan-out set; `revoke()` drops both.
  - `enroll(...)` — the transaction. Validates **before** consuming the invite, so a
    bad key/endpoint or duplicate id never burns the miner's one-time invite.
- **`mesh-enroll-server`** (`src/bin/server.rs`) — the enroll service: `POST /v1/invite`
  (ops), `POST /v1/enroll`, `POST /v1/revoke` (ops), `GET /healthz`. Rewrites the
  authorized-key store file on each change.
- **`mesh-enroll`** (`src/bin/client.rs`) — miner side: generates the key, persists it,
  POSTs the enroll request.

## Run the demo

```sh
# 1. start the enroll service
SOVRIGHT_ENROLL_OPS_TOKEN=secret-ops \
SOVRIGHT_ENROLL_KEYSTORE=/tmp/authorized_keys.json \
SOVRIGHT_MESH_PEERS=10.0.0.1:9000,10.0.0.2:9000 \
cargo run -p sovright-mesh-enroll --bin mesh-enroll-server

# 2. ops issues an invite
curl -s -X POST 127.0.0.1:8088/v1/invite \
  -d '{"ops_token":"secret-ops","pool":"pool-alpha","ttl_secs":3600}'

# 3. miner generates a key and enrolls with the invite code
cargo run -p sovright-mesh-enroll --bin mesh-enroll -- \
  --server 127.0.0.1:8088 --invite <code> \
  --miner-id pool-alpha --endpoint 203.0.113.7:9000

# 4. the key is now in the store the relays read
cat /tmp/authorized_keys.json
```

## Not yet built (tracked in the RFC, §9)

TLS on the enroll hop; durable/transactional stores; the relay-side reload of
`authorized_keys` from this store; the loopback block-inject hook on the miner's node;
per-miner metrics/rate limits; the deployment bundle.
