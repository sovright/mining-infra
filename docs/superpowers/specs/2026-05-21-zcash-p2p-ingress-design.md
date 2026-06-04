# Zcash P2P Ingress Design

## Goal

Add a Bedrock-owned Zcash mainnet P2P ingress daemon that can discover peers, connect to the Zcash P2P network, observe block inventory and block payloads, and produce first-seen timing data that can be compared with public block explorers.

## Scope

The first release is an observation and relay-ingress MVP. It does not replace Zebra validation, does not submit blocks, and does not claim consensus acceptance. Zebra remains the validating path for mainnet correctness.

## Architecture

Create a new crate and binary named `bedrock-p2p-ingress`.

Components:

- `config`: environment-based runtime configuration for seeds, peer count, timeouts, event log, and optional FORGE relay output.
- `wire`: Zcash P2P message framing, compact-size encoding, inventory parsing, and checksum validation.
- `peer`: one outbound TCP session that performs `version` / `verack`, responds to `ping`, handles `inv`, sends `getdata`, and logs received `block` payloads.
- `event`: JSONL event sink used for deployment comparison.
- `forge`: optional bridge from P2P block payloads to the existing FORGE `RelayClient`.

## Data Flow

1. Resolve configured mainnet DNS seeds on TCP port `8233`.
2. Connect outbound to a bounded number of peers.
3. Perform Zcash P2P handshake using ZIP 204 message framing.
4. Listen for `inv` messages with `MSG_BLOCK` inventory.
5. Send `getdata` for new block inventory entries.
6. On `block`, compute the Zcash block hash from the serialized header and log `p2p_block_received`.
7. If relay config is present, forward a header-only `CompactBlock` into FORGE as an experimental ingress signal.

## Safety

- Outbound-only by default; no listener is required for the MVP.
- Bounded peers and message payload sizes.
- Logs both inventory and block receipt events.
- Does not mark blocks as consensus-valid.
- Does not submit blocks to Zebra or zcashd.
- Optional FORGE bridge is disabled unless relay peers and auth key are explicitly provided.

## Deployment

Deploy the daemon on the ops or Zebra host as a systemd service. It should write JSONL events to `/var/log/bedrock/zcash-p2p-ingress.jsonl`. After deploy, compare P2P event times with the existing public-source observer log.
