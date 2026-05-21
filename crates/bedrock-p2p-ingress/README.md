# bedrock-p2p-ingress

Native Zcash P2P ingress daemon for Bedrock/FORGE.

This is an MVP for timing and ingress experiments. It discovers Zcash mainnet
peers, performs the P2P handshake, listens for block inventory, requests block
payloads, and logs first-seen events.

It does not consensus-validate blocks and does not submit blocks. Use Zebra as
the validation path.

## Run

```sh
RUST_LOG=info cargo run -p bedrock-p2p-ingress
```

Useful environment variables:

```text
BEDROCK_P2P_DNS_SEEDS=dnsseed.z.cash,dnsseed.str4d.xyz,mainnet.seeder.zfnd.org,mainnet.is.yolo.money
BEDROCK_P2P_PEERS=1.2.3.4:8233
BEDROCK_P2P_MAX_PEERS=8
BEDROCK_P2P_EVENT_LOG=/var/log/bedrock/zcash-p2p-ingress.jsonl
BEDROCK_P2P_RELAY_PEERS=10.40.0.3:8333
BEDROCK_P2P_RELAY_AUTH_KEY_HEX=<64 hex chars>
```

The FORGE bridge is disabled unless both `BEDROCK_P2P_RELAY_PEERS` and
`BEDROCK_P2P_RELAY_AUTH_KEY_HEX` are configured.
