# sovright-p2p-ingress

Native Zcash P2P ingress daemon for the Sovright relay network.

This is an MVP for timing and ingress experiments. It discovers Zcash mainnet
peers, performs the P2P handshake, listens for block inventory, requests block
payloads, and logs first-seen events. Optional crawler mode learns additional
peers from `addr` gossip and rotates through a bounded peer queue.

It does not consensus-validate blocks and does not submit blocks. Use Zebra as
the validation path.

## Run

```sh
RUST_LOG=info cargo run -p sovright-p2p-ingress
```

Useful environment variables:

```text
SOVRIGHT_P2P_DNS_SEEDS=dnsseed.z.cash,dnsseed.str4d.xyz,mainnet.seeder.zfnd.org,mainnet.is.yolo.money
SOVRIGHT_P2P_PEERS=1.2.3.4:8233
SOVRIGHT_P2P_MAX_PEERS=8
SOVRIGHT_P2P_CRAWLER_ENABLED=false
SOVRIGHT_P2P_CRAWLER_MAX_KNOWN_PEERS=5000
SOVRIGHT_P2P_CRAWLER_MAX_ADDR_PER_MESSAGE=1000
SOVRIGHT_P2P_CRAWLER_DRAIN_INTERVAL_SECS=5
SOVRIGHT_P2P_EVENT_LOG=/var/log/bedrock/zcash-p2p-ingress.jsonl
SOVRIGHT_P2P_RELAY_PEERS=10.40.0.3:8333
SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX=<64 hex chars>
```

When crawler mode is enabled, the daemon still only makes outbound Zcash P2P
connections. It does not open an inbound listener, submit blocks, or forward to
FORGE unless the separate FORGE bridge settings are configured.

Measurement events include `p2p_connect_timing`, `p2p_handshake_timing`,
`p2p_ping_rtt`, `p2p_block_inv`, `p2p_getdata_sent`, and
`p2p_block_received`. These events are advisory telemetry only; crawler mode
does not rotate connections by score yet.

The FORGE bridge is disabled unless both `SOVRIGHT_P2P_RELAY_PEERS` and
`SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX` are configured.
`SOVRIGHT_P2P_RELAY_DATA_SHARDS` and `SOVRIGHT_P2P_RELAY_PARITY_SHARDS`
override the default `10+3` FEC profile for relay traffic; they must match the
relay daemon and receiving sidecar.
