# NU7 activation fixture

`testnet_nu7_4465026.hex` is the unmodified public-testnet activation block.
Its metadata freezes the consensus block hash, raw-byte SHA-256, transaction
sizes, and `getblock` verbosity-2 txid/authdigest results from both pinned clients.
The raw block was also retrieved by public P2P `getdata`; its SHA-256 matches the
bytes accepted by Zebra in the earlier controlled activation replay. Public
fixture provenance contains no private host inventory or operational endpoints.

The block contains a v6 coinbase with one Ironwood action and a non-coinbase v5
transaction. Tests compare each transaction's digest against both node oracles
and reconstruct the exact raw bytes through all-prefilled, cached compact and
skeleton paths. Missing receiver cache data must first report incomplete.

The v6 coinbase remains prefilled: short-ID resolution here exercises only the
v5 transaction. This is not general shielded-transaction, relay transport,
FEC/recovery, or submission-path qualification. The two clients share code
ancestry; matching RPC digests are not independent cryptographic implementations.

## Transport qualification

`real_nu7_authenticated_udp_reaches_sidecar_candidate` sends this fixture through
an authenticated loopback relay with production Equihash validation, 10+3 FEC,
and full-prefill compact reconstruction. It verifies byte-exact sidecar output
without submitting. This does not simulate packet loss or qualify cached/skeleton
transport, sustained load, or all testnet difficulty targets.

The ignored `live_nu7_authenticated_transport_submission` test requires explicit
`NU7_TEST_RAW_BLOCK` (hex file), `NU7_TEST_RAW_SHA256`, and `NU7_TEST_RPC_PORT`
(loopback RPC). It refuses any chain except `test` with active NU7, a known block,
or a block that does not extend the observed tip. Run only against an isolated
qualification node and a canonical block independently obtained from a reference
node. It performs one real submission and requires canonical acceptance; do not
retry an ambiguous RPC outcome without checking the node first.

```sh
cargo +1.99.0 test -p sovright-p2p-ingress --locked \
  live_nu7_authenticated_transport_submission -- --ignored --nocapture
```

These tests do not change the production testnet-output prohibition. The relay's
stateless target bound is the mainnet limit, not the larger testnet limit; full
nodes remain responsible for contextual difficulty and consensus validation.
