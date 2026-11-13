# Luxor upgrade-only qualification

Status: **partial; no production release recommendation**. Assessment date:
2026-10-07 UTC. Luxor is assumed to run the current published Sovright client;
this is the user's scope assumption, not a fresh inspection of Luxor's machines.

## Baseline and candidate

The GitHub latest release is
[relay-client-2a29ebd](https://github.com/sovright/mining-infra/releases/tag/relay-client-2a29ebd),
published September 10. Its body identifies build source
`2a29ebde863e76e3c9d87d94e2b5ce94f64cce29`. Both the local tag and GitHub tag API resolve to
`5d37ae9f4d6157dadb624e71b329727b4e161b35`, a different commit. Source comparisons
here use the release body's build source, not the tag name. Release metadata and
asset digests do not independently attest the build source. Resolve this
provenance discrepancy when producing the new release; do not repeat it.

Published Linux amd64 assets (downloaded files match GitHub SHA-256 metadata):

| Component | Asset | SHA-256 |
| --- | --- | --- |
| Receive client | `relay-sidecar-linux-amd64` | `c3a80b86dd342d4b96516196a9ef17e6a8c469a909554ee9981790fce4ea74d2` |
| Submission gateway / P2P ingress | `bedrock-p2p-ingress-linux-amd64` | `6f728f5b548e4cfad436e284598263623edf0dfbb4cfc0fd286207a622d2df53` |

Candidate source is merged commit `6a29472046614eb4f238a4c5c6e63d6d7d9d6982`.
The existing Linux qualification receipt in deployment PR #127 records:

| Candidate executable | SHA-256 |
| --- | --- |
| `relay-sidecar` | `20ffb5bace7bcbb68d11b01e2139b3d23825c21dc315b742ec25cc95577e48c2` |
| `sovright-p2p-ingress` | `e3692cbf8c75408e3db610c1c4c53b24a0cc0a00d630fe11cde87109e99e720f` |

These are qualification artifacts, not published production replacements.
The customer-facing asset names and installed paths must be preserved by release
packaging; internal Cargo binary names differ from the public asset names.

## Compatibility assessed here

| Surface | Evidence | Boundary |
| --- | --- | --- |
| Sidecar TOML | Source schema/defaults differ only in a memory-budget comment; frozen released example loads through `Config::from_file` | Does not inspect Luxor's private configuration or exercise runtime connections |
| Existing behavior switches | Regression preserves FEC 10+3, 100 ms polling, announcements on, receive/submission/gate off in the released example | Real deployments keep their existing explicit settings; the example is not a replacement configuration |
| Pool RPC | Real activation-block bytes pass the production stateless validator and existing `submitblock` JSON-RPC shape, arriving unchanged at a recording backend despite relay failure | Backend is mocked; does not prove mainnet validity, live node acceptance, timeout failover or mining-job construction |
| NU7 transport | Existing real-block tests cover authenticated local UDP/FEC, exact reconstruction, and sidecar dry-run candidate generation | Local candidate endpoints, not old/new mixed-release interoperability or a sustained Linux run |
| P2P version | Candidate mainnet selection emits 170190; testnet emits 170180 | Zcash-facing gateway behavior, not a new sidecar UDP protocol setting; protocol advertisement alone is not consensus qualification |

The released example is frozen verbatim from `2a29ebd` as
`crates/sovright-relay-sidecar/tests/fixtures/relay-client-2a29ebd.toml`.
SHA-256: `def4f75f458654b31a62cdebc9baa237b4f4e22b42a3ed18d116bb09afccbff9`.
It contains only public example values. No production credentials are requested.

## Work Sovright owns before release

1. Qualify the exact Linux sidecar and gateway against the intended deployed
   relay release, using existing configuration shapes. Exercise receive,
   compact/cache/raw fallback, pool RPC, relay timeout/unavailability, restarts
   and sustained delivery. Our separate Zebra sync diagnostic remains open.
2. Qualify the supported full-node release, template/coinbase and fee/parent
   changes, accepted solved blocks, activation and reorgs. Our sidecar does not
   construct Luxor's mining jobs. Do not promise its binary update fixes an
   incompatible pool template assembler. Any discovered pool change becomes
   an exact patch/instruction owned by Sovright, not an open-ended Luxor task.
3. Exercise 25-second cadence and burst recovery, including the gateway's
   existing four-requests-per-minute default. Do not silently tune operator
   limits or claim the average block rate proves burst capacity.
4. Pin final mainnet activation/node release, qualify diverse forwarding peers,
   and rehearse direct submission plus NU7-compatible recovery. The forwarding
   floor applies from startup, so peer availability must pass before canary.
5. Publish one checksummed package with correct source provenance and preserved
   public filenames. Supply exact service/path-aware install, restart and
   fallback commands after those details are verified; no guessed systemd unit
   or executable path belongs in the customer handoff.
6. Fill in the [one-page handoff](luxor-nu7-handoff.md), name an operator and
   window, then request only the canary installation and subsequent rolling
   update. Customer communication and mainnet rollout are separate actions.

## Reproduction

Run with Rust 1.99.0 and the candidate lockfile:

```sh
cargo test --locked -p sovright-relay-sidecar --test release_upgrade
cargo test --locked -p sovright-p2p-ingress real_nu7
cargo test --locked -p sovright-p2p-ingress submitblock_rpc::tests
```

The ignored `live_nu7_authenticated_transport_submission` test requires explicit
isolated testnet RPC and a new canonical successor; it is not run by these
ordinary test commands. Prior live evidence and remaining fleet gates are in
[deployment PR #127](https://github.com/sovright/sovright-relay-mainnet-deployment/pull/127).

Local macOS results for this change: released-config regression **1 passed**;
`real_nu7` selection **4 passed**; submitblock RPC suite **14 passed** (one test
overlaps the NU7 selection). Formatting and diff whitespace checks pass. These
are source-level checks, not execution of the Linux release assets.
