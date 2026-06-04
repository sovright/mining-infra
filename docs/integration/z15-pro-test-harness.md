# Z15 Pro Test Harness — Stratum V1 ↔ V2 Proxy Validation

End-to-end harness for validating the `bedrock-v1-proxy` against a real Bitmain
Antminer Z15 Pro. The Z15 Pro speaks Stratum V1 (ZIP 301) only; this harness
proves the proxy correctly bridges it to the Bedrock V2 pool, with side-by-side
parity against a native V2 test miner.

---

## 1. Hardware Under Test

| Item | Spec |
|---|---|
| Model | Bitmain Antminer Z15 Pro |
| Algorithm | Equihash (200,9) — ZEC / ZEN |
| Nominal hashrate | 840 ksol/s |
| Efficiency | ~3.31 J/ksol |
| Power (on-wall, 25 °C) | ~2650–2780 W |
| Power supply | Integrated APW12; dual C13/C14 inlets on the rear |
| Input voltage | 200–240 V AC required (no 110 V operation) |
| Dimensions / weight | 428 × 195 × 290 mm, ~16.9 kg |
| Network | 100 Mbit Ethernet (RJ45), no Wi-Fi |
| Acoustic | ~75 dB at 25 °C |
| Stratum protocol | V1 / JSON-RPC over TCP (ZIP 301 dialect) |
| Firmware | Stock Bitmain. No V2 firmware exists. Record exact firmware date from *System → Overview*. |

### Site requirements (full harness)

These apply to the full §6 test pass — especially the 24 h soak (T13). For a
short integration smoke test see [§1.1 Bench smoke profile](#11-bench-smoke-profile-relaxed-requirements)
below; most of these can be relaxed.

- **Circuit**: dedicated 230 V / 30 A (NEMA L6-30 or IEC equivalent) with at
  least 3.5 kW headroom on the breaker. Don't share the circuit with other
  miners or office gear.
- **PDU**: must provide **two** C13 outlets (one per PSU inlet). Use a
  metered/switched PDU so we can remote-kill the unit (§9).
- **Power cords**: two C13–to–PDU-outlet cords rated ≥15 A. Both inlets must
  be energised; the Z15 Pro will not start on a single PSU input.
- **Cooling**: front-to-back airflow, intake ≤30 °C, ≥1 m clearance behind for
  exhaust. Plan for ~9000 BTU/h of heat rejection.
- **Acoustic isolation**: 75 dB sustained — do not co-locate with humans.
- **Network**: dedicated VLAN/subnet for the test harness. We want to mirror
  traffic without polluting prod and we want a clean firewall boundary.

---

## 1.1 Bench smoke profile (relaxed requirements)

For a **short integration check** (≤30 min powered, just enough to prove the
software stack talks to a real ASIC), you do **not** need the full site setup.
Use this profile to get a yes/no answer on integration before committing to
rack space and a dedicated circuit.

### What the smoke test is for

- Confirm `bedrock-v1-proxy` correctly handshakes with a real Z15 Pro, not
  just `zcash-test-miner --v1`.
- Confirm field encoding (ZIP 301) survives real firmware (Bitmain's JSON
  parser is fussier than ours).
- Confirm at least one real share round-trips: ASIC → proxy → pool → accept.

### What the smoke test is **not** for

- 24 h stability (T13) — needs the full thermal/electrical setup.
- Vardiff convergence at steady state (T6) — needs the unit at full hashrate
  long enough to settle; partial OK in 30 min but don't draw conclusions.
- Block-found path (§5.6, §8) — use regtest instead, not bench hardware.
- Anything you'd cite as "the proxy is production-ready."

### Relaxed requirements

| Full harness | Smoke profile | Notes |
|---|---|---|
| Dedicated 230 V / 30 A circuit with 3.5 kW headroom | Any 230 V outlet on a 15 A+ circuit (~12 A draw) | Don't share with other heavy loads. |
| 110 V SKU unsupported | Still unsupported | If your lab is 110 V only, **skip the ASIC** and run §1.2 software-only profile. |
| Two C13 outlets on a metered/switched PDU | One 230 V outlet + a passive C13 splitter is acceptable | The dual inlets are for current sharing, not redundancy — a splitter on one circuit is electrically fine. **Both inlets must still be energised.** |
| Remote-switchable PDU (kill switch) | A reachable power strip with a physical switch | Someone must be present for the entire smoke run. |
| Front-to-back airflow, ≤30 °C intake, 1 m exhaust clearance | Open room, table-top, exhaust pointed at an open window or doorway | The chassis thermal protection will throttle before damage on a 30 min run. |
| 9000 BTU/h cooling budget | None — let the room absorb it | Don't smoke-test in a closed closet. |
| 75 dB acoustic isolation | Foam earplugs for anyone in the room | Don't stand next to it for >10 min unprotected. |
| Dedicated VLAN with traffic mirroring | Any switch on the same subnet as your dev box | Skip the span port; rely on proxy/pool logs + a single-side `tcpdump` if needed. |
| DHCP reservation | Note the IP it grabs, hard-code it for the run | No need to touch the router config. |

### Smoke profile test selection

Run only these from §6:

| # | Why |
|---|---|
| T1 | Cold start handshake — does the ASIC reach the proxy at all. |
| T2 | First share accepted — proves end-to-end happy path on real hardware. |
| T4 | Field encoding (one captured `mining.notify` decoded by hand) — catches ZIP 301 regressions cheaply. |
| T5 | Solution prefix tolerance — the Z15 Pro's actual byte layout. |
| T10 | ASIC link flap — fast, doesn't need the full thermal envelope. |

Skip T3, T6, T7, T8, T9, T11, T12, T13, T14 in smoke mode; defer to the full
harness.

### Smoke profile exit criteria

- T1, T2, T4, T5, T10 all PASS.
- Proxy did not panic.
- ASIC dashboard shows at least one accepted share (§4.11).
- Save the proxy log and one `mining.notify` hex dump in
  `runs/<date>-z15pro-smoke/` — that's it, no formal artifact bundle required.

A green smoke result authorizes scheduling the full harness. It does **not**
authorize shipping anything.

---

## 1.2 Software-only profile (no ASIC at all)

If you don't have hardware available, want to iterate quickly on the proxy,
or your lab is 110 V only:

- Run §4.1–§4.5 (build + Zebra + pool + proxy + `zcash-test-miner --v1`).
- That single command exercises the full V1↔V2 translation path with
  CPU-generated Equihash solutions.
- Covers T1, T3, T4, T7, T8, T9, T11, T12 end-to-end. It does **not** cover
  T2/T5/T6/T10 (those need real ASIC firmware behaviour) or T13/T14.
- Useful as the inner-loop CI check; not a substitute for the bench smoke
  before any hardware-dependent claim.

---

## 2. Topology

```
                                          ┌──────────────────────┐
                                          │  Zebra full node     │
                                          │  RPC :8232           │
                                          └──────────┬───────────┘
                                                     │ getblocktemplate
                                                     ▼
┌──────────────┐ V1 JSON-RPC  ┌──────────────────┐ V2 binary ┌──────────────────┐
│ Z15 Pro ASIC │ ───────────► │ bedrock-v1-proxy │ ────────► │ zcash-pool-server│
│  (DUT)       │   :3334      │  (translator)    │  :3333    │  (upstream)      │
└──────────────┘              └──────────────────┘           └────────┬─────────┘
                                                                      │ submitblock
                                                                      ▼
                                                            (Zebra, same node)

       ┌──────────────────┐ V2 binary
       │ zcash-test-miner │ ─────────────────────────────────────────►  (parity baseline)
       │  (CPU, native V2)│   :3333
       └──────────────────┘

Observability:
  - proxy /metrics  :9334
  - pool   /metrics :9090  (bedrock-strata)
  - tcpdump on span port between ASIC and proxy
  - tcpdump on loopback between proxy and pool
```

All four host processes (Zebra, pool, proxy, test-miner) run on a single Linux
box for the first pass; split across hosts once the single-box run is green.

---

## 3. Software Versions to Pin

| Component | Source | Pin |
|---|---|---|
| Zebra | upstream | `v2.x` mainnet build, synced past NU6 |
| `zcash-pool-server` | this repo | current `main` SHA recorded in run log |
| `bedrock-v1-proxy` | this repo | same SHA |
| `zcash-test-miner` | this repo | same SHA |
| Z15 Pro firmware | Bitmain | record exact version from web UI |

Record all SHAs in `runs/<date>-z15pro/manifest.txt` at the start of every run.

---

## 4. Bring-up Sequence

> **Role split (May 2026).** Bring-up is now divided across two role-specific
> runbooks; this section is kept as the technical reference behind them.
>
> - **Site operator** (Singapore on-site): follow
>   [`bedrock-z15-bench/docs/site-operator-runbook.md`](https://github.com/sovright/bedrock-z15-bench/blob/main/docs/site-operator-runbook.md).
>   That doc supersedes §4.6 (physical bring-up), §4.7 (find IP), §4.8 (first
>   login), and §4.9 (network hardening) below. It hands off when the jump
>   host is reachable on Tailscale and the ASIC sits on an isolated subnet
>   with stock firmware and a hardened web UI.
> - **Harness engineer** (remote, post-handoff): follow
>   [`z15-pro-harness-engineer-runbook.md`](z15-pro-harness-engineer-runbook.md).
>   That doc supersedes §4.10 (configure pools) and §4.11 (verify on
>   dashboard) below, and incorporates §4.1–§4.5 via the
>   `sovright/bedrock-z15-bench` provision script.
>
> Read on if you want the underlying detail (manual build commands, exact
> JSON for the proxy/pool configs, fallback procedures). For day-to-day
> operation use the two role runbooks.

### 4.1 Build

```bash
cargo build --release -p zcash-pool-server
cargo build --release -p bedrock-v1-proxy
cargo build --release -p zcash-test-miner
```

### 4.2 Start Zebra

Already provisioned. Confirm:

```bash
curl -s -u user:pass -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}' \
  http://127.0.0.1:8232 | jq .result.blocks
```

Must return current tip and `verificationprogress ≈ 1.0`.

### 4.3 Start the pool server

`configs/pool.toml`:

```toml
listen_addr = "0.0.0.0:3333"
zebra_url   = "http://127.0.0.1:8232"
nonce_1_len = 4
initial_difficulty = 32
target_shares_per_minute = 5.0
# Noise OFF for first bring-up — re-enable in §7.5
```

```bash
cargo run --release --example run_pool -p zcash-pool-server -- --config configs/pool.toml
```

### 4.4 Start the V1 proxy

`configs/proxy.toml`:

```toml
[proxy]
listen   = "0.0.0.0:3334"
upstream = "127.0.0.1:3333"

[proxy.timeouts]
upstream_connect       = 10
upstream_reconnect_max = 60
miner_idle             = 600

[metrics]
enabled = true
listen  = "0.0.0.0:9334"

[logging]
level = "debug"   # debug for bring-up, info for steady-state
```

```bash
./target/release/bedrock-v1-proxy --config configs/proxy.toml
```

### 4.5 Smoke-test the proxy with the simulated V1 client first

Before plugging in the ASIC, prove the path works with `zcash-test-miner --v1`:

```bash
./target/release/zcash-test-miner --pool-addr 127.0.0.1:3334 --v1 --worker-prefix sim
```

Expect: `mining.subscribe` → `mining.set_target` → `mining.notify` → at least one
`mining.submit` accepted within ~2 minutes. **Do not connect the Z15 Pro until
this passes.**

### 4.6 Z15 Pro physical bring-up

Do this **once**, before touching any pool config, with the unit on the bench
next to its eventual rack position.

1. **Unbox & inspect**. Verify both hash boards are seated, no shipping damage
   to the PSU module or fans. Confirm the model sticker reads "Z15 Pro" and
   record the serial number into `manifest.txt`.
2. **Rack**. Front intake faces cold aisle. Leave ≥1 m exhaust clearance.
3. **Ground**. The chassis must be bonded to rack ground via the PDU.
4. **Network first, power second.** Plug an Ethernet cable from the test VLAN
   switch into the RJ45 port on the controller board. The link LED on the port
   should light immediately if the switch is up — useful sanity check before
   power.
5. **Power**. Plug **both** C13 cords into the rear PSU inlets, then into two
   separate outlets on the PDU. Energise. Fans should ramp to full for ~30 s
   then settle. The unit beeps once on successful POST.
6. **Wait ~2 minutes** for the controller to boot and grab a DHCP lease.

### 4.7 Find the miner's IP

Three options, in order of preference:

| Method | How |
|---|---|
| **IP Reporter** (preferred) | Run Bitmain's "IP Reporter" utility on a laptop on the same L2. Press the recessed *IPReport* button on the Z15 Pro controller board for ~1 s. The utility window pops up with IP + MAC. |
| **DHCP lease table** | Check the test VLAN's DHCP server / router admin UI for a new lease with OUI `Bitmain`. |
| **Subnet scan** | `nmap -sn 192.0.2.0/24` (or `arp -a` after a broadcast ping) — slowest, use as fallback. |

Assign a **DHCP reservation** for that MAC immediately so the IP is stable
across the harness run. Record IP + MAC in `manifest.txt`.

### 4.8 First login & firmware check

Browse to `http://<miner-ip>/`. Default credentials:

| Field | Value |
|---|---|
| Username | `root` |
| Password | `root` |

You will be forced to change the password on first login on recent firmware.
Set a strong password and stash it in the lab password manager (do **not**
commit it).

Go to **System → Overview** and record:

- Firmware build date
- Kernel version
- Hash board count (should be 3) and per-board status (all "OK")
- Fan RPMs (4 fans, all spinning)

If the firmware is more than ~6 months stale, update via **System → Upgrade**
using a signed image downloaded from Bitmain's support site. **Do not** flash
third-party firmware (Vnish, Braiins, etc.) for this harness — we are testing
the proxy against stock V1 behaviour.

### 4.9 Network hardening (do before pool config)

In **System → Administration / Network**:

- Set a static IP **or** keep DHCP with the reservation from §4.7.
- Set NTP to a reachable server (the pool/Zebra time must agree within a
  couple of seconds or stale-share rates will be misleading).
- Disable any "Bitmain remote management" / cloud features.
- Change the SSH password if SSH is enabled; otherwise disable SSH.

### 4.10 Configure pools to point at the proxy

In **Miner Configuration** (some firmware revisions label this *Miner Setting*
or *Pool*) you'll see **three pool slots**, each with three fields. Fill them
as follows:

| Slot | URL | Worker | Password |
|---|---|---|---|
| Pool 1 (primary — DUT) | `stratum+tcp://<proxy-host>:3334` | `t1YourZcashAddress.z15pro-1` | `x` |
| Pool 2 (proxy backup) | `stratum+tcp://<proxy-host>:3334` | `t1YourZcashAddress.z15pro-1-bak` | `x` |
| Pool 3 (escape hatch) | **leave the unit's existing production pool URL** | existing worker | existing password |

Notes:

- **Worker format** is mandatory `wallet.workername`. The Z15 Pro will refuse
  to authorize otherwise on most pools; our proxy is lenient but keep the
  format consistent for downstream metrics.
- The Z15 Pro **always fills all three slots**; if you leave a slot blank
  some firmware revisions throw a validation error. Hence Pool 2 = same proxy
  with a `-bak` worker (gives us a clean way to see failover engage in proxy
  logs) and Pool 3 = the prod pool as an overnight safety net (§9).
- The URL must include `stratum+tcp://`. The Z15 Pro **does not** support
  `stratum+ssl://` or `stratum+noise://`; this is exactly why we need the
  proxy.
- Click **Save & Apply**. The miner reboots its mining process (not the whole
  controller — ~10 s). Watch the proxy log: you should see a TCP accept,
  then `mining.subscribe`, `mining.authorize`, within seconds.

### 4.11 Verify on the ASIC's own dashboard

In **Miner Status / Dashboard** check, in order:

| Field | Expected after ~2 min |
|---|---|
| Pool 1 status | `Alive` |
| Pool 1 Getworks | incrementing |
| Pool 1 Accepted | > 0 |
| Pool 1 Rejected | 0 (a handful is acceptable during vardiff warmup) |
| GH/S (5s) | climbing toward 840 ksol/s |
| Board temps | < 80 °C inlet, < 95 °C chip |
| Fan speeds | all four > 3000 RPM |

If any of those fail, **stop and diagnose before running the test cases in
§6** — they assume a healthy ASIC.

---

## 5. What "Working Correctly" Means

The proxy is correct iff **every** acceptance criterion below holds.

### 5.1 Handshake & subscription

- ASIC's `mining.subscribe` returns a 2-element result: `[[["mining.notify", session_id]], nonce1_hex]`.
- `nonce1_hex` length matches `nonce_1_len` from the pool config (4 bytes → 8 hex chars).
- `mining.authorize` returns `true`.
- `mining.extranonce.subscribe` returns `true`.

Verify in proxy logs at `debug` and via tcpdump of the V1 socket.

### 5.2 Job translation (V2 → V1)

For each `NewEquihashJob` from the pool, the ASIC must receive a `mining.notify`
where, per ZIP 301:

- `job_id` is a string (decimal of the V2 u32).
- `version` is **hex** (4-byte little-endian → 8 hex chars).
- `prevhash`, `merkle_root`, `hash_reserved` are **big-endian** hex.
- `ntime`, `nbits` are 4-byte hex.
- `clean_jobs` flag follows the V2 future/clean semantics.

### 5.3 Target translation

Every `SetTarget` from the pool yields **both** `mining.set_target` (BE hex) and
`mining.set_difficulty` (float) to the ASIC. The Z15 Pro firmware needs at
least one of these to adjust; sending both is required for compatibility.

### 5.4 Share submission (V1 → V2)

For each `mining.submit` from the ASIC:

- `nonce_2` is parsed as hex; total nonce length is `nonce_1_len + nonce_2_len == 32`.
- `solution` is 1344 bytes after stripping the optional `fd 40 05` compactSize prefix.
- `ntime` parses as a u32.
- A matching `SubmitEquihashShare` reaches the pool with the correct `channel_id`,
  `sequence`, and `job_id`.
- The pool's `SubmitSharesResponse` is mapped back to the V1 JSON-RPC response
  using the original request `id`, with `true` for accept and `false` plus error
  string for reject.

### 5.5 Vardiff

Within ~10 minutes, the per-channel difficulty converges to a value that
produces ≈5 shares/min from the Z15 Pro. Confirm by:

- proxy `proxy_v1_set_difficulty_sent_total` counter increasing,
- pool's vardiff metric for that channel settling,
- ASIC's accepted share rate (from its own UI) ≈ target.

### 5.6 Block found path

On at least one accepted block-difficulty share during the run:

- Pool calls Zebra's `submitblock`,
- Zebra returns `null` (accepted) or `"duplicate"`,
- ASIC receives `mining.notify` with `clean_jobs=true` within one job cycle.

If we don't get lucky on testnet/mainnet during the run, force the path by
pointing at regtest (see §8).

### 5.7 Reconnect & resilience

- Kill the pool process. Proxy must log upstream loss, the ASIC's V1 socket must
  stay open, and on pool restart the proxy reconnects within
  `upstream_reconnect_max` and sends a fresh `mining.set_extranonce` if
  `nonce_1` changed.
- Kill the proxy. ASIC reconnects to proxy on next retry cycle; no shares lost
  beyond the in-flight window.
- Unplug ASIC Ethernet for 30 s, plug back. Proxy session closes and a new one
  opens cleanly.

### 5.8 Long-soak parity

24 h continuous run, side-by-side with `zcash-test-miner` (V2 native) pointed at
the same pool. Compare:

- accepted / rejected / stale ratios within ±1 % normalized for hashrate,
- no proxy panics, no leaked sockets (`ss -tnp | grep proxy | wc -l` stays
  bounded by active session count + small ε),
- proxy RSS stable (< 50 MB drift).

---

## 6. Test Cases

| # | Name | Procedure | Pass criteria |
|---|---|---|---|
| T1 | Cold start handshake | Boot all four services in order §4. | Z15 reaches "Mining" state in its UI within 60 s. |
| T2 | First share accepted | Wait after T1. | Pool log shows `share_accepted` for the Z15 channel within 5 min. |
| T3 | Job freshness | Tail proxy log. | Median delta between V2 `NewEquihashJob` rx and V1 `mining.notify` tx ≤ 5 ms. |
| T4 | Field encoding | Capture one `mining.notify` via tcpdump; decode by hand. | `version` is 8-hex-char LE, hashes are BE hex, lengths match §5.2. |
| T5 | Solution prefix tolerance | Force ASIC to submit; capture `mining.submit`. | Proxy accepts both 1344- and 1347-byte forms (the 1347 form starts with `fd4005`). |
| T6 | Vardiff convergence | Run 15 min from cold start. | Difficulty stabilizes; share rate within ±20 % of `target_shares_per_minute`. |
| T7 | Reject path | Submit a known-bad share (use `zcash-test-miner --v1` with a mangled solution; the Z15 should not be tampered with). | Pool rejects; proxy maps to `false` with error string on the original V1 `id`. |
| T8 | Pool restart | `kill -TERM` pool, restart 30 s later. | Proxy auto-reconnects; ASIC sees new `mining.set_extranonce` if `nonce_1` changed; mining resumes ≤ 90 s. |
| T9 | Proxy restart | `kill -TERM` proxy, restart 10 s later. | ASIC reconnects on its own retry; new session established; no firmware reboot required. |
| T10 | ASIC link flap | Unplug RJ45 for 30 s. | Old session drains/closes in proxy logs; new session opens on replug. |
| T11 | Idle timeout | Send `mining.subscribe` then nothing (use `nc` separately). | Proxy closes V1 socket after `miner_idle` elapses. |
| T12 | Metrics scrape | `curl :9334/metrics` and `:9090/metrics`. | Both return 200, expose session counts, shares-accepted, shares-rejected, reconnect counters. |
| T13 | 24 h soak | Leave Z15 + test-miner running side-by-side for 24 h. | §5.8 criteria all hold. |
| T14 | Noise enabled | Re-run T1–T6 with Noise keys configured (§7.5). | All identical results, plus successful Noise handshake on V2 upstream. |

Each test case gets its own row in `runs/<date>-z15pro/results.csv` with PASS,
FAIL, or SKIP and a short note.

---

## 7. Observability

### 7.1 Logs

- `bedrock-v1-proxy` at `debug` during bring-up. Filter by session id for any
  individual miner.
- `zcash-pool-server` at `info`, `debug` for the `share`, `vardiff`, and
  `template` targets.
- Ship both to a single `journalctl` instance (or `tee` to file) so timestamps
  line up.

### 7.2 Metrics (Prometheus)

Scrape both `:9334` (proxy) and `:9090` (pool). Minimum dashboard panels:

- Active V1 sessions, active V2 upstream connections (should match 1:1).
- Shares submitted / accepted / rejected per channel.
- Job translation latency histogram.
- Upstream reconnect counter (alert on > 0 in steady state).
- Per-channel vardiff target over time.

### 7.3 Packet captures

```bash
# V1 side (ASIC ↔ proxy)
sudo tcpdump -i <ASIC-facing-iface> -w runs/<date>-z15pro/v1.pcap 'tcp port 3334'

# V2 side (proxy ↔ pool), on loopback if same host
sudo tcpdump -i lo -w runs/<date>-z15pro/v2.pcap 'tcp port 3333'
```

Rotate captures hourly (`-G 3600 -W 24`). Keep at least the first hour and any
hour containing a fault.

### 7.4 ASIC-side telemetry

Z15 Pro web UI → *Miner Status* every 10 min: hashrate (avg / 1 m / 15 m),
accepted, rejected, hardware errors, fan RPM, board temps. Log into CSV.

### 7.5 Noise encryption pass

After §6 T1–T13 pass without Noise, enable Noise on the **V2 upstream only**
(the Z15 Pro cannot speak Noise on the V1 side — that hop stays plaintext
inside the trusted LAN). Set `noise_*` keys in `pool.toml`, regenerate static
keypair, restart pool. The proxy currently connects to the pool without Noise;
if/when proxy-side Noise lands, re-run T14 with both legs encrypted.

---

## 8. Forcing a Block-Found Event

Mainnet hashrate makes block discovery via a single Z15 Pro statistically
unlikely during a short run. To exercise §5.6 deterministically, run Zebra in
**regtest** mode on a side machine:

1. `zebrad --network=Regtest` with mining keys configured.
2. Pool config → point `zebra_url` at the regtest node.
3. Set pool `initial_difficulty` very low (e.g. 1).
4. The Z15 Pro will find blocks within minutes. Verify `submitblock` accept,
   `clean_jobs` propagation, and chain tip advance via
   `zebra-cli getblockchaininfo`.

Do **not** run regtest on the same node as a mainnet Zebra; use separate data
directories and ports.

---

## 9. Safety & Operations

- **Kill switch**: **both** PDU outlets feeding the Z15 Pro must be
  remote-switchable, and the kill action must drop both simultaneously
  (single-PSU operation is unsupported and can damage the unit). Never run
  unattended on the first night.
- **Thermal trip**: configure the PDU or rack environmental monitor to cut
  power if intake air exceeds 35 °C — the Z15 Pro will happily cook itself
  before its own thermal protection kicks in if airflow is restricted.
- **Wallet**: use a dedicated transparent address whose key lives on an offline
  machine; the address only collects PPS payouts during the harness run.
- **Firewall**: proxy `:3334` exposed only on the test VLAN. Metrics ports
  bound to `127.0.0.1` or behind WireGuard.
- **Backout**: if anything looks wrong, point Pool 1 on the Z15 back to the
  existing production pool URL from the unit's previous config — the fallback
  pool slots make this a single web-UI change.

---

## 10. Run Artifact Layout

```
runs/<YYYY-MM-DD>-z15pro/
├── manifest.txt              # git SHAs, firmware versions, operator, start/stop times
├── configs/
│   ├── pool.toml
│   └── proxy.toml
├── logs/
│   ├── zebra.log
│   ├── pool.log
│   ├── proxy.log
│   └── test-miner.log
├── pcaps/
│   ├── v1-*.pcap
│   └── v2-*.pcap
├── metrics/
│   └── prom-snapshots/       # hourly snapshots of /metrics
├── asic-telemetry.csv
├── results.csv               # one row per test case
└── notes.md                  # freeform observations, anomalies, follow-ups
```

Commit this directory (without pcaps if they're large — store those out-of-band
with a SHA-256 manifest committed in-tree) so the run is reproducible and
reviewable.

---

## 11. Exit Criteria

The harness run is **complete and passing** when all of:

- T1–T14 are PASS,
- 24 h soak (T13) shows < 0.5 % unexplained reject rate above the test-miner
  baseline,
- No proxy panics, no upstream reconnect storms (> 1/hr steady-state),
- A signed run report is filed in `runs/<date>-z15pro/notes.md` and linked
  from the next phase planning doc.

Anything less is a regression report, not a green light.
