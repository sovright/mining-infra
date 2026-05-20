# Z15 Pro Harness Engineer Runbook

This runbook is the remote engineer's view of the Z15 Pro bench. It picks up
after the site operator finishes their handoff per
[`bedrock-z15-bench/docs/site-operator-runbook.md`](https://github.com/sovright/bedrock-z15-bench/blob/main/docs/site-operator-runbook.md).

**Pre-conditions** (operator has confirmed):

- Jump host is reachable on Tailscale, tagged `tag:z15-bench`.
- ASIC is on the isolated subnet (`192.168.8.50`) and powered, with stock
  Bitmain firmware, NTP set, password changed.
- `/opt/bedrock/bin/{zcash-pool-server,bedrock-v1-proxy,zcash-test-miner}`
  are installed and a release tag is recorded in `/etc/bedrock/release.tag`.
- Three systemd units are installed and disabled.
- Pool / worker configuration on the ASIC web UI is untouched.

The site operator does **not** do anything in this runbook — it's all you.

---

## 1. Reach the jump host

The bench tailnet is `tail7e789b.ts.net` under the "bootstrap" Tailscale
account. You should be tagged `tag:bench-engineer` or `tag:bench-admin`.

```bash
tailscale status                                # confirm you see bedrock-bench-01
ssh zaki@bedrock-bench-01                       # MagicDNS short name
# or, fully qualified:
ssh zaki@bedrock-bench-01.tail7e789b.ts.net
```

If `ssh` fails:
- Check the operator's handoff doc for the exact tailnet hostname.
- Confirm your tailnet account is tagged `tag:bench-engineer` (admin console).
- Check that `verify.sh` PASSed on the operator's handoff — if not, the
  jump host is not ready and you should pause before going further.

---

## 2. Configure the harness stack

The provision script ships the binaries but not the configs. You drop these
in once and they persist across restarts.

### 2.1 Pool config

```bash
sudo mkdir -p /etc/bedrock
sudo tee /etc/bedrock/pool.toml > /dev/null <<'EOF'
listen_addr = "0.0.0.0:3333"
zebra_url   = "http://127.0.0.1:8232"
nonce_1_len = 4
initial_difficulty = 32
target_shares_per_minute = 5.0
# Noise OFF for first bring-up — re-enable in §7.5 of the harness reference.
EOF
```

### 2.2 Proxy config

```bash
sudo tee /etc/bedrock/proxy.toml > /dev/null <<'EOF'
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
level = "debug"
EOF
```

### 2.3 Test miner config (parity baseline)

```bash
sudo tee /etc/bedrock/test-miner.toml > /dev/null <<'EOF'
pool_addr     = "127.0.0.1:3333"
worker_prefix = "sim"
EOF
```

### 2.4 Zebra

Zebra is **not** preinstalled by `provision.sh`. You install it yourself, on
the jump host, configured to listen on `127.0.0.1:8232`. Use the upstream
binary from the Zebra release page. Sync from scratch takes ~1 day on a
residential gigabit link; you may opt to skip Zebra entirely if a smoke-only
run is all you need (use `zcash-test-miner --v1` to drive the proxy).

---

## 3. Start the stack

```bash
sudo systemctl enable --now bedrock-pool.service
sudo systemctl enable --now bedrock-v1-proxy.service
journalctl -u bedrock-pool.service -u bedrock-v1-proxy.service -f
```

Wait until you see `accepted miner connection` from the proxy and a
`NewEquihashJob` going out.

### Smoke-test with the simulated V1 client first

Before pointing the ASIC at the proxy, prove the path works end-to-end with
`zcash-test-miner --v1`:

```bash
/opt/bedrock/bin/zcash-test-miner --pool-addr 127.0.0.1:3334 --v1 \
  --worker-prefix sim
```

Expect: `mining.subscribe` → `mining.set_target` → `mining.notify` → at
least one `mining.submit` accepted within ~2 minutes. **Do not configure
the ASIC against the proxy until this passes.**

---

## 4. Point the ASIC at the proxy

You configure the ASIC web UI by tunneling its HTTP port over SSH back to
your laptop:

```bash
ssh -L 8080:192.168.8.50:80 zaki@bedrock-bench-01
# Browser → http://localhost:8080/
```

Log in with the ASIC password stored in the shared vault.

Open **Miner Configuration** and fill in the three pool slots:

| Slot | URL | Worker | Password |
|---|---|---|---|
| Pool 1 (primary — DUT) | `stratum+tcp://192.168.8.10:3334` | `t1YourZcashAddress.z15pro-1` | `x` |
| Pool 2 (proxy backup) | `stratum+tcp://192.168.8.10:3334` | `t1YourZcashAddress.z15pro-1-bak` | `x` |
| Pool 3 (escape hatch) | leave the existing prod pool URL | existing worker | existing password |

The Z15 Pro **always fills all three slots**; some firmware revisions throw
a validation error if any is blank.

Click **Save & Apply**. The miner reboots its mining process (~10 s). Watch
the proxy log; you should see `mining.subscribe`, `mining.authorize` from
the ASIC within seconds.

---

## 5. Verify on the ASIC's own dashboard

Via the SSH tunnel from §4, in **Miner Status / Dashboard** check after
~2 minutes:

| Field | Expected |
|---|---|
| Pool 1 status | `Alive` |
| Pool 1 Getworks | incrementing |
| Pool 1 Accepted | > 0 |
| Pool 1 Rejected | 0 (a handful during vardiff warmup is OK) |
| GH/S (5s) | climbing toward 840 ksol/s |
| Board temps | < 80 °C inlet, < 95 °C chip |
| Fan speeds | all four > 3000 RPM |

If any fail, see [`z15-pro-test-harness.md` §6 troubleshooting](z15-pro-test-harness.md).

---

## 6. Execute the test cases

See [`z15-pro-test-harness.md`](z15-pro-test-harness.md) for the full
matrix (T1–T14) and acceptance criteria.

For first bring-up, run the **smoke profile** (T1, T2, T4, T5, T10). Record
results in `runs/<date>-z15pro/results.csv`.

For a green-light run, execute the full matrix including the 24-hour soak
(T13) and the Noise pass (T14).

---

## 7. Observability

- Proxy metrics: `curl http://127.0.0.1:9334/metrics`
- Pool metrics: `curl http://127.0.0.1:9090/metrics`
- Logs: `journalctl -u bedrock-pool.service -u bedrock-v1-proxy.service -f`
- Packet capture (V1 side): `sudo tcpdump -i any -w /tmp/v1.pcap 'tcp port 3334'`
- ASIC telemetry: SSH tunnel to the web UI as in §4 and read **Miner Status**.

For Prometheus + Grafana scraping over Tailscale, expose the metrics ports
to the tailnet only (firewall on the jump host blocks them from the LAN by
default — re-confirm if you change it).

---

## 8. Operational notes

- **Restarting the ASIC**: requires the site operator to be physically
  present. There is no remote PDU. Coordinate via the ClickUp task.
- **Restarting the second router**: same — needs operator.
- **Restarting the jump host or any service on it**: you can do that
  remotely.
- **Site safety**: do not run unattended overnight in the first week.
  See [`z15-pro-test-harness.md` §9](z15-pro-test-harness.md) for the
  full safety rules.

---

## 9. Tear-down

When the harness run is complete:

1. `sudo systemctl disable --now bedrock-pool.service bedrock-v1-proxy.service bedrock-test-miner.service`
2. Log into the ASIC web UI (via SSH tunnel) and reset Pool 1 to the prod
   pool URL from Pool 3 — so the ASIC keeps producing for the existing
   pool even after we stop running the bench harness against it.
3. Push the run artifacts (`runs/<date>-z15pro/`) to the bedrock repo.
4. Comment on the ClickUp task with the run result and a link to the
   results bundle.

Hardware stays in situ unless we explicitly retire the bench.
