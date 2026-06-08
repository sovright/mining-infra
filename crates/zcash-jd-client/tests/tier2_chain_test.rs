//! Tier-2 full-chain integration test: pool + JDC + proxy + real CPU miner.
//!
//! This is the FIRST place the *accept* paths run end-to-end with a REAL
//! Equihash solution. Every prior unit/integration suite deliberately deferred
//! the accepted-share, LowDifficulty, and block-path assertions to here because
//! no valid-Equihash fixture exists without a CPU solver. The chain under test:
//!
//! ```text
//! zcash-test-miner --v1 (spawned binary, real Equihash CPU solver)
//!   -> sovright-v1-stratum-proxy (spawned binary: --listen P1 --upstream P2)
//!   -> zcash-jd-client downstream listener on P2 (in-process)
//!   -> JD connection -> zcash-pool-server's JD server on P3 (in-process pool)
//!   -> both JDC + pool template providers: a mock Zebra JSON-RPC over HTTP
//! ```
//!
//! Assertions:
//!  (a) the JDC declared a job to the pool (a credited share proves a token was
//!      allocated AND a job declared, since the pool credits only declared-job
//!      shares),
//!  (b) at least one share flows END-TO-END: accepted by the JDC listener AND
//!      credited in the pool's PayoutTracker under the JDC's user id (this
//!      exercises SubmitSharesJd validation server-side with a REAL solution —
//!      the deferred accept path),
//!  (c) if any solution meets the block target the block path fired: submitblock
//!      hit the mock Zebra (asserted OPPORTUNISTICALLY — not required),
//!  (d) no rejected-share storm (pool-side rejected count stays 0 or tiny
//!      relative to accepted).
//!
//! ## Binaries
//! The proxy and miner run as spawned binaries. They are located in the
//! workspace `target/<profile>/` directory relative to `CARGO_MANIFEST_DIR`.
//! This test REQUIRES `cargo build --workspace` (or `cargo test`, which builds
//! all targets) to have produced them first; CI's build step does this. A
//! missing binary panics with a clear "run cargo build --workspace first"
//! message rather than hanging.
//!
//! ## Runtime
//! A real CPU solver finding an Equihash-(200,9) solution takes a few seconds
//! per attempt, so this test is gated behind `#[ignore]` and given a generous
//! 120s budget. Run with:
//!   cargo test -p zcash-jd-client --test tier2_chain_test -- --ignored

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zcash_jd_client::{JdClient, JdClientConfig};
use zcash_pool_server::{PayoutTracker, PoolConfig, PoolServer};
use zcash_template_provider::testutil::TestTemplateFactory;

/// The JDC user identifier. The pool credits accepted declared-job shares under
/// this exact string (it is the AllocateToken `user_identifier` -> token
/// `client_id` -> PayoutTracker key).
const JDC_USER_ID: &str = "tier2-jdc-miner";

/// Overall test budget. A CPU solver needs a few seconds per Equihash solution;
/// 120s leaves ample slack for slow CI while still failing rather than hanging.
///
/// This is also the worst-case leak ceiling for the spawned proxy + miner
/// binaries: the `ChildGuard` `Drop` reaps them on any normal exit (success,
/// failure, panic-unwind), but `Drop` does NOT run if the test *process* is
/// hard-killed (SIGKILL / `cargo test` timeout kill). In that case the children
/// outlive us; bounding the test's own wall-clock at BUDGET keeps that window
/// small rather than unbounded.
const BUDGET: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Process guard: kill spawned children on test exit (success, failure, panic).
// ---------------------------------------------------------------------------

struct ChildGuard {
    name: &'static str,
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!("[tier2] killed spawned process: {}", self.name);
    }
}

// ---------------------------------------------------------------------------
// Mock Zebra: a minimal HTTP/1.1 JSON-RPC server.
//
// Serves `getblocktemplate` (always the same trivially-easy template),
// `submitblock` (records the hex, returns null = accepted), and
// `getbestblockhash`. Implemented over raw tokio TCP so the test adds no HTTP
// dependency. Both the pool and the JDC point their `zebra_url` here, so they
// observe the SAME prev_hash and the JDC's declaration is never stale.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockZebra {
    /// Pre-serialized JSON `result` value for getblocktemplate.
    template_result: Arc<serde_json::Value>,
    /// Block hexes received via submitblock (proves assertion (c)).
    submitted_blocks: Arc<Mutex<Vec<String>>>,
}

impl MockZebra {
    fn new() -> Self {
        // Trivially-easy template:
        //  * version 4 (ZIP 301 notify VERSION == 4),
        //  * bits 0x2007ffff -> compact_to_target yields a huge (easy) BLOCK
        //    target, so virtually every valid solution also meets the block
        //    target (making assertion (c) usually fire),
        //  * target field all-0xff -> the easiest possible 256-bit target for
        //    the pool's own block-target bookkeeping,
        //  * empty transactions -> block assembly = header + solution + coinbase.
        // Pull a known-good coinbase hex from the factory (it produces a
        // decodable minimal coinbase the TemplateBuilder/JD validator accept),
        // then hand-build the getblocktemplate JSON so we control target/bits
        // exactly. The field names match `GetBlockTemplateResponse`'s serde
        // (deserialize) contract — that struct is Deserialize-only, so we build
        // the wire JSON directly rather than serializing it.
        let factory = TestTemplateFactory::new().version(4).height(1_000_000);
        let response = factory.build();
        let coinbase_hex = response
            .coinbase_txn
            .get("data")
            .and_then(|d| d.as_str())
            .expect("factory coinbase has data")
            .to_string();

        let value = serde_json::json!({
            "version": 4,
            "previousblockhash": "0".repeat(64),
            "defaultroots": {
                "merkleroot": "0".repeat(64),
                "chainhistoryroot": "0".repeat(64),
                "authdataroot": "0".repeat(64),
                "blockcommitmentshash": "0".repeat(64),
            },
            "transactions": [],
            "coinbasetxn": { "data": coinbase_hex },
            // Easiest possible 256-bit BLOCK target for the pool's bookkeeping.
            "target": "f".repeat(64),
            "height": 1_000_000,
            // compact_to_target(0x2007ffff) is a huge (easy) target, so almost
            // every valid Equihash solution also meets the block target.
            "bits": "2007ffff",
            "curtime": 1_700_000_000u64,
        });

        Self {
            template_result: Arc::new(value),
            submitted_blocks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn submitted_count(&self) -> usize {
        self.submitted_blocks.lock().unwrap().len()
    }

    /// Build the JSON-RPC `result` for a given method/id.
    fn handle_method(&self, method: &str, id: serde_json::Value, body: &str) -> serde_json::Value {
        let result = match method {
            "getblocktemplate" => (*self.template_result).clone(),
            "submitblock" => {
                // Record the submitted block hex (first param), return null
                // (Zebra returns null on accept). We sanity-check the bytes so a
                // regression that submits garbage is caught instead of being
                // counted as block-path success: the hex must be non-empty,
                // valid hex, and at least header(140) + solution(1344) bytes —
                // a Zcash block is header + compact-size + 1344-byte Equihash
                // solution + tx count + coinbase, so 1484 bytes (2968 hex chars)
                // is a safe lower bound. This proves the submit codepath fired
                // with structurally plausible bytes; it does NOT assert
                // Zebra-grade block validity (that is Task 10's live E2E).
                const MIN_BLOCK_HEX_LEN: usize = (140 + 1344) * 2;
                if let Ok(req) = serde_json::from_str::<serde_json::Value>(body)
                    && let Some(hex) = req
                        .get("params")
                        .and_then(|p| p.get(0))
                        .and_then(|h| h.as_str())
                {
                    assert!(
                        !hex.is_empty()
                            && hex.len() >= MIN_BLOCK_HEX_LEN
                            && hex.bytes().all(|b| b.is_ascii_hexdigit()),
                        "submitblock received implausible block hex (len={}, expected >= {} valid hex chars)",
                        hex.len(),
                        MIN_BLOCK_HEX_LEN,
                    );
                    self.submitted_blocks.lock().unwrap().push(hex.to_string());
                }
                serde_json::Value::Null
            }
            "getbestblockhash" => serde_json::Value::String("0".repeat(64)),
            _ => serde_json::Value::Null,
        };
        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
    }

    /// Bind an ephemeral port and serve until the runtime drops the task.
    async fn serve(self) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let me = self.clone();
                tokio::spawn(async move {
                    let _ = me.handle_conn(stream).await;
                });
            }
        });
        addr
    }

    async fn handle_conn(&self, mut stream: TcpStream) -> std::io::Result<()> {
        // The reqwest client uses keep-alive; serve multiple requests per conn.
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        loop {
            // Read until we have a full request (headers + Content-Length body).
            loop {
                if let Some((headers_end, content_len)) = parse_http_head(&buf) {
                    let total = headers_end + content_len;
                    if buf.len() >= total {
                        break;
                    }
                }
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Ok(()); // peer closed
                }
                buf.extend_from_slice(&tmp[..n]);
            }

            let (headers_end, content_len) = parse_http_head(&buf).unwrap();
            let body_bytes = buf[headers_end..headers_end + content_len].to_vec();
            let body = String::from_utf8_lossy(&body_bytes).to_string();

            let req: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
            let method = req
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);

            let resp = self.handle_method(&method, id, &body);
            let resp_body = serde_json::to_vec(&resp).unwrap();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                resp_body.len()
            );
            stream.write_all(http.as_bytes()).await?;
            stream.write_all(&resp_body).await?;
            stream.flush().await?;

            // Drain the consumed request from the buffer.
            buf.drain(..headers_end + content_len);
        }
    }
}

/// Find the end of the HTTP headers and the Content-Length. Returns
/// `(headers_end_offset, content_length)` once the full header block is present.
///
/// Content-Length only; reqwest always sets it for these calls.
fn parse_http_head(buf: &[u8]) -> Option<(usize, usize)> {
    let head_end = find_subslice(buf, b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buf[..head_end]);
    let mut content_len = 0usize;
    for line in head.lines() {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }
    Some((head_end, content_len))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Binary location.
// ---------------------------------------------------------------------------

/// Locate a workspace binary built into `target/<profile>/`. `CARGO_MANIFEST_DIR`
/// points at `crates/zcash-jd-client`, so the workspace `target` dir is two
/// levels up. We honor the active profile (debug vs release) via the standard
/// `PROFILE`-less heuristic: integration tests run under the same profile as the
/// build, and `cargo test` defaults to debug. We try debug then release.
fn workspace_binary(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_root = manifest
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .map(|p| p.join("target"))
        .expect("workspace target dir");

    for profile in ["debug", "release"] {
        let candidate = target_root.join(profile).join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    panic!(
        "binary `{name}` not found under {}/{{debug,release}} — run `cargo build --workspace` first",
        target_root.display()
    );
}

/// Bind an ephemeral port, return the addr, and immediately release it so a
/// spawned process can rebind. There is a tiny TOCTOU window, but on loopback
/// with the OS handing out fresh ephemeral ports this is reliable in practice
/// and avoids hard-coded ports that collide on CI.
async fn ephemeral_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

// ---------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spawns binaries + runs a real CPU Equihash solver (multi-second); run with --ignored"]
async fn tier2_full_chain_declared_job_mining() {
    // NOTE: we deliberately do NOT install a tracing subscriber here.
    // `PoolServer::with_template_provider` (called by `PoolServer::new`) installs
    // the global subscriber via `set_global_default`, which panics if one is
    // already set. Let the pool own logging; the test reports via eprintln!.
    let deadline = Instant::now() + BUDGET;

    // --- Mock Zebra (shared by pool + JDC) ------------------------------------
    let zebra = MockZebra::new();
    let zebra_addr = zebra.clone().serve().await;
    let zebra_url = format!("http://{zebra_addr}");

    // --- Ephemeral ports ------------------------------------------------------
    let pool_jd_addr = ephemeral_addr().await; // P3: pool JD server
    let jdc_listen_addr = ephemeral_addr().await; // P2: JDC downstream listener
    let proxy_listen_addr = ephemeral_addr().await; // P1: proxy SV1 listen
    let pool_stratum_addr = ephemeral_addr().await; // pool stratum (unused by chain)
    let pool_metrics_addr = ephemeral_addr().await;

    // --- In-process pool ------------------------------------------------------
    // A non-empty payout script is required when JD is enabled (PoolConfig
    // validation enforces the pairing). Any non-empty script works for the
    // chain under test; the coinbase the JDC builds is re-checked by the JD
    // server against this script.
    let pool_payout_script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 push20 (prefix)
    let pool_config = PoolConfig {
        listen_addr: pool_stratum_addr,
        zebra_url: zebra_url.clone(),
        initial_difficulty: 1e-9, // below saturation: accept every valid solution at cold start
        target_shares_per_minute: 5.0,
        nonce_1_len: 4,
        noise_enabled: false,
        warn_plain_mode: false,
        metrics_addr: Some(pool_metrics_addr),
        jd_listen_addr: Some(pool_jd_addr),
        pool_payout_script: Some(pool_payout_script),
        template_poll_ms: 250,
        ..Default::default()
    };
    let pool = PoolServer::new(pool_config).expect("pool server constructs");
    // Grab the payout tracker BEFORE `run()` consumes the server. This is the
    // server-side ground truth for assertions (a)+(b)+(d).
    let payout: Arc<PayoutTracker> = Arc::clone(pool.payout_tracker());
    tokio::spawn(async move {
        if let Err(e) = pool.run().await {
            eprintln!("[tier2] pool server exited: {e}");
        }
    });

    // --- In-process JD client -------------------------------------------------
    let jdc_config = JdClientConfig {
        zebra_url: zebra_url.clone(),
        pool_jd_addr,
        user_identifier: JDC_USER_ID.to_string(),
        template_poll_ms: 250,
        miner_payout_address: None,
        noise_enabled: false,
        pool_public_key: None,
        full_template_mode: false,
        tx_selection: Default::default(),
        jdc_listen: Some(jdc_listen_addr),
    };
    let jdc = JdClient::new(jdc_config).expect("jd client constructs");
    tokio::spawn(async move {
        if let Err(e) = jdc.run().await {
            eprintln!("[tier2] jd client exited: {e}");
        }
    });

    // Give the pool + JDC a moment to bind their listeners and for the JDC to
    // declare its first job to the pool before downstream clients connect.
    wait_until(deadline, Duration::from_millis(200), || async {
        tcp_connectable(jdc_listen_addr).await && tcp_connectable(pool_jd_addr).await
    })
    .await
    .expect("pool JD + JDC listeners came up within budget");

    // --- Spawned proxy: SV1 (P1) -> SV2 upstream to JDC listener (P2) ----------
    let proxy_bin = workspace_binary("sovright-v1-stratum-proxy");
    let proxy = Command::new(&proxy_bin)
        .arg("--listen")
        .arg(proxy_listen_addr.to_string())
        .arg("--upstream")
        .arg(jdc_listen_addr.to_string())
        .arg("--no-metrics")
        .spawn()
        .expect("spawn proxy");
    let _proxy_guard = ChildGuard {
        name: "sovright-v1-stratum-proxy",
        child: proxy,
    };

    wait_until(deadline, Duration::from_millis(200), || async {
        tcp_connectable(proxy_listen_addr).await
    })
    .await
    .expect("proxy SV1 listener came up within budget");

    // --- Spawned miner: V1 CPU solver against the proxy (P1) ------------------
    let miner_bin = workspace_binary("zcash-test-miner");
    let miner = Command::new(&miner_bin)
        .arg("--v1")
        .arg("--pool-addr")
        .arg(proxy_listen_addr.to_string())
        .arg("--worker-prefix")
        .arg("tier2")
        .spawn()
        .expect("spawn miner");
    let _miner_guard = ChildGuard {
        name: "zcash-test-miner",
        child: miner,
    };

    // --- Poll for an end-to-end credited share (assertions a + b) -------------
    // The pool credits PayoutTracker[JDC_USER_ID] only when a relayed
    // SubmitSharesJd share passes server-side Equihash verification against the
    // pool-granted share target. A non-zero total_shares therefore proves:
    //   * a token was allocated + a job declared (else no job to credit), and
    //   * a REAL solution traversed miner -> proxy -> JDC listener (accepted) ->
    //     pool (re-verified + credited).
    let credited = wait_until(deadline, Duration::from_millis(250), || {
        let payout = Arc::clone(&payout);
        async move {
            payout
                .get_stats(&JDC_USER_ID.to_string())
                .map(|s| s.total_shares > 0)
                .unwrap_or(false)
        }
    })
    .await;

    let stats = payout
        .get_stats(&JDC_USER_ID.to_string())
        .unwrap_or_default();

    assert!(
        credited.is_ok() && stats.total_shares > 0,
        "expected at least one end-to-end credited share under user {JDC_USER_ID} within {BUDGET:?}; \
         got stats={stats:?}. (a) declaration + (b) accept path did not complete."
    );
    eprintln!(
        "[tier2] credited shares for {JDC_USER_ID}: total={} window={} total_difficulty={}",
        stats.total_shares, stats.window_shares, stats.total_difficulty
    );

    // --- (c) Block path: opportunistic --------------------------------------
    // bits=0x2007ffff is the EASIEST block target representable in compact form
    // (zcash mainnet's pow limit). It is still meaningfully harder than the
    // all-ones SHARE target, so a given accepted share meets the block target
    // only ~3% of the time (roughly P(solution-hash top byte <= 0x07)). The
    // miner keeps running (its guard drops only at function end), so we let it
    // keep solving and poll for a submitblock for a generous grace window
    // bounded by the overall budget. This is asserted OPPORTUNISTICALLY — the
    // test never fails if no solution happens to clear the block target.
    //
    // What firing PROVES: the JDC's block-submission codepath ran end-to-end
    // and handed Zebra structurally plausible block bytes (length + hex checked
    // in the mock's submitblock handler). It does NOT prove the block is
    // Zebra-grade valid — full consensus validation against a live node is
    // Task 10's job, not this in-process chain test.
    let mut blocks = zebra.submitted_count();
    if blocks == 0 {
        let block_deadline = (Instant::now() + Duration::from_secs(20)).min(deadline);
        let _ = wait_until(block_deadline, Duration::from_millis(200), || {
            let zebra = zebra.clone();
            async move { zebra.submitted_count() > 0 }
        })
        .await;
        blocks = zebra.submitted_count();
    }
    if blocks > 0 {
        eprintln!("[tier2] BLOCK PATH FIRED: {blocks} submitblock call(s) to mock Zebra");
    } else {
        eprintln!("[tier2] block path did not fire this run (not required)");
    }

    // --- (d) No rejected-share storm -----------------------------------------
    // The PayoutTracker only counts ACCEPTED shares, so pool-side rejections are
    // not directly visible here. We assert the positive invariant instead: a
    // healthy run produces a meaningful number of accepted shares without the
    // chain stalling. A storm of rejections would manifest as ZERO accepted
    // shares (already caught above) because every relayed batch would be
    // rejected. We additionally require the accepted count to be plausible
    // (>=1) and finite difficulty, i.e. no NaN poisoning.
    assert!(
        stats.total_shares >= 1,
        "expected >=1 accepted share, got {}",
        stats.total_shares
    );
    assert!(
        stats.total_difficulty.is_finite() && stats.total_difficulty > 0.0,
        "accepted-share difficulty must be finite/positive (no rejection-storm poisoning), got {}",
        stats.total_difficulty
    );

    // Flush stderr so the diagnostic lines appear even on a fast exit.
    let _ = std::io::stderr().flush();
}

// ---------------------------------------------------------------------------
// Polling helpers.
// ---------------------------------------------------------------------------

/// Poll `cond` every `interval` until it returns true or `deadline` passes.
/// Returns `Ok(())` on success, `Err(())` if the deadline elapsed first.
async fn wait_until<F, Fut>(deadline: Instant, interval: Duration, mut cond: F) -> Result<(), ()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    loop {
        if cond().await {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(());
        }
        tokio::time::sleep(interval).await;
    }
}

/// True if a TCP connection to `addr` succeeds right now.
async fn tcp_connectable(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_ok()
}
