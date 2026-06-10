//! A polled, cached view of the local Zebra chain.
//!
//! The submit safety gate needs sync access to `(tip_height, parent_known(hash))`
//! from inside the per-candidate evaluation path. Doing RPC calls inline on
//! every candidate would add unpredictable latency and would cascade failures
//! if Zebra hiccups. This module gives the gate a struct that:
//!
//! - polls `getblockchaininfo` on a short cadence to track the local tip,
//! - keeps a bounded LRU of recently-confirmed parent hashes,
//! - falls back to an inline `getblockheader` lookup for cache misses, with
//!   the result then admitted to the LRU,
//! - and implements `ChainView` over an `Arc<ZebraChainView>` so the gate
//!   can borrow a sync view of the cached state.
//!
//! The polling task is owned by an `Arc<ZebraChainView>` so multiple gate
//! instances on the same sidecar share one polling channel.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::rpc::ZebraRpc;
use crate::submit_gate::ChainView;

/// Type alias for the underlying RPC failure surface. The poller logs and
/// continues; the gate sees a stale tip during a transient outage rather
/// than a panic.
type RpcResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Cached chain state shared between the polling task and `ChainView` callers.
///
/// The fields are intentionally simple: `tip_height` is the most recent value
/// observed via `getblockchaininfo`, and `known_parents` is a small LRU of
/// hashes confirmed-present in the local Zebra.
#[derive(Debug)]
struct CachedChainState {
    /// Last-known best-chain tip height.
    tip_height: u64,
    /// Bounded LRU of recently-confirmed parent hashes. Front is least
    /// recently confirmed, back is most recently.
    known_parents: VecDeque<[u8; 32]>,
    /// Maximum entries to retain in `known_parents`.
    parent_cache_capacity: usize,
}

impl CachedChainState {
    fn new(parent_cache_capacity: usize) -> Self {
        Self {
            tip_height: 0,
            known_parents: VecDeque::with_capacity(parent_cache_capacity),
            parent_cache_capacity,
        }
    }

    fn contains_parent(&self, hash: &[u8; 32]) -> bool {
        self.known_parents.iter().any(|h| h == hash)
    }

    fn admit_parent(&mut self, hash: [u8; 32]) {
        // Skip if already present; promotes the entry to most-recent.
        if let Some(idx) = self.known_parents.iter().position(|h| h == &hash) {
            self.known_parents.remove(idx);
        } else if self.known_parents.len() == self.parent_cache_capacity {
            self.known_parents.pop_front();
        }
        self.known_parents.push_back(hash);
    }
}

/// Configuration for the polling task.
#[derive(Debug, Clone)]
pub struct ZebraChainViewConfig {
    /// Cadence for `getblockchaininfo` polls. Default 5 seconds.
    pub tip_poll_interval: Duration,
    /// Maximum entries in the parent-known LRU. Default 256.
    pub parent_cache_capacity: usize,
}

impl Default for ZebraChainViewConfig {
    fn default() -> Self {
        Self {
            tip_poll_interval: Duration::from_secs(5),
            parent_cache_capacity: 256,
        }
    }
}

/// Cached chain view backed by a polled `ZebraRpc`.
///
/// Construct via `new`; the polling task is launched lazily by `start`.
pub struct ZebraChainView {
    state: RwLock<CachedChainState>,
    config: ZebraChainViewConfig,
}

impl ZebraChainView {
    /// Construct a new chain view. The poller does not start until `start`
    /// is awaited; tests can construct a `ZebraChainView` and prime the
    /// state directly without ever starting the poller.
    pub fn new(config: ZebraChainViewConfig) -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(CachedChainState::new(config.parent_cache_capacity)),
            config,
        })
    }

    /// Launch the polling task. Returns a `tokio::task::JoinHandle` so the
    /// caller can drop the view to cancel the poller, or `join().await` it
    /// during graceful shutdown.
    ///
    /// The task polls `rpc.get_blockchain_info()` every
    /// `config.tip_poll_interval`. On error, it logs at `tracing::warn` and
    /// keeps the cached tip from the prior successful poll until the next
    /// successful one — the gate's height-window check then operates on a
    /// possibly stale tip, which is the correct conservative behavior.
    pub fn start(self: Arc<Self>, rpc: Arc<ZebraRpc>) -> tokio::task::JoinHandle<()> {
        let view = Arc::clone(&self);
        let interval = view.config.tip_poll_interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                match rpc.get_blockchain_info().await {
                    Ok(info) => view.set_tip_height(info.blocks),
                    Err(error) => {
                        tracing::warn!(?error, "ZebraChainView: get_blockchain_info failed");
                    }
                }
            }
        })
    }

    /// Apply a fresh tip height. Public so the staging service can prime the
    /// cache from a manual call before spinning up the poller, and so tests
    /// can drive the state deterministically.
    pub fn set_tip_height(&self, height: u64) {
        if let Ok(mut state) = self.state.write() {
            state.tip_height = height;
        }
    }

    /// Admit a confirmed parent hash to the cache. Public so the staging
    /// service can pre-seed the cache from `get_blockchain_info` (the best
    /// block hash itself is always a known parent for the next-tip block)
    /// and so tests can drive the state deterministically.
    pub fn admit_parent(&self, hash: [u8; 32]) {
        if let Ok(mut state) = self.state.write() {
            state.admit_parent(hash);
        }
    }

    /// Look up a parent hash, falling back to a live `getblockheader` RPC if
    /// not in the cache. On a successful live lookup, the hash is admitted
    /// to the cache.
    ///
    /// Use this on the fast path of the staging service that does not run
    /// inside the sync gate (which requires the sync `ChainView` trait).
    pub async fn parent_known_async(&self, rpc: &ZebraRpc, hash: &[u8; 32]) -> RpcResult<bool> {
        if let Ok(state) = self.state.read()
            && state.contains_parent(hash)
        {
            return Ok(true);
        }
        let hex_hash = display_hex_encode(hash);
        let known = self
            .get_block_header_with_retry(rpc, &hex_hash)
            .await?
            .is_some();
        if known {
            self.admit_parent(*hash);
        }
        Ok(known)
    }

    /// Look up the height of a block hash via the local Zebra. Used by the
    /// gated submit handler to fill `CandidateMeta.height = parent_height + 1`.
    ///
    /// On a successful lookup, the hash is also admitted to the parent-known
    /// cache as a side effect — the height query proves the hash exists, so
    /// the next `parent_known` for the same hash short-circuits.
    pub async fn height_of(&self, rpc: &ZebraRpc, hash: &[u8; 32]) -> RpcResult<Option<u64>> {
        let hex_hash = display_hex_encode(hash);
        match self.get_block_header_with_retry(rpc, &hex_hash).await? {
            Some(info) => {
                self.admit_parent(*hash);
                Ok(Some(info.height))
            }
            None => Ok(None),
        }
    }

    /// Call `rpc.get_block_header(...)` with bounded retry on transient
    /// transport errors.
    ///
    /// Observed in production (relay-us-central1-1 → zebra-us-central1-2,
    /// 2026-06-09 to 06-10): the local Zebra's RPC port briefly refuses TCP
    /// connections in 30–60s bursts that align with GCE disk-snapshot
    /// freezes on the underlying persistent disk. Without retry, every
    /// reassembled candidate that arrived during a burst was treated as
    /// having an unknown parent (the gate's cache-only `parent_known` check
    /// can't distinguish "parent doesn't exist" from "we couldn't ask").
    /// At 11.6% cumulative rate this produced page-level noise.
    ///
    /// The retry budget (~2s total) is sized to mask brief freezes but
    /// short enough that a genuinely-down Zebra still surfaces quickly to
    /// the caller — better than blocking the per-candidate gate path for
    /// many seconds during a real outage.
    async fn get_block_header_with_retry(
        &self,
        rpc: &ZebraRpc,
        hex_hash: &str,
    ) -> RpcResult<Option<crate::rpc::BlockHeaderInfo>> {
        retry_transient(|| async { rpc.get_block_header(hex_hash).await }).await
    }
}

/// Bounded-retry wrapper around any async operation that yields a
/// `RpcResult<T>`. Retries on transient transport errors only — logical RPC
/// errors that have already been mapped to `Ok(...)` by the caller pass
/// through on the first attempt.
///
/// Extracted as a free function so tests can drive the retry loop without
/// instantiating a real `ZebraRpc`/HTTP client.
async fn retry_transient<F, Fut, T>(mut op: F) -> RpcResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = RpcResult<T>>,
{
    // First attempt + 3 retries, exponentially spaced (100ms, 500ms, 1500ms).
    const BACKOFFS_MS: [u64; 3] = [100, 500, 1500];
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for attempt in 0..=BACKOFFS_MS.len() {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !is_transient_transport_error(err.as_ref()) || attempt == BACKOFFS_MS.len() {
                    last_err = Some(err);
                    break;
                }
                tracing::warn!(
                    attempt = attempt + 1,
                    backoff_ms = BACKOFFS_MS[attempt],
                    error = %err,
                    "ZebraChainView: transient RPC error on get_block_header; retrying"
                );
                tokio::time::sleep(Duration::from_millis(BACKOFFS_MS[attempt])).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "retry_transient: no error captured".into()))
}

/// True when an error string matches the patterns that production has been
/// seeing for transient Zebra RPC outages — primarily ConnectionRefused
/// during GCE disk-snapshot freezes — so we should retry instead of giving
/// up after a single attempt.
fn is_transient_transport_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let text = err.to_string();
    text.contains("ConnectionRefused")
        || text.contains("connection refused")
        || text.contains("Connection reset")
        || text.contains("timed out")
        || text.contains("timeout")
        || text.contains("os error 111") // ECONNREFUSED
        || text.contains("os error 110") // ETIMEDOUT
}

impl ChainView for Arc<ZebraChainView> {
    fn tip_height(&self) -> u64 {
        self.state.read().map(|s| s.tip_height).unwrap_or(0)
    }

    fn parent_known(&self, parent_hash: &[u8; 32]) -> bool {
        self.state
            .read()
            .map(|s| s.contains_parent(parent_hash))
            .unwrap_or(false)
    }
}

/// Lowercase hex encoding without external dependencies.
#[cfg(test)]
fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Zcash/Bitcoin display-form hex encoding for block hashes.
///
/// Block hashes are stored in headers in natural (little-endian) byte order
/// but the RPC interface displays + accepts them in reversed (big-endian)
/// hex — e.g. the hash printed by `zcash-cli getblockhash` is the trailing
/// header bytes first. `getblockheader <hash>` expects this reversed form,
/// so pass the prev_hash bytes straight from `header[4..36]` through this
/// function before calling Zebra RPC. The cache stores the raw natural-order
/// bytes; only the boundary with Zebra needs the display form.
fn display_hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes.iter().rev() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view() -> Arc<ZebraChainView> {
        ZebraChainView::new(ZebraChainViewConfig {
            tip_poll_interval: Duration::from_secs(1),
            parent_cache_capacity: 4,
        })
    }

    #[test]
    fn fresh_state_reports_zero_tip_and_no_parents() {
        let view = make_view();
        assert_eq!(view.tip_height(), 0);
        assert!(!view.parent_known(&[1u8; 32]));
    }

    #[test]
    fn set_tip_height_is_visible_through_chain_view() {
        let view = make_view();
        view.set_tip_height(3370892);
        assert_eq!(view.tip_height(), 3370892);
    }

    #[test]
    fn admit_parent_makes_it_known() {
        let view = make_view();
        let hash = [7u8; 32];
        view.admit_parent(hash);
        assert!(view.parent_known(&hash));
    }

    #[test]
    fn parent_cache_evicts_least_recent_at_capacity() {
        let view = make_view();
        for i in 0u8..4 {
            view.admit_parent([i; 32]);
        }
        // Promote [0; 32] by re-admitting; it should now be most-recent.
        view.admit_parent([0u8; 32]);
        // Inserting one more evicts [1; 32] (the new least-recent).
        view.admit_parent([99u8; 32]);

        assert!(view.parent_known(&[0u8; 32]), "[0] promoted, must survive");
        assert!(
            !view.parent_known(&[1u8; 32]),
            "[1] is least-recent, must be evicted"
        );
        assert!(view.parent_known(&[2u8; 32]));
        assert!(view.parent_known(&[3u8; 32]));
        assert!(view.parent_known(&[99u8; 32]));
    }

    #[test]
    fn hex_encode_lowercase() {
        let bytes = [
            0u8, 0x9a, 0xff, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let out = hex_encode(&bytes);
        assert_eq!(&out[..8], "009aff10");
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn classifies_connection_refused_as_transient() {
        let cases = [
            "tcp connect error: ConnectionRefused",
            "Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }",
            "connection refused",
            "Connection reset by peer",
            "operation timed out",
            "request timeout",
            "io error: os error 111",
            "os error 110 (timed out)",
        ];
        for text in cases {
            let err: Box<dyn std::error::Error + Send + Sync> = text.into();
            assert!(
                is_transient_transport_error(err.as_ref()),
                "expected transient: {text}"
            );
        }
    }

    #[test]
    fn does_not_classify_logical_errors_as_transient() {
        let cases = [
            "Block not found",
            "Method not allowed",
            "Bad JSON-RPC response",
            "unknown method",
            "Invalid parameter",
        ];
        for text in cases {
            let err: Box<dyn std::error::Error + Send + Sync> = text.into();
            assert!(
                !is_transient_transport_error(err.as_ref()),
                "should not retry on: {text}"
            );
        }
    }

    #[tokio::test]
    async fn retry_transient_succeeds_after_two_connection_refused() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let result: RpcResult<u32> = retry_transient(|| {
            let calls = Arc::clone(&calls_clone);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err::<u32, _>("ConnectionRefused: simulated".into())
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_transient_gives_up_after_four_total_attempts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let result: RpcResult<u32> = retry_transient(|| {
            let calls = Arc::clone(&calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<u32, _>("os error 111 ConnectionRefused".into())
            }
        })
        .await;
        assert!(result.is_err());
        // 1 first attempt + 3 retries = 4 total.
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn retry_transient_does_not_retry_on_logical_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let result: RpcResult<u32> = retry_transient(|| {
            let calls = Arc::clone(&calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<u32, _>("Block not found".into())
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "logical errors must not be retried");
    }
}
