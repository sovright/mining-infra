//! Loopback-only `submitblock` JSON-RPC gateway for mining pools.
//!
//! A pool can send the same `submitblock` call it would send to Zebra. The
//! gateway validates the solved block before amplification, then starts relay
//! fanout and local Zebra submission concurrently. Zebra remains the consensus
//! authority and its result is returned to the pool; relay failure is logged but
//! never turns a successful local submission into a pool-visible failure.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonrpsee::RpcModule;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::Value;
use sovright_relay::ZCASH_FULL_HEADER_SIZE;
use sovright_relay_sidecar::rpc::ZebraRpc;
use sovright_relay_sidecar::submit::SubmitBlock;
use tracing::{info, warn};
use zcash_equihash_validator::{EquihashValidator, Target, compact_to_target};

use crate::block::compact_block_from_raw_block;
use crate::config::SubmitBlockRpcConfig;
use crate::error::{IngressError, Result};
use crate::relay_bridge::{ForwardedBlock, RelayBridge};
use crate::tx_cache::TxCache;

// Zcash block-header byte layout (all little-endian, contiguous from offset 0):
//   version(4) prev(32) merkle(32) finalsaplingroot(32) time(4) bits(4) nonce(32)
// so `bits` starts at 4+32+32+32+4 = 104 (BITS_OFFSET) and the fixed header is
// 140 bytes (BASE_HEADER_BYTES). It is followed by CompactSize(1344) == the
// 3-byte prefix [0xfd,0x40,0x05] then the 1344-byte Equihash solution.
const BITS_OFFSET: usize = 104;
const BASE_HEADER_BYTES: usize = 140;
const SOLUTION_PREFIX_BYTES: usize = 3;
const SOLUTION_BYTES: usize = 1_344;
const JSON_OVERHEAD_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: u32 = 16;

type RelayFuture<'a> = Pin<Box<dyn Future<Output = Result<ForwardedBlock>> + Send + 'a>>;

trait RelayBlockForwarder: Send + Sync {
    fn forward_block<'a>(
        &'a self,
        block: &'a [u8],
        tx_cache: Option<&'a TxCache>,
    ) -> RelayFuture<'a>;
}

impl RelayBlockForwarder for RelayBridge {
    fn forward_block<'a>(
        &'a self,
        block: &'a [u8],
        tx_cache: Option<&'a TxCache>,
    ) -> RelayFuture<'a> {
        Box::pin(async move { RelayBridge::forward_block(self, block, tx_cache).await })
    }
}

trait SubmittedBlockValidator: Send + Sync {
    fn validate(&self, block: &[u8]) -> std::result::Result<String, String>;
}

struct MainnetSubmittedBlockValidator {
    max_block_bytes: usize,
    equihash: EquihashValidator,
}

impl MainnetSubmittedBlockValidator {
    fn new(max_block_bytes: usize) -> Self {
        Self {
            max_block_bytes,
            equihash: EquihashValidator::new(),
        }
    }
}

impl SubmittedBlockValidator for MainnetSubmittedBlockValidator {
    fn validate(&self, block: &[u8]) -> std::result::Result<String, String> {
        if block.len() > self.max_block_bytes {
            return Err(format!(
                "block is too large: bytes={} max={}",
                block.len(),
                self.max_block_bytes
            ));
        }
        if block.len() < ZCASH_FULL_HEADER_SIZE {
            return Err(format!(
                "block is shorter than the Zcash header: bytes={} minimum={ZCASH_FULL_HEADER_SIZE}",
                block.len()
            ));
        }
        if block[BASE_HEADER_BYTES..BASE_HEADER_BYTES + SOLUTION_PREFIX_BYTES] != [0xfd, 0x40, 0x05]
        {
            return Err("invalid Equihash solution CompactSize prefix".to_string());
        }

        // Parse every transaction and reject trailing bytes before doing the
        // expensive Equihash check or touching the relay fanout path.
        let compact = compact_block_from_raw_block(block).map_err(|error| error.to_string())?;

        let bits = u32::from_le_bytes(
            block[BITS_OFFSET..BITS_OFFSET + 4]
                .try_into()
                .expect("bits slice is four bytes"),
        );
        if bits & 0x0080_0000 != 0 || bits & 0x007f_ffff == 0 {
            return Err(format!("invalid compact target bits: {bits:#010x}"));
        }
        // Anti-garbage PoW guard, NOT a consensus-difficulty check: we only
        // require the block's PoW to meet its own stated target within the valid
        // mainnet range (diff >= 1). Whether it clears the *current* network
        // difficulty is Zebra's job — a block Zebra rejects for low difficulty
        // may still be fanned into the mesh, which is acceptable given the
        // loopback-only, trusted-pool threat model.
        let target = compact_to_target(bits);
        if target.0 == [0u8; 32] || target > Target::max_mainnet() {
            return Err(format!("target outside Zcash mainnet range: {bits:#010x}"));
        }

        let header = &block[..BASE_HEADER_BYTES];
        let solution = &block[BASE_HEADER_BYTES + SOLUTION_PREFIX_BYTES..ZCASH_FULL_HEADER_SIZE];
        debug_assert_eq!(solution.len(), SOLUTION_BYTES);
        self.equihash
            .verify_solution(header, solution)
            .map_err(|error| format!("invalid mainnet proof of work: {error}"))?;

        // Deliberately NOT `EquihashValidator::verify_share`, whose target arm
        // hashes with BLAKE2b personalised "ZcashBlockHash". That value is the
        // relay's INTERNAL object id (see sovright_relay::hash), not Zcash's
        // block hash, so comparing it to an nBits-derived target rejected every
        // genuine mainnet block -- proven by
        // `production_validator_accepts_a_real_mainnet_block`.
        //
        // Zcash's PoW hash is the double-SHA256 of the full 1487-byte
        // serialized header, compared as a little-endian 256-bit integer. The
        // relay transport path already reaches the same conclusion in
        // sovright_relay::transport::pow::header_meets_stated_target.
        let pow_hash = sovright_relay::consensus_block_hash(&block[..ZCASH_FULL_HEADER_SIZE]);
        if !target.is_met_by(&pow_hash) {
            return Err(format!(
                "proof of work does not meet the block's stated target: bits={bits:#010x}"
            ));
        }

        Ok(compact.header_hash().to_string())
    }
}

struct SubmitBlockRpcState {
    relay: Arc<dyn RelayBlockForwarder>,
    zebra: Arc<dyn SubmitBlock + Send + Sync>,
    validator: Arc<dyn SubmittedBlockValidator>,
    tx_cache: Option<TxCache>,
    rate_limiter: RequestRateLimiter,
    relay_timeout: Duration,
}

#[derive(Clone)]
struct RequestRateLimiter {
    capacity: usize,
    window: Duration,
    accepted: Arc<std::sync::Mutex<VecDeque<Instant>>>,
}

impl RequestRateLimiter {
    fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            accepted: Arc::new(std::sync::Mutex::new(VecDeque::with_capacity(capacity))),
        }
    }

    fn allow(&self, now: Instant) -> bool {
        let Ok(mut accepted) = self.accepted.lock() else {
            return false;
        };
        while accepted
            .front()
            .is_some_and(|timestamp| now.duration_since(*timestamp) >= self.window)
        {
            accepted.pop_front();
        }
        if accepted.len() >= self.capacity {
            return false;
        }
        accepted.push_back(now);
        true
    }
}

/// Start the loopback HTTP JSON-RPC server and return its lifetime handle.
pub async fn start_submitblock_rpc(
    config: SubmitBlockRpcConfig,
    relay: RelayBridge,
    tx_cache: Option<TxCache>,
) -> Result<ServerHandle> {
    if !config.bind_addr.ip().is_loopback() {
        return Err(IngressError::Config(
            "submitblock RPC listener must be loopback".to_string(),
        ));
    }

    let zebra = ZebraRpc::new(&config.zebra_url)
        .await
        .map_err(|error| IngressError::Config(format!("invalid Zebra RPC URL: {error}")))?;
    let state = SubmitBlockRpcState {
        relay: Arc::new(relay),
        zebra: Arc::new(zebra),
        validator: Arc::new(MainnetSubmittedBlockValidator::new(config.max_block_bytes)),
        tx_cache,
        rate_limiter: RequestRateLimiter::new(
            config.max_requests_per_minute,
            Duration::from_secs(60),
        ),
        relay_timeout: config.relay_timeout,
    };
    let (_, handle) = start_rpc_server(&config, state).await?;
    Ok(handle)
}

async fn start_rpc_server(
    config: &SubmitBlockRpcConfig,
    state: SubmitBlockRpcState,
) -> Result<(std::net::SocketAddr, ServerHandle)> {
    let request_body_bytes = config
        .max_block_bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(JSON_OVERHEAD_BYTES))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            IngressError::Config("submitblock RPC request size limit overflow".to_string())
        })?;
    let mut module = RpcModule::new(state);
    module
        .register_async_method("submitblock", |params, state, _| async move {
            let block_hex = parse_submitblock_params(params.parse::<Vec<Value>>())?;
            handle_submitblock(state.as_ref(), block_hex).await
        })
        .map_err(|error| IngressError::Config(format!("register submitblock RPC: {error}")))?;

    let server = ServerBuilder::default()
        .http_only()
        .max_connections(MAX_CONNECTIONS)
        .max_request_body_size(request_body_bytes)
        .set_batch_request_config(jsonrpsee::server::BatchRequestConfig::Disabled)
        .build(config.bind_addr)
        .await
        .map_err(IngressError::Io)?;
    let local_addr = server.local_addr().map_err(IngressError::Io)?;
    let handle = server.start(module);
    info!(
        %local_addr,
        zebra_url = %config.zebra_url,
        max_block_bytes = config.max_block_bytes,
        max_requests_per_minute = config.max_requests_per_minute,
        relay_timeout_millis = config.relay_timeout.as_millis(),
        "Pool submitblock relay gateway started"
    );
    Ok((local_addr, handle))
}

fn parse_submitblock_params(
    params: std::result::Result<Vec<Value>, jsonrpsee::types::ErrorObjectOwned>,
) -> std::result::Result<String, ErrorObjectOwned> {
    let params = params.map_err(|error| invalid_params(error.to_string()))?;
    if params.is_empty() || params.len() > 2 {
        return Err(invalid_params(
            "submitblock expects the block hex and at most one ignored compatibility parameter",
        ));
    }
    params[0]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_params("submitblock block parameter must be a non-empty hex string"))
}

async fn handle_submitblock(
    state: &SubmitBlockRpcState,
    block_hex: String,
) -> std::result::Result<Option<String>, ErrorObjectOwned> {
    let started = Instant::now();
    // Decode and validate BEFORE consulting the rate limiter: a malformed or
    // invalid request must never consume the relay-amplification budget, so a
    // client spamming garbage cannot starve a real submission.
    let block = hex::decode(&block_hex)
        .map_err(|error| invalid_params(format!("submitblock block is not valid hex: {error}")))?;
    let block_hash = state
        .validator
        .validate(&block)
        .map_err(|error| ErrorObjectOwned::owned(-32010, error, None::<()>))?;

    // The rate limiter bounds relay-mesh amplification ONLY; it must never gate
    // consensus submission. Zebra is authoritative, so a found block is always
    // submitted to it. When the limiter trips we skip the relay fanout but still
    // submit to Zebra — a false rate-limit can therefore never lose a block.
    let relay_allowed = state.rate_limiter.allow(started);

    let zebra_started = Instant::now();
    let zebra_future = async {
        let result = state.zebra.submit_block(&block_hex).await;
        (result, zebra_started.elapsed())
    };

    let (relay_report, (zebra_result, zebra_elapsed)) = if relay_allowed {
        let relay_started = Instant::now();
        let relay_future = async {
            let result = match tokio::time::timeout(
                state.relay_timeout,
                state.relay.forward_block(&block, state.tx_cache.as_ref()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(IngressError::Timeout(format!(
                    "relay forwarding exceeded {}ms",
                    state.relay_timeout.as_millis()
                ))),
            };
            (result, relay_started.elapsed())
        };
        let (relay_pair, zebra_pair) = tokio::join!(relay_future, zebra_future);
        (Some(relay_pair), zebra_pair)
    } else {
        warn!(
            %block_hash,
            "Pool submitblock rate limit reached; skipping relay amplification and still submitting to Zebra"
        );
        (None, zebra_future.await)
    };

    if let Some((relay_result, relay_elapsed)) = relay_report {
        match relay_result {
            Ok(forwarded) => info!(
                %block_hash,
                relay_mode = forwarded.mode.as_str(),
                relay_objects = forwarded.relay_objects,
                relay_wire_bytes = forwarded.bytes,
                relay_elapsed_ms = relay_elapsed.as_millis(),
                "Pool submitblock forwarded directly into relay mesh"
            ),
            Err(error) => warn!(
                %block_hash,
                %error,
                relay_elapsed_ms = relay_elapsed.as_millis(),
                "Pool submitblock relay forwarding failed; preserving Zebra result"
            ),
        }
    }

    let result = zebra_result.map_err(|error| {
        ErrorObjectOwned::owned(
            -32603,
            format!("local Zebra submitblock RPC failed: {error}"),
            None::<()>,
        )
    })?;
    info!(
        %block_hash,
        zebra_result = result.as_deref().unwrap_or("accepted"),
        zebra_elapsed_ms = zebra_elapsed.as_millis(),
        total_elapsed_ms = started.elapsed().as_millis(),
        "Pool submitblock completed"
    );
    Ok(result)
}

fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, message.into(), None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use sovright_relay_sidecar::submit::SubmitFuture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AcceptValidator;

    impl SubmittedBlockValidator for AcceptValidator {
        fn validate(&self, _block: &[u8]) -> std::result::Result<String, String> {
            Ok("test-block".to_string())
        }
    }

    struct MockRelay {
        calls: AtomicUsize,
        fail: bool,
    }

    impl RelayBlockForwarder for MockRelay {
        fn forward_block<'a>(
            &'a self,
            _block: &'a [u8],
            _tx_cache: Option<&'a TxCache>,
        ) -> RelayFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.fail {
                    Err(IngressError::Relay("relay unavailable".to_string()))
                } else {
                    Ok(ForwardedBlock {
                        tx_count: 1,
                        bytes: 128,
                        relay_objects: 1,
                        mode: crate::relay_bridge::ForwardMode::CompactBlock,
                    })
                }
            })
        }
    }

    struct MockZebra {
        calls: AtomicUsize,
        result: Option<String>,
    }

    impl SubmitBlock for MockZebra {
        fn submit_block<'a>(&'a self, _block_hex: &'a str) -> SubmitFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.result.clone();
            Box::pin(async move { Ok(result) })
        }
    }

    fn state(relay_fails: bool, zebra_result: Option<&str>) -> SubmitBlockRpcState {
        SubmitBlockRpcState {
            relay: Arc::new(MockRelay {
                calls: AtomicUsize::new(0),
                fail: relay_fails,
            }),
            zebra: Arc::new(MockZebra {
                calls: AtomicUsize::new(0),
                result: zebra_result.map(ToOwned::to_owned),
            }),
            validator: Arc::new(AcceptValidator),
            tx_cache: None,
            rate_limiter: RequestRateLimiter::new(4, Duration::from_secs(60)),
            relay_timeout: Duration::from_secs(1),
        }
    }

    #[tokio::test]
    async fn json_rpc_server_accepts_standard_submitblock_call() {
        let config = SubmitBlockRpcConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zebra_url: "http://127.0.0.1:1".to_string(),
            max_block_bytes: 4 * 1024 * 1024,
            max_requests_per_minute: 4,
            relay_timeout: Duration::from_secs(1),
        };
        let (addr, handle) = start_rpc_server(&config, state(false, None)).await.unwrap();
        let client = HttpClientBuilder::default()
            .build(format!("http://{addr}"))
            .unwrap();

        let result: Option<String> = client
            .request("submitblock", rpc_params!["00"])
            .await
            .unwrap();

        assert_eq!(result, None);
        handle.stop().unwrap();
    }

    #[test]
    fn params_accept_standard_and_compatibility_shapes() {
        assert_eq!(
            parse_submitblock_params(Ok(vec![Value::String("abcd".to_string())])).unwrap(),
            "abcd"
        );
        assert_eq!(
            parse_submitblock_params(Ok(vec![Value::String("abcd".to_string()), Value::Null,]))
                .unwrap(),
            "abcd"
        );
    }

    #[test]
    fn params_reject_missing_or_non_string_block() {
        assert!(parse_submitblock_params(Ok(vec![])).is_err());
        assert!(parse_submitblock_params(Ok(vec![Value::Bool(true)])).is_err());
    }

    #[tokio::test]
    async fn returns_zebra_result_after_relay_forward() {
        let state = state(false, None);
        assert_eq!(
            handle_submitblock(&state, "00".to_string()).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn relay_failure_does_not_mask_zebra_acceptance() {
        let state = state(true, None);
        assert_eq!(
            handle_submitblock(&state, "00".to_string()).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn preserves_zebra_rejection_string() {
        let state = state(false, Some("duplicate"));
        assert_eq!(
            handle_submitblock(&state, "00".to_string()).await.unwrap(),
            Some("duplicate".to_string())
        );
    }

    /// Mainnet block 3470793: the 1487-byte header on line 1, then its 7
    /// transactions. Reused from the sovright-relay fixtures rather than
    /// duplicated, so both crates judge the same real bytes.
    const MAINNET_BLOCK_FIXTURE: &str =
        include_str!("../../sovright-relay/tests/fixtures/mainnet_block_3470793.txt");

    fn real_mainnet_block() -> Vec<u8> {
        let mut lines = MAINNET_BLOCK_FIXTURE
            .lines()
            .filter(|line| !line.trim().is_empty());
        let header = hex::decode(lines.next().expect("header line").trim()).expect("header hex");
        assert_eq!(header.len(), ZCASH_FULL_HEADER_SIZE);
        let txs: Vec<Vec<u8>> = lines
            .map(|line| hex::decode(line.trim()).expect("tx hex"))
            .collect();

        let mut block = header;
        crate::wire::encode_compact_size(txs.len() as u64, &mut block);
        for tx in &txs {
            block.extend_from_slice(tx);
        }
        block
    }

    /// THE regression. Every prior test here only proved that GARBAGE is
    /// rejected, so nothing established that a genuine solved block is
    /// ACCEPTED -- which is exactly how this survived.
    ///
    /// The gateway validated PoW with `EquihashValidator::verify_share`, whose
    /// target arm hashes with BLAKE2b personalised "ZcashBlockHash". That is
    /// the relay's INTERNAL object id, not Zcash's block hash. Zcash's PoW hash
    /// is the double-SHA256 of the full 1487-byte serialized header, so the
    /// guard rejected every real block a pool could submit.
    #[test]
    fn production_validator_accepts_a_real_mainnet_block() {
        let validator = MainnetSubmittedBlockValidator::new(4 * 1024 * 1024);
        let block = real_mainnet_block();
        assert!(
            validator.validate(&block).is_ok(),
            "a genuine mainnet block must pass the anti-garbage PoW guard: {:?}",
            validator.validate(&block)
        );
    }

    /// Pins the digest itself, so a refactor cannot quietly reintroduce the
    /// BLAKE2b value. The double-SHA256 of this header is the block hash Zebra
    /// and every explorer report, and it meets the target the header's own
    /// nBits encodes; the BLAKE2b digest does not.
    #[test]
    fn pow_hash_is_double_sha256_not_blake2b() {
        let block = real_mainnet_block();
        let header = &block[..ZCASH_FULL_HEADER_SIZE];

        let bits = u32::from_le_bytes(
            header[BITS_OFFSET..BITS_OFFSET + 4]
                .try_into()
                .expect("bits slice is four bytes"),
        );
        let target = compact_to_target(bits);

        let consensus = sovright_relay::consensus_block_hash(header);
        assert_eq!(
            sovright_relay::consensus_block_hash_display(header),
            "000000000030976123e65211bdfb288b21b4492f56bb1a42710588ca6b8c0d98",
            "fixture must be the block Zebra reports under this hash"
        );
        assert!(
            target.is_met_by(&consensus),
            "a real mined block must meet the target its own nBits encodes"
        );

        let blake = sovright_relay::zcash_block_hash(header);
        assert_ne!(consensus, blake, "the two digests must not be conflated");
        assert!(
            !target.is_met_by(&blake),
            "the BLAKE2b object id does NOT meet the target -- using it here is \
             what rejected genuine blocks"
        );
    }

    #[test]
    fn production_validator_rejects_short_and_bad_pow_blocks() {
        let validator = MainnetSubmittedBlockValidator::new(4 * 1024 * 1024);
        assert!(validator.validate(&[0u8; 100]).is_err());

        let mut invalid = vec![0u8; ZCASH_FULL_HEADER_SIZE];
        invalid[BASE_HEADER_BYTES..BASE_HEADER_BYTES + SOLUTION_PREFIX_BYTES]
            .copy_from_slice(&[0xfd, 0x40, 0x05]);
        // A structurally minimal one-transaction block; PoW/target remain invalid.
        invalid.push(1);
        invalid.extend_from_slice(&1u32.to_le_bytes());
        invalid.push(0);
        invalid.push(0);
        invalid.extend_from_slice(&0u32.to_le_bytes());
        assert!(validator.validate(&invalid).is_err());
    }

    struct RejectValidator;

    impl SubmittedBlockValidator for RejectValidator {
        fn validate(&self, _block: &[u8]) -> std::result::Result<String, String> {
            Err("rejected".to_string())
        }
    }

    fn state_parts(
        relay_fails: bool,
        rate_capacity: usize,
        validator: Arc<dyn SubmittedBlockValidator>,
    ) -> (Arc<MockRelay>, Arc<MockZebra>, SubmitBlockRpcState) {
        let relay = Arc::new(MockRelay {
            calls: AtomicUsize::new(0),
            fail: relay_fails,
        });
        let zebra = Arc::new(MockZebra {
            calls: AtomicUsize::new(0),
            result: None,
        });
        let state = SubmitBlockRpcState {
            relay: relay.clone(),
            zebra: zebra.clone(),
            validator,
            tx_cache: None,
            rate_limiter: RequestRateLimiter::new(rate_capacity, Duration::from_secs(60)),
            relay_timeout: Duration::from_secs(1),
        };
        (relay, zebra, state)
    }

    #[tokio::test]
    async fn rate_limit_skips_relay_but_still_submits_to_zebra() {
        // Capacity 0 => the limiter always trips. A found block must still reach
        // Zebra (the consensus authority); only the relay amplification is skipped.
        let (relay, zebra, state) = state_parts(false, 0, Arc::new(AcceptValidator));
        let out = handle_submitblock(&state, "00".to_string()).await.unwrap();
        assert_eq!(
            out, None,
            "Zebra's result is still returned when rate limited"
        );
        assert_eq!(
            zebra.calls.load(Ordering::SeqCst),
            1,
            "Zebra must be submitted to even when the relay is rate limited"
        );
        assert_eq!(
            relay.calls.load(Ordering::SeqCst),
            0,
            "relay amplification must be skipped when rate limited"
        );
    }

    #[tokio::test]
    async fn invalid_request_does_not_consume_relay_budget() {
        // A rejected block must not spend a relay-amplification token, so garbage
        // spam cannot starve a real submission. capacity 1: after a rejected
        // request, a valid one must still be allowed to relay.
        let (relay, zebra, state) = state_parts(false, 1, Arc::new(RejectValidator));
        assert!(
            handle_submitblock(&state, "00".to_string()).await.is_err(),
            "invalid block is rejected"
        );
        // Swap in an accepting validator against the same limiter state and submit.
        let state = SubmitBlockRpcState {
            validator: Arc::new(AcceptValidator),
            ..state
        };
        handle_submitblock(&state, "00".to_string()).await.unwrap();
        assert_eq!(
            relay.calls.load(Ordering::SeqCst),
            1,
            "the single relay token survived the rejected request and served the valid one"
        );
        assert_eq!(zebra.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rate_limiter_is_bounded_and_recovers_after_window() {
        let limiter = RequestRateLimiter::new(2, Duration::from_secs(10));
        let now = Instant::now();
        assert!(limiter.allow(now));
        assert!(limiter.allow(now + Duration::from_secs(1)));
        assert!(!limiter.allow(now + Duration::from_secs(2)));
        assert!(limiter.allow(now + Duration::from_secs(10)));
    }
}
