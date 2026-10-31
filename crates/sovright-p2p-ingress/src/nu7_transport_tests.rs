//! Isolated qualification only: no production testnet output gate is changed.
use super::nu7_fixture::{Nu7Fixture, tx_cache};
use super::*;
use sovright_relay::RelayPayload;
use sovright_relay_sidecar::submit::{
    SubmissionOutcome, SubmitBlockMode, handle_relay_compact_block,
    handle_relay_compact_block_with_mempool,
};

struct NeverSubmit;
impl sovright_relay_sidecar::submit::SubmitBlock for NeverSubmit {
    fn submit_block<'a>(&'a self, _: &'a str) -> sovright_relay_sidecar::submit::SubmitFuture<'a> {
        panic!("dry-run qualification must not submit")
    }
}

#[tokio::test]
async fn real_nu7_authenticated_udp_reaches_sidecar_candidate() {
    let raw = Nu7Fixture::load().raw;
    use sovright_relay::{EquihashPowValidator, PowResult, PowValidator, ZCASH_FULL_HEADER_SIZE};
    assert_eq!(
        EquihashPowValidator.validate(&raw[..ZCASH_FULL_HEADER_SIZE]),
        PowResult::Valid
    );
    let compact = transport(&raw).await;
    let result = handle_relay_compact_block(&NeverSubmit, &compact, SubmitBlockMode::DryRun)
        .await
        .unwrap();
    let SubmissionOutcome::DryRun(candidate) = result else {
        panic!("unexpected submission outcome")
    };
    assert_eq!(hex::decode(candidate.block_hex).unwrap(), raw);
    assert_eq!(
        candidate.consensus_block_hash,
        "000089ba27100beede16d64b34e3d1b626b428cb7ee9fe6dcfdc217ce24e78af"
    );
}

/// Cached compact and skeleton for the same NU7 block through the
/// authenticated loopback relay. The skeleton is a separate relay object (v3
/// skeleton FEC profile) that only `recv_payload` returns. No packet loss.
#[tokio::test]
async fn real_nu7_cached_compact_and_skeleton_cross_authenticated_udp() {
    use sovright_relay::ZCASH_FULL_HEADER_SIZE;
    let fixture = Nu7Fixture::load();
    let origin = tx_cache();
    origin.insert(fixture.v5_wtxid(), fixture.v5_transaction());

    let mut skeleton = None;
    let mut cached = None;
    let (forwarded, finished) = relay_loopback(
        &fixture.raw,
        BridgeMode {
            compact_from_tx_cache: true,
            skeleton_first: true,
        },
        Some(&origin),
        |payload| {
            // One slot per kind: a repeat of one kind never stands in for the other.
            match payload {
                RelayPayload::CompactSkeleton(block) if skeleton.is_none() => {
                    skeleton = Some(block)
                }
                RelayPayload::CompactBlock(block) if cached.is_none() => cached = Some(block),
                _ => {}
            }
            skeleton.is_some() && cached.is_some()
        },
    )
    .await;
    assert!(
        finished,
        "within 5 s: skeleton received = {}, cached compact received = {}",
        skeleton.is_some(),
        cached.is_some()
    );
    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

    for (kind, block) in [("skeleton", skeleton), ("cached compact", cached)] {
        let block = block.unwrap();
        assert_eq!(
            &block.header[..],
            &fixture.raw[..ZCASH_FULL_HEADER_SIZE],
            "{kind}: a different block"
        );
        assert_eq!(
            sovright_relay::consensus_block_hash_display(&block.header),
            fixture.consensus_hash(),
            "{kind}"
        );
        assert_eq!(
            block.short_ids.len(),
            1,
            "{kind}: v5 transaction as a short ID"
        );

        let receiver = tx_cache();
        receiver.insert(fixture.v5_wtxid(), fixture.v5_transaction());
        match handle_relay_compact_block_with_mempool(
            &NeverSubmit,
            &block,
            SubmitBlockMode::DryRun,
            &receiver,
        )
        .await
        {
            Ok(SubmissionOutcome::DryRun(candidate)) => {
                assert_eq!(
                    hex::decode(candidate.block_hex).unwrap(),
                    fixture.raw,
                    "{kind}"
                )
            }
            other => panic!("{kind}: expected a DryRun candidate, got {other:?}"),
        }

        // Without the receiver's copy a getblocktxn request is prepared and,
        // even in live mode, nothing is submitted: NeverSubmit panics if it is.
        match handle_relay_compact_block_with_mempool(
            &NeverSubmit,
            &block,
            SubmitBlockMode::Live,
            &tx_cache(),
        )
        .await
        {
            Ok(SubmissionOutcome::NeedsTransactions { request, .. }) => {
                assert_eq!(request.indexes, vec![1], "{kind}")
            }
            other => panic!("{kind}: expected NeedsTransactions, got {other:?}"),
        }
    }
}

/// Skeleton-first with a cold origin cache: the origin never saw the v5
/// transaction, so the skeleton's short ID comes from the cache-miss fallback
/// that derives the NU7 v5 wtxid from the transaction bytes. A receiver holding
/// the transaction must still rebuild the exact block from the skeleton alone.
#[tokio::test]
async fn real_nu7_skeleton_from_cold_origin_cache_reconstructs_exact_block() {
    use sovright_relay::ZCASH_FULL_HEADER_SIZE;
    let fixture = Nu7Fixture::load();
    let cold_origin = tx_cache();

    let mut skeleton = None;
    let (_, finished) = relay_loopback(
        &fixture.raw,
        BridgeMode {
            compact_from_tx_cache: true,
            skeleton_first: true,
        },
        Some(&cold_origin),
        |payload| {
            if let RelayPayload::CompactSkeleton(block) = payload {
                skeleton = Some(block);
            }
            skeleton.is_some()
        },
    )
    .await;
    assert!(finished, "no skeleton within 5 s from a cold origin cache");
    let skeleton = skeleton.unwrap();
    assert_eq!(&skeleton.header[..], &fixture.raw[..ZCASH_FULL_HEADER_SIZE]);
    assert_eq!(
        skeleton.short_ids.len(),
        1,
        "the v5 transaction must be a short ID even though the origin never cached it"
    );

    let receiver = tx_cache();
    receiver.insert(fixture.v5_wtxid(), fixture.v5_transaction());
    match handle_relay_compact_block_with_mempool(
        &NeverSubmit,
        &skeleton,
        SubmitBlockMode::DryRun,
        &receiver,
    )
    .await
    {
        Ok(SubmissionOutcome::DryRun(candidate)) => {
            assert_eq!(hex::decode(candidate.block_hex).unwrap(), fixture.raw)
        }
        other => panic!("expected a DryRun candidate, got {other:?}"),
    }
}

/// Bridge settings the qualification tests vary.
#[derive(Clone, Copy)]
struct BridgeMode {
    compact_from_tx_cache: bool,
    skeleton_first: bool,
}

async fn transport(raw: &[u8]) -> CompactBlock {
    let mut received = None;
    let (forwarded, finished) = relay_loopback(
        raw,
        BridgeMode {
            compact_from_tx_cache: false,
            skeleton_first: false,
        },
        None,
        |payload| {
            if let RelayPayload::CompactBlock(block) = payload {
                received = Some(block);
            }
            received.is_some()
        },
    )
    .await;
    assert!(finished, "relay delivery timed out");
    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    received.unwrap()
}

/// Send `raw` through an authenticated loopback relay and hand each payload
/// the receiver gets to `take` until it returns true. Returns the bridge's
/// result and whether `take` finished within 5 s.
async fn relay_loopback(
    raw: &[u8],
    mode: BridgeMode,
    origin_cache: Option<&TxCache>,
    mut take: impl FnMut(RelayPayload) -> bool,
) -> (ForwardedBlock, bool) {
    use sovright_relay::{AuthKey, RelayConfig, RelayNode};
    use tokio::time::{sleep, timeout};
    let key = [0x67; 32]; // Disposable local test key, never a fleet credential.
    let mut node = RelayNode::new(
        RelayConfig::new("127.0.0.1:0".parse().unwrap())
            .with_authorized_keys(vec![AuthKey::new("nu7-test", key)]),
    )
    .unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let config = ClientConfig::new(vec![addr], key)
        .with_bind_addr("127.0.0.1:0".parse().unwrap())
        .with_auth_required(true);
    let mut receiver = RelayClient::new(config.clone()).unwrap();
    receiver.bind().await.unwrap();
    let (mut incoming, outgoing) = receiver.take_receiver().unwrap();
    let mut origin = RelayClient::new(config).unwrap();
    origin.bind().await.unwrap();
    let bridge = RelayBridge {
        sender: origin.sender(),
        data_shards: 10,
        parity_shards: 3,
        chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
        compact_from_tx_cache: mode.compact_from_tx_cache,
        skeleton_first: mode.skeleton_first,
        raw_fallback_with_tx_cache: false,
        raw_segment_send_rounds: 1,
        raw_segment_round_delay: Duration::ZERO,
        recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
            4,
            Duration::from_secs(30),
        ))),
        parse_permits: ParsePermits::new(),
        block_body_rejections: Default::default(),
        peer_pow_limit: None,
        block_log: None,
        forward_unreadable_blocks: false,
        unverified_forwards: Default::default(),
    };
    // Drop aborts all tasks, including on a failed assertion or timeout.
    let mut tasks = tokio::task::JoinSet::new();
    let runner = Arc::clone(&node);
    tasks.spawn(async move { runner.run().await });
    tasks.spawn(async move { origin.run().await });
    tasks.spawn(async move { receiver.run_with_outgoing(outgoing).await });
    timeout(Duration::from_secs(5), async {
        while node.session_count().await != 2 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both authenticated sessions must register");
    let forwarded = bridge.forward_block(raw, origin_cache).await.unwrap();
    let finished = timeout(Duration::from_secs(5), async {
        while let Some(payload) = incoming.recv_payload().await {
            if take(payload) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(node.metrics().snapshot().packets_received > 0);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    (forwarded, finished)
}

/// Explicit operator-only qualification against an isolated testnet node.
/// This test is ignored in CI and refuses non-loopback RPC, non-testnet chain,
/// a known block, or a block that does not extend the observed node tip.
#[tokio::test]
#[ignore = "requires explicit canonical block, SHA256, and isolated testnet RPC port"]
async fn live_nu7_authenticated_transport_submission() {
    use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
    use sha2::{Digest, Sha256};
    use sovright_relay_sidecar::{rpc::ZebraRpc, submit::SubmitBlockStatus};
    let path = std::env::var("NU7_TEST_RAW_BLOCK").expect("explicit raw block hex path required");
    let expected_sha = std::env::var("NU7_TEST_RAW_SHA256").expect("explicit SHA256 required");
    let port: u16 = std::env::var("NU7_TEST_RPC_PORT")
        .expect("explicit loopback port required")
        .parse()
        .unwrap();
    assert_ne!(port, 0);
    let raw = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&raw)), expected_sha);
    let compact = transport(&raw).await;
    let url = format!("http://127.0.0.1:{port}");
    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .unwrap();
    let info: serde_json::Value = client
        .request("getblockchaininfo", rpc_params![])
        .await
        .unwrap();
    assert_eq!(
        info["chain"], "test",
        "live qualification refuses any other chain"
    );
    assert_eq!(info["consensus"]["chaintip"], "77190ad9");
    let mut parent = raw[4..36].to_vec();
    parent.reverse();
    assert_eq!(
        info["bestblockhash"],
        hex::encode(parent),
        "node tip changed; stop"
    );
    let expected_hash = sovright_relay::consensus_block_hash_display(&compact.header);
    let node = ZebraRpc::new(&url).await.unwrap();
    assert!(
        node.get_block_header(&expected_hash)
            .await
            .unwrap()
            .is_none(),
        "already known; no fresh acceptance claim"
    );
    let outcome = handle_relay_compact_block(&node, &compact, SubmitBlockMode::Live)
        .await
        .unwrap();
    let SubmissionOutcome::Submitted { candidate, status } = outcome else {
        panic!("not submitted")
    };
    assert_eq!(hex::decode(&candidate.block_hex).unwrap(), raw);
    // A duplicate/race is not promoted to a new acceptance receipt.
    assert_eq!(status, SubmitBlockStatus::Accepted);
    let header = node
        .get_block_header(&expected_hash)
        .await
        .unwrap()
        .expect("accepted block missing");
    let canonical: String = client
        .request("getblockhash", rpc_params![header.height])
        .await
        .unwrap();
    assert_eq!(canonical, expected_hash);
    assert_eq!(header.height, info["blocks"].as_u64().unwrap() + 1);
    println!(
        "NU7_TRANSPORT_RECEIPT {}",
        serde_json::json!({"raw_sha256": expected_sha, "bytes": raw.len(), "height": header.height, "consensus_hash": canonical, "result": "accepted", "route": "authenticated loopback relay UDP / FEC / sidecar reconstruction / testnet submitblock"})
    );
}
