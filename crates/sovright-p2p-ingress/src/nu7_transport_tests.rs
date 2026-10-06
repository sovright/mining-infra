//! Isolated qualification only: no production testnet output gate is changed.
use super::*;
use sovright_relay_sidecar::submit::{
    SubmissionOutcome, SubmitBlockMode, handle_relay_compact_block,
};

struct NeverSubmit;
impl sovright_relay_sidecar::submit::SubmitBlock for NeverSubmit {
    fn submit_block<'a>(&'a self, _: &'a str) -> sovright_relay_sidecar::submit::SubmitFuture<'a> {
        panic!("dry-run qualification must not submit")
    }
}

#[tokio::test]
async fn real_nu7_authenticated_udp_reaches_sidecar_candidate() {
    let raw =
        hex::decode(include_str!("../tests/fixtures/testnet_nu7_4465026.hex").trim()).unwrap();
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

async fn transport(raw: &[u8]) -> CompactBlock {
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
        compact_from_tx_cache: false,
        skeleton_first: false,
        raw_fallback_with_tx_cache: false,
        raw_segment_send_rounds: 1,
        raw_segment_round_delay: Duration::ZERO,
        recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
            4,
            Duration::from_secs(30),
        ))),
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
    let forwarded = bridge.forward_block(raw, None).await.unwrap();
    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    let received = timeout(Duration::from_secs(5), incoming.recv())
        .await
        .expect("relay delivery timed out")
        .expect("receiver stopped");
    assert!(node.metrics().snapshot().packets_received > 0);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    received
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
