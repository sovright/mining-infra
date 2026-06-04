//! Relay integration tests

use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{
    AuthDigest, ClientConfig, CompactBlockBuilder, RelayClient, RelayConfig, RelayNode,
    StubPowValidator, TestMempool, TxId, WtxId, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    split_raw_block, zcash_block_hash,
};

fn make_test_block() -> sovright_relay::CompactBlock {
    let header = vec![0xab; 2189];
    let nonce = 0xdeadbeef_u64;

    let coinbase = WtxId::new(
        TxId::from_bytes([0x00; 32]),
        AuthDigest::from_bytes([0x00; 32]),
    );

    let mut builder = CompactBlockBuilder::new(header, nonce);
    builder.add_transaction(coinbase, vec![0u8; 500]);

    let mempool = TestMempool::new();
    builder.build(&mempool)
}

fn raw_block_hash(raw_block: &[u8]) -> [u8; 32] {
    zcash_block_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE])
}

/// Test that a RelayNode can receive chunks from a connected client.
///
/// This test verifies the basic network path works:
/// - Node binds and runs
/// - Client connects and sends block chunks
/// - Node receives packets (session management)
#[tokio::test]
async fn relay_node_receives_chunks() {
    // Start relay node
    let config =
        RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_unauthenticated_peers_allowed(true);
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let node_handle = tokio::spawn(async move { node_clone.run().await });

    // Give node time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client
    let client_config = ClientConfig::new(vec![node_addr], [0x42; 32]);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();

    let sender = client.sender();

    // Start client in background
    let _client_handle = tokio::spawn(async move { client.run().await });

    // Give client time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a block
    let block = make_test_block();
    sender.send(block).await.unwrap();

    // Give time for transmission
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify node has received the session from the client
    let session_count = node.session_count().await;
    // Session should be created when packets are received
    assert!(
        session_count > 0,
        "Expected at least 1 session, got {}",
        session_count
    );

    // Cleanup - stop both node and client properly
    node.stop();
    // Note: We can't easily stop the client from outside, but dropping sender will signal it
    drop(sender);

    // Wait for node to finish
    let _ = node_handle.await;
}

/// Test basic client-to-client relay setup.
///
/// This test verifies the multi-client topology:
/// - Relay node accepts connections from multiple clients
/// - Sender client can transmit blocks
/// - Node manages multiple sessions
///
/// Note: Full end-to-end block reception requires additional
/// protocol work (block reconstruction on receiver side).
#[tokio::test]
async fn client_to_client_via_relay() {
    // Start relay node (no auth required for testing)
    let node_config =
        RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_unauthenticated_peers_allowed(true);
    let mut node = RelayNode::new(node_config).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let node_handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create sender client
    let sender_config = ClientConfig::new(vec![node_addr], [0x01; 32]);
    let mut sender_client = RelayClient::new(sender_config).unwrap();
    sender_client.bind().await.unwrap();
    let block_sender = sender_client.sender();

    let _sender_handle = tokio::spawn(async move { sender_client.run().await });

    // Create receiver client
    let receiver_config = ClientConfig::new(vec![node_addr], [0x02; 32]);
    let mut receiver_client = RelayClient::new(receiver_config).unwrap();
    receiver_client.bind().await.unwrap();

    // Note: In a real test, we'd set up the receiver to actually receive
    // For now, just verify the setup works
    let _receiver_handle = tokio::spawn(async move { receiver_client.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a block from sender
    let block = make_test_block();
    block_sender.send(block.clone()).await.unwrap();

    // Give time for relay
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify node has sessions
    let session_count = node.session_count().await;
    assert!(
        session_count >= 1,
        "Expected at least 1 session, got {}",
        session_count
    );

    // Cleanup
    node.stop();
    // Note: Client tasks will exit when their sockets are dropped
    let _ = node_handle.await;
}

/// Test authenticated relay with HMAC verification.
///
/// This test verifies that authentication works:
/// - Node configured with authorized_keys
/// - Client sends authenticated (version 2) chunks
/// - Node accepts and processes the chunks
/// - Metrics show no auth failures
#[tokio::test]
async fn authenticated_relay() {
    let auth_key = [0x42; 32];

    // Start relay node with auth required
    let node_config =
        RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![auth_key]);
    let mut node = RelayNode::new(node_config).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let node_handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client with matching auth key
    let client_config = ClientConfig::new(vec![node_addr], auth_key);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();
    let sender = client.sender();

    let _client_handle = tokio::spawn(async move { client.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a block
    let block = make_test_block();
    sender.send(block).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify metrics
    let metrics = node.metrics().snapshot();
    assert!(
        metrics.packets_received > 0,
        "Expected packets to be received"
    );
    assert_eq!(metrics.auth_failures, 0, "Expected no auth failures");
    assert!(
        metrics.sessions_created > 0,
        "Expected session to be created"
    );

    // Cleanup
    node.stop();
    let _ = node_handle.await;
}

/// Test that a receive-only client registers with the relay before sending
/// block announcements, so relays can forward future blocks to it.
#[tokio::test]
async fn receive_only_client_registers_session_with_keepalive() {
    let auth_key = [0x42; 32];

    let node_config =
        RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![auth_key]);
    let mut node = RelayNode::new(node_config).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let node_handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = ClientConfig::new(vec![node_addr], auth_key).with_auth_required(true);
    let mut receiver_client = RelayClient::new(client_config).unwrap();
    receiver_client.bind().await.unwrap();
    let (_receiver, outgoing) = receiver_client.take_receiver().unwrap();

    let client_handle =
        tokio::spawn(async move { receiver_client.run_with_outgoing(outgoing).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics = node.metrics().snapshot();
    assert_eq!(metrics.auth_failures, 0, "Expected no auth failures");
    assert!(
        metrics.sessions_created > 0,
        "Expected keepalive to create a relay session"
    );
    assert!(
        node.session_count().await > 0,
        "Expected receive-only client to be registered as a relay session"
    );

    node.stop();
    client_handle.abort();
    let _ = node_handle.await;
}

#[tokio::test]
async fn raw_block_segments_flow_client_to_client_via_relay() {
    let auth_key = [0x42; 32];

    let node_config =
        RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![auth_key]);
    let mut node = RelayNode::with_validator(node_config, StubPowValidator).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);
    let node_handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let receiver_config = ClientConfig::new(vec![node_addr], auth_key).with_auth_required(true);
    let mut receiver_client = RelayClient::new(receiver_config).unwrap();
    receiver_client.bind().await.unwrap();
    let (mut receiver, outgoing) = receiver_client.take_receiver().unwrap();
    let receiver_handle =
        tokio::spawn(async move { receiver_client.run_with_outgoing(outgoing).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let sender_config = ClientConfig::new(vec![node_addr], auth_key).with_auth_required(true);
    let mut sender_client = RelayClient::new(sender_config).unwrap();
    sender_client.bind().await.unwrap();
    let sender = sender_client.sender();
    let sender_handle = tokio::spawn(async move { sender_client.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut raw_block = vec![0xab; ZCASH_FULL_HEADER_SIZE];
    raw_block.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    raw_block.resize(ZCASH_FULL_HEADER_SIZE + 4096, 0xcd);
    let block_hash = raw_block_hash(&raw_block);
    let segments = split_raw_block(block_hash, &raw_block, 2_000).unwrap();
    assert!(segments.len() > 1);

    for segment in segments.iter().cloned() {
        sender.send_raw_block_segment(segment).await.unwrap();
    }

    let mut received = Vec::new();
    while received.len() < segments.len() {
        let segment =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_raw_block_segment())
                .await
                .expect("timed out waiting for raw block segment")
                .expect("raw block segment receiver closed");
        received.push(segment);
    }

    let reassembled = reassemble_raw_block(&received).unwrap();
    assert_eq!(reassembled, raw_block);

    node.stop();
    receiver_handle.abort();
    sender_handle.abort();
    let _ = node_handle.await;
}

/// Test that unauthenticated client is rejected when auth is required.
#[tokio::test]
async fn unauthenticated_client_rejected() {
    let auth_key = [0x42; 32];
    let wrong_key = [0x00; 32]; // Different key

    // Start relay node with auth required
    let node_config =
        RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(vec![auth_key]);
    let mut node = RelayNode::new(node_config).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let node_handle = tokio::spawn(async move { node_clone.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client with WRONG auth key
    let client_config = ClientConfig::new(vec![node_addr], wrong_key);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();
    let sender = client.sender();

    let _client_handle = tokio::spawn(async move { client.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a block (should be rejected by node)
    let block = make_test_block();
    sender.send(block).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify auth failures were recorded
    let metrics = node.metrics().snapshot();
    assert!(
        metrics.packets_received > 0,
        "Expected packets to be received"
    );
    assert!(metrics.auth_failures > 0, "Expected auth failures");
    assert_eq!(metrics.sessions_created, 0, "Expected no sessions created");

    // Cleanup
    node.stop();
    let _ = node_handle.await;
}
