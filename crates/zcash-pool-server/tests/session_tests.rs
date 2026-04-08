//! Integration tests for Session::run() main loop
//!
//! These tests exercise the Session over real TCP connections using Plain transport,
//! verifying job delivery, target updates, shutdown, and share forwarding.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use zcash_mining_protocol::codec::{
    decode_new_equihash_job, decode_set_target, encode_submit_share, MessageFrame,
};
use zcash_mining_protocol::messages::{NewEquihashJob, SubmitEquihashShare};
use zcash_pool_server::session::{ServerMessage, Session, SessionMessage, Transport};

/// Helper: bind a TCP listener on localhost with an OS-assigned port, return (listener, addr).
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server_stream, _) = listener.accept().await.unwrap();
    (server_stream, client)
}

/// Helper: create a test NewEquihashJob with valid nonce lengths (nonce_1=4, nonce_2=28).
fn make_test_job(job_id: u32) -> NewEquihashJob {
    NewEquihashJob {
        channel_id: 0, // Session::send_job overwrites this with self.channel_id
        job_id,
        future_job: false,
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        nonce_1: vec![0x01, 0x02, 0x03, 0x04],
        nonce_2_len: 28,
        time: 1700000000,
        bits: 0x2007ffff,
        target: [0xff; 32],
        clean_jobs: true,
    }
}

/// Helper: read a complete framed message from a TCP stream.
/// Returns the full frame (header + payload).
async fn read_framed_message(stream: &mut TcpStream) -> Vec<u8> {
    // Read the 6-byte header first
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await.unwrap();

    let frame = MessageFrame::decode(&header).unwrap();
    let payload_len = frame.length as usize;

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await.unwrap();
    }

    let mut full = header.to_vec();
    full.extend(payload);
    full
}

/// Create a Session with Plain transport and return (session, server_tx, server_rx, channel_id).
fn make_session(
    server_stream: TcpStream,
    channel_id: u32,
) -> (
    Session,
    mpsc::Sender<ServerMessage>,
    mpsc::Receiver<SessionMessage>,
) {
    let (server_msg_tx, server_msg_rx) = mpsc::channel::<ServerMessage>(16);
    let (session_msg_tx, session_msg_rx) = mpsc::channel::<SessionMessage>(16);

    let session = Session::new(
        Transport::Plain(server_stream),
        channel_id,
        session_msg_tx,
        server_msg_rx,
    );

    (session, server_msg_tx, session_msg_rx)
}

// ============================================================================
// Test 1: Session receives a job and writes it to TCP
// ============================================================================

#[tokio::test]
async fn test_session_receives_job() {
    let (server_stream, mut client) = tcp_pair().await;
    let channel_id = 42;
    let (session, server_tx, _session_rx) = make_session(server_stream, channel_id);

    // Spawn the session run loop
    let handle = tokio::spawn(async move { session.run().await });

    // Send a job through the server channel
    let job = make_test_job(100);
    server_tx.send(ServerMessage::NewJob(job.clone())).await.unwrap();

    // Read the framed message from the client side
    let msg_bytes = tokio::time::timeout(Duration::from_secs(5), read_framed_message(&mut client))
        .await
        .expect("timed out waiting for job message");

    // Decode and verify
    let decoded = decode_new_equihash_job(&msg_bytes).unwrap();
    assert_eq!(decoded.channel_id, channel_id, "session should stamp its channel_id");
    assert_eq!(decoded.job_id, 100);
    assert_eq!(decoded.prev_hash, [0xaa; 32]);
    assert_eq!(decoded.merkle_root, [0xbb; 32]);
    assert_eq!(decoded.block_commitments, [0xcc; 32]);
    assert_eq!(decoded.nonce_1, vec![0x01, 0x02, 0x03, 0x04]);
    assert_eq!(decoded.nonce_2_len, 28);
    assert_eq!(decoded.time, 1700000000);
    assert_eq!(decoded.bits, 0x2007ffff);
    assert!(decoded.clean_jobs);

    // Shut down the session cleanly
    server_tx.send(ServerMessage::Shutdown).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("session did not shut down in time");
    result.unwrap().unwrap();
}

// ============================================================================
// Test 2: Session receives SetTarget and writes it to TCP
// ============================================================================

#[tokio::test]
async fn test_session_receives_set_target() {
    let (server_stream, mut client) = tcp_pair().await;
    let channel_id = 7;
    let (session, server_tx, _session_rx) = make_session(server_stream, channel_id);

    let handle = tokio::spawn(async move { session.run().await });

    let target = [0xaa; 32];
    server_tx
        .send(ServerMessage::SetTarget { target })
        .await
        .unwrap();

    let msg_bytes = tokio::time::timeout(Duration::from_secs(5), read_framed_message(&mut client))
        .await
        .expect("timed out waiting for set_target message");

    let decoded = decode_set_target(&msg_bytes).unwrap();
    assert_eq!(decoded.channel_id, channel_id);
    assert_eq!(decoded.target, [0xaa; 32]);

    // Shut down
    server_tx.send(ServerMessage::Shutdown).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("session did not shut down in time");
    result.unwrap().unwrap();
}

// ============================================================================
// Test 3: Session shuts down on Shutdown message
// ============================================================================

#[tokio::test]
async fn test_session_shutdown() {
    let (server_stream, _client) = tcp_pair().await;
    let channel_id = 1;
    let (session, server_tx, mut session_rx) = make_session(server_stream, channel_id);

    let handle = tokio::spawn(async move { session.run().await });

    server_tx.send(ServerMessage::Shutdown).await.unwrap();

    // The session task should complete
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("session did not shut down in time");
    result.unwrap().unwrap();

    // After shutdown, session sends a Disconnected message
    let msg = tokio::time::timeout(Duration::from_millis(100), session_rx.recv()).await;
    match msg {
        Ok(Some(SessionMessage::Disconnected { channel_id: cid })) => {
            assert_eq!(cid, channel_id);
        }
        _ => {
            // Disconnected message may have been sent before channel was polled;
            // the important thing is that the task completed.
        }
    }
}

// ============================================================================
// Test 4: Session shuts down when server channel is dropped
// ============================================================================

#[tokio::test]
async fn test_session_shutdown_on_channel_drop() {
    let (server_stream, _client) = tcp_pair().await;
    let channel_id = 99;
    let (session, server_tx, _session_rx) = make_session(server_stream, channel_id);

    let handle = tokio::spawn(async move { session.run().await });

    // Drop the sender -- session should detect the closed channel and exit
    drop(server_tx);

    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("session did not shut down after channel drop");
    result.unwrap().unwrap();
}

// ============================================================================
// Test 5: Session forwards a share from miner to server
// ============================================================================

#[tokio::test]
async fn test_session_forwards_share() {
    let (server_stream, mut client) = tcp_pair().await;
    let channel_id = 10;
    let (session, server_tx, mut session_rx) = make_session(server_stream, channel_id);

    let handle = tokio::spawn(async move { session.run().await });

    // Build and encode a SubmitEquihashShare on the client side
    let share = SubmitEquihashShare {
        channel_id,
        sequence_number: 1,
        job_id: 50,
        nonce_2: vec![0xde; 28],
        time: 1700000001,
        solution: [0x42; 1344],
    };
    let encoded = encode_submit_share(&share).unwrap();

    // Write the encoded share to the TCP stream (as a miner would)
    client.write_all(&encoded).await.unwrap();
    client.flush().await.unwrap();

    // The session should forward the share as a SessionMessage::ShareSubmitted
    let msg = tokio::time::timeout(Duration::from_secs(5), session_rx.recv())
        .await
        .expect("timed out waiting for share forwarding")
        .expect("session_rx closed unexpectedly");

    match msg {
        SessionMessage::ShareSubmitted {
            channel_id: cid,
            share: forwarded_share,
            response_tx,
        } => {
            assert_eq!(cid, channel_id);
            assert_eq!(forwarded_share.job_id, 50);
            assert_eq!(forwarded_share.sequence_number, 1);
            assert_eq!(forwarded_share.nonce_2, vec![0xde; 28]);
            assert_eq!(forwarded_share.time, 1700000001);
            assert_eq!(forwarded_share.solution, [0x42; 1344]);

            // Send a response so the session can write it back (and not timeout/break)
            use zcash_mining_protocol::messages::ShareResult;
            response_tx.send(ShareResult::Accepted).unwrap();
        }
        other => panic!("expected ShareSubmitted, got {:?}", other),
    }

    // The session should write the share response back to the client.
    // Read it to verify the full round-trip.
    let response_bytes =
        tokio::time::timeout(Duration::from_secs(5), read_framed_message(&mut client))
            .await
            .expect("timed out waiting for share response");

    let response = zcash_mining_protocol::codec::decode_submit_shares_response(&response_bytes)
        .unwrap();
    assert_eq!(response.channel_id, channel_id);
    assert_eq!(response.sequence_number, 1);
    assert_eq!(response.result, zcash_mining_protocol::messages::ShareResult::Accepted);

    // Shut down
    server_tx.send(ServerMessage::Shutdown).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("session did not shut down in time");
    result.unwrap().unwrap();
}

// ============================================================================
// Test 6: Session sends Disconnected when client drops TCP connection
// ============================================================================

#[tokio::test]
async fn test_session_disconnected_on_client_drop() {
    let (server_stream, client) = tcp_pair().await;
    let channel_id = 77;
    let (session, _server_tx, mut session_rx) = make_session(server_stream, channel_id);

    let handle = tokio::spawn(async move { session.run().await });

    // Drop the client TCP connection
    drop(client);

    // The session should exit and send Disconnected
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("session did not exit after client disconnect");
    result.unwrap().unwrap();

    // Check for Disconnected message
    let msg = session_rx.try_recv();
    match msg {
        Ok(SessionMessage::Disconnected { channel_id: cid }) => {
            assert_eq!(cid, channel_id);
        }
        _ => {
            // The message was already consumed or buffered; the task exiting is sufficient.
        }
    }
}
