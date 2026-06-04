//! Integration tests for the JDC downstream listener (Task 5).
//!
//! These drive a raw tokio `TcpStream` as the fake translator proxy: they bind
//! the listener on an ephemeral port, push declared jobs into the shared state,
//! and assert on the `NewEquihashJob` / `SubmitSharesResponse` frames that come
//! back over the wire.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use zcash_jd_client::block_submitter::BlockSubmitter;
use zcash_jd_client::declared_job::{CurrentDeclaredJob, DeclaredJobState};
use zcash_jd_client::listener::{RelayShare, run_listener};
use zcash_mining_protocol::codec::{
    MessageFrame, decode_new_equihash_job, decode_submit_shares_response, encode_submit_share,
};
use zcash_mining_protocol::messages::{
    RejectReason, ShareResult, SubmitEquihashShare, message_types,
};

const SHARE_TARGET: [u8; 32] = [0x11; 32];

fn sample_job(job_id: u32) -> CurrentDeclaredJob {
    CurrentDeclaredJob {
        job_id,
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        time: 1_700_000_000,
        bits: 0x1d00_ffff,
        share_target: SHARE_TARGET,
        coinbase_tx: vec![0x01, 0x02, 0x03],
        transactions: vec![vec![0x04], vec![0x05]],
    }
}

/// Spawn the listener on an ephemeral port and return (addr, state, relay_rx,
/// push_rx). The listener task is detached; the OS reclaims the port on test
/// exit.
async fn spawn_listener() -> (
    std::net::SocketAddr,
    Arc<DeclaredJobState>,
    mpsc::Receiver<RelayShare>,
    mpsc::Receiver<RelayShare>,
) {
    // Bind first to grab a concrete port, then hand the addr to the listener.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let state = DeclaredJobState::new();
    let (relay_tx, relay_rx) = mpsc::channel(64);
    let (push_tx, push_rx) = mpsc::channel(8);
    let submitter = Arc::new(BlockSubmitter::new("http://127.0.0.1:1".to_string()));

    let state_clone = state.clone();
    tokio::spawn(async move {
        let _ = run_listener(addr, state_clone, relay_tx, push_tx, submitter).await;
    });

    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, state, relay_rx, push_rx)
}

/// Read exactly one complete protocol frame from the stream.
async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; MessageFrame::HEADER_SIZE];
    stream.read_exact(&mut header).await.unwrap();
    let frame = MessageFrame::decode(&header).unwrap();
    let mut payload = vec![0u8; frame.length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    let mut full = header.to_vec();
    full.extend(payload);
    full
}

/// Try to read a frame within `dur`; returns None on timeout.
async fn try_read_frame(stream: &mut TcpStream, dur: Duration) -> Option<Vec<u8>> {
    timeout(dur, read_frame(stream)).await.ok()
}

#[tokio::test]
async fn no_job_before_declaration() {
    let (addr, _state, _relay, _push) = spawn_listener().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // No declared job yet: the proxy must receive nothing.
    let got = try_read_frame(&mut stream, Duration::from_millis(300)).await;
    assert!(got.is_none(), "expected no frame before any declaration");
}

#[tokio::test]
async fn job_broadcast_on_declaration() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // Declare a job after connect.
    state.set(sample_job(42)).await;

    let frame = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("expected a NewEquihashJob frame");
    let header = MessageFrame::decode(&frame).unwrap();
    assert_eq!(header.msg_type, message_types::NEW_EQUIHASH_JOB);

    let job = decode_new_equihash_job(&frame).unwrap();
    assert_eq!(job.job_id, 42);
    assert_eq!(job.target, SHARE_TARGET);
    assert!(job.clean_jobs);
    assert_eq!(job.nonce_2_len, 28);
    // nonce_1 + nonce_2 must sum to 32.
    assert_eq!(job.nonce_1.len() + job.nonce_2_len as usize, 32);
    assert!(job.validate_nonce_len());
}

#[tokio::test]
async fn job_update_rebroadcast() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    state.set(sample_job(1)).await;
    let first = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("first job");
    let first_job = decode_new_equihash_job(&first).unwrap();
    assert_eq!(first_job.job_id, 1);

    // Update the job: a second NewEquihashJob must arrive.
    state.set(sample_job(2)).await;
    let second = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("second job");
    let second_job = decode_new_equihash_job(&second).unwrap();
    assert_eq!(second_job.job_id, 2);
}

#[tokio::test]
async fn job_served_on_connect_when_already_declared() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    // Declare BEFORE the proxy connects.
    state.set(sample_job(99)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let frame = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("job on connect");
    let job = decode_new_equihash_job(&frame).unwrap();
    assert_eq!(job.job_id, 99);
}

/// Build a SubmitEquihashShare with a given job_id, nonce_2 length, and garbage
/// solution distinguished by `tag` so dedup keys differ.
fn make_share(channel_id: u32, seq: u32, job_id: u32, nonce_2_len: usize, tag: u8) -> Vec<u8> {
    let mut solution = [0u8; 1344];
    solution[0] = tag;
    let share = SubmitEquihashShare {
        channel_id,
        sequence_number: seq,
        job_id,
        nonce_2: vec![tag; nonce_2_len],
        time: 1_700_000_000,
        solution,
    };
    encode_submit_share(&share).unwrap()
}

/// Connect, get the served job, and return (stream, channel_id) ready to submit.
async fn connect_with_job(
    addr: std::net::SocketAddr,
    state: &Arc<DeclaredJobState>,
    job_id: u32,
) -> (TcpStream, u32) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    state.set(sample_job(job_id)).await;
    let frame = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("job frame");
    let job = decode_new_equihash_job(&frame).unwrap();
    (stream, job.channel_id)
}

#[tokio::test]
async fn stale_job_share_rejected() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let (mut stream, channel_id) = connect_with_job(addr, &state, 10).await;

    // Submit for a different job_id -> StaleJob.
    let bytes = make_share(channel_id, 1, 999, 28, 0x01);
    stream.write_all(&bytes).await.unwrap();

    let resp_frame = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("response");
    let resp = decode_submit_shares_response(&resp_frame).unwrap();
    assert_eq!(resp.sequence_number, 1);
    assert_eq!(resp.result, ShareResult::Rejected(RejectReason::StaleJob));
}

#[tokio::test]
async fn bad_nonce2_len_rejected() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let (mut stream, channel_id) = connect_with_job(addr, &state, 11).await;

    // nonce_2 of 27 bytes (should be 28) -> Other("bad nonce_2 length").
    let bytes = make_share(channel_id, 7, 11, 27, 0x01);
    stream.write_all(&bytes).await.unwrap();

    let resp_frame = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("response");
    let resp = decode_submit_shares_response(&resp_frame).unwrap();
    assert_eq!(resp.sequence_number, 7);
    match resp.result {
        ShareResult::Rejected(RejectReason::Other(msg)) => {
            assert!(msg.contains("nonce_2"), "unexpected msg: {}", msg);
        }
        other => panic!("expected Other reject, got {:?}", other),
    }
}

#[tokio::test]
async fn invalid_solution_rejected() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let (mut stream, channel_id) = connect_with_job(addr, &state, 12).await;

    // Correct job_id and nonce_2 length, but garbage solution -> InvalidSolution.
    let bytes = make_share(channel_id, 3, 12, 28, 0x01);
    stream.write_all(&bytes).await.unwrap();

    let resp_frame = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("response");
    let resp = decode_submit_shares_response(&resp_frame).unwrap();
    assert_eq!(resp.sequence_number, 3);
    assert_eq!(
        resp.result,
        ShareResult::Rejected(RejectReason::InvalidSolution)
    );
}

#[tokio::test]
async fn duplicate_share_rejected() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let (mut stream, channel_id) = connect_with_job(addr, &state, 13).await;

    // First submission: garbage solution -> InvalidSolution (but the key is
    // registered before verify, per the register-before-verify rule).
    let bytes = make_share(channel_id, 1, 13, 28, 0x05);
    stream.write_all(&bytes).await.unwrap();
    let r1 = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("first response");
    let resp1 = decode_submit_shares_response(&r1).unwrap();
    assert_eq!(
        resp1.result,
        ShareResult::Rejected(RejectReason::InvalidSolution)
    );

    // Resubmit the byte-identical share -> Duplicate (caught before verify).
    let bytes2 = make_share(channel_id, 2, 13, 28, 0x05);
    stream.write_all(&bytes2).await.unwrap();
    let r2 = try_read_frame(&mut stream, Duration::from_secs(2))
        .await
        .expect("second response");
    let resp2 = decode_submit_shares_response(&r2).unwrap();
    assert_eq!(resp2.sequence_number, 2);
    assert_eq!(resp2.result, ShareResult::Rejected(RejectReason::Duplicate));
}

#[tokio::test]
async fn unexpected_message_type_ignored() {
    let (addr, state, _relay, _push) = spawn_listener().await;
    let (mut stream, _channel_id) = connect_with_job(addr, &state, 14).await;

    // Send a NewEquihashJob (a pool->miner message) upstream-wise: the listener
    // accepts only SUBMIT_EQUIHASH_SHARE and must ignore this with no response.
    let bogus = MessageFrame {
        extension_type: 0,
        msg_type: message_types::SET_TARGET,
        length: 0,
    };
    let mut bytes = bogus.encode().to_vec();
    // length 0 -> no payload
    stream.write_all(&bytes).await.unwrap();
    bytes.clear();

    let got = try_read_frame(&mut stream, Duration::from_millis(300)).await;
    assert!(got.is_none(), "listener must not respond to ignored types");
}

// =============================================================================
// DELIBERATE COVERAGE GAP: the accept/relay path, the LowDifficulty rejection
// path, and the block-submission path are NOT exercised here. All three require
// a structurally valid Equihash solution (the accept/relay path needs a hash at
// or under the share target; LowDifficulty needs a structurally valid solution
// whose hash sits above the share target; the block path needs a hash under the
// block target too). No valid-Equihash-solution fixture exists in this suite —
// the only way to produce one is a real CPU solver. All three are covered by
// Task 7's full-chain integration test. The tests above cover every rejection
// and broadcast path reachable without a valid solution.
// =============================================================================
