//! #130 PR B characterization: a forged raw segment that claims the real body's
//! digest, length and count (S10). A `known_gap_` test pins what the code does
//! today: it passes because the gap is open, and is not a behaviour to preserve.
use std::net::SocketAddr;

use sovright_relay::{
    AuthKey, BlockReceiver, BlockSender, ClientConfig, CompactBlock, PrefilledTx, RelayClient,
    RelayConfig, RelayNode, RelayPayload, SegmentedBlockError, TransportError, split_raw_block,
};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

use super::*;

const KEY: [u8; 32] = [0x42; 32];
/// Ten data shards of the largest fixed-profile payload, less the length prefix.
const FRAME_BYTES: usize = 10 * 1124 - 4;

fn real_block() -> Vec<u8> {
    fixtures::mainnet_raw_block()
}

fn real_hash() -> [u8; 32] {
    zcash_block_hash(&real_block()[..ZCASH_FULL_HEADER_SIZE])
}

fn real_segments() -> Vec<RawBlockSegment> {
    let segments = split_raw_block(real_hash(), &real_block(), FRAME_BYTES).unwrap();
    assert!(segments.len() > 1);
    segments
}

/// The last segment of another body of this block. Its own payload digest holds,
/// and it claims the real body's digest, length and count, so nothing ahead of
/// reassembly can tell it from the real one.
fn forged_last_segment(real: &[RawBlockSegment]) -> RawBlockSegment {
    let mut other = real_block();
    *other.last_mut().unwrap() ^= 0x01;
    let mut forged = split_raw_block(real_hash(), &other, FRAME_BYTES)
        .unwrap()
        .pop()
        .unwrap();
    let last = real.last().unwrap();
    assert_eq!(forged.segment_index, last.segment_index);
    assert_eq!(forged.segment_count, last.segment_count);
    assert_eq!(forged.raw_block_len, last.raw_block_len);
    assert_ne!(forged.payload, last.payload);
    forged.raw_block_digest = last.raw_block_digest;
    forged
}

fn buffer() -> RawSegmentBuffer {
    RawSegmentBuffer::new(
        RawSegmentBufferConfig::new(128, 64 * 1024 * 1024, Duration::from_secs(120)).unwrap(),
    )
}

fn insert_all(
    buffer: &mut RawSegmentBuffer,
    segments: &[RawBlockSegment],
) -> Option<Vec<RawBlockSegment>> {
    segments.iter().find_map(
        |segment| match buffer.insert(segment.clone(), Instant::now()) {
            RawSegmentInsert::Complete { segments, .. } => Some(segments),
            RawSegmentInsert::Pending => None,
            RawSegmentInsert::Dropped { reason } => panic!("dropped: {reason}"),
        },
    )
}

#[test]
fn known_gap_a_forged_segment_takes_the_slot_and_fails_the_set() {
    let real = real_segments();
    let mut buffer = buffer();
    assert!(matches!(
        buffer.insert(forged_last_segment(&real), Instant::now()),
        RawSegmentInsert::Pending
    ));

    let complete = insert_all(&mut buffer, &real).expect("the set completes");

    assert_eq!(
        reassemble_raw_block(&complete),
        Err(SegmentedBlockError::DigestMismatch)
    );

    // The buffer itself would recover: the failed set is gone, and the real
    // segments alone reassemble. What stops that on a relay is the next test.
    let complete = insert_all(&mut buffer, &real).expect("the real set completes alone");
    assert_eq!(reassemble_raw_block(&complete).unwrap(), real_block());
}

async fn start_node() -> (
    Arc<RelayNode>,
    SocketAddr,
    JoinHandle<Result<(), TransportError>>,
) {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
        .with_fec(10, 3);
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let running = Arc::clone(&node);
    let task = tokio::spawn(async move { running.run().await });
    sleep(Duration::from_millis(50)).await;
    (node, addr, task)
}

fn client_config(node: SocketAddr) -> ClientConfig {
    ClientConfig::new(vec![node], KEY)
        .with_auth_required(true)
        .with_fec(10, 3)
}

async fn start_sender(node: SocketAddr) -> (BlockSender, JoinHandle<Result<(), TransportError>>) {
    let mut client = RelayClient::new(client_config(node)).unwrap();
    client.bind().await.unwrap();
    let sender = client.sender();
    let task = tokio::spawn(async move { client.run().await });
    (sender, task)
}

async fn start_receiver(
    node: SocketAddr,
) -> (BlockReceiver, JoinHandle<Result<(), TransportError>>) {
    let mut client = RelayClient::new(client_config(node)).unwrap();
    client.bind().await.unwrap();
    let (receiver, outgoing) = client.take_receiver().unwrap();
    let task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
    (receiver, task)
}

async fn next_payload(receiver: &mut BlockReceiver) -> RelayPayload {
    timeout(Duration::from_secs(10), receiver.recv_payload())
        .await
        .expect("the payload crosses the relay")
        .expect("the receiver stays open")
}

async fn next_segment(receiver: &mut BlockReceiver) -> RawBlockSegment {
    match next_payload(receiver).await {
        RelayPayload::RawBlockSegment(segment) => segment,
        other => panic!("expected a raw segment, got {other:?}"),
    }
}

/// An object of another kind on the real header, sent after the segments. The
/// client hands payloads over in order, so anything that crossed comes before it.
fn marker() -> CompactBlock {
    CompactBlock::new(
        fixtures::mainnet_serialized_header(),
        0,
        Vec::new(),
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![0xee; 64],
        }],
    )
}

async fn segments_before_marker(receiver: &mut BlockReceiver) -> Vec<RawBlockSegment> {
    let mut segments = Vec::new();
    loop {
        match next_payload(receiver).await {
            RelayPayload::RawBlockSegment(segment) => segments.push(segment),
            _ => return segments,
        }
    }
}

/// A real node checking Equihash, a real receiving client over UDP loopback and the
/// sidecar's real buffer. The forger holds a fleet key, so its segment is authentic
/// at every step. The real last segment then never reaches the buffer, the set
/// fails, and a second honest sender cannot help while the client keeps those ids
/// as delivered. This covers the raw path only.
#[tokio::test]
async fn known_gap_a_forged_segment_costs_the_block_on_a_real_relay() {
    let real = real_segments();
    let last = real.len() - 1;
    let forged = forged_last_segment(&real);

    let (node, node_addr, node_task) = start_node().await;
    let (mut receiver, receiver_task) = start_receiver(node_addr).await;
    sleep(Duration::from_millis(200)).await;
    let (honest, honest_task) = start_sender(node_addr).await;
    let (forger, forger_task) = start_sender(node_addr).await;
    let (second, second_task) = start_sender(node_addr).await;
    sleep(Duration::from_millis(100)).await;

    // Segment 0 proves the header, which opens the block's other segments.
    honest
        .send_raw_block_segment(real[0].clone())
        .await
        .unwrap();
    let mut delivered = vec![next_segment(&mut receiver).await];

    forger.send_raw_block_segment(forged.clone()).await.unwrap();
    let arrived = next_segment(&mut receiver).await;
    assert_eq!(
        arrived.payload, forged.payload,
        "the node and the client have only the claims to go on"
    );
    delivered.push(arrived);

    for segment in &real[1..] {
        honest
            .send_raw_block_segment(segment.clone())
            .await
            .unwrap();
    }
    honest.send(marker()).await.unwrap();
    delivered.extend(segments_before_marker(&mut receiver).await);

    assert_eq!(delivered.len(), real.len(), "the real last segment is lost");
    assert_eq!(
        delivered
            .iter()
            .filter(|segment| segment.segment_index as usize == last)
            .map(|segment| &segment.payload)
            .collect::<Vec<_>>(),
        vec![&forged.payload]
    );
    let complete = insert_all(&mut buffer(), &delivered).expect("the set completes");
    assert_eq!(
        reassemble_raw_block(&complete),
        Err(SegmentedBlockError::DigestMismatch)
    );

    for segment in &real {
        second
            .send_raw_block_segment(segment.clone())
            .await
            .unwrap();
    }
    second.send_skeleton(marker()).await.unwrap();
    assert!(
        segments_before_marker(&mut receiver).await.is_empty(),
        "the marker crossed, so the relay is working and the client dropped the real copy"
    );

    node.stop();
    for task in [receiver_task, honest_task, forger_task, second_task] {
        task.abort();
    }
    let _ = node_task.await;
}
