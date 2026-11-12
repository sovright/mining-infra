//! #130 PR B characterization: an incomplete set evicted from the raw segment buffer,
//! while the client still records its segments as delivered. A `known_gap_` test pins
//! what the code does today: it passes because the gap is open, and is not a behaviour
//! to preserve. That the client refuses a repeat is shown by direct calls in
//! `relay/known_gap_resource_client_tests.rs`. The test here adds the real buffer.
use std::net::SocketAddr;

use sovright_relay::{
    BlockChunker, BlockReceiver, Chunk, ChunkHeader, ClientConfig, RelayClient, RelayPayload,
    RelaySession, split_raw_block,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::*;

const KEY: [u8; 32] = [0x42; 32];
/// Ten data shards of the largest fixed-profile payload, less the length prefix.
const FRAME_BYTES: usize = 10 * 1124 - 4;
const A: [u8; 32] = [0xa1; 32];
const B: [u8; 32] = [0xb2; 32];
const C: [u8; 32] = [0xc3; 32];

fn segments(hash: [u8; 32], fill: u8) -> Vec<RawBlockSegment> {
    let raw = vec![fill; 15_000];
    let segments = split_raw_block(hash, &raw, FRAME_BYTES).unwrap();
    assert_eq!(segments.len(), 2);
    segments
}

/// One incomplete set at a time, so the second set evicts the first. The default is
/// 128; this is the smallest way to reach the same eviction.
fn one_set_buffer() -> RawSegmentBuffer {
    RawSegmentBuffer::new(
        RawSegmentBufferConfig::new(1, 64 * 1024 * 1024, Duration::from_secs(120)).unwrap(),
    )
}

fn insert(buffer: &mut RawSegmentBuffer, segment: RawBlockSegment) -> RawSegmentInsert {
    buffer.insert(segment, Instant::now())
}

/// The buffer alone: after eviction the set needs every segment again.
#[test]
fn an_evicted_set_needs_every_segment_again() {
    let (a, b) = (segments(A, 1), segments(B, 2));
    let mut buffer = one_set_buffer();
    assert!(matches!(
        insert(&mut buffer, a[0].clone()),
        RawSegmentInsert::Pending
    ));
    assert!(matches!(
        insert(&mut buffer, b[0].clone()),
        RawSegmentInsert::Pending
    ));
    assert!(!buffer.entries.contains_key(&A), "the older set is evicted");

    assert!(matches!(
        insert(&mut buffer, a[1].clone()),
        RawSegmentInsert::Pending
    ));
    let RawSegmentInsert::Complete { segments, .. } = insert(&mut buffer, a[0].clone()) else {
        panic!("the set completes once both segments are back");
    };
    assert_eq!(reassemble_raw_block(&segments).unwrap(), vec![1; 15_000]);
}

fn signed(session: &RelaySession, segment: &RawBlockSegment) -> Vec<Vec<u8>> {
    BlockChunker::new(10, 3)
        .unwrap()
        .raw_block_segment_to_chunks(segment)
        .unwrap()
        .into_iter()
        .map(|chunk| {
            let h = &chunk.header;
            let mac = session.compute_hmac(
                &h.block_hash,
                h.chunk_id,
                h.total_chunks,
                h.payload_len,
                &chunk.payload,
            );
            let header = ChunkHeader::new_raw_block_segment_authenticated(
                &h.block_hash,
                h.chunk_id,
                h.total_chunks,
                h.payload_len,
                mac,
            );
            Chunk::new(header, chunk.payload).to_bytes()
        })
        .collect()
}

async fn send(peer: &UdpSocket, to: SocketAddr, session: &RelaySession, segment: &RawBlockSegment) {
    for datagram in signed(session, segment) {
        peer.send_to(&datagram, to).await.unwrap();
    }
}

async fn next_segment(receiver: &mut BlockReceiver) -> RawBlockSegment {
    match timeout(Duration::from_secs(10), receiver.recv_payload()).await {
        Ok(Some(RelayPayload::RawBlockSegment(segment))) => segment,
        other => panic!("expected a raw segment, got {other:?}"),
    }
}

/// Integration evidence on a real client over loopback, not proof of an order. The
/// positive steps wait on delivery. The claim that a segment did not come rests on a
/// later object from the same socket, which assumes loopback keeps its order.
#[tokio::test]
async fn known_gap_an_evicted_set_is_not_rebuilt_through_the_client() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut client = RelayClient::new(
        ClientConfig::new(vec![peer_addr], KEY)
            .with_bind_addr("127.0.0.1:0".parse().unwrap())
            .with_auth_required(true)
            .with_fec(10, 3),
    )
    .unwrap();
    client.bind().await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let (mut receiver, outgoing) = client.take_receiver().unwrap();
    let client_task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
    let session = RelaySession::new(peer_addr, "test", KEY);

    let (a, b, c) = (segments(A, 1), segments(B, 2), segments(C, 3));
    let mut buffer = one_set_buffer();

    send(&peer, client_addr, &session, &a[0]).await;
    let first = next_segment(&mut receiver).await;
    assert_eq!(first, a[0]);
    assert!(matches!(
        insert(&mut buffer, first),
        RawSegmentInsert::Pending
    ));

    send(&peer, client_addr, &session, &b[0]).await;
    let other = next_segment(&mut receiver).await;
    assert_eq!(other, b[0]);
    assert!(matches!(
        insert(&mut buffer, other),
        RawSegmentInsert::Pending
    ));
    assert!(!buffer.entries.contains_key(&A), "the set is evicted");

    // Every segment of the evicted set again, then an object of another block.
    send(&peer, client_addr, &session, &a[0]).await;
    send(&peer, client_addr, &session, &a[1]).await;
    send(&peer, client_addr, &session, &c[0]).await;

    let repeated = next_segment(&mut receiver).await;
    assert_eq!(
        repeated, a[1],
        "the segment the set is missing did not come"
    );
    assert_eq!(next_segment(&mut receiver).await, c[0]);

    assert!(matches!(
        insert(&mut buffer, repeated),
        RawSegmentInsert::Pending
    ));
    let entry = buffer.entries.get(&A).expect("the set opens again");
    assert!(entry.segments[0].is_none(), "and it can never complete");

    client_task.abort();
}
