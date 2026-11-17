//! #130 PR B characterization: what today's parser, node and client do with the
//! chunk layout the design draft proposes. The bytes are built by hand here. No such
//! format exists in this crate, and these tests are not a specification of one.
//! They run against this tree, which is not known to be what a live fleet runs.

use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{
    AuthKey, BlockChunker, BlockReceiver, Chunk, ChunkHeader, ClientConfig, RawBlockSegment,
    RelayClient, RelayConfig, RelayNode, RelayPayload, RelaySession, ZCASH_FULL_HEADER_SIZE,
    split_raw_block, zcash_block_hash,
};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use zcash_pool_common::fixtures;

const KEY: [u8; 32] = [0x42; 32];
const FRAME_BYTES: usize = 10 * 1124 - 4;

fn segments() -> Vec<RawBlockSegment> {
    let raw = fixtures::mainnet_raw_block();
    let hash = zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]);
    split_raw_block(hash, &raw, FRAME_BYTES).unwrap()
}

fn chunks(segment: &RawBlockSegment) -> Vec<Chunk> {
    BlockChunker::new(10, 3)
        .unwrap()
        .raw_block_segment_to_chunks(segment)
        .unwrap()
}

/// A valid chunk with only its version byte changed.
fn version_4_in_todays_layout(chunk: &Chunk) -> Vec<u8> {
    let mut bytes = chunk.to_bytes();
    bytes[4] = 4;
    bytes
}

/// The draft's layout: an 80 byte header with format and depth bytes, four 32 byte
/// proof nodes, then the payload. The field values are not meaningful.
fn draft_layout(chunk: &Chunk) -> Vec<u8> {
    let wire = chunk.to_bytes();
    let mut bytes = wire[..4].to_vec();
    bytes.extend_from_slice(&[4, wire[5], 1, 4]);
    bytes.extend_from_slice(&[0x11; 32]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&[0x22; 32]);
    bytes.extend_from_slice(&[0x33; 128]);
    bytes.extend_from_slice(&chunk.payload);
    bytes
}

/// Authentic version 2 datagrams for one segment, as a session with `KEY` sends them.
fn signed_datagrams(session: &RelaySession, segment: &RawBlockSegment) -> Vec<Vec<u8>> {
    chunks(segment)
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

async fn send_all(socket: &UdpSocket, to: std::net::SocketAddr, datagrams: &[Vec<u8>]) {
    for datagram in datagrams {
        socket.send_to(datagram, to).await.unwrap();
    }
}

async fn next_segment(receiver: &mut BlockReceiver) -> RawBlockSegment {
    let payload = timeout(Duration::from_secs(10), receiver.recv_payload())
        .await
        .expect("the segment arrives")
        .expect("the receiver stays open");
    match payload {
        RelayPayload::RawBlockSegment(segment) => segment,
        other => panic!("expected a raw segment, got {other:?}"),
    }
}

#[test]
fn the_parser_refuses_version_4_and_message_type_5() {
    let chunk = chunks(&segments()[0]).remove(0);
    assert!(Chunk::from_bytes(&chunk.to_bytes()).is_ok());

    for bytes in [version_4_in_todays_layout(&chunk), draft_layout(&chunk)] {
        let error = Chunk::from_bytes(&bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported protocol version: 4"),
            "{error}"
        );
    }

    let mut new_type = chunk.to_bytes();
    new_type[5] = 5;
    let error = Chunk::from_bytes(&new_type).unwrap_err();
    assert!(
        error.to_string().contains("invalid message type: 5"),
        "{error}"
    );
}

/// From a session the node already holds: nothing is forwarded and the session
/// carries on. The received counter moves, so the cost is the packets themselves.
#[tokio::test]
async fn a_node_drops_the_new_version_and_keeps_the_session() {
    let segments = segments();
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
        .with_fec(10, 3);
    let mut node = RelayNode::new(config).unwrap();
    node.bind().await.unwrap();
    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let running = Arc::clone(&node);
    let node_task = tokio::spawn(async move { running.run().await });
    sleep(Duration::from_millis(50)).await;

    let mut client = RelayClient::new(
        ClientConfig::new(vec![node_addr], KEY)
            .with_auth_required(true)
            .with_fec(10, 3),
    )
    .unwrap();
    client.bind().await.unwrap();
    let (mut receiver, outgoing) = client.take_receiver().unwrap();
    let client_task = tokio::spawn(async move { client.run_with_outgoing(outgoing).await });
    sleep(Duration::from_millis(200)).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session = RelaySession::new(node_addr, "test", KEY);

    send_all(&peer, node_addr, &signed_datagrams(&session, &segments[0])).await;
    assert_eq!(next_segment(&mut receiver).await.segment_index, 0);
    // The chunks after the k-th are forwarded as well: let them all finish.
    let settled = |node: &RelayNode| node.metrics().snapshot().packets_received;
    let mut received = settled(&node);
    loop {
        sleep(Duration::from_millis(100)).await;
        let now = settled(&node);
        if now == received {
            break;
        }
        received = now;
    }
    let before = node.metrics().snapshot();

    let refused: Vec<Vec<u8>> = chunks(&segments[1])
        .iter()
        .flat_map(|chunk| [version_4_in_todays_layout(chunk), draft_layout(chunk)])
        .collect();
    send_all(&peer, node_addr, &refused).await;
    let expected = before.packets_received + refused.len() as u64;
    timeout(Duration::from_secs(5), async {
        while node.metrics().snapshot().packets_received < expected {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the node reads every datagram");
    assert_eq!(
        node.metrics().snapshot().packets_forwarded,
        before.packets_forwarded,
        "nothing of the new version is forwarded"
    );

    send_all(&peer, node_addr, &signed_datagrams(&session, &segments[1])).await;
    assert_eq!(next_segment(&mut receiver).await.segment_index, 1);

    node.stop();
    client_task.abort();
    let _ = node_task.await;
}

/// What a current relay would do to a client that has not been upgraded: it reads
/// and drops the new version, and the next object is delivered once.
#[tokio::test]
async fn a_client_ignores_the_new_version_and_delivers_the_next_object() {
    let segments = segments();
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
    sleep(Duration::from_millis(100)).await;

    let refused: Vec<Vec<u8>> = chunks(&segments[1])
        .iter()
        .flat_map(|chunk| [version_4_in_todays_layout(chunk), draft_layout(chunk)])
        .collect();
    send_all(&peer, client_addr, &refused).await;

    let session = RelaySession::new(peer_addr, "test", KEY);
    send_all(
        &peer,
        client_addr,
        &signed_datagrams(&session, &segments[0]),
    )
    .await;

    assert_eq!(next_segment(&mut receiver).await.segment_index, 0);
    assert!(
        timeout(Duration::from_millis(300), receiver.recv_payload())
            .await
            .is_err(),
        "nothing else is delivered"
    );
    client_task.abort();
}
