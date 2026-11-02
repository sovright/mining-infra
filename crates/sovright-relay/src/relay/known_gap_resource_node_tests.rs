//! #130 PR B characterization, by direct calls: no socket read, no sleep. A chunk's
//! replay mark and its assembly do not end together. A `known_gap_` test pins what the
//! code does today: it passes because the gap is open, and is not a behaviour to
//! preserve. `cleanup_expired_sessions` here is the same call the run loop makes.
use crate::compact_block::{CompactBlock, PrefilledTx};
use crate::{ChunkHeader, StubPowValidator};

use super::*;

const KEY: [u8; 32] = [0x42; 32];
const OBJECT: [u8; 32] = [0xab; 32];
/// `MAX_PENDING_BLOCKS` in `transport/session.rs`.
const PENDING_LIMIT: u8 = 64;

fn peer(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Assemblies expire at the first cleanup, so a test needs no clock. Marks keep
/// their own fixed 120 second lifetime.
async fn node() -> RelayNode<StubPowValidator> {
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
        .with_fec(10, 3)
        .with_timeouts(Duration::from_secs(600), Duration::ZERO);
    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
    node.bind().await.unwrap();
    node
}

fn object(node: &RelayNode<StubPowValidator>, id: [u8; 32], fill: u8) -> Vec<Vec<u8>> {
    let compact = CompactBlock::new(
        vec![fill; 2189],
        0,
        Vec::new(),
        vec![PrefilledTx {
            index: 0,
            tx_data: vec![fill; 400],
        }],
    );
    let session = RelaySession::new(peer(1), "test", KEY);
    node.chunker
        .compact_block_to_chunks(&compact, &id)
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
            let header = ChunkHeader::new_block_authenticated(
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

async fn send(node: &RelayNode<StubPowValidator>, from: SocketAddr, datagrams: &[Vec<u8>]) {
    for datagram in datagrams {
        node.handle_packet(datagram, from).await.unwrap();
    }
}

/// Chunks held for `OBJECT` in `from`'s session, and whether it was validated.
async fn held(node: &RelayNode<StubPowValidator>, from: SocketAddr) -> Option<(usize, bool)> {
    let sessions = node.sessions.read().await;
    let assembly = sessions.get(&from)?.pending_blocks.get(&OBJECT)?;
    Some((assembly.received_count(), assembly.pow_validated))
}

/// Nine of the ten needed chunks, the assembly expires, and every chunk comes again
/// from the same session. The nine are refused as repeats although nothing holds them.
#[tokio::test]
async fn known_gap_marks_outlive_an_expired_assembly() {
    let node = node().await;
    let sender = peer(4001);
    let chunks = object(&node, OBJECT, 0x11);
    assert_eq!(chunks.len(), 13);

    send(&node, sender, &chunks[..9]).await;
    assert_eq!(held(&node, sender).await, Some((9, false)));

    node.cleanup_expired_sessions().await;
    assert_eq!(held(&node, sender).await, None, "the assembly is gone");

    send(&node, sender, &chunks).await;
    assert_eq!(
        held(&node, sender).await,
        Some((4, false)),
        "only the four chunks never seen are taken, and ten are needed"
    );

    // Another session has no marks, so the same datagrams rebuild the object.
    let other = peer(4002);
    send(&node, other, &chunks).await;
    assert_eq!(held(&node, other).await, Some((13, true)));
}

/// The session's table is full, so the object gets no assembly, but its marks are
/// written first. Room comes back and nothing of the object is taken.
#[tokio::test]
async fn known_gap_a_chunk_refused_for_room_stays_marked() {
    let node = node().await;
    let sender = peer(4003);
    for i in 0..PENDING_LIMIT {
        let filler = object(&node, [i; 32], i);
        send(&node, sender, &filler[..1]).await;
    }
    let chunks = object(&node, OBJECT, 0x22);

    send(&node, sender, &chunks).await;
    assert_eq!(held(&node, sender).await, None, "no room for the object");

    node.cleanup_expired_sessions().await;
    send(&node, sender, &chunks).await;
    assert_eq!(
        held(&node, sender).await,
        None,
        "the table has room, and every chunk is refused as a repeat"
    );

    let other = peer(4004);
    send(&node, other, &chunks).await;
    assert_eq!(held(&node, other).await, Some((13, true)));
}
