//! #130 PR B characterization, by direct calls: no socket, no sleep. The client has no
//! chunk marks. What it keeps is the delivery record, written when a payload enters
//! the channel. `pending` is a plain map here, and clearing it stands for the expiry
//! the run loop applies to it. A `known_gap_` test pins what the code does today: it
//! passes because the gap is open, and is not a behaviour to preserve.
use crate::ChunkHeader;
use crate::segmented_block::{segment_object_hash, split_raw_block};
use crate::transport::RelaySession;

use super::*;

type Pending = HashMap<[u8; 32], (BlockAssembly, usize)>;
type Delivered = HashMap<[u8; 32], Instant>;

const KEY: [u8; 32] = [0x42; 32];
/// `MAX_PENDING_BLOCKS_CLIENT`.
const PENDING_LIMIT: u8 = 64;

struct Receiver {
    client: RelayClient,
    payloads: mpsc::Receiver<RelayPayload>,
    pending: Pending,
    delivered: Delivered,
}

impl Receiver {
    fn new() -> Self {
        let config =
            ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], KEY).with_fec(10, 3);
        let mut client = RelayClient::new(config).unwrap();
        let (tx, payloads) = mpsc::channel(8);
        client.incoming_tx = Some(tx);
        Self {
            client,
            payloads,
            pending: HashMap::new(),
            delivered: HashMap::new(),
        }
    }

    async fn feed(&mut self, chunks: &[Vec<u8>]) {
        for bytes in chunks {
            let chunk = Chunk::from_bytes(bytes).unwrap();
            self.client
                .handle_incoming_chunk(chunk, &mut self.pending, &mut self.delivered)
                .await;
        }
    }

    /// Everything delivered so far. `feed` returns only after each send has finished.
    fn taken(&mut self) -> Vec<RawBlockSegment> {
        let mut segments = Vec::new();
        while let Ok(payload) = self.payloads.try_recv() {
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected a raw segment, got {other:?}"),
            }
        }
        segments
    }
}

fn segment() -> RawBlockSegment {
    split_raw_block([0x31; 32], &[0xcd; 9000], 11_236)
        .unwrap()
        .remove(0)
}

fn object_id(segment: &RawBlockSegment) -> [u8; 32] {
    segment_object_hash(segment.block_hash, segment.segment_index)
}

fn wire(receiver: &Receiver, segment: &RawBlockSegment) -> Vec<Vec<u8>> {
    let session = RelaySession::new("0.0.0.0:0".parse().unwrap(), "test", KEY);
    receiver
        .client
        .chunker
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

#[tokio::test]
async fn a_client_takes_the_chunks_again_after_losing_an_assembly() {
    let mut receiver = Receiver::new();
    let segment = segment();
    let chunks = wire(&receiver, &segment);

    receiver.feed(&chunks[..9]).await;
    assert!(receiver.taken().is_empty());
    assert_eq!(receiver.pending.len(), 1);

    receiver.pending.clear();

    receiver.feed(&chunks).await;
    assert_eq!(receiver.taken(), vec![segment]);
}

#[tokio::test]
async fn a_client_takes_a_chunk_it_had_no_room_for_once_there_is_room() {
    let mut receiver = Receiver::new();
    let segment = segment();
    let chunks = wire(&receiver, &segment);
    for i in 0..PENDING_LIMIT {
        let assembly = BlockAssembly::new_for_message([i; 32], 13, MessageType::RawBlockSegment);
        receiver.pending.insert([i; 32], (assembly, 0));
    }

    receiver.feed(&chunks).await;
    assert!(receiver.taken().is_empty());
    assert!(!receiver.pending.contains_key(&object_id(&segment)));

    receiver.pending.clear();

    receiver.feed(&chunks).await;
    assert_eq!(receiver.taken(), vec![segment]);
}

/// The record says the payload entered the channel. It does not say the sidecar
/// still holds it, so a repeat is refused either way until the record is 120 seconds
/// old. This does not show a repeat ever comes: a sender has to send one.
#[tokio::test]
async fn known_gap_a_delivered_object_is_refused_until_its_record_expires() {
    let mut receiver = Receiver::new();
    let segment = segment();
    let chunks = wire(&receiver, &segment);

    receiver.feed(&chunks).await;
    assert_eq!(receiver.taken(), vec![segment.clone()]);

    receiver.feed(&chunks).await;
    assert!(receiver.taken().is_empty(), "the repeat is refused");
    assert!(receiver.pending.is_empty(), "nothing is even assembled");

    let past = Instant::now() - RECENT_DELIVERED_TTL - Duration::from_secs(1);
    receiver.delivered.insert(object_id(&segment), past);

    receiver.feed(&chunks).await;
    assert_eq!(receiver.taken(), vec![segment]);
}
