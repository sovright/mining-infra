//! #130 PR B research harness: the delivery lease prototype beside the real raw segment
//! buffer. Test only. It wires nothing into the client, the sidecar's handler or the
//! wire, and the buffer is unchanged: the harness holds the leases and learns about
//! evictions by reading the buffer's entries after each insert.
//!
//! What a completed set means is left open. Nothing here calls `complete`. A block that
//! is rejected later has no decided way back, and these tests do not choose one.
//!
//! The ledger counts payload bytes as declared here. The buffer's slots and entries,
//! the queues and the allocator are outside that count.
//!
//! The ids here exist for these tests and must not move into production. A segment's is
//! its header hash and index, and a block's is that hash with its bits flipped. Neither
//! tells two bodies of one header apart, and `research/delivery-lease` has a buffer
//! that does.

#[path = "../../../research/delivery-lease/src/lib.rs"]
#[allow(dead_code, unexpected_cfgs)]
mod delivery_lease;

use delivery_lease::{
    Admission, DeliveryLedger, Lease, Limits, ObjectId, Phase, Refusal, Ticket, Transit,
};
use sovright_relay::split_raw_block;
use tokio::sync::{mpsc, oneshot};

use super::*;

/// Ten data shards of the largest fixed-profile payload, less the length prefix.
const FRAME_BYTES: usize = 10 * 1124 - 4;
const RAW_LEN: usize = 15_000;
const A: [u8; 32] = [0xa1; 32];
const B: [u8; 32] = [0xb2; 32];

fn limits() -> Limits {
    Limits {
        max_records: 32,
        max_live_owners: 32,
        max_reserved_bytes: 16 * RAW_LEN,
        repeat_budget: 2,
        completed_ttl: Duration::from_secs(120),
        released_ttl: Duration::from_secs(86_400),
        transit: Transit::default(),
    }
}

fn segments(hash: [u8; 32], fill: u8) -> Vec<RawBlockSegment> {
    let segments = split_raw_block(hash, &vec![fill; RAW_LEN], FRAME_BYTES).unwrap();
    assert_eq!(segments.len(), 2);
    segments
}

fn object_id(segment: &RawBlockSegment) -> ObjectId {
    let mut id = segment.block_hash;
    id[30..].copy_from_slice(&segment.segment_index.to_be_bytes());
    id
}

/// The assembled block's place in the ledger. No segment id can equal it here.
fn block_key(hash: [u8; 32]) -> ObjectId {
    hash.map(|byte| !byte)
}

/// A segment on its way, carried with its ownership. Fields drop in order, so the
/// payload goes before the bytes that count it come back.
struct Carried {
    segment: RawBlockSegment,
    ticket: Ticket,
}

fn deliver(ledger: &DeliveryLedger, segment: &RawBlockSegment, now: Instant) -> Option<Carried> {
    match ledger.admit(object_id(segment), segment.payload.len(), now) {
        Admission::Admitted(ticket) => Some(Carried {
            segment: segment.clone(),
            ticket,
        }),
        _ => None,
    }
}

enum Taken {
    Pending,
    Complete(Vec<RawBlockSegment>, Vec<Lease>),
    Dropped,
}

/// The buffer comes first, so on drop the payloads go before the leases counting them.
/// `probe` sits between them to show that order.
struct LeasedBuffer {
    buffer: RawSegmentBuffer,
    probe: Option<Probe>,
    leases: HashMap<[u8; 32], Vec<Lease>>,
}

impl LeasedBuffer {
    fn new(max_sets: usize) -> Self {
        let config =
            RawSegmentBufferConfig::new(max_sets, 64 * 1024 * 1024, Duration::from_secs(120));
        Self {
            buffer: RawSegmentBuffer::new(config.unwrap()),
            probe: None,
            leases: HashMap::new(),
        }
    }

    fn take(&mut self, carried: Carried, now: Instant) -> Taken {
        let Carried { segment, ticket } = carried;
        let lease = ticket.accept();
        let block = segment.block_hash;

        let result = self.buffer.insert(segment, now);

        let taken = match result {
            RawSegmentInsert::Pending => {
                self.leases.entry(block).or_default().push(lease);
                Taken::Pending
            }
            RawSegmentInsert::Dropped { .. } => {
                drop(lease);
                Taken::Dropped
            }
            RawSegmentInsert::Complete { segments, .. } => {
                let mut leases = self.leases.remove(&block).unwrap_or_default();
                leases.push(lease);
                Taken::Complete(segments, leases)
            }
        };
        self.release_evicted();
        taken
    }

    /// The buffer has already dropped these payloads.
    fn release_evicted(&mut self) {
        let entries = &self.buffer.entries;
        self.leases.retain(|block, _| entries.contains_key(block));
    }
}

/// One block and everything counted for it. Fields drop in order.
///
/// The segment leases stay after their payloads have gone. That keeps a copy of a
/// segment from being delivered again while the block is being judged, and it counts
/// those bytes twice for as long as they stay. This is a conservative choice for the
/// harness and not a decided policy; see `dropping_segment_leases_lets_copies_back`.
struct AssembledBlock {
    raw: Vec<u8>,
    probe: Option<Probe>,
    block_lease: Lease,
    segment_leases: Vec<Lease>,
    peak_reserved: usize,
}

/// The copy is reserved before it is made, because the segments and the block are both
/// alive while it runs. If it does not fit, both sides are given back.
fn assemble(
    ledger: &DeliveryLedger,
    segments: Vec<RawBlockSegment>,
    segment_leases: Vec<Lease>,
    now: Instant,
) -> Result<AssembledBlock, Refusal> {
    let first = &segments[0];
    let (key, raw_len) = (block_key(first.block_hash), first.raw_block_len as usize);
    let ticket = match ledger.admit(key, raw_len, now) {
        Admission::Admitted(ticket) => ticket,
        Admission::Refused(refusal) => {
            drop(segments);
            drop(segment_leases);
            return Err(refusal);
        }
        other => panic!("expected an admission, got {other:?}"),
    };
    let block_lease = ticket.accept();
    let raw = reassemble_raw_block(&segments).unwrap();
    let peak_reserved = ledger.snapshot().reserved_bytes;
    drop(segments);
    Ok(AssembledBlock {
        raw,
        probe: None,
        block_lease,
        segment_leases,
        peak_reserved,
    })
}

fn take_pending(buffer: &mut LeasedBuffer, carried: Carried, now: Instant) {
    assert!(matches!(buffer.take(carried, now), Taken::Pending));
}

fn take_last(
    buffer: &mut LeasedBuffer,
    carried: Carried,
    now: Instant,
) -> (Vec<RawBlockSegment>, Vec<Lease>) {
    match buffer.take(carried, now) {
        Taken::Complete(segments, leases) => (segments, leases),
        _ => panic!("expected the set to complete"),
    }
}

#[test]
fn a_lease_lives_while_its_segment_is_held() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(8);
    let a = segments(A, 1);

    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);

    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Held));
    assert_eq!(
        ledger.snapshot().reserved_bytes,
        buffer.buffer.total_payload_bytes
    );
    assert!(deliver(&ledger, &a[0], now).is_none(), "a copy is refused");
}

#[test]
fn evicting_a_set_releases_its_leases() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(1);
    let (a, b) = (segments(A, 1), segments(B, 2));
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);

    take_pending(&mut buffer, deliver(&ledger, &b[0], now).unwrap(), now);

    assert!(!buffer.buffer.entries.contains_key(&A));
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Released));
    assert_eq!(ledger.observe(&object_id(&b[0])), Some(Phase::Held));
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.reserved_bytes, buffer.buffer.total_payload_bytes);
    assert_eq!((snapshot.held, snapshot.live_owners), (1, 1));
}

#[test]
fn a_segment_that_comes_back_after_eviction_rebuilds_the_set() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(1);
    let (a, b) = (segments(A, 1), segments(B, 2));
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    take_pending(&mut buffer, deliver(&ledger, &b[0], now).unwrap(), now);

    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    let last = deliver(&ledger, &a[1], now).unwrap();
    let (set, leases) = take_last(&mut buffer, last, now);

    let block = assemble(&ledger, set, leases, now).unwrap();
    assert_eq!(block.raw, vec![1; RAW_LEN]);
}

#[test]
fn nothing_rebuilds_a_set_without_its_segments() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(1);
    let (a, b) = (segments(A, 1), segments(B, 2));
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    take_pending(&mut buffer, deliver(&ledger, &b[0], now).unwrap(), now);

    assert!(!buffer.buffer.entries.contains_key(&A));
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Released));
}

#[test]
fn assembling_a_block_counts_the_copy_and_completes_nothing() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(8);
    let a = segments(A, 1);
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    let last = deliver(&ledger, &a[1], now).unwrap();
    let (set, leases) = take_last(&mut buffer, last, now);
    assert_eq!(ledger.snapshot().reserved_bytes, RAW_LEN, "the segments");

    let block = assemble(&ledger, set, leases, now).unwrap();

    assert_eq!(block.peak_reserved, 2 * RAW_LEN, "both copies were alive");
    assert_eq!(ledger.snapshot().reserved_bytes, 2 * RAW_LEN);
    assert_eq!(block.raw.len(), RAW_LEN);
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Held));
    assert_eq!(ledger.observe(&block_key(A)), Some(Phase::Held));
    assert!(deliver(&ledger, &a[0], now).is_none());

    drop(block);

    let snapshot = ledger.snapshot();
    assert_eq!((snapshot.reserved_bytes, snapshot.live_owners), (0, 0));
    assert_eq!(snapshot.completed, 0, "assembly finished nothing");
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Released));
}

/// The other possible choice, shown and not chosen: giving the bytes back at once lets
/// a copy of a segment in while the block is still being judged.
#[test]
fn dropping_segment_leases_lets_copies_back() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(8);
    let a = segments(A, 1);
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    let last = deliver(&ledger, &a[1], now).unwrap();
    let (set, leases) = take_last(&mut buffer, last, now);
    let mut block = assemble(&ledger, set, leases, now).unwrap();

    block.segment_leases.clear();

    assert_eq!(ledger.snapshot().reserved_bytes, RAW_LEN);
    assert!(deliver(&ledger, &a[0], now).is_some());
    assert_eq!(ledger.observe(&block_key(A)), Some(Phase::Held));
    drop(block.block_lease);
}

#[test]
fn a_block_that_does_not_fit_gives_everything_back() {
    let limits = Limits {
        max_reserved_bytes: RAW_LEN + RAW_LEN / 2,
        ..limits()
    };
    let (ledger, now) = (DeliveryLedger::new(limits), Instant::now());
    let mut buffer = LeasedBuffer::new(8);
    let a = segments(A, 1);
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    let last = deliver(&ledger, &a[1], now).unwrap();
    let (set, leases) = take_last(&mut buffer, last, now);

    assert_eq!(
        assemble(&ledger, set, leases, now).err(),
        Some(Refusal::Bytes)
    );

    let snapshot = ledger.snapshot();
    assert_eq!((snapshot.reserved_bytes, snapshot.live_owners), (0, 0));
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Released));
}

/// Reads the ledger as it dies. The fields before it are gone by then, and the ones
/// after it are not.
struct Probe {
    ledger: DeliveryLedger,
    reserved_at_drop: Arc<std::sync::Mutex<Option<usize>>>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        *self.reserved_at_drop.lock().unwrap() = Some(self.ledger.snapshot().reserved_bytes);
    }
}

#[test]
fn a_leased_buffer_lets_go_of_payloads_before_leases() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(8);
    let a = segments(A, 1);
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    let seen = Arc::default();
    buffer.probe = Some(Probe {
        ledger: ledger.clone(),
        reserved_at_drop: Arc::clone(&seen),
    });

    drop(buffer);

    assert_eq!(*seen.lock().unwrap(), Some(a[0].payload.len()));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[test]
fn an_assembled_block_lets_go_of_its_bytes_before_its_leases() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let mut buffer = LeasedBuffer::new(8);
    let a = segments(A, 1);
    take_pending(&mut buffer, deliver(&ledger, &a[0], now).unwrap(), now);
    let last = deliver(&ledger, &a[1], now).unwrap();
    let (set, leases) = take_last(&mut buffer, last, now);
    let mut block = assemble(&ledger, set, leases, now).unwrap();
    let seen = Arc::default();
    block.probe = Some(Probe {
        ledger: ledger.clone(),
        reserved_at_drop: Arc::clone(&seen),
    });

    drop(block);

    assert_eq!(*seen.lock().unwrap(), Some(2 * RAW_LEN));
    assert_eq!(ledger.snapshot().reserved_bytes, 0);
}

#[tokio::test]
async fn a_closed_channel_gives_back_a_carried_segment() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let a = segments(A, 1);
    let (tx, rx) = mpsc::channel(4);
    for segment in &a {
        tx.try_send(deliver(&ledger, segment, now).unwrap())
            .map_err(|_| ())
            .unwrap();
    }
    assert_eq!(ledger.snapshot().reserved_bytes, RAW_LEN);

    drop(rx);

    let snapshot = ledger.snapshot();
    assert_eq!((snapshot.reserved_bytes, snapshot.live_owners), (0, 0));
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Released));
}

#[tokio::test]
async fn an_aborted_producer_gives_back_a_carried_segment() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let a = segments(A, 1);
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(deliver(&ledger, &a[0], now).unwrap())
        .map_err(|_| ())
        .unwrap();
    let carried = deliver(&ledger, &a[1], now).unwrap();
    let (parked_tx, parked) = oneshot::channel();

    let producer = tokio::spawn(async move {
        parked_tx.send(()).unwrap();
        tx.send(carried).await.is_ok()
    });
    parked.await.unwrap();
    producer.abort();

    assert!(producer.await.unwrap_err().is_cancelled());
    assert_eq!(ledger.observe(&object_id(&a[1])), Some(Phase::Released));
    assert_eq!(ledger.snapshot().reserved_bytes, a[0].payload.len());
}

/// The consumer task owns the buffer and its leases, and is cancelled with both.
#[tokio::test]
async fn an_aborted_consumer_gives_back_what_it_held() {
    let (ledger, now) = (DeliveryLedger::new(limits()), Instant::now());
    let a = segments(A, 1);
    let (tx, mut rx) = mpsc::channel::<(Carried, oneshot::Sender<()>)>(1);

    let consumer = tokio::spawn(async move {
        let mut buffer = LeasedBuffer::new(8);
        while let Some((carried, done)) = rx.recv().await {
            take_pending(&mut buffer, carried, Instant::now());
            done.send(()).unwrap();
        }
    });
    let (done, taken) = oneshot::channel();
    tx.send((deliver(&ledger, &a[0], now).unwrap(), done))
        .await
        .map_err(|_| ())
        .unwrap();
    taken.await.unwrap();
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Held));

    consumer.abort();

    assert!(consumer.await.unwrap_err().is_cancelled());
    let snapshot = ledger.snapshot();
    assert_eq!((snapshot.reserved_bytes, snapshot.live_owners), (0, 0));
    assert_eq!(ledger.observe(&object_id(&a[0])), Some(Phase::Released));
}
