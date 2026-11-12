//! Block body validation at the ingress boundary (#130), and how copies of one
//! block race through it. Forwarding is observed through the sender's channel,
//! so "nothing was sent" is a direct check rather than a timeout. The races are
//! held open by state, a full send channel or a held permit, not by timing.
use super::nu7_fixture::{Nu7Fixture, tx_cache};
use super::*;
use crate::block::{compact_block_from_raw_block, reconstruct_block};
use crate::event::EventSink;
use crate::wire::Network;
use sovright_relay::test_support::{committed_header, raw_block};
use sovright_relay::{
    BlockBodyError, BoundSend, RelayPayload, ZCASH_FULL_HEADER_SIZE, consensus_block_hash,
    reassemble_raw_block, validate_block_body, validate_block_transactions, zcash_block_hash,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zcash_equihash_validator::compact_to_target;
use zcash_pool_common::{BITS_OFFSET, fixtures};

pub(crate) struct Harness {
    pub(crate) bridge: RelayBridge,
    pub(crate) outgoing: mpsc::Receiver<RelayPayload>,
    /// What waits for the bound send, for a test that answers it by hand.
    pub(crate) bound_sends: Option<mpsc::Receiver<BoundSend>>,
    bound_copies: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    _client: RelayClient,
}

pub(crate) fn harness() -> Harness {
    let mut client = RelayClient::new(
        ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true),
    )
    .unwrap();
    let sender = client.sender();
    let bound_sends = client.take_bound_sends();
    let (_receiver, outgoing) = client.take_receiver().unwrap();
    let bridge = RelayBridge {
        sender,
        data_shards: 10,
        parity_shards: 3,
        chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
        compact_from_tx_cache: false,
        skeleton_first: false,
        raw_fallback_with_tx_cache: false,
        raw_segment_send_rounds: 1,
        raw_segment_round_delay: Duration::ZERO,
        recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
            64,
            Duration::from_secs(30),
        ))),
        raw_wire: RawWire::Legacy,
        parse_permits: ParsePermits::new(),
        block_body_rejections: Default::default(),
        peer_pow_limit: None,
        block_log: None,
        forward_unreadable_blocks: false,
        unverified_forwards: Default::default(),
    };
    Harness {
        bridge,
        outgoing,
        bound_sends,
        bound_copies: Arc::default(),
        _client: client,
    }
}

impl Harness {
    /// Every bound send goes well from here on, and is kept as a copy that went out.
    fn answers_bound_sends(&mut self) {
        let mut sends = self.bound_sends.take().unwrap();
        let copies = Arc::clone(&self.bound_copies);
        tokio::spawn(async move {
            while let Some(send) = sends.recv().await {
                copies.lock().unwrap().push(send.raw().to_vec());
                send.finish(Ok(()));
            }
        });
    }

    fn bound_copies(&self) -> Vec<Vec<u8>> {
        self.bound_copies.lock().unwrap().clone()
    }

    /// A forward with a limit on the wait, so a test cannot hang on a full channel.
    async fn forward(&self, raw: &[u8]) -> Result<ForwardedBlock> {
        finishes(self.bridge.forward_block(raw, None)).await
    }

    /// The next bound send, left for the test to answer.
    pub(crate) async fn next_bound_send(&mut self) -> BoundSend {
        finishes(self.bound_sends.as_mut().unwrap().recv())
            .await
            .unwrap()
    }

    pub(crate) fn sent(&mut self) -> Vec<RelayPayload> {
        let mut payloads = Vec::new();
        while let Ok(payload) = self.outgoing.try_recv() {
            payloads.push(payload);
        }
        payloads
    }

    fn recorded(&self, raw: &[u8]) -> bool {
        self.bridge.recent_forwarded.lock().unwrap().contains(
            &zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]),
            std::time::Instant::now(),
        )
    }
}

/// The NU7 block with its v5 transaction changed: still parses, new txid.
pub(crate) fn good_and_bad() -> (Vec<u8>, Vec<u8>) {
    let fixture = Nu7Fixture::load();
    let tx = fixture.v5_transaction();
    let offset = fixture
        .raw
        .windows(tx.len())
        .position(|window| window == tx.as_slice())
        .unwrap();
    let mut bad = fixture.raw.clone();
    bad[offset + 169] ^= 0x01;
    (fixture.raw, bad)
}

fn block_from_compact(compact: &CompactBlock) -> Vec<u8> {
    let mut raw = compact.header.clone();
    crate::wire::encode_compact_size(compact.prefilled_txs.len() as u64, &mut raw);
    for tx in &compact.prefilled_txs {
        raw.extend_from_slice(&tx.tx_data);
    }
    raw
}

fn assert_rejected(result: Result<ForwardedBlock>, expected: BlockBodyError) {
    match result {
        Err(IngressError::InvalidBlockBody(error)) => assert_eq!(error, expected),
        Err(other) => panic!("expected {expected:?}, got {other}"),
        Ok(forwarded) => panic!(
            "expected {expected:?}, forwarded as {}",
            forwarded.mode.as_str()
        ),
    }
}

#[tokio::test]
async fn a_bad_body_is_neither_forwarded_nor_recorded() {
    let (_, bad) = good_and_bad();
    let mut harness = harness();

    assert_rejected(
        harness.bridge.forward_block(&bad, None).await,
        BlockBodyError::MerkleMismatch,
    );

    assert!(harness.sent().is_empty());
    assert!(!harness.recorded(&bad));
}

#[tokio::test]
async fn a_good_body_after_a_bad_one_is_forwarded_byte_for_byte() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    assert!(harness.bridge.forward_block(&bad, None).await.is_err());

    let forwarded = harness.bridge.forward_block(&good, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    assert!(harness.recorded(&good));
    let sent = harness.sent();
    let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
        panic!("expected one compact block, got {sent:?}");
    };
    assert_eq!(block_from_compact(compact), good);
}

/// A known header is skipped before validation. Nothing is forwarded, so a bad
/// copy of a block already sent costs no hashing and changes nothing.
#[tokio::test]
async fn a_known_header_is_skipped_without_validation() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    harness.bridge.forward_block(&good, None).await.unwrap();
    harness.sent();

    let repeat = harness.bridge.forward_block(&good, None).await.unwrap();
    let bad_copy = harness.bridge.forward_block(&bad, None).await.unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
    assert_eq!(bad_copy.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
}

#[tokio::test]
async fn a_large_block_is_forwarded_byte_for_byte_as_raw_segments() {
    let raw = fixtures::mainnet_raw_block();
    let mut harness = harness();

    let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
    let segments: Vec<RawBlockSegment> = harness
        .sent()
        .into_iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment,
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), raw);
}

/// Bytes that the block parser accepts but a strict reader must not.
#[tokio::test]
async fn parser_accepted_blocks_are_refused_before_sending() {
    let header = fixtures::mainnet_serialized_header();
    let txs = fixtures::mainnet_transactions();
    let with_count = |count: &[u8], txs: &[Vec<u8>]| {
        let mut raw = header.clone();
        raw.extend_from_slice(count);
        txs.iter().for_each(|tx| raw.extend_from_slice(tx));
        raw
    };
    let mut repeated = txs.clone();
    repeated.push(txs[6].clone());
    let cases = [
        (
            with_count(&[0xfd, 7, 0], &txs),
            BlockBodyError::InvalidCount,
        ),
        (
            with_count(&[8], &repeated),
            BlockBodyError::DuplicateTxid { index: 7 },
        ),
    ];
    for (raw, expected) in cases {
        let mut harness = harness();
        assert!(
            compact_block_from_raw_block(&raw).is_ok(),
            "parser accepts it"
        );
        assert_rejected(harness.bridge.forward_block(&raw, None).await, expected);
        assert!(harness.sent().is_empty());
        assert!(!harness.recorded(&raw));
    }
}

/// The block parser refuses these too, but the reader's reason is the one
/// reported. They must stay refused and send nothing.
#[tokio::test]
async fn malformed_blocks_send_nothing() {
    let raw = fixtures::mainnet_raw_block();
    let mut trailing = raw.clone();
    trailing.push(0);
    for malformed in [
        trailing,
        raw[..raw.len() - 1].to_vec(),
        raw[..raw.len() / 2].to_vec(),
    ] {
        let mut harness = harness();
        assert!(matches!(
            harness.bridge.forward_block(&malformed, None).await,
            Err(IngressError::InvalidBlockBody(_))
        ));
        assert!(harness.sent().is_empty());
        assert!(!harness.recorded(&malformed));
    }
}

/// The gateway still checks with the block parser and forwarding with the
/// transaction reader, so they must agree on real blocks.
#[test]
fn the_reader_and_the_block_parser_agree_on_real_blocks() {
    for raw in [Nu7Fixture::load().raw, fixtures::mainnet_raw_block()] {
        let compact = compact_block_from_raw_block(&raw).unwrap();
        assert_eq!(validate_block_body(&raw), Ok(compact.tx_count()));
    }
}

/// Peers and the gateway share one count, by the reason the reader gave, and a
/// refusal on length counts like any other. Only refusals count.
#[tokio::test]
async fn refused_bodies_are_counted_by_reason_on_both_entry_points() {
    let (good, bad) = good_and_bad();
    let oversized = vec![0; MAX_BLOCK_BYTES + 1];
    let harness = harness();
    let bridge = &harness.bridge;

    assert!(bridge.forward_block(&bad, None).await.is_err());
    assert!(bridge.forward_pool_block(&bad, None).await.is_err());
    assert!(bridge.forward_block(&oversized, None).await.is_err());
    assert!(bridge.forward_block(&[], None).await.is_err());
    bridge.forward_block(&good, None).await.unwrap();
    bridge.forward_block(&bad, None).await.unwrap();

    let count = |label| bridge.block_body_rejections.count(label);
    assert_eq!(count("merkle_mismatch"), 2, "a known header is not refused");
    assert_eq!(count("too_large"), 1);
    assert_eq!(count("invalid_header_length"), 1);
    assert_eq!(count("transaction"), 0);
}

/// A failed send says nothing about the body, so it is not a refusal.
#[tokio::test]
async fn a_relay_failure_is_not_counted_as_a_refused_body() {
    let (good, _) = good_and_bad();
    let Harness {
        bridge, outgoing, ..
    } = harness();
    drop(outgoing);

    let outcome = bridge.forward_block(&good, None).await;

    assert!(matches!(outcome, Err(IngressError::Relay(_))));
    for kind in BlockBodyError::ALL {
        let label = kind.label();
        assert_eq!(bridge.block_body_rejections.count(label), 0, "{label}");
    }
}

/// The dedup key is hashed from the header, so a payload that cannot hold one
/// stops here, with the same reason the reader gives.
#[tokio::test]
async fn a_payload_too_short_for_a_header_is_refused_before_dedup() {
    let raw = fixtures::mainnet_raw_block();
    for short in [&[][..], &raw[..ZCASH_FULL_HEADER_SIZE - 1]] {
        let mut harness = harness();
        assert_rejected(
            harness.bridge.forward_block(short, None).await,
            BlockBodyError::InvalidHeaderLength,
        );
        assert!(harness.sent().is_empty());
    }
}

/// A known header stops before any parsing, whatever follows it. The block
/// parser used to run first and refuse this one.
#[tokio::test]
async fn a_known_header_is_skipped_even_if_its_body_cannot_be_parsed() {
    let (good, _) = good_and_bad();
    let mut harness = harness();
    harness.bridge.forward_block(&good, None).await.unwrap();
    harness.sent();

    let truncated = harness
        .bridge
        .forward_block(&good[..good.len() - 1], None)
        .await
        .unwrap();
    let header_only = harness
        .bridge
        .forward_block(&good[..ZCASH_FULL_HEADER_SIZE], None)
        .await
        .unwrap();

    assert_eq!(truncated.mode, ForwardMode::Deduplicated);
    assert_eq!(header_only.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
}

/// The delivery event keeps its transaction count without a parse.
#[tokio::test]
async fn a_deduplicated_delivery_reports_the_declared_count() {
    let raw = fixtures::mainnet_raw_block();
    let harness = harness();
    let first = harness.bridge.forward_block(&raw, None).await.unwrap();

    let repeat = harness.bridge.forward_block(&raw, None).await.unwrap();
    let header_only = harness
        .bridge
        .forward_block(&raw[..ZCASH_FULL_HEADER_SIZE], None)
        .await
        .unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
    assert_eq!(repeat.tx_count, first.tx_count);
    assert_eq!(header_only.tx_count, 0);
}

/// What goes on the wire is what the reader validated, slice by slice.
#[tokio::test]
async fn the_forwarded_slices_are_the_readers_transactions() {
    let raw = Nu7Fixture::load().raw;
    let mut harness = harness();

    harness.bridge.forward_block(&raw, None).await.unwrap();

    let sent = harness.sent();
    let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
        panic!("expected one compact block, got {sent:?}");
    };
    let slices: Vec<&[u8]> = compact
        .prefilled_txs
        .iter()
        .map(|tx| tx.tx_data.as_slice())
        .collect();
    let parsed = parse_block_body(raw).unwrap();
    assert_eq!(slices, parsed.transactions().collect::<Vec<_>>());
    assert_eq!(
        validate_block_transactions(&compact.header, slices.iter().copied()),
        Ok(2)
    );
}

/// A block of one empty transaction in the version 2 layout, with this header
/// word, and a header that commits to it.
fn block_with_transaction_header(transaction_header: u32) -> Vec<u8> {
    let mut tx = transaction_header.to_le_bytes().to_vec();
    tx.extend_from_slice(&[0, 0]); // no transparent inputs or outputs
    tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
    tx.push(0); // no joinsplits
    let header = committed_header(0xab, std::slice::from_ref(&tx));
    raw_block(&header, std::slice::from_ref(&tx))
}

/// Parsing is not consensus, and this is where the two parsers differ on it.
/// With the overwinter flag clear, `zcash_primitives` reads every version from 3
/// up as version 2, the pre-Overwinter rule; the block parser stops at 2. So such
/// a block now goes out, where the block parser used to stop it.
///
/// That says the bytes are one transaction, not that a chain accepts it. Which
/// versions a height allows stays with the node, and nothing here adds that
/// rule. The pool gateway still checks with the block parser, so it still refuses
/// these. Real blocks read the same both ways, so only these show the block
/// parser is out of the forwarding path.
#[tokio::test]
async fn forwarding_follows_the_reader_which_does_not_judge_consensus() {
    for version in [3, 4, 5, 6, 0x7fff_ffff] {
        let raw = block_with_transaction_header(version);
        assert!(compact_block_from_raw_block(&raw).is_err());
        assert_eq!(validate_block_body(&raw), Ok(1), "version {version}");

        let mut harness = harness();
        let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();

        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
        let sent = harness.sent();
        let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
            panic!("expected one compact block, got {sent:?}");
        };
        assert_eq!(block_from_compact(compact), raw);
    }
}

/// The edges of that difference: version 2 reads the same both ways, and version
/// 0 and an overwintered header with no version group are refused by both.
#[tokio::test]
async fn the_parsers_agree_on_either_side_of_that_difference() {
    let agreed = block_with_transaction_header(2);
    assert!(compact_block_from_raw_block(&agreed).is_ok());
    assert_eq!(validate_block_body(&agreed), Ok(1));

    for transaction_header in [0, 0x8000_0003] {
        let raw = block_with_transaction_header(transaction_header);
        assert!(compact_block_from_raw_block(&raw).is_err());

        let mut harness = harness();
        assert_rejected(
            harness.bridge.forward_block(&raw, None).await,
            BlockBodyError::Transaction { index: 0 },
        );
        assert!(harness.sent().is_empty());
    }
}

/// Every object sent for a cached block: the skeleton, the full compact block
/// behind it, and the raw fallback. Each must give back the exact block.
#[tokio::test]
async fn every_object_sent_for_a_cached_block_carries_the_block() {
    let fixture = Nu7Fixture::load();
    let cache = tx_cache();
    cache.insert(fixture.v5_wtxid(), fixture.v5_transaction());
    let mut harness = harness();
    harness.bridge.compact_from_tx_cache = true;
    harness.bridge.skeleton_first = true;
    harness.bridge.raw_fallback_with_tx_cache = true;

    let forwarded = harness
        .bridge
        .forward_block(&fixture.raw, Some(&cache))
        .await
        .unwrap();

    assert_eq!(forwarded.mode, ForwardMode::CompactBlockWithRawFallback);
    let sent = harness.sent();
    let [
        RelayPayload::CompactSkeleton(skeleton),
        RelayPayload::CompactBlock(compact),
        fallback @ ..,
    ] = sent.as_slice()
    else {
        panic!("expected a skeleton and a compact block first, got {sent:?}");
    };
    assert_eq!(skeleton.short_ids.len(), 1);
    assert_eq!(compact.short_ids.len(), 1);
    assert_eq!(reconstruct_block(skeleton, &cache), fixture.raw);
    assert_eq!(reconstruct_block(compact, &cache), fixture.raw);
    let segments: Vec<RawBlockSegment> = fallback
        .iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment.clone(),
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), fixture.raw);
}

// ---------------------------------------------------------------------------
// Copies of one block racing through the forward path.
// ---------------------------------------------------------------------------

/// How many objects the relay client's send channel holds.
const OUTGOING_CAPACITY: usize = 16;

/// Only stops a hang. Nothing here asserts how long anything took.
async fn finishes<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("did not finish")
}

pub(crate) async fn eventually(mut condition: impl FnMut() -> bool) {
    finishes(async {
        while !condition() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
}

pub(crate) fn hash_of(raw: &[u8]) -> [u8; 32] {
    zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE])
}

pub(crate) fn in_flight(bridge: &RelayBridge, hash: &[u8; 32]) -> bool {
    let recent = bridge.recent_forwarded.lock().unwrap();
    recent.in_flight.contains_key(hash)
}

/// How many copies are waiting on the send in progress.
fn waiting_on(bridge: &RelayBridge, hash: &[u8; 32]) -> usize {
    let recent = bridge.recent_forwarded.lock().unwrap();
    recent
        .in_flight
        .get(hash)
        .map_or(0, |sender| sender.receiver_count())
}

fn spawn_forward(bridge: &RelayBridge, raw: &[u8]) -> JoinHandle<Result<ForwardedBlock>> {
    let bridge = bridge.clone();
    let raw = raw.to_vec();
    tokio::spawn(async move { bridge.forward_block(&raw, None).await })
}

/// Leave the send channel full, so the next send waits until it is drained.
pub(crate) async fn fill_send_channel(bridge: &RelayBridge) {
    let filler = compact_block_from_raw_block(&block_with_transaction_header(2)).unwrap();
    for _ in 0..OUTGOING_CAPACITY {
        bridge.sender.send(filler.clone()).await.unwrap();
    }
}

async fn hold(permits: &Arc<Semaphore>) -> OwnedSemaphorePermit {
    Arc::clone(permits).acquire_owned().await.unwrap()
}

pub(crate) async fn hold_p2p_permit(bridge: &RelayBridge) -> OwnedSemaphorePermit {
    hold(&bridge.parse_permits.p2p).await
}

async fn spare_permit() -> OwnedSemaphorePermit {
    hold(&Arc::new(Semaphore::new(1))).await
}

async fn release_after_a_yield(permit: OwnedSemaphorePermit) {
    tokio::task::yield_now().await;
    drop(permit);
}

async fn cancel(task: JoinHandle<Result<ForwardedBlock>>) {
    task.abort();
    match task.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("the task finished before it was cancelled"),
    }
}

async fn forwarded(task: JoinHandle<Result<ForwardedBlock>>) -> ForwardedBlock {
    finishes(task).await.unwrap().unwrap()
}

pub(crate) fn compact_blocks_of(sent: &[RelayPayload], raw: &[u8]) -> usize {
    sent.iter()
        .filter(|payload| {
            matches!(payload, RelayPayload::CompactBlock(compact)
                if compact.header == raw[..ZCASH_FULL_HEADER_SIZE])
        })
        .count()
}

/// Two bodies for one header that both validate: a v6 txid leaves out the
/// scriptSig, so changing a byte of one keeps every txid and the merkle root.
pub(crate) fn two_valid_bodies() -> (Vec<u8>, Vec<u8>) {
    let header = fixtures::mainnet_serialized_header();
    let txs = fixtures::mainnet_transactions();
    let mut other = txs.clone();
    other[2][70] ^= 0x01;
    let (first, second) = (raw_block(&header, &txs), raw_block(&header, &other));
    assert_ne!(first, second);
    assert_eq!(validate_block_body(&second), Ok(txs.len()));
    (first, second)
}

/// Refused on length alone, so these neither queue for a permit nor get copied.
#[tokio::test]
async fn a_payload_of_the_wrong_length_needs_no_permit() {
    let harness = harness();
    let _p2p = hold(&harness.bridge.parse_permits.p2p).await;
    let _pool = hold(&harness.bridge.parse_permits.pool).await;
    let oversized = vec![0; MAX_BLOCK_BYTES + 1];
    let too_large = BlockBodyError::TooLarge {
        bytes: oversized.len(),
    };
    let short = &oversized[..ZCASH_FULL_HEADER_SIZE - 1];

    let bridge = &harness.bridge;
    assert_rejected(
        finishes(bridge.forward_block(&oversized, None)).await,
        too_large,
    );
    assert_rejected(
        finishes(bridge.forward_pool_block(&oversized, None)).await,
        too_large,
    );
    assert_rejected(
        finishes(bridge.forward_block(short, None)).await,
        BlockBodyError::InvalidHeaderLength,
    );
    assert_rejected(
        finishes(bridge.forward_pool_block(short, None)).await,
        BlockBodyError::InvalidHeaderLength,
    );
}

#[tokio::test]
async fn a_known_header_needs_no_permit() {
    let (good, _) = good_and_bad();
    let harness = harness();
    harness.bridge.forward_block(&good, None).await.unwrap();
    let _permit = hold(&harness.bridge.parse_permits.p2p).await;

    let repeat = finishes(harness.bridge.forward_block(&good, None))
        .await
        .unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
}

#[tokio::test]
async fn the_gateway_and_the_peers_do_not_queue_behind_each_other() {
    let (good, _) = good_and_bad();
    let other = block_with_transaction_header(2);
    let harness = harness();

    let p2p = hold(&harness.bridge.parse_permits.p2p).await;
    let from_pool = finishes(harness.bridge.forward_pool_block(&good, None))
        .await
        .unwrap();
    drop(p2p);
    let _pool = hold(&harness.bridge.parse_permits.pool).await;
    assert_eq!(harness.bridge.parse_permits.pool.available_permits(), 0);
    let from_peer = finishes(harness.bridge.forward_block(&other, None))
        .await
        .unwrap();

    assert_eq!(from_pool.mode, ForwardMode::CompactBlock);
    assert_eq!(from_peer.mode, ForwardMode::CompactBlock);
}

/// They all queue on one permit, and only the first gets as far as sending.
#[tokio::test]
async fn concurrent_copies_of_a_block_are_sent_once() {
    let (good, _) = good_and_bad();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;
    assert_eq!(harness.bridge.parse_permits.p2p.available_permits(), 0);
    let copies: Vec<_> = (0..8)
        .map(|_| spawn_forward(&harness.bridge, &good))
        .collect();
    tokio::task::yield_now().await;
    assert!(harness.sent().is_empty(), "the permit holds them all back");
    assert!(copies.iter().all(|copy| !copy.is_finished()));

    drop(permit);

    let mut modes = Vec::new();
    for copy in copies {
        modes.push(forwarded(copy).await.mode);
    }
    let sends = modes
        .iter()
        .filter(|mode| **mode == ForwardMode::CompactBlock)
        .count();
    assert_eq!(sends, 1, "{modes:?}");
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(!in_flight(&harness.bridge, &hash_of(&good)));
}

/// The bad copy goes first and fails its own parse. It holds no claim while it
/// does, so the good copy behind it is neither hidden nor deduplicated.
#[tokio::test]
async fn a_bad_copy_ahead_of_a_good_one_holds_nothing_back() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;

    let (bad_copy, good_copy, ()) = tokio::join!(
        harness.bridge.forward_block(&bad, None),
        harness.bridge.forward_block(&good, None),
        release_after_a_yield(permit),
    );

    assert_rejected(bad_copy, BlockBodyError::MerkleMismatch);
    assert_eq!(good_copy.unwrap().mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
}

/// Behind a good copy, a bad one is settled by the recheck after its permit and
/// is never parsed: parsing it would have been refused, not deduplicated.
#[tokio::test]
async fn a_good_copy_ahead_of_a_bad_one_settles_it_unparsed() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;

    let (good_copy, bad_copy, ()) = tokio::join!(
        harness.bridge.forward_block(&good, None),
        harness.bridge.forward_block(&bad, None),
        release_after_a_yield(permit),
    );

    assert_eq!(good_copy.unwrap().mode, ForwardMode::CompactBlock);
    assert_eq!(bad_copy.unwrap().mode, ForwardMode::Deduplicated);
    let sent = harness.sent();
    let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
        panic!("expected one compact block, got {sent:?}");
    };
    assert_eq!(block_from_compact(compact), good);
}

/// Nothing here can tell these two apart, so whichever validates first is sent.
/// That is the open limit on authorization-only changes, not a choice of body.
#[tokio::test]
async fn the_first_of_two_valid_bodies_is_the_one_sent() {
    let (first, second) = two_valid_bodies();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;

    let (first_copy, second_copy, ()) = tokio::join!(
        harness.bridge.forward_block(&first, None),
        harness.bridge.forward_block(&second, None),
        release_after_a_yield(permit),
    );

    assert_eq!(first_copy.unwrap().mode, ForwardMode::RawBlockSegments);
    assert_eq!(second_copy.unwrap().mode, ForwardMode::Deduplicated);
    let segments: Vec<RawBlockSegment> = harness
        .sent()
        .into_iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment,
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), first);
}

#[tokio::test]
async fn a_cancelled_send_passes_the_block_to_the_waiting_copy() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    fill_send_channel(&harness.bridge).await;
    let first = spawn_forward(&harness.bridge, &good);
    eventually(|| in_flight(&harness.bridge, &hash)).await;
    let second = spawn_forward(&harness.bridge, &good);
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    cancel(first).await;

    eventually(|| in_flight(&harness.bridge, &hash)).await;
    assert_eq!(
        harness.sent().len(),
        OUTGOING_CAPACITY,
        "the cancelled send put nothing on the channel"
    );
    assert_eq!(forwarded(second).await.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
    assert!(!in_flight(&harness.bridge, &hash));
}

/// The two bridges share dedup state and permits, as clones do, but the first
/// sends through a channel that closes under it.
#[tokio::test]
async fn a_failed_send_passes_the_block_to_the_waiting_copy() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    let mut failing_client = RelayClient::new(
        ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true),
    )
    .unwrap();
    let (_receiver, failing_outgoing) = failing_client.take_receiver().unwrap();
    let mut failing = harness.bridge.clone();
    failing.sender = failing_client.sender();
    fill_send_channel(&failing).await;

    let first = spawn_forward(&failing, &good);
    eventually(|| in_flight(&harness.bridge, &hash)).await;
    let second = spawn_forward(&harness.bridge, &good);
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    drop(failing_outgoing);

    assert!(matches!(
        finishes(first).await.unwrap(),
        Err(IngressError::Relay(_))
    ));
    assert_eq!(forwarded(second).await.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
    assert!(!in_flight(&harness.bridge, &hash));
}

/// With no channel left, every copy fails. None hangs and none is deduplicated
/// against a send that never finished.
#[tokio::test]
async fn a_closed_channel_fails_every_copy_and_records_nothing() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let Harness {
        bridge, outgoing, ..
    } = harness();
    fill_send_channel(&bridge).await;
    let first = spawn_forward(&bridge, &good);
    eventually(|| in_flight(&bridge, &hash)).await;
    let second = spawn_forward(&bridge, &good);
    eventually(|| waiting_on(&bridge, &hash) == 1).await;

    drop(outgoing);

    for copy in [first, second] {
        assert!(matches!(
            finishes(copy).await.unwrap(),
            Err(IngressError::Relay(_))
        ));
    }
    assert!(!in_flight(&bridge, &hash));
    assert!(matches!(bridge.forward_state(&hash), ForwardState::Open));
}

#[tokio::test]
async fn a_cancelled_waiter_leaves_the_send_alone() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    fill_send_channel(&harness.bridge).await;
    let first = spawn_forward(&harness.bridge, &good);
    eventually(|| in_flight(&harness.bridge, &hash)).await;
    let second = spawn_forward(&harness.bridge, &good);
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    cancel(second).await;
    assert_eq!(waiting_on(&harness.bridge, &hash), 0);
    harness.sent();

    assert_eq!(forwarded(first).await.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
}

/// A copy still queueing for a permit has validated nothing, so it holds no
/// claim, and cancelling it leaves the block open for the next delivery.
#[tokio::test]
async fn a_copy_cancelled_in_the_queue_leaves_nothing_behind() {
    let (good, bad) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;
    let queued = spawn_forward(&harness.bridge, &bad);
    tokio::task::yield_now().await;
    assert!(!in_flight(&harness.bridge, &hash));

    cancel(queued).await;
    drop(permit);

    assert!(matches!(
        harness.bridge.forward_state(&hash),
        ForwardState::Open
    ));
    let forwarded = finishes(harness.bridge.forward_block(&good, None))
        .await
        .unwrap();
    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
}

/// A copy that validated while another was claiming keeps what it prepared, and
/// sends it if the claim ends without a send.
#[tokio::test]
async fn a_dropped_claim_passes_to_a_copy_that_already_validated() {
    let hash = [0x51; 32];
    let harness = harness();
    let claim = harness
        .bridge
        .claim_forward(hash, hash, spare_permit().await)
        .await
        .unwrap()
        .unwrap();
    let bridge = harness.bridge.clone();
    let permit = spare_permit().await;
    let waiter = tokio::spawn(async move {
        bridge
            .claim_forward(hash, hash, permit)
            .await
            .unwrap()
            .is_some()
    });
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    drop(claim);

    assert!(finishes(waiter).await.unwrap());
    assert!(!in_flight(&harness.bridge, &hash));
}

#[tokio::test]
async fn a_committed_claim_settles_a_copy_that_already_validated() {
    let hash = [0x52; 32];
    let harness = harness();
    let claim = harness
        .bridge
        .claim_forward(hash, hash, spare_permit().await)
        .await
        .unwrap()
        .unwrap();
    let bridge = harness.bridge.clone();
    let permit = spare_permit().await;
    let waiter = tokio::spawn(async move {
        bridge
            .claim_forward(hash, hash, permit)
            .await
            .unwrap()
            .is_some()
    });
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    claim.commit();

    assert!(!finishes(waiter).await.unwrap());
    assert!(!in_flight(&harness.bridge, &hash));
    assert!(matches!(
        harness.bridge.forward_state(&hash),
        ForwardState::Forwarded
    ));
}

/// A copy that waits on someone else's send has finished its own work, so it
/// must not keep the next body in the queue from being parsed meanwhile.
#[tokio::test]
async fn a_copy_waiting_on_a_send_gives_its_permit_back() {
    let hash = [0x53; 32];
    let harness = harness();
    let claim = harness
        .bridge
        .claim_forward(hash, hash, spare_permit().await)
        .await
        .unwrap()
        .unwrap();
    let permits = Arc::new(Semaphore::new(1));
    let permit = hold(&permits).await;
    let bridge = harness.bridge.clone();
    let waiter = tokio::spawn(async move {
        bridge
            .claim_forward(hash, hash, permit)
            .await
            .unwrap()
            .is_some()
    });

    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;
    assert_eq!(permits.available_permits(), 1);

    drop(claim);
    assert!(finishes(waiter).await.unwrap());
}

/// The work's permit comes back with its result, so a validated copy can keep it
/// until it has claimed the block. A copy that failed gives it up at once.
#[tokio::test]
async fn preparation_hands_the_permit_back_only_for_a_valid_body() {
    let (good, bad) = good_and_bad();
    let harness = harness();
    let permits = Arc::new(Semaphore::new(1));

    let prepared = harness
        .bridge
        .prepare_off_workers(&good, None, hold(&permits).await)
        .await
        .map(|(_, permit)| permit)
        .unwrap();
    assert_eq!(permits.available_permits(), 0);
    drop(prepared);

    let refused = harness
        .bridge
        .prepare_off_workers(&bad, None, hold(&permits).await)
        .await;
    assert!(matches!(refused, Err(IngressError::InvalidBlockBody(_))));
    assert_eq!(permits.available_permits(), 1);
}

/// Cancelling the caller does not stop blocking work, so the permit must stay
/// held until the work itself ends, or the limit counts only live callers.
#[tokio::test]
async fn a_cancelled_caller_leaves_the_permit_with_the_work() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = hold(&permits).await;
    let (started, has_started) = std::sync::mpsc::channel();
    let (finish, may_finish) = std::sync::mpsc::channel::<()>();
    let caller = tokio::spawn(run_holding_permit(permit, move || {
        started.send(()).unwrap();
        may_finish.recv().unwrap();
    }));
    eventually(|| has_started.try_recv().is_ok()).await;

    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert_eq!(permits.available_permits(), 0);

    finish.send(()).unwrap();
    eventually(|| permits.available_permits() == 1).await;
}

#[tokio::test]
async fn a_panic_in_the_work_releases_the_permit() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = hold(&permits).await;

    let result = finishes(run_holding_permit(permit, || -> () {
        panic!("the work failed")
    }))
    .await;

    assert!(result.unwrap_err().is_panic());
    assert_eq!(permits.available_permits(), 1);
}

/// A bridge with the peer target check on, as `from_config` builds it. The other
/// harnesses leave it off because their synthetic headers would all miss.
pub(crate) fn checked_harness(network: Network) -> Harness {
    let mut harness = harness();
    harness.bridge.peer_pow_limit = Some(network.pow_limit());
    harness
}

/// `header` followed by a body the reader refuses. A refusal with
/// `Transaction { index: 0 }` shows the block got past the target check.
pub(crate) fn unreadable_body(header: &[u8]) -> Vec<u8> {
    let mut raw = header.to_vec();
    raw.push(1);
    raw.extend_from_slice(&[0xff; 40]);
    raw
}

/// A real header with its target made impossible for its hash to meet.
pub(crate) fn header_missing_its_target() -> Vec<u8> {
    let mut header = fixtures::mainnet_serialized_header();
    header[BITS_OFFSET..][..4].copy_from_slice(&0x0300_0001u32.to_le_bytes());
    header
}

/// A made-up header stating `bits` and ground until its hash meets them. Its
/// solution does not verify, which is why meeting the target is not proof of work.
pub(crate) fn header_stating(bits: u32) -> Vec<u8> {
    let target = compact_to_target(bits);
    let mut header = fixtures::mainnet_serialized_header();
    header[BITS_OFFSET..][..4].copy_from_slice(&bits.to_le_bytes());
    for nonce in 0u32.. {
        header[108..112].copy_from_slice(&nonce.to_le_bytes());
        if target.is_met_by(&consensus_block_hash(&header)) {
            break;
        }
    }
    header
}

/// The permit is held throughout, so this finishes only if the header is refused
/// before one is taken.
#[tokio::test]
async fn a_header_missing_its_target_is_refused_without_a_permit() {
    let mut harness = checked_harness(Network::Mainnet);
    let _held = hold_p2p_permit(&harness.bridge).await;
    let out_of_range = vec![0xab; ZCASH_FULL_HEADER_SIZE];
    for header in [header_missing_its_target(), out_of_range] {
        let raw = unreadable_body(&header);

        assert_rejected(
            finishes(harness.bridge.forward_block(&raw, None)).await,
            BlockBodyError::HeaderTarget,
        );

        assert!(harness.sent().is_empty());
        assert!(!harness.recorded(&raw));
    }
    let count = |label| harness.bridge.block_body_rejections.count(label);
    assert_eq!(count("header_target"), 2);
    assert_eq!(count("transaction"), 0, "nothing was parsed");
}

/// The block hash is the consensus SHA256d. These are real blocks, so a BLAKE2b
/// object id in its place would miss their targets.
#[tokio::test]
async fn real_blocks_pass_the_target_check_of_their_network() {
    let mut mainnet = checked_harness(Network::Mainnet);
    let forwarded = mainnet
        .bridge
        .forward_block(&fixtures::mainnet_raw_block(), None)
        .await
        .unwrap();
    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);

    let mut testnet = checked_harness(Network::Testnet);
    let forwarded = testnet
        .bridge
        .forward_block(&Nu7Fixture::load().raw, None)
        .await
        .unwrap();
    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

    assert!(!mainnet.sent().is_empty());
    assert!(!testnet.sent().is_empty());
}

/// Testnet's minimum difficulty is out of range on mainnet, so the limit has to
/// come from the network.
#[tokio::test]
async fn a_minimum_difficulty_target_passes_only_on_testnet() {
    let raw = unreadable_body(&header_stating(0x2007_ffff));

    assert_rejected(
        checked_harness(Network::Testnet)
            .bridge
            .forward_block(&raw, None)
            .await,
        BlockBodyError::Transaction { index: 0 },
    );
    assert_rejected(
        checked_harness(Network::Mainnet)
            .bridge
            .forward_block(&raw, None)
            .await,
        BlockBodyError::HeaderTarget,
    );
}

/// The gateway has its own target check ahead of this, so its path is unchanged.
#[tokio::test]
async fn the_gateway_path_does_not_apply_the_peer_check() {
    let harness = checked_harness(Network::Mainnet);
    let raw = unreadable_body(&header_missing_its_target());

    assert_rejected(
        harness.bridge.forward_pool_block(&raw, None).await,
        BlockBodyError::Transaction { index: 0 },
    );
}

/// Inside the dedup window a real header costs no parse, whatever follows it.
#[tokio::test]
async fn a_known_real_header_with_another_body_costs_no_parse() {
    let (good, _) = good_and_bad();
    let mut harness = checked_harness(Network::Testnet);
    harness.bridge.forward_block(&good, None).await.unwrap();
    harness.sent();

    let repeat = unreadable_body(&good[..ZCASH_FULL_HEADER_SIZE]);
    let forwarded = harness.bridge.forward_block(&repeat, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::Deduplicated);
    assert_eq!(harness.bridge.block_body_rejections.count("transaction"), 0);
}

/// The target check does not stop this. A header outside the dedup window passes
/// it with any body, a refused body is not recorded, and so each delivery of the
/// same bytes is parsed again.
#[tokio::test]
async fn known_gap_a_reused_real_header_is_parsed_on_every_delivery() {
    let mut harness = checked_harness(Network::Mainnet);
    let raw = unreadable_body(&fixtures::mainnet_serialized_header());

    for _ in 0..2 {
        assert_rejected(
            harness.bridge.forward_block(&raw, None).await,
            BlockBodyError::Transaction { index: 0 },
        );
    }

    assert_eq!(harness.bridge.block_body_rejections.count("transaction"), 2);
    assert!(harness.sent().is_empty());
    assert!(!harness.recorded(&raw));
}

/// A real block plus one byte matches its header, so it costs the sender nothing
/// and each delivery still costs a full parse.
#[tokio::test]
async fn known_gap_a_real_block_with_a_trailing_byte_is_parsed_on_every_delivery() {
    let harness = checked_harness(Network::Mainnet);
    let mut raw = fixtures::mainnet_raw_block();
    raw.push(0);

    for _ in 0..2 {
        assert_rejected(
            harness.bridge.forward_block(&raw, None).await,
            BlockBodyError::TrailingBytes { bytes: 1 },
        );
    }

    let count = |label| harness.bridge.block_body_rejections.count(label);
    assert_eq!(count("trailing_bytes"), 2);
}

/// The coinbase line is written before the send, and it is telemetry: a log that
/// cannot be written must not cost the block.
#[tokio::test]
async fn a_coinbase_that_cannot_be_written_does_not_stop_the_block() {
    let (good, _) = good_and_bad();
    let sink = EventSink::unwritable();
    assert!(sink.p2p_peer_error("peer", "writes fail").is_err());
    let mut harness = harness();
    let bridge = harness.bridge.clone().logging_block_events(sink, "peer");

    let forwarded = bridge.forward_block(&good, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    assert!(harness.recorded(&good));
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
}

/// A transaction in a layout the reader does not know: its version group is
/// unassigned. The last byte tells bodies apart.
pub(crate) fn unknown_layout_transaction(bytes: usize, last: u8) -> Vec<u8> {
    let mut tx = 0x8000_0007u32.to_le_bytes().to_vec();
    tx.extend_from_slice(&0x7a7a_7a7au32.to_le_bytes());
    tx.resize(bytes, 0x5a);
    tx[bytes - 1] = last;
    tx
}

/// A real header with its real proof of work, over a body the reader stops in:
/// transaction 0 parses, transaction 1 cannot.
pub(crate) fn unreadable_block(bytes: usize, last: u8) -> Vec<u8> {
    let coinbase = fixtures::mainnet_transactions().swap_remove(0);
    raw_block(
        &fixtures::mainnet_serialized_header(),
        &[coinbase, unknown_layout_transaction(bytes, last)],
    )
}

const UNREADABLE: BlockBodyError = BlockBodyError::Transaction { index: 1 };

/// A bridge as `from_config` builds it with the emergency bypass on.
pub(crate) fn bypass_harness() -> Harness {
    let mut harness = checked_harness(Network::Mainnet);
    harness.bridge.forward_unreadable_blocks = true;
    harness
}

fn raw_segments(sent: Vec<RelayPayload>) -> Vec<RawBlockSegment> {
    sent.into_iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment,
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect()
}

fn unverified_entries(bridge: &RelayBridge) -> usize {
    bridge.unverified_forwards.lock().unwrap().entries.len()
}

#[tokio::test]
async fn without_the_bypass_an_unreadable_body_is_refused() {
    let raw = unreadable_block(400, 1);
    let mut harness = checked_harness(Network::Mainnet);

    assert_rejected(harness.bridge.forward_block(&raw, None).await, UNREADABLE);

    assert!(harness.sent().is_empty());
    assert_eq!(
        harness.bridge.block_body_rejections.unverified_forwards(),
        0
    );
}

/// Raw only, because nothing else can be built without the transaction boundaries.
/// It claims nothing: a forged body in this path must not hide the real block.
#[tokio::test]
async fn an_unreadable_body_goes_out_raw_and_claims_nothing() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_harness();

    let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegmentsUnverified);
    assert_eq!(forwarded.mode.as_str(), "raw_block_segments_unverified");
    let segments = raw_segments(harness.sent());
    assert_eq!(reassemble_raw_block(&segments).unwrap(), raw);
    assert!(!harness.recorded(&raw));
    let rejections = &harness.bridge.block_body_rejections;
    assert_eq!(rejections.unverified_forwards(), 1);
    assert_eq!(rejections.count("transaction"), 0, "it was not refused");
}

/// The bypass covers a body nothing is known against. Each of these is a finding
/// about the body, and one is a repeat found before the reader stopped.
#[tokio::test]
async fn the_bypass_leaves_every_other_refusal_standing() {
    let header = fixtures::mainnet_serialized_header();
    let txs = fixtures::mainnet_transactions();
    let genuine = raw_block(&header, &txs);
    let mut trailing = genuine.clone();
    trailing.push(0);
    let mut changed = txs.clone();
    changed[3][60] ^= 0x01;
    let mut repeated = txs.clone();
    repeated.push(txs[6].clone());
    let repeat_then_unreadable = [
        txs[0].clone(),
        txs[1].clone(),
        txs[1].clone(),
        unknown_layout_transaction(400, 1),
    ];
    let mut bad_count = header.clone();
    bad_count.extend_from_slice(&[0xfd, 7, 0]);
    txs.iter().for_each(|tx| bad_count.extend_from_slice(tx));
    let cases = [
        (trailing, BlockBodyError::TrailingBytes { bytes: 1 }),
        (raw_block(&header, &changed), BlockBodyError::MerkleMismatch),
        (
            raw_block(&header, &repeated),
            BlockBodyError::DuplicateTxid { index: 7 },
        ),
        (
            raw_block(&header, &repeat_then_unreadable),
            BlockBodyError::DuplicateTxid { index: 2 },
        ),
        (bad_count, BlockBodyError::InvalidCount),
        (
            vec![0; MAX_BLOCK_BYTES + 1],
            BlockBodyError::TooLarge {
                bytes: MAX_BLOCK_BYTES + 1,
            },
        ),
        (vec![0; 10], BlockBodyError::InvalidHeaderLength),
    ];
    for (raw, expected) in cases {
        let mut harness = bypass_harness();

        assert_rejected(harness.bridge.forward_block(&raw, None).await, expected);

        assert!(harness.sent().is_empty(), "{expected:?}");
        assert_eq!(
            harness.bridge.block_body_rejections.unverified_forwards(),
            0
        );
    }
}

/// Meeting the target is cheap, so the bypass also needs a valid solution.
#[tokio::test]
async fn a_header_with_no_real_proof_of_work_gets_no_bypass() {
    let raw = unreadable_body(&header_stating(0x1f07_ffff));
    let mut harness = bypass_harness();

    assert_rejected(
        harness.bridge.forward_block(&raw, None).await,
        BlockBodyError::Transaction { index: 0 },
    );

    assert!(harness.sent().is_empty());
    assert_eq!(
        harness.bridge.block_body_rejections.unverified_forwards(),
        0
    );
}

/// Forged body first, real body second: the real one goes out the usual way.
#[tokio::test]
async fn a_valid_copy_after_an_unreadable_one_is_sent_as_usual() {
    let genuine = fixtures::mainnet_raw_block();
    let mut harness = bypass_harness();
    harness
        .bridge
        .forward_block(&unreadable_block(400, 1), None)
        .await
        .unwrap();
    harness.sent();

    let forwarded = harness.bridge.forward_block(&genuine, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
    assert_eq!(
        reassemble_raw_block(&raw_segments(harness.sent())).unwrap(),
        genuine
    );
    assert!(harness.recorded(&genuine));
}

#[tokio::test]
async fn a_known_block_stops_an_unreadable_copy_unparsed() {
    let mut harness = bypass_harness();
    harness
        .bridge
        .forward_block(&fixtures::mainnet_raw_block(), None)
        .await
        .unwrap();
    harness.sent();

    let forwarded = harness
        .bridge
        .forward_block(&unreadable_block(400, 1), None)
        .await
        .unwrap();

    assert_eq!(forwarded.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
    assert_eq!(
        harness.bridge.block_body_rejections.unverified_forwards(),
        0
    );
}

#[tokio::test]
async fn the_same_unreadable_bytes_go_out_once() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_harness();
    harness.bridge.forward_block(&raw, None).await.unwrap();
    harness.sent();

    let repeat = harness.bridge.forward_block(&raw, None).await.unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
    assert_eq!(
        harness.bridge.block_body_rejections.unverified_forwards(),
        1
    );
}

fn body_budget(bridge: &RelayBridge) -> usize {
    bridge.unverified_forwards.lock().unwrap().per_header
}

async fn use_up_body_budget(harness: &mut Harness, bodies: usize) {
    for body in 0..bodies {
        let raw = unreadable_block(400, body as u8);
        let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();
        assert_eq!(forwarded.mode, ForwardMode::RawBlockSegmentsUnverified);
    }
    harness.sent();
}

/// Inside the budget a real unreadable body still gets out behind forged ones.
#[tokio::test]
async fn the_real_unreadable_body_passes_while_the_budget_lasts() {
    let mut harness = bypass_harness();
    let spare = body_budget(&harness.bridge) - 1;
    use_up_body_budget(&mut harness, spare).await;

    let real = unreadable_block(400, 0xff);
    let forwarded = harness.bridge.forward_block(&real, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegmentsUnverified);
    assert_eq!(
        reassemble_raw_block(&raw_segments(harness.sent())).unwrap(),
        real
    );
}

/// The limit stops recovery here. Forged bodies under a real header cost nothing,
/// so whoever sends them first can use the whole budget and the real unreadable
/// body is refused until it refreshes. No budget guarantees recovery from that.
#[tokio::test]
async fn known_gap_forged_bodies_can_use_up_the_budget_before_the_real_one() {
    let mut harness = bypass_harness();
    let budget = body_budget(&harness.bridge);
    use_up_body_budget(&mut harness, budget).await;

    let real = unreadable_block(400, 0xff);
    assert_rejected(harness.bridge.forward_block(&real, None).await, UNREADABLE);

    assert!(harness.sent().is_empty());
    assert_eq!(harness.bridge.block_body_rejections.count("transaction"), 1);
}

/// The limit is on bodies nothing could check, so a block that validates is outside it.
#[tokio::test]
async fn a_used_budget_does_not_touch_a_block_that_validates() {
    let mut harness = bypass_harness();
    let budget = body_budget(&harness.bridge);
    use_up_body_budget(&mut harness, budget).await;

    let forwarded = harness
        .bridge
        .forward_block(&fixtures::mainnet_raw_block(), None)
        .await
        .unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
}

#[test]
fn the_budget_refreshes_when_the_window_ends_and_not_before() {
    let window = Duration::from_secs(30);
    let mut forwards = UnverifiedForwards::new(64, window, 2);
    let body = |digest| UnverifiedBody {
        header_hash: [1; 32],
        digest: [digest; 32],
    };
    let start = std::time::Instant::now();
    assert!(matches!(
        forwards.reserve(body(1), start),
        UnverifiedReservation::Reserved
    ));
    assert!(matches!(
        forwards.reserve(body(2), start),
        UnverifiedReservation::Reserved
    ));
    forwards.commit(&body(1));
    forwards.commit(&body(2));

    assert!(matches!(
        forwards.reserve(body(3), start + window),
        UnverifiedReservation::HeaderFull
    ));
    assert!(matches!(
        forwards.reserve(body(3), start + window + Duration::from_millis(1)),
        UnverifiedReservation::Reserved
    ));
}

/// Review item 2 on #134: on `RawWire::Legacy` a copy of a body still being sent is a repeat,
/// as it was before the #130 work, rather than waiting on the send.
#[test]
fn on_the_legacy_wire_a_copy_during_a_send_is_a_repeat() {
    let now = std::time::Instant::now();
    let mut forwards = UnverifiedForwards::new(4, Duration::from_secs(1), 1);
    let body = UnverifiedBody {
        header_hash: [1; 32],
        digest: [2; 32],
    };
    assert!(matches!(
        forwards.reserve(body, now),
        UnverifiedReservation::Reserved
    ));
    assert!(matches!(
        forwards.reserve(body, now),
        UnverifiedReservation::Repeat
    ));
}

#[test]
fn in_flight_reservations_survive_expiry_and_capacity_pressure_until_cancelled() {
    let now = std::time::Instant::now();
    let state = Arc::new(std::sync::Mutex::new(
        UnverifiedForwards::new(1, Duration::from_secs(1), 1).waiting_for_copies(true),
    ));
    let first = UnverifiedBody {
        header_hash: [1; 32],
        digest: [2; 32],
    };
    let other = UnverifiedBody {
        header_hash: [3; 32],
        digest: [4; 32],
    };
    assert!(matches!(
        state.lock().unwrap().reserve(first, now),
        UnverifiedReservation::Reserved
    ));
    let guard = UnverifiedSlot {
        forwards: Arc::clone(&state),
        body: first,
        left: false,
        sent: false,
    };
    let later = now + Duration::from_secs(2);
    assert!(matches!(
        state.lock().unwrap().reserve(first, later),
        UnverifiedReservation::Sending(_)
    ));
    assert!(matches!(
        state.lock().unwrap().reserve(other, later),
        UnverifiedReservation::HeaderFull
    ));
    drop(guard);
    assert!(matches!(
        state.lock().unwrap().reserve(other, later),
        UnverifiedReservation::Reserved
    ));
}

#[test]
fn full_budget_preserves_sent_entries_until_window_expiry() {
    let start = std::time::Instant::now();
    let window = Duration::from_secs(1);
    let mut forwards = UnverifiedForwards::new(1, window, 1);
    let first = UnverifiedBody {
        header_hash: [1; 32],
        digest: [2; 32],
    };
    let other = UnverifiedBody {
        header_hash: [3; 32],
        digest: [4; 32],
    };
    assert!(matches!(
        forwards.reserve(first, start),
        UnverifiedReservation::Reserved
    ));
    forwards.commit(&first);
    assert!(matches!(
        forwards.reserve(other, start + window),
        UnverifiedReservation::HeaderFull
    ));
    assert!(matches!(
        forwards.reserve(first, start + window),
        UnverifiedReservation::Repeat
    ));
    assert!(matches!(
        forwards.reserve(other, start + window + Duration::from_millis(50)),
        UnverifiedReservation::Reserved
    ));
}

/// The first relay refuses a target above the mainnet range, so a block like this
/// could not go anywhere. Refusing it here says so rather than counting a forward.
#[tokio::test]
async fn the_bypass_refuses_a_testnet_minimum_difficulty_block() {
    let raw = unreadable_body(&fixtures::testnet_genesis_serialized_header());
    let mut harness = checked_harness(Network::Testnet);
    harness.bridge.forward_unreadable_blocks = true;

    assert_rejected(
        harness.bridge.forward_block(&raw, None).await,
        BlockBodyError::Transaction { index: 0 },
    );

    assert!(harness.sent().is_empty());
    assert_eq!(
        harness.bridge.block_body_rejections.count("header_target"),
        0
    );
}

#[tokio::test]
async fn the_bypass_covers_a_testnet_block_in_the_mainnet_target_range() {
    let raw = unreadable_body(&Nu7Fixture::load().raw[..ZCASH_FULL_HEADER_SIZE]);
    let mut harness = checked_harness(Network::Testnet);
    harness.bridge.forward_unreadable_blocks = true;

    let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegmentsUnverified);
    assert_eq!(
        reassemble_raw_block(&raw_segments(harness.sent())).unwrap(),
        raw
    );
}

#[tokio::test]
async fn a_failed_unverified_send_gives_its_place_back() {
    let raw = unreadable_block(400, 1);
    let Harness {
        bridge, outgoing, ..
    } = bypass_harness();
    drop(outgoing);

    let outcome = bridge.forward_block(&raw, None).await;

    assert!(matches!(outcome, Err(IngressError::Relay(_))));
    assert_eq!(unverified_entries(&bridge), 0);
    assert_eq!(bridge.block_body_rejections.unverified_forwards(), 0);
}

#[tokio::test]
async fn a_cancelled_unverified_send_gives_its_place_back() {
    let raw = unreadable_block(400, 1);
    let harness = bypass_harness();
    fill_send_channel(&harness.bridge).await;
    let bridge = harness.bridge.clone();
    let task = tokio::spawn(async move { bridge.forward_block(&raw, None).await });
    eventually(|| unverified_entries(&harness.bridge) == 1).await;

    cancel(task).await;

    eventually(|| unverified_entries(&harness.bridge) == 0).await;
    assert_eq!(
        harness.bridge.block_body_rejections.unverified_forwards(),
        0
    );
}

#[tokio::test]
async fn concurrent_copies_of_an_unreadable_body_are_sent_once() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_harness();

    let (first, second) = tokio::join!(
        harness.bridge.forward_block(&raw, None),
        harness.bridge.forward_block(&raw, None),
    );

    let modes = [first.unwrap().mode, second.unwrap().mode];
    assert!(modes.contains(&ForwardMode::RawBlockSegmentsUnverified));
    assert!(modes.contains(&ForwardMode::Deduplicated));
    assert_eq!(
        reassemble_raw_block(&raw_segments(harness.sent())).unwrap(),
        raw
    );
}

/// Known gap for #130 PR B, not a behaviour to preserve. One after the other, with
/// nothing in flight: the first body to pass the strict reader takes the header, and
/// the other strict body of that header leaves this ingress with nothing sent. The
/// gate is not involved, because the second body never reaches a relay.
#[tokio::test]
async fn known_gap_a_strict_body_stops_the_other_body_of_its_header_here() {
    let (real, other) = two_valid_bodies();
    assert_eq!(
        real[..ZCASH_FULL_HEADER_SIZE],
        other[..ZCASH_FULL_HEADER_SIZE]
    );
    let transactions = validate_block_body(&real).unwrap();
    assert_eq!(
        validate_block_body(&other),
        Ok(transactions),
        "the first body must pass the strict reader, or this is not the case under test"
    );
    let mut harness = harness();
    harness.bridge.peer_pow_limit = Some(Target::mainnet_pow_limit());

    let first = harness.bridge.forward_block(&other, None).await.unwrap();
    assert_eq!(first.mode, ForwardMode::RawBlockSegments);

    let second = harness.bridge.forward_block(&real, None).await.unwrap();
    assert_eq!(second.mode, ForwardMode::Deduplicated);
    assert_eq!(second.relay_objects, 0);

    let segments: Vec<RawBlockSegment> = harness
        .sent()
        .into_iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment,
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), other);
    assert!(harness.recorded(&real), "the record is per header");
}

// #130 PR B: the same bridge with a record per body. `known_gap_a_strict_body_stops_the_
// other_body_of_its_header_here` above is the legacy wire, and it stays as it is.

fn harness_on(wire: RawWire, bodies_per_header: usize) -> Harness {
    let mut harness = holding_bound_sends(wire, bodies_per_header);
    harness.answers_bound_sends();
    harness
}

/// [`harness_on`], with every bound send left for the test to answer.
pub(crate) fn holding_bound_sends(wire: RawWire, bodies_per_header: usize) -> Harness {
    let mut harness = harness();
    harness.bridge.raw_wire = wire;
    harness.bridge.recent_forwarded = Arc::new(std::sync::Mutex::new(
        RecentForwardedHashes::new(64, Duration::from_secs(30))
            .with_bodies_per_header(bodies_per_header),
    ));
    harness.bridge.peer_pow_limit = Some(Target::mainnet_pow_limit());
    harness
}

#[tokio::test]
async fn under_a_record_per_body_both_bodies_of_a_header_go_out() {
    let (real, other) = two_valid_bodies();
    let harness = harness_on(RawWire::Dual, 4);

    let first = harness.forward(&other).await.unwrap();
    let second = harness.forward(&real).await.unwrap();

    assert_eq!(first.mode, ForwardMode::RawBlockSegments);
    assert_eq!(second.mode, ForwardMode::RawBlockSegments);
    assert_eq!(harness.bound_copies(), vec![other, real]);
}

#[tokio::test]
async fn under_a_record_per_body_the_same_body_is_a_repeat() {
    let (real, _) = two_valid_bodies();
    let harness = harness_on(RawWire::Dual, 4);

    harness.forward(&real).await.unwrap();
    let again = harness.forward(&real).await.unwrap();

    assert_eq!(again.mode, ForwardMode::Deduplicated);
    assert_eq!(harness.bound_copies().len(), 1);
}

/// What brings a copy back on the same connection: another copy from a peer, once the
/// record of the first has ended. Nothing here asks for one, and a receiver has no way to.
#[tokio::test]
async fn the_same_ingress_sends_a_body_again_once_its_record_ends() {
    let (real, _) = two_valid_bodies();
    let mut harness = harness_on(RawWire::Bound, 4);
    harness.bridge.recent_forwarded = Arc::new(std::sync::Mutex::new(
        RecentForwardedHashes::new(64, Duration::ZERO).with_bodies_per_header(4),
    ));

    harness.forward(&real).await.unwrap();
    let again = harness.forward(&real).await.unwrap();

    assert_eq!(again.mode, ForwardMode::RawBlockSegments);
    assert_eq!(harness.bound_copies().len(), 2);
}

/// Fails closed. Which body gets the last place is the order they came in, and the real
/// one can be the one turned away.
#[tokio::test]
async fn known_gap_a_header_at_its_limit_turns_the_next_body_away() {
    let (real, other) = two_valid_bodies();
    let harness = harness_on(RawWire::Dual, 1);

    harness.forward(&other).await.unwrap();
    let turned_away = harness.forward(&real).await;

    assert!(matches!(turned_away, Err(IngressError::Relay(_))));
    assert_eq!(harness.bound_copies(), vec![other]);
}

/// A send that did not finish keeps no place and leaves no record.
#[tokio::test]
async fn a_failed_send_gives_its_place_back() {
    let (real, other) = two_valid_bodies();
    let mut harness = harness_on(RawWire::Dual, 1);
    let (closed, gone) = tokio::sync::mpsc::channel(1);
    drop(gone);
    let working = std::mem::replace(&mut harness.bridge.sender, BlockSender::for_tests(closed));

    assert!(harness.forward(&other).await.is_err());

    harness.bridge.sender = working;
    let next = harness.forward(&real).await.unwrap();
    assert_eq!(next.mode, ForwardMode::RawBlockSegments);
}

#[tokio::test]
async fn the_bound_wire_sends_no_legacy_segment() {
    let (real, _) = two_valid_bodies();
    let mut harness = harness_on(RawWire::Bound, 4);

    harness.forward(&real).await.unwrap();

    assert_eq!(harness.bound_copies(), vec![real]);
    assert!(harness.sent().is_empty());
}

#[tokio::test]
async fn the_legacy_wire_sends_no_bound_copy() {
    let (real, _) = two_valid_bodies();
    let harness = harness_on(RawWire::Legacy, 4);

    harness.forward(&real).await.unwrap();

    assert!(harness.bound_copies().is_empty());
}

// What a bound copy has to do before a body counts as sent: be encoded and go to the socket.
// That is all this ingress can know, and it says nothing of whether the copy arrived.

fn is_open(harness: &Harness, raw: &[u8]) -> bool {
    let key = body_key(raw);
    matches!(harness.bridge.forward_state(&key), ForwardState::Open)
}

fn is_sent(harness: &Harness, raw: &[u8]) -> bool {
    let key = body_key(raw);
    matches!(harness.bridge.forward_state(&key), ForwardState::Forwarded)
}

/// The record's key under a record per body.
fn body_key(raw: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]));
    digest.update(raw);
    digest.finalize().into()
}

/// A forward has nothing left to wait for once its bound send is taken, unless it waits for
/// the answer, so a few turns of this one thread are enough to tell.
async fn still_waiting(task: &JoinHandle<Result<ForwardedBlock>>) {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished(), "it did not wait for the send");
}

#[tokio::test]
async fn a_body_stays_open_until_its_bound_copy_has_gone() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Bound, 4);
    let task = spawn_forward(&harness.bridge, &real);

    let send = harness.next_bound_send().await;
    still_waiting(&task).await;
    assert!(!is_sent(&harness, &real));

    send.finish(Ok(()));
    forwarded(task).await;
    assert!(is_sent(&harness, &real));
    let again = harness.forward(&real).await.unwrap();
    assert_eq!(again.mode, ForwardMode::Deduplicated);
}

#[tokio::test]
async fn a_bound_copy_that_failed_leaves_the_body_open() {
    let failures = [
        TransportError::InvalidChunk("does not fit".into()),
        TransportError::Io(std::io::Error::other("the socket refused")),
    ];
    for failure in failures {
        let (real, _) = two_valid_bodies();
        let mut harness = holding_bound_sends(RawWire::Bound, 4);
        let task = spawn_forward(&harness.bridge, &real);

        harness.next_bound_send().await.finish(Err(failure));

        let outcome = finishes(task).await.unwrap();
        assert!(matches!(outcome, Err(IngressError::Relay(_))));
        assert!(is_open(&harness, &real));

        let again = spawn_forward(&harness.bridge, &real);
        harness.next_bound_send().await.finish(Ok(()));
        assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
        assert!(is_sent(&harness, &real));
    }
}

/// How a client that stopped looks from here: whoever held the send is gone.
#[tokio::test]
async fn a_bound_send_nobody_answered_leaves_the_body_open() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Bound, 4);
    let task = spawn_forward(&harness.bridge, &real);

    drop(harness.next_bound_send().await);

    assert!(matches!(
        finishes(task).await.unwrap(),
        Err(IngressError::Relay(_))
    ));
    assert!(is_open(&harness, &real));
    let again = spawn_forward(&harness.bridge, &real);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
}

#[tokio::test]
async fn a_cancelled_forward_leaves_the_body_open() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Bound, 4);
    let task = spawn_forward(&harness.bridge, &real);
    let send = harness.next_bound_send().await;
    still_waiting(&task).await;

    cancel(task).await;

    assert!(is_open(&harness, &real));
    send.finish(Ok(()));
    assert!(is_open(&harness, &real), "nobody was left to record it");
    let again = spawn_forward(&harness.bridge, &real);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
}

#[tokio::test]
async fn a_copy_waits_for_the_bound_send_and_is_then_a_repeat() {
    let (real, _) = two_valid_bodies();
    let key = body_key(&real);
    let mut harness = holding_bound_sends(RawWire::Bound, 4);
    let first = spawn_forward(&harness.bridge, &real);
    let send = harness.next_bound_send().await;
    let second = spawn_forward(&harness.bridge, &real);
    eventually(|| waiting_on(&harness.bridge, &key) == 1).await;

    send.finish(Ok(()));

    forwarded(first).await;
    assert_eq!(forwarded(second).await.mode, ForwardMode::Deduplicated);
    assert!(harness.bound_sends.as_mut().unwrap().try_recv().is_err());
}

#[tokio::test]
async fn a_copy_waiting_on_a_bound_send_that_failed_sends_instead() {
    let (real, _) = two_valid_bodies();
    let key = body_key(&real);
    let mut harness = holding_bound_sends(RawWire::Bound, 4);
    let first = spawn_forward(&harness.bridge, &real);
    let send = harness.next_bound_send().await;
    let second = spawn_forward(&harness.bridge, &real);
    eventually(|| waiting_on(&harness.bridge, &key) == 1).await;

    send.finish(Err(TransportError::Timeout));

    assert!(finishes(first).await.unwrap().is_err());
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(second).await.mode, ForwardMode::Deduplicated);
}

// What a failed or abandoned bound copy leaves behind. A validated body and one under the
// bypass keep different records, and each has to say the same things: what left counts, the
// body can come again, and only once every copy has gone is it a repeat.

fn bypass_on(wire: RawWire) -> Harness {
    let mut harness = bypass_harness();
    harness.bridge.raw_wire = wire;
    // As `RelayBridge::new` sets it from the config.
    harness
        .bridge
        .unverified_forwards
        .lock()
        .unwrap()
        .wait_for_sending = wire.keys_by_body();
    harness
}

fn unverified_seen(harness: &Harness) -> (usize, u64) {
    let rejections = &harness.bridge.block_body_rejections;
    (
        unverified_entries(&harness.bridge),
        rejections.unverified_forwards(),
    )
}

fn rejected(harness: &Harness) -> u64 {
    let rejections = &harness.bridge.block_body_rejections;
    let counts = BlockBodyError::ALL.iter();
    counts.map(|kind| rejections.count(kind.label())).sum()
}

/// How many copies wait on an unverified send in progress.
fn copies_waiting(bridge: &RelayBridge) -> usize {
    let forwards = bridge.unverified_forwards.lock().unwrap();
    let waiting = forwards.sending.values();
    waiting.map(|sending| sending.receiver_count()).sum()
}

/// A caller at the pool's door, at `relay_timeout`'s default. The clock here stands still until
/// nothing else can move, and blocking work counts, so this runs out only with the send held
/// and no amount of preparing can race it. What it hands back is the send the client still has.
async fn caller_gives_up(harness: &mut Harness, raw: &[u8]) -> BoundSend {
    let (bridge, raw) = (harness.bridge.clone(), raw.to_vec());
    let caller = tokio::spawn(async move {
        let forward = bridge.forward_pool_block(&raw, None);
        let gave_up = tokio::time::timeout(Duration::from_secs(1), forward).await;
        gave_up.map(|_| ())
    });
    let send = harness.next_bound_send().await;
    assert!(finishes(caller).await.unwrap().is_err(), "it did not wait");
    send
}

/// Leaves the client's bound queue full with nothing taking from it. This takes more than the
/// queue holds, so whatever the number the queue ends up full.
async fn fill_bound_queue(harness: &Harness) -> Vec<JoinHandle<()>> {
    let sends = (0..16).map(|_| {
        let sender = harness.bridge.sender.clone();
        tokio::spawn(async move {
            let _ = sender.send_bound_raw_block(Arc::default()).await;
        })
    });
    let sends = sends.collect();
    tokio::task::yield_now().await;
    sends
}

/// Lets the queue go, as a client that got through it would.
fn empty_bound_queue(harness: &mut Harness, filling: Vec<JoinHandle<()>>) {
    filling.iter().for_each(JoinHandle::abort);
    let queue = harness.bound_sends.as_mut().unwrap();
    while let Ok(send) = queue.try_recv() {
        send.finish(Ok(()));
    }
}

/// Everything a claim or a slot holds has been let go.
fn nothing_held(harness: &Harness) -> bool {
    let recent = harness.bridge.recent_forwarded.lock().unwrap();
    let forwards = harness.bridge.unverified_forwards.lock().unwrap();
    let mut entries = forwards.entries.iter();
    recent.in_flight.is_empty()
        && recent.sending_bodies.is_empty()
        && forwards.sending.is_empty()
        && entries.all(|(_, _, progress)| *progress != UnverifiedProgress::Sending)
}

/// How many copies wait on a send in progress, under a claim or a slot.
fn copies_held_up(bridge: &RelayBridge) -> usize {
    let recent = bridge.recent_forwarded.lock().unwrap();
    let on_claims = recent.in_flight.values().map(watch::Sender::receiver_count);
    on_claims.sum::<usize>() + copies_waiting(bridge)
}

/// How the send a copy waits on comes to an end.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SendEnd {
    Failed,
    /// Whatever held the send went without a word.
    NobodyAnswered,
    Cancelled,
    /// `relay_timeout`, at its default, on the clock these tests stop.
    TimedOut,
    /// The client's queue went, with the send still in hand.
    ClientWent,
}

/// However a send ends, nothing stays held, the copy that waited on it gets its answer, and
/// the body is a repeat only once every copy has gone. A wait that never ended would fail here
/// on [`finishes`], so this is also what shows none of them can. With `failure_sends` (dual),
/// a bound send that fails once the legacy copy has left leaves the body sent, and the copy
/// that waited is a repeat.
async fn a_copy_gets_past_every_end_of_a_send(
    harness_for: impl Fn() -> Harness,
    raw: &[u8],
    went: ForwardMode,
    failure_sends: bool,
) {
    use SendEnd::*;
    for end in [Failed, NobodyAnswered, Cancelled, TimedOut, ClientWent] {
        let mut harness = harness_for();
        let (bridge, body) = (harness.bridge.clone(), raw.to_vec());
        let limit = Duration::from_secs(if end == TimedOut { 1 } else { 3600 });
        let first = tokio::spawn(async move {
            let forward = bridge.forward_pool_block(&body, None);
            tokio::time::timeout(limit, forward).await
        });
        let send = harness.next_bound_send().await;
        let second = spawn_forward(&harness.bridge, raw);
        eventually(|| copies_held_up(&harness.bridge) == 1).await;

        let mut held = None;
        match end {
            Failed => send.finish(Err(TransportError::Timeout)),
            NobodyAnswered => drop(send),
            Cancelled => {
                first.abort();
                held = Some(send);
            }
            TimedOut => held = Some(send),
            ClientWent => {
                drop(harness.bound_sends.take());
                held = Some(send);
            }
        }

        let sent = failure_sends && matches!(end, Failed | NobodyAnswered | ClientWent);
        match finishes(first).await {
            Ok(Ok(outcome)) => assert_eq!(outcome.is_ok(), sent, "{end:?}"),
            Ok(Err(_)) => assert_eq!(end, TimedOut),
            Err(_) => assert_eq!(end, Cancelled),
        }
        harness.sent();
        if sent {
            let second = forwarded(second).await;
            assert_eq!(second.mode, ForwardMode::Deduplicated, "{end:?}");
            assert!(harness.sent().is_empty(), "{end:?}");
        } else if end == ClientWent {
            assert!(finishes(second).await.unwrap().is_err(), "{end:?}");
        } else {
            harness.next_bound_send().await.finish(Ok(()));
            assert_eq!(forwarded(second).await.mode, went, "{end:?}");
            harness.sent();
            let third = harness.forward(raw).await.unwrap();
            assert_eq!(third.mode, ForwardMode::Deduplicated, "{end:?}");
        }
        assert!(nothing_held(&harness), "{end:?}");
        assert_eq!(rejected(&harness), 0, "{end:?}");
        drop(held);
    }
}

#[tokio::test(start_paused = true)]
async fn a_copy_of_a_strict_body_gets_past_every_end_of_a_send_in_dual() {
    let (real, _) = two_valid_bodies();
    let harness = || holding_bound_sends(RawWire::Dual, 4);
    a_copy_gets_past_every_end_of_a_send(harness, &real, ForwardMode::RawBlockSegments, true).await;
}

#[tokio::test(start_paused = true)]
async fn a_copy_of_a_strict_body_gets_past_every_end_of_a_send_on_the_bound_wire() {
    let (real, _) = two_valid_bodies();
    let harness = || holding_bound_sends(RawWire::Bound, 4);
    a_copy_gets_past_every_end_of_a_send(harness, &real, ForwardMode::RawBlockSegments, false)
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_copy_of_an_unverified_body_gets_past_every_end_of_a_send_in_dual() {
    let raw = unreadable_block(400, 1);
    let harness = || bypass_on(RawWire::Dual);
    let went = ForwardMode::RawBlockSegmentsUnverified;
    a_copy_gets_past_every_end_of_a_send(harness, &raw, went, true).await;
}

#[tokio::test(start_paused = true)]
async fn a_copy_of_an_unverified_body_gets_past_every_end_of_a_send_on_the_bound_wire() {
    let raw = unreadable_block(400, 1);
    let harness = || bypass_on(RawWire::Bound);
    let went = ForwardMode::RawBlockSegmentsUnverified;
    a_copy_gets_past_every_end_of_a_send(harness, &raw, went, false).await;
}

/// On the bound wire nothing left, so there is nothing to count and the place goes back.
#[tokio::test]
async fn a_failed_bound_copy_gives_an_unverified_place_back() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_on(RawWire::Bound);
    let task = spawn_forward(&harness.bridge, &raw);

    harness
        .next_bound_send()
        .await
        .finish(Err(TransportError::Timeout));

    assert!(finishes(task).await.unwrap().is_err());
    assert!(harness.sent().is_empty());
    assert_eq!(unverified_seen(&harness), (0, 0));

    let again = spawn_forward(&harness.bridge, &raw);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
    assert_eq!(unverified_seen(&harness), (1, 1));
}

#[tokio::test]
async fn an_unverified_body_counts_on_the_bound_wire_once_it_has_gone() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_on(RawWire::Bound);
    let task = spawn_forward(&harness.bridge, &raw);

    harness.next_bound_send().await.finish(Ok(()));

    forwarded(task).await;
    assert_eq!(unverified_seen(&harness), (1, 1));
}

/// In dual the legacy copy left without its checks, and that is what this record bounds and
/// reports, so it counts then, and once. A failed bound copy leaves the body sent, so its next
/// delivery is a repeat and does not send the legacy copy again.
#[tokio::test]
async fn after_a_failed_bound_copy_an_unverified_body_is_sent_and_counts_once_in_dual() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_on(RawWire::Dual);
    let task = spawn_forward(&harness.bridge, &raw);

    harness
        .next_bound_send()
        .await
        .finish(Err(TransportError::Timeout));

    let first = forwarded(task).await;
    assert_eq!(first.mode, ForwardMode::RawBlockSegmentsUnverified);
    assert_eq!(legacy_copy(harness.sent()), raw);
    assert_eq!(unverified_seen(&harness), (1, 1));

    let again = harness.forward(&raw).await.unwrap();
    assert_eq!(again.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty(), "no second legacy copy");
    assert_eq!(unverified_seen(&harness), (1, 1));
}

#[tokio::test(start_paused = true)]
async fn after_a_timeout_an_unverified_body_stays_open_and_counts_once_in_dual() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_on(RawWire::Dual);

    let send = caller_gives_up(&mut harness, &raw).await;

    assert_eq!(legacy_copy(harness.sent()), raw);
    assert_eq!(unverified_seen(&harness), (1, 1));
    assert_eq!(send.raw(), raw, "the client still has it to send");
    send.finish(Ok(()));

    let again = spawn_forward(&harness.bridge, &raw);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
    assert_eq!(unverified_seen(&harness), (1, 1));
}

/// A body that left holds its place while it is owed, and goes at its time like any other.
#[test]
fn an_owed_body_holds_its_place_until_its_window_ends() {
    let start = std::time::Instant::now();
    let window = Duration::from_secs(1);
    let mut forwards = UnverifiedForwards::new(4, window, 1);
    let (first, other) = (
        UnverifiedBody {
            header_hash: [1; 32],
            digest: [2; 32],
        },
        UnverifiedBody {
            header_hash: [1; 32],
            digest: [3; 32],
        },
    );
    assert!(matches!(
        forwards.reserve(first, start),
        UnverifiedReservation::Reserved
    ));
    forwards.settle(&first, UnverifiedProgress::Owed);

    assert!(matches!(
        forwards.reserve(other, std::time::Instant::now()),
        UnverifiedReservation::HeaderFull
    ));
    let after = std::time::Instant::now() + window + Duration::from_millis(1);
    assert!(matches!(
        forwards.reserve(other, after),
        UnverifiedReservation::Reserved
    ));
}

/// In dual a failed bound copy leaves the body sent, so what leaves one owed here is a caller
/// that gave up with the bound copy still under way.
#[tokio::test(start_paused = true)]
async fn an_owed_body_can_come_again_with_its_header_at_its_limit() {
    let (raw, other) = (unreadable_block(400, 1), unreadable_block(400, 2));
    let mut harness = bypass_on(RawWire::Dual);
    harness.bridge.unverified_forwards = Arc::new(std::sync::Mutex::new(UnverifiedForwards::new(
        64,
        Duration::from_secs(30),
        1,
    )));
    caller_gives_up(&mut harness, &raw)
        .await
        .finish(Err(TransportError::Timeout));
    harness.sent();

    let turned_away = harness.forward(&other).await;
    assert!(matches!(
        turned_away,
        Err(IngressError::InvalidBlockBody(_))
    ));
    assert_eq!(rejected(&harness), 1, "that one is a real refusal");
    assert!(harness.sent().is_empty());

    let again = spawn_forward(&harness.bridge, &raw);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
}

// A copy that comes while the same body is going is neither refused nor a repeat yet: how that
// send ends says what it is. A body the record turns away is still a refusal.

#[tokio::test]
async fn a_copy_during_an_unverified_send_waits_and_is_then_a_repeat() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_on(RawWire::Bound);
    let first = spawn_forward(&harness.bridge, &raw);
    let send = harness.next_bound_send().await;
    let second = spawn_forward(&harness.bridge, &raw);
    eventually(|| copies_waiting(&harness.bridge) == 1).await;
    assert_eq!(rejected(&harness), 0);

    send.finish(Ok(()));

    forwarded(first).await;
    assert_eq!(forwarded(second).await.mode, ForwardMode::Deduplicated);
    assert_eq!(rejected(&harness), 0);
    assert_eq!(unverified_seen(&harness), (1, 1));
}

/// On the bound wire the copy that waited sends when that send fails. In dual the legacy copy
/// left, so the body is sent and the copy that waited is a repeat.
#[tokio::test]
async fn a_copy_during_an_unverified_send_goes_by_how_that_send_fails() {
    for wire in [RawWire::Bound, RawWire::Dual] {
        let raw = unreadable_block(400, 1);
        let mut harness = bypass_on(wire);
        let first = spawn_forward(&harness.bridge, &raw);
        let send = harness.next_bound_send().await;
        let second = spawn_forward(&harness.bridge, &raw);
        eventually(|| copies_waiting(&harness.bridge) == 1).await;

        send.finish(Err(TransportError::Timeout));

        if wire == RawWire::Dual {
            forwarded(first).await;
            assert_eq!(forwarded(second).await.mode, ForwardMode::Deduplicated);
        } else {
            assert!(finishes(first).await.unwrap().is_err());
            harness.next_bound_send().await.finish(Ok(()));
            assert_ne!(forwarded(second).await.mode, ForwardMode::Deduplicated);
        }
        assert_eq!(rejected(&harness), 0, "{wire:?}");
        assert_eq!(unverified_seen(&harness), (1, 1), "{wire:?}");
    }
}

#[tokio::test]
async fn another_body_past_the_limit_during_a_send_is_still_refused() {
    let (raw, other) = (unreadable_block(400, 1), unreadable_block(400, 2));
    let mut harness = bypass_on(RawWire::Bound);
    harness.bridge.unverified_forwards = Arc::new(std::sync::Mutex::new(UnverifiedForwards::new(
        64,
        Duration::from_secs(30),
        1,
    )));
    let first = spawn_forward(&harness.bridge, &raw);
    let send = harness.next_bound_send().await;

    let turned_away = harness.forward(&other).await;

    assert!(matches!(
        turned_away,
        Err(IngressError::InvalidBlockBody(_))
    ));
    assert_eq!(rejected(&harness), 1);
    send.finish(Ok(()));
    forwarded(first).await;
}

/// In dual a full bound queue holds no legacy copy back, and once that copy has left the body
/// is sent: its next delivery is a repeat, not a second legacy copy.
#[tokio::test]
async fn a_full_bound_queue_in_dual_leaves_an_unverified_body_sent_by_its_legacy_copy() {
    let raw = unreadable_block(400, 1);
    let mut harness = bypass_on(RawWire::Dual);
    let filling = fill_bound_queue(&harness).await;

    let went = finishes(harness.bridge.forward_pool_block(&raw, None)).await;

    assert!(went.is_ok());
    assert_eq!(legacy_copy(harness.sent()), raw);
    assert_eq!(unverified_seen(&harness), (1, 1));
    empty_bound_queue(&mut harness, filling);

    let again = harness.forward(&raw).await.unwrap();
    assert_eq!(again.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
    assert_eq!(unverified_seen(&harness), (1, 1));
}

// Dual: the legacy copy owes nothing to the bound one.

fn legacy_copy(sent: Vec<RelayPayload>) -> Vec<u8> {
    reassemble_raw_block(&raw_segments(sent)).unwrap()
}

/// And the body is sent by it, so a bound path that keeps failing costs no legacy copy again.
#[tokio::test]
async fn a_bound_failure_lets_the_legacy_copy_go_in_dual() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 4);
    drop(harness.bound_sends.take());

    let outcome = harness.forward(&real).await;

    assert_eq!(outcome.unwrap().mode, ForwardMode::RawBlockSegments);
    assert_eq!(legacy_copy(harness.sent()), real);
    assert!(
        is_sent(&harness, &real),
        "the failed bound copy is not tried again"
    );
    for _ in 0..3 {
        let again = harness.forward(&real).await.unwrap();
        assert_eq!(again.mode, ForwardMode::Deduplicated);
        assert!(harness.sent().is_empty(), "no legacy copy again");
    }
}

/// The answer from a bound send that takes its time is no reason for legacy to wait.
#[tokio::test]
async fn a_bound_copy_under_way_lets_the_legacy_copy_go_in_dual() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 4);
    let task = spawn_forward(&harness.bridge, &real);

    let send = harness.next_bound_send().await;
    eventually(|| !harness.outgoing.is_empty()).await;
    still_waiting(&task).await;

    assert_eq!(legacy_copy(harness.sent()), real);
    send.finish(Ok(()));
    forwarded(task).await;
}

/// A body counts under its header from the moment a copy of it has left, so a bound path in
/// trouble is no way past the limit. Its legacy copy left, so it is sent, and it does not
/// come again.
#[tokio::test]
async fn after_a_failed_bound_copy_a_strict_body_is_sent_and_keeps_its_place_in_dual() {
    let (real, other) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 1);
    let task = spawn_forward(&harness.bridge, &real);
    harness
        .next_bound_send()
        .await
        .finish(Err(TransportError::Timeout));
    forwarded(task).await;
    assert_eq!(legacy_copy(harness.sent()), real);
    assert!(is_sent(&harness, &real));

    let turned_away = harness.forward(&other).await;
    assert!(matches!(turned_away, Err(IngressError::Relay(_))));
    assert!(harness.sent().is_empty(), "nothing of the other body left");

    let again = harness.forward(&real).await.unwrap();
    assert_eq!(again.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty(), "no legacy copy again");
}

/// The value did not change. Past it the caller goes, the send does not, and the body stays
/// open and keeps its place: what the client still sends has nobody left to record it.
#[tokio::test(start_paused = true)]
async fn after_a_timeout_a_strict_body_stays_open_and_keeps_its_place_in_dual() {
    let (real, other) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 1);

    let send = caller_gives_up(&mut harness, &real).await;

    assert_eq!(legacy_copy(harness.sent()), real);
    assert!(is_open(&harness, &real));
    assert_eq!(send.raw(), real, "the client still has it to send");
    send.finish(Ok(()));
    assert!(is_open(&harness, &real));
    let turned_away = harness.forward(&other).await;
    assert!(matches!(turned_away, Err(IngressError::Relay(_))));

    let again = spawn_forward(&harness.bridge, &real);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
    assert!(is_sent(&harness, &real));
}

/// On the bound wire nothing has left yet, so a failed copy keeps no place.
#[tokio::test]
async fn a_failed_copy_on_the_bound_wire_keeps_no_place_under_its_header() {
    let (real, other) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Bound, 1);
    let task = spawn_forward(&harness.bridge, &real);
    harness
        .next_bound_send()
        .await
        .finish(Err(TransportError::Timeout));
    assert!(finishes(task).await.unwrap().is_err());

    let next = spawn_forward(&harness.bridge, &other);
    harness.next_bound_send().await.finish(Ok(()));

    assert_ne!(forwarded(next).await.mode, ForwardMode::Deduplicated);
}

/// A body under a claim is counted once, however far its send has got.
#[tokio::test]
async fn a_body_counts_once_while_it_goes_from_sending_to_sent() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 4);
    let task = spawn_forward(&harness.bridge, &real);
    let send = harness.next_bound_send().await;
    let header = hash_of(&real);
    let count = |harness: &Harness| {
        let mut recent = harness.bridge.recent_forwarded.lock().unwrap();
        recent.bodies_of(&header, &[0; 32], std::time::Instant::now())
    };

    eventually(|| !harness.outgoing.is_empty()).await;
    still_waiting(&task).await;
    assert_eq!(count(&harness), 1);
    send.finish(Ok(()));
    forwarded(task).await;
    assert_eq!(count(&harness), 1);
}

/// The limit is for bodies, and on this wire a header has one. With no record of what was sent,
/// every copy is a repeat of that one, as it was before there was a limit.
#[tokio::test]
async fn the_legacy_wire_with_no_record_turns_no_copy_away() {
    let (real, _) = two_valid_bodies();
    let mut harness = harness_on(RawWire::Legacy, 4);
    harness.bridge.recent_forwarded = Arc::new(std::sync::Mutex::new(
        RecentForwardedHashes::new(0, Duration::from_secs(30)).with_bodies_per_header(4),
    ));

    for _ in 0..6 {
        let sent = harness.forward(&real).await.unwrap();
        assert_ne!(sent.mode, ForwardMode::Deduplicated);
        harness.sent();
    }
}

/// Nor the other way round: legacy waiting for room in its channel does not keep the bound
/// copy from the client, so a caller that gives up leaves that copy going.
#[tokio::test]
async fn a_slow_legacy_copy_lets_the_bound_copy_go_in_dual() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 4);
    fill_send_channel(&harness.bridge).await;
    let task = spawn_forward(&harness.bridge, &real);

    let send = harness.next_bound_send().await;

    assert_eq!(send.raw(), real);
    cancel(task).await;
    send.finish(Ok(()));
    assert!(is_open(&harness, &real));
}

/// The client's bound queue is full. That is no reason for legacy to wait. On the bound wire
/// the caller hears of it and the body stays open; in dual the legacy copy left, so the body
/// is sent and is not sent again.
#[tokio::test]
async fn a_full_bound_queue_comes_back_to_the_caller_of_a_strict_body() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Bound, 4);
    let filling = fill_bound_queue(&harness).await;

    let refused = finishes(harness.bridge.forward_pool_block(&real, None)).await;

    assert!(matches!(refused, Err(IngressError::Relay(_))));
    assert!(harness.sent().is_empty());
    assert!(is_open(&harness, &real));
    empty_bound_queue(&mut harness, filling);

    let again = spawn_forward(&harness.bridge, &real);
    harness.next_bound_send().await.finish(Ok(()));
    assert_ne!(forwarded(again).await.mode, ForwardMode::Deduplicated);
    assert!(is_sent(&harness, &real));
}

#[tokio::test]
async fn a_full_bound_queue_in_dual_leaves_a_strict_body_sent_by_its_legacy_copy() {
    let (real, _) = two_valid_bodies();
    let mut harness = holding_bound_sends(RawWire::Dual, 4);
    let filling = fill_bound_queue(&harness).await;

    let went = finishes(harness.bridge.forward_pool_block(&real, None)).await;

    assert!(went.is_ok());
    assert_eq!(legacy_copy(harness.sent()), real);
    assert!(is_sent(&harness, &real));
    empty_bound_queue(&mut harness, filling);

    let again = harness.forward(&real).await.unwrap();
    assert_eq!(again.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
}

/// The real bridge through a real client and node to a real receiver: both bodies of one
/// header come out whole. There is no sidecar in this crate, so this stops at the channel.
#[tokio::test]
async fn both_bodies_cross_a_real_node_from_the_bridge() {
    use sovright_relay::{
        AuthKey, BoundRawConfig, ClientConfig, RelayClient, RelayConfig, RelayNode,
        StubPowValidator,
    };

    const KEY: [u8; 32] = [0x42; 32];
    let config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![AuthKey::new("fleet", KEY)])
        .with_fec(10, 3)
        .with_bound_raw(Default::default());
    let mut node = RelayNode::with_validator(config, StubPowValidator).unwrap();
    node.bind().await.unwrap();
    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let running = Arc::clone(&node);
    tokio::spawn(async move { running.run().await });

    let client_config = || {
        ClientConfig::new(vec![node_addr], KEY)
            .with_bind_addr("127.0.0.1:0".parse().unwrap())
            .with_auth_required(true)
            .with_send_pacing(32, Duration::from_micros(200))
    };
    let mut receiver_client =
        RelayClient::new(client_config().with_bound_raw(BoundRawConfig::default())).unwrap();
    receiver_client.bind().await.unwrap();
    let (mut receiver, outgoing) = receiver_client.take_receiver().unwrap();
    let mut blocks = receiver.take_bound_blocks().unwrap();
    tokio::spawn(async move {
        let _keep = receiver;
        receiver_client.run_with_outgoing(outgoing).await
    });
    finishes(async {
        while node.session_count().await == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    let mut sending_client = RelayClient::new(client_config()).unwrap();
    sending_client.bind().await.unwrap();
    let mut harness = harness_on(RawWire::Bound, 4);
    harness.bridge.sender = sending_client.sender();
    tokio::spawn(async move { sending_client.run().await });

    let (real, other) = two_valid_bodies();
    harness.forward(&other).await.unwrap();
    harness.forward(&real).await.unwrap();

    for body in [other, real] {
        let block = tokio::time::timeout(Duration::from_secs(10), blocks.recv())
            .await
            .expect("a body crosses the relay")
            .unwrap();
        assert_eq!(block.raw(), body);
        block.finish();
    }
}
