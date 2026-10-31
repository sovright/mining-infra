//! Block body validation at the ingress boundary (#130). Forwarding is observed
//! through the sender's channel, so "nothing was sent" is a direct check rather
//! than a timeout.
use super::nu7_fixture::Nu7Fixture;
use super::*;
use sovright_relay::{
    BlockBodyError, RelayPayload, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    validate_block_body, zcash_block_hash,
};
use tokio::sync::mpsc;
use zcash_pool_common::fixtures;

struct Harness {
    bridge: RelayBridge,
    outgoing: mpsc::Receiver<RelayPayload>,
    _client: RelayClient,
}

fn harness() -> Harness {
    let mut client = RelayClient::new(
        ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true),
    )
    .unwrap();
    let sender = client.sender();
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
    };
    Harness {
        bridge,
        outgoing,
        _client: client,
    }
}

impl Harness {
    fn sent(&mut self) -> Vec<RelayPayload> {
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
fn good_and_bad() -> (Vec<u8>, Vec<u8>) {
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

/// The block parser already refuses these; they must stay refused and send
/// nothing.
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
        assert!(
            harness
                .bridge
                .forward_block(&malformed, None)
                .await
                .is_err()
        );
        assert!(harness.sent().is_empty());
        assert!(!harness.recorded(&malformed));
    }
}

/// The forwarded compact block comes from the block parser and the check from
/// the transaction reader, so they must agree on real blocks.
#[test]
fn the_reader_and_the_block_parser_agree_on_real_blocks() {
    for raw in [Nu7Fixture::load().raw, fixtures::mainnet_raw_block()] {
        let compact = compact_block_from_raw_block(&raw).unwrap();
        assert_eq!(validate_block_body(&raw), Ok(compact.tx_count()));
    }
}

#[test]
fn a_parser_and_reader_disagreement_is_refused() {
    let raw = Nu7Fixture::load().raw;
    let mut compact = compact_block_from_raw_block(&raw).unwrap();
    compact.prefilled_txs.pop();

    let error = check_forwarded_body(&raw, &compact).unwrap_err();

    let IngressError::InvalidBlockBody(error) = error else {
        panic!("unexpected error {error}");
    };
    assert_eq!(
        error,
        BlockBodyError::CountMismatch {
            parsed: 2,
            declared: 1
        }
    );
}
