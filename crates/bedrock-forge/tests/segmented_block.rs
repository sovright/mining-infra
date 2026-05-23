use bedrock_forge::{RawBlockSegment, SegmentedBlockError, reassemble_raw_block, split_raw_block};

fn block_hash() -> [u8; 32] {
    [0x42; 32]
}

#[test]
fn split_raw_block_respects_encoded_frame_budget() {
    let raw_block = vec![0xab; 25_000];
    let max_frame_len = RawBlockSegment::HEADER_LEN + 4_096;

    let segments = split_raw_block(block_hash(), &raw_block, max_frame_len).unwrap();

    assert!(segments.len() > 1);
    assert!(
        segments
            .iter()
            .all(|segment| segment.encoded_len() <= max_frame_len)
    );
    assert_eq!(segments[0].segment_count as usize, segments.len());
}

#[test]
fn segmented_raw_block_round_trips_after_encode_decode() {
    let raw_block = (0..80_000)
        .map(|value| (value % 251) as u8)
        .collect::<Vec<_>>();
    let max_frame_len = RawBlockSegment::HEADER_LEN + 8_192;
    let segments = split_raw_block(block_hash(), &raw_block, max_frame_len).unwrap();
    let decoded = segments
        .iter()
        .map(|segment| RawBlockSegment::decode(&segment.encode()).unwrap())
        .collect::<Vec<_>>();

    let reassembled = reassemble_raw_block(&decoded).unwrap();

    assert_eq!(reassembled, raw_block);
}

#[test]
fn reassemble_raw_block_rejects_missing_segment() {
    let raw_block = vec![0xcd; 12_000];
    let max_frame_len = RawBlockSegment::HEADER_LEN + 4_000;
    let mut segments = split_raw_block(block_hash(), &raw_block, max_frame_len).unwrap();
    segments.pop();

    let error = reassemble_raw_block(&segments).unwrap_err();

    assert_eq!(
        error,
        SegmentedBlockError::MissingSegment { segment_index: 2 }
    );
}

#[test]
fn reassemble_raw_block_rejects_digest_mismatch() {
    let raw_block = vec![0xef; 12_000];
    let max_frame_len = RawBlockSegment::HEADER_LEN + 4_000;
    let mut segments = split_raw_block(block_hash(), &raw_block, max_frame_len).unwrap();
    segments[1].payload[0] ^= 0x01;

    let error = reassemble_raw_block(&segments).unwrap_err();

    assert_eq!(error, SegmentedBlockError::DigestMismatch);
}

#[test]
fn split_raw_block_rejects_budget_without_payload_room() {
    let raw_block = vec![0x11; 10];
    let error = split_raw_block(block_hash(), &raw_block, RawBlockSegment::HEADER_LEN).unwrap_err();

    assert_eq!(error, SegmentedBlockError::SegmentPayloadTooSmall);
}
