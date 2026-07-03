//! Forward Error Correction for compact block relay
//!
//! Uses Reed-Solomon erasure coding to enable block reconstruction
//! even when some UDP packets are lost.

mod decoder;
mod encoder;
mod error;

pub use decoder::FecDecoder;
pub use encoder::FecEncoder;
pub use error::FecError;

use crate::transport::MAX_TOTAL_CHUNKS;

/// Adaptive parity ratio: ~1 parity shard per this many data shards (min 1).
///
/// Eight yields ~12.5% redundancy, comparable to the fixed 224/32 (~14%)
/// production profile while collapsing tiny blocks to a handful of packets.
pub const ADAPTIVE_PARITY_DIVISOR: usize = 8;

/// Skeleton parity ratio: ~1 parity shard per this many data shards.
///
/// The compact skeleton is the reconstruction-critical fast path, usually a
/// single UDP packet, so it is sized with heavier redundancy than the normal
/// adaptive profile (divisor 4 rather than 8) and a parity floor of
/// [`SKELETON_MIN_PARITY_SHARDS`], so a single lost packet still reconstructs.
pub const SKELETON_PARITY_DIVISOR: usize = 4;

/// Minimum parity shards for a skeleton FEC profile. A one-data-shard skeleton
/// therefore ships with two parity copies (any one of the three shards
/// reconstructs it), surviving a single packet loss.
pub const SKELETON_MIN_PARITY_SHARDS: usize = 2;

/// Size a Reed-Solomon FEC profile to a specific block length.
///
/// Returns `Some((data_shards, parity_shards))` sized so that:
/// * `data_shards = max(1, ceil(data_len / max_payload))` -- just enough data
///   shards for the payload to fit one shard per UDP chunk, and
/// * `parity_shards = max(1, ceil(data_shards / ADAPTIVE_PARITY_DIVISOR))`.
///
/// Returns `None` when the resulting `data_shards + parity_shards` would exceed
/// [`MAX_TOTAL_CHUNKS`] (256) -- the signal for the caller to fall back to the
/// fixed scheme and emit version-2 chunks. Very large blocks therefore keep the
/// existing behavior instead of overflowing the 8-bit shard space.
///
/// `max_payload` must be > 0 (the per-chunk payload budget); `data_len` of 0
/// returns `None` since there is nothing to encode.
pub fn adaptive_shards(data_len: usize, max_payload: usize) -> Option<(usize, usize)> {
    if data_len == 0 || max_payload == 0 {
        return None;
    }
    let data_shards = data_len.div_ceil(max_payload).max(1);
    let parity_shards = data_shards.div_ceil(ADAPTIVE_PARITY_DIVISOR).max(1);
    if data_shards + parity_shards > MAX_TOTAL_CHUNKS as usize {
        return None;
    }
    Some((data_shards, parity_shards))
}

/// Size a Reed-Solomon FEC profile for a compact *skeleton* of a given length.
///
/// Identical to [`adaptive_shards`] for the data-shard count, but applies a
/// heavier parity floor so the reconstruction-critical skeleton survives a lost
/// packet: `parity_shards = max(SKELETON_MIN_PARITY_SHARDS,
/// ceil(data_shards / SKELETON_PARITY_DIVISOR))`.
///
/// Returns `None` under the same overflow / zero-input conditions as
/// [`adaptive_shards`] (the caller then falls back to the fixed scheme).
pub fn adaptive_shards_skeleton(data_len: usize, max_payload: usize) -> Option<(usize, usize)> {
    if data_len == 0 || max_payload == 0 {
        return None;
    }
    let data_shards = data_len.div_ceil(max_payload).max(1);
    let parity_shards = data_shards
        .div_ceil(SKELETON_PARITY_DIVISOR)
        .max(SKELETON_MIN_PARITY_SHARDS);
    if data_shards + parity_shards > MAX_TOTAL_CHUNKS as usize {
        return None;
    }
    Some((data_shards, parity_shards))
}

#[cfg(test)]
mod adaptive_tests {
    use super::*;
    use crate::transport::MAX_PAYLOAD_SIZE_V3;

    #[test]
    fn one_byte_is_one_data_one_parity() {
        assert_eq!(adaptive_shards(1, MAX_PAYLOAD_SIZE_V3), Some((1, 1)));
    }

    #[test]
    fn one_kib_is_single_shard() {
        assert_eq!(adaptive_shards(1024, MAX_PAYLOAD_SIZE_V3), Some((1, 1)));
    }

    #[test]
    fn typical_compact_block_is_two_data_one_parity() {
        // ~1.6 KB compact block => 2 data shards, 1 parity => 3 chunks.
        assert_eq!(adaptive_shards(1624, MAX_PAYLOAD_SIZE_V3), Some((2, 1)));
    }

    #[test]
    fn exactly_max_payload_is_single_data_shard() {
        assert_eq!(
            adaptive_shards(MAX_PAYLOAD_SIZE_V3, MAX_PAYLOAD_SIZE_V3),
            Some((1, 1))
        );
        // One byte over spills into a second data shard.
        assert_eq!(
            adaptive_shards(MAX_PAYLOAD_SIZE_V3 + 1, MAX_PAYLOAD_SIZE_V3),
            Some((2, 1))
        );
    }

    #[test]
    fn multi_packet_block_scales_parity() {
        // 100 data shards worth => parity = ceil(100/8) = 13.
        let len = 100 * MAX_PAYLOAD_SIZE_V3;
        assert_eq!(adaptive_shards(len, MAX_PAYLOAD_SIZE_V3), Some((100, 13)));
    }

    #[test]
    fn boundary_just_under_limit_is_some() {
        // 227 data shards => parity ceil(227/8)=29 => 256 total (== limit).
        let len = 227 * MAX_PAYLOAD_SIZE_V3;
        assert_eq!(adaptive_shards(len, MAX_PAYLOAD_SIZE_V3), Some((227, 29)));
    }

    #[test]
    fn oversized_block_returns_fallback_signal() {
        // 228 data shards => parity ceil(228/8)=29 => 257 total (> 256) => None.
        let len = 228 * MAX_PAYLOAD_SIZE_V3;
        assert_eq!(adaptive_shards(len, MAX_PAYLOAD_SIZE_V3), None);
        // A very large block also falls back.
        assert_eq!(adaptive_shards(10_000_000, MAX_PAYLOAD_SIZE_V3), None);
    }

    #[test]
    fn zero_inputs_return_none() {
        assert_eq!(adaptive_shards(0, MAX_PAYLOAD_SIZE_V3), None);
        assert_eq!(adaptive_shards(100, 0), None);
    }

    #[test]
    fn skeleton_single_shard_ships_two_parity_copies() {
        // A one-packet skeleton must survive a single lost packet: 1 data + 2
        // parity, so any one of the three shards reconstructs it.
        assert_eq!(
            adaptive_shards_skeleton(1, MAX_PAYLOAD_SIZE_V3),
            Some((1, 2))
        );
        assert_eq!(
            adaptive_shards_skeleton(1024, MAX_PAYLOAD_SIZE_V3),
            Some((1, 2))
        );
        assert_eq!(
            adaptive_shards_skeleton(MAX_PAYLOAD_SIZE_V3, MAX_PAYLOAD_SIZE_V3),
            Some((1, 2))
        );
    }

    #[test]
    fn skeleton_parity_floor_beats_the_normal_adaptive_profile() {
        // For the same data length, the skeleton profile carries at least as
        // much parity as the normal adaptive profile, and strictly more for
        // small blocks (the fast-path redundancy the skeleton exists for).
        for len in [1usize, 1024, 4096, 20 * MAX_PAYLOAD_SIZE_V3] {
            let (sd, sp) = adaptive_shards_skeleton(len, MAX_PAYLOAD_SIZE_V3).unwrap();
            let (ad, ap) = adaptive_shards(len, MAX_PAYLOAD_SIZE_V3).unwrap();
            assert_eq!(sd, ad, "skeleton keeps the same data-shard count");
            assert!(sp >= ap, "skeleton parity must not be lower");
            assert!(sp >= SKELETON_MIN_PARITY_SHARDS);
        }
    }

    #[test]
    fn skeleton_scales_parity_by_quarter() {
        // 100 data shards => ceil(100/4) = 25 parity (vs 13 for the normal 1/8).
        let len = 100 * MAX_PAYLOAD_SIZE_V3;
        assert_eq!(
            adaptive_shards_skeleton(len, MAX_PAYLOAD_SIZE_V3),
            Some((100, 25))
        );
    }

    #[test]
    fn skeleton_zero_inputs_return_none() {
        assert_eq!(adaptive_shards_skeleton(0, MAX_PAYLOAD_SIZE_V3), None);
        assert_eq!(adaptive_shards_skeleton(100, 0), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_creates_correct_shard_count() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let data = vec![0u8; 1000];
        let shards = encoder.encode(&data).unwrap();
        assert_eq!(shards.len(), 13); // 10 data + 3 parity
    }

    #[test]
    fn encoder_shards_have_equal_size() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let data = vec![0u8; 1000];
        let shards = encoder.encode(&data).unwrap();
        let shard_size = shards[0].len();
        for shard in &shards {
            assert_eq!(shard.len(), shard_size);
        }
    }

    #[test]
    fn encoder_rejects_zero_data_shards() {
        let result = FecEncoder::new(0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn encoder_rejects_zero_parity_shards() {
        let result = FecEncoder::new(10, 0);
        assert!(result.is_err());
    }

    #[test]
    fn encoder_rejects_empty_data() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let result = encoder.encode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn encoder_handles_single_byte() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let shards = encoder.encode(&[42u8]).unwrap();
        assert_eq!(shards.len(), 13);
        // Single byte with 10 data shards means each shard is 1 byte
        assert!(shards.iter().all(|s| s.len() == 1));
    }

    #[test]
    fn decoder_reconstructs_from_all_shards() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!".to_vec();
        let shards = encoder.encode(&original).unwrap();

        // Convert to Option<Vec<u8>> (all present)
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        let recovered = decoder.decode(shard_opts, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn decoder_reconstructs_with_missing_shards() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!".to_vec();
        let shards = encoder.encode(&original).unwrap();

        // Simulate losing 3 shards (parity can recover up to parity_shards losses)
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[2] = None;
        shard_opts[5] = None;
        shard_opts[8] = None;

        let recovered = decoder.decode(shard_opts, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn decoder_fails_with_too_many_missing() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!".to_vec();
        let shards = encoder.encode(&original).unwrap();

        // Simulate losing 4 shards (more than parity_shards)
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[0] = None;
        shard_opts[1] = None;
        shard_opts[2] = None;
        shard_opts[3] = None;

        let result = decoder.decode(shard_opts, original.len());
        assert!(result.is_err());
    }
}
