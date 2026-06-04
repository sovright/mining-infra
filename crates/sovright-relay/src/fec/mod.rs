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
