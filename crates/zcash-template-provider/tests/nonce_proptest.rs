use proptest::prelude::*;
use zcash_template_provider::NoncePartitioner;

proptest! {
    /// Different IDs within the addressable range always produce different nonce_1 prefixes.
    /// The addressable range is 2^(nonce_1_len * 8), so we constrain IDs to fit.
    #[test]
    fn nonce_partitions_non_overlapping(
        nonce_1_len in 1usize..=8,
        id_a in 0u64..1000,
        id_b in 0u64..1000,
    ) {
        // Constrain IDs to the addressable space for this nonce_1_len.
        // With nonce_1_len bytes, we can encode 2^(len*8) unique prefixes.
        let (id_a, id_b) = if nonce_1_len < 8 {
            let max_id = 1u64 << (nonce_1_len * 8);
            (id_a % max_id, id_b % max_id)
        } else {
            (id_a, id_b)
        };
        prop_assume!(id_a != id_b);
        let partitioner = NoncePartitioner::new(nonce_1_len).unwrap();
        let range_a = partitioner.get_range(id_a);
        let range_b = partitioner.get_range(id_b);
        prop_assert_ne!(range_a.nonce_1, range_b.nonce_1);
    }

    /// nonce_1 length always matches the configured length.
    #[test]
    fn nonce_1_correct_length(
        nonce_1_len in 1usize..=32,
        id in 0u64..10000,
    ) {
        let partitioner = NoncePartitioner::new(nonce_1_len).unwrap();
        let range = partitioner.get_range(id);
        prop_assert_eq!(range.nonce_1.len(), nonce_1_len);
    }

    /// nonce_1 + nonce_2 always covers exactly 32 bytes.
    #[test]
    fn nonce_lengths_sum_to_32(
        nonce_1_len in 1usize..=32,
        id in 0u64..10000,
    ) {
        let partitioner = NoncePartitioner::new(nonce_1_len).unwrap();
        let range = partitioner.get_range(id);
        prop_assert_eq!(range.nonce_1.len() + range.nonce_2_len, 32);
    }

    /// make_nonce produces a valid 32-byte nonce when given correct nonce_2 length.
    #[test]
    fn make_nonce_roundtrip(
        nonce_1_len in 1usize..=31,
        id in 0u64..1000,
    ) {
        let partitioner = NoncePartitioner::new(nonce_1_len).unwrap();
        let range = partitioner.get_range(id);
        let nonce_2 = vec![0xab; range.nonce_2_len];
        let full = range.make_nonce(&nonce_2).unwrap();
        prop_assert_eq!(&full[..nonce_1_len], &range.nonce_1[..]);
        prop_assert_eq!(&full[nonce_1_len..], &nonce_2[..]);
    }

    /// Constructor rejects nonce_1_len > 32.
    #[test]
    fn rejects_invalid_nonce_1_len(
        nonce_1_len in 33usize..256,
    ) {
        prop_assert!(NoncePartitioner::new(nonce_1_len).is_none());
    }
}
