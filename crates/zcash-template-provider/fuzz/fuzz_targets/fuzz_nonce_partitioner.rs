#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zcash_template_provider::NoncePartitioner;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    nonce_1_len: usize,
    id: u64,
    nonce_2: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    // Clamp nonce_1_len to avoid massive allocations
    let nonce_1_len = input.nonce_1_len % 64;

    if let Some(partitioner) = NoncePartitioner::new(nonce_1_len) {
        assert_eq!(partitioner.nonce_1_len(), nonce_1_len);
        assert_eq!(partitioner.nonce_2_len(), 32 - nonce_1_len);

        let range = partitioner.get_range(input.id);
        assert_eq!(range.nonce_1.len(), nonce_1_len);
        assert_eq!(range.nonce_2_len, 32 - nonce_1_len);

        // make_nonce should succeed only if nonce_2 has the right length
        let result = range.make_nonce(&input.nonce_2);
        if input.nonce_2.len() == range.nonce_2_len {
            let nonce = result.expect("make_nonce should succeed with correct length");
            assert_eq!(nonce.len(), 32);
            // Verify nonce_1 prefix is preserved
            assert_eq!(&nonce[..nonce_1_len], &range.nonce_1[..]);
        } else {
            assert!(result.is_none(), "make_nonce should fail with wrong length");
        }
    } else {
        // new() should only fail for nonce_1_len > 32
        assert!(nonce_1_len > 32, "NoncePartitioner::new should only fail for len > 32");
    }
});
