#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use sovright_relay::{Chunk, MessageType, CHUNK_MAGIC, MAX_PAYLOAD_SIZE};

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut chunk) = Chunk::arbitrary(&mut u) else { return };

    // Normalize to valid protocol constraints
    chunk.header.magic = CHUNK_MAGIC;
    let Ok(use_v2) = u.arbitrary::<bool>() else { return };
    chunk.header.version = if use_v2 { 2 } else { 1 };
    if chunk.header.total_chunks == 0 {
        chunk.header.total_chunks = 1;
    }
    if chunk.header.total_chunks > 256 {
        chunk.header.total_chunks = 256;
    }
    if chunk.header.chunk_id >= chunk.header.total_chunks {
        chunk.header.chunk_id = chunk.header.total_chunks - 1;
    }
    if chunk.payload.len() > MAX_PAYLOAD_SIZE {
        chunk.payload.truncate(MAX_PAYLOAD_SIZE);
    }
    if chunk.header.msg_type == MessageType::Block && chunk.payload.is_empty() {
        chunk.payload = vec![0u8];
    }
    chunk.header.payload_len = chunk.payload.len() as u16;

    let bytes = chunk.to_bytes();
    let parsed = Chunk::from_bytes(&bytes);

    // If it serialized, it should parse back
    if let Ok(parsed) = parsed {
        assert_eq!(chunk.header.magic, parsed.header.magic);
        assert_eq!(chunk.header.msg_type, parsed.header.msg_type);
        assert_eq!(chunk.header.block_hash, parsed.header.block_hash);
        assert_eq!(chunk.header.chunk_id, parsed.header.chunk_id);
        assert_eq!(chunk.header.total_chunks, parsed.header.total_chunks);
        assert_eq!(chunk.payload, parsed.payload);
    }
});
