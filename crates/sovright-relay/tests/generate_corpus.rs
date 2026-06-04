//! One-shot utility to generate seed corpus files for fuzzing.
//! Run: cargo test -p sovright-relay --features generate-corpus --test generate_corpus
#![cfg(feature = "generate-corpus")]

use sovright_relay::{CHUNK_MAGIC, Chunk, ChunkHeader};
use std::fs;

#[test]
fn generate_fuzz_corpus() {
    let corpus_base = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus");

    // ChunkHeader corpus
    let dir = format!("{}/fuzz_chunk_header", corpus_base);
    fs::create_dir_all(&dir).unwrap();

    // Valid v1 header
    let header = ChunkHeader::new_block(&[0xaa; 32], 0, 4, 100);
    let mut buf = vec![0u8; 44];
    write_header_v1(&header, &mut buf);
    fs::write(format!("{}/valid_v1", dir), &buf).unwrap();

    // Empty/short inputs
    fs::write(format!("{}/empty", dir), &[] as &[u8]).unwrap();
    fs::write(format!("{}/short", dir), &[0x5A, 0x43]).unwrap();

    // Bad magic
    let mut bad_magic = buf.clone();
    bad_magic[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    fs::write(format!("{}/bad_magic", dir), &bad_magic).unwrap();

    // Chunk corpus
    let dir = format!("{}/fuzz_chunk", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let chunk = Chunk::new(
        ChunkHeader::new_block(&[0xbb; 32], 0, 2, 10),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    );
    fs::write(format!("{}/valid_chunk", dir), chunk.to_bytes()).unwrap();

    // Roundtrip corpus (same as chunk)
    let dir = format!("{}/fuzz_roundtrip_chunk", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    fs::write(format!("{}/valid_chunk", dir), chunk.to_bytes()).unwrap();

    println!("Corpus files generated in {}", corpus_base);
}

fn write_header_v1(header: &ChunkHeader, buf: &mut [u8]) {
    buf[0..4].copy_from_slice(&CHUNK_MAGIC.to_be_bytes());
    buf[4] = 1; // version
    buf[5] = header.msg_type as u8;
    buf[6..38].copy_from_slice(&header.block_hash);
    buf[38..40].copy_from_slice(&header.chunk_id.to_be_bytes());
    buf[40..42].copy_from_slice(&header.total_chunks.to_be_bytes());
    buf[42..44].copy_from_slice(&header.payload_len.to_be_bytes());
}
