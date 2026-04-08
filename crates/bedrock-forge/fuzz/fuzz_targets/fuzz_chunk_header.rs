#![no_main]
use libfuzzer_sys::fuzz_target;
use bedrock_forge::ChunkHeader;

fuzz_target!(|data: &[u8]| {
    let _ = ChunkHeader::from_bytes(data);
});
