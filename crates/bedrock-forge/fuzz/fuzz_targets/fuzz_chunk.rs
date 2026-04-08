#![no_main]
use libfuzzer_sys::fuzz_target;
use bedrock_forge::Chunk;

fuzz_target!(|data: &[u8]| {
    let _ = Chunk::from_bytes(data);
});
