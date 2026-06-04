#![no_main]
use libfuzzer_sys::fuzz_target;
use sovright_relay::ChunkHeader;

fuzz_target!(|data: &[u8]| {
    let _ = ChunkHeader::from_bytes(data);
});
