#![no_main]
use libfuzzer_sys::fuzz_target;
use sovright_relay::Chunk;

fuzz_target!(|data: &[u8]| {
    let _ = Chunk::from_bytes(data);
});
