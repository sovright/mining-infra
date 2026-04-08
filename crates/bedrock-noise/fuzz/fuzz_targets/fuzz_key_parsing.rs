#![no_main]
use libfuzzer_sys::fuzz_target;
use bedrock_noise::PublicKey;
use bedrock_noise::Keypair;

fuzz_target!(|data: &[u8]| {
    // Fuzz PublicKey::from_hex with arbitrary bytes interpreted as a string
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic, only return Ok or Err
        let _ = PublicKey::from_hex(s);
    }

    // Also fuzz Keypair::from_private_hex
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Keypair::from_private_hex(s);
    }

    // Fuzz PublicKey::from_bytes with exact 32 bytes
    if data.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[..32]);
        let pk = PublicKey::from_bytes(arr);
        // Roundtrip through hex must not panic
        let hex = pk.to_hex();
        let restored = PublicKey::from_hex(&hex).expect("roundtrip must succeed");
        assert_eq!(pk.as_bytes(), restored.as_bytes());
    }
});
