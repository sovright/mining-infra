#![no_main]
use libfuzzer_sys::fuzz_target;
use snow::Builder;

/// Noise NK pattern used by bedrock-noise
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

fuzz_target!(|data: &[u8]| {
    // Set up a responder state and feed it arbitrary bytes as if they were
    // the initiator's first handshake message. This exercises snow's message
    // parsing and the Noise protocol's ability to reject malformed input
    // without panicking.

    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let keypair = builder.generate_keypair().unwrap();

    let builder2 = Builder::new(NOISE_PATTERN.parse().unwrap());
    let mut responder = builder2
        .local_private_key(&keypair.private)
        .build_responder()
        .unwrap();

    // Feed fuzzed data as the first handshake message
    let mut payload = vec![0u8; 65535];
    let _ = responder.read_message(data, &mut payload);

    // If read_message succeeded (unlikely with random data), try to continue
    // the handshake by writing a response - must not panic either way
    let mut response = vec![0u8; 65535];
    let _ = responder.write_message(&[], &mut response);

    // Also test the initiator side: feed fuzzed data as the server's response
    let builder3 = Builder::new(NOISE_PATTERN.parse().unwrap());
    let mut initiator = builder3
        .remote_public_key(&keypair.public)
        .build_initiator()
        .unwrap();

    // First the initiator writes its message (valid)
    let mut msg = vec![0u8; 65535];
    let _ = initiator.write_message(&[], &mut msg);

    // Then feed fuzzed data as the server's response
    let mut payload2 = vec![0u8; 65535];
    let _ = initiator.read_message(data, &mut payload2);
});
