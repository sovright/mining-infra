//! Integration tests for Noise encryption

use sovright_noise::{Keypair, NoiseInitiator, NoiseResponder, PublicKey};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_multiple_concurrent_connections() {
    let server_keypair = Keypair::generate();
    let server_public = server_keypair.public.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server - we need to create a new responder for each connection
    // since NoiseResponder doesn't implement Clone
    let server_private_hex = server_keypair.private_hex();
    tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, _) = listener.accept().await.unwrap();
            let server_kp = Keypair::from_private_hex(&server_private_hex).unwrap();
            let responder = NoiseResponder::new(server_kp);
            tokio::spawn(async move {
                let mut noise = responder.accept(stream).await.unwrap();
                let msg = noise.read_message().await.unwrap();
                noise.write_message(&msg).await.unwrap(); // Echo
            });
        }
    });

    // Connect 3 clients concurrently
    let mut handles = vec![];
    for i in 0..3 {
        let pk = server_public.clone();
        let handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let initiator = NoiseInitiator::new(pk);
            let mut noise = initiator.connect(stream).await.unwrap();

            let msg = format!("Hello from client {}", i);
            noise.write_message(msg.as_bytes()).await.unwrap();
            let response = noise.read_message().await.unwrap();
            assert_eq!(response, msg.as_bytes());
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_key_persistence() {
    let keypair = Keypair::generate();
    let private_hex = keypair.private_hex();
    let public_hex = keypair.public.to_hex();

    // Restore from hex
    let restored = Keypair::from_private_hex(&private_hex).unwrap();
    assert_eq!(restored.public.to_hex(), public_hex);
}

#[tokio::test]
async fn test_public_key_from_hex() {
    let keypair = Keypair::generate();
    let public_hex = keypair.public.to_hex();

    let restored_public = PublicKey::from_hex(&public_hex).unwrap();
    assert_eq!(keypair.public.as_bytes(), restored_public.as_bytes());
}

#[tokio::test]
async fn test_bidirectional_communication() {
    let server_keypair = Keypair::generate();
    let server_public = server_keypair.public.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server task
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let responder = NoiseResponder::new(server_keypair);
        let mut noise = responder.accept(stream).await.unwrap();

        // Multiple message exchanges
        for i in 0..5 {
            let msg = noise.read_message().await.unwrap();
            assert_eq!(msg, format!("client-msg-{}", i).as_bytes());
            noise
                .write_message(format!("server-msg-{}", i).as_bytes())
                .await
                .unwrap();
        }
    });

    // Client
    let client_stream = TcpStream::connect(addr).await.unwrap();
    let initiator = NoiseInitiator::new(server_public);
    let mut client_noise = initiator.connect(client_stream).await.unwrap();

    for i in 0..5 {
        client_noise
            .write_message(format!("client-msg-{}", i).as_bytes())
            .await
            .unwrap();
        let response = client_noise.read_message().await.unwrap();
        assert_eq!(response, format!("server-msg-{}", i).as_bytes());
    }

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_empty_message() {
    let server_keypair = Keypair::generate();
    let server_public = server_keypair.public.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let responder = NoiseResponder::new(server_keypair);
        let mut noise = responder.accept(stream).await.unwrap();

        // Receive and echo an empty message
        let msg = noise.read_message().await.unwrap();
        assert!(msg.is_empty());
        noise.write_message(&msg).await.unwrap();
    });

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let initiator = NoiseInitiator::new(server_public);
    let mut client_noise = initiator.connect(client_stream).await.unwrap();

    // Send empty message
    client_noise.write_message(&[]).await.unwrap();
    let response = client_noise.read_message().await.unwrap();
    assert!(response.is_empty());

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_binary_data() {
    let server_keypair = Keypair::generate();
    let server_public = server_keypair.public.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Binary data with all byte values
    let binary_data: Vec<u8> = (0..=255).collect();

    let binary_clone = binary_data.clone();
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let responder = NoiseResponder::new(server_keypair);
        let mut noise = responder.accept(stream).await.unwrap();

        let msg = noise.read_message().await.unwrap();
        assert_eq!(msg, binary_clone);
        noise.write_message(&msg).await.unwrap();
    });

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let initiator = NoiseInitiator::new(server_public);
    let mut client_noise = initiator.connect(client_stream).await.unwrap();

    client_noise.write_message(&binary_data).await.unwrap();
    let response = client_noise.read_message().await.unwrap();
    assert_eq!(response, binary_data);

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_keypair_debug_does_not_leak_private_key() {
    let keypair = Keypair::generate();
    let debug_output = format!("{:?}", keypair);

    // Should contain "redacted" for private key
    assert!(debug_output.contains("redacted"));
    // Should not contain the actual private key hex
    assert!(!debug_output.contains(&keypair.private_hex()));
}

#[tokio::test]
async fn test_different_clients_different_sessions() {
    let server_keypair = Keypair::generate();
    let server_public = server_keypair.public.clone();
    let server_private_hex = server_keypair.private_hex();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server handles two sequential connections
    let server_handle = tokio::spawn(async move {
        for expected_id in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let server_kp = Keypair::from_private_hex(&server_private_hex).unwrap();
            let responder = NoiseResponder::new(server_kp);
            let mut noise = responder.accept(stream).await.unwrap();

            let msg = noise.read_message().await.unwrap();
            let msg_str = String::from_utf8_lossy(&msg);
            assert!(msg_str.contains(&expected_id.to_string()));
        }
    });

    // Two sequential clients
    for i in 0..2 {
        let pk = server_public.clone();
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(pk);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        let msg = format!("Message from client {}", i);
        client_noise.write_message(msg.as_bytes()).await.unwrap();
    }

    server_handle.await.unwrap();
}
