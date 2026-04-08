//! Noise NK handshake implementation
//!
//! NK pattern: Client knows server's static public key.
//! - Client (initiator): ephemeral key only
//! - Server (responder): static keypair

use crate::keys::{Keypair, PublicKey};
use crate::transport::NoiseStream;
use snow::Builder;
use std::io;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// Maximum handshake message size
const MAX_HANDSHAKE_MSG: usize = 65535;

/// Noise handshake initiator (client side)
pub struct NoiseInitiator {
    server_public_key: PublicKey,
}

impl NoiseInitiator {
    /// Create initiator with known server public key
    pub fn new(server_public_key: PublicKey) -> Self {
        Self { server_public_key }
    }

    /// Perform handshake and return encrypted stream
    pub async fn connect(self, mut stream: TcpStream) -> Result<NoiseStream<TcpStream>, HandshakeError> {
        debug!("Starting Noise NK handshake as initiator");

        let builder: Builder<'_> = Builder::new(crate::NOISE_PATTERN.parse().unwrap());
        let mut handshake = builder
            .remote_public_key(self.server_public_key.as_bytes())
            .build_initiator()
            .map_err(HandshakeError::Snow)?;

        // -> e, es (client sends ephemeral, establishes shared secret)
        let mut msg = vec![0u8; MAX_HANDSHAKE_MSG];
        let len = handshake.write_message(&[], &mut msg).map_err(HandshakeError::Snow)?;
        trace!("Sending handshake message: {} bytes", len);

        stream.write_u16(len as u16).await?;
        stream.write_all(&msg[..len]).await?;

        // <- e, ee (server responds)
        let len = stream.read_u16().await? as usize;
        if len > MAX_HANDSHAKE_MSG {
            return Err(HandshakeError::MessageTooLarge(len));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;
        trace!("Received handshake response: {} bytes", len);

        let mut payload = vec![0u8; MAX_HANDSHAKE_MSG];
        let _payload_len = handshake.read_message(&msg, &mut payload).map_err(HandshakeError::Snow)?;

        // Transition to transport mode
        let transport = handshake.into_transport_mode().map_err(HandshakeError::Snow)?;
        debug!("Noise handshake complete (initiator)");

        Ok(NoiseStream::new(stream, transport))
    }
}

/// Noise handshake responder (server side)
pub struct NoiseResponder {
    keypair: Keypair,
}

impl NoiseResponder {
    /// Create responder with server's static keypair
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Get the public key clients need to connect
    pub fn public_key(&self) -> &PublicKey {
        &self.keypair.public
    }

    /// Accept a connection and perform handshake
    pub async fn accept(&self, mut stream: TcpStream) -> Result<NoiseStream<TcpStream>, HandshakeError> {
        debug!("Starting Noise NK handshake as responder");

        let builder: Builder<'_> = Builder::new(crate::NOISE_PATTERN.parse().unwrap());
        let mut handshake = builder
            .local_private_key(self.keypair.private_bytes())
            .build_responder()
            .map_err(HandshakeError::Snow)?;

        // <- e, es (receive client's ephemeral)
        let len = stream.read_u16().await? as usize;
        if len > MAX_HANDSHAKE_MSG {
            return Err(HandshakeError::MessageTooLarge(len));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;
        trace!("Received handshake message: {} bytes", len);

        let mut payload = vec![0u8; MAX_HANDSHAKE_MSG];
        let _payload_len = handshake.read_message(&msg, &mut payload).map_err(HandshakeError::Snow)?;

        // -> e, ee (send server's ephemeral)
        let mut response = vec![0u8; MAX_HANDSHAKE_MSG];
        let len = handshake.write_message(&[], &mut response).map_err(HandshakeError::Snow)?;
        trace!("Sending handshake response: {} bytes", len);

        stream.write_u16(len as u16).await?;
        stream.write_all(&response[..len]).await?;

        // Transition to transport mode
        let transport = handshake.into_transport_mode().map_err(HandshakeError::Snow)?;
        debug!("Noise handshake complete (responder)");

        Ok(NoiseStream::new(stream, transport))
    }
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Noise protocol error: {0}")]
    Snow(snow::Error),

    #[error("Handshake message too large: {0} bytes")]
    MessageTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_handshake_roundtrip() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        // Start server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            responder.accept(stream).await.unwrap()
        });

        // Connect client
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let _client_noise = initiator.connect(client_stream).await.unwrap();

        // Server should complete too
        let _server_noise = server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_wrong_server_public_key() {
        use std::time::Duration;

        let server_keypair = Keypair::generate();
        let wrong_keypair = Keypair::generate(); // Different keypair

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            responder.accept(stream).await
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        // Client uses the WRONG public key
        let initiator = NoiseInitiator::new(wrong_keypair.public.clone());

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            initiator.connect(client_stream),
        )
        .await;

        // Should complete within timeout (not hang)
        let handshake_result = result.expect("handshake should not hang");

        let server_result = tokio::time::timeout(
            Duration::from_secs(5),
            server_handle,
        )
        .await
        .expect("server should not hang");

        // At least one side must fail
        let client_failed = handshake_result.is_err();
        let server_failed = server_result.is_err() || server_result.unwrap().is_err();
        assert!(
            client_failed || server_failed,
            "Handshake with wrong key should fail on at least one side"
        );
    }

    #[tokio::test]
    async fn test_server_drops_mid_handshake() {
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server accepts then immediately drops the stream
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let server_keypair = Keypair::generate();
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_keypair.public.clone());

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            initiator.connect(client_stream),
        )
        .await;

        // Should complete within timeout
        let handshake_result = result.expect("handshake should not hang");
        // Client should get an IO error since server dropped the connection
        assert!(
            handshake_result.is_err(),
            "Client should fail when server drops connection"
        );

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_garbage_data_instead_of_handshake() {
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;

        let server_keypair = Keypair::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            responder.accept(stream).await
        });

        // Client sends garbage instead of a proper handshake
        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        // Write a length prefix followed by random garbage
        let garbage = vec![0xDE; 128];
        client_stream.write_u16(garbage.len() as u16).await.unwrap();
        client_stream.write_all(&garbage).await.unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            server_handle,
        )
        .await;

        let server_result = result
            .expect("server should not hang")
            .expect("server task should not panic");

        assert!(
            server_result.is_err(),
            "Server should fail when receiving garbage data"
        );
    }
}
