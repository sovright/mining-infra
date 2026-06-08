//! Session handler for miner connections
//!
//! Each miner connection is handled by a Session that:
//! - Reads shares from the miner over TCP
//! - Forwards shares to the server for validation
//! - Sends jobs and difficulty updates to the miner
//! - Handles vardiff adjustments

use crate::error::{PoolError, Result};
use sovright_noise::NoiseStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use zcash_mining_protocol::codec::{
    MessageFrame, decode_set_worker_identity, encode_new_equihash_job,
    encode_set_target as codec_encode_set_target,
    encode_submit_shares_response as codec_encode_submit_shares_response,
};
use zcash_mining_protocol::messages::{
    NewEquihashJob, SetTarget, SetWorkerIdentity, ShareResult, SubmitEquihashShare,
    SubmitSharesResponse, message_types,
};

/// A decoded inbound client message.
pub enum InboundMessage {
    Share(Box<SubmitEquihashShare>),
    Identity(SetWorkerIdentity),
    /// A SET_WORKER_IDENTITY frame that failed decode/validation. The session
    /// warns and continues (spec: invalid identity never disconnects).
    InvalidIdentity(String),
}

/// Decode an inbound frame by type. Unknown types are an error; the session
/// disconnects on them, same as before SetWorkerIdentity existed.
pub fn classify_message(msg_data: &[u8]) -> Result<InboundMessage> {
    let frame = MessageFrame::decode(msg_data).map_err(PoolError::Protocol)?;
    match frame.msg_type {
        message_types::SUBMIT_EQUIHASH_SHARE => {
            Ok(InboundMessage::Share(Box::new(decode_submit_share(msg_data)?)))
        }
        message_types::SET_WORKER_IDENTITY => {
            match decode_set_worker_identity(msg_data) {
                Ok(ident) => Ok(InboundMessage::Identity(ident)),
                Err(e) => Ok(InboundMessage::InvalidIdentity(e.to_string())),
            }
        }
        other => Err(PoolError::InvalidMessage(format!(
            "Unknown message type: 0x{other:02x}"
        ))),
    }
}

/// Messages sent from session to server
#[derive(Debug)]
pub enum SessionMessage {
    /// Miner submitted a share
    ShareSubmitted {
        channel_id: u32,
        share: Box<SubmitEquihashShare>,
        response_tx: oneshot::Sender<ShareResult>,
    },
    /// Session disconnected
    Disconnected { channel_id: u32 },
    /// Miner declared its worker identity (validated at decode; policy is
    /// enforced by the server, which owns channel state).
    IdentityDeclared { channel_id: u32, worker_name: String },
}

/// Messages sent from server to session
#[derive(Debug)]
pub enum ServerMessage {
    /// New job to send to miner
    NewJob(NewEquihashJob),
    /// Update share target (vardiff)
    SetTarget { target: [u8; 32] },
    /// Shutdown the session
    Shutdown,
}

/// Transport for miner connections (plain or Noise-encrypted)
pub enum Transport {
    Plain(TcpStream),
    Noise(NoiseStream<TcpStream>),
}

/// Session state for a single miner connection
pub struct Session {
    /// Transport for this connection
    transport: Transport,
    /// Channel ID for this miner
    channel_id: u32,
    /// Sender to forward messages to server
    server_tx: mpsc::Sender<SessionMessage>,
    /// Receiver for messages from server
    server_rx: mpsc::Receiver<ServerMessage>,
    /// Read buffer for incoming messages (plain transport only)
    read_buf: Vec<u8>,
}

impl Session {
    /// Create a new session
    pub fn new(
        transport: Transport,
        channel_id: u32,
        server_tx: mpsc::Sender<SessionMessage>,
        server_rx: mpsc::Receiver<ServerMessage>,
    ) -> Self {
        Self {
            transport,
            channel_id,
            server_tx,
            server_rx,
            read_buf: Vec::with_capacity(4096),
        }
    }

    /// Main session loop
    pub async fn run(mut self) -> Result<()> {
        info!("Session started for channel {}", self.channel_id);
        let channel_id = self.channel_id;

        loop {
            let read_future = Self::read_next_message(&mut self.transport, &mut self.read_buf);
            let server_future = self.server_rx.recv();
            tokio::select! {
                // Read from miner
                read_result = read_future => {
                    match read_result {
                        Ok(Some(msg)) => {
                            match classify_message(&msg) {
                                Ok(InboundMessage::Share(share)) => {
                                    if share.channel_id != self.channel_id {
                                        error!(
                                            "Share channel_id {} does not match session {} - disconnecting",
                                            share.channel_id, channel_id
                                        );
                                        break;
                                    }
                                    debug!(
                                        "Received share: channel={}, job={}, seq={}",
                                        share.channel_id, share.job_id, share.sequence_number
                                    );
                                    if let Err(e) = self.handle_share(*share).await {
                                        match &e {
                                            PoolError::Timeout | PoolError::ChannelSend => {
                                                error!(
                                                    "Fatal share handling error for channel {}: {} - disconnecting",
                                                    channel_id, e
                                                );
                                                break;
                                            }
                                            _ => {
                                                warn!("Error handling share: {}", e);
                                            }
                                        }
                                    }
                                }
                                Ok(InboundMessage::Identity(ident)) => {
                                    if let Err(e) = self
                                        .server_tx
                                        .send(SessionMessage::IdentityDeclared {
                                            channel_id,
                                            worker_name: ident.worker_name,
                                        })
                                        .await
                                    {
                                        error!(
                                            "Failed to forward identity for channel {}: {}",
                                            channel_id, e
                                        );
                                        break;
                                    }
                                }
                                Ok(InboundMessage::InvalidIdentity(reason)) => {
                                    warn!(
                                        "Ignoring invalid worker identity on channel {}: {}",
                                        channel_id, reason
                                    );
                                }
                                Err(e) => {
                                    error!("Parse error for channel {}: {}", channel_id, e);
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            // Connection closed
                            info!("Connection closed for channel {}", channel_id);
                            break;
                        }
                        Err(e) => {
                            error!("Read error for channel {}: {}", channel_id, e);
                            break;
                        }
                    }
                }

                // Receive messages from server
                msg = server_future => {
                    match msg {
                        Some(ServerMessage::NewJob(job)) => {
                            if let Err(e) = self.send_job(job).await {
                                error!("Error sending job: {}", e);
                                break;
                            }
                        }
                        Some(ServerMessage::SetTarget { target }) => {
                            if let Err(e) = self.send_set_target(target).await {
                                error!("Error sending target: {}", e);
                                break;
                            }
                        }
                        Some(ServerMessage::Shutdown) => {
                            info!("Shutdown requested for channel {}", channel_id);
                            break;
                        }
                        None => {
                            // Server channel closed
                            info!("Server channel closed for channel {}", channel_id);
                            break;
                        }
                    }
                }
            }
        }

        // Notify server of disconnection
        let _ = self
            .server_tx
            .send(SessionMessage::Disconnected { channel_id })
            .await;

        Ok(())
    }

    /// Read the next complete message from the transport
    async fn read_next_message(
        transport: &mut Transport,
        read_buf: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        match transport {
            Transport::Noise(noise) => {
                let msg = noise.read_message().await?;
                if msg.is_empty() {
                    return Ok(None);
                }
                Ok(Some(msg))
            }
            Transport::Plain(stream) => loop {
                if let Some(msg) = Self::try_parse_message(read_buf)? {
                    return Ok(Some(msg));
                }

                let mut temp_buf = [0u8; 1024];
                let n = stream.read(&mut temp_buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                read_buf.extend_from_slice(&temp_buf[..n]);
            },
        }
    }

    /// Try to parse a complete message from the read buffer
    fn try_parse_message(read_buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        // Prevent unbounded buffer growth (64KB max)
        const MAX_BUFFER_SIZE: usize = 65536;
        if read_buf.len() > MAX_BUFFER_SIZE {
            return Err(PoolError::InvalidMessage(
                "Read buffer exceeded maximum size of 64KB".to_string(),
            ));
        }

        // Check if we have enough data for the header
        if read_buf.len() < MessageFrame::HEADER_SIZE {
            return Ok(None);
        }

        // Parse frame header
        let frame = MessageFrame::decode(read_buf).map_err(PoolError::Protocol)?;

        // Validate frame size limit (1MB max per message)
        const MAX_FRAME_SIZE: u32 = 1_048_576;
        if frame.length > MAX_FRAME_SIZE {
            return Err(PoolError::InvalidMessage(format!(
                "Frame size {} exceeds maximum of 1MB",
                frame.length
            )));
        }

        let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;

        // Check if we have the complete message
        if read_buf.len() < total_len {
            return Ok(None);
        }

        // Extract message bytes
        let msg_data: Vec<u8> = read_buf.drain(..total_len).collect();
        Ok(Some(msg_data))
    }

    /// Write a message to the transport
    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.transport {
            Transport::Noise(noise) => {
                noise.write_message(data).await?;
                noise.flush().await?;
            }
            Transport::Plain(stream) => {
                stream.write_all(data).await?;
                stream.flush().await?;
            }
        }
        Ok(())
    }

    /// Timeout for share validation response (30 seconds)
    const SHARE_VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);

    /// Handle a share submission
    async fn handle_share(&mut self, share: SubmitEquihashShare) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        let sequence_number = share.sequence_number;

        // Send share to server for validation
        self.server_tx
            .send(SessionMessage::ShareSubmitted {
                channel_id: self.channel_id,
                share: Box::new(share),
                response_tx,
            })
            .await
            .map_err(|_| PoolError::ChannelSend)?;

        // Wait for validation result with timeout
        let result = match tokio::time::timeout(Self::SHARE_VALIDATION_TIMEOUT, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                // Channel was dropped - validation failed
                warn!(
                    "Share validation channel dropped for seq {}",
                    sequence_number
                );
                return Err(PoolError::ChannelSend);
            }
            Err(_) => {
                // Timeout - validation took too long
                warn!("Share validation timeout for seq {}", sequence_number);
                return Err(PoolError::Timeout);
            }
        };

        // Send response to miner
        self.send_response(sequence_number, result).await
    }

    /// Send a job to the miner
    async fn send_job(&mut self, mut job: NewEquihashJob) -> Result<()> {
        // Update job with channel-specific info
        job.channel_id = self.channel_id;

        // Encode and send
        let encoded = encode_new_equihash_job(&job).map_err(PoolError::Protocol)?;

        self.write_message(&encoded).await?;

        debug!(
            "Sent job {} to channel {} (clean={})",
            job.job_id, self.channel_id, job.clean_jobs
        );

        Ok(())
    }

    /// Send a target update (vardiff) to the miner
    async fn send_set_target(&mut self, target: [u8; 32]) -> Result<()> {
        // Encode SetTarget message
        let set_target = SetTarget {
            channel_id: self.channel_id,
            target,
        };

        let encoded = encode_set_target(&set_target)?;
        self.write_message(&encoded).await?;

        debug!("Sent SetTarget to channel {}", self.channel_id);

        Ok(())
    }

    /// Send a share response to the miner
    async fn send_response(&mut self, sequence_number: u32, result: ShareResult) -> Result<()> {
        let response = SubmitSharesResponse {
            channel_id: self.channel_id,
            sequence_number,
            result,
        };

        let encoded = encode_submit_shares_response(&response)?;
        self.write_message(&encoded).await?;

        debug!(
            "Sent response for seq {} to channel {}",
            sequence_number, self.channel_id
        );

        Ok(())
    }
}

// ============================================================================
// Codec functions (stubs for messages not yet implemented in Phase 2)
// ============================================================================

/// Decode a SubmitEquihashShare message
/// Uses the codec from zcash-mining-protocol
fn decode_submit_share(data: &[u8]) -> Result<SubmitEquihashShare> {
    zcash_mining_protocol::codec::decode_submit_share(data).map_err(PoolError::Protocol)
}

/// Encode a SetTarget message using the canonical codec
fn encode_set_target(msg: &SetTarget) -> Result<Vec<u8>> {
    codec_encode_set_target(msg).map_err(PoolError::Protocol)
}

/// Encode a SubmitSharesResponse using the canonical codec.
///
/// Previously this function had an incompatible wire format: it encoded
/// rejection as a single byte (1=StaleJob, 2=Duplicate, etc.) instead of
/// the canonical two-byte format (0x01=Rejected + reason_code). This caused
/// clients using the canonical decoder to fail parsing server responses.
fn encode_submit_shares_response(msg: &SubmitSharesResponse) -> Result<Vec<u8>> {
    codec_encode_submit_shares_response(msg).map_err(PoolError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_mining_protocol::messages::RejectReason;

    #[test]
    fn classify_inbound_frames() {
        use zcash_mining_protocol::codec::{encode_set_worker_identity, encode_submit_share};
        use zcash_mining_protocol::messages::{SetWorkerIdentity, SubmitEquihashShare};

        let ident =
            encode_set_worker_identity(&SetWorkerIdentity { worker_name: "rig-1".into() })
                .unwrap();
        assert!(
            matches!(classify_message(&ident), Ok(InboundMessage::Identity(m)) if m.worker_name == "rig-1")
        );

        let share = SubmitEquihashShare {
            channel_id: 7,
            sequence_number: 0,
            job_id: 1,
            nonce_2: vec![0; 28],
            time: 0,
            solution: [0u8; 1344],
        };
        let share_bytes = encode_submit_share(&share).unwrap();
        assert!(matches!(classify_message(&share_bytes), Ok(InboundMessage::Share(_)))); // Box<_> matches _

        // Unknown type still errors (caller disconnects on it).
        let mut unknown = ident.clone();
        unknown[2] = 0x7f;
        assert!(classify_message(&unknown).is_err());

        // Malformed 0x24 frame yields InvalidIdentity, not Err.
        let mut malformed = ident.clone();
        // Corrupt the payload: set name_len byte to 255, making it unreadable.
        // Header is 6 bytes; payload starts at byte 6.
        malformed[6] = 255;
        assert!(matches!(
            classify_message(&malformed),
            Ok(InboundMessage::InvalidIdentity(_))
        ));
    }

    #[test]
    fn test_encode_set_target() {
        let msg = SetTarget {
            channel_id: 42,
            target: [0xff; 32],
        };

        let encoded = encode_set_target(&msg).unwrap();

        // Frame header (6 bytes) + channel_id (4 bytes) + target (32 bytes)
        assert_eq!(encoded.len(), 6 + 4 + 32);

        // Check message type
        assert_eq!(encoded[2], message_types::SET_TARGET);
    }

    #[test]
    fn test_encode_submit_shares_response_accepted() {
        let msg = SubmitSharesResponse {
            channel_id: 1,
            sequence_number: 100,
            result: ShareResult::Accepted,
        };

        let encoded = encode_submit_shares_response(&msg).unwrap();

        // Frame header (6 bytes) + channel_id (4) + seq (4) + result (1)
        assert_eq!(encoded.len(), 6 + 4 + 4 + 1);

        // Check message type
        assert_eq!(encoded[2], message_types::SUBMIT_SHARES_RESPONSE);

        // Check result code: 0x00 = Accepted
        assert_eq!(encoded[encoded.len() - 1], 0);
    }

    #[test]
    fn test_encode_submit_shares_response_rejected() {
        let msg = SubmitSharesResponse {
            channel_id: 1,
            sequence_number: 101,
            result: ShareResult::Rejected(RejectReason::StaleJob),
        };

        let encoded = encode_submit_shares_response(&msg).unwrap();

        // Canonical format: header(6) + channel_id(4) + seq(4) + rejected(1) + reason(1) = 16
        assert_eq!(encoded.len(), 6 + 4 + 4 + 1 + 1);

        // Check result code: 0x01 = Rejected
        assert_eq!(encoded[6 + 4 + 4], 0x01);

        // Check reason code: 0x00 = StaleJob
        assert_eq!(encoded[6 + 4 + 4 + 1], 0x00);
    }

    #[test]
    fn test_encode_submit_shares_response_roundtrip() {
        // Verify encode/decode roundtrip works with the canonical codec
        let msg = SubmitSharesResponse {
            channel_id: 42,
            sequence_number: 999,
            result: ShareResult::Rejected(RejectReason::Duplicate),
        };

        let encoded = encode_submit_shares_response(&msg).unwrap();
        let decoded = zcash_mining_protocol::codec::decode_submit_shares_response(&encoded)
            .expect("canonical decode should succeed");

        assert_eq!(decoded.channel_id, 42);
        assert_eq!(decoded.sequence_number, 999);
        assert_eq!(
            decoded.result,
            ShareResult::Rejected(RejectReason::Duplicate)
        );
    }
}
