//! Downstream listener: serves declared jobs to local mining hardware.
//!
//! The JDC declares miner-built templates to the pool, then SERVES those exact
//! jobs to mining hardware through this listener (the only downstream client is
//! the SV1→V2 translator proxy in `sovright-v1-stratum-proxy`). The proxy
//! adopts `channel_id` / `nonce_1` / `nonce_2_len` / `target` from the first
//! `NewEquihashJob`, then submits `SubmitEquihashShare`s which we validate
//! locally against the pool-granted share target before telling the proxy
//! Accepted and relaying the share to the pool for authoritative credit.
//!
//! Wire protocol is `zcash-mining-protocol` (6-byte frame header, no
//! handshake — channels are implicit). Per session we mint a local
//! `channel_id` from an [`AtomicU32`] (downstream channel ids are local only
//! and unrelated to the JD channel id used in `SubmitSharesJd`).

use crate::block_submitter::BlockSubmitter;
use crate::declared_job::{CurrentDeclaredJob, DeclaredJobState};
use crate::share_path::{self, NONCE_2_LEN, ShareOutcome, share_dedup_key};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zcash_jd_server::messages::JdShare;
use zcash_mining_protocol::codec::{
    MessageFrame, decode_submit_share, encode_new_equihash_job, encode_submit_shares_response,
};
use zcash_mining_protocol::messages::{
    NewEquihashJob, RejectReason, ShareResult, SubmitEquihashShare, SubmitSharesResponse,
    message_types,
};

/// Maximum number of distinct share keys remembered per downstream session
/// before further distinct shares are treated as duplicates (bounds memory).
/// Mirrors the pool-side per-job cap.
const MAX_SEEN_SHARES: usize = 10_000;

/// Maximum read-buffer size for a single downstream connection (64 KB).
///
/// This cap assumes a single well-behaved proxy downstream (the SV1->V2
/// translator). A `SubmitEquihashShare` frame is ~1.4 KB, so 64 KB comfortably
/// holds several pipelined submissions; it is a backstop against a misbehaving
/// peer streaming bytes without a frame boundary, not a multi-tenant fairness
/// mechanism.
const MAX_BUFFER_SIZE: usize = 65_536;

/// A locally-validated share to relay to the pool, plus the side effects the
/// listener already performed downstream (telling the proxy Accepted).
///
/// `version` is the declared job's version (NOT miner-controlled) so the pool
/// re-derives the same header. `nonce` is the full reassembled 32-byte nonce.
#[derive(Debug, Clone)]
pub struct RelayShare {
    /// Job ID the share was mined against.
    pub job_id: u32,
    /// The share payload (version/time/nonce/solution) for `SubmitSharesJd`.
    pub share: JdShare,
}

/// Shared block-submission dependencies handed to each session.
#[derive(Clone)]
struct BlockSink {
    submitter: Arc<BlockSubmitter>,
    /// Sends a found block (the declared job + winning share) to the JD session
    /// loop, which forwards a `PushSolution` to the pool.
    push_tx: mpsc::Sender<RelayShare>,
}

/// Run the downstream listener until the process exits or the bind fails.
///
/// `relay_tx` carries every locally-accepted share to the JD session loop for
/// batched relay to the pool. `push_tx` carries block-meeting shares so the JD
/// loop can also send a `PushSolution`. Block submission to Zebra happens
/// in-session via `submitter`.
///
/// HEAD-OF-LINE / BACKPRESSURE: every session funnels its accepted shares
/// through the single bounded `relay_tx`, and the JD session loop relays them
/// over one serialized JD transport (one `SubmitSharesJd` in flight at a time,
/// awaiting the pool's response). A slow pool response therefore backpressures
/// `relay_tx.send` and, once the channel fills, the submitting session's
/// `handle_share` await — this is the intended degradation mode (the design
/// assumes a single trusted proxy downstream, so cross-session fairness is a
/// non-goal; correctness of credit, owned by the pool, takes precedence over
/// relay throughput).
pub async fn run_listener(
    listen_addr: SocketAddr,
    state: Arc<DeclaredJobState>,
    relay_tx: mpsc::Sender<RelayShare>,
    push_tx: mpsc::Sender<RelayShare>,
    submitter: Arc<BlockSubmitter>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "JDC downstream listener bound");

    let next_channel_id = Arc::new(AtomicU32::new(1));
    let block_sink = BlockSink { submitter, push_tx };

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "downstream accept failed");
                continue;
            }
        };
        let channel_id = next_channel_id.fetch_add(1, Ordering::Relaxed);
        let session = DownstreamSession::new(
            channel_id,
            state.clone(),
            relay_tx.clone(),
            block_sink.clone(),
            peer,
        );
        tokio::spawn(async move {
            if let Err(e) = session.run(stream).await {
                warn!(peer = %peer, error = %e, "downstream session ended with error");
            }
        });
    }
}

/// A single downstream proxy connection.
struct DownstreamSession {
    channel_id: u32,
    /// `nonce_1` served to the proxy = channel_id little-endian (4 bytes).
    nonce_1: [u8; 4],
    state: Arc<DeclaredJobState>,
    relay_tx: mpsc::Sender<RelayShare>,
    block_sink: BlockSink,
    peer: SocketAddr,
    /// Per-session dedup of seen share keys (register-before-verify).
    ///
    /// Dedup scope is per-job (matching the pool side): the set is cleared
    /// whenever the session's current job_id changes, so the [`MAX_SEEN_SHARES`]
    /// cap bounds a single job's distinct shares rather than the connection's
    /// lifetime. See `last_job_id`.
    seen_shares: HashSet<[u8; 32]>,
    /// The job_id the `seen_shares` set is currently scoped to, if any. When a
    /// share arrives for a different job, the dedup set is reset.
    last_job_id: Option<u32>,
}

impl DownstreamSession {
    fn new(
        channel_id: u32,
        state: Arc<DeclaredJobState>,
        relay_tx: mpsc::Sender<RelayShare>,
        block_sink: BlockSink,
        peer: SocketAddr,
    ) -> Self {
        Self {
            channel_id,
            nonce_1: channel_id.to_le_bytes(),
            state,
            relay_tx,
            block_sink,
            peer,
            seen_shares: HashSet::new(),
            last_job_id: None,
        }
    }

    async fn run(mut self, stream: TcpStream) -> std::io::Result<()> {
        info!(peer = %self.peer, channel_id = self.channel_id, "downstream session started");
        let (reader, mut writer) = stream.into_split();
        let mut reader = reader;
        let mut read_buf: Vec<u8> = Vec::with_capacity(4096);
        let mut updates = self.state.subscribe();

        // On connect: serve the current job immediately if one exists.
        if let Some(job) = self.state.current().await {
            self.send_job(&mut writer, &job).await?;
        }

        loop {
            tokio::select! {
                // Job updates from the JD session loop. The watch channel
                // coalesces intentionally: if several declarations land between
                // wakeups we only ever read the newest via `current()`, which is
                // exactly what we want — stale intermediate jobs must not be
                // served to the proxy.
                changed = updates.changed() => {
                    if changed.is_err() {
                        // State dropped; nothing more to serve.
                        break;
                    }
                    if let Some(job) = self.state.current().await {
                        self.send_job(&mut writer, &job).await?;
                    }
                    // If the job was cleared we simply stop sending; the proxy
                    // waits. (We do not tear down the session on clear.)
                }
                // Frames from the proxy.
                msg = read_next_frame(&mut reader, &mut read_buf) => {
                    match msg? {
                        Some(frame) => {
                            self.handle_frame(&mut writer, &frame).await?;
                        }
                        None => {
                            info!(peer = %self.peer, channel_id = self.channel_id, "proxy disconnected");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Send a `NewEquihashJob` built from the current declared job.
    async fn send_job(
        &self,
        writer: &mut OwnedWriteHalf,
        job: &CurrentDeclaredJob,
    ) -> std::io::Result<()> {
        let new_job = NewEquihashJob {
            channel_id: self.channel_id,
            job_id: job.job_id,
            future_job: false,
            version: job.version,
            prev_hash: job.prev_hash,
            merkle_root: job.merkle_root,
            block_commitments: job.block_commitments,
            nonce_1: self.nonce_1.to_vec(),
            nonce_2_len: NONCE_2_LEN as u8,
            time: job.time,
            bits: job.bits,
            target: job.share_target,
            clean_jobs: true,
        };
        let encoded =
            encode_new_equihash_job(&new_job).map_err(|e| std::io::Error::other(e.to_string()))?;
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        debug!(
            peer = %self.peer,
            channel_id = self.channel_id,
            job_id = job.job_id,
            "served NewEquihashJob to proxy"
        );
        Ok(())
    }

    /// Dispatch one decoded frame from the proxy.
    async fn handle_frame(
        &mut self,
        writer: &mut OwnedWriteHalf,
        frame: &[u8],
    ) -> std::io::Result<()> {
        let header = match MessageFrame::decode(frame) {
            Ok(h) => h,
            Err(e) => {
                warn!(peer = %self.peer, error = %e, "undecodable frame header from proxy");
                return Ok(());
            }
        };

        match header.msg_type {
            message_types::SUBMIT_EQUIHASH_SHARE => match decode_submit_share(frame) {
                Ok(share) => self.handle_share(writer, share).await,
                Err(e) => {
                    warn!(peer = %self.peer, error = %e, "failed to decode SubmitEquihashShare");
                    Ok(())
                }
            },
            other => {
                debug!(
                    peer = %self.peer,
                    msg_type = format!("0x{:02x}", other),
                    "ignoring unexpected downstream message type"
                );
                Ok(())
            }
        }
    }

    /// Validate one submitted share, respond downstream, and relay if accepted.
    async fn handle_share(
        &mut self,
        writer: &mut OwnedWriteHalf,
        share: SubmitEquihashShare,
    ) -> std::io::Result<()> {
        let seq = share.sequence_number;

        // Resolve the current declared job.
        let Some(job) = self.state.current().await else {
            return self
                .respond(writer, seq, ShareResult::Rejected(RejectReason::StaleJob))
                .await;
        };

        // 1. Job must match the current declared job.
        if share.job_id != job.job_id {
            return self
                .respond(writer, seq, ShareResult::Rejected(RejectReason::StaleJob))
                .await;
        }

        // Dedup is per-job: when the current job_id changes, the previous job's
        // seen-share keys are irrelevant (and could falsely reject distinct
        // shares of the new job once the cap is hit). Reset the set on every
        // job transition so MAX_SEEN_SHARES bounds a single job, not the whole
        // connection. (The job-update select arm is where a new job is served;
        // resetting here also covers the share path directly.)
        if self.last_job_id != Some(job.job_id) {
            self.seen_shares.clear();
            self.last_job_id = Some(job.job_id);
        }

        // 2. Reassemble the full nonce (validates nonce_2 length == 28).
        let Some(nonce) = share_path::reassemble_nonce(&self.nonce_1, &share.nonce_2) else {
            return self
                .respond(
                    writer,
                    seq,
                    ShareResult::Rejected(RejectReason::Other("bad nonce_2 length".to_string())),
                )
                .await;
        };

        // 3 & 4. Dedup: register the key BEFORE the expensive Equihash check so
        // byte-identical replays are caught regardless of validity. Remembering
        // an invalid share is harmless and rate-limits resubmission of garbage.
        let key = share_dedup_key(&nonce, share.time, &share.solution);
        if self.seen_shares.contains(&key) {
            return self
                .respond(writer, seq, ShareResult::Rejected(RejectReason::Duplicate))
                .await;
        }
        if self.seen_shares.len() >= MAX_SEEN_SHARES {
            warn!(
                peer = %self.peer,
                cap = MAX_SEEN_SHARES,
                "downstream dedup set full; rejecting share as duplicate"
            );
            return self
                .respond(writer, seq, ShareResult::Rejected(RejectReason::Duplicate))
                .await;
        }
        self.seen_shares.insert(key);

        // 5. Verify the Equihash solution against the share target.
        let outcome = share_path::verify_share(&job, share.time, &nonce, &share.solution);

        // Respond downstream via the outcome's wire mapping (single source of
        // truth for outcome -> ShareResult), then handle relay/block side
        // effects only on acceptance.
        self.respond(writer, seq, outcome.to_share_result()).await?;

        match outcome {
            ShareOutcome::Rejected(_) => Ok(()),
            ShareOutcome::Accepted {
                nonce,
                meets_block_target,
            } => {
                // 6. Share accepted: queue for relay to the pool.
                let relay = RelayShare {
                    job_id: job.job_id,
                    share: JdShare {
                        version: job.version,
                        time: share.time,
                        nonce,
                        solution: share.solution,
                    },
                };

                if self.relay_tx.send(relay.clone()).await.is_err() {
                    warn!(peer = %self.peer, "relay channel closed; share not relayed to pool");
                }

                // 7. Block check: solution also meets the BLOCK target.
                if meets_block_target {
                    self.on_block_found(&job, relay).await;
                }

                Ok(())
            }
        }
    }

    /// Handle a share whose solution also meets the block target: assemble the
    /// block and submit to Zebra, and signal the JD loop to PushSolution. Any
    /// failure here is logged only — the share was already accepted.
    async fn on_block_found(&self, job: &CurrentDeclaredJob, relay: RelayShare) {
        info!(
            peer = %self.peer,
            job_id = job.job_id,
            "downstream share meets BLOCK target — assembling block"
        );

        let header = share_path::build_header(job, relay.share.time, &relay.share.nonce);
        let block_hex = BlockSubmitter::build_block_hex(
            &header,
            &relay.share.solution,
            &job.coinbase_tx,
            &job.transactions,
        );
        if let Err(e) = self.block_sink.submitter.submit_block(&block_hex).await {
            error!(job_id = job.job_id, error = %e, "block submission to Zebra failed");
        }

        // Signal the JD session loop to send PushSolution to the pool.
        if self.block_sink.push_tx.send(relay).await.is_err() {
            warn!("push channel closed; PushSolution not sent to pool");
        }
    }

    async fn respond(
        &self,
        writer: &mut OwnedWriteHalf,
        sequence_number: u32,
        result: ShareResult,
    ) -> std::io::Result<()> {
        let resp = SubmitSharesResponse {
            channel_id: self.channel_id,
            sequence_number,
            result,
        };
        let encoded = encode_submit_shares_response(&resp)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Read one complete `MessageFrame`-delimited message from `reader`, buffering
/// partial reads in `read_buf`. Returns `Ok(None)` on clean EOF. Cribbed from
/// the pool server's plain-TCP frame loop.
async fn read_next_frame(
    reader: &mut OwnedReadHalf,
    read_buf: &mut Vec<u8>,
) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(msg) = try_parse_frame(read_buf)? {
            return Ok(Some(msg));
        }
        let mut temp = [0u8; 1024];
        let n = reader.read(&mut temp).await?;
        if n == 0 {
            return Ok(None);
        }
        read_buf.extend_from_slice(&temp[..n]);
    }
}

/// Try to drain one complete frame from `read_buf`.
fn try_parse_frame(read_buf: &mut Vec<u8>) -> std::io::Result<Option<Vec<u8>>> {
    if read_buf.len() > MAX_BUFFER_SIZE {
        return Err(std::io::Error::other(
            "downstream read buffer exceeded 64KB",
        ));
    }
    if read_buf.len() < MessageFrame::HEADER_SIZE {
        return Ok(None);
    }
    let frame = MessageFrame::decode(read_buf).map_err(|e| std::io::Error::other(e.to_string()))?;
    let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
    if read_buf.len() < total_len {
        return Ok(None);
    }
    let msg: Vec<u8> = read_buf.drain(..total_len).collect();
    Ok(Some(msg))
}
