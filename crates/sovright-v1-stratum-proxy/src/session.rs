use crate::config::ProxyConfig;
use crate::translate::{self, TranslateError};
use crate::v1::codec::V1Codec;
use crate::v1::messages::{
    self, Authorize, ExtranonceSubscribe, JsonRpcRequest, Notification, SetExtranonceParams,
    Submit, Subscribe,
};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::future::{pending, pending as future_pending};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{self, Instant};
use tracing::{debug, info, warn};
use zcash_mining_protocol::codec::{
    MessageFrame, decode_new_equihash_job, decode_set_target, decode_submit_shares_response,
    encode_set_worker_identity, encode_submit_share,
};
use zcash_mining_protocol::messages::SetWorkerIdentity;
use zcash_mining_protocol::messages::{
    NewEquihashJob, RejectReason, SetTarget, ShareResult, SubmitEquihashShare,
    SubmitSharesResponse, message_types,
};

#[derive(Debug, Default)]
pub struct ProxyMetrics {
    active_sessions: AtomicUsize,
    total_connections: AtomicU64,
    total_v2_reconnects: AtomicU64,
}

impl ProxyMetrics {
    pub fn on_session_started(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_session_stopped(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn on_upstream_reconnected(&self) {
        self.total_v2_reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# TYPE sovright_v1_stratum_proxy_active_sessions gauge\n",
                "sovright_v1_stratum_proxy_active_sessions {}\n",
                "# TYPE sovright_v1_stratum_proxy_total_connections counter\n",
                "sovright_v1_stratum_proxy_total_connections {}\n",
                "# TYPE sovright_v1_stratum_proxy_total_v2_reconnects counter\n",
                "sovright_v1_stratum_proxy_total_v2_reconnects {}\n"
            ),
            self.active_sessions.load(Ordering::Relaxed),
            self.total_connections.load(Ordering::Relaxed),
            self.total_v2_reconnects.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connected,
    Subscribed,
    Authorized,
    Mining,
}

#[derive(Debug)]
pub struct MinerSession {
    downstream_reader: BufReader<OwnedReadHalf>,
    downstream_writer: OwnedWriteHalf,
    downstream_line: String,
    upstream: Option<UpstreamConnection>,
    config: ProxyConfig,
    metrics: Arc<ProxyMetrics>,
    peer_addr: SocketAddr,
    state: SessionState,
    worker_name: Option<String>,
    extranonce_subscribed: bool,
    channel_id: Option<u32>,
    nonce_1: Vec<u8>,
    nonce_2_size: Option<usize>,
    job_map: HashMap<String, u32>,
    current_job: Option<NewEquihashJob>,
    current_target: Option<[u8; 32]>,
    next_sequence: u32,
    pending_shares: HashMap<u32, PendingShare>,
    reconnect_delay: Duration,
    next_reconnect_at: Option<Instant>,
    ever_connected_upstream: bool,
}

#[derive(Debug)]
struct PendingShare {
    request_id: Value,
}

#[derive(Debug)]
struct UpstreamConnection {
    stream: TcpStream,
    read_buf: Vec<u8>,
}

#[derive(Debug)]
enum UpstreamMessage {
    NewJob(NewEquihashJob),
    SetTarget(SetTarget),
    SubmitResponse(SubmitSharesResponse),
}

#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Protocol(zcash_mining_protocol::ProtocolError),
    Translate(TranslateError),
    InvalidRequest(String),
    UpstreamClosed,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {}", error),
            Self::Json(error) => write!(f, "JSON error: {}", error),
            Self::Protocol(error) => write!(f, "protocol error: {}", error),
            Self::Translate(error) => write!(f, "translation error: {}", error),
            Self::InvalidRequest(message) => f.write_str(message),
            Self::UpstreamClosed => f.write_str("upstream closed the connection"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<zcash_mining_protocol::ProtocolError> for SessionError {
    fn from(error: zcash_mining_protocol::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<TranslateError> for SessionError {
    fn from(error: TranslateError) -> Self {
        Self::Translate(error)
    }
}

impl MinerSession {
    pub fn new(
        stream: TcpStream,
        config: ProxyConfig,
        metrics: Arc<ProxyMetrics>,
        peer_addr: SocketAddr,
    ) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            downstream_reader: BufReader::new(reader),
            downstream_writer: writer,
            downstream_line: String::new(),
            upstream: None,
            config,
            metrics,
            peer_addr,
            state: SessionState::Connected,
            worker_name: None,
            extranonce_subscribed: false,
            channel_id: None,
            nonce_1: Vec::new(),
            nonce_2_size: None,
            job_map: HashMap::new(),
            current_job: None,
            current_target: None,
            next_sequence: 0,
            pending_shares: HashMap::new(),
            reconnect_delay: Duration::from_secs(1),
            next_reconnect_at: None,
            ever_connected_upstream: false,
        }
    }

    pub async fn run(mut self) -> Result<(), SessionError> {
        info!(peer = %self.peer_addr, "Miner session started");

        loop {
            let idle = time::sleep(self.config.timeouts.miner_idle);
            tokio::pin!(idle);
            let next_reconnect_at = self.next_reconnect_at;
            let (downstream_reader, downstream_line, upstream) = (
                &mut self.downstream_reader,
                &mut self.downstream_line,
                &mut self.upstream,
            );

            tokio::select! {
                line_result = Self::read_v1_line(downstream_reader, downstream_line) => {
                    match line_result? {
                        Some(line) => self.handle_v1_line(&line).await?,
                        None => {
                            info!(peer = %self.peer_addr, worker = ?self.worker_name, "Miner disconnected");
                            break;
                        }
                    }
                }
                upstream_result = async {
                    match upstream.as_mut() {
                        Some(upstream) => upstream.read_message().await,
                        None => future_pending::<Result<Option<UpstreamMessage>, SessionError>>().await,
                    }
                }, if upstream.is_some() => {
                    match upstream_result? {
                        Some(message) => self.handle_upstream_message(message, true).await?,
                        None => self.on_upstream_disconnect("upstream connection closed").await?,
                    }
                }
                _ = async {
                    match next_reconnect_at {
                        Some(deadline) => time::sleep_until(deadline).await,
                        None => pending::<()>().await,
                    }
                }, if next_reconnect_at.is_some() => {
                    self.try_reconnect().await?;
                }
                _ = &mut idle => {
                    info!(peer = %self.peer_addr, worker = ?self.worker_name, "Closing idle miner session");
                    break;
                }
            }
        }

        self.fail_all_pending_shares("Session closed").await?;
        Ok(())
    }

    async fn read_v1_line(
        reader: &mut BufReader<OwnedReadHalf>,
        buf: &mut String,
    ) -> Result<Option<String>, SessionError> {
        buf.clear();
        // Read into a bounded buffer to prevent memory exhaustion from
        // a malicious client sending megabytes without a newline.
        let limit = V1Codec::MAX_LINE_LENGTH;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if buf.is_empty() {
                    return Ok(None);
                }
                // EOF mid-line: return what we have
                break;
            }
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let line_bytes = &available[..pos];
                buf.push_str(&String::from_utf8_lossy(line_bytes));
                reader.consume(pos + 1); // consume including newline
                break;
            }
            // No newline yet — append what we have
            let chunk_len = available.len();
            buf.push_str(&String::from_utf8_lossy(available));
            reader.consume(chunk_len);
            if buf.len() > limit {
                return Err(SessionError::InvalidRequest(format!(
                    "downstream line exceeded {} bytes",
                    limit
                )));
            }
        }
        Ok(Some(buf.trim_end_matches(['\r', '\n']).to_owned()))
    }

    async fn handle_v1_line(&mut self, line: &str) -> Result<(), SessionError> {
        if line.trim().is_empty() {
            return Ok(());
        }

        let raw: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                self.send_json(&messages::json_rpc_error_response(
                    Value::Null,
                    -32700,
                    format!("parse error: {}", error),
                ))
                .await?;
                return Ok(());
            }
        };

        let request: JsonRpcRequest = match serde_json::from_value(raw) {
            Ok(request) => request,
            Err(error) => {
                self.send_json(&messages::json_rpc_error_response(
                    Value::Null,
                    -32600,
                    format!("invalid request: {}", error),
                ))
                .await?;
                return Ok(());
            }
        };

        let params = match request.params_as_array() {
            Ok(params) => params,
            Err(error) => {
                self.send_json(&messages::json_rpc_error_response(
                    request.id.clone(),
                    -32602,
                    error,
                ))
                .await?;
                return Ok(());
            }
        };

        match request.method.as_str() {
            "mining.subscribe" => match Subscribe::try_from(params) {
                Ok(subscribe) => self.handle_subscribe(request.id, subscribe).await,
                Err(error) => {
                    self.send_json(&messages::json_rpc_error_response(
                        request.id, -32602, error,
                    ))
                    .await?;
                    Ok(())
                }
            },
            "mining.authorize" => match Authorize::try_from(params) {
                Ok(authorize) => self.handle_authorize(request.id, authorize).await,
                Err(error) => {
                    self.send_json(&messages::json_rpc_error_response(
                        request.id, -32602, error,
                    ))
                    .await?;
                    Ok(())
                }
            },
            "mining.extranonce.subscribe" => match ExtranonceSubscribe::try_from(params) {
                Ok(subscribe) => {
                    self.handle_extranonce_subscribe(request.id, subscribe)
                        .await
                }
                Err(error) => {
                    self.send_json(&messages::json_rpc_error_response(
                        request.id, -32602, error,
                    ))
                    .await?;
                    Ok(())
                }
            },
            "mining.submit" => match Submit::try_from(params) {
                Ok(submit) => self.handle_submit(request.id, submit).await,
                Err(error) => {
                    self.send_json(&messages::json_rpc_error_response(
                        request.id, -32602, error,
                    ))
                    .await?;
                    Ok(())
                }
            },
            other => {
                self.send_json(&messages::json_rpc_error_response(
                    request.id,
                    -32601,
                    format!("unknown method '{}'", other),
                ))
                .await?;
                Ok(())
            }
        }
    }

    async fn handle_subscribe(
        &mut self,
        request_id: Value,
        subscribe: Subscribe,
    ) -> Result<(), SessionError> {
        debug!(
            peer = %self.peer_addr,
            user_agent = ?subscribe.user_agent,
            session_id = ?subscribe.session_id,
            host = ?subscribe.host,
            port = ?subscribe.port,
            "Handling mining.subscribe"
        );
        if self.upstream.is_none() {
            match self.connect_upstream().await {
                Ok(initial_messages) => {
                    for message in initial_messages {
                        self.handle_upstream_message(message, false).await?;
                    }
                }
                Err(error) => {
                    self.send_json(&messages::json_rpc_error_response(
                        request_id,
                        -32603,
                        format!("failed to connect upstream: {}", error),
                    ))
                    .await?;
                    return Ok(());
                }
            }
        }

        self.recompute_state();

        // ZIP 301: mining.subscribe result is [SESSION_ID, NONCE_1], where
        // SESSION_ID is a plain string (for reconnect), NOT a Bitcoin-style
        // [method, subscription_id] pair. Real Zcash firmware (Bitmain Z15 /
        // GodMiner) needs this shape; with the pair form it authorizes but
        // silently drops once work arrives.
        let session_id = self
            .channel_id
            .map(|channel_id| channel_id.to_string())
            .unwrap_or_else(|| "session".to_string());
        let result = serde_json::json!([session_id, translate::bytes_to_hex(&self.nonce_1)]);

        self.send_json(&messages::success_response(request_id, result))
            .await?;
        self.send_set_extranonce().await?;
        self.flush_work_state(false).await?;
        Ok(())
    }

    async fn handle_authorize(
        &mut self,
        request_id: Value,
        authorize: Authorize,
    ) -> Result<(), SessionError> {
        debug!(
            peer = %self.peer_addr,
            worker = %authorize.worker_name,
            password_supplied = authorize.password.is_some(),
            "Handling mining.authorize"
        );
        self.worker_name = Some(authorize.worker_name);
        self.recompute_state();
        self.send_json(&messages::bool_response(request_id, true))
            .await?;
        // Forward the SV1 username as our upstream worker identity so the pool
        // can attribute this connection's shares to it. Only send if upstream
        // exists; never fail the authorize response over an identity-send error.
        if self.upstream.is_some() {
            self.send_worker_identity().await?;
        }
        self.flush_work_state(false).await?;
        Ok(())
    }

    async fn handle_extranonce_subscribe(
        &mut self,
        request_id: Value,
        _subscribe: ExtranonceSubscribe,
    ) -> Result<(), SessionError> {
        self.extranonce_subscribed = true;
        self.send_json(&messages::bool_response(request_id, true))
            .await?;
        Ok(())
    }

    async fn handle_submit(
        &mut self,
        request_id: Value,
        submit: Submit,
    ) -> Result<(), SessionError> {
        if let Some(worker_name) = &self.worker_name
            && submit.worker_name != *worker_name
        {
            warn!(
                expected = %worker_name,
                got = %submit.worker_name,
                "Rejecting share: worker name mismatch"
            );
            self.send_json(&messages::submit_error_response(
                request_id,
                "Worker name mismatch",
            ))
            .await?;
            return Ok(());
        }

        let Some(channel_id) = self.channel_id else {
            self.send_json(&messages::submit_error_response(
                request_id,
                "Upstream not connected",
            ))
            .await?;
            return Ok(());
        };

        let Some(job_id) = self.job_map.get(&submit.job_id).copied() else {
            self.send_json(&messages::submit_error_response(request_id, "Stale job"))
                .await?;
            return Ok(());
        };

        let Some(upstream) = self.upstream.as_mut() else {
            self.send_json(&messages::submit_error_response(
                request_id,
                "Upstream reconnecting",
            ))
            .await?;
            return Ok(());
        };

        let sequence_number = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);

        let share = match translate::submit_to_v2(
            channel_id,
            sequence_number,
            job_id,
            &submit.nonce_2_hex,
            &submit.time_hex,
            &submit.solution_hex,
        ) {
            Ok(share) => share,
            Err(error) => {
                self.send_json(&messages::submit_error_response(
                    request_id,
                    error.to_string(),
                ))
                .await?;
                return Ok(());
            }
        };

        upstream.write_share(&share).await?;
        self.pending_shares
            .insert(sequence_number, PendingShare { request_id });
        Ok(())
    }

    async fn handle_upstream_message(
        &mut self,
        message: UpstreamMessage,
        emit_notifications: bool,
    ) -> Result<(), SessionError> {
        match message {
            UpstreamMessage::NewJob(job) => {
                let nonce_changed = self.nonce_1 != job.nonce_1
                    || self.nonce_2_size != Some(job.nonce_2_len as usize);
                let target_changed = self.current_target != Some(job.target);

                if job.clean_jobs {
                    self.job_map.clear();
                }

                self.channel_id = Some(job.channel_id);
                self.nonce_1 = job.nonce_1.clone();
                self.nonce_2_size = Some(job.nonce_2_len as usize);
                self.current_target = Some(job.target);
                self.job_map.insert(job.job_id.to_string(), job.job_id);
                self.current_job = Some(job.clone());
                self.recompute_state();

                if emit_notifications && self.can_send_work_notifications() {
                    if nonce_changed {
                        self.send_set_extranonce().await?;
                    }
                    if target_changed {
                        self.send_target_update(job.target).await?;
                    }
                    self.send_notify(&job).await?;
                }
            }
            UpstreamMessage::SetTarget(target) => {
                self.channel_id = Some(target.channel_id);
                self.current_target = Some(target.target);
                self.recompute_state();
                if emit_notifications && self.can_send_work_notifications() {
                    self.send_target_update(target.target).await?;
                }
            }
            UpstreamMessage::SubmitResponse(response) => {
                self.handle_submit_response(response).await?;
            }
        }

        Ok(())
    }

    async fn handle_submit_response(
        &mut self,
        response: SubmitSharesResponse,
    ) -> Result<(), SessionError> {
        let Some(pending) = self.pending_shares.remove(&response.sequence_number) else {
            warn!(
                sequence = response.sequence_number,
                "Received upstream response for unknown sequence"
            );
            return Ok(());
        };

        match response.result {
            ShareResult::Accepted => {
                self.send_json(&messages::bool_response(pending.request_id, true))
                    .await?;
            }
            ShareResult::Rejected(reason) => {
                self.send_json(&messages::submit_error_response(
                    pending.request_id,
                    reject_reason_to_string(&reason),
                ))
                .await?;
            }
        }

        Ok(())
    }

    async fn connect_upstream(&mut self) -> Result<Vec<UpstreamMessage>, SessionError> {
        // Pass the upstream as a host:port string on every (re)connect so
        // `TcpStream::connect` re-resolves DNS each time. This is why we keep a
        // string here instead of a cached `SocketAddr`: a compose service like
        // `jdc` whose container IP changes on restart is dialed correctly.
        let upstream = UpstreamConnection::connect(
            &self.config.upstream,
            self.config.timeouts.upstream_connect,
        )
        .await?;
        self.upstream = Some(upstream);

        let mut initial_messages = Vec::new();
        loop {
            let Some(upstream) = self.upstream.as_mut() else {
                return Err(SessionError::UpstreamClosed);
            };

            let message = match time::timeout(
                self.config.timeouts.upstream_connect,
                upstream.read_message(),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    self.upstream = None;
                    return Err(SessionError::InvalidRequest(
                        "timed out waiting for initial upstream job".to_string(),
                    ));
                }
            };

            match message {
                Some(message) => {
                    let saw_job = matches!(message, UpstreamMessage::NewJob(_));
                    initial_messages.push(message);
                    if saw_job {
                        break;
                    }
                }
                None => {
                    self.upstream = None;
                    return Err(SessionError::UpstreamClosed);
                }
            }
        }

        self.reconnect_delay = Duration::from_secs(1);
        self.next_reconnect_at = None;
        if self.ever_connected_upstream {
            self.metrics.on_upstream_reconnected();
        } else {
            self.ever_connected_upstream = true;
        }

        // Forward worker identity on (re)connect if already known (covers
        // reconnects where authorize has already set worker_name). On first
        // connect the worker_name is None and this is a no-op.
        self.send_worker_identity().await?;

        Ok(initial_messages)
    }

    async fn try_reconnect(&mut self) -> Result<(), SessionError> {
        self.next_reconnect_at = None;
        match self.connect_upstream().await {
            Ok(initial_messages) => {
                self.job_map.clear();
                self.current_job = None;
                self.current_target = None;
                self.fail_all_pending_shares("Upstream reconnected").await?;
                for message in initial_messages {
                    self.handle_upstream_message(message, false).await?;
                }
                self.send_set_extranonce().await?;
                self.flush_work_state(false).await?;
                info!(peer = %self.peer_addr, worker = ?self.worker_name, "Reconnected upstream");
            }
            Err(error) => {
                warn!(
                    peer = %self.peer_addr,
                    worker = ?self.worker_name,
                    "Upstream reconnect failed: {}",
                    error
                );
                self.schedule_reconnect();
            }
        }

        Ok(())
    }

    async fn on_upstream_disconnect(&mut self, reason: &str) -> Result<(), SessionError> {
        warn!(
            peer = %self.peer_addr,
            worker = ?self.worker_name,
            "{}",
            reason
        );
        self.upstream = None;
        self.channel_id = None;
        self.current_job = None;
        self.current_target = None;
        self.job_map.clear();
        self.recompute_state();
        self.fail_all_pending_shares("Upstream disconnected")
            .await?;
        self.schedule_reconnect();
        Ok(())
    }

    fn schedule_reconnect(&mut self) {
        let delay = self
            .reconnect_delay
            .min(self.config.timeouts.upstream_reconnect_max);
        self.next_reconnect_at = Some(Instant::now() + delay);
        self.reconnect_delay = self
            .reconnect_delay
            .saturating_mul(2)
            .min(self.config.timeouts.upstream_reconnect_max);
    }

    async fn fail_all_pending_shares(&mut self, reason: &str) -> Result<(), SessionError> {
        if self.pending_shares.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_shares);
        for (_, share) in pending {
            self.send_json(&messages::submit_error_response(
                share.request_id,
                reason.to_string(),
            ))
            .await?;
        }
        Ok(())
    }

    /// Send a SetWorkerIdentity message upstream using the current worker_name.
    ///
    /// Called from two sites:
    ///  1. end of `handle_authorize` — the REQUIRED primary path: upstream
    ///     already exists, worker name just arrived.
    ///  2. end of `connect_upstream` — covers reconnects where the worker name
    ///     is already known. On first connect the name is None and this is a
    ///     no-op; pool immutability means a duplicate after reconnect is ignored.
    ///
    /// Never fails the caller: encode failures (post-sanitization: impossible)
    /// are logged and skipped; upstream write errors propagate like any other
    /// upstream write error.
    async fn send_worker_identity(&mut self) -> Result<(), SessionError> {
        let Some(raw_name) = self.worker_name.as_deref() else {
            return Ok(());
        };
        let Some(name) = sanitize_worker_name(raw_name) else {
            return Ok(());
        };
        let Some(upstream) = self.upstream.as_mut() else {
            return Ok(());
        };
        let msg = SetWorkerIdentity { worker_name: name };
        match encode_set_worker_identity(&msg) {
            Ok(encoded) => {
                upstream.write_raw(&encoded).await?;
            }
            Err(e) => {
                // Post-sanitization this cannot happen; never block mining on a label.
                warn!(error = %e, "Failed to encode worker identity, continuing anonymous");
            }
        }
        Ok(())
    }

    async fn flush_work_state(&mut self, include_extranonce: bool) -> Result<(), SessionError> {
        if !self.can_send_work_notifications() {
            return Ok(());
        }

        if include_extranonce {
            self.send_set_extranonce().await?;
        }
        if let Some(target) = self.current_target {
            self.send_target_update(target).await?;
        }
        if let Some(job) = self.current_job.clone() {
            self.send_notify(&job).await?;
        }

        Ok(())
    }

    async fn send_notify(&mut self, job: &NewEquihashJob) -> Result<(), SessionError> {
        let notify = Notification::new("mining.notify", translate::job_to_notify(job));
        self.send_typed_json(&notify).await
    }

    async fn send_target_update(&mut self, target: [u8; 32]) -> Result<(), SessionError> {
        let (target_params, _difficulty_params) = translate::target_to_v1(&target);
        let set_target = Notification::new("mining.set_target", target_params);
        // Zcash V1 miners (e.g. Bitmain Z15 / GodMiner) are target-based and use
        // mining.set_target exclusively. Emitting a Bitcoin-style
        // mining.set_difficulty alongside it causes some firmware to reject the
        // session (observed: Z15 Pro disconnects ~130ms after the work burst).
        self.send_typed_json(&set_target).await
    }

    async fn send_set_extranonce(&mut self) -> Result<(), SessionError> {
        let Some(nonce_2_size) = self.nonce_2_size else {
            return Ok(());
        };
        if self.nonce_1.is_empty() {
            return Ok(());
        }
        if !self.extranonce_subscribed && self.worker_name.is_none() {
            return Ok(());
        }

        let message = Notification::new(
            "mining.set_extranonce",
            SetExtranonceParams(translate::bytes_to_hex(&self.nonce_1), nonce_2_size),
        );
        self.send_typed_json(&message).await
    }

    async fn send_json(&mut self, value: &Value) -> Result<(), SessionError> {
        let encoded = serde_json::to_vec(value)?;
        self.downstream_writer.write_all(&encoded).await?;
        self.downstream_writer.write_all(b"\n").await?;
        self.downstream_writer.flush().await?;
        Ok(())
    }

    async fn send_typed_json<T>(&mut self, value: &T) -> Result<(), SessionError>
    where
        T: serde::Serialize,
    {
        let encoded = serde_json::to_vec(value)?;
        self.downstream_writer.write_all(&encoded).await?;
        self.downstream_writer.write_all(b"\n").await?;
        self.downstream_writer.flush().await?;
        Ok(())
    }

    fn recompute_state(&mut self) {
        self.state = if self.upstream.is_some() && self.worker_name.is_some() {
            SessionState::Mining
        } else if self.worker_name.is_some() {
            SessionState::Authorized
        } else if self.upstream.is_some() {
            SessionState::Subscribed
        } else {
            SessionState::Connected
        };
    }

    fn can_send_work_notifications(&self) -> bool {
        self.state == SessionState::Mining
    }
}

impl UpstreamConnection {
    async fn connect(addr: &str, timeout: Duration) -> Result<Self, SessionError> {
        let stream = match time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(SessionError::InvalidRequest(format!(
                    "timed out connecting to upstream {}",
                    addr
                )));
            }
        };

        Ok(Self {
            stream,
            read_buf: Vec::with_capacity(4096),
        })
    }

    async fn write_share(&mut self, share: &SubmitEquihashShare) -> Result<(), SessionError> {
        let encoded = encode_submit_share(share)?;
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Write pre-encoded bytes directly to the upstream stream.
    async fn write_raw(&mut self, data: &[u8]) -> Result<(), SessionError> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_message(&mut self) -> Result<Option<UpstreamMessage>, SessionError> {
        loop {
            if self.read_buf.len() >= MessageFrame::HEADER_SIZE {
                let frame = MessageFrame::decode(&self.read_buf[..MessageFrame::HEADER_SIZE])?;
                let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
                if self.read_buf.len() >= total_len {
                    let message = self.read_buf.drain(..total_len).collect::<Vec<_>>();
                    match decode_upstream_message(&message)? {
                        Some(message) => return Ok(Some(message)),
                        None => continue,
                    }
                }
            }

            let mut temp = [0u8; 4096];
            let read = self.stream.read(&mut temp).await?;
            if read == 0 {
                return Ok(None);
            }
            self.read_buf.extend_from_slice(&temp[..read]);
        }
    }
}

fn decode_upstream_message(frame: &[u8]) -> Result<Option<UpstreamMessage>, SessionError> {
    let parsed = MessageFrame::decode(frame)?;
    let message = match parsed.msg_type {
        message_types::NEW_EQUIHASH_JOB => UpstreamMessage::NewJob(decode_new_equihash_job(frame)?),
        message_types::SET_TARGET => UpstreamMessage::SetTarget(decode_set_target(frame)?),
        message_types::SUBMIT_SHARES_RESPONSE => {
            UpstreamMessage::SubmitResponse(decode_submit_shares_response(frame)?)
        }
        other => {
            warn!("Ignoring unknown upstream message type 0x{:02x}", other);
            return Ok(None);
        }
    };

    Ok(Some(message))
}

/// Sanitize an SV1 username into a protocol-valid worker name: replace any
/// character outside [A-Za-z0-9._-] with '_', truncate to 64 chars. Returns
/// None for an empty input (caller skips identity; pool falls back to
/// channel_N). Sanitize rather than reject: SV1 usernames are arbitrary
/// ASIC-config strings and the proxy must not refuse service over a label.
fn sanitize_worker_name(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    Some(cleaned)
}

fn reject_reason_to_string(reason: &RejectReason) -> String {
    match reason {
        RejectReason::StaleJob => "Stale job".to_string(),
        RejectReason::Duplicate => "Duplicate share".to_string(),
        RejectReason::InvalidSolution => "Invalid solution".to_string(),
        RejectReason::LowDifficulty => "Low difficulty".to_string(),
        RejectReason::Other(message) => message.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_worker_name_cases() {
        assert_eq!(sanitize_worker_name("rig-1"), Some("rig-1".to_string()));
        assert_eq!(
            sanitize_worker_name("addr.worker"),
            Some("addr.worker".to_string())
        );
        assert_eq!(
            sanitize_worker_name("has space!"),
            Some("has_space_".to_string())
        );
        assert_eq!(
            sanitize_worker_name(&"x".repeat(80)),
            Some("x".repeat(64))
        );
        assert_eq!(sanitize_worker_name(""), None);
        assert_eq!(sanitize_worker_name("🔥🔥"), Some("__".to_string()));
    }
}
