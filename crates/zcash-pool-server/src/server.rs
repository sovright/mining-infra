//! Main pool server orchestration
//!
//! Coordinates template provider, sessions, job distribution, and share processing.
//!
//! ## Known Limitations (MVP)
//!
//! - **Vardiff state**: Per-channel vardiff state is owned by Session tasks. The server
//!   creates temporary Channel instances for job creation which don't preserve vardiff
//!   history. A production implementation would add a ChannelManager that maintains
//!   persistent channel state server-side.
//!
//! - **Block target**: Currently uses a simplified block target. Production would
//!   extract the actual target from the template.

use crate::channel::Channel;
use crate::config::PoolConfig;
use crate::duplicate::{DuplicateDetector, InMemoryDuplicateDetector};
use crate::error::{PoolError, Result};
#[cfg(feature = "forge")]
use crate::forge::ForgeRelay;
use crate::job::JobDistributor;
use crate::payout::{MinerId, PayoutTracker};
use crate::security::{ConnectionTracker, SequenceCheckResult, SequenceValidator, TimingJitter};
use crate::session::{ServerMessage, Session, SessionMessage, Transport};
use crate::share::ShareProcessor;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};
use tracing::{debug, error, info, warn};
use zcash_equihash_validator::VardiffConfig;
use zcash_jd_server::{
    handle_jd_client_with_transport, CurrentTemplateContext, JdServer, JdServerConfig,
    JdTransport,
};
use zcash_mining_protocol::messages::{NewEquihashJob, ShareResult};
use bedrock_noise::{Keypair, NoiseResponder};
use bedrock_strata::{init_logging, start_metrics_server, LogFormat, PoolMetrics};
use zcash_template_provider::types::BlockTemplate;
use zcash_template_provider::{TemplateProvider, TemplateProviderConfig};
use zcash_mining_protocol::messages::SubmitEquihashShare;
use hex;

#[derive(Clone)]
struct ConnectionCtx {
    config: PoolConfig,
    job_distributor: Arc<RwLock<JobDistributor>>,
    sessions: Arc<RwLock<HashMap<u32, mpsc::Sender<ServerMessage>>>>,
    channels: Arc<RwLock<HashMap<u32, Channel>>>,
    session_tx: mpsc::Sender<SessionMessage>,
    metrics: Arc<PoolMetrics>,
    connection_tracker: Arc<ConnectionTracker>,
    sequence_validator: Arc<SequenceValidator>,
    connection_times: Arc<RwLock<HashMap<u32, (Instant, SocketAddr)>>>,
}

/// Main pool server
pub struct PoolServer {
    /// Server configuration
    config: PoolConfig,
    /// Template provider for fetching block templates
    template_provider: Arc<TemplateProvider>,
    /// Job distributor (creates jobs from templates)
    job_distributor: Arc<RwLock<JobDistributor>>,
    /// Share processor (validates shares)
    share_processor: Arc<ShareProcessor>,
    /// Duplicate share detector
    duplicate_detector: Arc<InMemoryDuplicateDetector>,
    /// PPS payout tracker
    payout_tracker: Arc<PayoutTracker>,
    /// Active sessions (channel_id -> sender)
    sessions: Arc<RwLock<HashMap<u32, mpsc::Sender<ServerMessage>>>>,
    /// Channel state (channel_id -> Channel)
    channels: Arc<RwLock<HashMap<u32, Channel>>>,
    /// Channel for session messages
    session_tx: mpsc::Sender<SessionMessage>,
    /// Receiver for session messages
    session_rx: mpsc::Receiver<SessionMessage>,
    /// Current block target (for checking block finds)
    current_block_target: Arc<RwLock<[u8; 32]>>,
    /// JD Server (embedded, optional)
    jd_server: Arc<JdServer>,
    /// JD Server listen address (None = disabled)
    jd_listen_addr: Option<SocketAddr>,
    /// Noise responder for encrypted connections (None = disabled)
    noise_responder: Option<Arc<NoiseResponder>>,
    /// Pool metrics
    metrics: Arc<PoolMetrics>,
    /// Forge relay for compact block propagation (optional, requires "forge" feature)
    #[cfg(feature = "forge")]
    forge_relay: Option<Arc<ForgeRelay>>,
    /// Sequence validator for replay protection
    sequence_validator: Arc<SequenceValidator>,
    /// Connection tracker for attack detection
    connection_tracker: Arc<ConnectionTracker>,
    /// Timing jitter for response timing attack mitigation
    timing_jitter: Arc<TimingJitter>,
    /// Track connection start times (channel_id -> (Instant, SocketAddr))
    connection_times: Arc<RwLock<HashMap<u32, (Instant, SocketAddr)>>>,
    /// Limits concurrent miner handshakes and sessions.
    miner_slots: Arc<Semaphore>,
    /// Limits concurrent JD handshakes and sessions.
    jd_slots: Arc<Semaphore>,
}

impl PoolServer {
    /// Create a new pool server
    pub fn new(config: PoolConfig) -> Result<Self> {
        // Validate configuration before proceeding
        config
            .validate()
            .map_err(|e| PoolError::Config(e.to_string()))?;
        let max_connections = config.max_connections;

        // Initialize logging based on config
        let log_format = if config.json_logging {
            LogFormat::Json
        } else {
            LogFormat::Pretty
        };
        init_logging(log_format, "info");

        // Create metrics
        let metrics = Arc::new(PoolMetrics::new());

        // Create forge relay if enabled (requires "forge" feature)
        #[cfg(feature = "forge")]
        let forge_relay = if config.forge_relay_enabled {
            match ForgeRelay::new(&config) {
                Ok(relay) => {
                    info!("Forge relay initialized");
                    Some(Arc::new(relay))
                }
                Err(e) => {
                    warn!("Failed to create forge relay: {}. Continuing without relay.", e);
                    None
                }
            }
        } else {
            info!("Forge relay disabled");
            None
        };
        #[cfg(not(feature = "forge"))]
        if config.forge_relay_enabled {
            warn!("Forge relay requested but 'forge' feature is not enabled. Ignoring.");
        }

        // Create template provider
        let tp_config = TemplateProviderConfig {
            zebra_url: config.zebra_url.clone(),
            poll_interval_ms: config.template_poll_ms,
        };
        let template_provider = TemplateProvider::new(tp_config)
            .map_err(|e| PoolError::TemplateProvider(e.to_string()))?;

        // Create session channel (buffered to handle bursts)
        let (session_tx, session_rx) = mpsc::channel(10000);

        // Create payout tracker (shared with JD server)
        let payout_tracker = Arc::new(PayoutTracker::default());

        // Create JD Server with shared payout tracker
        let jd_config = JdServerConfig {
            pool_payout_script: config.pool_payout_script.clone().unwrap_or_default(),
            noise_enabled: config.jd_noise_enabled,
            full_template_enabled: config.jd_full_template_enabled,
            full_template_validation: config.jd_full_template_validation,
            min_pool_payout: config.jd_min_pool_payout,
            ..JdServerConfig::default()
        };
        let jd_server = Arc::new(JdServer::new(jd_config, Arc::clone(&payout_tracker)));

        let jd_listen_addr = config.jd_listen_addr;

        // Create Noise responder if enabled for miner or JD connections
        let noise_responder = if config.noise_enabled || config.jd_noise_enabled {
            let keypair = if let Some(ref key_path) = config.noise_private_key_path {
                // Load keypair from file
                let key_hex = std::fs::read_to_string(key_path)
                    .map_err(|e| PoolError::Config(format!("Failed to read noise key file: {}", e)))?;
                Keypair::from_private_hex(key_hex.trim())
                    .map_err(|e| PoolError::Config(format!("Invalid noise private key: {}", e)))?
            } else {
                // Generate a new keypair
                let kp = Keypair::generate();
                info!(
                    "Generated new Noise keypair. Public key: {}",
                    kp.public.to_hex()
                );
                info!("To persist this key, save the private key to a file and set noise_private_key_path");
                kp
            };
            Some(Arc::new(NoiseResponder::new(keypair)))
        } else {
            // Warn about insecure plain mode if configured
            if config.warn_plain_mode {
                warn!("⚠️  SECURITY WARNING: Noise encryption is DISABLED");
                warn!("    Plain mode is vulnerable to StraTap, BiteCoin, and ISP Log attacks");
                warn!("    Enable noise_enabled=true for production deployments");
            }
            None
        };

        // Create security components
        let sequence_validator = Arc::new(SequenceValidator::new(
            config.sequence_max_gap,
            128, // Window size for tracking seen sequences
        ));

        let connection_tracker = Arc::new(ConnectionTracker::new(
            Duration::from_secs(config.short_lived_threshold_secs),
            Duration::from_secs(300), // 5 minute tracking window
            config.max_short_lived_per_window,
        ));

        let timing_jitter = Arc::new(TimingJitter::new(
            Duration::from_millis(config.timing_jitter_min_ms),
            Duration::from_millis(config.timing_jitter_max_ms),
        ));

        info!("Security features: sequence_validation={}, connection_tracking={}, timing_jitter={}",
            config.sequence_validation_enabled,
            config.connection_tracking_enabled,
            config.timing_jitter_enabled
        );

        Ok(Self {
            config,
            template_provider: Arc::new(template_provider),
            job_distributor: Arc::new(RwLock::new(JobDistributor::new())),
            share_processor: Arc::new(ShareProcessor::new()),
            duplicate_detector: Arc::new(InMemoryDuplicateDetector::new()),
            payout_tracker,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            session_tx,
            session_rx,
            // Initialize to impossible target (all zeros) so any share validated
            // before the first template arrives is rejected. This is fail-closed:
            // no hash can be <= [0x00; 32] except the zero hash itself.
            current_block_target: Arc::new(RwLock::new([0x00; 32])),
            jd_server,
            jd_listen_addr,
            noise_responder,
            metrics,
            #[cfg(feature = "forge")]
            forge_relay,
            sequence_validator,
            connection_tracker,
            timing_jitter,
            connection_times: Arc::new(RwLock::new(HashMap::new())),
            miner_slots: Arc::new(Semaphore::new(max_connections)),
            jd_slots: Arc::new(Semaphore::new(max_connections)),
        })
    }

    fn connection_ctx(&self) -> ConnectionCtx {
        ConnectionCtx {
            config: self.config.clone(),
            job_distributor: Arc::clone(&self.job_distributor),
            sessions: Arc::clone(&self.sessions),
            channels: Arc::clone(&self.channels),
            session_tx: self.session_tx.clone(),
            metrics: Arc::clone(&self.metrics),
            connection_tracker: Arc::clone(&self.connection_tracker),
            sequence_validator: Arc::clone(&self.sequence_validator),
            connection_times: Arc::clone(&self.connection_times),
        }
    }

    /// Run the pool server
    pub async fn run(mut self) -> Result<()> {
        // Start metrics server if configured
        if let Some(metrics_addr) = self.config.metrics_addr {
            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                start_metrics_server(metrics_addr, metrics).await;
            });
        }

        // Bind to listen address
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Pool server listening on {}", self.config.listen_addr);

        // Optionally bind JD listener
        let jd_listener = if let Some(addr) = self.jd_listen_addr {
            let listener = TcpListener::bind(addr).await?;
            info!("JD Server listening on {}", addr);
            Some(listener)
        } else {
            info!("JD Server disabled (no jd_listen_addr configured)");
            None
        };

        // Subscribe to template updates
        let mut template_rx = self.template_provider.subscribe();

        // Spawn template provider task
        let tp = Arc::clone(&self.template_provider);
        tokio::spawn(async move {
            if let Err(e) = tp.run().await {
                error!("CRITICAL: Template provider terminated: {}. Pool will serve stale jobs until restarted.", e);
            }
        });

        // Initialize and start forge relay if enabled
        #[cfg(feature = "forge")]
        if let Some(ref forge) = self.forge_relay {
            if let Err(e) = forge.init().await {
                warn!("Failed to initialize forge relay: {}. Continuing without relay.", e);
            } else {
                let forge = Arc::clone(forge);
                tokio::spawn(async move {
                    if let Err(e) = forge.start().await {
                        warn!("Forge relay start error: {}", e);
                    }
                });
                info!("Forge relay started");
            }
        }

        // Spawn periodic stats logging and stale miner cleanup
        let payout_tracker = Arc::clone(&self.payout_tracker);
        let sessions = Arc::clone(&self.sessions);
        let metrics = Arc::clone(&self.metrics);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                // Clean up stale miner entries (idle > 30 minutes)
                payout_tracker.cleanup_stale_miners(Duration::from_secs(1800));
                payout_tracker.rotate_window_if_needed();

                let session_count = sessions.read().await.len();
                let active_miners = payout_tracker.active_miner_count();
                let hashrate = payout_tracker.estimate_pool_hashrate();

                // Update metrics
                metrics.set_hashrate(hashrate);

                info!(
                    "Pool stats: {} connections, {} active miners, {:.2} H/s",
                    session_count, active_miners, hashrate
                );
            }
        });

        // Spawn periodic cleanup for connection tracker and sequence validator
        let cleanup_connection_tracker = Arc::clone(&self.connection_tracker);
        let cleanup_sequence_validator = Arc::clone(&self.sequence_validator);
        tokio::spawn(async move {
            // Run cleanup every 5 minutes
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            let max_age = Duration::from_secs(3600); // 1 hour
            loop {
                interval.tick().await;
                cleanup_connection_tracker.cleanup(max_age);
                cleanup_sequence_validator.cleanup_stale(max_age);
                debug!("Periodic cleanup completed for connection tracker and sequence validator");
            }
        });

        // Main event loop
        loop {
            tokio::select! {
                // Accept new miner connections
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            info!("New connection from {}", addr);

                            let Ok(permit) = self.miner_slots.clone().try_acquire_owned() else {
                                warn!("Connection limit reached, rejecting {}", addr);
                                continue;
                            };

                            // Track connection in metrics
                            self.metrics.record_connection();

                            let ctx = self.connection_ctx();
                            let metrics = Arc::clone(&self.metrics);
                            let connection_tracker = Arc::clone(&self.connection_tracker);
                            let connection_tracking_enabled = self.config.connection_tracking_enabled;
                            let noise_enabled = self.config.noise_enabled;
                            let responder = self.noise_responder.clone();

                            tokio::spawn(async move {
                                if connection_tracking_enabled && connection_tracker.is_flagged(&addr) {
                                    warn!(
                                        "Connection from flagged address {}, allowing but monitoring",
                                        addr
                                    );
                                }

                                let transport = if noise_enabled {
                                    if let Some(responder) = responder {
                                        metrics.record_noise_handshake();
                                        match tokio::time::timeout(
                                            Duration::from_secs(10),
                                            responder.accept(stream),
                                        )
                                        .await
                                        {
                                            Err(_) => {
                                                metrics.record_noise_handshake_failed();
                                                metrics.record_disconnection();
                                                warn!("Noise handshake timed out for {}", addr);
                                                return;
                                            }
                                            Ok(Ok(noise_stream)) => {
                                                info!("Noise handshake successful for {}", addr);
                                                Transport::Noise(noise_stream)
                                            }
                                            Ok(Err(e)) => {
                                                metrics.record_noise_handshake_failed();
                                                metrics.record_disconnection();
                                                metrics.record_decryption_failure();
                                                warn!("Noise handshake failed for {}: {}", addr, e);

                                                if connection_tracking_enabled {
                                                    let connected_at = connection_tracker.on_connect(addr);
                                                    if connection_tracker.on_disconnect(addr, connected_at, true) {
                                                        metrics.inc_flagged_addresses();
                                                    }
                                                }
                                                return;
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Noise enabled but no responder available; falling back to plaintext"
                                        );
                                        Transport::Plain(stream)
                                    }
                                } else {
                                    Transport::Plain(stream)
                                };

                                if let Err(e) =
                                    Self::handle_new_connection(ctx, transport, addr, permit).await
                                {
                                    metrics.record_disconnection();
                                    error!("Error handling new connection: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }

                // Accept JD client connections (if JD server is enabled)
                jd_accept_result = async {
                    if let Some(ref listener) = jd_listener {
                        listener.accept().await
                    } else {
                        // If JD is disabled, this branch never completes
                        std::future::pending().await
                    }
                } => {
                    if let Ok((stream, addr)) = jd_accept_result {
                        info!("New JD client from {}", addr);
                        let Ok(permit) = self.jd_slots.clone().try_acquire_owned() else {
                            warn!("JD connection limit reached, rejecting {}", addr);
                            continue;
                        };
                        self.metrics.record_jd_connection();
                        let jd_server = Arc::clone(&self.jd_server);
                        let metrics = Arc::clone(&self.metrics);
                        let client_id = format!("jd_{}", addr);
                        let jd_noise_enabled = self.config.jd_noise_enabled;
                        let responder = self.noise_responder.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let transport = if jd_noise_enabled {
                                if let Some(responder) = responder {
                                    metrics.record_noise_handshake();
                                    match tokio::time::timeout(
                                        Duration::from_secs(10),
                                        responder.accept(stream),
                                    )
                                    .await
                                    {
                                        Ok(Ok(noise_stream)) => JdTransport::Noise(noise_stream),
                                        Ok(Err(e)) => {
                                            metrics.record_noise_handshake_failed();
                                            warn!("JD Noise handshake failed from {}: {}", addr, e);
                                            metrics.record_jd_disconnection();
                                            return;
                                        }
                                        Err(_) => {
                                            metrics.record_noise_handshake_failed();
                                            warn!("JD Noise handshake timed out from {}", addr);
                                            metrics.record_jd_disconnection();
                                            return;
                                        }
                                    }
                                } else {
                                    warn!("JD Noise enabled but no responder available; falling back to plaintext");
                                    JdTransport::Plain(stream)
                                }
                            } else {
                                JdTransport::Plain(stream)
                            };

                            if let Err(e) = handle_jd_client_with_transport(transport, jd_server, client_id).await {
                                warn!("JD client error: {}", e);
                            }
                            metrics.record_jd_disconnection();
                        });
                    }
                }

                // Handle template updates
                template_result = template_rx.recv() => {
                    match template_result {
                        Ok(template) => {
                            if let Err(e) = self.handle_new_template(template).await {
                                error!("Error handling template: {}", e);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Missed {} template updates", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            error!("Template provider channel closed");
                            return Err(PoolError::TemplateProvider("channel closed".to_string()));
                        }
                    }
                }

                // Handle session messages
                Some(msg) = self.session_rx.recv() => {
                    if let Err(e) = self.handle_session_message(msg).await {
                        error!("Error handling session message: {}", e);
                    }
                }

                // Handle graceful shutdown
                _ = signal::ctrl_c() => {
                    info!("Shutdown signal received, closing connections gracefully...");

                    // Notify all sessions to shut down
                    let sessions = self.sessions.read().await;
                    let session_count = sessions.len();
                    for (channel_id, sender) in sessions.iter() {
                        if sender.send(ServerMessage::Shutdown).await.is_err() {
                            debug!("Session {} already closed", channel_id);
                        }
                    }
                    drop(sessions);

                    // Give sessions a moment to close gracefully
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    info!("Graceful shutdown complete ({} sessions closed)", session_count);
                    return Ok(());
                }
            }
        }
    }

    /// Handle a new miner connection
    async fn handle_new_connection(
        ctx: ConnectionCtx,
        transport: Transport,
        addr: SocketAddr,
        permit: OwnedSemaphorePermit,
    ) -> Result<()> {
        // Track connection start time
        let connected_at = if ctx.config.connection_tracking_enabled {
            ctx.connection_tracker.on_connect(addr)
        } else {
            Instant::now()
        };

        // Generate unique nonce_1 for this channel
        let channel_id = Channel::next_id();
        let nonce_1 = match Channel::generate_nonce_1(channel_id, ctx.config.nonce_1_len) {
            Some(n) => n,
            None => {
                error!(
                    "Invalid nonce_1_len configuration: {}",
                    ctx.config.nonce_1_len
                );
                return Err(PoolError::InvalidMessage(format!(
                    "Invalid nonce_1_len: {}",
                    ctx.config.nonce_1_len
                )));
            }
        };

        // Create vardiff config
        let vardiff_config = VardiffConfig {
            target_shares_per_minute: ctx.config.target_shares_per_minute,
            initial_difficulty: ctx.config.initial_difficulty,
            min_difficulty: ctx.config.initial_difficulty,
            max_difficulty: 1e12,
            retarget_interval: Duration::from_secs(90),
            variance_tolerance: 0.25,
        };

        // Create channel
        let channel = match Channel::new_with_id(channel_id, nonce_1, vardiff_config) {
            Some(c) => c,
            None => {
                error!("Failed to create channel {}", channel_id);
                return Err(PoolError::InvalidMessage(
                    "Failed to create channel".to_string(),
                ));
            }
        };

        // Create communication channels
        let (server_to_session_tx, server_to_session_rx) = mpsc::channel(1000);

        // Store session sender
        {
            let mut sessions = ctx.sessions.write().await;
            sessions.insert(channel_id, server_to_session_tx.clone());
        }

        // Store channel state
        {
            let mut channels = ctx.channels.write().await;
            channels.insert(channel_id, channel);
        }

        // Create session
        let session = Session::new(
            transport,
            channel_id,
            ctx.session_tx.clone(),
            server_to_session_rx,
        );

        // Store connection time for tracking
        {
            let mut conn_times = ctx.connection_times.write().await;
            conn_times.insert(channel_id, (connected_at, addr));
        }

        // Send initial job if available
        let initial_job = {
            let distributor = ctx.job_distributor.read().await;
            if distributor.has_template() {
                let mut channels = ctx.channels.write().await;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    if let Some(job) = distributor.create_job(channel, true) {
                        channel.add_job(job.clone(), true);
                        Some(job)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(job) = initial_job {
            let _ = server_to_session_tx.send(ServerMessage::NewJob(job)).await;
        }

        // Spawn session task
        let sessions = Arc::clone(&ctx.sessions);
        let channels = Arc::clone(&ctx.channels);
        let metrics = Arc::clone(&ctx.metrics);
        let connection_tracker = Arc::clone(&ctx.connection_tracker);
        let sequence_validator = Arc::clone(&ctx.sequence_validator);
        let connection_times = Arc::clone(&ctx.connection_times);
        let connection_tracking_enabled = ctx.config.connection_tracking_enabled;
        let short_lived_threshold = Duration::from_secs(ctx.config.short_lived_threshold_secs);

        tokio::spawn(async move {
            let _permit = permit;
            let decryption_error = match session.run().await {
                Ok(()) => false,
                Err(e) => {
                    debug!("Session {} ended: {}", channel_id, e);
                    // Check if this is a decryption error using error variant
                    matches!(&e, PoolError::Io(io_err) if io_err.kind() == std::io::ErrorKind::InvalidData)
                }
            };

            // Get connection time info before cleanup
            let conn_info = connection_times.write().await.remove(&channel_id);

            // Clean up session and channel atomically on exit
            // Note: We take both locks before modifying either to prevent race conditions
            // where share validation could access a channel that's partially cleaned up
            {
                let mut sessions_guard = sessions.write().await;
                let mut channels_guard = channels.write().await;
                sessions_guard.remove(&channel_id);
                channels_guard.remove(&channel_id);
            }

            // Track connection duration and detect attack patterns
            if let Some((connected_at, addr)) = conn_info {
                let duration = connected_at.elapsed();
                metrics.observe_connection_duration(duration.as_secs_f64());

                // Check for short-lived connection
                if duration < short_lived_threshold {
                    metrics.record_short_lived_connection();
                }

                // Track disconnection for attack pattern detection
                if connection_tracking_enabled {
                    if connection_tracker.on_disconnect(addr, connected_at, decryption_error) {
                        metrics.inc_flagged_addresses();
                    }
                }

                // Clean up sequence validator state
                sequence_validator.remove_channel(channel_id);
            }

            metrics.record_disconnection();
        });


        info!("Session {} started", channel_id);
        Ok(())
    }

    /// Handle a new block template
    async fn handle_new_template(&self, template: BlockTemplate) -> Result<()> {
        let height = template.height;
        info!("New template at height {}", height);

        // Update block target
        {
            let mut target = self.current_block_target.write().await;
            *target = template.target.0;
        }

        // Update JD Server's current prev_hash (for stale detection)
        self.jd_server
            .set_current_prev_hash(template.header.prev_hash.0)
            .await;
        let template_txids: Vec<[u8; 32]> = template
            .transactions
            .iter()
            .filter_map(|tx| zcash_template_provider::types::Hash256::from_hex(&tx.hash).ok())
            .map(|hash| hash.0)
            .collect();
        self.jd_server
            .set_current_template(CurrentTemplateContext {
                version: template.header.version,
                prev_hash: template.header.prev_hash.0,
                block_commitments: template.header.hash_block_commitments.0,
                bits: template.header.bits,
                time: template.header.time,
                txids: template_txids,
                coinbase_tx_len: template.coinbase.len(),
            })
            .await;

        // Announce to forge relay network (non-blocking)
        #[cfg(feature = "forge")]
        if let Some(ref forge) = self.forge_relay {
            let forge = Arc::clone(forge);
            let template_clone = template.clone();
            tokio::spawn(async move {
                if let Err(e) = forge.announce_template(&template_clone).await {
                    warn!("Failed to announce template to forge relay: {}", e);
                }
            });
        }

        // Update job distributor
        let is_new_block = {
            let mut distributor = self.job_distributor.write().await;
            distributor.update_template(template)
        };

        // Broadcast jobs to all sessions
        self.broadcast_jobs(is_new_block).await?;

        // Prune stale job entries from the duplicate detector.
        // We do this AFTER broadcasting so that in-flight shares for old jobs
        // can still be checked against the detector before their entries are removed.
        if is_new_block {
            let active_job_ids: HashSet<u32> = {
                let channels = self.channels.read().await;
                channels.values().flat_map(|ch| ch.tracked_job_ids()).collect()
            };
            self.duplicate_detector.prune_inactive(&active_job_ids);
            info!("New block detected, pruned inactive jobs from duplicate detector");
        }

        Ok(())
    }

    /// Broadcast new jobs to all connected sessions
    async fn broadcast_jobs(&self, clean_jobs: bool) -> Result<()> {
        // Collect session senders first, then release the sessions lock before
        // acquiring channels.write(). This prevents sessions.read() from being
        // held while channels.write() is acquired, which would block all share
        // submissions for the duration of job creation.
        let session_senders: Vec<(u32, mpsc::Sender<ServerMessage>)> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .map(|(&id, sender)| (id, sender.clone()))
                .collect()
        };

        let jobs_to_send = {
            let distributor = self.job_distributor.read().await;

            if !distributor.has_template() {
                return Ok(());
            }

            let mut jobs: Vec<(mpsc::Sender<ServerMessage>, NewEquihashJob)> = Vec::new();

            {
                let mut channels = self.channels.write().await;
                for (channel_id, sender) in &session_senders {
                    if let Some(channel) = channels.get_mut(channel_id) {
                        if let Some(job) = distributor.create_job(channel, clean_jobs) {
                            channel.add_job(job.clone(), clean_jobs);
                            jobs.push((sender.clone(), job));
                        }
                    }
                }
            }

            jobs
        };

        let mut broadcast_count = 0;
        let mut slow_or_closed = Vec::new();
        for (sender, job) in jobs_to_send {
            match sender.try_send(ServerMessage::NewJob(job)) {
                Ok(()) => {
                    broadcast_count += 1;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(ServerMessage::NewJob(job)))
                | Err(tokio::sync::mpsc::error::TrySendError::Closed(ServerMessage::NewJob(job))) => {
                    slow_or_closed.push(job.channel_id);
                }
                Err(_) => {}
            }
        }

        if !slow_or_closed.is_empty() {
            let mut sessions = self.sessions.write().await;
            let mut channels = self.channels.write().await;
            for channel_id in slow_or_closed {
                warn!(
                    "Dropping slow or closed session {} during job broadcast",
                    channel_id
                );
                sessions.remove(&channel_id);
                channels.remove(&channel_id);
            }
        }

        debug!(
            "Broadcast job to {} sessions (clean={})",
            broadcast_count, clean_jobs
        );
        Ok(())
    }

    /// Handle a message from a session
    async fn handle_session_message(&self, msg: SessionMessage) -> Result<()> {
        match msg {
            SessionMessage::ShareSubmitted {
                channel_id,
                share,
                response_tx,
            } => {
                self.handle_share_submission(channel_id, *share, response_tx)
                    .await
            }
            SessionMessage::Disconnected { channel_id } => {
                // Cleanup is handled by the spawned session task on exit
                // (see handle_new_connection). This message is informational only
                // to avoid a double-cleanup race between the task exit path and
                // this message handler.
                info!("Session {} disconnected", channel_id);
                Ok(())
            }
        }
    }

    /// Handle a share submission
    async fn handle_share_submission(
        &self,
        channel_id: u32,
        share: zcash_mining_protocol::messages::SubmitEquihashShare,
        response_tx: tokio::sync::oneshot::Sender<zcash_mining_protocol::messages::ShareResult>,
    ) -> Result<()> {
        // Validate sequence number for replay protection
        if self.config.sequence_validation_enabled {
            let seq_result = self.sequence_validator.validate(channel_id, share.sequence_number);
            match seq_result {
                SequenceCheckResult::Valid => {}
                SequenceCheckResult::ValidOutOfOrder
                | SequenceCheckResult::GapTooLarge
                | SequenceCheckResult::StaleSequence => {
                    self.metrics.record_sequence_anomaly();
                    warn!(
                        "Rejecting non-monotonic sequence {} for channel {}",
                        share.sequence_number, channel_id
                    );
                    return response_tx
                        .send(ShareResult::Rejected(
                            zcash_mining_protocol::messages::RejectReason::Other(
                                "invalid sequence".to_string(),
                            ),
                        ))
                        .map_err(|_| PoolError::ChannelSend)
                        .map(|_| ());
                }
                SequenceCheckResult::Replay => {
                    self.metrics.record_replay_attempt();
                    warn!(
                        "Replay detected: channel {} seq {} - rejecting share",
                        channel_id, share.sequence_number
                    );
                    return response_tx
                        .send(ShareResult::Rejected(
                            zcash_mining_protocol::messages::RejectReason::Duplicate,
                        ))
                        .map_err(|_| PoolError::ChannelSend)
                        .map(|_| ());
                }
            }
        }

        // Check rate limit BEFORE any expensive validation
        {
            let mut channels = self.channels.write().await;
            if let Some(channel) = channels.get_mut(&channel_id) {
                if !channel.check_rate_limit() {
                    debug!("Rate limiting channel {}", channel_id);
                    return response_tx
                        .send(ShareResult::Rejected(
                            zcash_mining_protocol::messages::RejectReason::Other("rate limited".to_string()),
                        ))
                        .map_err(|_| PoolError::ChannelSend)
                        .map(|_| ());
                }
            }
        }

        // Get block target
        let block_target = *self.current_block_target.read().await;

        // Grab the job without holding the lock during validation.
        // Use is_job_active() which checks BOTH the active flag AND the TTL,
        // matching the Quint spec's job expiry model.
        let job = {
            let channels = self.channels.read().await;
            let channel = channels.get(&channel_id).ok_or(PoolError::UnknownChannel(channel_id))?;
            if !channel.is_job_active(share.job_id) {
                return response_tx
                    .send(ShareResult::Rejected(
                        zcash_mining_protocol::messages::RejectReason::StaleJob,
                    ))
                    .map_err(|_| PoolError::ChannelSend)
                    .map(|_| ());
            }
            channel.get_job(share.job_id)
                .ok_or(PoolError::UnknownJob(share.job_id))?
                .job.clone()
        };

        // Validate share without holding the channel lock
        let result = self.share_processor.validate_share_with_job(
            &share,
            &job,
            self.duplicate_detector.as_ref(),
            &block_target,
        );

        // Apply vardiff update and record payout atomically under one lock.
        // This prevents the channel from being removed between the two operations.
        let (maybe_new_target, _accepted_info) = if let Ok(ref validation) = result {
            if validation.accepted {
                let difficulty = validation.difficulty;
                let is_block = validation.is_block;
                let mut channels = self.channels.write().await;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    // Re-check job is still active after regaining the lock.
                    // Between the read at line ~860 and this write lock, a new block
                    // could have deactivated the job via broadcast_jobs(clean=true).
                    // Without this re-check, shares for stale jobs would be accepted
                    // and paid — the TOCTOU race modeled by ConcurrentShareValidation
                    // in the Quint spec.
                    if !channel.is_job_active(share.job_id) {
                        debug!("Job {} became stale during validation for channel {}", share.job_id, channel_id);
                        (None, None)
                    } else {
                        let new_target = if channel.record_share().is_some() {
                            Some(channel.current_target())
                        } else {
                            None
                        };
                        // Record payout inside same lock scope
                        if let Some(diff) = difficulty {
                            let miner_id: MinerId = self
                                .connection_times
                                .read()
                                .await
                                .get(&channel_id)
                                .map(|(_, addr)| addr.ip().to_string())
                                .unwrap_or_else(|| format!("channel_{}", channel_id));
                            self.payout_tracker.record_share(&miner_id, diff);
                        }
                        (new_target, Some((difficulty, is_block)))
                    }
                } else {
                    warn!("Channel {} removed during share validation", channel_id);
                    (None, None)
                }
            } else {
                (None, Some((None, false)))
            }
        } else {
            (None, None)
        };

        let share_result = match result {
            Ok(validation) => {
                if validation.accepted {
                    // Check for block find
                    if validation.is_block {
                        info!(
                            "BLOCK FOUND by channel {}! Job: {}, Height: {:?}",
                            channel_id,
                            share.job_id,
                            self.job_distributor.read().await.current_height()
                        );

                        // Announce to forge relay BEFORE submitting to Zebra
                        // This gives the relay network a head start
                        #[cfg(feature = "forge")]
                        if let Some(ref forge) = self.forge_relay {
                            let header = job.build_header(&job.build_nonce(&share.nonce_2).unwrap_or_default());

                            // Clone all needed data atomically in one lock acquisition
                            let forge_data = {
                                let distributor = self.job_distributor.read().await;
                                distributor.current_template().map(|t| {
                                    let tx_hashes: Vec<[u8; 32]> = t.transactions.iter()
                                        .filter_map(|tx| {
                                            let bytes = hex::decode(&tx.hash).ok()?;
                                            if bytes.len() == 32 {
                                                let mut arr = [0u8; 32];
                                                arr.copy_from_slice(&bytes);
                                                arr.reverse();
                                                Some(arr)
                                            } else {
                                                None
                                            }
                                        })
                                        .collect();
                                    let coinbase = t.coinbase.clone();
                                    (coinbase, tx_hashes)
                                })
                            };

                            if let Some((coinbase, tx_hashes)) = forge_data {
                                let forge = Arc::clone(forge);
                                tokio::spawn(async move {
                                    if let Err(e) = forge.announce_block(&header, &coinbase, &tx_hashes).await {
                                        warn!("Failed to announce block to forge relay: {}", e);
                                    }
                                });
                            }
                        }

                        if let Err(e) = self.submit_block(&job, &share).await {
                            warn!("Failed to submit block for job {}: {}", share.job_id, e);
                        }
                    }

                    debug!(
                        "Share accepted from channel {} (diff: {:?})",
                        channel_id, validation.difficulty
                    );
                }

                validation.result
            }
            Err(e) => {
                warn!("Share validation error: {}", e);
                zcash_mining_protocol::messages::ShareResult::Rejected(
                    zcash_mining_protocol::messages::RejectReason::InvalidSolution,
                )
            }
        };

        // Apply vardiff target update if needed
        if let Some(target) = maybe_new_target {
            if let Some(sender) = self.sessions.read().await.get(&channel_id) {
                let _ = sender
                    .send(ServerMessage::SetTarget { target })
                    .await;
            }
        }

        // Apply timing jitter before response (mitigates timing attacks)
        if self.config.timing_jitter_enabled {
            self.timing_jitter.apply().await;
        }

        // Send response back to session
        let _ = response_tx.send(share_result);

        Ok(())
    }

    async fn submit_block(&self, job: &NewEquihashJob, share: &SubmitEquihashShare) -> Result<()> {
        let template = {
            let distributor = self.job_distributor.read().await;
            distributor
                .current_template()
                .ok_or_else(|| PoolError::TemplateProvider("missing current template".to_string()))?
        };

        if template.header.prev_hash.0 != job.prev_hash {
            return Err(PoolError::TemplateProvider(
                "template prev_hash mismatch for solved job".to_string(),
            ));
        }

        let block_bytes = build_block_bytes(job, share, &template)?;
        let block_hex = hex::encode(block_bytes);

        match self.template_provider.submit_block(&block_hex).await {
            Ok(None) => {
                info!("Submitted block for job {} successfully", share.job_id);
            }
            Ok(Some(err)) => {
                warn!("Zebra rejected block for job {}: {}", share.job_id, err);
            }
            Err(e) => {
                return Err(PoolError::TemplateProvider(e.to_string()));
            }
        }

        Ok(())
    }

    /// Get the number of active sessions
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Get payout tracker reference
    pub fn payout_tracker(&self) -> &Arc<PayoutTracker> {
        &self.payout_tracker
    }

    /// Get current pool stats
    pub async fn get_stats(&self) -> PoolStats {
        let sessions = self.session_count().await;
        let active_miners = self.payout_tracker.active_miner_count();
        let hashrate = self.payout_tracker.estimate_pool_hashrate();
        let current_height = self.job_distributor.read().await.current_height();

        PoolStats {
            connected_sessions: sessions,
            active_miners,
            estimated_hashrate: hashrate,
            current_height,
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of connected sessions
    pub connected_sessions: usize,
    /// Number of active miners (submitted shares recently)
    pub active_miners: usize,
    /// Estimated pool hashrate
    pub estimated_hashrate: f64,
    /// Current block height
    pub current_height: Option<u64>,
}

use zcash_pool_common::write_compact_size as write_varint;

fn build_block_bytes(
    job: &NewEquihashJob,
    share: &SubmitEquihashShare,
    template: &BlockTemplate,
) -> Result<Vec<u8>> {
    if template.coinbase.is_empty() {
        return Err(PoolError::TemplateProvider(
            "template coinbase is empty".to_string(),
        ));
    }

    // Validate share timestamp: must be within ±2 hours of the job time
    // to match Zcash's MAX_FUTURE_BLOCK_TIME consensus rule
    const MAX_TIME_OFFSET: u32 = 7200; // 2 hours in seconds
    if share.time > job.time.saturating_add(MAX_TIME_OFFSET)
        || share.time < job.time.saturating_sub(MAX_TIME_OFFSET)
    {
        return Err(PoolError::InvalidMessage(format!(
            "share time {} is too far from job time {} (max offset: {}s)",
            share.time, job.time, MAX_TIME_OFFSET
        )));
    }

    let full_nonce = job
        .build_nonce(&share.nonce_2)
        .ok_or_else(|| PoolError::InvalidMessage("Invalid nonce_2 length".to_string()))?;
    let mut header = job.build_header(&full_nonce);
    header[100..104].copy_from_slice(&share.time.to_le_bytes());

    let mut block = Vec::with_capacity(
        header.len()
            + share.solution.len()
            + template.coinbase.len()
            + template.transactions.len() * 100,
    );
    block.extend_from_slice(&header);
    // CompactSize encoding for solution length (1344 bytes)
    write_varint(1344, &mut block);
    block.extend_from_slice(&share.solution);

    let tx_count = 1 + template.transactions.len() as u64;
    write_varint(tx_count, &mut block);
    block.extend_from_slice(&template.coinbase);

    for tx in &template.transactions {
        let tx_bytes = hex::decode(&tx.data)
            .map_err(|e| PoolError::TemplateProvider(format!("invalid tx data: {}", e)))?;
        block.extend_from_slice(&tx_bytes);
    }

    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_server_creation() {
        let config = PoolConfig::default();
        let server = PoolServer::new(config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_pool_stats_default() {
        let stats = PoolStats {
            connected_sessions: 0,
            active_miners: 0,
            estimated_hashrate: 0.0,
            current_height: None,
        };
        assert_eq!(stats.connected_sessions, 0);
    }
}
