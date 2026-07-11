use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Config, is_accepted_peer_addr};
use crate::error::{IngressError, Result};
use crate::event::EventSink;

#[derive(Clone)]
pub struct Crawler {
    inner: Arc<Mutex<CrawlerInner>>,
    enabled: bool,
    rotation_enabled: bool,
    rotation_cooldown: Duration,
    rotation_failure_cooldown: Duration,
    max_known_peers: usize,
    accept_nonstandard_ports: bool,
    peer_scoring_enabled: bool,
}

struct CrawlerInner {
    peers: HashMap<SocketAddr, PeerRecord>,
    queue: VecDeque<SocketAddr>,
    next_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOutcome {
    Rotated,
    Errored,
}

impl PeerOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::Errored => "errored",
        }
    }
}

#[derive(Debug, Clone)]
struct PeerRecord {
    active: bool,
    queued: bool,
    eligible_at: Instant,
    score: i64,
    sequence: u64,
}

impl Crawler {
    pub fn new(config: &Config, initial_peers: impl IntoIterator<Item = SocketAddr>) -> Self {
        let mut peers = HashMap::new();
        let mut queue = VecDeque::new();
        let now = Instant::now();
        let mut next_sequence = 0u64;
        for peer in initial_peers {
            if !is_accepted_peer_addr(&peer, config.accept_nonstandard_ports) {
                continue;
            }
            if peers
                .insert(
                    peer,
                    PeerRecord {
                        active: false,
                        queued: true,
                        eligible_at: now,
                        score: 0,
                        sequence: next_sequence,
                    },
                )
                .is_none()
            {
                queue.push_back(peer);
                next_sequence = next_sequence.saturating_add(1);
            }
        }

        Self {
            inner: Arc::new(Mutex::new(CrawlerInner {
                peers,
                queue,
                next_sequence,
            })),
            enabled: config.crawler_enabled,
            rotation_enabled: config.rotation_enabled,
            rotation_cooldown: config.rotation_cooldown,
            rotation_failure_cooldown: config.rotation_failure_cooldown,
            max_known_peers: config.crawler_max_known_peers,
            accept_nonstandard_ports: config.accept_nonstandard_ports,
            peer_scoring_enabled: config.peer_scoring_enabled,
        }
    }

    pub fn next_peer(&self) -> Option<SocketAddr> {
        let mut inner = self.inner.lock().ok()?;
        let now = Instant::now();
        if self.peer_scoring_enabled {
            return Self::next_scored_peer(&mut inner, now);
        }

        let candidates = inner.queue.len();
        for _ in 0..candidates {
            let peer = inner.queue.pop_front()?;
            let Some(record) = inner.peers.get_mut(&peer) else {
                continue;
            };
            record.queued = false;
            if record.active {
                continue;
            }
            if record.eligible_at <= now {
                record.active = true;
                return Some(peer);
            }
            record.queued = true;
            inner.queue.push_back(peer);
        }
        None
    }

    fn next_scored_peer(inner: &mut CrawlerInner, now: Instant) -> Option<SocketAddr> {
        let mut best = None;
        for (index, peer) in inner.queue.iter().enumerate() {
            let Some(record) = inner.peers.get(peer) else {
                continue;
            };
            if record.active || record.eligible_at > now {
                continue;
            }
            let is_better = match best {
                None => true,
                Some((_, best_score, best_sequence)) => {
                    record.score > best_score
                        || (record.score == best_score && record.sequence < best_sequence)
                }
            };
            if is_better {
                best = Some((index, record.score, record.sequence));
            }
        }

        let (index, _, _) = best?;
        let peer = inner.queue.remove(index)?;
        let record = inner.peers.get_mut(&peer)?;
        record.queued = false;
        record.active = true;
        Some(peer)
    }

    pub fn queue_len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.queue.len())
            .unwrap_or_default()
    }

    pub fn known_len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.peers.len())
            .unwrap_or_default()
    }

    pub fn release_peer(
        &self,
        peer: SocketAddr,
        outcome: PeerOutcome,
        events: &EventSink,
    ) -> Result<()> {
        let (queue_len, cooldown) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| IngressError::Wire("crawler mutex poisoned".to_string()))?;
            let Some(record) = inner.peers.get_mut(&peer) else {
                return Ok(());
            };
            record.active = false;

            let mut cooldown = Duration::ZERO;
            if self.rotation_enabled {
                cooldown = match outcome {
                    PeerOutcome::Rotated => self.rotation_cooldown,
                    PeerOutcome::Errored => self.rotation_failure_cooldown,
                };
                record.eligible_at = Instant::now() + cooldown;
                if !record.queued {
                    record.queued = true;
                    inner.queue.push_back(peer);
                }
            }
            (inner.queue.len(), cooldown)
        };

        events.p2p_peer_rotation(
            &peer.to_string(),
            outcome.as_str(),
            cooldown.as_millis(),
            queue_len,
        )
    }

    pub fn score_peer(
        &self,
        peer: SocketAddr,
        delta: i64,
        reason: &str,
        events: &EventSink,
    ) -> Result<()> {
        if !self.peer_scoring_enabled || delta == 0 {
            return Ok(());
        }

        let Some(score) = ({
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| IngressError::Wire("crawler mutex poisoned".to_string()))?;
            inner.peers.get_mut(&peer).map(|record| {
                record.score = record.score.saturating_add(delta);
                record.score
            })
        }) else {
            return Ok(());
        };

        events.p2p_peer_score(&peer.to_string(), score, reason)
    }

    pub fn add_discovered(
        &self,
        source_peer: &str,
        peers: impl IntoIterator<Item = SocketAddr>,
        events: &EventSink,
    ) -> Result<usize> {
        if !self.enabled {
            return Ok(0);
        }

        let mut accepted = Vec::new();
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| IngressError::Wire("crawler mutex poisoned".to_string()))?;
            for peer in peers {
                if !is_accepted_peer_addr(&peer, self.accept_nonstandard_ports) {
                    continue;
                }
                if inner.peers.len() >= self.max_known_peers {
                    break;
                }
                if inner.peers.contains_key(&peer) {
                    continue;
                }
                let sequence = inner.next_sequence;
                inner.next_sequence = inner.next_sequence.saturating_add(1);
                inner.peers.insert(
                    peer,
                    PeerRecord {
                        active: false,
                        queued: true,
                        eligible_at: Instant::now(),
                        score: 0,
                        sequence,
                    },
                );
                inner.queue.push_back(peer);
                accepted.push(peer);
            }
        }

        for peer in &accepted {
            events.p2p_peer_discovered(source_peer, &peer.to_string())?;
        }

        Ok(accepted.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn config(rotation_enabled: bool) -> Config {
        Config {
            seeds: Vec::new(),
            peers: Vec::new(),
            max_peers: 8,
            connect_timeout: Duration::from_secs(5),
            peer_runtime: Duration::from_secs(0),
            crawler_enabled: true,
            crawler_max_known_peers: 100,
            crawler_max_addr_per_message: 100,
            crawler_drain_interval: Duration::from_secs(1),
            rotation_enabled,
            rotation_cooldown: Duration::from_secs(0),
            rotation_failure_cooldown: Duration::from_secs(30),
            accept_nonstandard_ports: false,
            peer_scoring_enabled: false,
            peer_score_block_inv: 5,
            peer_score_block_received: 25,
            peer_score_relay_forwarded: 10,
            peer_score_error: -50,
            tx_cache_enabled: false,
            tx_cache_max_entries: 200_000,
            tx_cache_max_bytes: 536_870_912,
            tx_cache_max_tx_bytes: 2_097_152,
            tx_feed_addr: None,
            tx_request_limit_per_inv: 256,
            event_log: None::<PathBuf>,
            relay_peers: Vec::new(),
            relay_bind_addr: "0.0.0.0:0".parse().unwrap(),
            relay_auth_key: None,
            relay_data_shards: 10,
            relay_parity_shards: 3,
            relay_adaptive_fec: false,
            relay_send_burst_packets: 0,
            relay_send_burst_delay_micros: 0,
            relay_compact_from_tx_cache: false,
            relay_skeleton_first: false,
            relay_raw_fallback_with_tx_cache: false,
            relay_raw_segment_send_rounds: 1,
            relay_raw_segment_round_delay_millis: 0,
            relay_forward_dedup_window: Duration::from_secs(30),
            relay_forward_dedup_capacity: 64,
            submitblock_rpc: None,
        }
    }

    fn events() -> EventSink {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sovright-p2p-crawler-test-{}-{}.jsonl",
            std::process::id(),
            unique
        ));
        EventSink::new(Some(path)).unwrap()
    }

    #[test]
    fn active_peer_is_not_selected_until_released() {
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let crawler = Crawler::new(&config(true), [peer]);

        assert_eq!(crawler.next_peer(), Some(peer));
        assert_eq!(crawler.next_peer(), None);

        crawler
            .release_peer(peer, PeerOutcome::Rotated, &events())
            .unwrap();

        assert_eq!(crawler.next_peer(), Some(peer));
    }

    #[test]
    fn released_peer_is_not_requeued_when_rotation_is_disabled() {
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let crawler = Crawler::new(&config(false), [peer]);

        assert_eq!(crawler.next_peer(), Some(peer));
        crawler
            .release_peer(peer, PeerOutcome::Rotated, &events())
            .unwrap();

        assert_eq!(crawler.next_peer(), None);
    }

    #[test]
    fn failed_peer_observes_failure_cooldown_before_retry() {
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let crawler = Crawler::new(&config(true), [peer]);

        assert_eq!(crawler.next_peer(), Some(peer));
        crawler
            .release_peer(peer, PeerOutcome::Errored, &events())
            .unwrap();

        assert_eq!(crawler.next_peer(), None);
    }

    #[test]
    fn discovered_peers_do_not_duplicate_active_peer() {
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let discovered: SocketAddr = "127.0.0.2:8233".parse().unwrap();
        let crawler = Crawler::new(&config(true), [peer]);

        assert_eq!(crawler.next_peer(), Some(peer));
        let accepted = crawler
            .add_discovered("127.0.0.9:8233", [peer, discovered], &events())
            .unwrap();

        assert_eq!(accepted, 1);
        assert_eq!(crawler.next_peer(), Some(discovered));
        assert_eq!(crawler.next_peer(), None);
    }

    #[test]
    fn crawler_rejects_known_zcash_fork_ports() {
        let zcash_peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let flux_peer: SocketAddr = "127.0.0.2:16125".parse().unwrap();
        let flux_alt_peer: SocketAddr = "127.0.0.3:26125".parse().unwrap();
        let crawler = Crawler::new(&config(true), [zcash_peer, flux_peer]);

        assert_eq!(crawler.known_len(), 1);
        assert_eq!(crawler.next_peer(), Some(zcash_peer));

        let accepted = crawler
            .add_discovered("127.0.0.9:8233", [flux_peer, flux_alt_peer], &events())
            .unwrap();

        assert_eq!(accepted, 0);
        assert_eq!(crawler.known_len(), 1);
    }

    #[test]
    fn crawler_rejects_nonstandard_ports_by_default() {
        let zcash_peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let nonstandard_peer: SocketAddr = "127.0.0.2:34567".parse().unwrap();
        let crawler = Crawler::new(&config(true), [zcash_peer, nonstandard_peer]);

        assert_eq!(crawler.known_len(), 1);
        assert_eq!(crawler.next_peer(), Some(zcash_peer));

        let accepted = crawler
            .add_discovered("127.0.0.9:8233", [nonstandard_peer], &events())
            .unwrap();

        assert_eq!(accepted, 0);
        assert_eq!(crawler.known_len(), 1);
    }

    #[test]
    fn scored_scheduler_prefers_higher_score() {
        let first: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let second: SocketAddr = "127.0.0.2:8233".parse().unwrap();
        let third: SocketAddr = "127.0.0.3:8233".parse().unwrap();
        let mut cfg = config(true);
        cfg.peer_scoring_enabled = true;
        let crawler = Crawler::new(&cfg, [first, second, third]);

        crawler
            .score_peer(third, 20, "block_received", &events())
            .unwrap();
        crawler
            .score_peer(second, 10, "block_inv", &events())
            .unwrap();

        assert_eq!(crawler.next_peer(), Some(third));
        assert_eq!(crawler.next_peer(), Some(second));
        assert_eq!(crawler.next_peer(), Some(first));
    }

    #[test]
    fn scored_scheduler_keeps_fifo_for_equal_scores() {
        let first: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let second: SocketAddr = "127.0.0.2:8233".parse().unwrap();
        let mut cfg = config(true);
        cfg.peer_scoring_enabled = true;
        let crawler = Crawler::new(&cfg, [first, second]);

        assert_eq!(crawler.next_peer(), Some(first));
        assert_eq!(crawler.next_peer(), Some(second));
    }

    #[test]
    fn scored_scheduler_skips_ineligible_high_score_peer() {
        let high_score: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let low_score: SocketAddr = "127.0.0.2:8233".parse().unwrap();
        let mut cfg = config(true);
        cfg.peer_scoring_enabled = true;
        cfg.rotation_cooldown = Duration::from_secs(30);
        let crawler = Crawler::new(&cfg, [high_score, low_score]);

        crawler
            .score_peer(high_score, 20, "block_received", &events())
            .unwrap();
        assert_eq!(crawler.next_peer(), Some(high_score));
        crawler
            .release_peer(high_score, PeerOutcome::Rotated, &events())
            .unwrap();

        assert_eq!(crawler.next_peer(), Some(low_score));
    }
}
