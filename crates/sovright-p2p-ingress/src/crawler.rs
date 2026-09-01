use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
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
    excluded_peer_ips: HashSet<IpAddr>,
    peer_scoring_enabled: bool,
    peer_score_half_life: Duration,
    peer_score_first: f64,
    peer_score_second: f64,
    peer_score_third: f64,
    peer_score_block_inv: f64,
}

struct CrawlerInner {
    peers: HashMap<SocketAddr, PeerRecord>,
    queue: VecDeque<SocketAddr>,
    next_sequence: u64,
    /// Per-block ledger of which peers have already announced, in arrival order.
    /// This is what makes rank-based scoring possible: the Nth distinct peer to
    /// announce a hash earns the Nth-place award, not a flat per-delivery credit.
    announcements: HashMap<[u8; 32], Vec<SocketAddr>>,
    announcement_order: VecDeque<[u8; 32]>,
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
    /// Exponentially decayed score. Stored with the instant it was last folded
    /// forward so decay can be applied lazily on read.
    score: f64,
    score_updated_at: Instant,
    sequence: u64,
}

impl PeerRecord {
    /// Score decayed to `now`.
    ///
    /// Decay is what stops the ranking from becoming a proxy for connection
    /// age: without it the score is a lifetime counter and a peer that was good
    /// last week outranks one that is good today. It also normalises for
    /// opportunity -- a peer scoring at rate r converges to r * half_life / ln2
    /// regardless of how long it has been connected.
    fn decayed(&self, now: Instant, half_life: Duration) -> f64 {
        if half_life.is_zero() {
            return self.score;
        }
        let elapsed = now
            .saturating_duration_since(self.score_updated_at)
            .as_secs_f64();
        self.score * 0.5f64.powf(elapsed / half_life.as_secs_f64())
    }

    fn add_decayed(&mut self, delta: f64, now: Instant, half_life: Duration) {
        self.score = self.decayed(now, half_life) + delta;
        self.score_updated_at = now;
    }
}

/// Cap on the per-block announcement ledger. Blocks arrive about every 75s, so
/// this is many hours of history; the bound exists so a peer spamming novel
/// hashes cannot grow it without limit.
pub(crate) const MAX_TRACKED_ANNOUNCEMENTS: usize = 4_096;

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
            if config.excluded_peer_ips.contains(&peer.ip()) {
                continue;
            }
            if peers
                .insert(
                    peer,
                    PeerRecord {
                        active: false,
                        queued: true,
                        eligible_at: now,
                        score: 0.0,
                        score_updated_at: now,
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
                announcements: HashMap::new(),
                announcement_order: VecDeque::new(),
            })),
            enabled: config.crawler_enabled,
            rotation_enabled: config.rotation_enabled,
            rotation_cooldown: config.rotation_cooldown,
            rotation_failure_cooldown: config.rotation_failure_cooldown,
            max_known_peers: config.crawler_max_known_peers,
            accept_nonstandard_ports: config.accept_nonstandard_ports,
            excluded_peer_ips: config.excluded_peer_ips.clone(),
            peer_scoring_enabled: config.peer_scoring_enabled,
            peer_score_half_life: config.peer_score_half_life,
            peer_score_first: config.peer_score_block_first as f64,
            peer_score_second: config.peer_score_block_second as f64,
            peer_score_third: config.peer_score_block_third as f64,
            peer_score_block_inv: config.peer_score_block_inv as f64,
        }
    }

    pub fn next_peer(&self) -> Option<SocketAddr> {
        let mut inner = self.inner.lock().ok()?;
        let now = Instant::now();
        if self.peer_scoring_enabled {
            return Self::next_scored_peer(&mut inner, now, self.peer_score_half_life);
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

    fn next_scored_peer(
        inner: &mut CrawlerInner,
        now: Instant,
        half_life: Duration,
    ) -> Option<SocketAddr> {
        let mut best: Option<(usize, f64, u64)> = None;
        for (index, peer) in inner.queue.iter().enumerate() {
            let Some(record) = inner.peers.get(peer) else {
                continue;
            };
            if record.active || record.eligible_at > now {
                continue;
            }
            // Compare decayed scores so a long-idle high-lifetime peer does not
            // outrank a peer that is delivering now.
            let score = record.decayed(now, half_life);
            let is_better = match best {
                None => true,
                Some((_, best_score, best_sequence)) => {
                    score > best_score || (score == best_score && record.sequence < best_sequence)
                }
            };
            if is_better {
                best = Some((index, score, record.sequence));
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

    /// Award a peer for announcing a block, weighted by how early it was.
    ///
    /// A flat per-delivery credit cannot distinguish a peer that is first from
    /// one that is half a second late, because both eventually deliver every
    /// block. Measured on relay-us-east4-1 over 5,039 blocks (2026-09-01), the
    /// best and worst peers both delivered ~1,670 blocks while sitting 0 ms and
    /// 507 ms behind the winner respectively -- indistinguishable under the old
    /// scheme. Rank is the signal; volume is not.
    pub fn score_block_announcement(
        &self,
        peer: SocketAddr,
        block_hash: [u8; 32],
        events: &EventSink,
    ) -> Result<()> {
        self.score_block_announcement_at(peer, block_hash, events, Instant::now())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn score_block_announcement_at(
        &self,
        peer: SocketAddr,
        block_hash: [u8; 32],
        events: &EventSink,
        now: Instant,
    ) -> Result<()> {
        if !self.peer_scoring_enabled {
            return Ok(());
        }
        let rank = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| IngressError::Wire("crawler mutex poisoned".to_string()))?;
            if !inner.announcements.contains_key(&block_hash) {
                inner.announcement_order.push_back(block_hash);
                inner.announcements.insert(block_hash, Vec::new());
            }
            let entry = inner
                .announcements
                .get_mut(&block_hash)
                .expect("just inserted");
            // Re-announcement of a block this peer already sent earns nothing;
            // otherwise a chatty peer could farm first-place points.
            if entry.contains(&peer) {
                None
            } else {
                entry.push(peer);
                Some(entry.len())
            }
        };
        self.prune_announcements()?;
        let Some(rank) = rank else { return Ok(()) };

        let (delta, reason) = match rank {
            1 => (self.peer_score_first, "block_inv_first"),
            2 => (self.peer_score_second, "block_inv_second"),
            3 => (self.peer_score_third, "block_inv_third"),
            _ => (self.peer_score_block_inv, "block_inv"),
        };

        let score = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| IngressError::Wire("crawler mutex poisoned".to_string()))?;
            let half_life = self.peer_score_half_life;
            match inner.peers.get_mut(&peer) {
                Some(record) => {
                    record.add_decayed(delta, now, half_life);
                    record.score
                }
                None => return Ok(()),
            }
        };
        events.p2p_peer_score(&peer.to_string(), score.round() as i64, reason)
    }

    fn prune_announcements(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| IngressError::Wire("crawler mutex poisoned".to_string()))?;
        while inner.announcement_order.len() > MAX_TRACKED_ANNOUNCEMENTS {
            if let Some(old) = inner.announcement_order.pop_front() {
                inner.announcements.remove(&old);
            }
        }
        Ok(())
    }

    /// Current decayed score. Test-only accessor: production reads the score
    /// through `next_scored_peer`, which decays inline.
    #[cfg(test)]
    pub fn peer_score(&self, peer: SocketAddr) -> f64 {
        self.peer_score_at(peer, Instant::now())
    }

    #[cfg(test)]
    pub fn peer_score_at(&self, peer: SocketAddr, now: Instant) -> f64 {
        let Ok(inner) = self.inner.lock() else {
            return 0.0;
        };
        inner
            .peers
            .get(&peer)
            .map(|r| r.decayed(now, self.peer_score_half_life))
            .unwrap_or(0.0)
    }

    #[cfg(test)]
    pub fn tracked_announcements(&self) -> usize {
        self.inner
            .lock()
            .map(|i| i.announcements.len())
            .unwrap_or(0)
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
            let now = Instant::now();
            let half_life = self.peer_score_half_life;
            inner.peers.get_mut(&peer).map(|record| {
                record.add_decayed(delta as f64, now, half_life);
                record.score
            })
        }) else {
            return Ok(());
        };

        events.p2p_peer_score(&peer.to_string(), score.round() as i64, reason)
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
                if self.excluded_peer_ips.contains(&peer.ip()) {
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
                        score: 0.0,
                        score_updated_at: Instant::now(),
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
            excluded_peer_ips: HashSet::new(),
            peer_scoring_enabled: false,
            peer_score_block_inv: 5,
            peer_score_block_first: 100,
            peer_score_block_second: 50,
            peer_score_block_third: 25,
            peer_score_half_life: Duration::from_secs(3600),
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
    fn crawler_rejects_excluded_peer_ips() {
        // Our own Zebra nodes became dialable when public inbound P2P was
        // opened. They are the closest peers in every region, so the crawler
        // connects to them and the ingress degrades into a downstream echo of
        // our own Zebra instead of an independent acquisition path.
        let external_peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let own_zebra: SocketAddr = "127.0.0.2:8233".parse().unwrap();
        let mut cfg = config(true);
        cfg.excluded_peer_ips = ["127.0.0.2".parse().unwrap()].into_iter().collect();

        let crawler = Crawler::new(&cfg, [external_peer, own_zebra]);

        assert_eq!(crawler.known_len(), 1);
        assert_eq!(crawler.next_peer(), Some(external_peer));

        let accepted = crawler
            .add_discovered("127.0.0.9:8233", [own_zebra], &events())
            .unwrap();

        assert_eq!(accepted, 0);
        assert_eq!(crawler.known_len(), 1);
    }

    #[test]
    fn excluded_peer_ip_is_rejected_on_every_port() {
        // Exclusion is per host, not per endpoint: a node we own is ours on
        // whatever port it gossips.
        let own_zebra_alt_port: SocketAddr = "127.0.0.2:18233".parse().unwrap();
        let mut cfg = config(true);
        cfg.accept_nonstandard_ports = true;
        cfg.excluded_peer_ips = ["127.0.0.2".parse().unwrap()].into_iter().collect();

        let crawler = Crawler::new(&cfg, [own_zebra_alt_port]);

        assert_eq!(crawler.known_len(), 0);
        assert_eq!(crawler.next_peer(), None);
    }

    #[test]
    fn empty_exclusion_set_keeps_every_peer() {
        let peer_a: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.2:8233".parse().unwrap();
        let crawler = Crawler::new(&config(true), [peer_a, peer_b]);

        assert_eq!(crawler.known_len(), 2);
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

    // --- arrival-rank scoring and decay ------------------------------------
    //
    // Measured on relay-us-east4-1 over 5,039 blocks (2026-09-01): the best peer
    // announced first 56.6% of the time at a median 0 ms behind the winner; the
    // worst sat 507 ms behind on median and won 3.1%. Both delivered ~1,670
    // blocks, so under a flat +25-per-delivery score they rank nearly the same.
    // The score could not see a 507 ms spread, which is why doubling the peer
    // cap produced 2.25x the announcements and 0% more first-hears.

    fn scoring_config() -> Config {
        let mut cfg = config(true);
        cfg.peer_scoring_enabled = true;
        cfg
    }

    #[test]
    fn first_announcer_of_a_block_outscores_the_stragglers() {
        let fast: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let slow: SocketAddr = "127.0.0.3:8233".parse().unwrap();
        let crawler = Crawler::new(&scoring_config(), [fast, slow]);
        let hash = [7u8; 32];

        crawler
            .score_block_announcement(fast, hash, &events())
            .unwrap();
        crawler
            .score_block_announcement(slow, hash, &events())
            .unwrap();

        assert!(
            crawler.peer_score(fast) > crawler.peer_score(slow),
            "being first must outscore being second on the same block"
        );
    }

    #[test]
    fn a_peer_that_only_ever_arrives_late_cannot_outrank_a_winner_by_volume() {
        // The live failure: the 507 ms peer delivered as many blocks as the 0 ms
        // peer and therefore scored as well. Rank-based points must break that.
        let fast: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let slow: SocketAddr = "127.0.0.3:8233".parse().unwrap();
        let crawler = Crawler::new(&scoring_config(), [fast, slow]);

        for i in 0..20u8 {
            let hash = [i; 32];
            crawler
                .score_block_announcement(fast, hash, &events())
                .unwrap();
            crawler
                .score_block_announcement(slow, hash, &events())
                .unwrap();
        }

        assert!(crawler.peer_score(fast) > crawler.peer_score(slow));
    }

    #[test]
    fn repeat_announcements_of_the_same_block_do_not_farm_points() {
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let crawler = Crawler::new(&scoring_config(), [peer]);
        let hash = [9u8; 32];

        let t = Instant::now();
        crawler
            .score_block_announcement_at(peer, hash, &events(), t)
            .unwrap();
        let after_first = crawler.peer_score_at(peer, t);
        crawler
            .score_block_announcement_at(peer, hash, &events(), t)
            .unwrap();

        // Read at the same instant: scores decay continuously, so comparing two
        // live reads would fail on elapsed time rather than on points awarded.
        assert_eq!(crawler.peer_score_at(peer, t), after_first);
    }

    #[test]
    fn scores_decay_so_ranking_reflects_recent_behaviour() {
        // Without decay the score is a lifetime counter and ranking becomes a
        // proxy for connection age -- the same defect class as the
        // lifetime-cumulative submit-rejection alert.
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let mut cfg = scoring_config();
        cfg.peer_score_half_life = Duration::from_secs(60);
        let crawler = Crawler::new(&cfg, [peer]);

        crawler
            .score_block_announcement(peer, [1u8; 32], &events())
            .unwrap();
        let fresh = crawler.peer_score(peer);
        let aged = crawler.peer_score_at(peer, Instant::now() + Duration::from_secs(60));

        assert!(
            aged < fresh * 0.6,
            "one half-life should roughly halve the score"
        );
        assert!(aged > fresh * 0.4);
    }

    #[test]
    fn decay_bounds_score_so_an_old_peer_cannot_coast_on_history() {
        let veteran: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let newcomer: SocketAddr = "127.0.0.3:8233".parse().unwrap();
        let mut cfg = scoring_config();
        cfg.peer_score_half_life = Duration::from_secs(1);
        let crawler = Crawler::new(&cfg, [veteran, newcomer]);

        for i in 0..50u8 {
            crawler
                .score_block_announcement(veteran, [i; 32], &events())
                .unwrap();
        }
        let later = Instant::now() + Duration::from_secs(30);
        crawler
            .score_block_announcement_at(newcomer, [200u8; 32], &events(), later)
            .unwrap();

        assert!(
            crawler.peer_score_at(newcomer, later) > crawler.peer_score_at(veteran, later),
            "30 half-lives of decay must outweigh 50 stale wins"
        );
    }

    #[test]
    fn announcement_tracker_is_bounded() {
        let peer: SocketAddr = "127.0.0.1:8233".parse().unwrap();
        let mut cfg = scoring_config();
        cfg.crawler_max_known_peers = 100;
        let crawler = Crawler::new(&cfg, [peer]);

        for i in 0..(MAX_TRACKED_ANNOUNCEMENTS + 500) {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
            crawler
                .score_block_announcement(peer, hash, &events())
                .unwrap();
        }

        assert!(crawler.tracked_announcements() <= MAX_TRACKED_ANNOUNCEMENTS);
    }
}
