use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::config::Config;
use crate::error::{IngressError, Result};
use crate::event::EventSink;

#[derive(Clone)]
pub struct Crawler {
    inner: Arc<Mutex<CrawlerInner>>,
    enabled: bool,
    max_known_peers: usize,
}

struct CrawlerInner {
    seen: HashSet<SocketAddr>,
    queue: VecDeque<SocketAddr>,
}

impl Crawler {
    pub fn new(config: &Config, initial_peers: impl IntoIterator<Item = SocketAddr>) -> Self {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        for peer in initial_peers {
            if seen.insert(peer) {
                queue.push_back(peer);
            }
        }

        Self {
            inner: Arc::new(Mutex::new(CrawlerInner { seen, queue })),
            enabled: config.crawler_enabled,
            max_known_peers: config.crawler_max_known_peers,
        }
    }

    pub fn next_peer(&self) -> Option<SocketAddr> {
        self.inner.lock().ok()?.queue.pop_front()
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
            .map(|inner| inner.seen.len())
            .unwrap_or_default()
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
                if inner.seen.len() >= self.max_known_peers {
                    break;
                }
                if inner.seen.insert(peer) {
                    inner.queue.push_back(peer);
                    accepted.push(peer);
                }
            }
        }

        for peer in &accepted {
            events.p2p_peer_discovered(source_peer, &peer.to_string())?;
        }

        Ok(accepted.len())
    }
}
