//! Which datagrams a node has finished with, for tests. Behind the `handled-log` feature, so
//! no real build has it. A test names what it sent, by source and bytes, and waits for exactly
//! that: no total count, no order, and nothing added to the wire.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use sha2::{Digest, Sha256};

/// More than any test here sends. Past this the oldest go, so a wait for one of those runs
/// out, and nothing passes on it.
const MAX_RECORDS: usize = 8192;

type Record = (SocketAddr, [u8; 32]);

fn record(src: SocketAddr, datagram: &[u8]) -> Record {
    (src, Sha256::digest(datagram).into())
}

#[derive(Debug, Default)]
pub(crate) struct HandledLog {
    finished: HashMap<Record, u64>,
    order: VecDeque<Record>,
}

impl HandledLog {
    pub(crate) fn note(&mut self, src: SocketAddr, datagram: &[u8]) {
        self.note_within(src, datagram, MAX_RECORDS);
    }

    fn note_within(&mut self, src: SocketAddr, datagram: &[u8], max: usize) {
        let record = record(src, datagram);
        let times = self.finished.entry(record).or_default();
        *times += 1;
        if *times > 1 {
            return;
        }
        self.order.push_back(record);
        if self.order.len() > max
            && let Some(oldest) = self.order.pop_front()
        {
            self.finished.remove(&oldest);
        }
    }

    pub(crate) fn times(&self, src: SocketAddr, datagram: &[u8]) -> u64 {
        let record = record(src, datagram);
        self.finished.get(&record).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn a_datagram_counts_for_its_source_and_its_bytes_alone() {
        let mut log = HandledLog::default();
        log.note(addr(1), b"one");
        log.note(addr(1), b"one");

        assert_eq!(log.times(addr(1), b"one"), 2);
        assert_eq!(log.times(addr(2), b"one"), 0);
        assert_eq!(log.times(addr(1), b"two"), 0);
    }

    #[test]
    fn the_log_stays_within_its_limit_and_the_oldest_go_first() {
        let mut log = HandledLog::default();
        for at in 0..10u8 {
            log.note_within(addr(1), &[at], 4);
        }

        assert_eq!(log.finished.len(), 4);
        assert_eq!(log.order.len(), 4);
        assert_eq!(log.times(addr(1), &[5]), 0);
        assert_eq!(log.times(addr(1), &[6]), 1);
    }
}
