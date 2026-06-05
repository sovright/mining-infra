//! Share-relay batching for the JD session loop.
//!
//! Locally-accepted downstream shares arrive on an mpsc channel from the
//! listener. The JD session loop batches them — up to [`MAX_BATCH`] shares or a
//! [`FLUSH_INTERVAL`] timeout, whichever comes first — into a single
//! `SubmitSharesJd` to the pool. This keeps one relayed share per network
//! round-trip from dominating throughput while bounding latency.
//!
//! DIVERGENCE NOTE: the pool is authoritative for credit. The JDC has already
//! told the proxy `Accepted` by the time a share reaches the relay, so a pool
//! rejection in `SubmitSharesJdResponse` cannot be propagated back downstream —
//! it is logged as a warning only. This is intentional: the JDC's local
//! validation against the pool-granted share target should agree with the
//! pool's, and the proxy's miner accounting is advisory; the pool's payout
//! tracker is the source of truth.

use crate::listener::RelayShare;
use std::time::Duration;
use zcash_jd_server::messages::{JdShare, SubmitSharesJd};

/// Maximum shares per relayed `SubmitSharesJd` batch. The wire format caps a
/// batch at 64; 32 leaves headroom and matches the flush cadence.
pub const MAX_BATCH: usize = 32;

/// Flush a partially-filled batch after this long even if under [`MAX_BATCH`].
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Accumulates relayed shares, grouped by job_id, and emits `SubmitSharesJd`
/// batches.
///
/// The wire message carries a single `job_id` per batch, so shares are grouped:
/// a batch is emitted when the running group for a job reaches [`MAX_BATCH`], or
/// when [`flush_all`](Self::flush_all) is called (timer fire / shutdown).
#[derive(Debug, Default)]
pub struct RelayBatcher {
    /// Pending shares grouped by job_id, preserving arrival order per job.
    pending: Vec<(u32, Vec<JdShare>)>,
    /// Monotonic request id for matching responses.
    next_request_id: u32,
    /// JD channel id used at declaration (reused for `SubmitSharesJd`).
    channel_id: u32,
}

impl RelayBatcher {
    /// Create a batcher bound to the JD channel id used at declaration.
    pub fn new(channel_id: u32) -> Self {
        Self {
            pending: Vec::new(),
            next_request_id: 1,
            channel_id,
        }
    }

    /// Add a share. Returns a full batch (`SubmitSharesJd`) if the share's job
    /// group reached [`MAX_BATCH`], otherwise `None`.
    pub fn push(&mut self, item: RelayShare) -> Option<SubmitSharesJd> {
        let RelayShare { job_id, share } = item;
        let group = match self.pending.iter_mut().find(|(id, _)| *id == job_id) {
            Some(g) => &mut g.1,
            None => {
                self.pending.push((job_id, Vec::new()));
                &mut self.pending.last_mut().unwrap().1
            }
        };
        group.push(share);

        if group.len() >= MAX_BATCH {
            let shares = std::mem::take(group);
            // Drop the now-empty group entry.
            self.pending.retain(|(_, v)| !v.is_empty());
            return Some(self.build_message(job_id, shares));
        }
        None
    }

    /// Emit one `SubmitSharesJd` per pending job group (used on timer/shutdown).
    /// Each returned batch holds 1..=MAX_BATCH shares.
    pub fn flush_all(&mut self) -> Vec<SubmitSharesJd> {
        let groups = std::mem::take(&mut self.pending);
        groups
            .into_iter()
            .filter(|(_, shares)| !shares.is_empty())
            .map(|(job_id, shares)| self.build_message(job_id, shares))
            .collect()
    }

    /// Whether there is anything pending to flush.
    pub fn is_empty(&self) -> bool {
        self.pending.iter().all(|(_, v)| v.is_empty())
    }

    fn build_message(&mut self, job_id: u32, shares: Vec<JdShare>) -> SubmitSharesJd {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        SubmitSharesJd {
            channel_id: self.channel_id,
            request_id,
            job_id,
            shares,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(tag: u8) -> JdShare {
        let mut nonce = [0u8; 32];
        nonce[0] = tag;
        JdShare {
            version: 5,
            time: 1_700_000_000,
            nonce,
            solution: [tag; 1344],
        }
    }

    fn relay(job_id: u32, tag: u8) -> RelayShare {
        RelayShare {
            job_id,
            share: share(tag),
        }
    }

    #[test]
    fn partial_batch_does_not_emit() {
        let mut b = RelayBatcher::new(1);
        for i in 0..5 {
            assert!(b.push(relay(7, i)).is_none());
        }
        assert!(!b.is_empty());
    }

    #[test]
    fn full_batch_emits_at_max() {
        let mut b = RelayBatcher::new(9);
        let mut emitted = None;
        for i in 0..MAX_BATCH {
            let r = b.push(relay(7, i as u8));
            if i + 1 == MAX_BATCH {
                emitted = r;
            } else {
                assert!(r.is_none());
            }
        }
        let msg = emitted.expect("batch at MAX");
        assert_eq!(msg.shares.len(), MAX_BATCH);
        assert_eq!(msg.job_id, 7);
        assert_eq!(msg.channel_id, 9);
        // After emitting a full batch the group is drained.
        assert!(b.is_empty());
    }

    #[test]
    fn flush_emits_partial() {
        let mut b = RelayBatcher::new(1);
        b.push(relay(7, 0));
        b.push(relay(7, 1));
        let msgs = b.flush_all();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].shares.len(), 2);
        assert!(b.is_empty());
        // A second flush with nothing pending emits nothing.
        assert!(b.flush_all().is_empty());
    }

    #[test]
    fn groups_by_job_id() {
        let mut b = RelayBatcher::new(1);
        b.push(relay(1, 0));
        b.push(relay(2, 1));
        b.push(relay(1, 2));
        let mut msgs = b.flush_all();
        msgs.sort_by_key(|m| m.job_id);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].job_id, 1);
        assert_eq!(msgs[0].shares.len(), 2);
        assert_eq!(msgs[1].job_id, 2);
        assert_eq!(msgs[1].shares.len(), 1);
    }

    #[test]
    fn request_ids_increment() {
        let mut b = RelayBatcher::new(1);
        b.push(relay(1, 0));
        let m1 = &b.flush_all()[0].request_id;
        let r1 = *m1;
        b.push(relay(1, 1));
        let r2 = b.flush_all()[0].request_id;
        assert_eq!(r2, r1 + 1);
    }
}
