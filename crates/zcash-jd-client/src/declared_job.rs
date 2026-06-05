//! Shared state for the JDC downstream listener.
//!
//! The JD Client declares miner-built templates to the pool and then SERVES
//! those exact declared jobs to local mining hardware (via the SV1→V2
//! translator proxy). [`DeclaredJobState`] is the hand-off point: the JD
//! session loop writes the current declared job here on every
//! `SetCustomMiningJobSuccess`, and the downstream listener reads it to build
//! `NewEquihashJob` frames for the proxy. Because the pool only ever sees the
//! template the JDC declared, it can never substitute a different one.

use std::sync::Arc;
use tokio::sync::{RwLock, watch};

/// A declared job ready to be served to downstream mining hardware.
///
/// Carries exactly the fields needed to (a) build the 140-byte Equihash header
/// for share verification and (b) reassemble the full block for submission to
/// Zebra if a share also meets the block target. The raw `transactions` are the
/// non-coinbase template transactions (raw consensus bytes), captured at
/// declaration time so the block can be reassembled without re-fetching.
#[derive(Debug, Clone)]
pub struct CurrentDeclaredJob {
    /// Job ID assigned by the pool in `SetCustomMiningJobSuccess`.
    pub job_id: u32,
    /// Block version.
    pub version: u32,
    /// Previous block hash (32 bytes).
    pub prev_hash: [u8; 32],
    /// Merkle root of the declared template (32 bytes).
    pub merkle_root: [u8; 32],
    /// `hashBlockCommitments` for NU5+ (32 bytes).
    pub block_commitments: [u8; 32],
    /// Block timestamp.
    pub time: u32,
    /// Compact difficulty target (nBits) — the BLOCK target.
    pub bits: u32,
    /// Pool-granted per-job SHARE target (256-bit, little-endian).
    pub share_target: [u8; 32],
    /// Raw coinbase transaction bytes.
    pub coinbase_tx: Vec<u8>,
    /// Raw non-coinbase transaction bytes, in template order.
    pub transactions: Vec<Vec<u8>>,
}

/// Shared, updatable handle to the current declared job.
///
/// Holds the current job behind an [`RwLock`] plus a [`watch`] channel used to
/// wake downstream listener sessions when the job changes. A `watch` (rather
/// than `Notify`) lets a freshly-connected session observe that *some* job
/// exists without racing a notification: it reads the lock on connect, then
/// awaits `changed()` for subsequent updates.
#[derive(Debug)]
pub struct DeclaredJobState {
    current: RwLock<Option<CurrentDeclaredJob>>,
    tx: watch::Sender<u64>,
}

impl DeclaredJobState {
    /// Create empty shared state wrapped in an `Arc`.
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = watch::channel(0u64);
        Arc::new(Self {
            current: RwLock::new(None),
            tx,
        })
    }

    /// Subscribe to job-update notifications.
    ///
    /// The value is an opaque monotonically-increasing generation counter;
    /// receivers only care that it *changed*.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }

    /// Read a clone of the current declared job, if any.
    pub async fn current(&self) -> Option<CurrentDeclaredJob> {
        self.current.read().await.clone()
    }

    /// Replace the current declared job and wake all subscribers.
    pub async fn set(&self, job: CurrentDeclaredJob) {
        {
            let mut guard = self.current.write().await;
            *guard = Some(job);
        }
        self.bump();
    }

    /// Clear the current declared job (e.g. on JD connection drop) and wake all
    /// subscribers so they stop serving the stale job.
    pub async fn clear(&self) {
        {
            let mut guard = self.current.write().await;
            *guard = None;
        }
        self.bump();
    }

    fn bump(&self) {
        // send_modify always marks the channel changed, even if the counter
        // wraps; subscribers compare-by-change, not by value.
        self.tx
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job(job_id: u32) -> CurrentDeclaredJob {
        CurrentDeclaredJob {
            job_id,
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            time: 1_700_000_000,
            bits: 0x1d00_ffff,
            share_target: [0x11; 32],
            coinbase_tx: vec![0x01, 0x02],
            transactions: vec![vec![0x03], vec![0x04]],
        }
    }

    #[tokio::test]
    async fn starts_empty() {
        let state = DeclaredJobState::new();
        assert!(state.current().await.is_none());
    }

    #[tokio::test]
    async fn set_then_read() {
        let state = DeclaredJobState::new();
        state.set(sample_job(7)).await;
        let job = state.current().await.expect("job present");
        assert_eq!(job.job_id, 7);
    }

    #[tokio::test]
    async fn clear_removes_job() {
        let state = DeclaredJobState::new();
        state.set(sample_job(1)).await;
        state.clear().await;
        assert!(state.current().await.is_none());
    }

    #[tokio::test]
    async fn subscribers_observe_updates() {
        let state = DeclaredJobState::new();
        let mut rx = state.subscribe();
        state.set(sample_job(1)).await;
        // changed() resolves because the generation counter advanced.
        rx.changed().await.expect("watch alive");
        let mut rx2 = state.subscribe();
        state.clear().await;
        rx2.changed().await.expect("watch alive on clear");
    }
}
