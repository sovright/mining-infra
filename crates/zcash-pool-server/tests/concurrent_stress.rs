//! Concurrent stress tests for shared pool types
//!
//! Verifies that PayoutTracker, InMemoryDuplicateDetector, JobDistributor, and Channel
//! behave correctly under heavy concurrent access.

use std::sync::Arc;
use tokio::sync::Barrier;

use zcash_pool_common::PayoutTracker;
use zcash_pool_server::{Channel, DuplicateDetector, InMemoryDuplicateDetector, JobDistributor};

use zcash_equihash_validator::VardiffConfig;
use zcash_mining_protocol::messages::NewEquihashJob;
use zcash_template_provider::types::{BlockTemplate, EquihashHeader, Hash256};

fn make_template(height: u64, prev_hash: [u8; 32]) -> BlockTemplate {
    BlockTemplate {
        template_id: height,
        height,
        header: EquihashHeader {
            version: 5,
            prev_hash: Hash256(prev_hash),
            merkle_root: Hash256([0xaa; 32]),
            hash_block_commitments: Hash256([0xbb; 32]),
            time: 1700000000,
            bits: 0x1d00ffff,
            nonce: [0; 32],
        },
        target: Hash256([0xff; 32]),
        transactions: vec![],
        coinbase: vec![],
        total_fees: 0,
    }
}

fn make_job(channel_id: u32, job_id: u32) -> NewEquihashJob {
    NewEquihashJob {
        channel_id,
        job_id,
        future_job: false,
        version: 5,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        block_commitments: [0; 32],
        nonce_1: vec![0; 4],
        nonce_2_len: 28,
        time: 0,
        bits: 0,
        target: [0xff; 32],
        clean_jobs: false,
    }
}

/// Test 1: 50 tasks each record 1000 shares concurrently for unique miners.
#[tokio::test(flavor = "multi_thread")]
async fn test_payout_tracker_concurrent_writes() {
    let tracker = Arc::new(PayoutTracker::default());
    let barrier = Arc::new(Barrier::new(50));

    let mut handles = Vec::with_capacity(50);
    for i in 0..50 {
        let tracker = Arc::clone(&tracker);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let miner_id = format!("miner_{}", i);
            for _ in 0..1000 {
                tracker.record_share(&miner_id, 1.0);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let all = tracker.get_all_stats();
    assert_eq!(all.len(), 50, "expected 50 unique miners");
    for i in 0..50 {
        let miner_id = format!("miner_{}", i);
        let stats = all.get(&miner_id).unwrap_or_else(|| panic!("missing {}", miner_id));
        assert_eq!(stats.total_shares, 1000, "miner {} total_shares", i);
        assert!(
            (stats.total_difficulty - 1000.0).abs() < f64::EPSILON,
            "miner {} total_difficulty = {}, expected 1000.0",
            i,
            stats.total_difficulty
        );
    }
}

/// Test 2: 100 tasks race to record the same share; exactly 1 must succeed.
#[tokio::test(flavor = "multi_thread")]
async fn test_duplicate_detector_toctou() {
    let detector = Arc::new(InMemoryDuplicateDetector::new());
    let barrier = Arc::new(Barrier::new(100));

    let nonce = vec![0xde, 0xad, 0xbe, 0xef];
    let solution = vec![0xaa; 1344];

    let mut handles = Vec::with_capacity(100);
    for _ in 0..100 {
        let detector = Arc::clone(&detector);
        let barrier = Arc::clone(&barrier);
        let nonce = nonce.clone();
        let solution = solution.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            detector.check_and_record(1, &nonce, &solution)
        }));
    }

    let mut new_count = 0u32;
    let mut dup_count = 0u32;
    for h in handles {
        let is_duplicate: bool = h.await.unwrap();
        if is_duplicate {
            dup_count += 1;
        } else {
            new_count += 1;
        }
    }

    assert_eq!(new_count, 1, "exactly 1 task should see the share as new");
    assert_eq!(dup_count, 99, "99 tasks should see it as duplicate");
}

/// Test 3: 1 writer updates templates while 20 readers query concurrently.
#[tokio::test(flavor = "multi_thread")]
async fn test_job_distributor_concurrent_access() {
    let distributor = Arc::new(tokio::sync::RwLock::new(JobDistributor::new()));
    let barrier = Arc::new(Barrier::new(21)); // 1 writer + 20 readers

    // Writer task: update_template 100 times with different heights
    let writer = {
        let distributor = Arc::clone(&distributor);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            for h in 0..100u64 {
                let mut prev = [0u8; 32];
                prev[0..8].copy_from_slice(&h.to_le_bytes());
                let template = make_template(h, prev);
                let mut dist = distributor.write().await;
                dist.update_template(template);
            }
        })
    };

    // 20 reader tasks
    let mut readers = Vec::with_capacity(20);
    for _ in 0..20 {
        let distributor = Arc::clone(&distributor);
        let barrier = Arc::clone(&barrier);
        readers.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..200 {
                let dist = distributor.read().await;
                let _ = dist.has_template();
                let _ = dist.current_height();
            }
        }));
    }

    writer.await.unwrap();
    for r in readers {
        r.await.unwrap();
    }
}

/// Test 4: 1 writer adds jobs while 1 reader checks job status concurrently.
#[tokio::test(flavor = "multi_thread")]
async fn test_channel_concurrent_job_cleanup() {
    let channel = Arc::new(tokio::sync::RwLock::new(
        Channel::new(vec![0; 4], VardiffConfig::default()).unwrap(),
    ));

    let barrier = Arc::new(Barrier::new(2));

    // Writer: add 100 jobs with clean_jobs=true
    let writer = {
        let channel = Arc::clone(&channel);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            for job_id in 1..=100u32 {
                let mut ch = channel.write().await;
                let job = make_job(ch.id, job_id);
                ch.add_job(job, true);
            }
        })
    };

    // Reader: check is_job_active in a loop
    let reader = {
        let channel = Arc::clone(&channel);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            for job_id in 1..=100u32 {
                let ch = channel.read().await;
                let _ = ch.is_job_active(job_id);
            }
        })
    };

    writer.await.unwrap();
    reader.await.unwrap();
}
