//! Network simulation for chaos testing

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::atomic::{AtomicU64, Ordering};

/// Network conditions for simulation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NetworkConditions {
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss: f64,
    /// Additional latency in milliseconds
    pub latency_ms: u64,
    /// Latency jitter in milliseconds
    pub jitter_ms: u64,
    /// Bandwidth limit in bytes per second (0 = unlimited)
    pub bandwidth_bps: u64,
    /// Whether to reorder packets
    pub reorder: bool,
    /// Duplicate packet rate (0.0 - 1.0)
    pub duplicate_rate: f64,
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self {
            packet_loss: 0.0,
            latency_ms: 0,
            jitter_ms: 0,
            bandwidth_bps: 0,
            reorder: false,
            duplicate_rate: 0.0,
        }
    }
}

#[allow(dead_code)]
impl NetworkConditions {
    /// Perfect network - no loss, no latency
    pub fn perfect() -> Self {
        Self::default()
    }

    /// Typical internet conditions
    pub fn typical_internet() -> Self {
        Self {
            packet_loss: 0.001, // 0.1% loss
            latency_ms: 50,
            jitter_ms: 10,
            bandwidth_bps: 100_000_000, // 100 Mbps
            reorder: false,
            duplicate_rate: 0.0,
        }
    }

    /// Lossy network for stress testing
    pub fn lossy() -> Self {
        Self {
            packet_loss: 0.05, // 5% loss
            latency_ms: 100,
            jitter_ms: 50,
            bandwidth_bps: 10_000_000, // 10 Mbps
            reorder: true,
            duplicate_rate: 0.001,
        }
    }

    /// Severely degraded network
    pub fn degraded() -> Self {
        Self {
            packet_loss: 0.15, // 15% loss
            latency_ms: 200,
            jitter_ms: 100,
            bandwidth_bps: 1_000_000, // 1 Mbps
            reorder: true,
            duplicate_rate: 0.01,
        }
    }

    /// Satellite-like conditions
    pub fn satellite() -> Self {
        Self {
            packet_loss: 0.02,
            latency_ms: 600, // High latency
            jitter_ms: 50,
            bandwidth_bps: 50_000_000,
            reorder: false,
            duplicate_rate: 0.0,
        }
    }
}

/// What happens to a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFate {
    /// Packet delivered normally
    Delivered,
    /// Packet lost
    Lost,
    /// Packet duplicated
    Duplicated,
}

/// Simulated network for testing
pub struct SimulatedNetwork {
    conditions: NetworkConditions,
    rng: std::sync::Mutex<StdRng>,
    packets_sent: AtomicU64,
    packets_lost: AtomicU64,
    packets_delivered: AtomicU64,
    packets_duplicated: AtomicU64,
}

#[allow(dead_code)]
impl SimulatedNetwork {
    /// Create a new simulated network
    pub fn new(conditions: NetworkConditions) -> Self {
        Self {
            conditions,
            rng: std::sync::Mutex::new(StdRng::seed_from_u64(42)),
            packets_sent: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            packets_delivered: AtomicU64::new(0),
            packets_duplicated: AtomicU64::new(0),
        }
    }

    /// Create with specific seed for reproducibility
    pub fn with_seed(conditions: NetworkConditions, seed: u64) -> Self {
        Self {
            conditions,
            rng: std::sync::Mutex::new(StdRng::seed_from_u64(seed)),
            packets_sent: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            packets_delivered: AtomicU64::new(0),
            packets_duplicated: AtomicU64::new(0),
        }
    }

    /// Determine the fate of a packet
    pub fn process_packet(&self) -> PacketFate {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);

        let mut rng = self.rng.lock().unwrap();
        let roll: f64 = rng.r#gen();

        if roll < self.conditions.packet_loss {
            self.packets_lost.fetch_add(1, Ordering::Relaxed);
            PacketFate::Lost
        } else if roll < self.conditions.packet_loss + self.conditions.duplicate_rate {
            self.packets_duplicated.fetch_add(1, Ordering::Relaxed);
            self.packets_delivered.fetch_add(2, Ordering::Relaxed);
            PacketFate::Duplicated
        } else {
            self.packets_delivered.fetch_add(1, Ordering::Relaxed);
            PacketFate::Delivered
        }
    }

    /// Get simulated latency for this packet in milliseconds
    pub fn get_latency_ms(&self) -> u64 {
        if self.conditions.jitter_ms == 0 {
            return self.conditions.latency_ms;
        }

        let mut rng = self.rng.lock().unwrap();
        let jitter: i64 =
            rng.gen_range(-(self.conditions.jitter_ms as i64)..=(self.conditions.jitter_ms as i64));
        (self.conditions.latency_ms as i64 + jitter).max(0) as u64
    }

    /// Get statistics
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_lost: self.packets_lost.load(Ordering::Relaxed),
            packets_delivered: self.packets_delivered.load(Ordering::Relaxed),
            packets_duplicated: self.packets_duplicated.load(Ordering::Relaxed),
        }
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_lost.store(0, Ordering::Relaxed);
        self.packets_delivered.store(0, Ordering::Relaxed);
        self.packets_duplicated.store(0, Ordering::Relaxed);
    }

    /// Get the conditions
    pub fn conditions(&self) -> &NetworkConditions {
        &self.conditions
    }
}

/// Network statistics
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub packets_delivered: u64,
    pub packets_duplicated: u64,
}

#[allow(dead_code)]
impl NetworkStats {
    /// Calculate actual loss rate
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_network_no_loss() {
        let net = SimulatedNetwork::new(NetworkConditions::perfect());

        for _ in 0..1000 {
            assert_eq!(net.process_packet(), PacketFate::Delivered);
        }

        let stats = net.stats();
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.packets_delivered, 1000);
    }

    #[test]
    fn lossy_network_drops_packets() {
        let net = SimulatedNetwork::with_seed(NetworkConditions::lossy(), 12345);

        for _ in 0..10000 {
            let _ = net.process_packet();
        }

        let stats = net.stats();
        // With 5% loss, expect roughly 500 lost packets (allow variance)
        assert!(stats.packets_lost > 300, "Expected some packet loss");
        assert!(stats.packets_lost < 800, "Loss rate too high");
    }

    #[test]
    fn latency_with_jitter() {
        let net = SimulatedNetwork::new(NetworkConditions {
            latency_ms: 100,
            jitter_ms: 20,
            ..Default::default()
        });

        let mut latencies = Vec::new();
        for _ in 0..100 {
            latencies.push(net.get_latency_ms());
        }

        // Check we get variety
        let min = *latencies.iter().min().unwrap();
        let max = *latencies.iter().max().unwrap();
        assert!(min >= 80, "Latency too low");
        assert!(max <= 120, "Latency too high");
        assert!(max > min, "No jitter observed");
    }
}
