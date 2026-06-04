//! Test the harness module

mod harness;

use harness::network::{NetworkConditions, PacketFate, SimulatedNetwork};

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

#[test]
fn network_presets() {
    // Verify all presets are valid
    let _ = NetworkConditions::perfect();
    let _ = NetworkConditions::typical_internet();
    let _ = NetworkConditions::lossy();
    let _ = NetworkConditions::degraded();
    let _ = NetworkConditions::satellite();
}
