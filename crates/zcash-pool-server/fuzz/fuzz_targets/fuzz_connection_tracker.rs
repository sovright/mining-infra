#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::SocketAddr;
use std::time::Duration;
use zcash_pool_server::security::ConnectionTracker;

/// Interprets fuzz data as a sequence of connect/disconnect operations
/// on various IP addresses, stress-testing eviction logic and flagging.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Configure tracker with small limits to exercise eviction
    let max_short_lived = (data[0] as usize).max(1).min(20);
    let _max_tracked = (data[1] as usize).max(2).min(50);

    let tracker = ConnectionTracker::new(
        Duration::from_millis(100), // short-lived threshold
        Duration::from_secs(300),   // tracking window
        max_short_lived,
    );
    // Use the public field pattern from tests
    // ConnectionTracker doesn't expose max_tracked_addresses setter,
    // but tests set it directly. Since it's pub(crate), we work with default.
    // Instead, use a small tracking window to exercise cleanup paths.

    let ops = &data[2..];
    let mut i = 0;
    let mut connected: Vec<(SocketAddr, std::time::Instant)> = Vec::new();

    while i < ops.len() {
        let op = ops[i];
        i += 1;

        match op % 4 {
            0 => {
                // Connect: generate an IP from next byte
                if i >= ops.len() {
                    break;
                }
                let ip_byte = ops[i];
                i += 1;
                let addr: SocketAddr =
                    format!("10.0.0.{}:3333", ip_byte).parse().unwrap();
                let instant = tracker.on_connect(addr);
                connected.push((addr, instant));
            }
            1 => {
                // Disconnect the most recent connection
                if let Some((addr, connected_at)) = connected.pop() {
                    let decrypt_error = i < ops.len() && ops[i] % 2 == 0;
                    if i < ops.len() {
                        i += 1;
                    }
                    let _flagged = tracker.on_disconnect(addr, connected_at, decrypt_error);
                }
            }
            2 => {
                // Check if flagged
                if i >= ops.len() {
                    break;
                }
                let ip_byte = ops[i];
                i += 1;
                let addr: SocketAddr =
                    format!("10.0.0.{}:3333", ip_byte).parse().unwrap();
                let _flagged = tracker.is_flagged(&addr);
                let _stats = tracker.get_stats(&addr);
            }
            3 => {
                // Clear flag or cleanup
                if i >= ops.len() {
                    break;
                }
                let ip_byte = ops[i];
                i += 1;
                let addr: SocketAddr =
                    format!("10.0.0.{}:3333", ip_byte).parse().unwrap();
                tracker.clear_flag(&addr);
            }
            _ => unreachable!(),
        }
    }

    // Final cleanup must not panic
    tracker.cleanup(Duration::from_secs(0));
});
