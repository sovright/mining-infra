//! Per-source rate limiting for unauthenticated relay traffic.
//!
//! Authenticating an unknown source costs one HMAC-SHA256 verification per
//! configured key, because the relay must trial-verify the packet against
//! every active key to discover which one (if any) it belongs to. With the
//! relay exposed to the public internet that is a free CPU burn for anyone
//! who can send UDP, and it scales with the number of invitees.
//!
//! This limiter caps how often a given source address may pay that cost.
//! It is applied ONLY on the no-existing-session path; an established
//! session is a cheap map lookup plus a single HMAC and is never limited,
//! so a legitimate peer is unaffected once it has authenticated.
//!
//! # Bounded by construction
//!
//! A naive per-IP map is itself a memory-exhaustion vector: an attacker
//! spraying spoofed source addresses would grow it without limit. Instead
//! this uses a fixed-size table of token buckets and hashes the source IP to
//! a slot. Memory is constant regardless of how many distinct sources are
//! seen. Colliding IPs share a bucket, which can only ever make the limit
//! stricter, never more permissive -- a safe direction to fail.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of token buckets. Fixed, so memory does not grow with traffic.
const SLOTS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Slot {
    tokens: f64,
    last_refill: Instant,
}

/// Fixed-memory, per-source token-bucket limiter for unauthenticated packets.
#[derive(Debug)]
pub struct UnauthRateLimiter {
    /// Sustained refill rate, tokens (packets) per second. Zero disables.
    rate_per_sec: f64,
    /// Maximum tokens a bucket can hold, i.e. the allowed instantaneous burst.
    burst: f64,
    slots: Mutex<Box<[Slot]>>,
}

impl UnauthRateLimiter {
    /// Create a limiter allowing `rate_per_sec` sustained unauthenticated
    /// packets per source with an instantaneous burst of `burst`.
    ///
    /// A `rate_per_sec` of zero disables limiting entirely.
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        let now = Instant::now();
        let slots = vec![
            Slot {
                tokens: burst,
                last_refill: now,
            };
            SLOTS
        ]
        .into_boxed_slice();
        Self {
            rate_per_sec,
            burst,
            slots: Mutex::new(slots),
        }
    }

    /// Whether limiting is active.
    pub fn is_enabled(&self) -> bool {
        self.rate_per_sec > 0.0
    }

    /// Consume one token for `ip`, returning whether the packet is allowed.
    ///
    /// Returns `true` unconditionally when limiting is disabled.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Testable form of [`UnauthRateLimiter::allow`] with an explicit clock.
    pub fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.is_enabled() {
            return true;
        }

        let index = Self::slot_for(ip);
        let mut slots = self
            .slots
            .lock()
            .expect("unauth rate limiter mutex poisoned");
        let slot = &mut slots[index];

        // Refill. `saturating_duration_since` keeps this monotonic-safe.
        let elapsed = now.saturating_duration_since(slot.last_refill);
        if elapsed > Duration::ZERO {
            slot.tokens = (slot.tokens + elapsed.as_secs_f64() * self.rate_per_sec).min(self.burst);
            slot.last_refill = now;
        }

        if slot.tokens >= 1.0 {
            slot.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn slot_for(ip: IpAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % SLOTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_up_to_the_burst_then_denies() {
        let limiter = UnauthRateLimiter::new(10.0, 5.0);
        let now = Instant::now();
        let peer = ip("203.0.113.7");

        for i in 0..5 {
            assert!(
                limiter.allow_at(peer, now),
                "packet {i} within burst must be allowed"
            );
        }
        assert!(
            !limiter.allow_at(peer, now),
            "packet past the burst must be denied"
        );
    }

    #[test]
    fn refills_over_time() {
        let limiter = UnauthRateLimiter::new(10.0, 5.0);
        let now = Instant::now();
        let peer = ip("203.0.113.7");

        for _ in 0..5 {
            assert!(limiter.allow_at(peer, now));
        }
        assert!(!limiter.allow_at(peer, now));

        // 10 tokens/sec => 300ms buys 3 tokens.
        let later = now + Duration::from_millis(300);
        for i in 0..3 {
            assert!(limiter.allow_at(peer, later), "refilled token {i}");
        }
        assert!(!limiter.allow_at(peer, later), "only 3 tokens were refilled");
    }

    #[test]
    fn refill_is_capped_at_the_burst() {
        let limiter = UnauthRateLimiter::new(10.0, 5.0);
        let now = Instant::now();
        let peer = ip("203.0.113.7");

        // Idle for a long time; the bucket must not exceed `burst`.
        let later = now + Duration::from_secs(3600);
        for i in 0..5 {
            assert!(limiter.allow_at(peer, later), "burst token {i}");
        }
        assert!(
            !limiter.allow_at(peer, later),
            "a long idle period must not accumulate more than the burst"
        );
    }

    #[test]
    fn one_flooding_source_does_not_starve_another() {
        let limiter = UnauthRateLimiter::new(10.0, 5.0);
        let now = Instant::now();
        let flooder = ip("203.0.113.7");
        let victim = ip("198.51.100.20");

        // Flooder exhausts its own bucket.
        for _ in 0..50 {
            let _ = limiter.allow_at(flooder, now);
        }
        assert!(!limiter.allow_at(flooder, now));

        // A different source is unaffected (barring a slot collision, which
        // these two fixed addresses do not have).
        assert!(
            limiter.allow_at(victim, now),
            "an unrelated source must still be admitted"
        );
    }

    #[test]
    fn zero_rate_disables_limiting() {
        let limiter = UnauthRateLimiter::new(0.0, 0.0);
        let now = Instant::now();
        let peer = ip("203.0.113.7");

        assert!(!limiter.is_enabled());
        for i in 0..10_000 {
            assert!(limiter.allow_at(peer, now), "packet {i} must be allowed");
        }
    }

    #[test]
    fn ipv6_sources_are_limited_too() {
        let limiter = UnauthRateLimiter::new(10.0, 2.0);
        let now = Instant::now();
        let peer = ip("2001:db8::1");

        assert!(limiter.allow_at(peer, now));
        assert!(limiter.allow_at(peer, now));
        assert!(!limiter.allow_at(peer, now));
    }

    #[test]
    fn memory_is_constant_across_many_distinct_sources() {
        let limiter = UnauthRateLimiter::new(10.0, 1.0);
        let now = Instant::now();
        // Spray many distinct sources; the table must not grow.
        for i in 0..50_000u32 {
            let octets = i.to_be_bytes();
            let addr = IpAddr::from([octets[0], octets[1], octets[2], octets[3]]);
            let _ = limiter.allow_at(addr, now);
        }
        let slots = limiter.slots.lock().unwrap();
        assert_eq!(slots.len(), SLOTS, "slot table must be fixed size");
    }
}
