//! Honest senders and small limits. The crate's own encoder builds these, so they show
//! bookkeeping and not agreement with the design: `tests/vectors.rs` is for that.
#![allow(dead_code)]

pub mod bodies;
pub mod segments;
pub mod world;

use std::time::{Duration, Instant};

use chunk_proof::assembler::{Arrival, Assembler, AssemblerLimits, DecodedObject};
use chunk_proof::budget::{Budget, Limits};
use chunk_proof::datagram::{Verifier, seal};
use chunk_proof::object::{Encoded, Profile, encode};

pub const KEY: [u8; 32] = [0x42; 32];
pub const ASSEMBLY_TTL: Duration = Duration::from_secs(30);
pub const REJECTED_TTL: Duration = Duration::from_secs(120);

pub fn max_content(_msg_type: u8) -> usize {
    1 << 20
}

pub fn assembler_limits() -> AssemblerLimits {
    AssemblerLimits {
        max_rejected: 16,
        assembly_ttl: ASSEMBLY_TTL,
        rejected_ttl: REJECTED_TTL,
        max_content,
    }
}

pub fn budget_with(max_objects: usize, max_held_bytes: usize, max_work_bytes: usize) -> Budget {
    Budget::new(Limits {
        max_sessions: 8,
        max_objects,
        max_held_bytes,
        max_work_bytes,
        max_spare_objects: 16,
        max_spare_bytes: 1 << 20,
    })
    .unwrap()
}

pub fn roomy_limits() -> Limits {
    Limits {
        max_sessions: 8,
        max_objects: 16,
        max_held_bytes: 1 << 20,
        max_work_bytes: 1 << 22,
        max_spare_objects: 16,
        max_spare_bytes: 1 << 20,
    }
}

pub fn roomy() -> Budget {
    Budget::new(roomy_limits()).unwrap()
}

/// Every shape: these tests are about what happens to them. The profile has its own.
pub fn verifier() -> Verifier {
    Verifier::new(KEY, Profile::EveryShape)
}

pub fn assembler_on(budget: &Budget) -> Assembler {
    Assembler::new(verifier(), budget.clone(), assembler_limits()).unwrap()
}

pub fn content(fill: u8, len: usize) -> Vec<u8> {
    (0..len).map(|at| fill.wrapping_add(at as u8)).collect()
}

pub fn object(msg_type: u8, n: u16, k: u16, fill: u8, len: usize) -> Encoded {
    encode(msg_type, n, k, &content(fill, len)).expect("a valid shape")
}

pub fn datagram(object: &Encoded, index: usize) -> Vec<u8> {
    seal(
        &KEY,
        &object.shape,
        &object.object_id,
        index as u16,
        &object.proofs[index],
        &object.shards[index],
    )
}

pub fn datagrams(object: &Encoded) -> Vec<Vec<u8>> {
    (0..object.shards.len())
        .map(|index| datagram(object, index))
        .collect()
}

pub fn decoded(arrival: Arrival) -> DecodedObject {
    match arrival {
        Arrival::Decoded(decoded) => decoded,
        other => panic!("expected a decoded object, got {other:?}"),
    }
}

pub fn pending(arrival: Arrival) {
    assert!(
        matches!(arrival, Arrival::Pending { .. }),
        "expected a stored chunk, got {arrival:?}"
    );
}

pub fn later(now: Instant, by: Duration) -> Instant {
    now + by
}
