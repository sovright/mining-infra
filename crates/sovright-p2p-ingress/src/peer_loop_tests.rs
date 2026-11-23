//! When the legacy peer loop exits, drains or keeps waiting (`peer_loop_step`).

use crate::{PeerLoopStep, peer_loop_step};

#[test]
fn exits_when_nothing_runs_and_nothing_is_queued() {
    assert_eq!(peer_loop_step(0, 0, false), PeerLoopStep::Exhausted);
    assert_eq!(peer_loop_step(0, 0, true), PeerLoopStep::Exhausted);
}

#[test]
fn waits_for_running_peers_when_the_static_queue_is_empty() {
    assert_eq!(peer_loop_step(1, 0, false), PeerLoopStep::DrainRunning);
}

#[test]
fn retries_a_requeued_static_peer_instead_of_exiting() {
    // Crawler off, the only peer dropped and rotation requeued it.
    assert_eq!(peer_loop_step(0, 1, false), PeerLoopStep::Wait);
}

#[test]
fn keeps_filling_slots_while_peers_are_queued() {
    assert_eq!(peer_loop_step(1, 2, false), PeerLoopStep::Wait);
    assert_eq!(peer_loop_step(0, 3, true), PeerLoopStep::Wait);
    assert_eq!(peer_loop_step(2, 0, true), PeerLoopStep::Wait);
}
