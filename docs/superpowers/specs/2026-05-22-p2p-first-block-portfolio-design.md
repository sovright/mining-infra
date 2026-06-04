# P2P First-Block Portfolio Optimizer Design

## Goal

Maximize the probability that at least one Bedrock regional observer sees each new Zcash block before public explorers and before a single-region naive node. The optimizer should treat remote Zcash peers as a portfolio, not as a pure latency race.

## Non-Goals

- Do not submit blocks.
- Do not enable P2P-to-FORGE forwarding.
- Do not open inbound Zcash P2P listeners.
- Do not disconnect a useful duplicate connection only because another observer has lower RTT.
- Do not require a central service in the first implementation slice.

## Design Principle

Lowest RTT is useful, but first-block discovery is the target. A peer with mediocre ping can still be valuable if it announces blocks early because of its topology, miner connectivity, or mempool/peer neighborhood.

The optimizer should prefer peers that repeatedly improve first-seen coverage:

```text
score = block discovery value + reliability - cost
```

Where discovery value is based on first or early block observations, reliability is based on successful handshakes and block responses, and cost is based on errors, stale behavior, and slot pressure.

## Architecture

Extend `bedrock-p2p-ingress` in three layers.

### 1. Local Peer Telemetry

Add a peer score table owned by the ingress process. It tracks one record per remote peer:

- connect attempts
- successful connections
- handshake success
- connect latency in milliseconds
- handshake latency in milliseconds
- optional ping RTT in milliseconds
- block inventory count
- block received count
- `getdata` to `block` latency
- peer errors
- last useful observation time
- rolling score

The peer session should emit structured events for new timing points:

- `p2p_connect_timing`
- `p2p_handshake_timing`
- `p2p_ping_rtt`
- `p2p_peer_score`
- `p2p_peer_rotated`

Existing block events remain the source of truth for real propagation value:

- `p2p_block_inv`
- `p2p_getdata_sent`
- `p2p_block_received`

### 2. Local Portfolio Scheduler

Replace the crawler's FIFO-only scheduling with scored slot allocation.

Each observer divides outbound slots into three buckets:

```text
60 percent proven peers
25 percent contenders
15 percent exploration
```

The percentages should be configurable. Proven peers are peers with useful recent block observations. Contenders are peers with promising timing or successful connection history. Exploration peers come from crawler `addr` gossip.

When a connection slot opens, the scheduler chooses from the highest-priority non-empty bucket. It should avoid rapid reconnect loops using per-peer cooldowns.

### 3. Offline Fleet Scorecard

Extend the existing regional timing collector or add a companion script that reads the deployed observer JSONL logs and computes fleet-wide peer quality:

```text
(observer, remote_peer) -> score
remote_peer -> top observer regions
block_hash -> first observer / first peer / regional spread
```

The scorecard should initially be advisory. It can write snapshots for review and later produce per-observer recommendation files:

```text
prefer: peers this observer should protect
drop: peers this observer can rotate out under slot pressure
explore_budget: slots to keep open for fresh peers
```

## Scoring

Use a rolling score with bounded memory. The first implementation can be simple and transparent:

```text
+100  first observer to receive a block
+50   top 2 observer for a block
+25   top 3 observer for a block
+10   received requested block successfully
+5    saw block inventory
+2    handshake success
-10   connection failure
-20   read timeout after handshake
-30   repeated block request without response
```

Apply small latency modifiers:

```text
+1 to +10 for low connect/handshake/ping latency
-1 to -10 for high latency
```

Latency modifiers should never dominate block discovery value.

Scores decay over time so yesterday's good peer does not permanently occupy a slot:

```text
score = score * decay_factor
```

The decay interval and factor should be configurable.

## Duplicate Peer Policy

For the same remote peer connected by multiple observers, keep a small top-K set instead of a single winner.

Recommended defaults:

```text
top_k_observers_per_peer = 2
minimum_switch_margin = 20 percent
minimum_observations_before_drop = 3 blocks
```

This preserves diversity. If Asia and Europe both connect to a peer, Asia should not automatically win because of lower RTT. The observer that contributes earlier block observations should be protected.

## Data Flow

1. Crawler discovers peers from DNS seeds and `addr` gossip.
2. Scheduler assigns outbound slots across proven, contender, and exploration buckets.
3. Peer tasks report timing and block events.
4. Local score table updates after each event.
5. Low-score peers are rotated out only when slot pressure exists and cooldown rules allow it.
6. Operator-side scorecard joins logs across regions and reports the fleet-wide view.
7. A later implementation can feed scorecard recommendations back into observers.

## Safety

- Keep the service outbound-only.
- Keep hard caps on outbound peers and discovered peer memory.
- Prefer soft rotation over aggressive disconnects.
- Keep exploration slots even when scores look stable.
- Add hysteresis before dropping a peer that recently delivered blocks.
- Avoid central coordinator dependency for the first implementation.

## Implementation Phases

### Phase 1: Measurement

- Add connect and handshake timing events.
- Add optional ping/pong RTT sampling.
- Extend timing summaries to rank `(observer, peer)` contributors.
- Do not change connection behavior.

### Phase 2: Local Scored Scheduling

- Add an in-process peer score table.
- Split slots into proven, contender, and exploration buckets.
- Rotate only failed, stale, or low-score peers.
- Keep existing crawler behavior as the fallback mode.

### Phase 3: Fleet Advisory Scorecard

- Add an operator-side scorecard script.
- Produce per-region recommendations.
- Compare recommended topology against actual first-block results.

### Phase 4: Recommendation Enforcement

- Let observers ingest optional recommendation files.
- Protect recommended peers under slot pressure.
- Drop discouraged peers only after minimum observations and switch margins are met.

## Tests

Unit tests:

- score updates reward first and early block observations
- score decay lowers stale peer priority
- scheduler preserves exploration budget
- scheduler prefers proven peers under slot pressure
- cooldown prevents immediate reconnect churn
- duplicate peer policy keeps top-K observers

Integration-style tests:

- simulated event stream produces expected peer ranking
- scheduler rotates an error-prone peer while keeping a proven peer
- crawler fallback still works when scoring is disabled

## Rollout

Deploy Phase 1 first and compare scorecard output to the live timing snapshots. Only enable local rotation after we can see that the scorecard agrees with observed first-block wins.

Default runtime mode should remain measurement-safe:

```text
BEDROCK_P2P_SCORE_ENABLED=false
BEDROCK_P2P_ROTATION_ENABLED=false
```

Operators can enable scoring without rotation before allowing any connection changes.
