# Stratum V2 Security Analysis for Zcash

This document analyzes known attacks against the Stratum V2 mining protocol and evaluates the exposure of this Zcash implementation to each attack vector.

## Overview

Stratum V2 was designed to address significant security weaknesses in Stratum V1, including lack of encryption and vulnerability to man-in-the-middle attacks. However, academic research has identified several attack vectors that remain relevant even with V2's improvements.

This analysis covers:
1. Network-level routing attacks (EROSION)
2. Privacy attacks (StraTap, ISP Log)
3. Hash hijacking attacks (BiteCoin)
4. Noise protocol cryptographic considerations
5. Template manipulation attacks
6. Resource exhaustion attacks

## Attack Analysis

### 1. EROSION Attack (Network Routing Attack)

**Source:** [Routing Attacks on Cryptocurrency Mining Pools](https://muoitran.com/publications/erosion.pdf) - ETH Zurich, 2024

**Attack Description:**

The EROSION attack exploits BGP (Border Gateway Protocol) hijacking to intercept traffic between miners and pools. Researchers discovered that:

- An adversary can use BGP hijacking to intercept mining pool traffic
- By tampering with a single encrypted packet, the attacker can persistently disrupt connections
- The Stratum V2 cryptography specification had a vulnerability allowing stealthier attacks
- 91% of mining pools across top cryptocurrencies are vulnerable to this attack class
- One malicious Autonomous System could theoretically take down 96% of Bitcoin mining power

**This Implementation's Exposure: PARTIALLY VULNERABLE**

**Code Analysis:**

In `crates/sovright-noise/src/transport.rs`, decryption failures return an error:

```rust
transport
    .read_message(&ciphertext, &mut plaintext)
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
```

In `crates/zcash-pool-server/src/session.rs`, read errors terminate the session:

```rust
Err(e) => {
    error!("Read error for channel {}: {}", channel_id, e);
    break;
}
```

**Impact:**

An attacker who intercepts traffic and corrupts a single encrypted packet will cause:
1. Decryption failure in the Noise layer
2. Session termination
3. Miner disconnection

The miner must then reconnect, losing any work in progress. Sustained attacks could significantly degrade pool hashrate.

**Mitigation Status:**

The official SV2 reference implementation patched this by implementing automatic reconnection on decryption failures (December 2023). This implementation terminates on failure but does not implement automatic reconnection with backoff.

**Recommendations:**

1. Implement automatic reconnection with exponential backoff
2. Add detection for repeated short-lived connections (potential attack indicator)
3. Log decryption failure patterns for monitoring
4. Consider multi-AS deployment for the pool infrastructure

---

### 2. StraTap and ISP Log Attacks (Privacy Attacks)

**Source:** [Hardening Stratum, the Bitcoin Pool Mining Protocol](https://arxiv.org/abs/1703.06545) - 2017

**Attack Description:**

- **StraTap:** Passively infers miner earnings by analyzing Stratum communications
- **ISP Log Attack:** Reconstructs miner earnings from packet timestamps alone, even without payload access

These attacks compromise financial privacy of mining operations, potentially enabling:
- Competitive intelligence gathering
- Targeted attacks on profitable miners
- Tax/regulatory surveillance

**This Implementation's Exposure: PROTECTED (when Noise enabled)**

**Code Analysis:**

The implementation supports both encrypted and plaintext modes in `crates/zcash-pool-server/src/session.rs`:

```rust
pub enum Transport {
    Plain(TcpStream),
    Noise(NoiseStream<TcpStream>),
}
```

When `noise_enabled=true` in configuration, all traffic uses Noise_NK encryption (`server.rs:270-287`).

**Residual Risks:**

| Risk | Severity | Notes |
|------|----------|-------|
| Plain mode exposure | High | All share data visible if Noise disabled |
| Timing analysis | Medium | Share acceptance/rejection patterns leak timing information |
| Traffic analysis | Low | Message sizes may reveal share submission patterns |

**Recommendations:**

1. Consider removing plain mode or requiring explicit opt-in with warnings
2. Add random delays to share responses to mitigate timing attacks
3. Document that Noise should always be enabled in production

---

### 3. BiteCoin Attack (Hash Hijacking)

**Source:** [Hardening Stratum](https://arxiv.org/abs/1703.06545)

**Attack Description:**

An active man-in-the-middle attack that:
1. Intercepts shares submitted by miners
2. Claims the shares and associated payouts for the attacker
3. Uses the "WireGhost" technique to surreptitiously maintain Stratum connections

This directly steals mining revenue from victims.

**This Implementation's Exposure: PROTECTED (when Noise enabled)**

**Code Analysis:**

The Noise_NK pattern provides server authentication in `crates/sovright-noise/src/handshake.rs`:

```rust
let mut handshake = builder
    .remote_public_key(self.server_public_key.as_bytes())
    .build_initiator()
    .map_err(HandshakeError::Snow)?;
```

Key protections:
- Miners must know the pool's public key out-of-band (prevents impersonation)
- AEAD encryption prevents tampering with messages in transit
- Handshake establishes session keys that only legitimate parties possess

**Residual Risks:**

| Risk | Severity | Notes |
|------|----------|-------|
| Plain mode | Critical | No protection against hash hijacking without Noise |
| No miner authentication | Medium | Pool authenticates to miners, but miners don't authenticate to pool |
| Public key distribution | Medium | Miners must securely obtain pool's public key |

**Recommendations:**

1. Mandatory Noise encryption for production deployments
2. Publish pool public key via multiple channels (website, DNS TXT, signed announcements)
3. Consider adding miner authentication for premium/trusted miner tiers

---

### 4. Noise NK Protocol Cryptographic Considerations

**Source:** [Noise Explorer - NK Pattern](https://noiseexplorer.com/patterns/NK/)

**Pattern Description:**

Noise_NK means:
- **N**: Initiator (miner) has no static key
- **K**: Responder's (pool) static key is known to initiator

This provides:
- Server authentication (miner verifies pool identity)
- Forward secrecy (with caveats)
- Encrypted communications

**Known Limitations:**

| Vulnerability | Impact | This Implementation |
|---------------|--------|---------------------|
| **Replay attacks** | Attacker could replay messages | No application-layer replay protection |
| **Key Compromise Impersonation (KCI)** | If pool key compromised, attacker can impersonate miners | Vulnerable |
| **Limited forward secrecy** | Pool key compromise decrypts past traffic | Vulnerable |
| **No sender authentication** | First message has no sender identity proof | By design (anonymous miners) |

**Code Analysis:**

In `crates/sovright-noise/src/transport.rs`, messages are processed without sequence validation:

```rust
pub async fn read_message(&mut self) -> io::Result<Vec<u8>> {
    let len = self.inner.read_u16().await? as usize;
    // ... decrypt and return
    // No sequence number or timestamp validation
}
```

**Recommendations:**

1. Add application-layer sequence numbers to detect replayed messages
2. Implement message timestamps with reasonable clock skew tolerance
3. Document key rotation procedures (periodic pool key regeneration)
4. Consider upgrading to NK1 or XX patterns for mutual authentication in future versions

---

### 5. Template Manipulation Attacks (Job Declaration)

**Attack Description:**

Miners using Job Declaration could attempt to:
- Submit templates with invalid transactions
- Include transactions that don't pay the pool
- Build on stale chain tips
- Exhaust server resources with rapid job declarations

**This Implementation's Exposure: WELL PROTECTED**

**Code Analysis:**

The JD Server in `crates/zcash-jd-server/src/server.rs` implements multiple layers of protection:

**Token Validation (lines 159-194):**
```rust
match self.token_manager.validate_token(&request.mining_job_token) {
    Ok(_) => {}
    Err(JdServerError::InvalidToken) => { /* reject */ }
    Err(JdServerError::TokenExpired) => { /* reject */ }
}
```

**Stale Prevention (lines 197-214):**
```rust
if let Some(expected_prev_hash) = *current_prev_hash {
    if request.prev_hash != expected_prev_hash {
        return Err(SetCustomMiningJobError::new(
            // StalePrevHash error
        ));
    }
}
```

**Mode Enforcement (lines 371-381):**
```rust
if token_info.granted_mode != JobDeclarationMode::FullTemplate {
    return Err(/* ModeMismatch */);
}
```

**Template Validation (lines 404-436):**
- Validates transaction structure
- Verifies merkle root computation
- Checks pool payout requirements

**Resource Limits:**

| Limit | Value | Location |
|-------|-------|----------|
| Frame size | 1 MB | `server.rs:604` |
| Shares per job | 100,000 | `duplicate.rs:12` |
| Buffer size | 64 KB | `session.rs:195` |
| Jobs per channel | 10 | `channel.rs:146` |

---

### 6. Resource Exhaustion Attacks

**Attack Description:**

Attackers could attempt to exhaust pool resources by:
- Flooding with duplicate shares
- Submitting shares faster than validation can process
- Creating many connections
- Sending oversized messages

**This Implementation's Exposure: PROTECTED**

**Code Analysis:**

**Rate Limiting (`channel.rs:184-189`):**
```rust
pub fn check_rate_limit(&mut self) -> bool {
    self.rate_limiter.check().is_allowed()
}
```

Applied before validation in `server.rs:630-644`:
```rust
if !channel.check_rate_limit() {
    debug!("Rate limiting channel {}", channel_id);
    return /* rejection */;
}
```

**Duplicate Detection (`duplicate.rs`):**
```rust
const MAX_SHARES_PER_JOB: usize = 100_000;

fn check_and_record(&self, job_id: u32, nonce_2: &[u8], solution: &[u8]) -> bool {
    if shares.len() >= MAX_SHARES_PER_JOB {
        return true; // Reject as duplicate
    }
    !shares.insert(hash)
}
```

**Connection Limits (`server.rs:261-265`):**
```rust
if current_connections >= self.config.max_connections {
    warn!("Connection limit reached, rejecting {}", addr);
    continue;
}
```

**Message Size Limits:**
- Frame header validation before reading payload
- Maximum frame size enforced at protocol layer

---

## Summary Matrix

| Attack | Severity | Exposure | Primary Mitigation |
|--------|----------|----------|-------------------|
| EROSION (BGP hijack) | High | Partial | Reconnection logic needed |
| StraTap/ISP Log | Medium | Low* | Noise encryption |
| BiteCoin (hash hijack) | Critical | Low* | Noise encryption |
| Noise NK weaknesses | Medium | Partial | Application-layer protection |
| Template manipulation | High | Low | Token/validation controls |
| Resource exhaustion | Medium | Low | Rate limiting, size limits |

*With Noise encryption enabled

---

## Configuration Recommendations

### Production Security Checklist

```toml
# pool-config.toml

# REQUIRED: Enable Noise encryption
noise_enabled = true

# REQUIRED: Use persistent key (don't regenerate on restart)
noise_private_key_path = "/secure/path/pool_noise_key.hex"

# RECOMMENDED: Enable JD Noise as well
jd_noise_enabled = true

# RECOMMENDED: Strict connection limits
max_connections = 10000

# RECOMMENDED: Enable metrics for monitoring
metrics_addr = "127.0.0.1:9090"
```

### Operational Security

1. **Key Management:**
   - Generate pool Noise key securely: `openssl rand -hex 32 > pool_noise_key.hex`
   - Store key with restricted permissions: `chmod 600 pool_noise_key.hex`
   - Publish public key via authenticated channels
   - Plan for key rotation (annual or after suspected compromise)

2. **Network Architecture:**
   - Deploy pool servers across multiple Autonomous Systems (AS)
   - Use anycast for geographic distribution
   - Implement DDoS protection at network edge
   - Monitor BGP announcements for your IP prefixes

3. **Monitoring:**
   - Alert on unusual disconnection rates
   - Track share rejection rates per miner
   - Monitor for repeated short-lived connections
   - Log Noise handshake failures

---

## Future Work

1. **Automatic Reconnection:** Implement reconnection with exponential backoff to mitigate EROSION
2. **Sequence Numbers:** Add application-layer replay protection
3. **Mutual Authentication:** Consider optional miner authentication for trusted pools
4. **Audit:** Commission formal security audit before mainnet deployment

---

## References

1. Tran, M., von Arx, T., Vanbever, L. (2024). "Routing Attacks on Cryptocurrency Mining Pools." IEEE S&P.
   https://muoitran.com/publications/erosion.pdf

2. Recabarren, R., Carbunar, B. (2017). "Hardening Stratum, the Bitcoin Pool Mining Protocol."
   https://arxiv.org/abs/1703.06545

3. Perrin, T. "The Noise Protocol Framework."
   https://noiseprotocol.org/noise.html

4. Symbolic Analysis of Noise NK Pattern.
   https://noiseexplorer.com/patterns/NK/

5. Stratum V2 Specification.
   https://github.com/stratum-mining/sv2-spec

6. Secureworks. "BGP Hijacking for Cryptocurrency Profit."
   https://www.secureworks.com/research/bgp-hijacking-for-cryptocurrency-profit

---

*Document created: 2026-01-29*
*Last updated: 2026-01-29*
