//! Human-facing status output: startup banner, connection/mining-started
//! notices, and the live stats panel.
//!
//! The formatting functions are pure (they return `String`) so they can be unit
//! tested without a terminal. Callers print the returned strings. The
//! [`run_stats_renderer`] task owns the only terminal I/O and timing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::metrics::{MetricsSnapshot, MinerMetrics, sol_per_sec};

// ANSI style codes.
const BOLD: &str = "1";
const DIM: &str = "2";
const CYAN: &str = "36";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const RED: &str = "31";

/// Wrap `s` in an ANSI SGR sequence when `color` is enabled, otherwise return
/// it unchanged.
pub fn style(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Lowercase hex encoding (avoids pulling in the `hex` crate here).
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// Render a 32-byte little-endian target as big-endian hex with leading zero
/// bytes trimmed (keeping at least one byte). This is how miners conventionally
/// eyeball a target/difficulty.
pub fn target_hex_be(target: &[u8; 32]) -> String {
    let be: Vec<u8> = target.iter().rev().copied().collect();
    let first_nonzero = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    to_hex(&be[first_nonzero..])
}

/// Count leading zero bits of a little-endian 256-bit target (MSB at index 31).
/// A higher count means a harder share target, so this serves as an honest,
/// monotonic difficulty proxy without needing a diff-1 reference.
pub fn target_leading_zero_bits(target: &[u8; 32]) -> u32 {
    let mut count = 0;
    for i in (0..32).rev() {
        let b = target[i];
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Format a duration compactly, e.g. `45s`, `3m04s`, `1h02m03s`.
pub fn fmt_duration(d: Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// Configuration summary shown once at launch.
pub struct StartupInfo<'a> {
    pub version: &'a str,
    pub mode: &'a str,
    pub pool_addr: &'a str,
    pub workers: u32,
    pub solver_threads: u32,
    /// `Some(short_key)` when Noise is enabled, `None` for plaintext.
    pub encryption: Option<String>,
}

/// The details that become available the moment a worker starts mining (i.e.
/// when its first job lands).
pub struct MiningStarted<'a> {
    pub worker: &'a str,
    /// Present for Stratum V2; `None` for V1 (which has no channel id).
    pub channel_id: Option<u32>,
    pub nonce_1_hex: String,
    pub nonce_2_len: usize,
    pub share_target: [u8; 32],
    pub bits: u32,
    pub clean: bool,
}

/// Multi-line launch banner.
pub fn startup_banner(info: &StartupInfo, color: bool) -> String {
    let title = style(&format!("zcash-test-miner v{}", info.version), BOLD, color);
    let enc = match &info.encryption {
        Some(k) => format!("Noise_NK ({k})"),
        None => "disabled (plaintext)".to_string(),
    };
    let label = |s: &str| style(s, DIM, color);
    format!(
        "\n{title}\n  {l_mode} {mode}\n  {l_pool} {pool}\n  {l_workers} {workers}\n  {l_threads} {threads}\n  {l_enc} {enc}\n",
        l_mode = label("mode:        "),
        mode = info.mode,
        l_pool = label("pool:        "),
        pool = info.pool_addr,
        l_workers = label("workers:     "),
        workers = info.workers,
        l_threads = label("solver/thrd: "),
        threads = info.solver_threads,
        l_enc = label("encryption:  "),
        enc = enc,
    )
}

/// One-line "connected" notice printed after the transport handshake and
/// identity exchange, before any job has arrived.
pub fn connected(worker: &str, encrypted: bool, color: bool) -> String {
    let check = style("\u{2713}", GREEN, color);
    let transport = if encrypted { "Noise_NK" } else { "plaintext" };
    format!(
        "{check} {} connected to pool ({})",
        style(worker, BOLD, color),
        transport
    )
}

/// Multi-field "mining started" notice printed when a worker's first job lands.
pub fn mining_started(info: &MiningStarted, color: bool) -> String {
    let header = style(
        &format!("\u{25b6} {} mining started", info.worker),
        BOLD,
        color,
    );
    let chan = match info.channel_id {
        Some(c) => format!("channel {c}"),
        None => "channel n/a (V1)".to_string(),
    };
    let diff_bits = target_leading_zero_bits(&info.share_target);
    let label = |s: &str| style(s, DIM, color);
    format!(
        "{header}\n  {l_chan} {chan}\n  {l_nonce} {n1} (nonce-1, {n1len}B) + {n2len}B nonce-2\n  {l_target} {tgt} (\u{2248}{diff_bits} leading zero bits)\n  {l_bits} {bits:#010x}\n  {l_clean} {clean}",
        l_chan = label("channel:  "),
        chan = chan,
        l_nonce = label("nonce:    "),
        n1 = info.nonce_1_hex,
        n1len = info.nonce_1_hex.len() / 2,
        n2len = info.nonce_2_len,
        l_target = label("target:   "),
        tgt = target_hex_be(&info.share_target),
        diff_bits = diff_bits,
        l_bits = label("net bits: "),
        bits = info.bits,
        l_clean = label("clean:    "),
        clean = info.clean,
    )
}

/// Multi-line live stats panel. Always ends with a trailing newline so the
/// in-place TTY redraw can count lines consistently.
pub fn stats_block(
    snap: &MetricsSnapshot,
    uptime: Duration,
    sol_per_s: f64,
    color: bool,
) -> String {
    let title = style("\u{2500}\u{2500} miner stats \u{2500}\u{2500}", CYAN, color);
    let label = |s: &str| style(s, DIM, color);
    let accepted = style(&snap.shares_accepted.to_string(), GREEN, color);
    let rejected = if snap.shares_rejected > 0 {
        style(&snap.shares_rejected.to_string(), RED, color)
    } else {
        snap.shares_rejected.to_string()
    };
    let blocks = if snap.blocks_found > 0 {
        style(&snap.blocks_found.to_string(), YELLOW, color)
    } else {
        snap.blocks_found.to_string()
    };
    format!(
        "{title}\n  {l_up} {up}\n  {l_rate} {rate:.3} Sol/s\n  {l_conn} {conn}\n  {l_shares} {submitted} submitted / {accepted} accepted / {rejected} rejected\n  {l_blocks} {blocks}\n",
        l_up = label("uptime:   "),
        up = fmt_duration(uptime),
        l_rate = label("hashrate: "),
        rate = sol_per_s,
        l_conn = label("workers:  "),
        conn = snap.connected_workers,
        l_shares = label("shares:   "),
        submitted = snap.shares_submitted,
        accepted = accepted,
        rejected = rejected,
        l_blocks = label("blocks:   "),
        blocks = blocks,
    )
}

/// Background task that periodically samples [`MinerMetrics`] and renders the
/// live stats panel until shutdown.
///
/// In TTY mode the panel is redrawn in place (cursor moved up over the previous
/// render). When piped/non-TTY it is reprinted as a fresh block each tick and
/// color is suppressed by the caller.
pub async fn run_stats_renderer(
    metrics: Arc<MinerMetrics>,
    interval: Duration,
    color: bool,
    tty: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    use std::io::Write;

    let start = Instant::now();
    let mut last = Instant::now();
    let mut last_attempts: u64 = 0;
    let mut prev_lines: usize = 0;

    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; consume it so the first render happens
    // one full interval in (by which point there is something to show).
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = Instant::now();
                let secs = now.duration_since(last).as_secs_f64();
                let snap = metrics.snapshot();
                let delta = snap.nonces_attempted.saturating_sub(last_attempts);
                let rate = sol_per_sec(delta, secs);
                last = now;
                last_attempts = snap.nonces_attempted;

                let panel = stats_block(&snap, now.duration_since(start), rate, color);

                if tty {
                    let mut out = String::new();
                    if prev_lines > 0 {
                        // Move cursor to the start of the previous panel and
                        // clear from there to the end of the screen.
                        out.push_str(&format!("\x1b[{prev_lines}F"));
                        out.push_str("\x1b[0J");
                    }
                    out.push_str(&panel);
                    print!("{out}");
                    let _ = std::io::stdout().flush();
                    prev_lines = panel.matches('\n').count();
                } else {
                    print!("{panel}");
                    let _ = std::io::stdout().flush();
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_hex_be_trims_leading_zeros() {
        // Little-endian: byte 31 (MSB) = 0x00, byte 30 = 0x0f, rest 0xff lower.
        let mut t = [0u8; 32];
        t[30] = 0x0f;
        t[29] = 0xab;
        // big-endian: 00..00 0f ab 00..00 -> trimmed to "0fab0000...0000"
        let hex = target_hex_be(&t);
        assert!(hex.starts_with("0fab"));
        assert!(!hex.starts_with("00"));
    }

    #[test]
    fn target_hex_be_all_zero() {
        let t = [0u8; 32];
        assert_eq!(target_hex_be(&t), "00");
    }

    #[test]
    fn leading_zero_bits_counts_from_msb() {
        let mut t = [0u8; 32];
        // MSB (index 31) = 0 -> 8 bits; index 30 = 0x0f -> 4 leading zeros.
        t[30] = 0x0f;
        assert_eq!(target_leading_zero_bits(&t), 12);
    }

    #[test]
    fn leading_zero_bits_all_zero_is_256() {
        assert_eq!(target_leading_zero_bits(&[0u8; 32]), 256);
    }

    #[test]
    fn fmt_duration_scales() {
        assert_eq!(fmt_duration(Duration::from_secs(45)), "45s");
        assert_eq!(fmt_duration(Duration::from_secs(184)), "3m04s");
        assert_eq!(fmt_duration(Duration::from_secs(3723)), "1h02m03s");
    }

    #[test]
    fn style_noop_without_color() {
        assert_eq!(style("hi", BOLD, false), "hi");
        assert_eq!(style("hi", BOLD, true), "\x1b[1mhi\x1b[0m");
    }

    #[test]
    fn startup_banner_has_key_fields() {
        let b = startup_banner(
            &StartupInfo {
                version: "9.9.9",
                mode: "Stratum V2",
                pool_addr: "1.2.3.4:3333",
                workers: 4,
                solver_threads: 2,
                encryption: Some("abcd1234".into()),
            },
            false,
        );
        assert!(b.contains("9.9.9"));
        assert!(b.contains("Stratum V2"));
        assert!(b.contains("1.2.3.4:3333"));
        assert!(b.contains("Noise_NK (abcd1234)"));
    }

    #[test]
    fn connected_reflects_transport() {
        assert!(connected("worker-1", true, false).contains("Noise_NK"));
        assert!(connected("worker-1", false, false).contains("plaintext"));
        assert!(connected("worker-1", false, false).contains("worker-1"));
    }

    #[test]
    fn mining_started_has_key_fields() {
        let mut tgt = [0u8; 32];
        tgt[30] = 0x0f;
        let s = mining_started(
            &MiningStarted {
                worker: "worker-1",
                channel_id: Some(7),
                nonce_1_hex: "a1b2c3d4".into(),
                nonce_2_len: 28,
                share_target: tgt,
                bits: 0x1f07ffff,
                clean: true,
            },
            false,
        );
        assert!(s.contains("worker-1"));
        assert!(s.contains("channel 7"));
        assert!(s.contains("a1b2c3d4"));
        assert!(s.contains("28B nonce-2"));
        assert!(s.contains("0x1f07ffff"));
        assert!(s.contains("leading zero bits"));
    }

    #[test]
    fn mining_started_v1_has_no_channel() {
        let s = mining_started(
            &MiningStarted {
                worker: "worker-1",
                channel_id: None,
                nonce_1_hex: "aabb".into(),
                nonce_2_len: 30,
                share_target: [0xff; 32],
                bits: 0x1d00ffff,
                clean: false,
            },
            false,
        );
        assert!(s.contains("channel n/a (V1)"));
    }

    #[test]
    fn stats_block_has_key_fields_and_trailing_newline() {
        let snap = MetricsSnapshot {
            nonces_attempted: 100,
            shares_submitted: 5,
            shares_accepted: 4,
            shares_rejected: 1,
            blocks_found: 2,
            connected_workers: 3,
        };
        let b = stats_block(&snap, Duration::from_secs(65), 1.234, false);
        assert!(b.ends_with('\n'));
        assert!(b.contains("1m05s"));
        assert!(b.contains("1.234 Sol/s"));
        assert!(b.contains("5 submitted / 4 accepted / 1 rejected"));
        assert!(b.contains("workers:   3") || b.contains("workers:  3"));
    }
}
