# TCP Congestion Control & Loss Recovery — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace basic Reno with CUBIC (RFC 9438), add SACK-based loss recovery (RFC 6675), PRR (RFC 6937), Limited Transmit (RFC 3042), and F-RTO (RFC 5682).

**Architecture:** New `congestion.rs` and `recovery.rs` modules with concrete structs (no traits). TCB replaces `cwnd/ssthresh/dup_ack_count` with `CubicState`, `SackRecovery`, `PrrState`, `FRtoState`. Integration into existing ACK processing, fast retransmit, RTO, and poll_send paths in `mod.rs`.

**Tech Stack:** Rust, coarsetime (for timestamps — always use supplied `now: Instant`, never `Instant::now()`), existing TCP handler + wire module infrastructure.

**Design doc:** `docs/plans/2026-03-07-tcp-congestion-recovery-design.md`

---

### Task 1: Create CubicState with slow start and loss response

**Files:**
- Create: `src/net/handler/tcp/congestion.rs`
- Modify: `src/net/handler/tcp/mod.rs:1` (add `pub(crate) mod congestion;`)

**Step 1: Write the failing tests**

Add unit tests in `congestion.rs`:

```rust
use coarsetime::Instant;

/// CUBIC constants (RFC 9438 §5).
const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;

pub struct CubicState {
    pub cwnd: u32,
    pub ssthresh: u32,
    w_max: u32,
    w_max_prev: u32,
    epoch_start: Option<Instant>,
    k: f64,
    origin_point: u32,
    tcp_cwnd: u32,
    ack_count: u32,
    eff_mss: u16,
    cwnd_before_rto: Option<u32>,
    ssthresh_before_rto: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_increases_cwnd_by_mss_per_ack() {
        let mut cubic = CubicState::new(1460);
        // IW = 10 * MSS = 14600, ssthresh = MAX => slow start.
        let now = Instant::now();
        cubic.on_ack(1460, now, 100);
        assert_eq!(cubic.cwnd, 14600 + 1460);
        cubic.on_ack(1460, now, 100);
        assert_eq!(cubic.cwnd, 14600 + 2 * 1460);
    }

    #[test]
    fn on_loss_sets_ssthresh_to_cwnd_times_beta() {
        let mut cubic = CubicState::new(1460);
        cubic.cwnd = 100_000;
        cubic.on_loss();
        assert_eq!(cubic.ssthresh, 70_000); // 100_000 * 0.7
        assert_eq!(cubic.cwnd, 70_000);
        assert_eq!(cubic.w_max, 100_000);
    }

    #[test]
    fn on_rto_resets_cwnd_to_one_mss() {
        let mut cubic = CubicState::new(1460);
        cubic.cwnd = 100_000;
        cubic.ssthresh = 50_000;
        cubic.on_rto();
        assert_eq!(cubic.cwnd, 1460);
        assert_eq!(cubic.ssthresh, 70_000); // 100_000 * 0.7
        assert_eq!(cubic.cwnd_before_rto, Some(100_000));
        assert_eq!(cubic.ssthresh_before_rto, Some(50_000));
    }

    #[test]
    fn beta_is_07_not_05() {
        let mut cubic = CubicState::new(1460);
        cubic.cwnd = 10_000;
        cubic.on_loss();
        // Reno would be 5000, CUBIC should be 7000.
        assert_eq!(cubic.ssthresh, 7000);
    }

    #[test]
    fn fast_convergence_reduces_w_max() {
        let mut cubic = CubicState::new(1460);
        // First loss at cwnd=100_000.
        cubic.cwnd = 100_000;
        cubic.on_loss();
        // w_max_prev = 100_000.
        // Second loss at cwnd=80_000 (below w_max_prev).
        cubic.cwnd = 80_000;
        cubic.on_loss();
        // Fast convergence: w_max = 80_000 * (1 + 0.7) / 2 = 68_000.
        assert_eq!(cubic.w_max, 68_000);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet congestion::tests`
Expected: FAIL — `CubicState::new`, `on_ack`, `on_loss`, `on_rto` not implemented

**Step 3: Implement CubicState::new, on_loss, on_rto, and slow start portion of on_ack**

```rust
impl CubicState {
    pub fn new(eff_mss: u16) -> Self {
        Self {
            cwnd: 10 * eff_mss as u32,
            ssthresh: u32::MAX,
            w_max: 0,
            w_max_prev: 0,
            epoch_start: None,
            k: 0.0,
            origin_point: 0,
            tcp_cwnd: 0,
            ack_count: 0,
            eff_mss,
            cwnd_before_rto: None,
            ssthresh_before_rto: None,
        }
    }

    /// Update eff_mss after MSS negotiation completes.
    pub fn set_mss(&mut self, eff_mss: u16) {
        self.eff_mss = eff_mss;
    }

    /// Called on each new ACK (that advances snd_una). NOT called during recovery.
    /// `rtt_ms` is the current smoothed RTT estimate in milliseconds.
    pub fn on_ack(&mut self, bytes_acked: u32, now: Instant, rtt_ms: u64) {
        let mss = self.eff_mss as u32;
        if self.cwnd < self.ssthresh {
            // Slow start: increase by MSS per ACK.
            self.cwnd += mss;
        } else {
            // Congestion avoidance: CUBIC window update (Task 2).
            self.cubic_update(bytes_acked, now, rtt_ms);
        }
    }

    /// Called on packet loss detected via 3 dup ACKs / SACK.
    pub fn on_loss(&mut self) {
        self.epoch_start = None;
        let mss = self.eff_mss as u32;

        // Fast convergence (RFC 9438 §5.8).
        if self.cwnd < self.w_max_prev {
            self.w_max_prev = self.cwnd;
            self.w_max = (self.cwnd as f64 * (1.0 + CUBIC_BETA) / 2.0) as u32;
        } else {
            self.w_max_prev = self.cwnd;
            self.w_max = self.cwnd;
        }

        self.ssthresh = (self.cwnd as f64 * CUBIC_BETA) as u32;
        self.ssthresh = self.ssthresh.max(2 * mss);
        self.cwnd = self.ssthresh;
    }

    /// Called on ECN congestion signal. Same as loss per RFC 9438.
    pub fn on_ecn(&mut self) {
        self.on_loss();
    }

    /// Called on RTO expiry. Saves state for F-RTO, resets to 1 MSS.
    pub fn on_rto(&mut self) {
        let mss = self.eff_mss as u32;
        self.cwnd_before_rto = Some(self.cwnd);
        self.ssthresh_before_rto = Some(self.ssthresh);
        self.epoch_start = None;

        self.w_max_prev = self.w_max;
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd as f64 * CUBIC_BETA) as u32;
        self.ssthresh = self.ssthresh.max(2 * mss);
        self.cwnd = mss;
    }

    /// Restore cwnd/ssthresh after F-RTO determines RTO was spurious.
    pub fn restore_after_spurious_rto(&mut self) {
        if let (Some(cwnd), Some(ssthresh)) = (self.cwnd_before_rto, self.ssthresh_before_rto) {
            self.cwnd = cwnd;
            self.ssthresh = ssthresh;
            self.cwnd_before_rto = None;
            self.ssthresh_before_rto = None;
        }
    }

    // Stub for Task 2.
    fn cubic_update(&mut self, _bytes_acked: u32, _now: Instant, _rtt_ms: u64) {
        // Placeholder — Reno-like until Task 2.
        let mss = self.eff_mss as u32;
        self.ack_count += _bytes_acked;
        if self.ack_count >= self.cwnd {
            self.cwnd += mss;
            self.ack_count -= self.cwnd - mss;
        }
    }
}
```

Also add `pub(crate) mod congestion;` to `src/net/handler/tcp/mod.rs` after line 5 (after `pub(crate) mod tcb;`).

**Step 4: Run tests to verify they pass**

Run: `cargo test -p voidnet congestion::tests`
Expected: All 5 tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/congestion.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): add CubicState with slow start, loss, and RTO response"
```

---

### Task 2: Implement CUBIC congestion avoidance window function

**Files:**
- Modify: `src/net/handler/tcp/congestion.rs` (replace `cubic_update` stub)

**Step 1: Write the failing tests**

Add to `congestion.rs` tests:

```rust
#[test]
fn congestion_avoidance_grows_past_w_max() {
    let mut cubic = CubicState::new(1460);
    // Simulate loss at cwnd=100_000 to set w_max.
    cubic.cwnd = 100_000;
    cubic.on_loss();
    // Now cwnd = 70_000, ssthresh = 70_000, w_max = 100_000.

    let start = Instant::now();
    let rtt_ms = 50;
    // Simulate ~400 ACKs over several seconds.
    for i in 0..400 {
        let elapsed_ms = (i as u64) * rtt_ms;
        let now = start + coarsetime::Duration::from_millis(elapsed_ms);
        cubic.on_ack(1460, now, rtt_ms);
    }
    // After enough time, cwnd should exceed w_max.
    assert!(
        cubic.cwnd > 100_000,
        "cwnd {} should exceed w_max 100_000",
        cubic.cwnd
    );
}

#[test]
fn tcp_friendliness_cwnd_at_least_reno() {
    let mut cubic = CubicState::new(1460);
    // Loss at 50_000.
    cubic.cwnd = 50_000;
    cubic.on_loss();
    // cwnd = 35_000, w_max = 50_000.

    let start = Instant::now();
    let rtt_ms = 100;
    let mut reno_cwnd = 35_000u32;
    let mss = 1460u32;
    for i in 0..200 {
        let now = start + coarsetime::Duration::from_millis(i * rtt_ms);
        cubic.on_ack(1460, now, rtt_ms);
        // Reno: cwnd += MSS^2 / cwnd per ACK.
        reno_cwnd += (mss * mss) / reno_cwnd;
    }
    assert!(
        cubic.cwnd >= reno_cwnd - mss,
        "CUBIC cwnd {} should be >= Reno cwnd {} (within 1 MSS)",
        cubic.cwnd,
        reno_cwnd
    );
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet congestion::tests`
Expected: FAIL — `cubic_update` stub doesn't follow cubic function

**Step 3: Implement the CUBIC window function**

Replace the `cubic_update` stub:

```rust
fn cubic_update(&mut self, bytes_acked: u32, now: Instant, rtt_ms: u64) {
    let mss = self.eff_mss as u32;

    // Initialize epoch on first ACK in congestion avoidance.
    if self.epoch_start.is_none() {
        self.epoch_start = Some(now);
        // If cwnd was less than w_max (e.g. after timeout), adjust K.
        if self.cwnd < self.w_max {
            self.k = ((self.w_max - self.cwnd) as f64 / CUBIC_C).cbrt();
            self.origin_point = self.w_max;
        } else {
            self.k = 0.0;
            self.origin_point = self.cwnd;
        }
        self.ack_count = 0;
        self.tcp_cwnd = self.cwnd;
    }

    let epoch_start = self.epoch_start.unwrap();
    let t = now.duration_since(epoch_start).as_millis() as f64 / 1000.0; // seconds

    // W_cubic(t) = C * (t - K)^3 + origin_point.
    let t_minus_k = t - self.k;
    let w_cubic = (CUBIC_C * t_minus_k * t_minus_k * t_minus_k) as i64
        + self.origin_point as i64;
    let w_cubic = (w_cubic.max(mss as i64)) as u32;

    // TCP-friendly estimate: W_est = origin_point * beta + 3 * (1-beta)/(1+beta) * t/RTT * MSS.
    if rtt_ms > 0 {
        let rtt_sec = rtt_ms as f64 / 1000.0;
        let acks_since_epoch = t / rtt_sec;
        let reno_inc = (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) * acks_since_epoch;
        self.tcp_cwnd = ((self.origin_point as f64 * CUBIC_BETA) + reno_inc * mss as f64) as u32;
    }

    // Take the larger of CUBIC and TCP-friendly.
    let target = w_cubic.max(self.tcp_cwnd);

    if target > self.cwnd {
        // Increase cwnd. Scale by bytes_acked to handle byte counting.
        let delta = target - self.cwnd;
        // Increase by (delta * MSS / cwnd) per ACK for smoothness.
        let inc = ((delta as u64 * mss as u64) / self.cwnd as u64) as u32;
        self.cwnd += inc.max(1);
    }
    // If target <= cwnd, hold steady (plateau near w_max before concave growth).
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p voidnet congestion::tests`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/congestion.rs
git commit -m "feat(tcp): implement CUBIC congestion avoidance window function (RFC 9438)"
```

---

### Task 3: Create SackRecovery with IsLost, SetPipe, and entry/exit

**Files:**
- Create: `src/net/handler/tcp/recovery.rs`
- Modify: `src/net/handler/tcp/mod.rs:1` (add `pub(crate) mod recovery;`)

**Step 1: Write the failing tests**

```rust
use std::collections::BTreeMap;

const DUP_THRESH: u32 = 3;

pub struct SackRecovery {
    pub in_recovery: bool,
    pub recovery_point: u32,
    pub pipe: u32,
    pub dup_ack_count: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_lost_with_3_sacked_above() {
        let recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // SACKed: [2000..3000], [3000..4000], [4000..5000] — 3 blocks above seq 1000.
        scoreboard.insert(2000u32, 1000u32);
        scoreboard.insert(3000u32, 1000u32);
        scoreboard.insert(4000u32, 1000u32);
        assert!(recovery.is_lost(1000, &scoreboard, 1000));
    }

    #[test]
    fn is_lost_with_large_gap() {
        let recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // Single SACK at [5000..6000] — 4000 bytes above seq 1000, > 3*MSS.
        scoreboard.insert(5000u32, 1000u32);
        assert!(recovery.is_lost(1000, &scoreboard, 1000));
    }

    #[test]
    fn not_lost_with_insufficient_sacks() {
        let recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // Only 2 blocks above.
        scoreboard.insert(2000u32, 1000u32);
        scoreboard.insert(3000u32, 1000u32);
        assert!(!recovery.is_lost(1000, &scoreboard, 1000));
    }

    #[test]
    fn set_pipe_counts_in_flight() {
        let mut recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // snd_una=1000, snd_nxt=5000 => 4 MSS-sized blocks.
        // Block [2000..3000] SACKed, block [1000..2000] is lost (3+ SACKed above).
        scoreboard.insert(2000u32, 1000u32);
        scoreboard.insert(3000u32, 1000u32);
        scoreboard.insert(4000u32, 1000u32);
        // [1000..2000]: lost => not counted.
        // [2000..3000]: SACKed => not counted.
        // [3000..4000]: SACKed => not counted.
        // [4000..5000]: SACKed => not counted.
        recovery.set_pipe(1000, 5000, &scoreboard, 1000);
        assert_eq!(recovery.pipe, 0);
    }

    #[test]
    fn set_pipe_counts_unacked_unsacked_as_in_flight() {
        let mut recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // snd_una=1000, snd_nxt=6000 => 5 MSS blocks.
        // Only [2000..3000] SACKed. [1000..2000] has only 1 SACK above — not lost.
        scoreboard.insert(2000u32, 1000u32);
        // [1000..2000]: not SACKed, only 1 block SACKed above (2000) — not lost => in flight.
        // [2000..3000]: SACKed.
        // [3000..4000]: not SACKed, 0 blocks above => in flight.
        // [4000..5000]: not SACKed, 0 blocks above => in flight.
        // [5000..6000]: not SACKed, 0 blocks above => in flight.
        recovery.set_pipe(1000, 6000, &scoreboard, 1000);
        assert_eq!(recovery.pipe, 4000); // 4 blocks in flight
    }

    #[test]
    fn enter_and_exit_recovery() {
        let mut recovery = SackRecovery::new();
        recovery.enter(5000);
        assert!(recovery.in_recovery);
        assert_eq!(recovery.recovery_point, 5000);

        // Partial ACK — doesn't exit.
        assert!(!recovery.on_ack(3000));
        assert!(recovery.in_recovery);

        // Full ACK — exits.
        assert!(recovery.on_ack(5000));
        assert!(!recovery.in_recovery);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet recovery::tests`
Expected: FAIL — `SackRecovery` methods not implemented

**Step 3: Implement SackRecovery**

```rust
use std::collections::BTreeMap;
use crate::net::wire::tcp::{seq_le, seq_lt};

const DUP_THRESH: u32 = 3;

pub struct SackRecovery {
    pub in_recovery: bool,
    pub recovery_point: u32,
    pub pipe: u32,
    pub dup_ack_count: u8,
}

impl SackRecovery {
    pub fn new() -> Self {
        Self {
            in_recovery: false,
            recovery_point: 0,
            pipe: 0,
            dup_ack_count: 0,
        }
    }

    /// Enter SACK recovery. `snd_nxt` is the recovery point.
    pub fn enter(&mut self, snd_nxt: u32) {
        self.in_recovery = true;
        self.recovery_point = snd_nxt;
    }

    /// Exit recovery, reset state.
    pub fn exit(&mut self) {
        self.in_recovery = false;
        self.dup_ack_count = 0;
        self.pipe = 0;
    }

    /// Process a new ACK during recovery. Returns true if recovery is complete.
    pub fn on_ack(&mut self, seg_ack: u32) -> bool {
        if seq_le(self.recovery_point, seg_ack) {
            self.exit();
            true
        } else {
            false
        }
    }

    /// RFC 6675 §4: IsLost predicate. A segment starting at `seq` is lost if
    /// DupThresh segments above it have been SACKed or the byte distance exceeds
    /// DupThresh * MSS.
    pub fn is_lost(&self, seq: u32, scoreboard: &BTreeMap<u32, u32>, eff_mss: u16) -> bool {
        let mss = eff_mss as u32;
        let mut sacked_segments_above = 0u32;
        let mut highest_sacked = seq;

        for (&start, &len) in scoreboard {
            let end = start.wrapping_add(len);
            if seq_lt(seq, start) {
                // Count MSS-sized segments in this SACK block.
                let block_segments = (len + mss - 1) / mss;
                sacked_segments_above += block_segments;
                if seq_lt(highest_sacked, end) {
                    highest_sacked = end;
                }
            }
        }

        // Lost if 3+ segments SACKed above, or distance > 3*MSS.
        let byte_distance = highest_sacked.wrapping_sub(seq);
        sacked_segments_above >= DUP_THRESH || byte_distance >= DUP_THRESH * mss
    }

    /// RFC 6675 §4.1: SetPipe — estimate bytes in the network.
    /// Iterates MSS-sized blocks from snd_una to snd_nxt.
    pub fn set_pipe(
        &mut self,
        snd_una: u32,
        snd_nxt: u32,
        scoreboard: &BTreeMap<u32, u32>,
        eff_mss: u16,
    ) {
        let mss = eff_mss as u32;
        let mut pipe = 0u32;
        let mut seq = snd_una;

        while seq_lt(seq, snd_nxt) {
            let block_end = seq.wrapping_add(mss);
            let is_sacked = self.is_sacked(seq, scoreboard);
            let is_lost = self.is_lost(seq, scoreboard, eff_mss);

            if !is_sacked && !is_lost {
                pipe += mss;
            }

            seq = block_end;
        }

        self.pipe = pipe;
    }

    /// Check if a sequence number falls within a SACKed range.
    fn is_sacked(&self, seq: u32, scoreboard: &BTreeMap<u32, u32>) -> bool {
        for (&start, &len) in scoreboard {
            let end = start.wrapping_add(len);
            if seq_le(start, seq) && seq_lt(seq, end) {
                return true;
            }
        }
        false
    }

    /// Find the lowest lost sequence number >= `from` for retransmission.
    pub fn next_lost_segment(
        &self,
        from: u32,
        snd_nxt: u32,
        scoreboard: &BTreeMap<u32, u32>,
        eff_mss: u16,
    ) -> Option<u32> {
        let mss = eff_mss as u32;
        let mut seq = from;
        while seq_lt(seq, snd_nxt) {
            if !self.is_sacked(seq, scoreboard) && self.is_lost(seq, scoreboard, eff_mss) {
                return Some(seq);
            }
            seq = seq.wrapping_add(mss);
        }
        None
    }
}
```

Also add `pub(crate) mod recovery;` to `src/net/handler/tcp/mod.rs` after the congestion module line.

**Step 4: Run tests to verify they pass**

Run: `cargo test -p voidnet recovery::tests`
Expected: All 6 tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/recovery.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): add SackRecovery with IsLost, SetPipe, entry/exit (RFC 6675)"
```

---

### Task 4: Add PrrState to recovery.rs

**Files:**
- Modify: `src/net/handler/tcp/recovery.rs`

**Step 1: Write the failing tests**

Add to `recovery.rs` tests:

```rust
#[test]
fn prr_proportional_when_pipe_above_ssthresh() {
    let mut prr = PrrState::new();
    prr.enter(10_000); // recover_fs = 10_000.
    let ssthresh = 7_000u32;
    let mss = 1460u16;

    // Simulate ACK delivering 1460 bytes.
    let snd_cnt = prr.on_ack(1460, 8_000, ssthresh, mss);
    // pipe=8000 > ssthresh=7000 => proportional.
    // snd_cnt = ceil(1460 * 7000 / 10000) - 0 = ceil(1022) = 1022.
    assert_eq!(snd_cnt, 1022);

    // After "sending" 1022 bytes.
    prr.on_sent(1022);
    // Second ACK.
    let snd_cnt = prr.on_ack(1460, 7_000, ssthresh, mss);
    // snd_cnt = ceil(2920 * 7000 / 10000) - 1022 = ceil(2044) - 1022 = 1022.
    assert_eq!(snd_cnt, 1022);
}

#[test]
fn prr_slow_start_reduction_when_pipe_below_ssthresh() {
    let mut prr = PrrState::new();
    prr.enter(10_000);
    let ssthresh = 7_000u32;
    let mss = 1460u16;

    // pipe=5000 < ssthresh.
    let snd_cnt = prr.on_ack(1460, 5_000, ssthresh, mss);
    // snd_cnt = min(7000 - 5000, 1460 - 0 + 1460) = min(2000, 2920) = 2000.
    assert_eq!(snd_cnt, 2000);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet recovery::tests::prr`
Expected: FAIL — `PrrState` not defined

**Step 3: Implement PrrState**

Add to `recovery.rs`:

```rust
pub struct PrrState {
    pub prr_delivered: u32,
    pub prr_out: u32,
    pub recover_fs: u32,
}

impl PrrState {
    pub fn new() -> Self {
        Self {
            prr_delivered: 0,
            prr_out: 0,
            recover_fs: 0,
        }
    }

    /// Enter recovery. `bytes_in_flight` = snd_nxt - snd_una at entry.
    pub fn enter(&mut self, bytes_in_flight: u32) {
        self.recover_fs = bytes_in_flight;
        self.prr_delivered = 0;
        self.prr_out = 0;
    }

    /// Reset on recovery exit.
    pub fn exit(&mut self) {
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.recover_fs = 0;
    }

    /// Called on each ACK during recovery. Returns snd_cnt (bytes allowed to send).
    /// `bytes_newly_delivered` = bytes_acked + bytes_newly_sacked.
    /// `pipe` = current pipe estimate. `ssthresh` = target cwnd.
    pub fn on_ack(&mut self, bytes_newly_delivered: u32, pipe: u32, ssthresh: u32, eff_mss: u16) -> u32 {
        self.prr_delivered += bytes_newly_delivered;

        if pipe > ssthresh {
            // Proportional: snd_cnt = ceil(prr_delivered * ssthresh / recover_fs) - prr_out.
            let numer = self.prr_delivered as u64 * ssthresh as u64;
            let target = ((numer + self.recover_fs as u64 - 1) / self.recover_fs as u64) as u32;
            target.saturating_sub(self.prr_out)
        } else {
            // Slow start reduction bound.
            let limit = self.prr_delivered.saturating_sub(self.prr_out) + eff_mss as u32;
            ssthresh.saturating_sub(pipe).min(limit)
        }
    }

    /// Called after sending bytes during recovery.
    pub fn on_sent(&mut self, bytes_sent: u32) {
        self.prr_out += bytes_sent;
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p voidnet recovery::tests`
Expected: All 8 tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/recovery.rs
git commit -m "feat(tcp): add PRR for smooth sending during recovery (RFC 6937)"
```

---

### Task 5: Add FRtoState to recovery.rs

**Files:**
- Modify: `src/net/handler/tcp/recovery.rs`

**Step 1: Write the failing tests**

Add to `recovery.rs` tests:

```rust
#[test]
fn frto_spurious_rto_detected() {
    let mut frto = FRtoState::new();
    frto.enter(1000); // snd_una at RTO = 1000.

    // First ACK advances snd_una.
    let result = frto.on_ack(2000);
    assert_eq!(result, FRtoAction::SendNewData);

    // Second ACK advances snd_una again => spurious.
    let result = frto.on_ack(3000);
    assert_eq!(result, FRtoAction::SpuriousRto);
}

#[test]
fn frto_genuine_loss_on_first_dup_ack() {
    let mut frto = FRtoState::new();
    frto.enter(1000);

    // First ACK is dup (snd_una doesn't advance).
    let result = frto.on_ack(1000);
    assert_eq!(result, FRtoAction::GenuineLoss);
}

#[test]
fn frto_genuine_loss_on_second_dup_ack() {
    let mut frto = FRtoState::new();
    frto.enter(1000);

    // First ACK advances.
    let result = frto.on_ack(2000);
    assert_eq!(result, FRtoAction::SendNewData);

    // Second ACK is dup.
    let result = frto.on_ack(2000);
    assert_eq!(result, FRtoAction::GenuineLoss);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet recovery::tests::frto`
Expected: FAIL — `FRtoState` not defined

**Step 3: Implement FRtoState**

Add to `recovery.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FRtoPhase {
    Disabled,
    Step1,
    Step2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FRtoAction {
    /// No F-RTO active — proceed normally.
    None,
    /// Send new data (not retransmissions) to probe.
    SendNewData,
    /// Spurious RTO detected — restore cwnd.
    SpuriousRto,
    /// Genuine loss confirmed — keep reduced cwnd.
    GenuineLoss,
}

pub struct FRtoState {
    pub phase: FRtoPhase,
    snd_una_at_rto: u32,
    snd_una_last: u32,
}

impl FRtoState {
    pub fn new() -> Self {
        Self {
            phase: FRtoPhase::Disabled,
            snd_una_at_rto: 0,
            snd_una_last: 0,
        }
    }

    /// Arm F-RTO on RTO retransmit.
    pub fn enter(&mut self, snd_una: u32) {
        self.phase = FRtoPhase::Step1;
        self.snd_una_at_rto = snd_una;
        self.snd_una_last = snd_una;
    }

    /// Process ACK during F-RTO. `new_snd_una` is the updated snd_una after this ACK.
    /// Returns the action to take.
    pub fn on_ack(&mut self, new_snd_una: u32) -> FRtoAction {
        match self.phase {
            FRtoPhase::Disabled => FRtoAction::None,
            FRtoPhase::Step1 => {
                if seq_lt(self.snd_una_last, new_snd_una) {
                    // ACK advances — move to Step2, send new data.
                    self.snd_una_last = new_snd_una;
                    self.phase = FRtoPhase::Step2;
                    FRtoAction::SendNewData
                } else {
                    // Dup ACK — genuine loss.
                    self.phase = FRtoPhase::Disabled;
                    FRtoAction::GenuineLoss
                }
            }
            FRtoPhase::Step2 => {
                if seq_lt(self.snd_una_last, new_snd_una) {
                    // Second advancing ACK — spurious RTO.
                    self.phase = FRtoPhase::Disabled;
                    FRtoAction::SpuriousRto
                } else {
                    // Dup ACK — genuine loss.
                    self.phase = FRtoPhase::Disabled;
                    FRtoAction::GenuineLoss
                }
            }
        }
    }

    /// Check if F-RTO is active (in Step1 or Step2).
    pub fn is_active(&self) -> bool {
        self.phase != FRtoPhase::Disabled
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p voidnet recovery::tests`
Expected: All 11 tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/recovery.rs
git commit -m "feat(tcp): add F-RTO spurious RTO detection (RFC 5682)"
```

---

### Task 6: Update TCB to use new congestion/recovery structs

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs` — replace `cwnd`, `ssthresh`, `dup_ack_count` with new structs
- Modify: `src/net/handler/tcp/mod.rs` — update all TCB construction sites and field accesses

This is a refactoring task. The goal is to swap fields in the TCB and update all references. No new behavior yet — the integration comes in Tasks 7-10.

**Step 1: Update TCB struct**

In `src/net/handler/tcp/tcb.rs`:
- Add imports: `use super::congestion::CubicState;` and `use super::recovery::{SackRecovery, PrrState, FRtoState};`
- Remove fields: `cwnd: u32`, `ssthresh: u32`, `dup_ack_count: u8`
- Add fields: `pub cubic: CubicState`, `pub recovery: SackRecovery`, `pub prr: PrrState`, `pub frto: FRtoState`
- Update `advertised_window()` — currently doesn't reference cwnd, so no change needed there.

**Step 2: Update TCB construction sites in mod.rs**

There are 2 TCB construction sites:
1. Active open (connect): `src/net/handler/tcp/mod.rs:229-293` — replace `cwnd: 10 * DEFAULT_RCV_MSS as u32, ssthresh: u32::MAX, dup_ack_count: 0` with `cubic: CubicState::new(DEFAULT_RCV_MSS), recovery: SackRecovery::new(), prr: PrrState::new(), frto: FRtoState::new()`
2. Passive open (SYN-RECEIVED): `src/net/handler/tcp/mod.rs:806-872` — same replacement, use `CubicState::new(peer_mss.min(DEFAULT_RCV_MSS))`

**Step 3: Update all field accesses**

Search for `tcb.cwnd`, `tcb.ssthresh`, `tcb.dup_ack_count` and replace:
- `tcb.cwnd` → `tcb.cubic.cwnd`
- `tcb.ssthresh` → `tcb.cubic.ssthresh`
- `tcb.dup_ack_count` → `tcb.recovery.dup_ack_count`

Key locations (approximate lines, may shift after earlier tasks):
- ACK processing (~1486-1492): `tcb.cwnd` / `tcb.ssthresh` → `tcb.cubic.cwnd` / `tcb.cubic.ssthresh`
- Dup ACK counter (~1602): `tcb.dup_ack_count` → `tcb.recovery.dup_ack_count`
- Fast retransmit (~1951): `tcb.dup_ack_count` → `tcb.recovery.dup_ack_count`
- Fast recovery cwnd halving (~2023-2026): `tcb.cwnd` / `tcb.ssthresh` → `tcb.cubic.cwnd` / `tcb.cubic.ssthresh`
- RTO cwnd reset (~2152-2154): same
- poll_send (~2244): `tcb.cwnd` → `tcb.cubic.cwnd`
- ECN response (~1567-1570): `tcb.cwnd` / `tcb.ssthresh` → `tcb.cubic.cwnd` / `tcb.cubic.ssthresh`
- All test assertions referencing `tcb.cwnd`, `tcb.ssthresh`, `tcb.dup_ack_count`

Also update the `make_tcb` helper in `tcb.rs` tests to use the new structs.

**Step 4: Run all tests to verify nothing is broken**

Run: `cargo test`
Expected: All tests PASS (behavior unchanged, just field access through structs)

**Step 5: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/mod.rs
git commit -m "refactor(tcp): replace cwnd/ssthresh/dup_ack_count with CubicState/SackRecovery/PrrState/FRtoState"
```

---

### Task 7: Integrate CUBIC into ACK processing

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` — ACK processing path

Replace the inline Reno congestion control with calls to `CubicState`.

**Step 1: Write integration test**

Add to `mod.rs` tests:

```rust
#[test]
fn cubic_congestion_control_on_new_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 { free.push(alloc_free_frame(100 + i)); }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let cwnd_before = handler.connections[0].cubic.cwnd;
    let mss = handler.connections[0].eff_snd_mss;

    // Send data and get it ACKed.
    handler.connections[0].send_buffer.write(&[0xAA; 1460]);
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    // ACK the data.
    let snd_nxt = handler.connections[0].snd_nxt;
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_nxt, flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(2, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);

    // In slow start: cwnd should increase by MSS.
    let cwnd_after = handler.connections[0].cubic.cwnd;
    assert_eq!(cwnd_after, cwnd_before + mss as u32, "slow start: cwnd += MSS");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p voidnet cubic_congestion_control_on_new_ack`
Expected: FAIL — ACK processing still uses inline Reno

**Step 3: Replace inline Reno with CubicState calls**

In `process_established` ACK processing (~line 1484-1492), replace:

```rust
// OLD:
let eff_mss = tcb.eff_snd_mss as u32;
if tcb.cwnd < tcb.ssthresh {
    tcb.cwnd += eff_mss;
} else {
    tcb.cwnd += (eff_mss * eff_mss) / tcb.cwnd;
}
tcb.dup_ack_count = 0;
```

With:

```rust
// NEW:
if !tcb.recovery.in_recovery {
    let rtt_ms = tcb.srtt.unwrap_or(tcb.rto);
    tcb.cubic.on_ack(bytes_acked as u32, now, rtt_ms);
}
tcb.recovery.dup_ack_count = 0;
```

Also replace the ECN response (~line 1567-1570):

```rust
// OLD:
tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
tcb.cwnd = tcb.ssthresh;

// NEW:
tcb.cubic.on_ecn();
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): integrate CUBIC into ACK processing, replacing inline Reno"
```

---

### Task 8: Integrate SACK recovery into fast retransmit

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` — fast retransmit path in `poll_timers` and dup ACK handling

**Step 1: Write integration test**

Add to `mod.rs` tests:

```rust
#[test]
fn sack_recovery_enters_on_3_dup_acks() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 { free.push(alloc_free_frame(100 + i)); }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Send 4 segments.
    handler.connections[0].send_buffer.write(&[0xAA; 5840]); // 4 * 1460
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    let snd_una = handler.connections[0].snd_una;

    // Send 3 dup ACKs (ACK for snd_una, no data).
    for i in 0..3 {
        let dup = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_una, flags::ACK, 65535, &[]);
        let dup_len = dup.len();
        handler.process_ipv4(Frame::new(10 + i, leak(dup), dup_len, false), &nh, &mut free, &mut rx, &mut tx);
    }

    assert!(handler.connections[0].recovery.in_recovery, "should be in recovery");
    assert_eq!(handler.connections[0].recovery.dup_ack_count, 3);
}

#[test]
fn sack_recovery_partial_ack_stays_in_recovery() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 { free.push(alloc_free_frame(100 + i)); }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Send 4 segments.
    handler.connections[0].send_buffer.write(&[0xAA; 5840]);
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    let snd_una = handler.connections[0].snd_una;
    let recovery_point = handler.connections[0].snd_nxt;

    // 3 dup ACKs → enter recovery.
    for i in 0..3 {
        let dup = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_una, flags::ACK, 65535, &[]);
        let dup_len = dup.len();
        handler.process_ipv4(Frame::new(10 + i, leak(dup), dup_len, false), &nh, &mut free, &mut rx, &mut tx);
    }
    assert!(handler.connections[0].recovery.in_recovery);

    // Partial ACK — advances snd_una but doesn't reach recovery_point.
    let partial_ack_seq = snd_una.wrapping_add(1460);
    let partial = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, partial_ack_seq, flags::ACK, 65535, &[]);
    let partial_len = partial.len();
    handler.process_ipv4(Frame::new(20, leak(partial), partial_len, false), &nh, &mut free, &mut rx, &mut tx);

    assert!(handler.connections[0].recovery.in_recovery, "should still be in recovery after partial ACK");
    assert_eq!(handler.connections[0].snd_una, partial_ack_seq);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet sack_recovery_enters_on_3_dup_acks sack_recovery_partial_ack_stays_in_recovery`
Expected: FAIL — dup ACK path doesn't enter recovery

**Step 3: Integrate recovery into dup ACK and fast retransmit paths**

In the **dup ACK branch** (~line 1599-1633), after incrementing dup_ack_count, add recovery entry:

```rust
// After: tcb.recovery.dup_ack_count += 1;
// Add:
if tcb.recovery.dup_ack_count == 3 && !tcb.recovery.in_recovery {
    let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una);
    tcb.recovery.enter(tcb.snd_nxt);
    tcb.prr.enter(bytes_in_flight);
    tcb.cubic.on_loss();
}
```

In the **new ACK branch** (~line 1473), add recovery exit check:

```rust
// After updating snd_una, before congestion control:
if tcb.recovery.in_recovery {
    if tcb.recovery.on_ack(seg_ack) {
        // Exited recovery.
        tcb.prr.exit();
    }
}
```

Replace the **fast retransmit block** in `poll_timers` (~line 1948-2027) with RFC 6675 recovery loop:

```rust
// Replace: if tcb.state != TcpState::Established || tcb.dup_ack_count < 3 { continue; }
// With: if tcb.state != TcpState::Established || !tcb.recovery.in_recovery { continue; }
```

Then use `recovery.set_pipe()` + `recovery.next_lost_segment()` to pick what to retransmit, gate on `pipe < cwnd`, and track PRR.

Replace the cwnd halving:
```rust
// OLD:
tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
tcb.cwnd = tcb.ssthresh;
tcb.dup_ack_count = 0;

// REMOVE — cubic.on_loss() already called at recovery entry.
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): integrate RFC 6675 SACK recovery with PRR into fast retransmit"
```

---

### Task 9: Integrate F-RTO into RTO path

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` — RTO retransmit path and ACK processing

**Step 1: Write integration test**

Add to `mod.rs` tests:

```rust
#[test]
fn frto_spurious_rto_restores_cwnd() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 { free.push(alloc_free_frame(100 + i)); }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Send data.
    handler.connections[0].send_buffer.write(&[0xAA; 2920]);
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    let cwnd_before_rto = handler.connections[0].cubic.cwnd;

    // Simulate RTO by setting deadline in the past and calling poll_timers.
    handler.connections[0].retransmit_deadline = Some(now);
    let rto_time = now + coarsetime::Duration::from_millis(1100);
    handler.poll_timers(rto_time, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    // F-RTO should be in Step1.
    assert!(handler.connections[0].frto.is_active());
    assert_eq!(handler.connections[0].cubic.cwnd, handler.connections[0].eff_snd_mss as u32);

    // First ACK advances snd_una.
    let snd_una = handler.connections[0].snd_una;
    let ack1 = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_una.wrapping_add(1460), flags::ACK, 65535, &[]);
    let ack1_len = ack1.len();
    handler.process_ipv4(Frame::new(10, leak(ack1), ack1_len, false), &nh, &mut free, &mut rx, &mut tx);

    // Second ACK advances snd_una again => spurious.
    let snd_una = handler.connections[0].snd_una;
    let ack2 = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_una.wrapping_add(1460), flags::ACK, 65535, &[]);
    let ack2_len = ack2.len();
    handler.process_ipv4(Frame::new(11, leak(ack2), ack2_len, false), &nh, &mut free, &mut rx, &mut tx);

    // cwnd should be restored.
    assert_eq!(handler.connections[0].cubic.cwnd, cwnd_before_rto, "cwnd restored after spurious RTO");
    assert!(!handler.connections[0].frto.is_active());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p voidnet frto_spurious_rto_restores_cwnd`
Expected: FAIL — F-RTO not integrated

**Step 3: Integrate F-RTO**

In the **RTO Established** path in `poll_timers` (~line 2123-2159), add F-RTO entry:

```rust
// After the existing RTO handling:
tcb.frto.enter(tcb.snd_una);
tcb.cubic.on_rto();
tcb.recovery.exit();
tcb.sack_scoreboard.clear();
```

Replace the inline cwnd reset:
```rust
// OLD:
tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
tcb.cwnd = tcb.eff_snd_mss as u32;
// REMOVE — cubic.on_rto() handles this.
```

In **ACK processing** (new ACK branch), add F-RTO check before normal congestion control:

```rust
// Before the existing congestion control:
if tcb.frto.is_active() {
    let action = tcb.frto.on_ack(seg_ack);
    match action {
        FRtoAction::SpuriousRto => {
            tcb.cubic.restore_after_spurious_rto();
        }
        FRtoAction::GenuineLoss => {
            // Keep reduced cwnd, proceed normally.
        }
        FRtoAction::SendNewData => {
            // F-RTO Step1→Step2: prefer sending new data in poll_send.
            // No cwnd changes needed here.
        }
        FRtoAction::None => {}
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): integrate F-RTO into RTO path for spurious timeout detection (RFC 5682)"
```

---

### Task 10: Integrate Limited Transmit and PRR into poll_send

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` — `poll_send` method

**Step 1: Write integration tests**

Add to `mod.rs` tests:

```rust
#[test]
fn limited_transmit_sends_on_first_dup_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 { free.push(alloc_free_frame(100 + i)); }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Fill send buffer with plenty of data, shrink cwnd to limit sending.
    let mss = handler.connections[0].eff_snd_mss as usize;
    handler.connections[0].send_buffer.write(&vec![0xAA; mss * 6]);
    handler.connections[0].snd_wnd = 65535;
    // Set cwnd to exactly 3*MSS so we can only send 3 segments.
    handler.connections[0].cubic.cwnd = (mss * 3) as u32;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}
    // 3 segments sent, 3*MSS in flight.

    let snd_una = handler.connections[0].snd_una;
    let snd_nxt_before = handler.connections[0].snd_nxt;

    // First dup ACK.
    let dup = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_una, flags::ACK, 65535, &[]);
    let dup_len = dup.len();
    handler.process_ipv4(Frame::new(10, leak(dup), dup_len, false), &nh, &mut free, &mut rx, &mut tx);

    // poll_send should allow 1 MSS of new data (limited transmit).
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    let snd_nxt_after = handler.connections[0].snd_nxt;
    assert_eq!(
        snd_nxt_after.wrapping_sub(snd_nxt_before) as usize,
        mss,
        "limited transmit: 1 MSS sent on first dup ACK"
    );
}

#[test]
fn prr_gates_sending_during_recovery() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 { free.push(alloc_free_frame(100 + i)); }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let mss = handler.connections[0].eff_snd_mss as usize;
    handler.connections[0].send_buffer.write(&vec![0xAA; mss * 10]);
    handler.connections[0].snd_wnd = 65535;
    handler.connections[0].cubic.cwnd = (mss * 10) as u32;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    let snd_una = handler.connections[0].snd_una;

    // 3 dup ACKs → enter recovery.
    for i in 0..3 {
        let dup = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, snd_una, flags::ACK, 65535, &[]);
        let dup_len = dup.len();
        handler.process_ipv4(Frame::new(10 + i, leak(dup), dup_len, false), &nh, &mut free, &mut rx, &mut tx);
    }

    assert!(handler.connections[0].recovery.in_recovery);
    // cwnd should be reduced (CUBIC beta=0.7).
    let cwnd = handler.connections[0].cubic.cwnd;
    assert!(cwnd < (mss * 10) as u32, "cwnd reduced after loss");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p voidnet limited_transmit_sends prr_gates_sending`
Expected: FAIL

**Step 3: Integrate Limited Transmit and PRR into poll_send**

In `poll_send` (~line 2237), update the send budget calculation:

```rust
// Compute how many bytes we can send.
let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;

let can_send = if tcb.recovery.in_recovery {
    // During recovery: use pipe + PRR to gate sending.
    tcb.recovery.set_pipe(
        tcb.snd_una,
        tcb.snd_nxt,
        &tcb.sack_scoreboard,
        tcb.eff_snd_mss,
    );
    let pipe = tcb.recovery.pipe as usize;
    let cwnd = tcb.cubic.cwnd as usize;
    if pipe < cwnd {
        // PRR determines actual budget.
        // Note: prr.on_ack was already called in ACK processing.
        (cwnd - pipe).min(tcb.eff_snd_mss as usize)
    } else {
        0
    }
} else {
    let send_window = (tcb.snd_wnd as usize).min(tcb.cubic.cwnd as usize);
    let mut budget = send_window.saturating_sub(bytes_in_flight);
    // Limited Transmit (RFC 3042): on 1st/2nd dup ACK, allow extra MSS.
    if tcb.recovery.dup_ack_count > 0
        && tcb.recovery.dup_ack_count <= 2
        && !tcb.recovery.in_recovery
    {
        budget += tcb.recovery.dup_ack_count as usize * tcb.eff_snd_mss as usize;
    }
    budget
};
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): integrate Limited Transmit (RFC 3042) and PRR (RFC 6937) into poll_send"
```

---

### Task 11: Final pass — update MSS after negotiation and verify all tests

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` — SYN-ACK processing (where eff_snd_mss is finalized)

After MSS negotiation completes (SYN-ACK received in SynSent, or ACK in SynReceived), call `tcb.cubic.set_mss(tcb.eff_snd_mss)` to ensure CUBIC uses the negotiated MSS.

**Step 1: Find MSS negotiation sites**

Search for `eff_snd_mss` assignment in `mod.rs` — it's set during TCB construction and potentially updated when processing the SYN-ACK. Add `cubic.set_mss()` call after each site where `eff_snd_mss` is finalized.

**Step 2: Add the set_mss calls**

At each site where `tcb.eff_snd_mss` is set post-construction:

```rust
tcb.cubic.set_mss(tcb.eff_snd_mss);
```

**Step 3: Run full test suite**

Run: `cargo test`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "fix(tcp): sync CUBIC MSS after negotiation completes"
```
