# TCP Congestion Control & Loss Recovery Design

**Goal:** Replace basic Reno congestion control with CUBIC (RFC 9438) and add proper SACK-based loss recovery (RFC 6675), PRR (RFC 6937), Limited Transmit (RFC 3042), and F-RTO (RFC 5682).

**Scope:** Single-connection focus. No benchmarking infrastructure in this round. No connection table changes (defer HashMap until multi-connection).

---

## Approach

Concrete structs, no traits. Extract congestion and recovery logic into separate modules while keeping integration in `mod.rs`. No dynamic dispatch — if/when BBR is added, the interface will differ enough to warrant redesign.

## File Structure

```
src/net/handler/tcp/
├── congestion.rs      # CubicState
├── recovery.rs        # SackRecovery + PrrState + FRtoState
├── mod.rs             # existing — calls into congestion/recovery
├── tcb.rs             # replace cwnd/ssthresh/dup_ack_count with new structs
└── ...existing...
```

**TCB changes:** Replace `cwnd: u32, ssthresh: u32, dup_ack_count: u8` with `cubic: CubicState`, `recovery: SackRecovery`, `prr: PrrState`, `frto: FRtoState`.

---

## CubicState (`congestion.rs`)

### Fields

- `cwnd: u32` — congestion window (bytes)
- `ssthresh: u32` — slow start threshold
- `w_max: u32` — window before last reduction
- `w_max_prev: u32` — previous w_max (for fast convergence)
- `epoch_start: Option<Instant>` — time of last loss event
- `k: f64` — time to reach w_max (seconds)
- `origin_point: u32` — W_max used in current epoch
- `tcp_cwnd: u32` — Reno-friendly estimate (TCP friendliness)
- `ack_count: u32` — bytes ACKed in current congestion avoidance round
- `eff_mss: u16` — cached MSS for calculations
- `cwnd_before_rto: Option<u32>` — saved for F-RTO restoration
- `ssthresh_before_rto: Option<u32>` — saved for F-RTO restoration

### Methods

- `on_ack(bytes_acked: u32, now: Instant, rtt: u64)` — slow start or CUBIC window update
- `on_loss()` — multiplicative decrease (beta=0.7), save w_max, compute K
- `on_rto()` — save cwnd/ssthresh for F-RTO, ssthresh = cwnd * 0.7, cwnd = 1 MSS
- `on_ecn()` — same as on_loss()
- `restore_after_spurious_rto()` — restore cwnd/ssthresh from saved values

### CUBIC Algorithm (RFC 9438 section 5)

**Window function:** `W_cubic(t) = C * (t - K)^3 + W_max`
- `C = 0.4`, `beta = 0.7`
- `K = cbrt(W_max * (1 - beta) / C)` = `cbrt(W_max * 0.3 / 0.4)`

**On loss/ECN:**
- `W_max = cwnd`
- `ssthresh = cwnd * 0.7`
- `cwnd = ssthresh`
- Compute K, reset epoch_start

**On ACK (not in recovery):**
- If `cwnd < ssthresh`: slow start — `cwnd += MSS` per ACK
- Else: compute `W_cubic(t)` and `W_est(t)`, `cwnd = max(W_cubic, W_est)`
- `W_est = W_max * beta + 3 * (1 - beta) / (1 + beta) * t / RTT`

**On RTO:**
- Save cwnd/ssthresh for F-RTO
- `ssthresh = cwnd * 0.7`, `cwnd = 1 MSS`
- Clear epoch

**Fast convergence (section 5.8):** If `W_max < W_max_prev`, set `W_max = W_max * (1 + beta) / 2`. Helps flows converge to fairness.

**Implementation notes:**
- Cube root via `f64::cbrt()` — called once per loss, not per ACK
- Time from `now: Instant` parameter, never `Instant::now()`
- All window values in bytes
- `cwnd` floor: 1 MSS

---

## SackRecovery (`recovery.rs`)

### Fields

- `in_recovery: bool`
- `recovery_point: u32` — snd_nxt at entry
- `pipe: u32` — estimated bytes in network
- `dup_ack_count: u8`

### Methods

- `enter(snd_nxt: u32)` — set in_recovery, recovery_point
- `exit()` — clear state
- `on_ack(seg_ack: u32) -> bool` — returns true if recovery exits (seg_ack >= recovery_point)
- `is_lost(seq: u32, sack_scoreboard: &BTreeMap<u32, u32>, eff_mss: u16) -> bool` — RFC 6675 section 4
- `set_pipe(snd_una: u32, snd_nxt: u32, sack_scoreboard: &BTreeMap<u32, u32>, eff_mss: u16)` — RFC 6675 section 4.1

### IsLost Predicate (RFC 6675 section 4)

A segment at `seq` is lost if:
- 3+ segments with higher sequence numbers are SACKed, OR
- The segment is `3 * MSS` bytes below the highest SACKed sequence

### SetPipe (RFC 6675 section 4.1)

Iterate MSS-sized blocks from snd_una to snd_nxt:
- If SACKed: skip
- If IsLost: skip (will retransmit)
- Else: pipe += MSS

### Recovery Loop (RFC 6675 section 5.1)

Runs in poll_timers and on each ACK during recovery:
1. SetPipe()
2. While pipe < cwnd:
   - If lost segment exists: retransmit, pipe += MSS
   - Else if new unsent data: send, pipe += MSS
   - Else: break

### Partial ACK Handling

ACK advances snd_una but below recovery_point — stay in recovery, SetPipe again, continue retransmitting.

---

## PrrState (`recovery.rs`)

### Fields

- `prr_delivered: u32`
- `prr_out: u32`
- `recover_fs: u32` — FlightSize at recovery entry

### Methods

- `enter(bytes_in_flight: u32)` — set recover_fs, zero counters
- `on_ack(bytes_newly_delivered: u32, pipe: u32, ssthresh: u32, eff_mss: u16) -> u32` — returns snd_cnt

### Algorithm (RFC 6937)

On each ACK during recovery:
- `prr_delivered += bytes_newly_acked + bytes_newly_sacked`
- If `pipe > ssthresh`: `snd_cnt = ceil(prr_delivered * ssthresh / recover_fs) - prr_out`
- If `pipe <= ssthresh`: `snd_cnt = min(ssthresh - pipe, prr_delivered - prr_out + MSS)`
- Floor: `snd_cnt = max(snd_cnt, 0)`
- After sending: `prr_out += bytes_sent`

---

## FRtoState (`recovery.rs`)

### Fields

- `state: FRtoPhase` — enum { Disabled, Step1, Step2 }
- `snd_una_at_rto: u32`

### State Machine (RFC 5682)

```
Disabled -> Step1    (on RTO retransmit)
Step1    -> Step2    (first ACK advances snd_una: send new data, not retransmits)
Step1    -> Disabled (first ACK is dup: genuine loss)
Step2    -> Disabled (second ACK advances snd_una: spurious RTO, restore cwnd)
Step2    -> Disabled (second ACK is dup: genuine loss)
```

On spurious detection: call `cubic.restore_after_spurious_rto()`.

---

## Integration Points in mod.rs

### ACK Processing (~line 1468)

**New ACK (advances snd_una):**
1. `recovery.on_ack(seg_ack)` — check if exiting recovery
2. If in recovery: `prr.on_ack(...)` for send budget, `recovery.set_pipe(...)` to update pipe
3. If not in recovery: `cubic.on_ack(bytes_acked, now)` — replaces lines 1486-1492
4. RTT measurement unchanged
5. SACK scoreboard parsing unchanged

**Duplicate ACK:**
1. `recovery.dup_ack_count += 1`
2. Limited Transmit: on count 1 or 2, allow 1 MSS new data in poll_send
3. On count == 3: `recovery.enter(snd_nxt)`, `prr.enter(bytes_in_flight)`, `cubic.on_loss()`

**ECN:** `cubic.on_ecn()` replaces inline halving (~line 1567).

### Fast Retransmit (~line 1948)

Replace current block:
1. Check `recovery.in_recovery` instead of `dup_ack_count >= 3`
2. `recovery.is_lost(seq, scoreboard)` to pick retransmit target
3. Gate on `recovery.pipe < cubic.cwnd`
4. After sending: `recovery.pipe += bytes`, `prr.prr_out += bytes`
5. Send new data if pipe < cwnd and no more lost segments

### RTO Retransmit (~line 2029)

1. `frto.enter(snd_una)`
2. `cubic.on_rto()` — saves cwnd/ssthresh, resets
3. `recovery.exit()` — clear recovery state and scoreboard
4. First ACK after RTO: F-RTO decides genuine vs spurious

### poll_send (~line 2229)

- In recovery: use `min(prr.snd_cnt, cwnd - pipe)` as send budget
- Not in recovery: `send_window = min(snd_wnd, cubic.cwnd)` (same as current but from cubic)
- Limited Transmit: if dup_ack_count in [1, 2], add `dup_ack_count * MSS` to effective budget

---

## Testing

All tests use existing `build_tcp_frame` / `TcpHandler` unit test infrastructure in `mod.rs`.

### CUBIC (unit tests on CubicState)

- `cubic_slow_start` — cwnd += MSS per ACK when below ssthresh
- `cubic_on_loss` — W_max saved, ssthresh = cwnd * 0.7, cwnd = ssthresh
- `cubic_on_rto` — cwnd = 1 MSS, ssthresh = cwnd * 0.7
- `cubic_congestion_avoidance` — after loss, cwnd follows cubic function, eventually exceeds W_max
- `cubic_tcp_friendliness` — cwnd >= W_est
- `cubic_fast_convergence` — W_max reduced when below previous W_max
- `cubic_beta_07_not_05` — verify beta = 0.7

### RFC 6675 (integration via handler)

- `sack_recovery_entry_on_3_dup_acks` — enters recovery, sets recovery_point
- `sack_recovery_is_lost_3_sacked_above` — IsLost correct with 3 SACKed segments beyond
- `sack_recovery_pipe_calculation` — SetPipe counts only in-flight bytes
- `sack_recovery_partial_ack_stays_in_recovery` — ACK advances but below recovery_point
- `sack_recovery_exit_on_full_ack` — ACK >= recovery_point exits recovery
- `sack_recovery_retransmits_lost_before_new` — lost segments prioritized

### PRR

- `prr_proportional_when_pipe_above_ssthresh` — snd_cnt tracks delivery rate
- `prr_slow_start_reduction_when_pipe_below` — converges to ssthresh

### Limited Transmit

- `limited_transmit_sends_on_first_dup_ack` — 1 MSS on dup_ack 1
- `limited_transmit_sends_on_second_dup_ack` — 1 MSS on dup_ack 2
- `limited_transmit_stops_at_third` — no extra send on 3rd

### F-RTO

- `frto_spurious_rto_restores_cwnd` — RTO -> advancing ACKs -> cwnd restored
- `frto_genuine_loss_keeps_reduced_cwnd` — RTO -> dup ACK -> normal loss behavior
