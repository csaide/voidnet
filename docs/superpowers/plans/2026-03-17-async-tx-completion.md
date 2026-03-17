# Async TX Completion Drain — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the event loop's TX completion drain non-blocking so multi-queue performance scales with core count.

**Architecture:** Replace the synchronous completion drain in `LocalRuntime::run()` with an in-flight counter (`in_flight_tx`) that tracks frames in the kernel TX pipeline across iterations. Completions are collected opportunistically at the top of each iteration rather than blocking until all arrive.

**Tech Stack:** Rust, AF_XDP (libxdp-sys), XDP BPF

**Spec:** `docs/superpowers/specs/2026-03-17-async-tx-completion-design.md`

---

## File Map

- **Modify:** `src/rt/local.rs`
  - `LocalRuntime::run()` method (lines 297–475) — restructure event loop
  - Add `LocalRuntime::recycle_rx_return()` private helper method

No new files. No other files modified.

---

## Task 1: Rewrite the event loop (single commit)

All changes go into `src/rt/local.rs`. This adds the `recycle_rx_return` helper AND rewrites the event loop in one pass to avoid dead-code warnings.

**Files:**
- Modify: `src/rt/local.rs:290-475` — add helper method + restructure `run()`

- [ ] **Step 0: Add the `recycle_rx_return` helper method**

Insert this method on `LocalRuntime` between `new_worker()` (ends at line 290) and the `run()` doc comment (line 292). This is inside `impl<'umem> LocalRuntime<'umem>`:

```rust
    /// Drains `rx_return` completely: fill queue first (ring-limited), overflow
    /// to `free_frames`.
    ///
    /// # Frame Accounting
    ///
    /// Every frame in `rx_return` moves to exactly one destination:
    /// - `fill_queue` via `process_fill_queue`: frame leaves our accounting
    ///   (kernel RX path owns it).
    /// - `free_frames`: frame stays in our accounting (available for TX).
    ///
    /// The fill queue ring size naturally caps how many frames enter the kernel
    /// RX path. Overflow goes to `free_frames` to maintain TX capacity.
    ///
    /// After return: `rx_return.num_frames() == 0`.
    #[inline(always)]
    fn recycle_rx_return(&mut self) -> Result<()> {
        // Feed fill queue — ring size prevents overfilling.
        while self.rx_return.num_frames() > 0 {
            if self.umem.process_fill_queue(&mut self.rx_return).is_err() {
                break; // Fill ring full
            }
        }
        // Overflow to free_frames — available for TX packet building.
        while self.rx_return.num_frames() > 0 {
            self.free_frames.push(self.rx_return.pop().unwrap());
        }
        // Wake fill queue so kernel processes newly submitted addresses.
        self.umem.maybe_wake_fill_queue(self.socket.fd())
    }
```

- [ ] **Step 1: Replace init variables (line 323)**

Replace:
```rust
let expected_free_frames = self.free_frames.num_frames();
```

With:
```rust
let expected_total = self.free_frames.num_frames() as u32;
let mut in_flight_tx: u32 = 0;
```

- [ ] **Step 2: Add Phase 1 + Phase 2 at the top of the while loop (after line 338)**

Insert immediately after `while !exit.load(Ordering::Relaxed) {` and BEFORE the existing `// ---- Receive & Protocol Dispatch ----` section:

```rust
            // ---- Phase 1: Collect TX Completions (non-blocking) ----
            // Frames completed by the kernel since last iteration return to
            // rx_return. Runs BEFORE recv to maximize frame availability.
            // Note: in_flight_tx correctness depends on the socket/interface
            // remaining operational. ENETDOWN would leave it permanently
            // inflated, but that is a fatal condition for the event loop.
            loop {
                match self.umem.process_completion_queue(&mut self.rx_return) {
                    Ok(n) => {
                        debug_assert!(in_flight_tx >= n, "completion underflow: in_flight={in_flight_tx} completed={n}");
                        in_flight_tx -= n;
                    }
                    Err(_) => break,
                }
            }

            // ---- Phase 2: Recycle rx_return → fill queue + free_frames ----
            // rx_return contains: TX completions from Phase 1, plus
            // handler-returned frames from the PREVIOUS iteration.
            self.recycle_rx_return()?;
```

- [ ] **Step 3: Replace the entire Transmit & Frame Recycling section (lines 425–471)**

Delete everything from `// ---- Transmit & Frame Recycling ----` (line 425) through the three `debug_assert_eq!` lines (line 471), inclusive. This also removes the `expected_size`, `free_before`, and `received`-based recycling variables. Replace with:

```rust
            // ---- Transmit (non-blocking) ----
            // Note: free_before is captured HERE (before transmit/recycle), matching
            // the current code's placement. Capacity wakes detect frames freed by
            // the transmit cycle, not by Phase 1+2 completion recycling.
            let free_before = self.free_frames.num_frames();

            while self.tx_return.num_frames() > 0 {
                match self.socket.send(&mut self.tx_return) {
                    Ok(n) => in_flight_tx += n,
                    Err(_) => {
                        // TX ring full — kick kernel and try to free completions.
                        self.socket.maybe_wake()?;
                        loop {
                            match self.umem.process_completion_queue(&mut self.rx_return) {
                                Ok(n) => {
                                    debug_assert!(in_flight_tx >= n, "completion underflow: in_flight={in_flight_tx} completed={n}");
                                    in_flight_tx -= n;
                                }
                                Err(_) => break,
                            }
                        }
                        self.recycle_rx_return()?;
                        // Retry once after freeing ring slots.
                        match self.socket.send(&mut self.tx_return) {
                            Ok(n) => in_flight_tx += n,
                            Err(_) => break, // Still full — defer to next iteration.
                        }
                    }
                }
            }

            // ---- Recycle remaining rx_return ----
            // Drains whatever is left in rx_return. If all sends above succeeded,
            // this contains handler-returned RX frames from protocol dispatch.
            // If Phase 9 hit WouldBlock, mid-retry recycle already drained
            // those, so this is a no-op in that path.
            self.recycle_rx_return()?;

            // ---- Capacity-Driven Wakes ----
            // After frame recycling, wake any futures blocked on capacity.
            // Only wake if free_frames actually grew (i.e., outbound capacity was freed).
            if self.free_frames.num_frames() > free_before {
                main_waker.set_woken();
                crate::rt::context::with_runtime_context(|ctx| {
                    let wakers = unsafe { &mut *ctx.capacity_wakers.get() };
                    for waker in wakers.drain(..) {
                        waker.wake();
                    }
                });
            }

            // ---- Frame Accounting Invariant ----
            debug_assert_eq!(
                self.rx_return.num_frames(),
                0,
                "rx_return must be fully drained"
            );
            // Use <= rather than == because frames held by UdpHandler's
            // FragmentReader are outside our tracked variables. The deficit
            // equals fragments currently awaiting reassembly. This also
            // corrects a pre-existing gap in the old == assertion.
            let tracked = self.free_frames.num_frames() as u32
                + in_flight_tx
                + self.tx_return.num_frames() as u32;
            debug_assert!(
                tracked <= expected_total,
                "Frame leak: tracked={} (free={} in_flight={} tx_pending={}) > expected={}",
                tracked,
                self.free_frames.num_frames(),
                in_flight_tx,
                self.tx_return.num_frames(),
                expected_total,
            );
```

- [ ] **Step 4: Remove the now-unused `received` variable**

The old code bound `received` at line 340 and used it in the recycling section (line 446: `while self.rx_return.num_frames() > received as usize`). That recycling section is now deleted, so `received` is unused.

Replace the entire receive match block (lines 339–372) with this version that drops the count:

```rust
            // ---- Receive & Protocol Dispatch ----
            match self.socket.recv(&mut buffer) {
                Err(_) => {}
                Ok(_) => {
                    // SAFETY: single-threaded, no reentrant handler calls.
                    let udp_handler = unsafe { &mut *self.udp_handler.get() };
                    let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
                    let pmtu = unsafe { &mut *self.pmtu.get() };
                    let Self {
                        neighbor_handler,
                        ethernet_handler,
                        ipv4_handler,
                        ipv6_handler,
                        ..
                    } = self;

                    for frame in buffer.take_frames() {
                        ethernet_handler.handle(
                            frame,
                            ipv4_handler,
                            ipv6_handler,
                            udp_handler,
                            tcp_handler,
                            neighbor_handler,
                            pmtu,
                            now,
                            &mut self.free_frames,
                            &mut self.rx_return,
                            &mut self.tx_return,
                        );
                    }
                }
            }
```

The only change vs the original: `let received = match` → `match`, and `Ok(received) => {` → `Ok(_) => {`, and the `received` return at the bottom of the Ok arm is removed.

- [ ] **Step 5: Verify it compiles**

Run: `cargo check 2>&1 | tail -20`
Expected: compiles with no errors. There may be warnings about `_received` or unused variables — fix any that appear.

- [ ] **Step 6: Run the test suite**

Run: `cargo test 2>&1 | tail -30`
Expected: all existing tests pass. This change only modifies the event loop scheduling, not protocol logic or frame management APIs.

- [ ] **Step 7: Commit**

```bash
git add src/rt/local.rs
git commit -m "perf(rt): make TX completion drain non-blocking for multi-queue scaling

Replace the synchronous completion drain in LocalRuntime::run() with an
in-flight TX counter. Completions are collected opportunistically at the
top of each iteration rather than blocking until all arrive. This removes
the per-iteration kernel round-trip that was throttling multi-queue
throughput.

Key changes:
- Add in_flight_tx counter tracking frames in kernel TX pipeline
- Drain completions non-blocking at loop start (Phase 1)
- Send tx_return non-blocking with one retry on WouldBlock (Phase 9)
- Extract recycle_rx_return() helper (fill queue first, overflow to free_frames)
- Fix pre-existing invariant gap: use <= to account for FragmentReader frames

New invariant: free_frames + in_flight_tx + tx_return <= expected_total
(replaces strict free_frames == expected_free_frames)

Spec: docs/superpowers/specs/2026-03-17-async-tx-completion-design.md"
```

---

## Verification Checklist

After the commit, verify:

- [ ] `cargo check` — no errors, no warnings
- [ ] `cargo test` — all tests pass
- [ ] `cargo clippy` — no new lints
- [ ] Manual review: read the final `run()` method top-to-bottom and trace every frame path to confirm no frame is dropped without entering `rx_return`, `tx_return`, or `free_frames`
