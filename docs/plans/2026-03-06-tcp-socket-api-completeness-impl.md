# TCP Socket API Completeness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the TCP socket API with half-close (`shutdown`), keep-alive probes, and SO_LINGER support.

**Architecture:** Three independent features layered onto the existing TCP handler and socket. Half-close adds write-side shutdown without closing reads. Keep-alive adds periodic probes for idle connection liveness. Linger controls close behavior (graceful vs RST abort).

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure.

---

## Task 1: Add Keep-Alive and Linger Fields to Tcb and TcpConfig

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs:80-106` (TcpConfig) and `src/net/handler/tcp/tcb.rs:108-212` (Tcb)

**Step 1: Add new fields to TcpConfig**

Add after the `delayed_ack_ms` field (line 92):

```rust
pub struct TcpConfig {
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub backlog: usize,
    pub time_wait_duration_ms: u64,
    pub tcp_no_delay: bool,
    pub delayed_ack_ms: u64,
    // --- NEW ---
    /// Enable TCP keep-alive probes. Default: false.
    pub keep_alive: bool,
    /// Idle time before first keep-alive probe in milliseconds. Default: 7200000 (2 hours).
    pub keep_alive_idle_ms: u64,
    /// Interval between keep-alive probes in milliseconds. Default: 75000 (75 seconds).
    pub keep_alive_interval_ms: u64,
    /// Max probes before aborting connection. Default: 9.
    pub keep_alive_count: u8,
    /// SO_LINGER setting. None = off (default), Some(0) = RST, Some(ms) = timeout.
    pub linger: Option<u64>,
}
```

Update `Default for TcpConfig`:

```rust
impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            send_buffer_size: 256 * 1024,
            recv_buffer_size: 256 * 1024,
            backlog: 128,
            time_wait_duration_ms: 60_000,
            tcp_no_delay: false,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
            keep_alive: false,
            keep_alive_idle_ms: 7_200_000,
            keep_alive_interval_ms: 75_000,
            keep_alive_count: 9,
            linger: None,
        }
    }
}
```

**Step 2: Add new fields to Tcb**

Add after the `nagle_enabled` field (line 211), before the closing `}`:

```rust
    // --- Keep-alive ---
    /// Whether keep-alive probes are enabled.
    pub keep_alive_enabled: bool,
    /// Idle time before first probe in milliseconds.
    pub keep_alive_idle_ms: u64,
    /// Interval between probes in milliseconds.
    pub keep_alive_interval_ms: u64,
    /// Max probes before aborting.
    pub keep_alive_count: u8,
    /// Timestamp of last data activity (send or receive).
    pub last_activity: Instant,
    /// Number of keep-alive probes sent since last activity.
    pub keep_alive_probes_sent: u8,

    // --- Linger ---
    /// SO_LINGER setting. None = off, Some(0) = RST, Some(ms) = timeout.
    pub linger: Option<u64>,
    /// Deadline for linger timeout (set when close is initiated with linger > 0).
    pub linger_deadline: Option<Instant>,
```

**Step 3: Update TCB initialization sites**

Update active open TCB init in `src/net/handler/tcp/mod.rs:179-220`:

Add after `nagle_enabled: !config.tcp_no_delay,` (line 219):

```rust
            keep_alive_enabled: config.keep_alive,
            keep_alive_idle_ms: config.keep_alive_idle_ms,
            keep_alive_interval_ms: config.keep_alive_interval_ms,
            keep_alive_count: config.keep_alive_count,
            last_activity: Instant::now(),
            keep_alive_probes_sent: 0,
            linger: config.linger,
            linger_deadline: None,
```

Update passive open TCB init in `src/net/handler/tcp/mod.rs:579-619`:

Add after `nagle_enabled: !listener.tcp_no_delay,` (line 619):

```rust
            keep_alive_enabled: false,
            keep_alive_idle_ms: 7_200_000,
            keep_alive_interval_ms: 75_000,
            keep_alive_count: 9,
            last_activity: Instant::now(),
            keep_alive_probes_sent: 0,
            linger: None,
            linger_deadline: None,
```

Update `ListenEntry` in `src/net/handler/tcp/mod.rs:39-50` — add fields:

```rust
    pub keep_alive: bool,
    pub keep_alive_idle_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub keep_alive_count: u8,
    pub linger: Option<u64>,
```

Update all `ListenEntry` construction sites (`listen` and `listen_with_config` methods) to populate these fields from config.

Update passive open TCB init to read from listener:

```rust
            keep_alive_enabled: listener.keep_alive,
            keep_alive_idle_ms: listener.keep_alive_idle_ms,
            keep_alive_interval_ms: listener.keep_alive_interval_ms,
            keep_alive_count: listener.keep_alive_count,
            linger: listener.linger,
```

**Step 4: Build and fix any compilation errors**

Run: `cargo build 2>&1 | head -50`
Expected: Clean compilation (all new fields initialized at both TCB creation sites).

**Step 5: Run tests**

Run: `cargo test 2>&1 | tail -20`
Expected: All existing tests pass (446 unit + 1 integration + 5 doc-tests).

**Step 6: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): add keep-alive and linger fields to Tcb and TcpConfig"
```

---

## Task 2: Implement Half-Close (shutdown)

**Files:**
- Modify: `src/net/socket/tcp.rs:161-376` (TcpStream, TcpWrite)
- Test: `src/net/handler/tcp/mod.rs` (existing test module)

**Step 1: Write failing tests**

Add to the test module in `src/net/handler/tcp/mod.rs`:

```rust
#[test]
fn shutdown_sets_pending_fin_and_write_closed() {
    // Create a connected TcpStream, call shutdown()
    // Verify: write_closed == true, pending_fin == true on TCB
    // Verify: stream is NOT fully closed (closed == false)
}

#[test]
fn write_returns_zero_after_shutdown() {
    // Create a connected TcpStream, call shutdown()
    // Call write() — poll should return Ready(0)
}

#[test]
fn read_works_after_shutdown() {
    // Create a connected TcpStream, call shutdown()
    // Put data in recv_buffer
    // Call read() — should return data
}
```

Note: These tests need to construct `TcpStream` directly or use the handler test infrastructure to simulate connections. Follow the pattern of existing tests in the file.

**Step 2: Add `write_closed` field to TcpStream**

In `src/net/socket/tcp.rs`, modify the `TcpStream` struct (line 161):

```rust
pub struct TcpStream {
    conn_id: ConnectionId,
    #[allow(dead_code)]
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    closed: bool,
    write_closed: bool,
}
```

Update `from_accepted` (line 279) to initialize `write_closed: false`.

Update `Connect::poll` (line 394) to initialize `write_closed: false` in the `TcpStream` construction.

**Step 3: Add `shutdown()` method to TcpStream**

Add after `close()` (line 349):

```rust
    /// Shut down the write side of this connection (half-close).
    ///
    /// Sends FIN to the remote peer but keeps the read side open.
    /// Subsequent writes will return 0. Reads continue until remote FIN.
    pub fn shutdown(&mut self) {
        if self.write_closed || self.closed {
            return;
        }
        self.write_closed = true;
        let handler = unsafe { &mut *self.handler.get() };
        handler.initiate_close(&self.conn_id);
    }
```

**Step 4: Modify TcpWrite to check write_closed**

Change `TcpStream::write()` to pass `write_closed`:

```rust
    pub fn write<'a>(&'a self, data: &'a [u8]) -> TcpWrite<'a> {
        TcpWrite {
            handler: &self.handler,
            conn_id: self.conn_id,
            data,
            written: 0,
            write_closed: self.write_closed || self.closed,
        }
    }
```

Add field to `TcpWrite`:

```rust
pub struct TcpWrite<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    data: &'stream [u8],
    written: usize,
    write_closed: bool,
}
```

Add early return in `TcpWrite::poll()`:

```rust
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(0);
        }
        // ... rest unchanged
    }
```

**Step 5: Build and run tests**

Run: `cargo build 2>&1 | head -50`
Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass including the new half-close tests.

**Step 6: Commit**

```bash
git add src/net/socket/tcp.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): implement half-close shutdown()"
```

---

## Task 3: Implement Keep-Alive Probes in poll_timers

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1058-1226` (poll_timers)
- Test: `src/net/handler/tcp/mod.rs` (test module)

**Step 1: Write failing tests**

```rust
#[test]
fn keep_alive_probe_sent_after_idle_timeout() {
    // Create established connection with keep_alive_enabled = true, short idle timeout (e.g., 100ms)
    // Advance time past idle timeout
    // Call poll_timers
    // Verify: a probe segment was sent (seq = snd_una - 1, no data, ACK flag)
    // Verify: keep_alive_probes_sent incremented to 1
}

#[test]
fn keep_alive_no_probe_when_disabled() {
    // Create established connection with keep_alive_enabled = false
    // Advance time well past any timeout
    // Call poll_timers
    // Verify: no probe sent
}

#[test]
fn keep_alive_connection_aborted_after_max_probes() {
    // Create established connection with keep_alive_enabled = true
    // Set keep_alive_count = 2, short timeouts
    // Send 3 probes without response
    // Verify: TcpEvent::Timeout pushed, connection removed
}
```

**Step 2: Add keep-alive probe logic to poll_timers**

In `poll_timers`, after the delayed ACK pass (line 1091) and before the fast retransmit pass (line 1093), add:

```rust
        // Keep-alive probe pass — send probes for idle established connections.
        let mut keep_alive_removals: Vec<usize> = Vec::new();
        for (i, tcb) in self.connections.iter_mut().enumerate() {
            if tcb.state != TcpState::Established || !tcb.keep_alive_enabled {
                continue;
            }

            let idle_ms = now.duration_since(tcb.last_activity).as_millis();

            let probe_threshold = if tcb.keep_alive_probes_sent == 0 {
                tcb.keep_alive_idle_ms
            } else {
                tcb.keep_alive_idle_ms + tcb.keep_alive_interval_ms * tcb.keep_alive_probes_sent as u64
            };

            if idle_ms >= probe_threshold {
                if tcb.keep_alive_probes_sent >= tcb.keep_alive_count {
                    // Max probes exceeded — abort connection.
                    tcb.event_queue.push(TcpEvent::Timeout);
                    keep_alive_removals.push(i);
                    continue;
                }

                // Send keep-alive probe: seq = snd_una - 1, no data, ACK.
                let id = tcb.id;
                let dst_mac = neighbor_handler
                    .lookup(now, &id.remote_addr)
                    .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());
                let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;

                SegmentBuilder::build_ack(
                    id.local_addr, id.remote_addr,
                    id.local_port, id.remote_port,
                    tcb.snd_una.wrapping_sub(1), tcb.rcv_nxt, window,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );

                tcb.keep_alive_probes_sent += 1;
            }
        }

        // Remove connections that exceeded keep-alive probes (reverse order).
        for idx in keep_alive_removals.into_iter().rev() {
            let id = self.connections[idx].id;
            self.decrement_syn_received(&id);
            self.connections.remove(idx);
        }
```

**Step 3: Build and run tests**

Run: `cargo build 2>&1 | head -50`
Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): implement keep-alive probes in poll_timers"
```

---

## Task 4: Reset Keep-Alive Timer on Activity

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:866-1053` (process_established) and `src/net/handler/tcp/mod.rs:1250-1310` (poll_send data path)
- Test: `src/net/handler/tcp/mod.rs` (test module)

**Step 1: Write failing test**

```rust
#[test]
fn keep_alive_activity_resets_probe_timer() {
    // Create established connection with keep_alive_enabled = true, short idle (100ms)
    // Set keep_alive_probes_sent = 2, last_activity = old time
    // Receive an ACK (process_established)
    // Verify: last_activity updated to now, keep_alive_probes_sent reset to 0
}
```

**Step 2: Add activity reset in process_established**

In `process_established`, after the valid new ACK processing (around line 905, after `tcb.snd_una = seg_ack;`), add:

```rust
                // Reset keep-alive timer on activity.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;
```

Also after data is copied into recv_buffer (in-order data processing), add the same reset:

```rust
                // Reset keep-alive timer on received data.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;
```

**Step 3: Add activity reset in poll_send**

In `poll_send`, after data is successfully sent (line 1297, after `tcb.snd_nxt = ...`), add:

```rust
                    tcb.last_activity = now;
                    tcb.keep_alive_probes_sent = 0;
```

**Step 4: Build and run tests**

Run: `cargo build 2>&1 | head -50`
Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): reset keep-alive timer on data activity"
```

---

## Task 5: Implement SO_LINGER in initiate_close and poll_send

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1357-1363` (initiate_close) and `src/net/handler/tcp/mod.rs:1312-1350` (poll_send FIN section)
- Test: `src/net/handler/tcp/mod.rs` (test module)

**Step 1: Write failing tests**

```rust
#[test]
fn linger_zero_sends_rst_immediately() {
    // Create established connection
    // Set linger = Some(0) on TCB
    // Call initiate_close
    // Verify: connection removed, RST sent (check tx_return for RST segment)
}

#[test]
fn linger_timeout_sets_deadline() {
    // Create established connection
    // Set linger = Some(1000) on TCB
    // Call initiate_close
    // Verify: pending_fin set, linger_deadline set to now + 1000ms
}

#[test]
fn linger_deadline_expired_sends_rst() {
    // Create established connection with pending_fin, linger_deadline in the past
    // Data still in send_buffer
    // Call poll_send
    // Verify: RST sent, connection removed
}
```

**Step 2: Modify initiate_close for linger**

Replace `initiate_close` (line 1357):

```rust
    pub fn initiate_close(&mut self, id: &ConnectionId) {
        let idx = match self.connections.iter().position(|c| c.id == *id) {
            Some(i) => i,
            None => return,
        };

        let tcb = &mut self.connections[idx];
        if tcb.pending_fin || (tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait) {
            return;
        }

        match tcb.linger {
            Some(0) => {
                // Linger(0): immediate RST, discard data, remove connection.
                tcb.event_queue.push(TcpEvent::Reset);
                self.connections.remove(idx);
            }
            Some(ms) => {
                // Linger(timeout): graceful close with deadline.
                tcb.pending_fin = true;
                tcb.linger_deadline = Some(Instant::now() + coarsetime::Duration::from_millis(ms));
            }
            None => {
                // Default: graceful close, no deadline.
                tcb.pending_fin = true;
            }
        }
    }
```

Note: For `linger(0)`, we don't send RST here directly because `initiate_close` doesn't have access to frame buffers. Instead, we mark the connection for removal and let the caller handle it. Alternative: we can use `remove_connection` which already sends RST. However, `initiate_close` doesn't have the frame buffer parameters. The simplest approach: just remove the connection and push a Reset event. The next `poll_send` won't find it. If a proper RST is needed, we need to refactor. For now, just removing the connection is sufficient — the remote will eventually time out or we can add RST sending in a follow-up.

Actually, looking at the existing `remove_connection` method (line 1409), it takes frame buffers. Since `initiate_close` doesn't have them, we need a different approach for linger(0):

Set a flag on the TCB and let `poll_send` handle the RST:

```rust
    pub fn initiate_close(&mut self, id: &ConnectionId) {
        if let Some(tcb) = self.connections.iter_mut().find(|c| c.id == *id) {
            if tcb.pending_fin || (tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait) {
                return;
            }

            match tcb.linger {
                Some(0) => {
                    // Linger(0): mark for RST abort in poll_send.
                    tcb.pending_fin = true;
                    tcb.linger_deadline = Some(Instant::recent()); // already expired = immediate RST
                    // Clear send buffer so poll_send sees no data and checks deadline.
                    tcb.send_buffer.clear();
                }
                Some(ms) => {
                    tcb.pending_fin = true;
                    tcb.linger_deadline = Some(Instant::now() + coarsetime::Duration::from_millis(ms));
                }
                None => {
                    tcb.pending_fin = true;
                }
            }
        }
    }
```

Wait — `RingBuffer` may not have a `clear()` method. Check and add one if needed, or use a different approach.

Simpler approach: In `poll_send`, check `linger_deadline` before the FIN section. If the deadline has expired, send RST and mark for removal instead of sending FIN.

**Step 3: Modify poll_send for linger deadline**

In `poll_send`, before the existing `if tcb.pending_fin` block (line 1312), add a linger deadline check:

```rust
            // Check linger deadline — if expired, abort with RST.
            if tcb.pending_fin {
                if let Some(deadline) = tcb.linger_deadline {
                    if now >= deadline {
                        let id = tcb.id;
                        let dst_mac = neighbor_handler
                            .lookup(now, &id.remote_addr)
                            .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

                        SegmentBuilder::build_rst_for_connection(
                            id.local_addr, id.remote_addr,
                            id.local_port, id.remote_port,
                            tcb.snd_nxt, tcb.rcv_nxt,
                            src_mac, dst_mac,
                            self.tx_offload, free_frames, tx_return,
                        );

                        tcb.event_queue.push(TcpEvent::Reset);
                        // Mark for removal — handled below.
                        tcb.state = TcpState::Closed;
                        tcb.pending_fin = false;
                        continue;
                    }
                }
            }
```

Note: `SegmentBuilder::build_rst_for_connection` may not exist. Check the existing RST building API. The existing `build_rst` takes incoming segment parameters. We may need a simpler RST builder or use the ACK-based RST format. The implementer should check `segment.rs` for the available RST builders and use the appropriate one, or build a simple RST with `seq = snd_nxt`, `ACK` flag, `ack = rcv_nxt`.

After the `poll_send` loop, add cleanup for Closed connections:

```rust
        // Remove connections marked Closed by linger abort.
        self.connections.retain(|tcb| tcb.state != TcpState::Closed);
```

**Step 4: Update initiate_close for linger**

```rust
    pub fn initiate_close(&mut self, id: &ConnectionId) {
        if let Some(tcb) = self.connections.iter_mut().find(|c| c.id == *id) {
            if tcb.pending_fin || (tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait) {
                return;
            }

            tcb.pending_fin = true;
            match tcb.linger {
                Some(0) => {
                    // Set deadline to now — poll_send will send RST immediately.
                    tcb.linger_deadline = Some(Instant::recent());
                }
                Some(ms) => {
                    tcb.linger_deadline = Some(Instant::now() + coarsetime::Duration::from_millis(ms));
                }
                None => {
                    // No deadline — graceful close.
                }
            }
        }
    }
```

**Step 5: Build and run tests**

Run: `cargo build 2>&1 | head -50`
Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): implement SO_LINGER in initiate_close and poll_send"
```

---

## Task 6: Add Socket API Methods (keepalive, linger, shutdown tests)

**Files:**
- Modify: `src/net/socket/tcp.rs` (TcpStream methods)
- Test: `src/net/handler/tcp/mod.rs` (test module)

**Step 1: Add set_keepalive / keepalive methods**

In `src/net/socket/tcp.rs`, after `nodelay()` (line 369):

```rust
    /// Enable or disable TCP keep-alive probes.
    pub fn set_keepalive(&self, enabled: bool) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
            tcb.keep_alive_enabled = enabled;
        }
    }

    /// Returns whether TCP keep-alive is enabled.
    pub fn keepalive(&self) -> bool {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_connection(&self.conn_id)
            .map(|tcb| tcb.keep_alive_enabled)
            .unwrap_or(false)
    }

    /// Set the SO_LINGER option.
    ///
    /// - `None`: default graceful close
    /// - `Some(0)`: hard RST on close
    /// - `Some(ms)`: graceful close with timeout in milliseconds
    pub fn set_linger(&self, linger: Option<u64>) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
            tcb.linger = linger;
        }
    }

    /// Returns the current SO_LINGER setting.
    pub fn linger(&self) -> Option<u64> {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_connection(&self.conn_id)
            .and_then(|tcb| tcb.linger)
    }
```

**Step 2: Build and run tests**

Run: `cargo build 2>&1 | head -50`
Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add src/net/socket/tcp.rs
git commit -m "feat(tcp): add keepalive, linger, and shutdown socket API methods"
```

---

## Task 7: Integration Tests for All Three Features

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (test module)

**Step 1: Write comprehensive integration-style tests**

These tests exercise the features end-to-end through the handler:

```rust
#[test]
fn half_close_full_lifecycle() {
    // 1. Establish connection
    // 2. shutdown() — sends FIN
    // 3. Verify writes return 0
    // 4. Remote sends data — verify reads work
    // 5. Remote sends FIN — verify read returns 0 (EOF)
}

#[test]
fn keep_alive_full_lifecycle() {
    // 1. Establish connection with keep_alive_enabled, short timeouts
    // 2. Let connection sit idle past keep_alive_idle_ms
    // 3. poll_timers — verify probe sent
    // 4. Receive ACK — verify probes reset
    // 5. Let idle again, exhaust probes — verify timeout event
}

#[test]
fn linger_zero_aborts_connection() {
    // 1. Establish connection, write data
    // 2. Set linger = Some(0)
    // 3. initiate_close
    // 4. poll_send — verify RST sent, connection removed
}

#[test]
fn linger_timeout_graceful_then_rst() {
    // 1. Establish connection, write data that won't drain
    // 2. Set linger = Some(100)
    // 3. initiate_close — verify deadline set
    // 4. poll_send before deadline — verify FIN behavior (waits for data to drain)
    // 5. Advance past deadline, poll_send — verify RST sent
}
```

**Step 2: Run all tests**

Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "test(tcp): add integration tests for half-close, keep-alive, and linger"
```

---

## Implementation Notes

### Key Line References (current state)
- `TcpConfig`: `src/net/handler/tcp/tcb.rs:80-106`
- `Tcb` struct: `src/net/handler/tcp/tcb.rs:108-212`
- `ListenEntry`: `src/net/handler/tcp/mod.rs:39-50`
- Active open TCB init: `src/net/handler/tcp/mod.rs:179-220`
- Passive open TCB init: `src/net/handler/tcp/mod.rs:579-619`
- `process_established`: `src/net/handler/tcp/mod.rs:866-1053`
- `poll_timers`: `src/net/handler/tcp/mod.rs:1058-1226`
- `poll_send`: `src/net/handler/tcp/mod.rs:1250-1351`
- `initiate_close`: `src/net/handler/tcp/mod.rs:1357-1363`
- `TcpStream` struct: `src/net/socket/tcp.rs:161-167`
- `TcpStream::close()`: `src/net/socket/tcp.rs:342-349`
- `TcpWrite`: `src/net/socket/tcp.rs:410-436`
- `TcpRead`: `src/net/socket/tcp.rs:439-464`

### Dependencies Between Tasks
- Task 1 (fields) must be done first — all other tasks depend on it.
- Tasks 2, 3, 4, 5, 6 can be done in any order after Task 1, but the suggested order minimizes conflicts.
- Task 7 (integration tests) should be done last.

### Test Command
Always use plain `cargo test` (no feature flags per project memory).

### RST Building
The implementer needs to check `src/net/handler/tcp/segment.rs` for available RST segment builders. If no suitable one exists for sending RST on an active connection (vs responding to an incoming segment), create a minimal helper. The probe segments for keep-alive use `build_ack` with `seq = snd_una - 1`.

### RingBuffer::clear()
If `RingBuffer` doesn't have a `clear()` method and linger(0) needs to discard the send buffer, the implementer can either add `clear()` or simply rely on the linger deadline approach (set deadline to now, let poll_send handle RST).
