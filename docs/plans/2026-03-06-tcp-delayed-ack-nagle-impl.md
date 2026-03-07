# TCP Delayed ACK + Nagle Algorithm Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add delayed ACK and Nagle algorithm to reduce per-segment overhead and small-packet floods.

**Architecture:** Four TCB fields (`ack_pending`, `delayed_ack_deadline`, `ack_delay_count`, `nagle_enabled`) gate ACK sending in `process_established` and data sending in `poll_send`. A new timer check in `poll_timers` flushes delayed ACKs. Config fields (`tcp_no_delay`, `delayed_ack_ms`) propagate through `TcpConfig` → `ListenEntry` → `Tcb`.

**Tech Stack:** Rust, coarsetime for timers.

---

### Dependency Graph

```
Task 1 (TCB + Config fields) ──> Task 2 (Delayed ACK) ──> Task 4 (Nagle)
                             ──> Task 3 (Delayed ACK timer)
                                                       ──> Task 5 (set_nodelay API)
```

Tasks 2 and 3 can be done in parallel after Task 1. Task 4 depends on Task 2 (needs `ack_pending` clearing in `poll_send`). Task 5 depends on Task 4.

---

### Task 1: Add TCB and Config Fields

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`
- Modify: `src/net/handler/tcp/mod.rs` (TCB initialization sites + ListenEntry)

**Context:**

The `Tcb` struct at `src/net/handler/tcp/tcb.rs:97` holds all per-connection state. There are two TCB initialization sites in `mod.rs`:
- Active open (connect): line ~175
- Passive open (SYN-RECEIVED): line ~570

`TcpConfig` at `tcb.rs:74` holds per-connection configuration. `ListenEntry` at `mod.rs:39` stores config values that get copied into passive-open TCBs.

**Step 1: Write the failing test**

Add to the test module in `src/net/handler/tcp/mod.rs`:

```rust
#[test]
fn new_connection_has_delayed_ack_fields() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Set up listener and complete handshake.
    let _accept = handler.listen(
        IpAddress::V4(LOCAL_IP), LOCAL_PORT, 128,
    ).unwrap();

    let syn = build_syn_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000);
    handler.process_ipv4_with_now(syn, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop(); // SYN-ACK

    let ack = build_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(ack, now, &NH, &mut free, &mut rx, &mut tx);

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };
    let tcb = handler.get_connection(&id).unwrap();
    assert!(!tcb.ack_pending);
    assert!(tcb.delayed_ack_deadline.is_none());
    assert_eq!(tcb.ack_delay_count, 0);
    assert!(tcb.nagle_enabled);
}
```

This test verifies the new fields exist and have correct defaults. It will fail because the fields don't exist yet.

**Step 2: Run test to verify it fails**

Run: `cargo test new_connection_has_delayed_ack_fields`
Expected: FAIL — no field `ack_pending` on type `Tcb`

**Step 3: Implement the fields**

In `src/net/handler/tcp/tcb.rs`:

Add constants after line 71 (`DEFAULT_RCV_WSCALE`):

```rust
/// Default delayed ACK timeout in milliseconds (RFC 9293 §4.2: < 500ms).
pub const DEFAULT_DELAYED_ACK_MS: u64 = 40;

/// Maximum consecutive unACKed segments before flushing (RFC 5681 §4.2).
pub const MAX_DELAYED_ACK_COUNT: u8 = 2;
```

Add fields to `TcpConfig` (after `time_wait_duration_ms` at line 82):

```rust
    /// If true, disable Nagle algorithm (send small segments immediately). Default: false.
    pub tcp_no_delay: bool,
    /// Maximum delay for ACKs in milliseconds. Default: 40.
    pub delayed_ack_ms: u64,
```

Update `TcpConfig::default()` to include:

```rust
            tcp_no_delay: false,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
```

Add fields to `Tcb` (after `time_wait_duration` at line 185):

```rust
    // --- Delayed ACK ---
    /// True when an ACK is owed but deferred.
    pub ack_pending: bool,
    /// Deadline for sending the deferred ACK.
    pub delayed_ack_deadline: Option<Instant>,
    /// Count of consecutive unACKed segments (flush at MAX_DELAYED_ACK_COUNT).
    pub ack_delay_count: u8,

    // --- Nagle algorithm ---
    /// When true, the Nagle algorithm gates small sends. Disabled by TCP_NODELAY.
    pub nagle_enabled: bool,
```

In `src/net/handler/tcp/mod.rs`:

Add to the import line 30 (the `use tcb::...` line), add `DEFAULT_DELAYED_ACK_MS`:

```rust
use tcb::{ConnectionId, Tcb, TcpConfig, TcpEvent, DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE, DEFAULT_DELAYED_ACK_MS};
```

Add fields to `ListenEntry` (after `time_wait_duration` at line 47):

```rust
    pub tcp_no_delay: bool,
    pub delayed_ack_ms: u64,
```

Update `listen_with_config` (after `time_wait_duration: config.time_wait_duration_ms` at line 109):

```rust
            tcp_no_delay: config.tcp_no_delay,
            delayed_ack_ms: config.delayed_ack_ms,
```

Update the active-open TCB init (connect, after `time_wait_duration` at line 210):

```rust
            ack_pending: false,
            delayed_ack_deadline: None,
            ack_delay_count: 0,
            nagle_enabled: !config.tcp_no_delay,
```

Update the passive-open TCB init (SYN-RECEIVED, after `time_wait_duration` at line 605):

```rust
            ack_pending: false,
            delayed_ack_deadline: None,
            ack_delay_count: 0,
            nagle_enabled: !listener.tcp_no_delay,
```

Note: For the passive-open TCB, the values come from `listener.tcp_no_delay` and `listener.delayed_ack_ms`. The `delayed_ack_ms` is used when setting the deadline (Task 2), not at init time.

**Step 4: Run test to verify it passes**

Run: `cargo test new_connection_has_delayed_ack_fields`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/mod.rs
git commit -m "feat: add delayed ACK and Nagle fields to TCB and TcpConfig"
```

---

### Task 2: Delayed ACK in process_established

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (process_established method + ListenEntry for delayed_ack_ms propagation)

**Context:**

Currently `process_established` (around line 860) sends an immediate ACK for every in-order data segment (line ~965). We need to change this to set `ack_pending` instead, and only send immediate ACKs for out-of-order data, duplicate data, and FIN.

The `process_established` method receives `now: Instant` as a parameter, which we use to compute the deadline.

The delayed ACK timeout value needs to be stored on the TCB so it can be checked in `poll_timers`. Add `delayed_ack_ms: u64` to the TCB, initialized from config/listener.

**Step 1: Write the failing tests**

Add to the test module in `src/net/handler/tcp/mod.rs`:

```rust
#[test]
fn delayed_ack_defers_ack_for_in_order_data() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), LOCAL_PORT, 128).unwrap();
    let syn = build_syn_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000);
    handler.process_ipv4_with_now(syn, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop(); // SYN-ACK
    let ack = build_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(ack, now, &NH, &mut free, &mut rx, &mut tx);

    // Send in-order data — should NOT produce an immediate ACK.
    let data = build_data_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1, b"hello");
    handler.process_ipv4_with_now(data, now, &NH, &mut free, &mut rx, &mut tx);

    assert_eq!(tx.num_frames(), 0, "delayed ACK should not send immediately");

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };
    let tcb = handler.get_connection(&id).unwrap();
    assert!(tcb.ack_pending);
    assert!(tcb.delayed_ack_deadline.is_some());
    assert_eq!(tcb.ack_delay_count, 1);
}

#[test]
fn delayed_ack_flushes_on_second_segment() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), LOCAL_PORT, 128).unwrap();
    let syn = build_syn_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000);
    handler.process_ipv4_with_now(syn, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop();
    let ack = build_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(ack, now, &NH, &mut free, &mut rx, &mut tx);

    // First data segment — deferred.
    let data1 = build_data_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1, b"hello");
    handler.process_ipv4_with_now(data1, now, &NH, &mut free, &mut rx, &mut tx);
    assert_eq!(tx.num_frames(), 0);

    // Second data segment — triggers immediate ACK (ack_delay_count >= 2).
    let data2 = build_data_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1006, 1, b"world");
    handler.process_ipv4_with_now(data2, now, &NH, &mut free, &mut rx, &mut tx);
    assert_eq!(tx.num_frames(), 1, "second segment should flush ACK");

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };
    let tcb = handler.get_connection(&id).unwrap();
    assert!(!tcb.ack_pending);
    assert_eq!(tcb.ack_delay_count, 0);
}

#[test]
fn out_of_order_data_sends_immediate_ack() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), LOCAL_PORT, 128).unwrap();
    let syn = build_syn_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000);
    handler.process_ipv4_with_now(syn, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop();
    let ack = build_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(ack, now, &NH, &mut free, &mut rx, &mut tx);

    // Send out-of-order data (skip seq 1001, send 1006).
    let data = build_data_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1006, 1, b"world");
    handler.process_ipv4_with_now(data, now, &NH, &mut free, &mut rx, &mut tx);

    // Out-of-order MUST send immediate duplicate ACK (for fast retransmit).
    assert_eq!(tx.num_frames(), 1, "OOO data must ACK immediately");
}

#[test]
fn fin_sends_immediate_ack() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), LOCAL_PORT, 128).unwrap();
    let syn = build_syn_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000);
    handler.process_ipv4_with_now(syn, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop();
    let ack = build_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(ack, now, &NH, &mut free, &mut rx, &mut tx);

    // Send FIN.
    let fin = build_fin_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(fin, now, &NH, &mut free, &mut rx, &mut tx);

    // FIN must be ACKed immediately.
    assert_eq!(tx.num_frames(), 1, "FIN must be ACKed immediately");
}
```

**Important:** The test helpers `build_data_frame` and `build_fin_frame` should already exist in the test module (they were created during data transfer and teardown implementation). If `build_fin_frame` doesn't exist, you'll need to create it — it's the same as `build_ack_frame` but with the FIN flag set. Check the existing test helpers before adding new ones.

**Step 2: Run tests to verify they fail**

Run: `cargo test delayed_ack_defers_ack_for_in_order_data`
Expected: FAIL — ACK is still sent immediately (tx.num_frames() == 1, not 0)

**Step 3: Implement delayed ACK**

Add `delayed_ack_ms: u64` field to `Tcb` (after `nagle_enabled`):

```rust
    /// Delayed ACK timeout in milliseconds.
    pub delayed_ack_ms: u64,
```

Add `delayed_ack_ms` to both TCB initialization sites:
- Active open: `delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,`
- Passive open: `delayed_ack_ms: listener.delayed_ack_ms,`

Import `MAX_DELAYED_ACK_COUNT` in the use line at the top of `mod.rs`:

```rust
use tcb::{..., DEFAULT_DELAYED_ACK_MS, MAX_DELAYED_ACK_COUNT};
```

In `process_established`, replace the in-order data ACK (around line 963-972) with:

```rust
                // Defer ACK (delayed ACK).
                let tcb = &mut self.connections[idx];
                tcb.ack_delay_count += 1;
                if tcb.ack_delay_count >= MAX_DELAYED_ACK_COUNT {
                    // Flush: ACK every other segment (RFC 5681 §4.2).
                    SegmentBuilder::build_ack(
                        tcb.id.local_addr, tcb.id.remote_addr,
                        tcb.id.local_port, tcb.id.remote_port,
                        tcb.snd_nxt, tcb.rcv_nxt,
                        DEFAULT_RCV_WND,
                        src_mac, dst_mac,
                        self.tx_offload, free_frames, tx_return,
                    );
                    tcb.ack_pending = false;
                    tcb.ack_delay_count = 0;
                    tcb.delayed_ack_deadline = None;
                } else {
                    tcb.ack_pending = true;
                    if tcb.delayed_ack_deadline.is_none() {
                        tcb.delayed_ack_deadline = Some(now + coarsetime::Duration::from_millis(tcb.delayed_ack_ms));
                    }
                }
```

Keep the out-of-order ACK (line ~982) and duplicate ACK (line ~993) as immediate — do NOT change those.

Keep the FIN ACK (line ~1016) as immediate — do NOT change that.

**Step 4: Run tests to verify they pass**

Run: `cargo test delayed_ack`
Expected: All 4 delayed ACK tests PASS

Run: `cargo test`
Expected: Some existing tests may fail because they expected immediate ACKs for in-order data. These tests need to be updated to either:
- Send two data segments (to trigger flush), or
- Call `poll_timers` with a future `now` to flush delayed ACKs, or
- Check `ack_pending` instead of `tx.num_frames()`

Fix any broken tests by adjusting expectations. The most common fix is: where a test sent one data segment and expected an ACK in `tx_return`, either send a second segment or advance time past the deadline and call `poll_timers`.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs src/net/handler/tcp/tcb.rs
git commit -m "feat: implement delayed ACK for TCP"
```

---

### Task 3: Delayed ACK Timer in poll_timers

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (poll_timers method)

**Context:**

`poll_timers` (line ~1032) currently handles fast retransmit and RTO retransmit. We need to add a delayed ACK flush pass: for any connection with `ack_pending == true` and `now >= delayed_ack_deadline`, send an ACK and clear the flag.

This should run BEFORE the fast retransmit and RTO passes, as it's a simpler check.

**Step 1: Write the failing test**

```rust
#[test]
fn delayed_ack_timer_flushes_pending_ack() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), LOCAL_PORT, 128).unwrap();
    let syn = build_syn_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1000);
    handler.process_ipv4_with_now(syn, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop();
    let ack = build_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1);
    handler.process_ipv4_with_now(ack, now, &NH, &mut free, &mut rx, &mut tx);

    // Send one data segment — deferred.
    let data = build_data_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 1001, 1, b"hello");
    handler.process_ipv4_with_now(data, now, &NH, &mut free, &mut rx, &mut tx);
    assert_eq!(tx.num_frames(), 0);

    // Advance time past delayed ACK deadline (40ms).
    let later = now + coarsetime::Duration::from_millis(50);
    handler.poll_timers(later, SRC_MAC, &NH, &mut free, &mut tx);

    assert_eq!(tx.num_frames(), 1, "timer should flush delayed ACK");

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };
    let tcb = handler.get_connection(&id).unwrap();
    assert!(!tcb.ack_pending);
    assert_eq!(tcb.ack_delay_count, 0);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test delayed_ack_timer_flushes_pending_ack`
Expected: FAIL — tx.num_frames() == 0 (no delayed ACK flush logic yet)

**Step 3: Implement delayed ACK timer**

In `poll_timers`, add a delayed ACK pass at the very beginning (before the fast retransmit loop at line ~1042):

```rust
        // Delayed ACK pass — flush pending ACKs whose deadline has expired.
        for tcb in &mut self.connections {
            if !tcb.ack_pending {
                continue;
            }
            if let Some(deadline) = tcb.delayed_ack_deadline {
                if now >= deadline {
                    let id = tcb.id;
                    let dst_mac = neighbor_handler
                        .lookup(now, &id.remote_addr)
                        .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());
                    let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;

                    SegmentBuilder::build_ack(
                        id.local_addr, id.remote_addr,
                        id.local_port, id.remote_port,
                        tcb.snd_nxt, tcb.rcv_nxt, window,
                        src_mac, dst_mac,
                        self.tx_offload, free_frames, tx_return,
                    );
                    tcb.ack_pending = false;
                    tcb.ack_delay_count = 0;
                    tcb.delayed_ack_deadline = None;
                }
            }
        }
```

**Step 4: Run tests to verify they pass**

Run: `cargo test delayed_ack_timer`
Expected: PASS

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat: add delayed ACK timer flush in poll_timers"
```

---

### Task 4: Nagle Algorithm in poll_send

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (poll_send method)

**Context:**

`poll_send` (line ~1197) currently sends any available data immediately. We need to add the Nagle gate: if `nagle_enabled` and there are bytes in flight and the data to send is less than MSS, don't send — wait for the outstanding ACK.

Also, when `poll_send` sends a data segment (which carries ACK flag), it should clear `ack_pending` since the ACK piggybacks on the data.

**Step 1: Write the failing tests**

```rust
#[test]
fn nagle_holds_small_data_when_bytes_in_flight() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake via active open.
    let event_queue = handler.connect(
        IpAddress::V4(LOCAL_IP), LOCAL_PORT,
        IpAddress::V4(REMOTE_IP), REMOTE_PORT,
        SRC_MAC, DST_MAC,
        &mut free, &mut tx,
    ).unwrap();
    let _ = tx.pop(); // SYN

    let syn_ack = build_syn_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 2000, 1);
    handler.process_ipv4_with_now(syn_ack, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop(); // ACK of SYN-ACK

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };

    // Write small data (less than MSS).
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        tcb.send_buffer.write(b"hello");
    }

    // First poll_send: nothing in flight → sends immediately.
    handler.poll_send(now, SRC_MAC, &NH, &mut free, &mut tx);
    assert_eq!(tx.num_frames(), 1, "first send should go (nothing in flight)");
    let _ = tx.pop();

    // Write more small data while first is still in flight (unACKed).
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        tcb.send_buffer.write(b"world");
    }

    // Second poll_send: bytes in flight + small data → Nagle holds it.
    handler.poll_send(now, SRC_MAC, &NH, &mut free, &mut tx);
    assert_eq!(tx.num_frames(), 0, "Nagle should hold small data when bytes in flight");
}

#[test]
fn nagle_allows_full_mss_even_with_bytes_in_flight() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    // Complete handshake via active open.
    let _event_queue = handler.connect(
        IpAddress::V4(LOCAL_IP), LOCAL_PORT,
        IpAddress::V4(REMOTE_IP), REMOTE_PORT,
        SRC_MAC, DST_MAC,
        &mut free, &mut tx,
    ).unwrap();
    let _ = tx.pop(); // SYN

    let syn_ack = build_syn_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 2000, 1);
    handler.process_ipv4_with_now(syn_ack, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop(); // ACK

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };

    // Write small data first to create bytes_in_flight.
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        tcb.send_buffer.write(b"small");
    }
    handler.poll_send(now, SRC_MAC, &NH, &mut free, &mut tx);
    let _ = tx.pop();

    // Write MSS-worth of data.
    let tcb = handler.get_connection_mut(&id).unwrap();
    let mss = tcb.eff_snd_mss as usize;
    let big_data = vec![0xABu8; mss];
    tcb.send_buffer.write(&big_data);
    drop(tcb);

    // poll_send: full MSS → always sends (Nagle allows it).
    handler.poll_send(now, SRC_MAC, &NH, &mut free, &mut tx);
    assert_eq!(tx.num_frames(), 1, "full MSS should always send");
}

#[test]
fn tcp_no_delay_sends_small_data_immediately() {
    let (mut handler, mut free, mut rx, mut tx) = setup();
    let now = Instant::now();

    let config = TcpConfig {
        tcp_no_delay: true,
        ..TcpConfig::default()
    };

    // Complete handshake via active open with config.
    let _event_queue = handler.connect_with_config(
        IpAddress::V4(LOCAL_IP), LOCAL_PORT,
        IpAddress::V4(REMOTE_IP), REMOTE_PORT,
        SRC_MAC, DST_MAC,
        config,
        &mut free, &mut tx,
    ).unwrap();
    let _ = tx.pop(); // SYN

    let syn_ack = build_syn_ack_frame(REMOTE_IP, LOCAL_IP, REMOTE_PORT, LOCAL_PORT, 2000, 1);
    handler.process_ipv4_with_now(syn_ack, now, &NH, &mut free, &mut rx, &mut tx);
    let _ = tx.pop(); // ACK

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: LOCAL_PORT,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    };

    // Write small data.
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        tcb.send_buffer.write(b"hello");
    }
    handler.poll_send(now, SRC_MAC, &NH, &mut free, &mut tx);
    let _ = tx.pop(); // First send goes (nothing in flight)

    // Write more small data while first in flight.
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        tcb.send_buffer.write(b"world");
    }
    handler.poll_send(now, SRC_MAC, &NH, &mut free, &mut tx);
    assert_eq!(tx.num_frames(), 1, "TCP_NODELAY should bypass Nagle");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test nagle_holds_small_data`
Expected: FAIL — Nagle gate not implemented yet, small data sends immediately

**Step 3: Implement Nagle gate and ACK piggybacking**

In `poll_send`, after computing `to_send` (around line 1218), add the Nagle gate:

```rust
            if can_send > 0 && data_available > 0 {
                let to_send = can_send.min(data_available).min(tcb.eff_snd_mss as usize);

                // Nagle algorithm: hold small segments when data is in flight.
                if tcb.nagle_enabled && bytes_in_flight > 0 && to_send < tcb.eff_snd_mss as usize {
                    // Don't send — wait for outstanding ACK to come back.
                } else {
                    // ... existing send logic (peek, build_data, advance snd_nxt, etc.) ...

                    // Piggyback: data segment carries ACK, so clear delayed ACK state.
                    tcb.ack_pending = false;
                    tcb.ack_delay_count = 0;
                    tcb.delayed_ack_deadline = None;
                }
            }
```

Restructure: wrap the existing send body in the `else` branch and add the piggyback clearing after the `SegmentBuilder::build_data` call.

**Step 4: Run tests to verify they pass**

Run: `cargo test nagle`
Run: `cargo test tcp_no_delay`
Expected: All 3 Nagle tests PASS

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat: implement Nagle algorithm with TCP_NODELAY support"
```

---

### Task 5: TcpStream::set_nodelay API

**Files:**
- Modify: `src/net/socket/tcp.rs`

**Context:**

`TcpStream` at `src/net/socket/tcp.rs:161` holds a `conn_id` and a `handler: Rc<UnsafeCell<TcpHandler>>`. It already has methods like `close()` that access the handler mutably.

We need `set_nodelay(&self, nodelay: bool)` that looks up the TCB and flips `nagle_enabled`.

**Step 1: Write the method**

Note: This is a socket-layer method. It cannot be unit-tested without the full runtime context (which requires root + real NIC). We verify it compiles and is consistent with existing methods.

Add to `TcpStream` impl block (after `close` method, around line 349):

```rust
    /// Enable or disable the Nagle algorithm (TCP_NODELAY).
    ///
    /// When `nodelay` is `true`, small segments are sent immediately
    /// without waiting for outstanding ACKs. Default is `false` (Nagle enabled).
    pub fn set_nodelay(&self, nodelay: bool) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
            tcb.nagle_enabled = !nodelay;
        }
    }

    /// Returns whether TCP_NODELAY is set (Nagle disabled).
    pub fn nodelay(&self) -> bool {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_connection(&self.conn_id)
            .map(|tcb| !tcb.nagle_enabled)
            .unwrap_or(false)
    }
```

Update the public exports in `src/net/socket/mod.rs` if needed (the existing `pub use tcp::...` line should already cover `TcpStream`).

**Step 2: Verify it compiles**

Run: `cargo build --features local`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add src/net/socket/tcp.rs
git commit -m "feat: add TcpStream::set_nodelay() API"
```
