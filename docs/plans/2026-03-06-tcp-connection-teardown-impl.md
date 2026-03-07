# TCP Connection Teardown Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement RFC 9293-compliant TCP connection teardown with FIN/FIN-ACK, all 6 teardown states (FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait), configurable TIME-WAIT duration, and graceful half-open draining.

**Architecture:** Lazy FIN sending via `pending_fin` flag on the TCB — `poll_send` sends FIN on next tick after send buffer drains. Teardown state processing in a new `process_teardown` method dispatching by state. TIME-WAIT cleaned up by `evict_stale`. `TcpStream::close()` rewritten to set flag only.

**Tech Stack:** Rust (2024 edition), no new dependencies. Uses existing `coarsetime`, `SegmentBuilder`, `FrameBuffer`, `LocalQueue` infrastructure.

**Design doc:** `docs/plans/2026-03-06-tcp-connection-teardown-design.md`

---

### Task 1: TCB Teardown Fields + TcpEvent::RemoteClose

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`

**Step 1: Add `RemoteClose` to `TcpEvent`**

In `tcb.rs`, add to the `TcpEvent` enum (~line 35):

```rust
pub enum TcpEvent {
    Connected,
    ConnectionRefused,
    Reset,
    Timeout,
    RemoteClose,
}
```

**Step 2: Add teardown fields to `Tcb`**

After the `last_send_time` field (~line 171), add:

```rust
    // --- Connection teardown ---
    /// Set by close(), consumed by poll_send to send FIN.
    pub pending_fin: bool,
    /// Sequence number of our FIN (needed to detect when FIN is ACKed).
    pub fin_seq: Option<u32>,
    /// Deadline for removing TIME-WAIT connections.
    pub time_wait_deadline: Option<Instant>,
    /// TIME-WAIT duration in milliseconds (from TcpConfig).
    pub time_wait_duration: u64,
```

**Step 3: Add `time_wait_duration_ms` to `TcpConfig`**

In `TcpConfig` (~line 73), add:

```rust
pub struct TcpConfig {
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub backlog: usize,
    /// TIME-WAIT duration in milliseconds. Default: 60000 (60 seconds).
    pub time_wait_duration_ms: u64,
}
```

Update `Default` impl:

```rust
impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            send_buffer_size: 256 * 1024,
            recv_buffer_size: 256 * 1024,
            backlog: 128,
            time_wait_duration_ms: 60_000,
        }
    }
}
```

**Step 4: Add `is_closing` helper to `TcpState`**

In `src/net/handler/tcp/state.rs`, add a helper method:

```rust
/// Returns `true` for states where the remote has sent FIN
/// (receive side is closed — read should return EOF when buffer empty).
#[inline]
pub fn is_remote_closed(self) -> bool {
    matches!(
        self,
        TcpState::CloseWait
            | TcpState::LastAck
            | TcpState::TimeWait
            | TcpState::Closing
            | TcpState::Closed
    )
}
```

**Step 5: Update all TCB construction sites in `mod.rs`**

There are two construction sites in `src/net/handler/tcp/mod.rs`:
1. `connect_with_config()` (~line 135-167)
2. `process_listen()` (~line 538-568)

Add to both:
```rust
pending_fin: false,
fin_seq: None,
time_wait_deadline: None,
time_wait_duration: config.time_wait_duration_ms,  // or 60_000 for default path
```

For `process_listen`, the listener's `ListenEntry` needs a `time_wait_duration` field. Add it to `ListenEntry` and populate from config in `listen_with_config`.

**Step 6: Run tests to verify compilation**

Run: `cargo test`
Expected: PASS (all existing tests still work, new fields have defaults)

**Step 7: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/state.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): TCB teardown fields, TcpEvent::RemoteClose, TcpConfig time_wait"
```

---

### Task 2: SegmentBuilder::build_fin_ack

**Files:**
- Modify: `src/net/handler/tcp/segment.rs`

**Step 1: Write the failing test**

Add to the `tests` module in `segment.rs`:

```rust
#[test]
fn build_fin_ack_ipv4() {
    let mut free = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    free.push(alloc_frame(100));

    SegmentBuilder::build_fin_ack(
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
        80, 12345,
        5000, 3000, 65535,
        [0xAA; 6].into(), [0xBB; 6].into(),
        false, &mut free, &mut tx,
    );

    assert_eq!(tx.num_frames(), 1, "FIN-ACK segment built");
    assert_eq!(free.num_frames(), 0, "free frame consumed");

    let frame = tx.pop().unwrap();
    let tcp_offset = ETH_LEN + IPV4_MIN_HEADER_LEN;
    let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
    assert_eq!(tcp.flags(), flags::ACK | flags::FIN);
    assert_eq!(tcp.seq_num(), 5000);
    assert_eq!(tcp.ack_num(), 3000);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test build_fin_ack`
Expected: FAIL — `build_fin_ack` not defined.

**Step 3: Implement build_fin_ack**

Add to `impl SegmentBuilder` (after `build_ack`):

```rust
/// Build a FIN-ACK segment (no data). Used for graceful connection close.
pub fn build_fin_ack<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    match (local_addr, remote_addr) {
        (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
            Self::build_ipv4_segment(
                local_ip, remote_ip,
                local_port, remote_port,
                seq, ack, flags::ACK | flags::FIN, window,
                &[],
                src_mac, dst_mac,
                tx_offload, free_frames, tx_return,
            );
        }
        (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
            Self::build_ipv6_segment(
                local_ip, remote_ip,
                local_port, remote_port,
                seq, ack, flags::ACK | flags::FIN, window,
                &[],
                src_mac, dst_mac,
                tx_offload, free_frames, tx_return,
            );
        }
        _ => {}
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test build_fin_ack`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/segment.rs
git commit -m "feat(tcp): SegmentBuilder::build_fin_ack for graceful close"
```

---

### Task 3: poll_send — FIN Sending for Established and CloseWait

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing test**

Add to the test module in `mod.rs`:

```rust
#[test]
fn poll_send_sends_fin_when_pending() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Set pending_fin.
    handler.connections[0].pending_fin = true;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // FIN should have been sent.
    assert_eq!(tx.num_frames(), 1, "FIN segment sent");
    let tcb = &handler.connections[0];
    assert_eq!(tcb.state, TcpState::FinWait1);
    assert!(!tcb.pending_fin, "pending_fin consumed");
    assert!(tcb.fin_seq.is_some(), "fin_seq recorded");
}

#[test]
fn poll_send_drains_data_before_fin() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Write data AND set pending_fin.
    handler.connections[0].send_buffer.write(b"final data");
    handler.connections[0].snd_wnd = 65535;
    handler.connections[0].pending_fin = true;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Should send data first, NOT FIN yet (data still in flight).
    assert_eq!(tx.num_frames(), 1, "data segment sent");
    assert_eq!(handler.connections[0].state, TcpState::Established, "still Established until data ACKed");
    assert!(handler.connections[0].pending_fin, "pending_fin still set");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test poll_send_sends_fin`
Expected: FAIL — current `poll_send` skips non-Established connections and doesn't check `pending_fin`.

**Step 3: Modify poll_send**

Rewrite `poll_send` (~line 1145) to handle FIN:

1. Change the state check from `if tcb.state != TcpState::Established { continue; }` to also allow `TcpState::CloseWait`:
```rust
if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
    continue;
}
```

2. After the existing data sending logic (after `tcb.snd_nxt = ...`), add FIN logic. The full revised structure:

```rust
// (existing data sending code stays the same)

// After data sending: check if we should send FIN.
if tcb.pending_fin {
    let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
    let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);

    // Only send FIN when all data has been sent (may still be in flight awaiting ACK).
    if data_available == 0 {
        let id = tcb.id;
        let dst_mac = neighbor_handler
            .lookup(now, &id.remote_addr)
            .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());
        let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;

        SegmentBuilder::build_fin_ack(
            id.local_addr, id.remote_addr,
            id.local_port, id.remote_port,
            tcb.snd_nxt, tcb.rcv_nxt, window,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );

        tcb.fin_seq = Some(tcb.snd_nxt);
        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes one sequence number

        tcb.pending_fin = false;

        match tcb.state {
            TcpState::Established => tcb.state = TcpState::FinWait1,
            TcpState::CloseWait => tcb.state = TcpState::LastAck,
            _ => {}
        }

        // Set retransmit timer for FIN.
        if tcb.retransmit_deadline.is_none() {
            tcb.retransmit_deadline = Some(now + coarsetime::Duration::from_millis(tcb.rto));
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test poll_send`
Expected: PASS (all poll_send tests including new ones)

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): poll_send sends FIN after draining send buffer"
```

---

### Task 4: Receive FIN in Established State

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn established_receives_fin_transitions_to_close_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Remote sends FIN.
    let fin_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin_data.len();
    handler.process_ipv4(Frame::new(2, leak(fin_data), fin_len, false), &nh, &mut free, &mut rx, &mut tx);

    // Should transition to CloseWait, send ACK, advance rcv_nxt.
    assert_eq!(handler.connections[0].state, TcpState::CloseWait);
    assert_eq!(handler.connections[0].rcv_nxt, 1002); // 1001 + FIN=1
    assert_eq!(tx.num_frames(), 1, "ACK for FIN sent");
}

#[test]
fn established_receives_fin_with_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Remote sends data + FIN piggybacked.
    let payload = b"goodbye";
    let fin_data = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, server_iss.wrapping_add(1),
        flags::ACK | flags::FIN, 65535, &[], payload,
    );
    let fin_len = fin_data.len();
    handler.process_ipv4(Frame::new(2, leak(fin_data), fin_len, false), &nh, &mut free, &mut rx, &mut tx);

    // Data should be in recv buffer, state should be CloseWait.
    assert_eq!(handler.connections[0].state, TcpState::CloseWait);
    assert_eq!(handler.connections[0].recv_buffer.available(), payload.len());
    // rcv_nxt = 1001 + 7 bytes data + 1 FIN = 1009
    assert_eq!(handler.connections[0].rcv_nxt, 1001 + payload.len() as u32 + 1);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test established_receives_fin`
Expected: FAIL — current `process_established` doesn't handle FIN flag.

**Step 3: Extend process_established for FIN**

In `process_established` (~line 830), after the data processing section (the `if payload_len > 0` block), add FIN handling. The FIN must be processed after data because FIN can piggyback on data:

```rust
// Step 4: Process FIN flag.
if seg_flags & flags::FIN != 0 {
    let tcb = &mut self.connections[idx];
    // Only process FIN if it's at the expected sequence number.
    // After data processing, rcv_nxt should be at seg_seq + payload_len.
    // FIN occupies the next sequence number after the data.
    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1); // FIN consumes one sequence number
    tcb.state = TcpState::CloseWait;
    tcb.event_queue.push(TcpEvent::RemoteClose);

    // Send ACK for FIN.
    let id = tcb.id;
    let snd_nxt = tcb.snd_nxt;
    let new_rcv_nxt = tcb.rcv_nxt;
    let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;
    SegmentBuilder::build_ack(
        id.local_addr, id.remote_addr,
        id.local_port, id.remote_port,
        snd_nxt, new_rcv_nxt, window,
        src_mac, dst_mac,
        self.tx_offload, free_frames, tx_return,
    );
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): handle FIN in Established state → CloseWait transition"
```

---

### Task 5: process_teardown — FinWait1 and FinWait2

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing tests**

```rust
#[test]
fn active_close_fin_wait1_to_fin_wait2() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Active close: set pending_fin, poll_send sends FIN → FinWait1.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.connections[0].state, TcpState::FinWait1);
    let fin_seq = handler.connections[0].fin_seq.unwrap();

    // Remote ACKs our FIN → FinWait2.
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(3, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.connections[0].state, TcpState::FinWait2);
}

#[test]
fn fin_wait2_receives_fin_to_time_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Active close → FinWait1 → FinWait2.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}
    let fin_seq = handler.connections[0].fin_seq.unwrap();
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(3, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::FinWait2);
    while tx.pop().is_some() {}

    // Remote sends FIN → TimeWait.
    let fin = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, fin_seq.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin.len();
    handler.process_ipv4(Frame::new(4, leak(fin), fin_len, false), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.connections[0].state, TcpState::TimeWait);
    assert!(handler.connections[0].time_wait_deadline.is_some());
    assert_eq!(tx.num_frames(), 1, "ACK for remote FIN");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test active_close_fin_wait1`
Expected: FAIL — teardown states currently hit `_ => { rx_return.push(frame); }` in `process_segment`.

**Step 3: Implement process_teardown and wire it into process_segment**

In `process_segment` (~line 451), replace `_ => { rx_return.push(frame); }` with:

```rust
TcpState::FinWait1 | TcpState::FinWait2 | TcpState::CloseWait
| TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
    let payload_offset = tcp_offset + tcp_header_len;
    let payload_len = frame.len().saturating_sub(payload_offset);
    self.process_teardown(
        idx, frame, now, seg_seq, seg_ack, seg_flags, seg_wnd,
        payload_offset, payload_len,
        src_mac, dst_mac,
        free_frames, rx_return, tx_return,
    );
}
_ => {
    rx_return.push(frame);
}
```

Then add the `process_teardown` method. For this task, implement FinWait1 and FinWait2:

```rust
fn process_teardown<'umem>(
    &mut self,
    idx: usize,
    frame: Frame<'umem>,
    now: Instant,
    seg_seq: u32,
    seg_ack: u32,
    seg_flags: u8,
    seg_wnd: u32,
    payload_offset: usize,
    payload_len: usize,
    src_mac: crate::net::wire::ethernet::MacAddress,
    dst_mac: crate::net::wire::ethernet::MacAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let state = self.connections[idx].state;

    // RST check — abort all states except TimeWait.
    if seg_flags & flags::RST != 0 {
        if state == TcpState::TimeWait {
            // Ignore RST in TIME-WAIT (prevents RST attacks).
            rx_return.push(frame);
            return;
        }
        self.connections[idx].event_queue.push(TcpEvent::Reset);
        self.connections.remove(idx);
        rx_return.push(frame);
        return;
    }

    match state {
        TcpState::FinWait1 => {
            let tcb = &mut self.connections[idx];
            let fin_acked = if seg_flags & flags::ACK != 0 {
                if let Some(fin_seq) = tcb.fin_seq {
                    crate::net::wire::tcp::seq_lt(fin_seq, seg_ack)
                } else {
                    false
                }
            } else {
                false
            };

            // Process ACK (advance snd_una if valid).
            if seg_flags & flags::ACK != 0 {
                let snd_una = tcb.snd_una;
                let snd_nxt = tcb.snd_nxt;
                if crate::net::wire::tcp::seq_lt(snd_una, seg_ack)
                    && crate::net::wire::tcp::seq_le(seg_ack, snd_nxt)
                {
                    let bytes_acked = seg_ack.wrapping_sub(snd_una) as usize;
                    tcb.snd_una = seg_ack;
                    tcb.send_buffer.advance(bytes_acked);
                    tcb.snd_wnd = seg_wnd;
                }
            }

            // Process data if present (remote may still be sending).
            if payload_len > 0 && seg_seq == tcb.rcv_nxt {
                let payload = &frame[payload_offset..payload_offset + payload_len];
                tcb.recv_buffer.write(payload);
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);
            }

            // Check for FIN from remote.
            let remote_fin = seg_flags & flags::FIN != 0;
            if remote_fin {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
            }

            // Determine new state.
            let tcb = &mut self.connections[idx];
            if fin_acked && remote_fin {
                // Both sides FINed and our FIN is ACKed → TimeWait.
                tcb.state = TcpState::TimeWait;
                tcb.time_wait_deadline = Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
                tcb.retransmit_deadline = None;
            } else if fin_acked {
                // Our FIN ACKed but no remote FIN yet → FinWait2.
                tcb.state = TcpState::FinWait2;
                tcb.retransmit_deadline = None;
            } else if remote_fin {
                // Remote FINed but our FIN not yet ACKed → Closing.
                tcb.state = TcpState::Closing;
            }

            // Send ACK if FIN or data received.
            if remote_fin || payload_len > 0 {
                let id = self.connections[idx].id;
                let snd_nxt = self.connections[idx].snd_nxt;
                let rcv_nxt = self.connections[idx].rcv_nxt;
                let window = self.connections[idx].recv_buffer.free_space().min(u16::MAX as usize) as u16;
                SegmentBuilder::build_ack(
                    id.local_addr, id.remote_addr,
                    id.local_port, id.remote_port,
                    snd_nxt, rcv_nxt, window,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            }

            rx_return.push(frame);
        }

        TcpState::FinWait2 => {
            let tcb = &mut self.connections[idx];

            // Process data if present (remote still sending).
            if payload_len > 0 && seg_seq == tcb.rcv_nxt {
                let payload = &frame[payload_offset..payload_offset + payload_len];
                tcb.recv_buffer.write(payload);
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);
            }

            // Check for FIN.
            if seg_flags & flags::FIN != 0 {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                tcb.state = TcpState::TimeWait;
                tcb.time_wait_deadline = Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
            }

            // Send ACK if FIN or data.
            if seg_flags & flags::FIN != 0 || payload_len > 0 {
                let id = tcb.id;
                let snd_nxt = tcb.snd_nxt;
                let rcv_nxt = tcb.rcv_nxt;
                let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;
                SegmentBuilder::build_ack(
                    id.local_addr, id.remote_addr,
                    id.local_port, id.remote_port,
                    snd_nxt, rcv_nxt, window,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            }

            rx_return.push(frame);
        }

        // Remaining states added in next tasks.
        _ => {
            rx_return.push(frame);
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): process_teardown for FinWait1 and FinWait2 states"
```

---

### Task 6: process_teardown — Closing, LastAck, TimeWait

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing tests**

```rust
#[test]
fn simultaneous_close_closing_to_time_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Active close → FinWait1.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.connections[0].state, TcpState::FinWait1);

    // Simultaneous close: remote sends FIN without ACKing ours → Closing.
    let fin = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin.len();
    handler.process_ipv4(Frame::new(3, leak(fin), fin_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::Closing);
    while tx.pop().is_some() {}

    // Remote ACKs our FIN → TimeWait.
    let fin_seq = handler.connections[0].fin_seq.unwrap();
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1002, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(4, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::TimeWait);
}

#[test]
fn passive_close_last_ack_removes_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Remote sends FIN → CloseWait.
    let fin = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin.len();
    handler.process_ipv4(Frame::new(2, leak(fin), fin_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::CloseWait);
    while tx.pop().is_some() {}

    // We close → pending_fin, poll_send sends FIN → LastAck.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.connections[0].state, TcpState::LastAck);
    let fin_seq = handler.connections[0].fin_seq.unwrap();

    // Remote ACKs our FIN → connection removed.
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1002, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(4, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections.len(), 0, "connection removed after LastAck");
}

#[test]
fn time_wait_ignores_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Full active close → TimeWait.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}
    let fin_seq = handler.connections[0].fin_seq.unwrap();
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(3, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    let fin = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, fin_seq.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin.len();
    handler.process_ipv4(Frame::new(4, leak(fin), fin_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::TimeWait);
    while tx.pop().is_some() {}

    // RST in TIME-WAIT should be ignored.
    let rst = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1002, 0, flags::RST, 0, &[]);
    let rst_len = rst.len();
    handler.process_ipv4(Frame::new(5, leak(rst), rst_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections.len(), 1, "connection NOT removed by RST in TIME-WAIT");
    assert_eq!(handler.connections[0].state, TcpState::TimeWait);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test simultaneous_close`
Expected: FAIL — Closing, LastAck, TimeWait not yet handled in `process_teardown`.

**Step 3: Add remaining states to process_teardown**

Add these match arms to the existing `process_teardown` method:

```rust
TcpState::Closing => {
    let tcb = &mut self.connections[idx];
    // Waiting for ACK of our FIN.
    if seg_flags & flags::ACK != 0 {
        if let Some(fin_seq) = tcb.fin_seq {
            if crate::net::wire::tcp::seq_lt(fin_seq, seg_ack) {
                tcb.snd_una = seg_ack;
                tcb.state = TcpState::TimeWait;
                tcb.time_wait_deadline = Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
                tcb.retransmit_deadline = None;
            }
        }
    }
    rx_return.push(frame);
}

TcpState::LastAck => {
    // Waiting for ACK of our FIN.
    if seg_flags & flags::ACK != 0 {
        let tcb = &self.connections[idx];
        if let Some(fin_seq) = tcb.fin_seq {
            if crate::net::wire::tcp::seq_lt(fin_seq, seg_ack) {
                self.connections.remove(idx);
                rx_return.push(frame);
                return;
            }
        }
    }
    rx_return.push(frame);
}

TcpState::TimeWait => {
    let tcb = &mut self.connections[idx];
    // FIN retransmit → re-ACK and restart timer.
    if seg_flags & flags::FIN != 0 {
        let id = tcb.id;
        let snd_nxt = tcb.snd_nxt;
        let rcv_nxt = tcb.rcv_nxt;
        let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;
        SegmentBuilder::build_ack(
            id.local_addr, id.remote_addr,
            id.local_port, id.remote_port,
            snd_nxt, rcv_nxt, window,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );
        tcb.time_wait_deadline = Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
    }
    // Everything else (including RST) is ignored — RST handled above.
    rx_return.push(frame);
}

TcpState::CloseWait => {
    // Remote already FINed. No new data expected.
    // Just handle RST (already handled above) and ignore everything else.
    rx_return.push(frame);
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): process_teardown for Closing, LastAck, TimeWait, CloseWait"
```

---

### Task 7: evict_stale — TIME-WAIT Cleanup

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn time_wait_evicted_after_deadline() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

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

    // Force into TimeWait state with expired deadline.
    handler.connections[0].state = TcpState::TimeWait;
    handler.connections[0].time_wait_deadline = Some(coarsetime::Instant::now());

    // Evict with a time in the future.
    let future = coarsetime::Instant::now() + coarsetime::Duration::from_secs(120);
    handler.evict_stale(future, &mut rx);
    assert_eq!(handler.connections.len(), 0, "TIME-WAIT connection evicted");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test time_wait_evicted`
Expected: FAIL — `evict_stale` is currently a no-op.

**Step 3: Implement evict_stale**

Replace the placeholder `evict_stale` (~line 1133):

```rust
pub fn evict_stale<'umem>(
    &mut self,
    now: Instant,
    _rx_return: &mut impl FrameBuffer<'umem>,
) {
    self.connections.retain(|tcb| {
        if tcb.state == TcpState::TimeWait {
            if let Some(deadline) = tcb.time_wait_deadline {
                if now >= deadline {
                    return false; // remove
                }
            }
        }
        true // keep
    });
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): evict_stale removes expired TIME-WAIT connections"
```

---

### Task 8: TcpStream::close() Rewrite + read() EOF

**Files:**
- Modify: `src/net/socket/tcp.rs`
- Modify: `src/net/handler/tcp/mod.rs` (add `initiate_close` method)

**Step 1: Add `initiate_close` to TcpHandler**

In `src/net/handler/tcp/mod.rs`, add a method to `impl TcpHandler`:

```rust
/// Initiate graceful close by setting pending_fin on the connection.
/// Called by TcpStream::close(). The actual FIN is sent by poll_send.
pub fn initiate_close(&mut self, id: &ConnectionId) {
    if let Some(tcb) = self.connections.iter_mut().find(|c| c.id == *id) {
        match tcb.state {
            TcpState::Established | TcpState::CloseWait => {
                tcb.pending_fin = true;
            }
            _ => {} // Already closing or closed.
        }
    }
}
```

**Step 2: Rewrite TcpStream::close()**

In `src/net/socket/tcp.rs`, replace the current `close()` method (~line 339):

```rust
/// Initiate graceful close of this connection.
///
/// Sets a flag on the TCB; the runtime's `poll_send` will drain
/// any remaining send buffer data and then send FIN on the next tick.
pub fn close(&mut self) {
    if self.closed {
        return;
    }
    self.closed = true;
    let handler = unsafe { &mut *self.handler.get() };
    handler.initiate_close(&self.conn_id);
}
```

**Step 3: Update TcpRead to return EOF**

Modify the `TcpRead` future's `poll` method (~line 431):

```rust
impl<'stream> Future for TcpRead<'stream> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&this.conn_id) {
            let n = tcb.recv_buffer.read(this.buf);
            if n > 0 {
                Poll::Ready(n)
            } else if tcb.state.is_remote_closed() {
                Poll::Ready(0) // EOF — remote has sent FIN and buffer is drained
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(0) // connection gone
        }
    }
}
```

This requires importing `TcpState` or using the `is_remote_closed()` method through the `state` field. The `is_remote_closed()` method was added to `TcpState` in Task 1.

**Step 4: Remove old `remove_connection` usage**

Remove the unused imports in `tcp.rs` that were only needed for the old RST hack: `SharedFrameBuffer`, `BasicFrameBuffer`. Keep the `remove_connection` method on TcpHandler for now (it may be useful for abort scenarios), but `TcpStream::close()` no longer calls it.

Clean up any unused imports.

**Step 5: Run tests to verify nothing broke**

Run: `cargo test`
Expected: PASS

**Step 6: Commit**

```bash
git add src/net/socket/tcp.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): TcpStream::close() sets pending_fin, read() returns EOF"
```

---

### Task 9: Full Teardown Integration Test

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (test only)

**Step 1: Write comprehensive teardown test**

```rust
#[test]
fn full_active_close_lifecycle() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let initial_free = free.num_frames();

    // 1. Handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // 2. Data exchange.
    let payload = b"hello";
    let data = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, server_iss.wrapping_add(1),
        flags::ACK, 65535, &[], payload,
    );
    let data_len = data.len();
    handler.process_ipv4(Frame::new(2, leak(data), data_len, false), &nh, &mut free, &mut rx, &mut tx);

    // 3. Active close.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::FinWait1);
    while tx.pop().is_some() {}

    // 4. Remote ACKs our FIN → FinWait2.
    let fin_seq = handler.connections[0].fin_seq.unwrap();
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1006, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(3, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::FinWait2);

    // 5. Remote sends FIN → TimeWait.
    let fin = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1006, fin_seq.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin.len();
    handler.process_ipv4(Frame::new(4, leak(fin), fin_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::TimeWait);
    while tx.pop().is_some() {}

    // 6. TIME-WAIT expires → connection removed.
    let future = coarsetime::Instant::now() + coarsetime::Duration::from_secs(120);
    handler.evict_stale(future, &mut rx);
    assert_eq!(handler.connections.len(), 0, "connection removed after TIME-WAIT");

    // 7. Frame accounting: all frames accounted for.
    let total = free.num_frames() + rx.num_frames() + tx.num_frames();
    assert_eq!(total, initial_free + 5, "all frames accounted for (initial + 5 incoming)");
}

#[test]
fn full_passive_close_lifecycle() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // 1. Handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // 2. Remote sends FIN → CloseWait.
    let fin = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK | flags::FIN, 65535, &[]);
    let fin_len = fin.len();
    handler.process_ipv4(Frame::new(2, leak(fin), fin_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::CloseWait);
    while tx.pop().is_some() {}

    // 3. We close → LastAck.
    handler.connections[0].pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::LastAck);
    while tx.pop().is_some() {}
    let fin_seq = handler.connections[0].fin_seq.unwrap();

    // 4. Remote ACKs our FIN → connection removed.
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1002, fin_seq.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(3, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections.len(), 0, "connection removed after LastAck");
}
```

**Step 2: Run tests**

Run: `cargo test full_active_close_lifecycle full_passive_close_lifecycle`
Expected: PASS

**Step 3: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "test(tcp): full active and passive close lifecycle integration tests"
```

---

## Task Dependency Graph

```
Task 1 (TCB fields + TcpEvent::RemoteClose)
  ├─> Task 2 (SegmentBuilder::build_fin_ack)
  │    └─> Task 3 (poll_send FIN sending)
  │         └─> Task 5 (process_teardown FinWait1/FinWait2)
  │              └─> Task 6 (process_teardown Closing/LastAck/TimeWait)
  │                   └─> Task 7 (evict_stale TIME-WAIT)
  │                        └─> Task 9 (integration tests)
  └─> Task 4 (FIN in Established → CloseWait)
       └─> Task 8 (TcpStream::close() + read() EOF)
            └─> Task 9 (integration tests)
```

Tasks 2 and 4 can be parallelized after Task 1. Tasks 5 and 8 can be parallelized after their respective dependencies. Task 9 depends on everything.
