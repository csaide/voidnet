# TCP Reliability & Performance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix window scaling bugs, add segment acceptability checks, TCP timestamps (RTTM/PAWS), zero-window probing, full SACK support, and zero-copy send path.

**Architecture:** Six features implemented bottom-up by dependency: window scaling fix (prerequisite for correct windows), segment acceptability (correctness gate), timestamps with PAWS (gates segment processing), zero-window probing (needs correct windows), full SACK (needs correct validation), zero-copy send (independent optimization). Each feature adds wire-level option support, TCB state, handler logic, and tests.

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure in `src/net/handler/tcp/`.

**Testing:** `cargo test` (no feature flags, no `--all-features`). Tests run under `sudo -E` via `.cargo/config.toml`.

**Key files reference:**
- Wire format: `src/net/wire/tcp.rs`
- TCB/config: `src/net/handler/tcp/tcb.rs`
- Handler: `src/net/handler/tcp/mod.rs`
- Segment builder: `src/net/handler/tcp/segment.rs`
- Ring buffer: `src/net/handler/tcp/ring_buffer.rs`
- Socket layer: `src/net/socket/tcp.rs`
- Checksum: `src/net/checksum/compute.rs`

---

## Task 1: Window Scaling Fix — TCB Helper and Incoming Window

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** `snd_wscale` is negotiated but never applied to incoming `seg_wnd`. Every `tcb.snd_wnd = seg_wnd` stores the raw 16-bit value instead of `seg_wnd << snd_wscale`. Per RFC 7323 §2.2, scaling applies only after the SYN exchange completes (Established state onward).

**Step 1: Add `advertised_window` helper to Tcb**

In `src/net/handler/tcp/tcb.rs`, add to the `impl Tcb` block:

```rust
/// Compute the window value to advertise in outgoing segments.
/// Downscales by `rcv_wscale` if window scaling is enabled.
#[inline]
pub fn advertised_window(&self) -> u16 {
    let free = self.recv_buffer.free_space();
    if self.wscale_enabled {
        (free >> self.rcv_wscale as usize).min(u16::MAX as usize) as u16
    } else {
        free.min(u16::MAX as usize) as u16
    }
}
```

**Step 2: Add `scale_incoming_window` helper**

In `src/net/handler/tcp/tcb.rs`, add to the `impl Tcb` block:

```rust
/// Scale an incoming window value by `snd_wscale`.
/// Only call after SYN exchange (Established onward).
#[inline]
pub fn scale_incoming_window(&self, raw_wnd: u32) -> u32 {
    if self.wscale_enabled {
        raw_wnd << self.snd_wscale as u32
    } else {
        raw_wnd
    }
}
```

**Step 3: Write tests for the helpers**

Add to the `#[cfg(test)]` section at the bottom of `src/net/handler/tcp/tcb.rs` (create the module if it doesn't exist):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::handler::tcp::ring_buffer::RingBuffer;

    fn make_test_tcb() -> Tcb {
        // Minimal Tcb for testing helpers — only relevant fields matter.
        Tcb {
            id: ConnectionId {
                local_addr: crate::net::wire::ip::IpAddress::V4(
                    crate::net::wire::ip::Ipv4Address::new([10, 0, 0, 1]),
                ),
                local_port: 8080,
                remote_addr: crate::net::wire::ip::IpAddress::V4(
                    crate::net::wire::ip::Ipv4Address::new([10, 0, 0, 2]),
                ),
                remote_port: 80,
            },
            state: TcpState::Established,
            from_passive_open: false,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            snd_mss: 1460,
            rcv_mss: 1460,
            eff_snd_mss: 1460,
            snd_wscale: 0,
            rcv_wscale: 0,
            wscale_enabled: false,
            retransmit_deadline: None,
            rto_backoff: 0,
            event_queue: crate::net::socket::LocalQueue::new(),
            send_buffer: RingBuffer::new(1024),
            recv_buffer: RingBuffer::new(1024),
            ooo_ranges: std::collections::BTreeMap::new(),
            cwnd: 65535,
            ssthresh: 65535,
            dup_ack_count: 0,
            srtt: None,
            rttvar: 0,
            rto: 1000,
            last_send_time: None,
            pending_fin: false,
            fin_seq: None,
            time_wait_deadline: None,
            time_wait_duration: 60_000,
            ack_pending: false,
            delayed_ack_deadline: None,
            ack_delay_count: 0,
            delayed_ack_ms: 40,
            nagle_enabled: true,
            keep_alive_enabled: false,
            keep_alive_idle_ms: 7_200_000,
            keep_alive_interval_ms: 75_000,
            keep_alive_count: 9,
            last_activity: Instant::now(),
            keep_alive_probes_sent: 0,
            linger: None,
            linger_deadline: None,
        }
    }

    #[test]
    fn advertised_window_no_scaling() {
        let tcb = make_test_tcb();
        // recv_buffer is 1024 bytes, all free
        assert_eq!(tcb.advertised_window(), 1024);
    }

    #[test]
    fn advertised_window_with_scaling() {
        let mut tcb = make_test_tcb();
        tcb.wscale_enabled = true;
        tcb.rcv_wscale = 7; // divide by 128
        // 1024 >> 7 = 8
        assert_eq!(tcb.advertised_window(), 8);
    }

    #[test]
    fn scale_incoming_window_no_scaling() {
        let tcb = make_test_tcb();
        assert_eq!(tcb.scale_incoming_window(512), 512);
    }

    #[test]
    fn scale_incoming_window_with_scaling() {
        let mut tcb = make_test_tcb();
        tcb.wscale_enabled = true;
        tcb.snd_wscale = 7; // multiply by 128
        assert_eq!(tcb.scale_incoming_window(512), 512 * 128);
    }
}
```

**Step 4: Apply `scale_incoming_window` to all `snd_wnd` assignments in Established+ states**

In `src/net/handler/tcp/mod.rs`, find every `tcb.snd_wnd = seg_wnd` that occurs after the SYN exchange:

1. In `process_established` (valid new ACK branch): change `tcb.snd_wnd = seg_wnd;` to `tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);`
2. In `process_teardown` FinWait1 ACK branch: same change.
3. Do NOT change the assignments in `process_syn_received` or `process_syn_sent` — those are during handshake where window is unscaled.

**Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/mod.rs
git commit -m "fix: apply window scaling to incoming seg_wnd and outgoing rcv_wnd"
```

---

## Task 2: Window Scaling Fix — Outgoing Window in All Segments

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** All `build_ack`, `build_data`, `build_fin_ack` calls pass either `DEFAULT_RCV_WND` (hardcoded 65535) or `recv_buffer.free_space().min(u16::MAX as usize) as u16` for the window parameter. Both are wrong when window scaling is enabled — they need to use `tcb.advertised_window()`.

**Step 1: Write a test verifying outgoing window is scaled**

Add to the test module in `src/net/handler/tcp/mod.rs`:

```rust
#[test]
fn outgoing_window_uses_wscale() {
    // Set up a connection with wscale_enabled and rcv_wscale = 7.
    // Send data to trigger an ACK, then verify the window field in the ACK
    // is downscaled by rcv_wscale.
    let mut handler = TcpHandler::new(false, false);
    let config = TcpConfig {
        recv_buffer_size: 1024, // power of 2
        send_buffer_size: 1024,
        ..TcpConfig::default()
    };
    let local_addr = IpAddress::V4(crate::net::wire::ip::Ipv4Address::new([10, 0, 0, 1]));
    let remote_addr = IpAddress::V4(crate::net::wire::ip::Ipv4Address::new([10, 0, 0, 2]));
    let local_port = 80u16;
    let remote_port = 12345u16;

    // Create a connection directly in Established state with wscale.
    let now = Instant::now();
    let conn_id = ConnectionId {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
    };

    // Use listen + inject SYN with wscale to establish connection properly.
    // For simplicity, manually create TCB:
    handler.connections.push(Tcb {
        id: conn_id,
        state: TcpState::Established,
        from_passive_open: true,
        iss: 100,
        snd_una: 101,
        snd_nxt: 101,
        snd_wnd: 65535,
        snd_wl1: 0,
        snd_wl2: 0,
        irs: 200,
        rcv_nxt: 201,
        rcv_wnd: 0,
        snd_mss: 1460,
        rcv_mss: 1460,
        eff_snd_mss: 1460,
        snd_wscale: 7,
        rcv_wscale: 7,
        wscale_enabled: true,
        retransmit_deadline: None,
        rto_backoff: 0,
        event_queue: crate::net::socket::LocalQueue::new(),
        send_buffer: RingBuffer::new(config.send_buffer_size),
        recv_buffer: RingBuffer::new(config.recv_buffer_size),
        ooo_ranges: std::collections::BTreeMap::new(),
        cwnd: 65535,
        ssthresh: 65535,
        dup_ack_count: 0,
        srtt: None,
        rttvar: 0,
        rto: 1000,
        last_send_time: None,
        pending_fin: false,
        fin_seq: None,
        time_wait_deadline: None,
        time_wait_duration: 60_000,
        ack_pending: false,
        delayed_ack_deadline: None,
        ack_delay_count: 0,
        delayed_ack_ms: 40,
        nagle_enabled: true,
        keep_alive_enabled: false,
        keep_alive_idle_ms: 7_200_000,
        keep_alive_interval_ms: 75_000,
        keep_alive_count: 9,
        last_activity: now,
        keep_alive_probes_sent: 0,
        linger: None,
        linger_deadline: None,
    });

    // Trigger a delayed ACK flush to get an outgoing segment.
    handler.connections[0].ack_pending = true;
    handler.connections[0].delayed_ack_deadline = Some(now); // already expired

    let src_mac = crate::net::wire::ethernet::MacAddress::new([0xAA; 6]);
    let neighbor = NeighborHandler::new(src_mac);
    let mut free = crate::xdp::frame::BasicFrameBuffer::new(4);
    let mut tx = crate::xdp::frame::BasicFrameBuffer::new(4);

    let buf = Box::leak(vec![0u8; 2048].into_boxed_slice());
    let frame = crate::xdp::frame::Frame::new(0, buf, 2048, false);
    free.push(frame);

    handler.poll_timers(now, src_mac, &neighbor, &mut free, &mut tx);

    assert_eq!(tx.num_frames(), 1);
    let out_frame = tx.pop().unwrap();
    let tcp_offset = 14 + 20; // ETH + IPv4
    let tcp = unsafe { TcpHeader::from_bytes_at(&out_frame, tcp_offset) };
    // 1024 bytes free >> 7 = 8
    assert_eq!(tcp.window(), 8);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test outgoing_window_uses_wscale`
Expected: FAIL — window will be 1024 (unscaled).

**Step 3: Replace all window computations with `advertised_window()`**

In `src/net/handler/tcp/mod.rs`, replace every occurrence of:
- `DEFAULT_RCV_WND` used as a window argument in ACK/data segments in Established+ states
- `tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16` and similar

With `tcb.advertised_window()`.

Specifically update these call sites:
1. `process_established` — delayed ACK flush `build_ack` call (line ~1231 area)
2. `process_established` — OOO duplicate ACK `build_ack` call
3. `process_established` — duplicate data ACK `build_ack` call
4. `process_established` — FIN handling `build_ack` call
5. `poll_timers` — delayed ACK pass `build_ack` call
6. `poll_timers` — keep-alive probe `build_ack` call
7. `poll_timers` — fast retransmit `build_data` call
8. `poll_timers` — RTO retransmit `build_data` call
9. `poll_send` — data `build_data` call
10. `poll_send` — FIN `build_fin_ack` call
11. `process_teardown` — all `build_ack` calls in FinWait1, FinWait2, TimeWait states
12. `process_syn_received` — challenge ACK (this one should stay as `DEFAULT_RCV_WND` since it's pre-Established)

**Important:** Keep `DEFAULT_RCV_WND` in `build_syn`, `build_syn_ack`, and the challenge ACK in `process_syn_received`. These are pre-Established.

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "fix: use advertised_window() for all outgoing segments"
```

---

## Task 3: Segment Acceptability Checks

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** RFC 9293 §3.10.7.4 requires checking that incoming segments fall within the receive window before processing. Currently no such check exists.

**Step 1: Write the acceptability helper and tests**

Add to `src/net/handler/tcp/mod.rs` (inside `impl TcpHandler` or as a free function):

```rust
/// Check segment acceptability per RFC 9293 §3.10.7.4.
///
/// Returns `true` if the segment is within the receive window.
#[inline]
fn is_segment_acceptable(seg_seq: u32, seg_len: u32, rcv_nxt: u32, rcv_wnd: u32) -> bool {
    use crate::net::wire::tcp::{seq_le, seq_lt};

    if seg_len == 0 {
        if rcv_wnd == 0 {
            seg_seq == rcv_nxt
        } else {
            // RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
            seq_le(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt.wrapping_add(rcv_wnd))
        }
    } else {
        if rcv_wnd == 0 {
            false
        } else {
            let seg_end = seg_seq.wrapping_add(seg_len - 1);
            let wnd_end = rcv_nxt.wrapping_add(rcv_wnd);
            // Start or end of segment in window
            (seq_le(rcv_nxt, seg_seq) && seq_lt(seg_seq, wnd_end))
                || (seq_le(rcv_nxt, seg_end) && seq_lt(seg_end, wnd_end))
        }
    }
}
```

Add tests:

```rust
#[test]
fn segment_acceptability_zero_len_zero_wnd() {
    // Only exact match accepted
    assert!(is_segment_acceptable(100, 0, 100, 0));
    assert!(!is_segment_acceptable(101, 0, 100, 0));
}

#[test]
fn segment_acceptability_zero_len_nonzero_wnd() {
    // SEG.SEQ must be in [RCV.NXT, RCV.NXT + RCV.WND)
    assert!(is_segment_acceptable(100, 0, 100, 1000));
    assert!(is_segment_acceptable(1099, 0, 100, 1000));
    assert!(!is_segment_acceptable(1100, 0, 100, 1000));
    assert!(!is_segment_acceptable(99, 0, 100, 1000));
}

#[test]
fn segment_acceptability_nonzero_len_zero_wnd() {
    // Never acceptable
    assert!(!is_segment_acceptable(100, 10, 100, 0));
}

#[test]
fn segment_acceptability_nonzero_len_nonzero_wnd() {
    // Start in window
    assert!(is_segment_acceptable(100, 10, 100, 1000));
    // End in window (start before)
    assert!(is_segment_acceptable(95, 10, 100, 1000));
    // Completely outside
    assert!(!is_segment_acceptable(1200, 10, 100, 1000));
    // Completely before
    assert!(!is_segment_acceptable(80, 10, 100, 1000));
}
```

**Step 2: Add the check at the top of `process_established`**

After the RST check (step 1 in process_established), before ACK processing, add:

```rust
// Segment acceptability check (RFC 9293 §3.10.7.4).
{
    let tcb = &self.connections[idx];
    let seg_len = Tcb::seg_len(payload_len, seg_flags);
    let rcv_wnd = if tcb.wscale_enabled {
        tcb.recv_buffer.free_space() as u32
    } else {
        tcb.recv_buffer.free_space().min(u16::MAX as usize) as u32
    };
    if !is_segment_acceptable(seg_seq, seg_len, tcb.rcv_nxt, rcv_wnd) {
        if seg_flags & flags::RST == 0 {
            // Send ACK for out-of-window segment.
            SegmentBuilder::build_ack(
                tcb.id.local_addr,
                tcb.id.remote_addr,
                tcb.id.local_port,
                tcb.id.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                tcb.advertised_window(),
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
            );
        }
        rx_return.push(frame);
        return;
    }
}
```

**Step 3: Add similar check at the top of `process_teardown`**

After the RST check in `process_teardown`, add the same acceptability check (before the `match state` block). The check is the same code — extract the rcv_wnd from the TCB and call `is_segment_acceptable`.

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass. Some existing tests may need adjustment if they were sending segments with bogus sequence numbers that now get rejected.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat: add segment acceptability checks per RFC 9293"
```

---

## Task 4: TCP Options — Timestamp and SACK Permitted Wire Format

**Files:**
- Modify: `src/net/wire/tcp.rs`

**Context:** Add option constants, parsing, and writing functions for Timestamps (Kind=8) and SACK Permitted (Kind=4). SACK block parsing (Kind=5) is also added here for later use.

**Step 1: Add option constants**

In `src/net/wire/tcp.rs`, extend the `options` module:

```rust
pub mod options {
    pub const END: u8 = 0;
    pub const NOP: u8 = 1;
    pub const MSS: u8 = 2;
    pub const WINDOW_SCALE: u8 = 3;
    pub const SACK_PERMITTED: u8 = 4;
    pub const SACK: u8 = 5;
    pub const TIMESTAMP: u8 = 8;
}
```

**Step 2: Add timestamp parsing and writing**

```rust
/// Parse Timestamp option (Kind=8, Len=10).
/// Returns (TSval, TSecr) or None if not present.
pub fn parse_timestamp(options: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            options::END => break,
            options::NOP => { i += 1; }
            options::TIMESTAMP => {
                if i + 10 > options.len() { return None; }
                if options[i + 1] != 10 { return None; }
                let tsval = u32::from_be_bytes([
                    options[i + 2], options[i + 3], options[i + 4], options[i + 5],
                ]);
                let tsecr = u32::from_be_bytes([
                    options[i + 6], options[i + 7], options[i + 8], options[i + 9],
                ]);
                return Some((tsval, tsecr));
            }
            _ => {
                if i + 1 >= options.len() { return None; }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() { return None; }
                i += len;
            }
        }
    }
    None
}

/// Write a 10-byte Timestamp option. Returns 10.
pub fn write_timestamp_option(buf: &mut [u8], tsval: u32, tsecr: u32) -> usize {
    buf[0] = options::TIMESTAMP;
    buf[1] = 10;
    buf[2..6].copy_from_slice(&tsval.to_be_bytes());
    buf[6..10].copy_from_slice(&tsecr.to_be_bytes());
    10
}
```

**Step 3: Add SACK Permitted parsing and writing**

```rust
/// Check if SACK Permitted option (Kind=4, Len=2) is present.
pub fn parse_sack_permitted(options: &[u8]) -> bool {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            options::END => break,
            options::NOP => { i += 1; }
            options::SACK_PERMITTED => {
                if i + 2 > options.len() { return false; }
                if options[i + 1] != 2 { return false; }
                return true;
            }
            _ => {
                if i + 1 >= options.len() { return false; }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() { return false; }
                i += len;
            }
        }
    }
    false
}

/// Write a 2-byte SACK Permitted option. Returns 2.
pub fn write_sack_permitted_option(buf: &mut [u8]) -> usize {
    buf[0] = options::SACK_PERMITTED;
    buf[1] = 2;
    2
}
```

**Step 4: Add SACK block parsing and writing**

```rust
/// Parse SACK blocks (Kind=5, variable length).
/// Returns up to 4 blocks as (left_edge, right_edge) pairs and the count.
pub fn parse_sack_blocks(options: &[u8]) -> ([Option<(u32, u32)>; 4], usize) {
    let mut blocks = [None; 4];
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            options::END => break,
            options::NOP => { i += 1; }
            options::SACK => {
                if i + 2 > options.len() { return (blocks, 0); }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() { return (blocks, 0); }
                let data_len = len - 2;
                let num_blocks = data_len / 8;
                let count = num_blocks.min(4);
                for b in 0..count {
                    let off = i + 2 + b * 8;
                    let left = u32::from_be_bytes([
                        options[off], options[off + 1], options[off + 2], options[off + 3],
                    ]);
                    let right = u32::from_be_bytes([
                        options[off + 4], options[off + 5], options[off + 6], options[off + 7],
                    ]);
                    blocks[b] = Some((left, right));
                }
                return (blocks, count);
            }
            _ => {
                if i + 1 >= options.len() { return (blocks, 0); }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() { return (blocks, 0); }
                i += len;
            }
        }
    }
    (blocks, 0)
}

/// Write SACK blocks option. Returns bytes written (2 + 8*N).
/// `blocks` should contain up to 4 (left_edge, right_edge) pairs.
pub fn write_sack_option(buf: &mut [u8], blocks: &[(u32, u32)]) -> usize {
    let count = blocks.len().min(4);
    let len = 2 + count * 8;
    buf[0] = options::SACK;
    buf[1] = len as u8;
    for (i, &(left, right)) in blocks.iter().take(count).enumerate() {
        let off = 2 + i * 8;
        buf[off..off + 4].copy_from_slice(&left.to_be_bytes());
        buf[off + 4..off + 8].copy_from_slice(&right.to_be_bytes());
    }
    len
}
```

**Step 5: Write tests for all new functions**

```rust
#[test]
fn parse_timestamp_valid() {
    let opts = [options::TIMESTAMP, 10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];
    assert_eq!(parse_timestamp(&opts), Some((0x00010000, 0x00020000)));
}

#[test]
fn parse_timestamp_absent() {
    let opts = [options::MSS, 4, 0x05, 0xB4];
    assert_eq!(parse_timestamp(&opts), None);
}

#[test]
fn write_timestamp_option_roundtrip() {
    let mut buf = [0u8; 10];
    let written = write_timestamp_option(&mut buf, 12345, 67890);
    assert_eq!(written, 10);
    assert_eq!(parse_timestamp(&buf), Some((12345, 67890)));
}

#[test]
fn parse_sack_permitted_valid() {
    let opts = [options::SACK_PERMITTED, 2];
    assert!(parse_sack_permitted(&opts));
}

#[test]
fn parse_sack_permitted_absent() {
    let opts = [options::MSS, 4, 0x05, 0xB4];
    assert!(!parse_sack_permitted(&opts));
}

#[test]
fn write_sack_permitted_roundtrip() {
    let mut buf = [0u8; 2];
    let written = write_sack_permitted_option(&mut buf);
    assert_eq!(written, 2);
    assert!(parse_sack_permitted(&buf));
}

#[test]
fn parse_sack_blocks_valid() {
    let mut opts = [0u8; 18]; // 2 header + 2 blocks * 8
    opts[0] = options::SACK;
    opts[1] = 18;
    opts[2..6].copy_from_slice(&100u32.to_be_bytes());
    opts[6..10].copy_from_slice(&200u32.to_be_bytes());
    opts[10..14].copy_from_slice(&300u32.to_be_bytes());
    opts[14..18].copy_from_slice(&400u32.to_be_bytes());
    let (blocks, count) = parse_sack_blocks(&opts);
    assert_eq!(count, 2);
    assert_eq!(blocks[0], Some((100, 200)));
    assert_eq!(blocks[1], Some((300, 400)));
}

#[test]
fn write_sack_option_roundtrip() {
    let mut buf = [0u8; 34];
    let sack_blocks = [(100, 200), (300, 400)];
    let written = write_sack_option(&mut buf, &sack_blocks);
    assert_eq!(written, 18);
    let (blocks, count) = parse_sack_blocks(&buf[..written]);
    assert_eq!(count, 2);
    assert_eq!(blocks[0], Some((100, 200)));
    assert_eq!(blocks[1], Some((300, 400)));
}

#[test]
fn parse_all_options_mixed() {
    // MSS + NOP + WSCALE + NOP + NOP + TIMESTAMP + SACK_PERMITTED
    let mut opts = [0u8; 24];
    let mut i = 0;
    i += write_mss_option(&mut opts[i..], 1460); // 4
    opts[i] = options::NOP; i += 1; // 5
    i += write_window_scale_option(&mut opts[i..], 7); // 8
    opts[i] = options::NOP; i += 1; // 9
    opts[i] = options::NOP; i += 1; // 10
    i += write_timestamp_option(&mut opts[i..], 1000, 2000); // 20
    i += write_sack_permitted_option(&mut opts[i..]); // 22

    assert_eq!(parse_mss(&opts[..i]), Some(1460));
    assert_eq!(parse_window_scale(&opts[..i]), Some(7));
    assert_eq!(parse_timestamp(&opts[..i]), Some((1000, 2000)));
    assert!(parse_sack_permitted(&opts[..i]));
}
```

**Step 6: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add src/net/wire/tcp.rs
git commit -m "feat: add timestamp, SACK permitted, and SACK block option parsing/writing"
```

---

## Task 5: Timestamp and SACK TCB Fields

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`

**Context:** Add fields to `TcpConfig` and `Tcb` for timestamp and SACK state.

**Step 1: Add TcpConfig fields**

In `TcpConfig` struct, add after `linger`:

```rust
/// Enable TCP timestamps (RFC 7323). Default: true.
pub timestamps: bool,
/// Enable SACK (RFC 2018). Default: true.
pub sack: bool,
```

In `Default for TcpConfig`, add:

```rust
timestamps: true,
sack: true,
```

**Step 2: Add Tcb fields**

In `Tcb` struct, add after the linger section:

```rust
// --- Timestamps (RFC 7323) ---
/// Whether timestamps were negotiated.
pub ts_enabled: bool,
/// Most recent TSval received from peer.
pub ts_recent: u32,
/// When ts_recent was last updated.
pub ts_recent_age: Instant,
/// Base instant for deriving our monotonic timestamp clock.
pub ts_offset: Instant,

// --- SACK ---
/// Whether SACK was negotiated.
pub sack_enabled: bool,
/// Scoreboard: byte ranges the peer has confirmed receiving (left_edge -> right_edge).
pub sack_scoreboard: BTreeMap<u32, u32>,

// --- Zero-window probing ---
/// Deadline for next zero-window probe.
pub persist_deadline: Option<Instant>,
/// Exponential backoff counter for persist probes (cap at 6).
pub persist_backoff: u8,
```

**Step 3: Update all Tcb construction sites**

In `src/net/handler/tcp/mod.rs`, find every place where a `Tcb { ... }` is constructed (active open and passive open paths) and add the new fields with defaults:

```rust
ts_enabled: false,
ts_recent: 0,
ts_recent_age: now,
ts_offset: now,
sack_enabled: false,
sack_scoreboard: BTreeMap::new(),
persist_deadline: None,
persist_backoff: 0,
```

Also update `ListenEntry` to include `timestamps` and `sack` fields (carried from TcpConfig).

**Step 4: Update test TCB construction**

Update `make_test_tcb()` and any inline Tcb construction in tests to include the new fields.

**Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/mod.rs
git commit -m "feat: add timestamp, SACK, and persist timer TCB fields"
```

---

## Task 6: Timestamp Negotiation in SYN/SYN-ACK

**Files:**
- Modify: `src/net/handler/tcp/segment.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** SYN and SYN-ACK must include the Timestamp option when `TcpConfig::timestamps` is true. SACK Permitted is also included when `TcpConfig::sack` is true. Update `build_syn` and `build_syn_ack` to accept optional timestamp and SACK permitted parameters.

**Step 1: Update `build_syn` signature and option buffer**

Change `build_syn` to accept additional parameters:

```rust
pub fn build_syn<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    iss: u32,
    window: u16,
    mss: u16,
    wscale: u8,
    timestamp: Option<(u32, u32)>,  // NEW: (TSval, TSecr=0)
    sack_permitted: bool,            // NEW
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
)
```

Update the option buffer to 24 bytes and build options:

```rust
let mut opt_buf = [0u8; 24];
let mut opt_len = write_mss_option(&mut opt_buf, mss);
opt_buf[opt_len] = options::NOP;
opt_len += 1;
opt_len += write_window_scale_option(&mut opt_buf[opt_len..], wscale);
if let Some((tsval, tsecr)) = timestamp {
    opt_buf[opt_len] = options::NOP;
    opt_len += 1;
    opt_buf[opt_len] = options::NOP;
    opt_len += 1;
    opt_len += write_timestamp_option(&mut opt_buf[opt_len..], tsval, tsecr);
}
if sack_permitted {
    opt_len += write_sack_permitted_option(&mut opt_buf[opt_len..]);
}
```

**Step 2: Update `build_syn_ack` similarly**

Add `timestamp: Option<(u32, u32)>` and `sack_permitted: bool` parameters. Build options in same order as SYN.

**Step 3: Update all `build_syn` and `build_syn_ack` call sites**

In `src/net/handler/tcp/mod.rs`:
- Active open `connect`/`connect_with_config`: pass `timestamp` based on config, `sack_permitted` based on config
- Passive open (SYN-RECEIVED creation in `process_listen`): pass timestamp/sack based on listener config
- SYN retransmit in `poll_timers`: pass the stored config values
- SYN-ACK retransmit in `poll_timers`: pass stored config values
- Simultaneous open SYN-ACK in `process_syn_sent`: pass stored values

For the timestamp TSval, compute from `now`: `now.duration_since(tcb.ts_offset).as_millis() as u32`
For SYN, TSecr is always 0. For SYN-ACK, TSecr should echo the peer's TSval (stored in `ts_recent` after parsing the SYN).

**Step 4: Parse peer options in SYN/SYN-ACK processing**

In `process_listen` (when receiving SYN):
- Call `parse_timestamp(options)` — if present AND our config allows timestamps, set `tcb.ts_enabled = true`, `tcb.ts_recent = peer_tsval`
- Call `parse_sack_permitted(options)` — if present AND our config allows SACK, set `tcb.sack_enabled = true`

In `process_syn_sent` (when receiving SYN-ACK):
- Same timestamp/SACK negotiation logic

**Step 5: Write test for timestamp negotiation**

```rust
#[test]
fn timestamp_negotiated_in_handshake() {
    // Build a SYN with timestamps, verify option is present in the frame.
    let mut free = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let buf = Box::leak(vec![0u8; 2048].into_boxed_slice());
    free.push(Frame::new(0, buf, 2048, false));

    SegmentBuilder::build_syn(
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
        8080, 80, 1000,
        65535, 1460, 7,
        Some((12345, 0)),  // timestamp
        true,              // sack_permitted
        MacAddress::new([0xAA; 6]),
        MacAddress::new([0xBB; 6]),
        false,
        &mut free, &mut tx,
    );

    assert_eq!(tx.num_frames(), 1);
    let frame = tx.pop().unwrap();
    let tcp_offset = 14 + 20;
    let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
    // Data offset should be > 5 (options present)
    assert!(tcp.data_offset() > 5);

    // Parse options from the frame
    let opt_start = tcp_offset + TCP_HEADER_LEN;
    let opt_end = tcp_offset + tcp.header_len();
    let options = &frame[opt_start..opt_end];
    assert_eq!(parse_timestamp(options).map(|(v, _)| v), Some(12345));
    assert!(parse_sack_permitted(options));
}
```

**Step 6: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat: negotiate timestamps and SACK permitted in SYN/SYN-ACK"
```

---

## Task 7: Timestamps in Data/ACK Segments + RTTM

**Files:**
- Modify: `src/net/handler/tcp/segment.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** When timestamps are negotiated, every segment must include the TS option (12 bytes with NOP padding). ACKs use TSecr to echo the peer's timestamp for RTT measurement. On receiving ACKs with TSecr, compute RTT and feed into the existing SRTT/RTTVAR/RTO estimator.

**Step 1: Update `build_ack`, `build_data`, `build_fin_ack` to accept optional timestamp**

Add `timestamp: Option<(u32, u32)>` parameter to each. When `Some`, include 12 bytes of options (NOP + NOP + TS option). For `build_ack` and `build_fin_ack`, pass the options to `build_ipv4_segment`/`build_ipv6_segment`. For `build_data`, change `build_ipv4_data_segment`/`build_ipv6_data_segment` to accept `tcp_options: &[u8]`.

For `build_data`, the internal helpers need to handle both options AND payload. Update `build_ipv4_data_segment` and `build_ipv6_data_segment` to accept a `tcp_options: &[u8]` parameter (currently hardcoded as `&[]`). Adjust header size calculation: `tcp_header_len = TCP_HEADER_LEN + opt_padded_len`.

**Step 2: Update all call sites to pass timestamps**

Wherever `build_ack`, `build_data`, `build_fin_ack` are called, compute the timestamp tuple if `tcb.ts_enabled`:

```rust
let ts = if tcb.ts_enabled {
    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
    Some((tsval, tcb.ts_recent))
} else {
    None
};
```

Pass `ts` to the builder call.

**Step 3: RTTM — update RTT from TSecr on ACK**

In `process_established`, in the valid new ACK branch, after advancing `snd_una`, if `ts_enabled`:

```rust
if tcb.ts_enabled {
    // Parse timestamp from incoming segment options.
    if let Some((_tsval, tsecr)) = parse_timestamp(options) {
        if tsecr != 0 {
            let our_ts = now.duration_since(tcb.ts_offset).as_millis() as u32;
            let rtt_ms = our_ts.wrapping_sub(tsecr) as u64;
            // Feed into RFC 6298 estimator (same logic, just more samples).
            match tcb.srtt {
                None => {
                    tcb.srtt = Some(rtt_ms);
                    tcb.rttvar = rtt_ms / 2;
                }
                Some(srtt) => {
                    let diff = rtt_ms.abs_diff(srtt);
                    tcb.rttvar = (3 * tcb.rttvar + diff) / 4;
                    tcb.srtt = Some((7 * srtt + rtt_ms) / 8);
                }
            }
            tcb.rto = (tcb.srtt.unwrap() + 4 * tcb.rttvar).clamp(1000, 60_000);
        }
    }
}
```

When timestamps are enabled, skip the old `last_send_time`-based RTT measurement (it's superseded by RTTM).

**Step 4: Update ts_recent on incoming segments**

In `process_established`, after acceptability check, when receiving data or ACK:

```rust
if tcb.ts_enabled {
    if let Some((tsval, _)) = parse_timestamp(options) {
        tcb.ts_recent = tsval;
        tcb.ts_recent_age = now;
    }
}
```

**Step 5: Pass options through to process_established and process_teardown**

Currently `process_established` doesn't receive the TCP options. Add an `options: &[u8]` parameter to `process_established` and `process_teardown`. Parse it from the frame in `process_segment` (the options are at `tcp_offset + TCP_HEADER_LEN .. tcp_offset + header_len`) and pass to the state handlers.

**Step 6: Write test for RTTM**

```rust
#[test]
fn timestamp_rttm_updates_rto() {
    // Set up connection with ts_enabled.
    // Send data (writes TSval into segment).
    // Receive ACK echoing our TSval.
    // Verify srtt/rto updated.
    // (Details: create TCB with ts_enabled, manually call process_established
    //  with a crafted ACK containing TSecr matching a known TSval)
}
```

**Step 7: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 8: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat: include timestamps in data/ACK segments, implement RTTM"
```

---

## Task 8: PAWS (Protection Against Wrapped Sequences)

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** RFC 7323 §5 — before segment acceptability check, reject segments with old timestamps. This prevents wrapped sequence numbers from being accepted on high-bandwidth connections.

**Step 1: Add PAWS check in `process_established`**

After RST check, before segment acceptability check, add:

```rust
// PAWS check (RFC 7323 §5).
if self.connections[idx].ts_enabled {
    if let Some((tsval, _)) = parse_timestamp(options) {
        let tcb = &self.connections[idx];
        // Check if TSval is older than ts_recent.
        // Use signed comparison for wraparound.
        let ts_diff = tsval.wrapping_sub(tcb.ts_recent) as i32;
        if ts_diff < 0 && seg_flags & flags::RST == 0 {
            // Check staleness: if ts_recent is older than 24 days, accept anyway.
            let staleness = now.duration_since(tcb.ts_recent_age).as_millis();
            if staleness < 24 * 24 * 60 * 60 * 1000 {
                // Reject: send ACK and drop.
                let tcb = &self.connections[idx];
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    tcb.advertised_window(),
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
                rx_return.push(frame);
                return;
            }
        }
    }
}
```

**Step 2: Add same PAWS check in `process_teardown`**

Same logic, placed after RST check and before state-specific processing.

**Step 3: Write tests**

```rust
#[test]
fn paws_rejects_old_timestamp() {
    // Create connection with ts_enabled and ts_recent = 1000.
    // Send segment with TSval = 999 (older).
    // Verify segment is dropped and ACK is sent.
}

#[test]
fn paws_accepts_rst_with_old_timestamp() {
    // RST segments bypass PAWS.
    // Create connection, send RST with old TSval.
    // Verify connection is removed (RST processed).
}

#[test]
fn paws_accepts_stale_ts_recent() {
    // If ts_recent_age > 24 days, accept even with old TSval.
    // (Hard to test with real time, but can set ts_recent_age to a very old Instant.)
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat: implement PAWS timestamp validation"
```

---

## Task 9: Zero-Window Probing

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** When the peer advertises window=0, the sender must periodically probe with 1-byte segments to detect when the window reopens. Without this, connections deadlock if the window update ACK is lost.

**Step 1: Add persist timer logic to `poll_send`**

In `poll_send`, after computing `send_window` and `can_send`, when `send_window == 0` and `data_available > 0`:

```rust
// Zero-window probing (persist timer).
if send_window == 0 && data_available > 0 {
    if tcb.persist_deadline.is_none() {
        // Start persist timer.
        tcb.persist_deadline = Some(now + coarsetime::Duration::from_millis(tcb.rto));
    } else if let Some(deadline) = tcb.persist_deadline {
        if now >= deadline {
            // Send 1-byte probe.
            let mut probe_byte = [0u8; 1];
            tcb.send_buffer.peek_at(bytes_in_flight, &mut probe_byte);

            let dst_mac = neighbor_handler
                .lookup(now, &tcb.id.remote_addr)
                .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

            let ts = if tcb.ts_enabled {
                let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                Some((tsval, tcb.ts_recent))
            } else {
                None
            };

            SegmentBuilder::build_data(
                tcb.id.local_addr,
                tcb.id.remote_addr,
                tcb.id.local_port,
                tcb.id.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                tcb.advertised_window(),
                &probe_byte,
                src_mac,
                dst_mac,
                self.tx_offload,
                ts,
                free_frames,
                tx_return,
            );

            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);

            // Exponential backoff, capped at ~60s.
            let backoff_rto = (tcb.rto << tcb.persist_backoff).min(60_000);
            tcb.persist_deadline = Some(now + coarsetime::Duration::from_millis(backoff_rto));
            if tcb.persist_backoff < 6 {
                tcb.persist_backoff += 1;
            }
        }
    }
    continue; // Skip normal data sending when window is 0.
}
```

**Step 2: Reset persist timer when window reopens**

In `process_established`, in the valid new ACK branch, after updating `snd_wnd`, add:

```rust
// Reset persist timer if window reopened.
if tcb.snd_wnd > 0 {
    tcb.persist_deadline = None;
    tcb.persist_backoff = 0;
}
```

**Step 3: Write tests**

```rust
#[test]
fn persist_probe_sent_on_zero_window() {
    // Set up established connection with snd_wnd = 0 and data in send buffer.
    // Call poll_send — should set persist_deadline but not send yet.
    // Advance time past deadline, call poll_send again.
    // Verify 1-byte probe segment emitted.
}

#[test]
fn persist_backoff_increases() {
    // After first probe, persist_backoff should be 1.
    // After second probe, persist_backoff should be 2.
    // Verify deadline intervals increase.
}

#[test]
fn persist_timer_cleared_on_window_reopen() {
    // Set up connection with persist_deadline set.
    // Process an ACK with snd_wnd > 0.
    // Verify persist_deadline is None and persist_backoff is 0.
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat: implement zero-window probing with persist timer"
```

---

## Task 10: SACK — Sending SACK Blocks in Duplicate ACKs

**Files:**
- Modify: `src/net/handler/tcp/segment.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** When OOO data arrives and SACK is enabled, the duplicate ACK should include SACK blocks reporting which byte ranges we have. This allows the sender to selectively retransmit only missing segments.

**Step 1: Add `build_ack_with_options` to SegmentBuilder**

Rather than modifying `build_ack` further, add a new builder that accepts pre-built option bytes:

```rust
/// Build an ACK segment with TCP options (timestamps, SACK blocks, etc.).
pub fn build_ack_with_options<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    tcp_options: &[u8],
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // Delegate to build_ipv4_segment / build_ipv6_segment with options
    match (local_addr, remote_addr) {
        (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
            Self::build_ipv4_segment(
                local_ip, remote_ip, local_port, remote_port,
                seq, ack, flags::ACK, window,
                tcp_options, src_mac, dst_mac, tx_offload,
                free_frames, tx_return,
            );
        }
        (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
            Self::build_ipv6_segment(
                local_ip, remote_ip, local_port, remote_port,
                seq, ack, flags::ACK, window,
                tcp_options, src_mac, dst_mac, tx_offload,
                free_frames, tx_return,
            );
        }
        _ => {}
    }
}
```

**Step 2: Build SACK blocks from ooo_ranges in OOO data path**

In `process_established`, in the OOO data branch (where duplicate ACK is sent), replace the plain `build_ack` with SACK-aware logic:

```rust
} else if seq_lt(rcv_nxt, seg_seq) {
    // Out-of-order data.
    let offset = seg_seq.wrapping_sub(rcv_nxt) as usize;
    let payload = &frame[payload_offset..payload_offset + payload_len];
    let tcb = &mut self.connections[idx];
    tcb.recv_buffer.write_at(offset, payload);
    tcb.ooo_ranges.insert(seg_seq, payload_len as u32);

    // Build SACK blocks from ooo_ranges (most recent first).
    let tcb = &self.connections[idx];
    let mut opt_buf = [0u8; 40];
    let mut opt_len = 0;

    // Add timestamp if enabled.
    if tcb.ts_enabled {
        opt_buf[opt_len] = options::NOP; opt_len += 1;
        opt_buf[opt_len] = options::NOP; opt_len += 1;
        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
        opt_len += write_timestamp_option(&mut opt_buf[opt_len..], tsval, tcb.ts_recent);
    }

    if tcb.sack_enabled {
        // Collect SACK blocks: most recent first, up to space limit.
        let max_blocks = if tcb.ts_enabled { 3 } else { 4 };
        let mut sack_blocks = Vec::new();
        // The range just received goes first.
        sack_blocks.push((seg_seq, seg_seq.wrapping_add(payload_len as u32)));
        // Then other ranges.
        for (&seq, &len) in tcb.ooo_ranges.iter().rev() {
            if seq == seg_seq { continue; } // already added
            if sack_blocks.len() >= max_blocks { break; }
            sack_blocks.push((seq, seq.wrapping_add(len)));
        }
        opt_len += write_sack_option(&mut opt_buf[opt_len..], &sack_blocks);
    }

    SegmentBuilder::build_ack_with_options(
        tcb.id.local_addr,
        tcb.id.remote_addr,
        tcb.id.local_port,
        tcb.id.remote_port,
        tcb.snd_nxt,
        tcb.rcv_nxt,
        tcb.advertised_window(),
        &opt_buf[..opt_len],
        src_mac,
        dst_mac,
        self.tx_offload,
        free_frames,
        tx_return,
    );
}
```

**Step 3: Write test**

```rust
#[test]
fn sack_blocks_sent_on_ooo_data() {
    // Set up established connection with sack_enabled.
    // Send in-order data at seq=201.
    // Send OOO data at seq=301 (gap at 211-300).
    // Verify the duplicate ACK contains a SACK block for [301, 301+len).
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat: send SACK blocks in duplicate ACKs for OOO data"
```

---

## Task 11: SACK — Scoreboard and Selective Retransmission

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** When we receive ACKs with SACK blocks from the peer, update the scoreboard. Use the scoreboard during fast retransmit to selectively retransmit only missing segments instead of retransmitting from `snd_una`.

**Step 1: Parse SACK blocks on incoming ACKs**

In `process_established`, in the valid new ACK branch, after updating `snd_una`:

```rust
// Update SACK scoreboard.
if tcb.sack_enabled {
    // Remove entries below new snd_una.
    let una = tcb.snd_una;
    tcb.sack_scoreboard.retain(|&left, _| !seq_lt(left, una));

    // Parse new SACK blocks from incoming segment.
    let (blocks, count) = parse_sack_blocks(options);
    for i in 0..count {
        if let Some((left, right)) = blocks[i] {
            tcb.sack_scoreboard.insert(left, right);
        }
    }
}
```

Also handle SACK blocks in the duplicate ACK branch:

```rust
} else if seg_ack == snd_una && payload_len == 0 {
    // Duplicate ACK.
    let tcb = &mut self.connections[idx];
    tcb.dup_ack_count += 1;
    // Keep-alive probe response handling...

    // Update SACK scoreboard on duplicate ACK.
    if tcb.sack_enabled {
        let (blocks, count) = parse_sack_blocks(options);
        for i in 0..count {
            if let Some((left, right)) = blocks[i] {
                tcb.sack_scoreboard.insert(left, right);
            }
        }
    }
}
```

**Step 2: Use scoreboard in fast retransmit**

In `poll_timers`, in the fast retransmit pass, when `sack_enabled`:

```rust
if tcb.sack_enabled && !tcb.sack_scoreboard.is_empty() {
    // Find first gap: scan from snd_una looking for the first byte
    // NOT covered by a SACK block.
    let mut retransmit_start = tcb.snd_una;
    for (&left, &right) in &tcb.sack_scoreboard {
        if seq_le(left, retransmit_start) && seq_lt(retransmit_start, right) {
            // retransmit_start is inside a SACKed range — skip past it.
            retransmit_start = right;
        }
    }

    if seq_lt(retransmit_start, tcb.snd_nxt) {
        // Retransmit from the gap.
        let offset = retransmit_start.wrapping_sub(tcb.snd_una) as usize;
        let gap_len = // find end of gap (next SACK left edge or snd_nxt)
            tcb.sack_scoreboard.iter()
                .find(|(&left, _)| seq_lt(retransmit_start, left))
                .map(|(&left, _)| left.wrapping_sub(retransmit_start) as usize)
                .unwrap_or((tcb.snd_nxt.wrapping_sub(retransmit_start)) as usize);
        let retransmit_len = gap_len.min(tcb.eff_snd_mss as usize);

        let mut payload = vec![0u8; retransmit_len];
        tcb.send_buffer.peek_at(offset, &mut payload);
        // ... build_data with payload, same as current fast retransmit
    }
} else {
    // Original fast retransmit from snd_una.
    // ... existing code
}
```

**Step 3: Clear scoreboard on RTO**

In `poll_timers` RTO retransmit path for Established state, add:

```rust
tcb.sack_scoreboard.clear();
```

**Step 4: Write tests**

```rust
#[test]
fn sack_scoreboard_updated_on_ack() {
    // Set up connection with sack_enabled.
    // Send 3 segments.
    // Receive ACK with SACK blocks for segments 2 and 3.
    // Verify scoreboard has the right entries.
}

#[test]
fn sack_selective_retransmit() {
    // Set up connection with data in flight at snd_una..snd_nxt.
    // Populate scoreboard with SACKed ranges (middle segment).
    // Trigger fast retransmit (dup_ack_count >= 3).
    // Verify retransmit is for the gap, not from snd_una.
}

#[test]
fn sack_scoreboard_cleared_on_rto() {
    // Populate scoreboard, trigger RTO.
    // Verify scoreboard is empty after RTO retransmit.
}
```

**Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat: SACK scoreboard tracking and selective retransmission"
```

---

## Task 12: Zero-Copy Send Path — Ring Buffer peek_slices

**Files:**
- Modify: `src/net/handler/tcp/ring_buffer.rs`

**Context:** Add `peek_slices` method that returns two slices instead of copying into a buffer. This eliminates heap allocation in the data send path.

**Step 1: Write failing tests**

```rust
#[test]
fn peek_slices_no_wrap() {
    let mut rb = RingBuffer::new(64);
    rb.write(b"hello world");
    let (a, b) = rb.peek_slices(0, 5);
    assert_eq!(a, b"hello");
    assert!(b.is_empty());
    assert_eq!(rb.available(), 11); // unchanged
}

#[test]
fn peek_slices_with_wrap() {
    let mut rb = RingBuffer::new(16);
    rb.write(&[0xAA; 12]);
    let mut discard = [0u8; 12];
    rb.read(&mut discard);
    // head=12, tail=12. Write 8 bytes wrapping.
    rb.write(&[0xBB; 8]);
    // Data spans 12..15 (4 bytes) and 0..3 (4 bytes).
    let (a, b) = rb.peek_slices(0, 8);
    assert_eq!(a, &[0xBB; 4]);
    assert_eq!(b, &[0xBB; 4]);
}

#[test]
fn peek_slices_with_offset() {
    let mut rb = RingBuffer::new(64);
    rb.write(b"hello world");
    let (a, b) = rb.peek_slices(6, 5);
    assert_eq!(a, b"world");
    assert!(b.is_empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test peek_slices`
Expected: FAIL — method doesn't exist.

**Step 3: Implement `peek_slices`**

```rust
/// Return two slices covering `len` bytes starting at `offset` from head,
/// without advancing head. Second slice is empty if data doesn't wrap.
#[inline]
pub fn peek_slices(&self, offset: usize, len: usize) -> (&[u8], &[u8]) {
    let pos = (self.head.wrapping_add(offset)) & self.mask;
    let first_len = len.min(self.buf.len() - pos);
    if first_len >= len {
        (&self.buf[pos..pos + len], &[])
    } else {
        let second_len = len - first_len;
        (&self.buf[pos..pos + first_len], &self.buf[..second_len])
    }
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/ring_buffer.rs
git commit -m "feat: add peek_slices for zero-copy send path"
```

---

## Task 13: Zero-Copy Send Path — Two-Slice build_data

**Files:**
- Modify: `src/net/handler/tcp/segment.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Context:** Change `build_data` to accept `(&[u8], &[u8])` instead of `&[u8]`, write both slices into the frame, and update all call sites to use `peek_slices`.

**Step 1: Update `build_data` signature**

Change `payload: &[u8]` to `payload: (&[u8], &[u8])`. Update the internal helpers `build_ipv4_data_segment` and `build_ipv6_data_segment` similarly:

```rust
pub fn build_data<'umem>(
    // ... same params ...
    payload: (&[u8], &[u8]),  // CHANGED
    // ... same params ...
)
```

In the internal helpers, compute total payload length as `payload.0.len() + payload.1.len()`. Copy both slices contiguously:

```rust
let payload_offset = tcp_offset + tcp_header_len;
frame[payload_offset..payload_offset + payload.0.len()].copy_from_slice(payload.0);
let second_start = payload_offset + payload.0.len();
frame[second_start..second_start + payload.1.len()].copy_from_slice(payload.1);
```

For checksum, the existing approach computes over `&frame[tcp_offset..frame_len]` after writing — this already covers both slices since they're in the frame.

**Step 2: Update all call sites in `mod.rs`**

Replace all `build_data` calls:

1. **poll_send data path:** Replace the `vec![0u8; to_send]` + `peek_at` with:
```rust
let (slice_a, slice_b) = tcb.send_buffer.peek_slices(bytes_in_flight, to_send);
// ... pass (slice_a, slice_b) to build_data
```

2. **poll_timers fast retransmit:** Same replacement.

3. **poll_timers RTO retransmit:** Same replacement.

4. **Zero-window probe** (Task 9): The 1-byte probe can use `(&probe_byte, &[])`.

**Step 3: Update existing `build_data` test**

The existing `build_data_ipv4` test passes `payload` as `&[u8]` — change to pass `(payload, &[])`.

**Step 4: Write test for two-slice payload**

```rust
#[test]
fn build_data_two_slices() {
    let mut free = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let buf = Box::leak(vec![0u8; 2048].into_boxed_slice());
    free.push(Frame::new(100, buf, 2048, false));

    let part1 = b"Hello";
    let part2 = b", TCP!";

    SegmentBuilder::build_data(
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
        8080, 80, 1000, 500, 65535,
        (part1, part2),
        MacAddress::new([0xAA; 6]),
        MacAddress::new([0xBB; 6]),
        false,
        None, // no timestamp
        &mut free, &mut tx,
    );

    assert_eq!(tx.num_frames(), 1);
    let frame = tx.pop().unwrap();
    let payload_start = 14 + 20 + 20; // ETH + IPv4 + TCP
    assert_eq!(&frame[payload_start..frame.len()], b"Hello, TCP!");
}
```

**Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat: zero-copy send path with two-slice build_data and peek_slices"
```

---

## Task 14: Socket Layer Updates

**Files:**
- Modify: `src/net/socket/tcp.rs`

**Context:** Add `set_timestamps()` and `set_sack()` methods to `TcpStream` for runtime configuration, matching the existing `set_nodelay()` / `set_keepalive()` pattern.

**Step 1: Add socket API methods**

After the `linger()` method in `TcpStream`:

```rust
/// Enable or disable TCP timestamps (RFC 7323).
pub fn set_timestamps(&self, enabled: bool) {
    let handler = unsafe { &mut *self.handler.get() };
    if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
        tcb.ts_enabled = enabled;
    }
}

/// Returns whether TCP timestamps are enabled.
pub fn timestamps(&self) -> bool {
    let handler = unsafe { &*self.handler.get() };
    handler
        .get_connection(&self.conn_id)
        .map(|tcb| tcb.ts_enabled)
        .unwrap_or(false)
}

/// Enable or disable SACK.
pub fn set_sack(&self, enabled: bool) {
    let handler = unsafe { &mut *self.handler.get() };
    if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
        tcb.sack_enabled = enabled;
    }
}

/// Returns whether SACK is enabled.
pub fn sack(&self) -> bool {
    let handler = unsafe { &*self.handler.get() };
    handler
        .get_connection(&self.conn_id)
        .map(|tcb| tcb.sack_enabled)
        .unwrap_or(false)
}
```

**Step 2: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add src/net/socket/tcp.rs
git commit -m "feat: add timestamps and SACK socket API methods"
```

---

## Task 15: Integration — Verify All Features Work Together

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (test section)

**Step 1: Write integration test combining all features**

```rust
#[test]
fn full_lifecycle_with_timestamps_sack_wscale() {
    // End-to-end test:
    // 1. Listen with timestamps + SACK + wscale enabled.
    // 2. Active open with same config.
    // 3. Complete handshake (verify options negotiated).
    // 4. Send data, receive ACK with correct scaled window.
    // 5. Simulate OOO data, verify SACK blocks sent.
    // 6. Simulate zero-window, verify persist probe sent.
    // 7. Graceful close.
}
```

**Step 2: Run all tests**

Run: `cargo test`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "test: integration test for timestamps, SACK, wscale, and persist timer"
```
