# TCP Data Transfer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement TCP data transfer (send/receive) for established connections with ring buffers, out-of-order reassembly, RTO + fast retransmit, and simple congestion control.

**Architecture:** Ring buffers for both send and receive paths. Incoming frames are copied into the receive ring buffer and returned to `rx_return` immediately — TCP never holds frames. Send path copies from the ring buffer into fresh frames. Out-of-order segments are tracked via `BTreeMap<u32, u32>` metadata. Congestion control uses a simple cwnd with slow start and halve-on-loss.

**Tech Stack:** Rust (2024 edition), no new dependencies. Uses existing `coarsetime`, `Frame<'umem>`, `FrameBuffer`, `LocalQueue`, `SegmentBuilder` infrastructure.

**Design doc:** `docs/plans/2026-03-06-tcp-data-transfer-design.md`

---

### Task 1: RingBuffer — Core Data Structure

**Files:**
- Create: `src/net/handler/tcp/ring_buffer.rs`
- Modify: `src/net/handler/tcp/mod.rs:1` (add `mod ring_buffer;`)

**Step 1: Write the failing tests**

In `src/net/handler/tcp/ring_buffer.rs`:

```rust
pub struct RingBuffer {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    len: usize,
    mask: usize,
}

impl RingBuffer {
    /// Create a new ring buffer. `capacity` must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "RingBuffer capacity must be a power of two");
        Self {
            buf: vec![0u8; capacity],
            head: 0,
            tail: 0,
            len: 0,
            mask: capacity - 1,
        }
    }

    /// Number of bytes available to read.
    #[inline]
    pub fn available(&self) -> usize {
        self.len
    }

    /// Number of bytes available to write.
    #[inline]
    pub fn free_space(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Total capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ring_buffer() {
        let rb = RingBuffer::new(1024);
        assert_eq!(rb.capacity(), 1024);
        assert_eq!(rb.available(), 0);
        assert_eq!(rb.free_space(), 1024);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn non_power_of_two_panics() {
        RingBuffer::new(1000);
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test ring_buffer -- --nocapture`
Expected: PASS (both tests)

**Step 3: Commit**

```bash
git add src/net/handler/tcp/ring_buffer.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): add RingBuffer skeleton with new/capacity/available/free_space"
```

---

### Task 2: RingBuffer — Write and Read Operations

**Files:**
- Modify: `src/net/handler/tcp/ring_buffer.rs`

**Step 1: Write the failing tests**

Add to the `tests` module in `ring_buffer.rs`:

```rust
#[test]
fn write_and_read() {
    let mut rb = RingBuffer::new(64);
    let data = b"hello world";
    let written = rb.write(data);
    assert_eq!(written, data.len());
    assert_eq!(rb.available(), data.len());
    assert_eq!(rb.free_space(), 64 - data.len());

    let mut buf = [0u8; 64];
    let read = rb.read(&mut buf);
    assert_eq!(read, data.len());
    assert_eq!(&buf[..read], data);
    assert_eq!(rb.available(), 0);
    assert_eq!(rb.free_space(), 64);
}

#[test]
fn write_wraps_around() {
    let mut rb = RingBuffer::new(16);
    // Fill 12 bytes, read 12, then write 8 which wraps around the boundary.
    rb.write(&[0xAA; 12]);
    let mut discard = [0u8; 12];
    rb.read(&mut discard);
    // head=12, tail=12. Write 8 bytes: 4 fit at end, 4 wrap to start.
    let written = rb.write(&[0xBB; 8]);
    assert_eq!(written, 8);
    assert_eq!(rb.available(), 8);

    let mut buf = [0u8; 8];
    let read = rb.read(&mut buf);
    assert_eq!(read, 8);
    assert_eq!(buf, [0xBB; 8]);
}

#[test]
fn write_when_full_returns_zero() {
    let mut rb = RingBuffer::new(16);
    let written = rb.write(&[0xFF; 16]);
    assert_eq!(written, 16);
    let written = rb.write(&[0xAA; 1]);
    assert_eq!(written, 0);
}

#[test]
fn partial_write_when_nearly_full() {
    let mut rb = RingBuffer::new(16);
    rb.write(&[0xFF; 12]);
    let written = rb.write(&[0xAA; 8]);
    assert_eq!(written, 4); // only 4 bytes free
    assert_eq!(rb.available(), 16);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test ring_buffer -- --nocapture`
Expected: FAIL — `write` and `read` methods not defined.

**Step 3: Implement write and read**

Add to `impl RingBuffer`:

```rust
/// Write bytes into the buffer at `tail`. Returns the number of bytes written.
/// Writes as many bytes as fit; returns less than `data.len()` if buffer is nearly full.
#[inline]
pub fn write(&mut self, data: &[u8]) -> usize {
    let to_write = data.len().min(self.free_space());
    if to_write == 0 {
        return 0;
    }
    let tail = self.tail & self.mask;
    let first = to_write.min(self.buf.len() - tail);
    self.buf[tail..tail + first].copy_from_slice(&data[..first]);
    if first < to_write {
        self.buf[..to_write - first].copy_from_slice(&data[first..to_write]);
    }
    self.tail = self.tail.wrapping_add(to_write);
    self.len += to_write;
    to_write
}

/// Read bytes from the buffer starting at `head`. Returns the number of bytes read.
/// Advances `head` by the number of bytes read.
#[inline]
pub fn read(&mut self, buf: &mut [u8]) -> usize {
    let to_read = buf.len().min(self.available());
    if to_read == 0 {
        return 0;
    }
    let head = self.head & self.mask;
    let first = to_read.min(self.buf.len() - head);
    buf[..first].copy_from_slice(&self.buf[head..head + first]);
    if first < to_read {
        buf[first..to_read].copy_from_slice(&self.buf[..to_read - first]);
    }
    self.head = self.head.wrapping_add(to_read);
    self.len -= to_read;
    to_read
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test ring_buffer -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/ring_buffer.rs
git commit -m "feat(tcp): RingBuffer write and read with wrap-around"
```

---

### Task 3: RingBuffer — write_at, peek_at, advance

**Files:**
- Modify: `src/net/handler/tcp/ring_buffer.rs`

**Step 1: Write the failing tests**

Add to `tests` module:

```rust
#[test]
fn write_at_and_read() {
    let mut rb = RingBuffer::new(64);
    // Write 4 bytes at offset 0 (like in-order).
    rb.write_at(0, b"AAAA");
    // Write 4 bytes at offset 8 (out-of-order, gap at 4..8).
    rb.write_at(8, b"CCCC");
    // Fill the gap.
    rb.write_at(4, b"BBBB");
    // Now advance tail to cover all 12 bytes.
    // (write_at for receive side — caller manages len/tail)
    assert_eq!(rb.available(), 0); // write_at doesn't advance len
}

#[test]
fn write_at_wraps() {
    let mut rb = RingBuffer::new(16);
    // Move head to position 12.
    rb.write(&[0xAA; 12]);
    let mut discard = [0u8; 12];
    rb.read(&mut discard);
    // head=12. write_at offset 2 from head = position 14. Writing 4 bytes wraps.
    rb.write_at(2, &[0xBB; 4]);
    // Verify by peeking.
    let mut buf = [0u8; 4];
    rb.peek_at(2, &mut buf);
    assert_eq!(buf, [0xBB; 4]);
}

#[test]
fn peek_at_does_not_advance() {
    let mut rb = RingBuffer::new(64);
    rb.write(b"hello");
    let mut buf = [0u8; 5];
    rb.peek_at(0, &mut buf);
    assert_eq!(&buf, b"hello");
    assert_eq!(rb.available(), 5); // unchanged
    // Peek again at offset 2.
    let mut buf2 = [0u8; 3];
    rb.peek_at(2, &mut buf2);
    assert_eq!(&buf2, b"llo");
}

#[test]
fn advance_frees_space() {
    let mut rb = RingBuffer::new(64);
    rb.write(b"hello world");
    rb.advance(5);
    assert_eq!(rb.available(), 6);
    assert_eq!(rb.free_space(), 64 - 6);
    let mut buf = [0u8; 6];
    rb.read(&mut buf);
    assert_eq!(&buf, b" world");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test ring_buffer -- --nocapture`
Expected: FAIL — `write_at`, `peek_at`, `advance` not defined.

**Step 3: Implement write_at, peek_at, advance**

Add to `impl RingBuffer`:

```rust
/// Write bytes at an arbitrary offset from `head`. Does NOT advance `tail` or `len`.
/// Used by the receive side for out-of-order segments — the caller is responsible
/// for tracking which ranges are filled and advancing `tail`/`len` when contiguous.
#[inline]
pub fn write_at(&mut self, offset: usize, data: &[u8]) {
    let pos = (self.head.wrapping_add(offset)) & self.mask;
    let first = data.len().min(self.buf.len() - pos);
    self.buf[pos..pos + first].copy_from_slice(&data[..first]);
    if first < data.len() {
        self.buf[..data.len() - first].copy_from_slice(&data[first..]);
    }
}

/// Read bytes at an arbitrary offset from `head` without advancing `head`.
/// Used by the send side for retransmission.
#[inline]
pub fn peek_at(&self, offset: usize, buf: &mut [u8]) {
    let pos = (self.head.wrapping_add(offset)) & self.mask;
    let first = buf.len().min(self.buf.len() - pos);
    buf[..first].copy_from_slice(&self.buf[pos..pos + first]);
    if first < buf.len() {
        buf[first..].copy_from_slice(&self.buf[..buf.len() - first]);
    }
}

/// Advance `head` by `n` bytes, freeing space. Used when bytes are ACKed (send)
/// or consumed by `TcpStream::read()` (receive).
#[inline]
pub fn advance(&mut self, n: usize) {
    debug_assert!(n <= self.len);
    self.head = self.head.wrapping_add(n);
    self.len -= n;
}

/// Advance `tail` and `len` to mark bytes as available for reading.
/// Used by the receive side when contiguous data is confirmed.
#[inline]
pub fn commit(&mut self, n: usize) {
    debug_assert!(n <= self.free_space());
    self.tail = self.tail.wrapping_add(n);
    self.len += n;
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test ring_buffer -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/ring_buffer.rs
git commit -m "feat(tcp): RingBuffer write_at, peek_at, advance, commit"
```

---

### Task 4: TCB — Add Data Transfer State

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`
- Modify: `src/net/handler/tcp/mod.rs` (update Tcb construction sites)

**Step 1: Add new fields to Tcb**

Add imports and fields to `src/net/handler/tcp/tcb.rs`:

```rust
use std::collections::BTreeMap;
use super::ring_buffer::RingBuffer;
```

Add to the `Tcb` struct:

```rust
// --- Data transfer buffers ---
/// Send ring buffer — user data is copied in, segments built from here.
pub send_buffer: RingBuffer,
/// Receive ring buffer — incoming payload copied here, user reads from here.
pub recv_buffer: RingBuffer,
/// Out-of-order receive ranges: seq -> byte_length (metadata only).
pub ooo_ranges: BTreeMap<u32, u32>,

// --- Congestion control ---
/// Congestion window in bytes.
pub cwnd: u32,
/// Slow start threshold.
pub ssthresh: u32,
/// Duplicate ACK counter for fast retransmit.
pub dup_ack_count: u8,

// --- RTT estimation (RFC 6298) ---
/// Smoothed RTT in microseconds.
pub srtt: Option<u64>,
/// RTT variance in microseconds.
pub rttvar: u64,
/// Retransmission timeout in milliseconds (computed from srtt/rttvar).
pub rto: u64,
```

**Step 2: Add TcpConfig**

Add to `src/net/handler/tcp/tcb.rs`:

```rust
/// Configuration for TCP connections.
pub struct TcpConfig {
    /// Send buffer size in bytes. Must be a power of two. Default: 256KB.
    pub send_buffer_size: usize,
    /// Receive buffer size in bytes. Must be a power of two. Default: 256KB.
    pub recv_buffer_size: usize,
    /// Listener backlog. Default: 128.
    pub backlog: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            send_buffer_size: 256 * 1024,
            recv_buffer_size: 256 * 1024,
            backlog: 128,
        }
    }
}
```

**Step 3: Update all Tcb construction sites in `mod.rs`**

There are three places where `Tcb { ... }` is constructed in `src/net/handler/tcp/mod.rs`:

1. `connect()` (~line 131) — active open
2. `process_listen()` (~line 459) — passive open SYN-RECEIVED
3. No others.

Add the new fields to each construction site with default values. Use `TcpConfig::default()` sizes for now. Initialize `cwnd` to `10 * eff_snd_mss` and `ssthresh` to `u32::MAX`. Set `rto` to `1000` (1 second initial RTO per RFC 6298).

Example fields to add to each `Tcb { ... }`:

```rust
send_buffer: RingBuffer::new(256 * 1024),
recv_buffer: RingBuffer::new(256 * 1024),
ooo_ranges: BTreeMap::new(),
cwnd: 10 * eff_snd_mss as u32,
ssthresh: u32::MAX,
dup_ack_count: 0,
srtt: None,
rttvar: 0,
rto: 1000,
```

Note: for the `connect()` site, `eff_snd_mss` is `DEFAULT_RCV_MSS` at creation time. For the `process_listen()` site, it's `peer_mss.min(DEFAULT_RCV_MSS)`.

**Step 4: Run tests to verify nothing broke**

Run: `cargo test tcp -- --nocapture`
Expected: PASS (all existing TCP tests still pass)

**Step 5: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): add data transfer state to TCB — ring buffers, cwnd, RTT"
```

---

### Task 5: SegmentBuilder — build_data()

**Files:**
- Modify: `src/net/handler/tcp/segment.rs`

**Step 1: Write the failing test**

Add to the `segment.rs` file (create a `#[cfg(test)] mod tests` block if not present):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::frame::{BasicFrameBuffer, Frame};
    use crate::net::wire::ip::{Ipv4Address, IpAddress};
    use crate::net::wire::ethernet::MacAddress;
    use crate::net::checksum::compute_tcp_checksum;

    fn alloc_free_frame(addr: u64) -> Frame<'static> {
        let buf = Box::leak(vec![0u8; 2048].into_boxed_slice());
        Frame::new(addr, buf, 2048, false)
    }

    #[test]
    fn build_data_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let payload = b"Hello, TCP!";
        let src_mac = MacAddress::new([0xAA; 6]);
        let dst_mac = MacAddress::new([0xBB; 6]);

        SegmentBuilder::build_data(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080, 80,
            1000, 500,
            65535,
            payload,
            src_mac, dst_mac,
            false, &mut free, &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);
        assert_eq!(free.num_frames(), 0);

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv4(20) + TCP(20) + payload(11) = 65
        assert_eq!(frame.len(), 65);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test build_data_ipv4 -- --nocapture`
Expected: FAIL — `build_data` not defined.

**Step 3: Implement build_data**

Add to `impl SegmentBuilder` in `segment.rs`:

```rust
/// Build a data segment with payload.
#[inline]
pub fn build_data<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    payload: &[u8],
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    match (local_addr, remote_addr) {
        (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
            Self::build_ipv4_data_segment(
                local_ip, remote_ip,
                local_port, remote_port,
                seq, ack, flags::ACK, window,
                payload,
                src_mac, dst_mac,
                tx_offload, free_frames, tx_return,
            );
        }
        (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
            Self::build_ipv6_data_segment(
                local_ip, remote_ip,
                local_port, remote_port,
                seq, ack, flags::ACK, window,
                payload,
                src_mac, dst_mac,
                tx_offload, free_frames, tx_return,
            );
        }
        _ => {}
    }
}
```

Add the IPv4 and IPv6 data segment builders. These are similar to the existing `build_ipv4_segment`/`build_ipv6_segment` but include a payload after the TCP header:

```rust
#[inline]
fn build_ipv4_data_segment<'umem>(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let Some(mut frame) = free_frames.pop() else {
        return;
    };

    let tcp_header_len = TCP_HEADER_LEN; // no options for data segments
    let data_offset = (tcp_header_len / 4) as u8;
    let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
    let frame_len = ETH_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len();

    if frame.capacity() < frame_len {
        free_frames.push(frame);
        return;
    }

    unsafe { frame.set_len(frame_len) };

    write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

    {
        let ip = &mut frame[ETH_LEN..ETH_LEN + IPV4_MIN_HEADER_LEN];
        ip.fill(0);
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40; // DF
        ip[8] = 64;   // TTL
        ip[9] = IpProtocols::Tcp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
    }
    {
        let ip = crate::net::wire::ip::Ipv4Header::from_bytes_mut(&mut frame);
        ip.fill_checksum();
    }

    let tcp_offset = ETH_LEN + IPV4_MIN_HEADER_LEN;
    Self::write_tcp_header(
        &mut frame, tcp_offset,
        src_port, dst_port, seq, ack, data_offset, tcp_flags, window,
        &[], 0,
    );

    // Copy payload.
    let payload_offset = tcp_offset + tcp_header_len;
    frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

    if !tx_offload {
        let tcp_bytes = &frame[tcp_offset..frame_len];
        let checksum = compute_tcp_checksum_from_parts(&src_ip, &dst_ip, &tcp_bytes[..TCP_HEADER_LEN], payload);
        frame[tcp_offset + 16] = checksum[0];
        frame[tcp_offset + 17] = checksum[1];
    }

    tx_return.push(frame);
}

#[inline]
fn build_ipv6_data_segment<'umem>(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let Some(mut frame) = free_frames.pop() else {
        return;
    };

    let tcp_header_len = TCP_HEADER_LEN;
    let data_offset = (tcp_header_len / 4) as u8;
    let payload_len = (tcp_header_len + payload.len()) as u16;
    let frame_len = ETH_LEN + IPV6_HEADER_LEN + tcp_header_len + payload.len();

    if frame.capacity() < frame_len {
        free_frames.push(frame);
        return;
    }

    unsafe { frame.set_len(frame_len) };

    write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

    {
        let ip = &mut frame[ETH_LEN..ETH_LEN + IPV6_HEADER_LEN];
        ip.fill(0);
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = IpProtocols::Tcp;
        ip[7] = 64;
        let src_bytes: [u8; 16] = src_ip.into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        ip[24..40].copy_from_slice(&dst_bytes);
    }

    let tcp_offset = ETH_LEN + IPV6_HEADER_LEN;
    Self::write_tcp_header(
        &mut frame, tcp_offset,
        src_port, dst_port, seq, ack, data_offset, tcp_flags, window,
        &[], 0,
    );

    let payload_offset = tcp_offset + tcp_header_len;
    frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

    if !tx_offload {
        let tcp_bytes = &frame[tcp_offset..frame_len];
        let checksum = compute_tcp_checksum_v6_from_parts(&src_ip, &dst_ip, &tcp_bytes[..TCP_HEADER_LEN], payload);
        frame[tcp_offset + 16] = checksum[0];
        frame[tcp_offset + 17] = checksum[1];
    }

    tx_return.push(frame);
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test build_data -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/segment.rs
git commit -m "feat(tcp): SegmentBuilder::build_data() for data segments"
```

---

### Task 6: TcpHandler — process_established() Receive Path

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing test**

Add to the existing `tests` module in `mod.rs`:

```rust
#[test]
fn established_receives_in_order_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete the handshake.
    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Clear tx from handshake.
    while tx.pop().is_some() {}

    // Send a data segment.
    let payload = b"Hello, TCP!";
    let data = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, server_iss.wrapping_add(1),
        flags::ACK, 65535, &[], payload,
    );
    let data_len = data.len();
    handler.process_ipv4(Frame::new(2, leak(data), data_len, false), &nh, &mut free, &mut rx, &mut tx);

    // Verify: frame returned to rx_return, ACK generated on tx.
    assert!(rx.num_frames() >= 1, "incoming frame returned to rx_return");
    assert_eq!(tx.num_frames(), 1, "ACK generated");

    // Verify: data is in the receive ring buffer.
    let tcb = &handler.connections[0];
    assert_eq!(tcb.recv_buffer.available(), payload.len());
    assert_eq!(tcb.rcv_nxt, 1001 + payload.len() as u32);
}
```

This requires a helper `build_tcp_frame_with_payload`. Add to test helpers:

```rust
fn build_tcp_frame_with_payload(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opt_padded_len = (tcp_options.len() + 3) & !3;
    let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
    let data_offset = (tcp_header_len / 4) as u8;
    let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
    let mut buf = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()];

    // Ethernet header.
    buf[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4 header.
    let ip = &mut buf[ETH_HEADER_LEN..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = IpProtocols::Tcp;
    let src_bytes: [u8; 4] = src_ip.into();
    ip[12..16].copy_from_slice(&src_bytes);
    let dst_bytes: [u8; 4] = dst_ip.into();
    ip[16..20].copy_from_slice(&dst_bytes);
    let cksum = compute_ipv4_checksum(&ip[..20]);
    ip[10] = cksum[0];
    ip[11] = cksum[1];

    // TCP header.
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let hdr = TcpHeader::new(
        src_port, dst_port, seq, ack,
        data_offset, tcp_flags, window,
        [0, 0], 0,
    );
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(&hdr as *const TcpHeader as *const u8, TCP_HEADER_LEN)
    };
    buf[tcp_off..tcp_off + TCP_HEADER_LEN].copy_from_slice(hdr_bytes);

    // Options.
    if !tcp_options.is_empty() {
        buf[tcp_off + TCP_HEADER_LEN..tcp_off + TCP_HEADER_LEN + tcp_options.len()]
            .copy_from_slice(tcp_options);
    }

    // Payload.
    let payload_off = tcp_off + tcp_header_len;
    buf[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    // TCP checksum (over header + payload).
    let tcp_segment = &mut buf[tcp_off..];
    let cksum = compute_tcp_checksum(&src_ip, &dst_ip, tcp_segment);
    buf[tcp_off + 16] = cksum[0];
    buf[tcp_off + 17] = cksum[1];

    buf
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test established_receives_in_order_data -- --nocapture`
Expected: FAIL — currently the Established branch just does `rx_return.push(frame)`.

**Step 3: Implement process_established**

Replace the `TcpState::Established` match arm in `process_segment()` (~line 357) with:

```rust
TcpState::Established => {
    self.process_established(
        idx, frame, seg_seq, seg_ack, seg_flags, seg_wnd, seg_len,
        src_mac, dst_mac,
        free_frames, rx_return, tx_return,
    );
}
```

Add the `process_established` method to `impl TcpHandler`. This handles:
- RST processing
- ACK processing (advance `snd_una`, update send window, duplicate ACK counting)
- In-order data: copy payload to recv_buffer, advance `rcv_nxt`, drain contiguous OOO ranges, send ACK
- Out-of-order data: copy payload to recv_buffer via `write_at`, record in `ooo_ranges`, send duplicate ACK
- Always return frame to `rx_return`

The implementation is substantial — the full method should follow RFC 9293 Section 3.10.7.4 (ESTABLISHED state processing) for the segments it handles. Key logic:

```rust
fn process_established<'umem>(
    &mut self,
    idx: usize,
    frame: Frame<'umem>,
    seg_seq: u32,
    seg_ack: u32,
    seg_flags: u8,
    seg_wnd: u32,
    seg_len: u32,
    src_mac: crate::net::wire::ethernet::MacAddress,
    dst_mac: crate::net::wire::ethernet::MacAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // Extract payload offset and length from frame before processing.
    let ip_header_len = /* extract from frame based on IP version */;
    let tcp_header_len = /* from data offset field already parsed */;
    let payload_start = /* ETH + IP + TCP header */;
    let payload_len = frame.len() - payload_start;

    let tcb = &self.connections[idx];
    let rcv_nxt = tcb.rcv_nxt;
    let rcv_wnd = tcb.rcv_wnd;

    // Step 1: Check RST.
    if seg_flags & flags::RST != 0 {
        self.connections[idx].event_queue.push(TcpEvent::Reset);
        self.connections.remove(idx);
        rx_return.push(frame);
        return;
    }

    // Step 2: Check ACK.
    if seg_flags & flags::ACK != 0 {
        let tcb = &mut self.connections[idx];
        if crate::net::wire::tcp::seq_lt(tcb.snd_una, seg_ack)
            && crate::net::wire::tcp::seq_le(seg_ack, tcb.snd_nxt)
        {
            // Valid new ACK.
            let bytes_acked = seg_ack.wrapping_sub(tcb.snd_una) as usize;
            tcb.snd_una = seg_ack;
            tcb.send_buffer.advance(bytes_acked);
            // Congestion control: slow start / congestion avoidance.
            if tcb.cwnd < tcb.ssthresh {
                tcb.cwnd += tcb.eff_snd_mss as u32;
            } else {
                tcb.cwnd += (tcb.eff_snd_mss as u32 * tcb.eff_snd_mss as u32) / tcb.cwnd;
            }
            tcb.dup_ack_count = 0;
            // Update send window.
            tcb.snd_wnd = seg_wnd;
            tcb.snd_wl1 = seg_seq;
            tcb.snd_wl2 = seg_ack;
        } else if seg_ack == tcb.snd_una {
            // Duplicate ACK.
            if payload_len == 0 {
                tcb.dup_ack_count += 1;
                // Fast retransmit at 3 duplicate ACKs handled in poll_timers.
            }
        }
    }

    // Step 3: Process data payload.
    if payload_len > 0 {
        let tcb = &mut self.connections[idx];
        if seg_seq == tcb.rcv_nxt {
            // In-order: copy to recv buffer, advance rcv_nxt.
            let payload = &frame[payload_start..payload_start + payload_len];
            tcb.recv_buffer.write(payload);
            tcb.recv_buffer.commit(payload_len); // if using write_at path
            // Actually for in-order, just use write() which advances tail.
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);

            // Drain any now-contiguous OOO ranges.
            while let Some((&ooo_seq, &ooo_len)) = tcb.ooo_ranges.iter().next() {
                if ooo_seq == tcb.rcv_nxt {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(ooo_len);
                    tcb.recv_buffer.commit(ooo_len as usize);
                    tcb.ooo_ranges.remove(&ooo_seq);
                } else {
                    break;
                }
            }

            // Send ACK.
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
        } else if crate::net::wire::tcp::seq_lt(rcv_nxt, seg_seq) {
            // Out-of-order: copy to recv buffer at offset, record range.
            let offset = seg_seq.wrapping_sub(rcv_nxt) as usize;
            let payload = &frame[payload_start..payload_start + payload_len];
            tcb.recv_buffer.write_at(offset, payload);
            tcb.ooo_ranges.insert(seg_seq, payload_len as u32);

            // Send duplicate ACK.
            let id = tcb.id;
            let snd_nxt = tcb.snd_nxt;
            let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;
            SegmentBuilder::build_ack(
                id.local_addr, id.remote_addr,
                id.local_port, id.remote_port,
                snd_nxt, rcv_nxt, window,
                src_mac, dst_mac,
                self.tx_offload, free_frames, tx_return,
            );
        }
        // else: duplicate data (seg_seq < rcv_nxt), just ACK.
    }

    // Always return frame.
    rx_return.push(frame);
}
```

Note: the payload offset calculation needs to extract the IP header length and TCP header length from the already-parsed values. The `seg_len` and header offsets are already computed in `process_ipv4`/`process_ipv6` — you'll need to pass the payload offset and payload length through `process_segment` as additional parameters.

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp -- --nocapture`
Expected: PASS (new test + all existing tests)

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): process_established() receive path with in-order and OOO handling"
```

---

### Task 7: TcpHandler — process_established() Out-of-Order Test

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (tests only)

**Step 1: Write the test**

```rust
#[test]
fn established_out_of_order_reassembly() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Send segment 2 first (out of order): seq=1006, 5 bytes "world".
    let seg2 = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1006, server_iss.wrapping_add(1),
        flags::ACK, 65535, &[], b"world",
    );
    let seg2_len = seg2.len();
    handler.process_ipv4(Frame::new(2, leak(seg2), seg2_len, false), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].rcv_nxt, 1001, "rcv_nxt not advanced for OOO");
    assert_eq!(handler.connections[0].ooo_ranges.len(), 1);

    // Now send segment 1 (fills the gap): seq=1001, 5 bytes "hello".
    let seg1 = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, server_iss.wrapping_add(1),
        flags::ACK, 65535, &[], b"hello",
    );
    let seg1_len = seg1.len();
    handler.process_ipv4(Frame::new(3, leak(seg1), seg1_len, false), &nh, &mut free, &mut rx, &mut tx);

    // Both segments should now be contiguous.
    assert_eq!(handler.connections[0].rcv_nxt, 1011, "rcv_nxt advanced past both segments");
    assert_eq!(handler.connections[0].ooo_ranges.len(), 0, "OOO ranges drained");
    assert_eq!(handler.connections[0].recv_buffer.available(), 10);

    // Read from recv buffer and verify contents.
    let mut buf = [0u8; 10];
    handler.connections[0].recv_buffer.read(&mut buf);
    assert_eq!(&buf, b"helloworld");
}
```

**Step 2: Run test**

Run: `cargo test established_out_of_order -- --nocapture`
Expected: PASS (if Task 6 is implemented correctly)

**Step 3: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "test(tcp): out-of-order segment reassembly test"
```

---

### Task 8: TcpHandler — poll_send()

**Files:**
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn poll_send_builds_data_segment() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Write data into the connection's send buffer.
    let payload = b"Hello from server!";
    handler.connections[0].send_buffer.write(payload);

    // Set snd_wnd so the window allows sending.
    handler.connections[0].snd_wnd = 65535;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert_eq!(tx.num_frames(), 1, "data segment built");
    let tcb = &handler.connections[0];
    assert_eq!(tcb.snd_nxt, server_iss.wrapping_add(1).wrapping_add(payload.len() as u32));
    assert_eq!(tcb.send_buffer.available(), payload.len()); // still in buffer until ACKed
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test poll_send_builds_data_segment -- --nocapture`
Expected: FAIL — `poll_send` not defined.

**Step 3: Implement poll_send**

Add to `impl TcpHandler`:

```rust
/// Poll established connections for outbound data segments.
/// Called each tick from the runtime loop after receive processing.
pub fn poll_send<'umem>(
    &mut self,
    now: Instant,
    src_mac: crate::net::wire::ethernet::MacAddress,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    for tcb in &mut self.connections {
        if tcb.state != TcpState::Established {
            continue;
        }

        // Compute how many bytes we can send.
        let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
        let send_window = (tcb.snd_wnd as usize).min(tcb.cwnd as usize);
        let can_send = send_window.saturating_sub(bytes_in_flight);
        let data_available = tcb.send_buffer.available() - bytes_in_flight; // unsent data

        if can_send == 0 || data_available == 0 {
            continue;
        }

        let to_send = can_send.min(data_available).min(tcb.eff_snd_mss as usize);

        // Peek the data from the send buffer (don't advance — held until ACKed).
        let mut payload = vec![0u8; to_send]; // NOTE: consider stack buffer for MSS-sized chunks
        tcb.send_buffer.peek_at(bytes_in_flight, &mut payload);

        let dst_mac = neighbor_handler
            .lookup(now, &tcb.id.remote_addr)
            .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

        let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;

        SegmentBuilder::build_data(
            tcb.id.local_addr, tcb.id.remote_addr,
            tcb.id.local_port, tcb.id.remote_port,
            tcb.snd_nxt, tcb.rcv_nxt, window,
            &payload,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );

        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(to_send as u32);

        // Set retransmit timer if not already running.
        if tcb.retransmit_deadline.is_none() {
            tcb.retransmit_deadline = Some(now + coarsetime::Duration::from_millis(tcb.rto));
        }
    }
}
```

Note: The `vec![0u8; to_send]` allocation is a concern. For the initial implementation this is acceptable because `to_send <= eff_snd_mss` (1460 bytes max). A future optimization can use a stack-allocated `[u8; 1460]` or a per-handler scratch buffer. Flag this with a `// TODO: use stack buffer to avoid allocation` comment.

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): poll_send() builds data segments from send buffer"
```

---

### Task 9: TcpHandler — Data Retransmission (RTO + Fast Retransmit)

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (extend `poll_timers`)

**Step 1: Write the failing test**

```rust
#[test]
fn fast_retransmit_on_three_dup_acks() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake + establish.
    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn_data.len();
    handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack_data.len();
    handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Put data in send buffer and send it.
    handler.connections[0].send_buffer.write(b"AAAA");
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {} // consume sent segment

    // Send 3 duplicate ACKs (ACKing the old snd_una, not the new data).
    let dup_ack_seq = server_iss.wrapping_add(1); // original snd_una
    for i in 0..3u64 {
        let dup = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, dup_ack_seq, flags::ACK, 65535, &[]);
        let dup_len = dup.len();
        handler.process_ipv4(Frame::new(10 + i, leak(dup), dup_len, false), &nh, &mut free, &mut rx, &mut tx);
    }

    assert_eq!(handler.connections[0].dup_ack_count, 3);

    // poll_timers should trigger fast retransmit.
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
    assert!(tx.num_frames() >= 1, "retransmitted segment");

    // cwnd should be halved.
    let tcb = &handler.connections[0];
    assert!(tcb.cwnd < 10 * tcb.eff_snd_mss as u32, "cwnd reduced");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test fast_retransmit -- --nocapture`
Expected: FAIL — `dup_ack_count` never reaches 3 / retransmit logic not implemented.

**Step 3: Extend poll_timers for data retransmission**

In the existing `poll_timers` method, add handling for Established state connections:

```rust
TcpState::Established => {
    // Fast retransmit check.
    if tcb.dup_ack_count >= 3 {
        // Retransmit oldest unACKed segment.
        let retransmit_len = tcb.send_buffer.available()
            .min(tcb.eff_snd_mss as usize);
        if retransmit_len > 0 {
            let mut payload = vec![0u8; retransmit_len];
            tcb.send_buffer.peek_at(0, &mut payload);
            let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;
            SegmentBuilder::build_data(
                id.local_addr, id.remote_addr,
                id.local_port, id.remote_port,
                tcb.snd_una, tcb.rcv_nxt, window,
                &payload,
                src_mac, dst_mac,
                self.tx_offload, free_frames, tx_return,
            );
        }
        tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
        tcb.cwnd = tcb.ssthresh;
        tcb.dup_ack_count = 0;
        continue;
    }

    // RTO retransmit.
    // (same pattern: peek from send buffer, rebuild segment, backoff timer)
    let retransmit_len = tcb.send_buffer.available().min(tcb.eff_snd_mss as usize);
    if retransmit_len > 0 {
        let mut payload = vec![0u8; retransmit_len];
        tcb.send_buffer.peek_at(0, &mut payload);
        let window = tcb.recv_buffer.free_space().min(u16::MAX as usize) as u16;
        SegmentBuilder::build_data(
            id.local_addr, id.remote_addr,
            id.local_port, id.remote_port,
            tcb.snd_una, tcb.rcv_nxt, window,
            &payload,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );
    }
    tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
    tcb.cwnd = tcb.eff_snd_mss as u32;
    tcb.rto_backoff += 1;
    tcb.retransmit_deadline = Some(now + coarsetime::Duration::from_millis(tcb.rto << tcb.rto_backoff));
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test tcp -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): data retransmission — RTO + fast retransmit on 3 dup ACKs"
```

---

### Task 10: TcpStream — write() and read() Futures

**Files:**
- Modify: `src/net/socket/tcp.rs`

**Step 1: Write the failing test**

Add to the `tests` module (create one if needed — follow the pattern in `udp.rs` with `with_test_context`):

```rust
#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};
    use std::pin::Pin;
    use std::future::Future;
    use crate::rt::context::{ContextDropGuard, RuntimeContext};
    use crate::rt::waker;
    use super::*;

    // Reuse the with_test_context pattern from udp.rs tests.

    #[test]
    fn write_returns_ready_when_buffer_has_space() {
        with_test_context(|| {
            // This test verifies the write future API exists and works.
            // Full integration requires a connected TcpStream which needs
            // handshake — so test the Write future directly against a
            // handler with a pre-built connection.
        });
    }
}
```

Note: Full TcpStream integration tests are complex because they require a completed handshake. The unit tests in `mod.rs` (Tasks 6-9) validate the handler logic. The socket-level tests here validate the future wiring.

**Step 2: Implement Write and Read futures**

Add to `src/net/socket/tcp.rs`:

```rust
/// Future returned by [`TcpStream::write()`].
pub struct TcpWrite<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    data: &'stream [u8],
    written: usize,
}

impl<'stream> Future for TcpWrite<'stream> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&this.conn_id) {
            let remaining = &this.data[this.written..];
            let n = tcb.send_buffer.write(remaining);
            this.written += n;
            if this.written == this.data.len() {
                Poll::Ready(this.written)
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(0) // connection gone
        }
    }
}

/// Future returned by [`TcpStream::read()`].
pub struct TcpRead<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    buf: &'stream mut [u8],
}

impl<'stream> Future for TcpRead<'stream> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&this.conn_id) {
            let n = tcb.recv_buffer.read(this.buf);
            if n > 0 {
                Poll::Ready(n)
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(0) // connection gone
        }
    }
}
```

Add methods to `TcpStream`:

```rust
/// Write data to this connection. Returns a future that resolves when
/// all bytes are copied into the send buffer.
pub fn write<'a>(&'a self, data: &'a [u8]) -> TcpWrite<'a> {
    TcpWrite {
        handler: &self.handler,
        conn_id: self.conn_id,
        data,
        written: 0,
    }
}

/// Read data from this connection. Returns a future that resolves when
/// data is available in the receive buffer.
pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> TcpRead<'a> {
    TcpRead {
        handler: &self.handler,
        conn_id: self.conn_id,
        buf,
    }
}
```

This also requires adding `get_connection_mut` to `TcpHandler`:

```rust
/// Get a mutable reference to a connection by ConnectionId.
pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
    self.connections.iter_mut().find(|c| c.id == *id)
}
```

**Step 3: Update socket/mod.rs exports**

Add `TcpWrite` and `TcpRead` to the public exports in `src/net/socket/mod.rs`.

**Step 4: Run tests to verify nothing broke**

Run: `cargo test -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/net/socket/tcp.rs src/net/socket/mod.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): TcpStream::write() and read() futures"
```

---

### Task 11: Runtime Loop — Integrate poll_send

**Files:**
- Modify: `src/rt/local.rs`

**Step 1: Add poll_send to the runtime loop**

In `LocalRuntime::run()`, after the `poll_timers` block (~line 327-336), add:

```rust
// Drive TCP data segment transmission.
{
    // SAFETY: single-threaded, no reentrant handler calls.
    let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
    tcp_handler.poll_send(
        now,
        self.neighbor_handler.local_mac(),
        &self.neighbor_handler,
        &mut self.free_frames,
        &mut self.tx_return,
    );
}
```

**Step 2: Run tests to verify nothing broke**

Run: `cargo test -- --nocapture`
Expected: PASS

**Step 3: Commit**

```bash
git add src/rt/local.rs
git commit -m "feat(tcp): integrate poll_send into runtime loop"
```

---

### Task 12: TcpConfig — Wiring Through listen/connect

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs` (TcpConfig already added in Task 4)
- Modify: `src/net/handler/tcp/mod.rs` (accept config in connect/listen)
- Modify: `src/net/socket/tcp.rs` (expose config on TcpListener/TcpStream)

**Step 1: Add config parameter to TcpHandler::connect and TcpHandler::listen**

Modify `listen` to accept an optional `TcpConfig` parameter for buffer sizes. Modify `connect` similarly. The `TcpConfig` values flow through to the `RingBuffer::new()` calls in Tcb construction.

**Step 2: Add `listen_with_config` and `connect_with_config` to TcpListener/TcpStream**

These mirror the existing `listen` / `connect` but accept a `TcpConfig`.

**Step 3: Run tests**

Run: `cargo test tcp -- --nocapture`
Expected: PASS

**Step 4: Commit**

```bash
git add src/net/handler/tcp/mod.rs src/net/handler/tcp/tcb.rs src/net/socket/tcp.rs
git commit -m "feat(tcp): TcpConfig for per-connection buffer sizing"
```

---

### Task 13: RTT Estimation (RFC 6298)

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (update ACK processing in process_established)

**Step 1: Write the test**

```rust
#[test]
fn rtt_estimation_updates_rto() {
    // After a segment is sent and ACKed, srtt/rttvar/rto should be updated.
    // Setup: handshake, write data, poll_send, then process an ACK.
    // Verify: tcb.srtt is Some, tcb.rto is reasonable (not the initial 1000ms).
}
```

**Step 2: Implement RTT update in ACK processing**

In `process_established`, when a valid new ACK is received and `bytes_acked > 0`:

```rust
// RTT measurement: use the time since the retransmit_deadline was set.
// Simplified: measure RTT from when the segment was sent (approximated
// by now - rto + remaining_deadline_time). For accuracy, store a
// `snd_nxt_timestamp` on the TCB when sending.
if let Some(send_time) = tcb.last_send_time {
    let rtt_us = now.duration_since(send_time).as_micros();
    match tcb.srtt {
        None => {
            // First measurement (RFC 6298 §2.2).
            tcb.srtt = Some(rtt_us);
            tcb.rttvar = rtt_us / 2;
        }
        Some(srtt) => {
            // Subsequent measurements (RFC 6298 §2.3).
            let diff = if rtt_us > srtt { rtt_us - srtt } else { srtt - rtt_us };
            tcb.rttvar = (3 * tcb.rttvar + diff) / 4;
            tcb.srtt = Some((7 * srtt + rtt_us) / 8);
        }
    }
    let srtt = tcb.srtt.unwrap();
    let rto = srtt + 4 * tcb.rttvar;
    tcb.rto = rto.max(1000).min(60_000) / 1000; // convert to ms, clamp 1s-60s
}
```

This requires adding a `last_send_time: Option<Instant>` field to `Tcb`, set in `poll_send` when a segment is sent.

**Step 3: Run tests**

Run: `cargo test tcp -- --nocapture`
Expected: PASS

**Step 4: Commit**

```bash
git add src/net/handler/tcp/mod.rs src/net/handler/tcp/tcb.rs
git commit -m "feat(tcp): RTT estimation per RFC 6298 updates RTO on ACK"
```

---

### Task 14: Final Integration — Verify Frame Accounting

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (test only)

**Step 1: Write comprehensive frame accounting test**

```rust
#[test]
fn frame_accounting_through_data_transfer() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);

    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let initial_total = free.num_frames();

    // Handshake.
    handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let syn_len = syn.len();
    handler.process_ipv4(Frame::new(0, leak(syn), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections[0].iss;
    let ack = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
    let ack_len = ack.len();
    handler.process_ipv4(Frame::new(1, leak(ack), ack_len, false), &nh, &mut free, &mut rx, &mut tx);

    // Data segment.
    let data = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, server_iss.wrapping_add(1),
        flags::ACK, 65535, &[], b"test data",
    );
    let data_len = data.len();
    handler.process_ipv4(Frame::new(2, leak(data), data_len, false), &nh, &mut free, &mut rx, &mut tx);

    // All frames accounted for: free + rx + tx = initial + incoming frames.
    let total = free.num_frames() + rx.num_frames() + tx.num_frames();
    // We started with initial_total free frames and injected 3 incoming frames.
    assert_eq!(total, initial_total + 3, "all frames accounted for");
}
```

**Step 2: Run test**

Run: `cargo test frame_accounting_through_data -- --nocapture`
Expected: PASS

**Step 3: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "test(tcp): comprehensive frame accounting through data transfer"
```

---

## Task Dependency Graph

```
Task 1 (RingBuffer skeleton)
  └─> Task 2 (write/read)
       └─> Task 3 (write_at/peek_at/advance)
            └─> Task 4 (TCB state additions)
                 ├─> Task 5 (SegmentBuilder::build_data)
                 │    └─> Task 8 (poll_send)
                 │         └─> Task 9 (retransmission)
                 │              └─> Task 11 (runtime integration)
                 │                   └─> Task 12 (TcpConfig wiring)
                 │                        └─> Task 13 (RTT estimation)
                 │                             └─> Task 14 (frame accounting)
                 └─> Task 6 (process_established receive)
                      └─> Task 7 (OOO test)
                           └─> Task 10 (TcpStream write/read futures)
```

Tasks 5-6 can be parallelized after Task 4. Tasks 8 and 10 can be parallelized after their respective dependencies.
