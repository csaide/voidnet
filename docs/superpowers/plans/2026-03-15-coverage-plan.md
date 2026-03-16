# Unit Test Coverage Improvement Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise VoidNet line coverage from 88.5% to 95-97% by adding ~170-210 unit tests across four phases.

**Architecture:** Tests are added to existing inline `#[cfg(test)] mod tests` blocks (or new ones where none exist). No shared test framework is created — each module is self-contained following existing patterns. Phase 3 introduces a minimal mock TcpStream for HTTP tests.

**Tech Stack:** Rust, `cargo test`, `cargo llvm-cov`, `futures::executor::block_on` (for async tests)

**Spec:** `docs/superpowers/specs/2026-03-15-coverage-plan-design.md`

---

## Chunk 1: Phase 1 — Pure Unit Tests (Tasks 1-13)

### Task 1: fragment/transport.rs — TcpHeader trait tests

**Files:**
- Modify: `src/net/fragment/transport.rs:63-111` (test module)

- [ ] **Step 1: Write the TcpHeader tests**

Add after the `custom_transport_header` test (line 110):

```rust
#[test]
fn tcp_header_as_transport_protocol() {
    let hdr = TcpHeader::default();
    assert_eq!(hdr.protocol(), IpProtocols::Tcp);
}

#[test]
fn tcp_header_as_transport_len() {
    let hdr = TcpHeader::default();
    assert_eq!(hdr.header_len(), TCP_HEADER_LEN);
}

#[test]
fn tcp_header_as_transport_write() {
    let mut hdr = TcpHeader::default();
    hdr.src_port = [0x00, 0x50]; // port 80
    hdr.dst_port = [0x1F, 0x90]; // port 8080
    let mut buf = [0u8; TCP_HEADER_LEN];
    hdr.write_to(&mut buf);
    assert_eq!(buf[0..2], [0x00, 0x50]);
    assert_eq!(buf[2..4], [0x1F, 0x90]);
    assert_eq!(buf.len(), TCP_HEADER_LEN);
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::fragment::transport::tests -- --nocapture`
Expected: 7 tests pass (4 existing + 3 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/fragment/transport.rs
git commit -m "test(fragment/transport): add TcpHeader TransportHeader trait tests"
```

---

### Task 2: fragment/pkt.rs — Empty packet and drain_to tests

**Files:**
- Modify: `src/net/fragment/pkt.rs:174-321` (test module)

- [ ] **Step 1: Write the empty packet and drain_to tests**

Add after the `into_frames_exact_size` test (line 320):

```rust
#[test]
fn empty_num_frames() {
    let pkt = Packet::Empty;
    assert_eq!(pkt.num_frames(), 0);
}

#[test]
fn empty_len() {
    let pkt = Packet::Empty;
    assert_eq!(pkt.len(), 0);
}

#[test]
fn empty_is_empty() {
    let pkt = Packet::Empty;
    assert!(pkt.is_empty());
}

#[test]
fn empty_frames_iter() {
    let pkt = Packet::Empty;
    assert_eq!(pkt.frames().count(), 0);
    assert_eq!(pkt.frames().size_hint(), (0, Some(0)));
}

#[test]
fn empty_frames_mut_iter() {
    let mut pkt = Packet::Empty;
    assert_eq!(pkt.frames_mut().count(), 0);
    assert_eq!(pkt.frames_mut().size_hint(), (0, Some(0)));
}

#[test]
fn empty_into_frames() {
    let pkt = Packet::Empty;
    let iter = pkt.into_frames();
    assert_eq!(iter.size_hint(), (0, Some(0)));
    assert_eq!(iter.count(), 0);
}

#[test]
fn from_empty_iterator() {
    let frames: Vec<Frame<'_>> = vec![];
    let pkt = Packet::from(frames.into_iter());
    assert_eq!(pkt.num_frames(), 0);
    assert!(pkt.is_empty());
}

#[test]
fn from_single_iterator() {
    let mut buf = [0u8; 64];
    buf[0] = 0xCC;
    let frames = vec![make_frame(&mut buf, 10)];
    let pkt = Packet::from(frames.into_iter());
    assert_eq!(pkt.num_frames(), 1);
    assert!(!pkt.is_empty());
}

#[test]
fn drain_to_single() {
    let mut buf = [0u8; 64];
    buf[0] = 0xDD;
    let pkt = Packet::Single(make_frame(&mut buf, 10));
    let mut target = BasicFrameBuffer::new(4);
    pkt.drain_to(&mut target);
    assert_eq!(target.num_frames(), 1);
}

#[test]
fn drain_to_multi() {
    let mut bufs = [[0u8; 64]; 3];
    let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
    let pkt = Packet::Multi(frames);
    let mut target = BasicFrameBuffer::new(4);
    pkt.drain_to(&mut target);
    assert_eq!(target.num_frames(), 3);
}

#[test]
fn drain_to_empty() {
    let pkt: Packet<'_> = Packet::Empty;
    let mut target = BasicFrameBuffer::new(4);
    pkt.drain_to(&mut target);
    assert_eq!(target.num_frames(), 0);
}
```

Also add this import at the top of the test module (after `use super::*;`):
```rust
use crate::xdp::frame::BasicFrameBuffer;
use crate::xdp::frame::FrameBuffer;
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::fragment::pkt::tests -- --nocapture`
Expected: 22 tests pass (10 existing + 12 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/fragment/pkt.rs
git commit -m "test(fragment/pkt): add empty packet, From iterator, and drain_to tests"
```

---

### Task 3: handler/tcp/tcb.rs — update_send_window return value test

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs:366+` (test module)

- [ ] **Step 1: Write the update_send_window tests**

Add after the `update_advertised_edge_sets_right_edge` test:

```rust
#[test]
fn update_send_window_zero_to_nonzero_returns_true() {
    let mut tcb = make_tcb(false, 0, 0, 1024);
    assert_eq!(tcb.snd_wnd, 0);
    assert!(tcb.update_send_window(1000));
}

#[test]
fn update_send_window_nonzero_to_nonzero_returns_false() {
    let mut tcb = make_tcb(false, 0, 0, 1024);
    tcb.snd_wnd = 500;
    assert!(!tcb.update_send_window(1000));
}

#[test]
fn update_send_window_nonzero_to_zero_returns_false() {
    let mut tcb = make_tcb(false, 0, 0, 1024);
    tcb.snd_wnd = 500;
    assert!(!tcb.update_send_window(0));
}

#[test]
fn update_send_window_zero_to_zero_returns_false() {
    let mut tcb = make_tcb(false, 0, 0, 1024);
    assert!(!tcb.update_send_window(0));
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::handler::tcp::tcb::tests -- --nocapture`
Expected: All tests pass (existing + 4 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/tcp/tcb.rs
git commit -m "test(tcp/tcb): add update_send_window transition return value tests"
```

---

### Task 4: pmtu.rs — with_mtu, Default, and mixed v4/v6 eviction tests

**Files:**
- Modify: `src/net/pmtu.rs:104-200` (test module)

- [ ] **Step 1: Write the new tests**

Add after the `evict_stale_keeps_fresh` test (line 198):

```rust
#[test]
fn with_mtu_sets_custom_default() {
    let now = Instant::now();
    let cache = PmtuCache::with_mtu(9000);
    let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
    assert_eq!(cache.get(now, &addr), 9000);
}

#[test]
fn default_trait_uses_standard_mtu() {
    let now = Instant::now();
    let cache = PmtuCache::default();
    let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
    assert_eq!(cache.get(now, &addr), 1500);
}

#[test]
fn evict_stale_mixed_v4_v6() {
    let now = Instant::now();
    let mut cache = PmtuCache::with_mtu_and_ttl(1500, Duration::from_secs(60));
    let v4 = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
    let v6 = IpAddress::V6(Ipv6Address::new([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]));

    cache.update(now, v4, 1400);
    let later = now.add(Duration::from_secs(30));
    cache.update(later, v6, 1280);

    // At now + 61s: v4 expired, v6 still fresh
    let evict_time = now.add(Duration::from_secs(61));
    cache.evict_stale(evict_time);
    assert_eq!(cache.table.len(), 1);
    assert_eq!(cache.get(evict_time, &v6), 1280);
    assert_eq!(cache.get(evict_time, &v4), 1500); // default (evicted)
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::pmtu::tests -- --nocapture`
Expected: All tests pass (8 existing + 3 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/pmtu.rs
git commit -m "test(pmtu): add with_mtu, Default, and mixed v4/v6 eviction tests"
```

---

### Task 5: xdp/frame/shared.rs — SharedFrameBuffer tests

**Files:**
- Modify: `src/xdp/frame/shared.rs` (add test module at end of file)

- [ ] **Step 1: Write the test module**

Add at the end of the file (after line 117):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::frame::Frame;

    fn make_frame(buf: &mut [u8], len: usize) -> Frame<'_> {
        Frame::new(0, buf, len, false)
    }

    #[test]
    fn from_basic_frame_buffer() {
        let basic = BasicFrameBuffer::new(8);
        let shared = SharedFrameBuffer::from(basic);
        assert_eq!(shared.num_frames(), 0);
        assert_eq!(shared.free_space(), 8);
    }

    #[test]
    fn push_and_pop() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut buf = [0u8; 64];
        buf[0] = 0xAA;
        shared.push(make_frame(&mut buf, 10));
        assert_eq!(shared.num_frames(), 1);
        let frame = shared.pop().unwrap();
        assert_eq!(frame[0], 0xAA);
        assert_eq!(shared.num_frames(), 0);
    }

    #[test]
    fn pop_empty_returns_none() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        assert!(shared.pop().is_none());
    }

    #[test]
    fn clone_shares_inner() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let cloned = shared.clone();
        let mut buf = [0u8; 64];
        shared.push(make_frame(&mut buf, 10));
        // Clone sees the same frame because they share the inner Rc
        assert_eq!(cloned.num_frames(), 1);
    }

    #[test]
    fn free_space_decreases_on_push() {
        let basic = BasicFrameBuffer::new(4);
        let mut shared = SharedFrameBuffer::from(basic);
        assert_eq!(shared.free_space(), 4);
        let mut buf = [0u8; 64];
        shared.push(make_frame(&mut buf, 10));
        assert_eq!(shared.free_space(), 3);
    }

    #[test]
    fn take_frames_drains_all() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut bufs = [[0u8; 64]; 3];
        for buf in bufs.iter_mut() {
            shared.push(make_frame(buf, 10));
        }
        assert_eq!(shared.num_frames(), 3);
        let taken: Vec<_> = shared.take_frames().collect();
        assert_eq!(taken.len(), 3);
        assert_eq!(shared.num_frames(), 0);
    }

    #[test]
    fn iter_frames_borrows() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut bufs = [[0u8; 64]; 2];
        bufs[0][0] = 0x01;
        bufs[1][0] = 0x02;
        for buf in bufs.iter_mut() {
            shared.push(make_frame(buf, 10));
        }
        let collected: Vec<_> = shared.iter_frames().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0][0], 0x01);
        assert_eq!(collected[1][0], 0x02);
    }

    #[test]
    fn iter_frames_mut_allows_mutation() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut buf = [0u8; 64];
        shared.push(make_frame(&mut buf, 10));
        for frame in shared.iter_frames_mut() {
            frame[0] = 0xFF;
        }
        let frame = shared.iter_frames().next().unwrap();
        assert_eq!(frame[0], 0xFF);
    }

    #[test]
    fn drain_range() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut bufs = [[0u8; 64]; 3];
        for (i, buf) in bufs.iter_mut().enumerate() {
            buf[0] = i as u8;
            shared.push(make_frame(buf, 10));
        }
        let drained: Vec<_> = shared.drain(0..2).collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(shared.num_frames(), 1);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test xdp::frame::shared::tests -- --nocapture`
Expected: 9 tests pass

- [ ] **Step 3: Commit**

```bash
git add src/xdp/frame/shared.rs
git commit -m "test(xdp/frame/shared): add SharedFrameBuffer unit tests"
```

---

### Task 6: rt/waker.rs — wake/drop vtable and noop waker tests

**Files:**
- Modify: `src/rt/waker.rs:99-137` (test module)

- [ ] **Step 1: Write the waker vtable tests**

Add after the `waker_clone_works` test (line 136):

```rust
#[test]
fn wake_consumes_waker() {
    let mw = MainWaker::new();
    mw.take_woken();
    let waker = mw.waker();
    waker.wake(); // consumes the waker (tests wake_main path)
    assert!(mw.take_woken());
}

#[test]
fn wake_by_ref_does_not_consume() {
    let mw = MainWaker::new();
    mw.take_woken();
    let waker = mw.waker();
    waker.wake_by_ref();
    assert!(mw.take_woken());
    // waker is still valid — drop it normally
    drop(waker);
}

#[test]
fn drop_waker_does_not_panic() {
    let mw = MainWaker::new();
    let waker = mw.waker();
    drop(waker);
    // Verify MainWaker still works after dropping the std::task::Waker
    mw.set_woken();
    assert!(mw.take_woken());
}

#[test]
fn multiple_wakers_from_same_main() {
    let mw = MainWaker::new();
    mw.take_woken();
    let w1 = mw.waker();
    let w2 = mw.waker();
    w1.wake_by_ref();
    assert!(mw.take_woken());
    w2.wake();
    assert!(mw.take_woken());
}

#[test]
fn noop_waker_does_not_panic() {
    let waker = task_queue_waker();
    waker.wake_by_ref();
    let cloned = waker.clone();
    cloned.wake();
    // Nothing to assert — just verify no panic/UB
}

#[test]
fn task_queue_waker_clone_roundtrip() {
    let waker = task_queue_waker();
    let cloned = waker.clone();
    drop(waker);
    cloned.wake_by_ref();
    drop(cloned);
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test rt::waker::tests -- --nocapture`
Expected: 10 tests pass (4 existing + 6 new)

- [ ] **Step 3: Commit**

```bash
git add src/rt/waker.rs
git commit -m "test(rt/waker): add wake/drop vtable and noop waker tests"
```

---

### Task 7: wire/arp.rs — ArpFrame and ArpPacket accessor tests

**Files:**
- Modify: `src/net/wire/arp.rs:126-142` (test module)

- [ ] **Step 1: Write the accessor tests**

Add after the `arp_packet_layout` test (line 141):

```rust
#[test]
fn arp_frame_as_bytes_length() {
    let mut buf = [0u8; ARP_FRAME_LEN];
    let frame = ArpFrame::from_bytes_mut(&mut buf);
    assert_eq!(frame.as_bytes().len(), ARP_FRAME_LEN);
}

#[test]
fn arp_packet_from_bytes_roundtrip() {
    let mut buf = [0u8; ARP_FRAME_LEN];
    // Set ARP operation to Reply in the packet portion
    let frame = ArpFrame::from_bytes_mut(&mut buf);
    frame.arp.oper = ArpOperations::Reply;
    frame.arp.htype = ArpHardwareTypes::Ethernet;

    let pkt = ArpPacket::from_bytes(&buf);
    assert_eq!(pkt.oper, ArpOperations::Reply);
    assert_eq!(pkt.htype, ArpHardwareTypes::Ethernet);
}

#[test]
fn arp_packet_from_bytes_mut_allows_mutation() {
    let mut buf = [0u8; ARP_FRAME_LEN];
    let pkt = ArpPacket::from_bytes_mut(&mut buf);
    pkt.oper = ArpOperations::Request;
    pkt.spa = Ipv4Address::new([10, 0, 0, 1]);
    assert_eq!(pkt.oper, ArpOperations::Request);
    assert_eq!(pkt.spa.octets, [10, 0, 0, 1]);
}

#[test]
#[should_panic]
fn arp_frame_from_bytes_mut_rejects_short_buffer() {
    let mut buf = [0u8; ARP_FRAME_LEN - 1];
    let _ = ArpFrame::from_bytes_mut(&mut buf);
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::wire::arp::tests -- --nocapture`
Expected: 6 tests pass (2 existing + 4 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/wire/arp.rs
git commit -m "test(wire/arp): add ArpFrame/ArpPacket accessor and validation tests"
```

---

### Task 8: wire/ndp.rs — NDP frame accessor and validation tests

**Files:**
- Modify: `src/net/wire/ndp.rs:119-152` (test module)

- [ ] **Step 1: Write the accessor tests**

Add after the `ndp_na_frame_layout` test (line 151):

```rust
#[test]
fn ndp_ns_frame_from_bytes_mut_roundtrip() {
    let mut buf = [0u8; NDP_NS_FRAME_LEN];
    let frame = NdpNsFrame::from_bytes_mut(&mut buf);
    frame.ns.icmp_type = 135;
    frame.ns.code = 0;
    let bytes = frame.as_bytes();
    assert_eq!(bytes.len(), NDP_NS_FRAME_LEN);
    // Verify the ICMPv6 type is at the right offset
    let ns_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
    assert_eq!(bytes[ns_offset], 135);
}

#[test]
fn ndp_na_frame_from_bytes_mut_roundtrip() {
    let mut buf = [0u8; NDP_NA_FRAME_LEN];
    let frame = NdpNaFrame::from_bytes_mut(&mut buf);
    frame.na.icmp_type = 136;
    frame.na.flags = [0x60, 0x00, 0x00, 0x00]; // Solicited + Override
    let bytes = frame.as_bytes();
    assert_eq!(bytes.len(), NDP_NA_FRAME_LEN);
    let na_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
    assert_eq!(bytes[na_offset], 136);
}

#[test]
fn ndp_ns_message_as_bytes_length() {
    let msg = NdpNsMessage {
        icmp_type: 135,
        code: 0,
        checksum: [0; 2],
        reserved: [0; 4],
        target: Ipv6Address::new([0; 16]),
        opt_type: 1,
        opt_len: 1,
        opt_mac: MacAddress { octets: [0; 6] },
    };
    assert_eq!(msg.as_bytes().len(), 32);
}

#[test]
fn ndp_na_message_as_bytes_length() {
    let msg = NdpNaMessage {
        icmp_type: 136,
        code: 0,
        checksum: [0; 2],
        flags: [0; 4],
        target: Ipv6Address::new([0; 16]),
        opt_type: 2,
        opt_len: 1,
        opt_mac: MacAddress { octets: [0; 6] },
    };
    assert_eq!(msg.as_bytes().len(), 32);
}

#[test]
fn ndp_constants() {
    assert_eq!(NDP_MIN_NS_NA_LEN, 24);
    assert_eq!(NDP_MIN_RA_LEN, 16);
    assert_eq!(
        ALL_NODES_MULTICAST.octets,
        [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
}

#[test]
#[should_panic]
fn ndp_ns_frame_from_bytes_mut_rejects_short() {
    let mut buf = [0u8; NDP_NS_FRAME_LEN - 1];
    let _ = NdpNsFrame::from_bytes_mut(&mut buf);
}

#[test]
#[should_panic]
fn ndp_na_frame_from_bytes_mut_rejects_short() {
    let mut buf = [0u8; NDP_NA_FRAME_LEN - 1];
    let _ = NdpNaFrame::from_bytes_mut(&mut buf);
}
```

Also add import for `MacAddress`:
```rust
use crate::net::wire::ethernet::MacAddress;
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::wire::ndp::tests -- --nocapture`
Expected: 11 tests pass (4 existing + 7 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/wire/ndp.rs
git commit -m "test(wire/ndp): add NDP frame accessor, constant, and validation tests"
```

---

### Task 9: checksum/common.rs — Large data and fold boundary tests

**Files:**
- Modify: `src/net/checksum/common.rs:168-267` (test module)

- [ ] **Step 1: Write the checksum edge case tests**

Add after the `checksum_to_bytes_nonzero` test (line 265):

```rust
#[test]
fn sum_words_large_data_exercises_wide_loop() {
    // 64 bytes triggers the 32-byte-per-iteration wide loop
    let data: Vec<u8> = (0u8..64).collect();
    let sum = sum_words(&data);
    // Verify via manual pairwise sum
    let mut expected = 0u64;
    for chunk in data.chunks(2) {
        expected += ((chunk[0] as u64) << 8) | (chunk[1] as u64);
    }
    assert_eq!(sum, expected);
}

#[test]
fn sum_words_carry_pending_consumed_by_next_byte() {
    // Start with pending byte 0xAB, then provide one more byte 0xCD
    // Should form word 0xABCD
    let (sum, pending) = sum_words_carry(&[0xCD], 0, Some(0xAB));
    assert_eq!(sum, 0xABCD);
    assert_eq!(pending, None);
}

#[test]
fn sum_words_carry_single_byte_becomes_pending() {
    let (sum, pending) = sum_words_carry(&[0x42], 100, None);
    assert_eq!(sum, 100);
    assert_eq!(pending, Some(0x42));
}

#[test]
fn fold_checksum_near_u16_max() {
    // 0xFFFF should fold to 0x0000
    let result = fold_checksum(0xFFFF);
    assert_eq!(result, 0x0000);
}

#[test]
fn fold_checksum_with_carry() {
    // 0x1FFFE = 0xFFFF + 0xFFFF, needs carry folding
    // fold: (0x1FFFE & 0xFFFF) + (0x1FFFE >> 16) = 0xFFFE + 1 = 0xFFFF
    // complement: !0xFFFF = 0x0000
    let result = fold_checksum(0x1FFFE);
    assert_eq!(result, 0x0000);
}

#[test]
fn fold_and_verify_correct_checksum() {
    let data = [0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06];
    let sum = sum_words(&data);
    let cksum = fold_checksum(sum);
    // Verify: sum of data + checksum should verify
    let full_sum = sum + cksum as u64;
    assert!(fold_and_verify(full_sum, 0x0000));
}

#[test]
fn sum_words_carry_three_slices() {
    // Verify correctness across 3 fragments with odd splits
    let full = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let expected = sum_words(&full);

    let (s1, p1) = sum_words_carry(&full[0..3], 0, None);
    let (s2, p2) = sum_words_carry(&full[3..5], s1, p1);
    let (mut s3, p3) = sum_words_carry(&full[5..7], s2, p2);
    if let Some(hi) = p3 {
        s3 += (hi as u64) << 8;
    }
    assert_eq!(s3, expected);
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test net::checksum::common::tests -- --nocapture`
Expected: All tests pass (8 existing + 7 new)

- [ ] **Step 3: Commit**

```bash
git add src/net/checksum/common.rs
git commit -m "test(checksum/common): add large data, fold boundary, and multi-slice tests"
```

---

### Task 10: xdp/program/map.rs — Map accessor tests

**Files:**
- Modify: `src/xdp/program/map.rs` (add test module at end of file)

- [ ] **Step 1: Write the test module**

Add at the end of the file (after line 87):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_map() -> Map {
        let info = bpf_map_info {
            name: {
                let mut name = [0; 16];
                let bytes = b"test_map";
                for (i, &b) in bytes.iter().enumerate() {
                    #[cfg(target_arch = "aarch64")]
                    {
                        name[i] = b;
                    }
                    #[cfg(target_arch = "x86_64")]
                    {
                        name[i] = b as i8;
                    }
                }
                name
            },
            ..unsafe { std::mem::zeroed() }
        };
        Map::new(std::ptr::null_mut(), info)
    }

    #[test]
    fn name_returns_map_name() {
        let map = make_test_map();
        assert!(map.name().starts_with("test_map"));
    }

    #[test]
    fn as_ptr_returns_inner() {
        let map = make_test_map();
        assert!(map.as_ptr().is_null()); // we constructed with null
    }

    #[test]
    fn as_mut_ptr_returns_inner() {
        let mut map = make_test_map();
        assert!(map.as_mut_ptr().is_null());
    }

    #[test]
    fn info_returns_info() {
        let map = make_test_map();
        let info = map.info();
        // Verify type/key_size/value_size are zero (from zeroed init)
        assert_eq!(info.type_, 0);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test xdp::program::map::tests -- --nocapture`
Expected: 4 tests pass

- [ ] **Step 3: Commit**

```bash
git add src/xdp/program/map.rs
git commit -m "test(xdp/program/map): add Map accessor tests"
```

---

### Task 11: neighbor/handler.rs — setter and lookup wrapper tests

**Files:**
- Modify: `src/net/neighbor/handler.rs:377+` (test module)

- [ ] **Step 1: Read existing test helpers to understand setup**

Run: `cargo test net::neighbor::handler::tests -- --list`
Review existing helper functions and constants in the test module.

- [ ] **Step 2: Write the setter and lookup tests**

Add after the last test in the module:

```rust
#[test]
fn set_offload_changes_flag() {
    let mut handler = new_handler();
    handler.set_offload(true);
    // Verify by checking the offload field (it affects checksum behavior)
    handler.set_offload(false);
    // No panic = success; the flag is stored internally
}

#[test]
fn set_local_mac_updates_mac() {
    let mut handler = new_handler();
    let new_mac = MacAddress {
        octets: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    };
    handler.set_local_mac(new_mac);
    assert_eq!(handler.local_mac(), new_mac);
}

#[test]
fn add_local_ipv6_dedup() {
    let mut handler = new_handler();
    let addr = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    handler.add_local_ipv6(addr);
    handler.add_local_ipv6(addr); // duplicate
    // Should not panic or duplicate internally
}

#[test]
fn lookup_v4_unknown_returns_none() {
    let handler = new_handler();
    let addr = Ipv4Address::new([192, 168, 99, 99]);
    assert!(handler.lookup_v4(&addr).is_none());
}

#[test]
fn lookup_v6_unknown_returns_none() {
    let handler = new_handler();
    let addr = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
    assert!(handler.lookup_v6(&addr).is_none());
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test net::neighbor::handler::tests -- --nocapture`
Expected: All tests pass (existing + 5 new)

- [ ] **Step 4: Commit**

```bash
git add src/net/neighbor/handler.rs
git commit -m "test(neighbor/handler): add setter and lookup wrapper tests"
```

---

### Task 12: handler/tcp/segment.rs — IPv6 segment building tests

**Files:**
- Modify: `src/net/handler/tcp/segment.rs:912+` (test module)

- [ ] **Step 1: Read existing IPv4 test patterns**

Read the existing `build_syn_ipv4`, `build_ack_ipv4`, `build_rst_ipv4` tests to understand the pattern. Each test:
1. Creates addresses, allocates a frame via `alloc_free_frame()`
2. Calls the build function
3. Asserts on the returned frame's TCP flags, sequence numbers, and checksum

- [ ] **Step 2: Write the IPv6 segment building tests**

Add after the last test in the module. The tests follow the same pattern as IPv4 tests but use `Ipv6Address` and `Ipv6` type parameter. Read the existing IPv4 tests for exact patterns — the IPv6 versions replace:
- `Ipv4Address` → `Ipv6Address`
- `IpAddress::V4(...)` → `IpAddress::V6(...)`
- `IPV4_MIN_HEADER_LEN` → `IPV6_HEADER_LEN` (40)
- IPv4 checksum verification → IPv6 checksum verification

Required tests:
- `build_syn_ipv6` — verify SYN flag, sequence number, MSS option
- `build_syn_ack_ipv6` — verify SYN+ACK flags, options
- `build_ack_ipv6` — verify ACK flag, ack number
- `build_rst_ipv6` — verify RST flag
- `build_fin_ack_ipv6` — verify FIN+ACK flags
- `build_data_ipv6` — verify payload, sequence, ACK
- `build_mismatched_v4_v6_returns_none` — verify that mixing V4 local with V6 remote returns the frame unused

The implementation for each test should use `IpAddress::V6(Ipv6Address::new([0xFE, 0x80, ...]))` addresses and follow the exact same assertion patterns as the IPv4 counterparts.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test net::handler::tcp::segment::tests -- --nocapture`
Expected: All tests pass (existing + 7 new)

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/segment.rs
git commit -m "test(tcp/segment): add IPv6 segment building and address mismatch tests"
```

---

### Task 13: wire/tcp.rs — Additional option edge case tests

**Files:**
- Modify: `src/net/wire/tcp.rs:468+` (test module)

- [ ] **Step 1: Read existing option tests to understand patterns**

Review `parse_mss_valid`, `parse_window_scale_valid`, `parse_timestamp_valid`, `parse_sack_blocks_two_blocks` for patterns.

- [ ] **Step 2: Write additional edge case tests**

Add after the last test:

```rust
#[test]
fn parse_sack_blocks_empty() {
    // SACK option with zero blocks (just kind + length=2)
    let hdr_bytes = build_tcp_header_with_options(&[5, 2]);
    let hdr = TcpHeader::from_bytes(&hdr_bytes);
    let blocks = hdr.sack_blocks();
    assert!(blocks.is_empty());
}

#[test]
fn parse_sack_blocks_one_block() {
    // SACK option with one block: kind=5, len=10, left_edge(4), right_edge(4)
    let mut opts = vec![5, 10];
    opts.extend_from_slice(&1000u32.to_be_bytes()); // left edge
    opts.extend_from_slice(&2000u32.to_be_bytes()); // right edge
    let hdr_bytes = build_tcp_header_with_options(&opts);
    let hdr = TcpHeader::from_bytes(&hdr_bytes);
    let blocks = hdr.sack_blocks();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0], (1000, 2000));
}

#[test]
fn seq_le_equal() {
    assert!(seq_le(100, 100));
}

#[test]
fn seq_lt_equal_is_false() {
    assert!(!seq_lt(100, 100));
}
```

Note: The helper `build_tcp_header_with_options` may need to be created if it doesn't exist. If the existing tests build headers differently (e.g., manually constructing byte arrays), follow that pattern instead. Read the test module to determine the exact approach.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test net::wire::tcp::tests -- --nocapture`
Expected: All tests pass (existing + 4 new)

- [ ] **Step 4: Commit**

```bash
git add src/net/wire/tcp.rs
git commit -m "test(wire/tcp): add SACK block parsing and sequence number edge case tests"
```

---

## Chunk 2: Phase 2 — Stateful TCP Handler Tests (Tasks 14-19)

All Phase 2 tests go in the existing `src/net/handler/tcp/tests/` directory using the established harness. Every test follows this pattern:

1. `let mut handler = new_handler();` + `let nh = new_neighbor_handler();`
2. Allocate frame buffers: `BasicFrameBuffer::new(32)` for free, rx, tx
3. Pre-populate free frames with `alloc_free_frame()`
4. Establish connection with `establish_connection()` or manual handshake
5. Clear tx: `while tx.pop().is_some() {}`
6. Exercise the code path
7. Assert on state, frames, and timers

### Task 14: teardown.rs — RST challenge ACK and partial state tests

**Files:**
- Modify: `src/net/handler/tcp/tests/teardown.rs`

- [ ] **Step 1: Read teardown.rs to understand existing test patterns**

Understand how existing tests handle FIN sequences and state transitions. Note the constants (LOCAL_IP, REMOTE_IP, etc.) and helper usage.

- [ ] **Step 2: Write RST challenge ACK test**

```rust
#[test]
fn rst_in_window_but_not_exact_seq_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 { free.push(alloc_free_frame(100 + i)); }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // RST with seq = rcv_nxt + 1 (in window but not exact)
    let rst = build_tcp_frame(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001 + 1, // seq is rcv_nxt + 1, not exact
        0, flags::RST, 65535, &[],
    );
    let len = rst.len();
    handler.process_ipv4(
        Frame::new(200, leak(rst), len, false),
        Instant::now(), &nh, &mut free, &mut rx, &mut tx,
    );

    // Should send challenge ACK, not tear down
    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert!(tx.num_frames() >= 1, "challenge ACK expected");
}
```

- [ ] **Step 3: Write FinWait2 data reception test**

```rust
#[test]
fn fin_wait2_data_before_remote_fin_acks_but_stays() {
    // Setup: establish, send FIN (Established -> FinWait1),
    // receive ACK of our FIN (FinWait1 -> FinWait2),
    // then receive data in FinWait2
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 { free.push(alloc_free_frame(100 + i)); }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Initiate close: set pending_fin, poll_send to send FIN
    handler.first_connection_mut().set_pending_fin();
    handler.poll_send(Instant::now(), nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {} // FIN-ACK sent

    // Transition to FinWait1
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);

    // Receive ACK of our FIN -> FinWait2
    let fin_ack_seq = handler.first_connection().snd_nxt;
    let ack_of_fin = build_tcp_frame(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, fin_ack_seq,
        flags::ACK, 65535, &[],
    );
    let len = ack_of_fin.len();
    handler.process_ipv4(
        Frame::new(201, leak(ack_of_fin), len, false),
        Instant::now(), &nh, &mut free, &mut rx, &mut tx,
    );
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);

    // Now receive data in FinWait2
    let data_seg = build_tcp_frame_with_payload(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, fin_ack_seq,
        flags::ACK, 65535, &[], b"hello",
    );
    let len = data_seg.len();
    handler.process_ipv4(
        Frame::new(202, leak(data_seg), len, false),
        Instant::now(), &nh, &mut free, &mut rx, &mut tx,
    );

    // Should stay in FinWait2 and ACK the data
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);
}
```

- [ ] **Step 4: Write additional teardown tests**

Add tests for:
- Closing partial ACK stays in Closing
- LastAck partial ACK persists connection
- TimeWait FIN retransmit restarts deadline
- CloseWait WL1/WL2 window update guard condition
- PAWS staleness edge case (very old ts_recent_age)

Follow the same pattern: establish connection, transition to the target state, inject a segment, assert state.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test net::handler::tcp::tests::teardown -- --nocapture`
Expected: All tests pass (existing + new)

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/tcp/tests/teardown.rs
git commit -m "test(tcp/teardown): add RST challenge ACK, FinWait2 data, and partial ACK tests"
```

---

### Task 15: established.rs — Challenge ACK, fast-path fallthrough, and OOO tests

**Files:**
- Modify: `src/net/handler/tcp/tests/established.rs` (or whichever file in `tests/` covers established state — may be `data_transfer.rs` or `edge_cases.rs`)

- [ ] **Step 1: Identify the correct test file for established state tests**

Check `data_transfer.rs`, `edge_cases.rs`, and `established.rs` to find where RST handling and OOO tests live.

- [ ] **Step 2: Write RST challenge ACK in Established test**

Similar to Task 14's RST test but ensuring the established state is preserved and a challenge ACK is sent when RST seq != rcv_nxt.

- [ ] **Step 3: Write fast-path fallthrough tests**

Test three fast-path fallthrough cases:
- PAWS failure: old timestamp on fast-path should fall through to slow path
- No window space: recv_buffer full triggers fallthrough
- Missing timestamp in TS-enabled connection

- [ ] **Step 4: Write out-of-order SACK block selection test**

Test multiple disjoint OOO ranges and verify SACK block selection respects max_blocks (3 with timestamps, 4 without) with "most recently received range first" ordering.

- [ ] **Step 5: Write out-of-order FIN test**

Test that FIN with seg_seq + payload_len != rcv_nxt is held until data is complete.

- [ ] **Step 6: Write ACK-for-unsent-data test**

```rust
#[test]
fn ack_for_unsent_data_sends_ack_and_drops() {
    // seg_ack > snd_nxt should trigger ACK with current snd_nxt
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 { free.push(alloc_free_frame(100 + i)); }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let snd_nxt = handler.first_connection().snd_nxt;

    // Send ACK for data we never sent (seg_ack > snd_nxt)
    let bad_ack = build_tcp_frame(
        REMOTE_IP, LOCAL_IP, 12345, 80,
        1001, snd_nxt.wrapping_add(1000), // ACKing unsent data
        flags::ACK, 65535, &[],
    );
    let len = bad_ack.len();
    handler.process_ipv4(
        Frame::new(300, leak(bad_ack), len, false),
        Instant::now(), &nh, &mut free, &mut rx, &mut tx,
    );

    // Should stay Established and send corrective ACK
    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert_eq!(handler.first_connection().snd_nxt, snd_nxt);
}
```

- [ ] **Step 7: Write duplicate data reception test**

Test that seg_seq < rcv_nxt (already-received data) is ACKed but not written to recv buffer.

- [ ] **Step 8: Run tests and commit**

Run: `cargo test net::handler::tcp::tests -- --nocapture`

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/established): add challenge ACK, fast-path fallthrough, OOO SACK, unsent-data ACK, and duplicate data tests"
```

---

### Task 16: transmit.rs — Limited transmit, persist cap, and linger tests

**Files:**
- Modify: `src/net/handler/tcp/tests/` (the file covering transmit behavior — likely `data_transfer.rs` or create entries in existing test files)

- [ ] **Step 1: Identify correct file and write limited transmit test**

Test that on 1st/2nd dup ACK, cwnd is inflated by dup_ack_count * MSS (RFC 3042).

- [ ] **Step 2: Write SWS avoidance with small windows test**

Test SWS avoidance edge case where max_snd_wnd < 2*MSS — verify `can_send >= (max_snd_wnd / 2).max(1)` behaves correctly.

- [ ] **Step 3: Write neighbor resolution pending test**

Test that when ARP lookup returns None (neighbor pending), the transmit loop breaks and re-marks with SendReady.

- [ ] **Step 4: Write persist timer backoff cap test**

Verify persist_backoff caps at 6 (max probe interval = RTO * 64).

- [ ] **Step 5: Write FIN state transition tests**

Test Established->FinWait1 and CloseWait->LastAck transitions when pending_fin is set and poll_send fires.

- [ ] **Step 6: Run tests and commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/transmit): add limited transmit, SWS, neighbor pending, persist cap, and FIN transition tests"
```

---

### Task 17: timers.rs — ECN and RTO edge case tests

**Files:**
- Modify: `src/net/handler/tcp/tests/timers.rs`

- [ ] **Step 1: Write RTO with empty send buffer test**

Verify that when RTO fires but send_buffer is empty, no retransmit is sent.

- [ ] **Step 2: Write ECN on keep-alive probe test**

Verify ECE flag on keep-alive probes when ecn_ce_received is set.

- [ ] **Step 3: Write delayed ACK neighbor pending test**

Verify that when neighbor lookup_or_resolve returns None during delayed ACK flush, the connection is re-marked for next poll_send.

- [ ] **Step 4: Write ECN disabled on retransmit test**

Verify that retransmitted segments have `ecn_ect: false` per RFC 3168.

- [ ] **Step 5: Run tests and commit**

```bash
git add src/net/handler/tcp/tests/timers.rs
git commit -m "test(tcp/timers): add RTO empty-buffer, ECN keep-alive, delayed ACK pending, and ECN retransmit tests"
```

---

### Task 18: syn_sent.rs — SYN-SENT edge cases

**Files:**
- Modify: `src/net/handler/tcp/tests/handshake.rs` (SYN-SENT tests likely here)

- [ ] **Step 1: Identify remaining edge cases**

Read the SYN-SENT handling code in `inbound/syn_sent.rs` and cross-reference with existing tests to find untested paths.

- [ ] **Step 2: Write edge case tests**

- [ ] **Step 3: Run tests and commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/syn_sent): add SYN-SENT state edge case tests"
```

---

### Task 19: listen.rs — Passive open edge cases

**Files:**
- Modify: `src/net/handler/tcp/tests/` (listener or handshake tests)

- [ ] **Step 1: Identify untested paths in `inbound/listen.rs`**

Read the passive open handler and cross-reference with existing tests.

- [ ] **Step 2: Write edge case tests for passive open**

- [ ] **Step 3: Run tests and commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/listen): add passive open edge case tests"
```

---

## Chunk 3: Phase 3 — Async/Future Tests (Tasks 20-28)

### Task 20: socket/queue.rs — LocalQueue::drain test

**Files:**
- Modify: `src/net/socket/queue.rs` (test module)

- [ ] **Step 1: Write drain test**

```rust
#[test]
fn local_queue_drain_range() {
    let mut queue = LocalQueue::new(8);
    for i in 0..5 {
        queue.push(i);
    }
    let drained: Vec<_> = queue.drain(1..3).collect();
    assert_eq!(drained, vec![1, 2]);
    assert_eq!(queue.len(), 3);
}
```

- [ ] **Step 2: Run tests and commit**

```bash
git add src/net/socket/queue.rs
git commit -m "test(socket/queue): add LocalQueue drain range test"
```

---

### Task 21: http/body.rs — read_all and expect_continue tests

**Files:**
- Modify: `src/net/http/body.rs:274+` (test module)

- [ ] **Step 1: Write read_all with limit test**

Use the existing `make_reader_parts()` helper and `futures::executor::block_on`:

```rust
#[test]
fn read_all_content_length() {
    let data = b"GET / HTTP/1.1\r\n\r\nhello world";
    let (stream, buf) = make_reader_parts(&data[18..]); // just the body
    let mut reader = BodyReader::new(BodyFraming::ContentLength(11), false, stream);
    let result = futures::executor::block_on(reader.read_all(&buf, 1024));
    assert!(result.is_ok());
    assert_eq!(&result.unwrap(), b"hello world");
}

#[test]
fn read_all_exceeds_limit() {
    let data = b"hello world this is long";
    let (stream, buf) = make_reader_parts(data);
    let mut reader = BodyReader::new(BodyFraming::ContentLength(24), false, stream);
    let result = futures::executor::block_on(reader.read_all(&buf, 5));
    assert!(result.is_err()); // exceeds limit of 5 bytes
}
```

- [ ] **Step 2: Write chunked edge case tests**

```rust
#[test]
fn chunked_read_eof_mid_chunk() {
    // Chunked body where stream EOF occurs before chunk data is complete
    let data = b"5\r\nhe"; // claims 5 bytes but only provides 2
    let (stream, buf) = make_reader_parts(data);
    let mut reader = BodyReader::new(BodyFraming::Chunked, false, stream);
    let result = futures::executor::block_on(reader.read(&buf));
    // Should error or return partial data
}

#[test]
fn chunked_read_invalid_chunk_size() {
    // Invalid hex in chunk size line
    let data = b"ZZZZ\r\nhello\r\n0\r\n\r\n";
    let (stream, buf) = make_reader_parts(data);
    let mut reader = BodyReader::new(BodyFraming::Chunked, false, stream);
    let result = futures::executor::block_on(reader.read(&buf));
    // Should error on parse failure
}

#[test]
fn consume_crlf_bare_newline() {
    // Some servers send \n without \r — verify we handle it
    let data = b"5\nhello\n0\n\n";
    let (stream, buf) = make_reader_parts(data);
    let mut reader = BodyReader::new(BodyFraming::Chunked, false, stream);
    let result = futures::executor::block_on(reader.read(&buf));
    // Should handle bare \n gracefully
}
```

Adapt based on actual BodyReader API — read the file for exact method signatures and error types.

- [ ] **Step 3: Run tests and commit**

```bash
git add src/net/http/body.rs
git commit -m "test(http/body): add read_all, limit enforcement, and chunked edge case tests"
```

---

### Task 22: http/response.rs — Status and header tests

**Files:**
- Modify: `src/net/http/response.rs:299+` (test module)

- [ ] **Step 1: Write set_status and add_header tests**

Test the synchronous parts of ResponseWriter (status setting, header accumulation). The async write tests require more infrastructure and may need to be deferred.

```rust
#[test]
fn set_status_stores_code_and_reason() {
    // Test that common status codes use &'static str (Borrowed)
    let phrase = super::reason_phrase(200);
    assert!(matches!(phrase, std::borrow::Cow::Borrowed("OK")));
}

#[test]
fn set_status_custom_reason() {
    let phrase = super::reason_phrase(299);
    // Unknown status codes produce "Unknown" or similar
    assert!(!phrase.is_empty());
}

#[test]
fn common_status_phrases() {
    assert_eq!(super::reason_phrase(200), "OK");
    assert_eq!(super::reason_phrase(404), "Not Found");
    assert_eq!(super::reason_phrase(500), "Internal Server Error");
    assert_eq!(super::reason_phrase(301), "Moved Permanently");
    assert_eq!(super::reason_phrase(304), "Not Modified");
}
```

Note: Adapt these tests based on what `reason_phrase` or equivalent is named in the actual code. Read the file first.

- [ ] **Step 2: Run tests and commit**

```bash
git add src/net/http/response.rs
git commit -m "test(http/response): add status code and reason phrase tests"
```

---

### Task 23: http/connection.rs — next_request and session transition tests

**Files:**
- Modify: `src/net/http/connection.rs:108+` (test module)

- [ ] **Step 1: Write buffer append and decode tests**

Use the existing `new_test_connection_http11()` helper to test request decoding from pre-filled buffers:

```rust
#[test]
fn decode_simple_get_from_buffer() {
    let mut conn = new_test_connection_http11();
    conn.buf.append(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let decoded = conn.try_decode();
    assert!(decoded.is_some());
}
```

Adapt based on actual method names after reading the file.

- [ ] **Step 2: Run tests and commit**

```bash
git add src/net/http/connection.rs
git commit -m "test(http/connection): add request decode and buffer tests"
```

---

### Task 24: http/codec/v1_1.rs — Transfer-Encoding fallthrough tests

**Files:**
- Modify: `src/net/http/codec/v1_1.rs` (test module)

- [ ] **Step 1: Write non-chunked Transfer-Encoding test**

Test that `Transfer-Encoding: gzip` (not "chunked") falls through to Content-Length handling.

- [ ] **Step 2: Run tests and commit**

```bash
git add src/net/http/codec/v1_1.rs
git commit -m "test(http/codec/v1_1): add non-chunked Transfer-Encoding fallthrough test"
```

---

### Task 25: http/codec/v1_0.rs — Additional edge case tests

**Files:**
- Modify: `src/net/http/codec/v1_0.rs` (test module)

- [ ] **Step 1: Write Content-Length edge case tests**

Test multi-request parsing with buffer offsets and edge cases.

- [ ] **Step 2: Run tests and commit**

```bash
git add src/net/http/codec/v1_0.rs
git commit -m "test(http/codec/v1_0): add Content-Length edge case tests"
```

---

### Task 26: http/codec/v0_9.rs — Query string path tests

**Files:**
- Modify: `src/net/http/codec/v0_9.rs` (test module)

- [ ] **Step 1: Write query string and special character tests**

```rust
#[test]
fn decode_path_with_query_string() {
    let request = b"GET /search?q=hello\r\n";
    let result = Http09Codec::new().decode(request, 0);
    assert!(result.is_some());
    // Verify path includes query string
}
```

- [ ] **Step 2: Run tests and commit**

```bash
git add src/net/http/codec/v0_9.rs
git commit -m "test(http/codec/v0_9): add query string and special character path tests"
```

---

### Task 27: socket/tcp.rs — Close, shutdown, and future poll tests

**Files:**
- Modify: `src/net/socket/tcp.rs:596+` (test module)

- [ ] **Step 1: Read existing make_test_stream() and TcpStream API**

Understand what `from_accepted_for_test()` returns and what methods are available. Determine if poll-based tests require additional setup (e.g., pre-populating handler state, constructing waker contexts).

- [ ] **Step 2: Write close and shutdown tests**

Use the existing `make_test_stream()` helper:

```rust
#[test]
fn close_sets_pending_fin() {
    let (mut stream, _handler) = make_test_stream();
    stream.close();
    // Verify close was called without panic
}

#[test]
fn shutdown_write_sets_pending_fin() {
    let (mut stream, _handler) = make_test_stream();
    stream.shutdown();
    // Verify shutdown was called without panic
}
```

Adapt based on actual method signatures.

- [ ] **Step 3: Write Connect::poll and Accept::poll tests**

Test future state transitions:
- Connect returning Pending when connection not yet established
- Accept returning Pending when no incoming connection

Use `std::task::Context::from_waker(&task_queue_waker())` or similar to drive poll manually.

- [ ] **Step 4: Write TcpRead::poll and TcpWrite::poll tests**

Test read/write future behavior:
- TcpRead returning data when recv_buffer has content
- TcpRead returning Pending when recv_buffer is empty
- TcpWrite returning Ready when send_buffer has space
- TcpWrite returning Pending when send_buffer is full

- [ ] **Step 5: Run tests and commit**

```bash
git add src/net/socket/tcp.rs
git commit -m "test(socket/tcp): add close, shutdown, and future poll tests"
```

---

### Task 28: socket/udp.rs — SendHalf, RecvHalf, and future poll tests

**Files:**
- Modify: `src/net/socket/udp.rs:479+` (test module)

- [ ] **Step 1: Write split socket operation tests**

Use the existing `with_test_context()` helper:

```rust
#[test]
fn discard_does_not_panic() {
    with_test_context(|| {
        let socket = UdpSocket::new(IpAddress::V4(Ipv4Address::new([127, 0, 0, 1])));
        socket.discard();
        // Verify discard mode was set
    });
}
```

- [ ] **Step 2: Write SendTo::poll and RecvFrom::poll tests**

Test future poll behavior within `with_test_context()`:
- SendTo::poll with v4 and v6 destination addresses
- RecvFrom::poll returning Pending when no data queued
- Echo::poll backpressure behavior

- [ ] **Step 3: Write RecvStream::poll_next test**

Test the Stream trait implementation on RecvStream.

- [ ] **Step 4: Run tests and commit**

```bash
git add src/net/socket/udp.rs
git commit -m "test(socket/udp): add discard, split socket, and future poll tests"
```

---

## Chunk 4: Phase 4 — Integration-Adjacent Tests (Tasks 29-34)

### Task 29: rt/task.rs — TaskQueue unit tests

**Files:**
- Modify: `src/rt/task.rs` (add test module)

- [ ] **Step 1: Read task.rs to understand TaskQueue internals**

Understand how `TaskQueue::new()`, `push()`, and `poll()` work. Identify what can be tested without a full runtime.

- [ ] **Step 2: Write TaskQueue tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_queue_new() {
        let queue = TaskQueue::new();
        // Verify initial state — empty staging and futures
    }

    #[test]
    fn task_queue_push_stages_future() {
        let mut queue = TaskQueue::new();
        queue.push(Box::pin(async { () }));
        // Future is staged but not yet polled
    }
}
```

Adapt based on actual TaskQueue API after reading the file.

- [ ] **Step 3: Run tests and commit**

```bash
git add src/rt/task.rs
git commit -m "test(rt/task): add TaskQueue construction and push tests"
```

---

### Task 30: rt/context.rs — ContextDropGuard and panic tests

**Files:**
- Modify: `src/rt/context.rs` (add test module)

- [ ] **Step 1: Read context.rs to understand ContextDropGuard and register_capacity_waker**

Understand how ContextDropGuard sets/clears the thread-local and what register_capacity_waker does.

- [ ] **Step 2: Write context tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn with_runtime_context_panics_outside_runtime() {
        with_runtime_context(|_ctx| {});
    }
}
```

- [ ] **Step 3: Write ContextDropGuard creation and cleanup tests**

If the guard can be constructed in test (it needs a RuntimeContext), follow the pattern from `src/net/socket/udp.rs:with_test_context()` which already builds a full RuntimeContext. Create a minimal variant for this test.

- [ ] **Step 4: Write register_capacity_waker test**

Verify that register_capacity_waker stores a waker and that it can be retrieved/triggered.

- [ ] **Step 5: Run tests and commit**

```bash
git add src/rt/context.rs
git commit -m "test(rt/context): add panic, ContextDropGuard, and capacity waker tests"
```

---

### Task 31: xdp/program/prog.rs — Input validation error path tests

**Files:**
- Modify: `src/xdp/program/prog.rs` (test module)

- [ ] **Step 1: Read prog.rs to understand testable error paths**

Identify which error paths in `new()` can be triggered without real BPF/XDP infrastructure:
- CString conversion failure (null byte in interface name)
- `if_nametoindex` returning 0 (nonexistent interface)

- [ ] **Step 2: Write input validation tests**

```rust
#[test]
fn new_with_null_byte_in_name_fails() {
    // Interface name with embedded null should fail CString conversion
    let result = XdpProgram::new("eth\00", ...);
    assert!(result.is_err());
}
```

Adapt based on actual XdpProgram::new() signature. Some error paths may not be triggerable without real interfaces — test what's possible.

- [ ] **Step 3: Run tests and commit**

```bash
git add src/xdp/program/prog.rs
git commit -m "test(xdp/program/prog): add input validation error path tests"
```

---

### Task 32: xdp/socket/rx.rs — SocketRx accessor tests

**Files:**
- Modify: `src/xdp/socket/rx.rs` (test module or add new one)

- [ ] **Step 1: Read rx.rs to understand testable surface**

Identify what can be tested without real XDP sockets (accessors, error paths).

- [ ] **Step 2: Write accessor tests**

- [ ] **Step 3: Run tests and commit**

```bash
git add src/xdp/socket/rx.rs
git commit -m "test(xdp/socket/rx): add SocketRx accessor tests"
```

---

### Task 33: xdp/socket/tx.rs — SocketTx accessor tests

**Files:**
- Modify: `src/xdp/socket/tx.rs` (test module or add new one)

- [ ] **Step 1: Read tx.rs to understand testable surface**

- [ ] **Step 2: Write accessor tests**

- [ ] **Step 3: Run tests and commit**

```bash
git add src/xdp/socket/tx.rs
git commit -m "test(xdp/socket/tx): add SocketTx accessor tests"
```

---

### Task 34: http/listener.rs — HttpListener accessor tests

**Files:**
- Modify: `src/net/http/listener.rs` (add test module)

- [ ] **Step 1: Read listener.rs to understand what's testable**

Determine if HttpListener can be constructed in a test context (likely needs TcpListener which needs runtime). If not, document what requires integration tests.

- [ ] **Step 2: Write any testable accessor tests**

- [ ] **Step 3: Run tests and commit**

```bash
git add src/net/http/listener.rs
git commit -m "test(http/listener): add HttpListener accessor tests"
```

---

### Task 35: Run full coverage and verify improvement

**Files:**
- None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass (932 existing + ~170-210 new = ~1100-1140 total)

- [ ] **Step 2: Run cargo llvm-cov**

Run: `cargo llvm-cov`
Expected: Overall line coverage 95-97% (up from 88.5%)

- [ ] **Step 3: Review coverage report for remaining gaps**

Check if any targeted files still have unexpectedly low coverage. Create follow-up tasks for any surprises.

- [ ] **Step 4: Commit any final adjustments**

```bash
git commit -m "test: verify coverage improvement to 95%+ across all phases"
```
