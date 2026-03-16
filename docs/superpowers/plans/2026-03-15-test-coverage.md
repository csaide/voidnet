# Test Coverage Improvement Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve line coverage from 83.8% to ~89–91% by adding unit tests to the highest-impact testable modules.

**Architecture:** Three phases targeting fully testable modules first (Phase 1), then partially testable TCP/UDP internals (Phase 2), then moderate-impact files (Phase 3). All tests go in `#[cfg(test)] mod tests` blocks within each source file.

**Tech Stack:** Rust, `cargo test` (no feature flags, runs as root via `.cargo/config.toml`), `cargo llvm-cov` for measurement.

**Async testing constraint:** `futures::executor::block_on` works ONLY when all data is pre-filled in the `ReadBuffer` and the code path never falls through to `stream.read()`. For any async test that would hit the stream (e.g., Content-Length body reading when the buffer is drained mid-read), a `LocalRuntime` is required. The existing chunked body tests work with `block_on` because all data is consumed from the pre-filled buffer. Content-Length tests must either: (a) pre-fill enough data and use a dest buffer large enough to consume in one read, or (b) use a `LocalRuntime`. Prefer (a) when possible to keep tests simple; use (b) only when multi-read behavior is being tested. Tests for `response.rs` public methods (`write_body`, `finish`, `flush_headers`) are deferred — they require a `LocalRuntime` + `TcpStream` with a connected peer.

---

## Chunk 1: Phase 1 — Fully Testable Modules

### Task 1: `wire/ip/proto.rs` — Display and constants

**Files:**
- Modify: `src/net/wire/ip/proto.rs`

- [ ] **Step 1: Write tests for IpProtocol Display and constants**

Add a `#[cfg(test)]` module at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_known_protocols() {
        assert_eq!(format!("{}", IpProtocol(IpProtocols::Icmp)), "ICMP");
        assert_eq!(format!("{}", IpProtocol(IpProtocols::IcmpV6)), "ICMPv6");
        assert_eq!(format!("{}", IpProtocol(IpProtocols::Udp)), "UDP");
        assert_eq!(format!("{}", IpProtocol(IpProtocols::Tcp)), "TCP");
    }

    #[test]
    fn display_unknown_protocol() {
        assert_eq!(format!("{}", IpProtocol(255)), "Unknown");
        assert_eq!(format!("{}", IpProtocol(0)), "Unknown");
    }

    #[test]
    fn protocol_constants() {
        assert_eq!(IpProtocols::Icmp, 1);
        assert_eq!(IpProtocols::IcmpV6, 58);
        assert_eq!(IpProtocols::Udp, 17);
        assert_eq!(IpProtocols::Tcp, 6);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test wire::ip::proto`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add src/net/wire/ip/proto.rs
git commit -m "test(wire/ip): add Display and constant tests for IpProtocol"
```

---

### Task 2: `xdp/error.rs` — Error Display coverage

**Files:**
- Modify: `src/xdp/error.rs`

- [ ] **Step 1: Write tests for Error Display variants**

Add a `#[cfg(test)]` module at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_error_variants() {
        let e = Error::InterfaceNotFound;
        assert_eq!(e.to_string(), "failed to find specified interface");

        let e = Error::FragmentationNotSupported;
        assert_eq!(e.to_string(), "fragmentation not supported by the network interface");

        let e = Error::ZeroCopyNotSupported;
        assert_eq!(e.to_string(), "zero copy not supported by the network interface");

        let e = Error::ExitRuntime;
        assert_eq!(e.to_string(), "Exiting runtime");

        let e = Error::InvalidFrameSize(3000);
        assert!(e.to_string().contains("3000"));

        let e = Error::InvalidFillRingSize(7);
        assert!(e.to_string().contains("7"));

        let e = Error::InvalidCompletionRingSize(5);
        assert!(e.to_string().contains("5"));

        let e = Error::InvalidAttachMode("bad".to_string());
        assert!(e.to_string().contains("bad"));

        let e = Error::InvalidCopyMode("bad".to_string());
        assert!(e.to_string().contains("bad"));

        let e = Error::Other("custom error".to_string());
        assert_eq!(e.to_string(), "custom error");

        let e = Error::GetMtu("eth0 failed".to_string());
        assert!(e.to_string().contains("eth0 failed"));

        let e = Error::GetChecksumOffload("not supported".to_string());
        assert!(e.to_string().contains("not supported"));
    }

    #[test]
    fn display_would_block() {
        let e = WouldBlock;
        assert_eq!(e.to_string(), "network I/O error: would block");
    }

    #[test]
    fn would_block_equality() {
        assert_eq!(WouldBlock, WouldBlock);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test xdp::error`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add src/xdp/error.rs
git commit -m "test(xdp): add Display tests for Error and WouldBlock"
```

---

### Task 3: `wire/ethernet.rs` — Display and write_ethernet_header

**Files:**
- Modify: `src/net/wire/ethernet.rs`

- [ ] **Step 1: Add Display and write_ethernet_header tests**

Append to the existing `mod tests` block (after `from_bytes_accepts_minimum_frame` test):

```rust
    #[test]
    fn mac_address_display() {
        let mac = MacAddress::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(format!("{}", mac), "01:23:45:67:89:ab");

        assert_eq!(format!("{}", MacAddress::zero()), "00:00:00:00:00:00");
        assert_eq!(format!("{}", MacAddress::broadcast()), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn ether_type_display() {
        assert_eq!(format!("{}", EtherTypes::IPv4), "IPv4");
        assert_eq!(format!("{}", EtherTypes::IPv6), "IPv6");
        assert_eq!(format!("{}", EtherTypes::Arp), "ARP");
        assert_eq!(format!("{}", EtherType { octets: [0x00, 0x00] }), "Unknown");
    }

    #[test]
    fn ethernet_frame_display() {
        let mut data = [0u8; 14];
        let src = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let dst = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        write_ethernet_header(&mut data, dst, src, EtherTypes::IPv4);
        let frame = EthernetFrame::from_bytes(&data);
        let display = format!("{}", frame);
        assert!(display.contains("aa:bb:cc:dd:ee:ff"));
        assert!(display.contains("11:22:33:44:55:66"));
        assert!(display.contains("IPv4"));
    }

    #[test]
    fn write_ethernet_header_sets_fields() {
        let mut data = [0u8; 14];
        let src = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let dst = MacAddress::broadcast();
        write_ethernet_header(&mut data, dst, src, EtherTypes::Arp);
        let frame = EthernetFrame::from_bytes(&data);
        assert_eq!(frame.dst_mac, MacAddress::broadcast());
        assert_eq!(frame.src_mac, src);
        assert_eq!(frame.ether_type, EtherTypes::Arp);
    }

    #[test]
    fn from_bytes_mut_allows_mutation() {
        let mut data = [0u8; 14];
        let frame = EthernetFrame::from_bytes_mut(&mut data);
        frame.dst_mac = MacAddress::broadcast();
        frame.ether_type = EtherTypes::IPv6;
        let frame = EthernetFrame::from_bytes(&data);
        assert_eq!(frame.dst_mac, MacAddress::broadcast());
        assert_eq!(frame.ether_type, EtherTypes::IPv6);
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn from_bytes_mut_rejects_truncated_frame() {
        let mut short = [0u8; 13];
        let _ = EthernetFrame::from_bytes_mut(&mut short);
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test wire::ethernet`
Expected: All tests pass (6 existing + 6 new = 12)

- [ ] **Step 3: Commit**

```bash
git add src/net/wire/ethernet.rs
git commit -m "test(wire): add Display, write_ethernet_header, and mutation tests"
```

---

### Task 4: `wire/ip/addr.rs` — FromStr, Display, std conversions, SocketAddr

**Files:**
- Modify: `src/net/wire/ip/addr.rs`

- [ ] **Step 1: Add FromStr and Display tests**

Append to the existing `mod tests` block:

```rust
    #[test]
    fn ipv4_display() {
        assert_eq!(format!("{}", Ipv4Address::loopback()), "127.0.0.1");
        assert_eq!(format!("{}", Ipv4Address::unspecified()), "0.0.0.0");
        assert_eq!(format!("{}", Ipv4Address::broadcast()), "255.255.255.255");
        assert_eq!(format!("{}", Ipv4Address::new([192, 168, 1, 1])), "192.168.1.1");
    }

    #[test]
    fn ipv4_from_str() {
        let addr: Ipv4Address = "10.0.0.1".parse().unwrap();
        assert_eq!(addr.octets, [10, 0, 0, 1]);

        let addr: Ipv4Address = "255.255.255.255".parse().unwrap();
        assert_eq!(addr, Ipv4Address::broadcast());

        assert!("not.an.ip".parse::<Ipv4Address>().is_err());
        assert!("".parse::<Ipv4Address>().is_err());
    }

    #[test]
    fn ipv4_std_conversions() {
        let std_addr = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let our_addr: Ipv4Address = std_addr.into();
        assert_eq!(our_addr.octets, [192, 168, 0, 1]);

        let back: std::net::Ipv4Addr = our_addr.into();
        assert_eq!(back, std_addr);
    }

    #[test]
    fn ipv6_display() {
        assert_eq!(format!("{}", Ipv6Address::loopback()), "::1");
        assert_eq!(format!("{}", Ipv6Address::unspecified()), "::");
    }

    #[test]
    fn ipv6_from_str() {
        let addr: Ipv6Address = "::1".parse().unwrap();
        assert_eq!(addr, Ipv6Address::loopback());

        let addr: Ipv6Address = "fe80::1".parse().unwrap();
        assert!(addr.is_link_local());

        assert!("not-an-ipv6".parse::<Ipv6Address>().is_err());
    }

    #[test]
    fn ipv6_std_conversions() {
        let std_addr = std::net::Ipv6Addr::LOCALHOST;
        let our_addr: Ipv6Address = std_addr.into();
        assert_eq!(our_addr, Ipv6Address::loopback());

        let back: std::net::Ipv6Addr = our_addr.into();
        assert_eq!(back, std_addr);
    }

    #[test]
    fn ip_address_display() {
        assert_eq!(format!("{}", IpAddress::V4(Ipv4Address::loopback())), "127.0.0.1");
        assert_eq!(format!("{}", IpAddress::V6(Ipv6Address::loopback())), "::1");
    }

    #[test]
    fn ip_address_from_str() {
        let addr: IpAddress = "10.0.0.1".parse().unwrap();
        assert_eq!(addr, IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])));

        let addr: IpAddress = "::1".parse().unwrap();
        assert_eq!(addr, IpAddress::V6(Ipv6Address::loopback()));

        assert!("garbage".parse::<IpAddress>().is_err());
    }

    #[test]
    fn ip_address_std_conversions() {
        let std_v4 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let our: IpAddress = std_v4.into();
        assert_eq!(our, IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])));
        let back: std::net::IpAddr = our.into();
        assert_eq!(back, std_v4);

        let std_v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let our: IpAddress = std_v6.into();
        assert_eq!(our, IpAddress::V6(Ipv6Address::loopback()));
        let back: std::net::IpAddr = our.into();
        assert_eq!(back, std_v6);
    }

    #[test]
    fn ip_address_from_std_ipv4() {
        let std_addr = std::net::Ipv4Addr::new(1, 2, 3, 4);
        let our: IpAddress = std_addr.into();
        assert_eq!(our, IpAddress::V4(Ipv4Address::new([1, 2, 3, 4])));
    }

    #[test]
    fn ip_address_from_std_ipv6() {
        let std_addr = std::net::Ipv6Addr::LOCALHOST;
        let our: IpAddress = std_addr.into();
        assert_eq!(our, IpAddress::V6(Ipv6Address::loopback()));
    }

    #[test]
    fn ip_address_is_unspecified() {
        assert!(IpAddress::V4(Ipv4Address::unspecified()).is_unspecified());
        assert!(IpAddress::V6(Ipv6Address::unspecified()).is_unspecified());
        assert!(!IpAddress::V4(Ipv4Address::loopback()).is_unspecified());
        assert!(!IpAddress::V6(Ipv6Address::loopback()).is_unspecified());
    }

    #[test]
    fn socket_addr_new() {
        let sa = SocketAddr::new(IpAddress::V4(Ipv4Address::loopback()), 8080);
        assert_eq!(sa.ip, IpAddress::V4(Ipv4Address::loopback()));
        assert_eq!(sa.port, 8080);
    }

    #[test]
    fn socket_addr_display() {
        let sa = SocketAddr::new(IpAddress::V4(Ipv4Address::loopback()), 443);
        assert_eq!(format!("{}", sa), "127.0.0.1:443");

        let sa = SocketAddr::new(IpAddress::V6(Ipv6Address::loopback()), 80);
        assert_eq!(format!("{}", sa), "::1:80");
    }

    #[test]
    fn socket_addr_from_str() {
        let sa: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(sa.ip, IpAddress::V4(Ipv4Address::loopback()));
        assert_eq!(sa.port, 8080);

        let sa: SocketAddr = "[::1]:443".parse().unwrap();
        assert_eq!(sa.ip, IpAddress::V6(Ipv6Address::loopback()));
        assert_eq!(sa.port, 443);

        assert!("not-a-socket-addr".parse::<SocketAddr>().is_err());
    }

    #[test]
    fn socket_addr_std_conversions() {
        let std_sa = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            3000,
        );
        let our: SocketAddr = std_sa.into();
        assert_eq!(our.ip, IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])));
        assert_eq!(our.port, 3000);

        let back: std::net::SocketAddr = our.into();
        assert_eq!(back, std_sa);
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test wire::ip::addr`
Expected: All tests pass (9 existing + 16 new = 25)

- [ ] **Step 3: Commit**

```bash
git add src/net/wire/ip/addr.rs
git commit -m "test(wire/ip): add FromStr, Display, std conversion, and SocketAddr tests"
```

---

### Task 5: `http/response.rs` — write_hex edge cases and Cow status

**Files:**
- Modify: `src/net/http/response.rs`

- [ ] **Step 1: Add write_hex edge cases**

Append to the existing `mod tests` block:

```rust
    #[test]
    fn write_hex_max_usize() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(usize::MAX, &mut buf);
        // usize::MAX on 64-bit = ffffffffffffffff (16 hex digits + \r\n = 18 bytes)
        let hex_str = std::str::from_utf8(&buf[..n - 2]).unwrap();
        assert!(hex_str.chars().all(|c| c == 'f'));
        assert_eq!(buf[n - 2], b'\r');
        assert_eq!(buf[n - 1], b'\n');
    }

    #[test]
    fn write_hex_powers_of_16() {
        let cases: &[(usize, &[u8])] = &[
            (0x10, b"10\r\n"),
            (0x100, b"100\r\n"),
            (0x1000, b"1000\r\n"),
        ];
        for &(val, expected) in cases {
            let mut buf = [0u8; HEX_BUF_LEN];
            let n = write_hex_usize(val, &mut buf);
            assert_eq!(&buf[..n], expected, "failed for value {:#x}", val);
        }
    }

    #[test]
    fn write_hex_mixed_digits() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(0xDEAD, &mut buf);
        assert_eq!(&buf[..n], b"dead\r\n");
    }

```

Note: The `response.rs` public methods (`set_status`, `write_body`, `finish`, `flush_headers`) require a `TcpStream` with a connected peer and a `LocalRuntime`. Testing these is deferred to the integration test pass. The `write_hex_*` tests cover the pure computation logic that accounts for the testable portion of this file.

- [ ] **Step 2: Run tests**

Run: `cargo test http::response`
Expected: All tests pass (8 existing + 3 new = 11)

- [ ] **Step 3: Commit**

```bash
git add src/net/http/response.rs
git commit -m "test(http): add write_hex edge cases and Cow status coverage"
```

---

### Task 6: `http/body.rs` — Content-Length body reading

**Files:**
- Modify: `src/net/http/body.rs`

- [ ] **Step 1: Add Content-Length body tests**

Append to the existing `mod tests` block. These tests use the existing `make_reader_parts` helper and `futures::executor::block_on`. **Important:** `block_on` works here because all data is pre-filled in the `ReadBuffer` and the dest buffer is large enough to consume everything in one call, so the code never falls through to `stream.read()`. Do NOT use a small dest buffer that would force multiple reads — that would require a `LocalRuntime`.

```rust
    #[test]
    fn content_length_read_exact() {
        let payload = b"Hello, World!";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(
            &stream,
            &mut buf,
            BodyFraming::ContentLength(payload.len()),
            false,
        );

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(&dest[..n], payload);
        assert!(reader.is_finished());
    }

    #[test]
    fn content_length_zero_is_immediately_finished() {
        let (stream, mut buf) = make_reader_parts(b"");
        let mut reader = BodyReader::new(
            &stream,
            &mut buf,
            BodyFraming::ContentLength(0),
            false,
        );

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 0);
        assert!(reader.is_finished());
    }

    #[test]
    fn body_framing_none_returns_zero() {
        let (stream, mut buf) = make_reader_parts(b"ignored data");
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::None, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 0);
        assert!(reader.is_finished());
    }

    #[test]
    fn chunked_read_large_chunk_size() {
        // Chunk size in hex: "10" = 16 bytes
        let payload = b"10\r\n0123456789abcdef\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 16);
        assert_eq!(&dest[..n], b"0123456789abcdef");
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test http::body`
Expected: All tests pass (8 existing + 4 new = 12)

- [ ] **Step 3: Commit**

```bash
git add src/net/http/body.rs
git commit -m "test(http): add Content-Length and BodyFraming::None body reader tests"
```

---

### Task 7: `http/connection.rs` — buffer and session tests

**Files:**
- Modify: `src/net/http/connection.rs`

- [ ] **Step 1: Read the file to understand available test helpers and uncovered paths**

Read `src/net/http/connection.rs` to identify the `new_test_connection` helper and the untested methods.

- [ ] **Step 2: Add tests for buffer and session management**

Append to the existing `mod tests` block. Use the existing `new_test_connection` helper. The specific tests depend on what `new_test_connection` returns and what methods are accessible. Focus on:
- `request_path()` with various path offsets (extend existing test)
- Session state after construction (verify initial state)
- Multiple calls to `respond()` / `prepare_next()` if accessible without async I/O

- [ ] **Step 3: Run tests**

Run: `cargo test http::connection`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/http/connection.rs
git commit -m "test(http): add connection buffer and session state tests"
```

---

### Task 8: `http/codec/v1_1.rs`, `v1_0.rs`, `mod.rs` — edge cases

**Files:**
- Modify: `src/net/http/codec/v1_1.rs`
- Modify: `src/net/http/codec/v1_0.rs`
- Modify: `src/net/http/codec/mod.rs`

- [ ] **Step 1: Read the codec files to identify specific uncovered branches**

Read all three files, focusing on the lines after the existing test modules to understand what edge cases are missing.

- [ ] **Step 2: Add edge case tests to v1_1.rs**

Append to the existing `mod tests` block in `v1_1.rs`. Focus on:
- Connection: close directive handling
- Connection: keep-alive directive handling
- Expect: 100-continue detection
- Multiple headers with same name
- Empty header value

- [ ] **Step 3: Add edge case tests to v1_0.rs**

Append to the existing `mod tests` block in `v1_0.rs`. Focus on:
- Missing Content-Length on POST (should use connection close)
- Zero Content-Length

- [ ] **Step 4: Add transition tests to mod.rs**

Append to the existing `mod tests` block in `mod.rs`. Focus on:
- `decode()` after transition to concrete codec
- `version()` after transition

- [ ] **Step 5: Run tests**

Run: `cargo test http::codec`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/net/http/codec/v1_1.rs src/net/http/codec/v1_0.rs src/net/http/codec/mod.rs
git commit -m "test(http/codec): add edge case tests for v1.1, v1.0, and codec dispatch"
```

---

### Task 9: Phase 1 verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Measure coverage improvement**

Run: `cargo llvm-cov --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); t=d['data'][0]['totals']['lines']; print(f\"Coverage: {t['percent']:.1f}% ({t['covered']}/{t['count']})\")"`
Expected: Coverage improvement from 83.8% baseline

- [ ] **Step 3: Commit any fixes if tests revealed issues**

---

## Chunk 2: Phase 2 — Partially Testable TCP/UDP Internals

### Task 10: `tcp/inbound/established.rs` — ACK, RTT, SACK, data processing

**Files:**
- Modify: `src/net/handler/tcp/tests/data_transfer.rs` (or create new test file)
- Reference: `src/net/handler/tcp/tests/mod.rs` for test helpers
- Reference: `src/net/handler/tcp/inbound/established.rs` for uncovered paths

- [ ] **Step 1: Read the uncovered paths in established.rs**

Read `src/net/handler/tcp/inbound/established.rs` to identify the specific uncovered branches: F-RTO handling, SACK scoreboard merge, ECN congestion response, OOO data, and FIN processing to CloseWait.

- [ ] **Step 2: Read existing tests to avoid duplication**

Read `src/net/handler/tcp/tests/data_transfer.rs`, `sack.rs`, `ecn.rs`, and `edge_cases.rs` to understand what's already tested.

- [ ] **Step 3: Write tests for uncovered established paths**

Add tests using the existing harness (`establish_connection`, `build_tcp_frame_with_payload`, etc.). Target:
- OOO segment handling: send seq 200 before seq 100, verify reordering
- FIN processing: send FIN segment to established connection, verify transition to CloseWait
- Duplicate ACK detection: send same ACK 3 times, verify fast retransmit trigger
- Window update: send ACK with larger window, verify `snd_wnd` update

- [ ] **Step 4: Run tests**

Run: `cargo test handler::tcp::tests`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/inbound): add established state coverage for OOO, FIN, dupACK, window updates"
```

---

### Task 11: `tcp/inbound/teardown.rs` — state transitions

**Files:**
- Modify: `src/net/handler/tcp/tests/teardown.rs`
- Reference: `src/net/handler/tcp/inbound/teardown.rs`
- Reference: `src/net/handler/tcp/tests/mod.rs`

- [ ] **Step 1: Read existing teardown tests**

Read `src/net/handler/tcp/tests/teardown.rs` to understand what transitions are already covered.

- [ ] **Step 2: Read the uncovered paths in teardown.rs**

Read `src/net/handler/tcp/inbound/teardown.rs` focusing on FinWait1→FinWait2, FinWait1→Closing (simultaneous close), FinWait2→TimeWait, CloseWait→LastAck, Closing→TimeWait, LastAck→Closed, TimeWait FIN retransmit.

- [ ] **Step 3: Write tests for uncovered teardown transitions**

Add tests for each uncovered state transition using `establish_connection` + triggering close + sending appropriate segments. Target:
- FinWait1 receives ACK of FIN → FinWait2
- FinWait1 receives FIN (no ACK of our FIN) → Closing (simultaneous close)
- FinWait2 receives FIN → TimeWait
- CloseWait: local close → LastAck
- LastAck receives ACK → connection removed
- TimeWait receives duplicate FIN → re-ACK, restart timer

- [ ] **Step 4: Run tests**

Run: `cargo test handler::tcp::tests::teardown`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/tcp/tests/teardown.rs
git commit -m "test(tcp/teardown): add coverage for all teardown state transitions"
```

---

### Task 12: `tcp/inbound/syn_received.rs` — handshake completion

**Files:**
- Modify: `src/net/handler/tcp/tests/handshake.rs`
- Reference: `src/net/handler/tcp/inbound/syn_received.rs`

- [ ] **Step 1: Read existing handshake tests and syn_received.rs**

Identify which paths in `process_syn_received` are already tested by the 3-way handshake helpers.

- [ ] **Step 2: Write tests for uncovered syn_received paths**

Target:
- Bad sequence number → challenge ACK
- RST in SYN_RECEIVED (passive open → back to LISTEN)
- RST in SYN_RECEIVED (active open → ConnectionRefused)
- SYN retransmit in SYN_RECEIVED → re-send SYN-ACK
- Window scale negotiation (peer offers different scale)

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::tests::handshake`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/handshake.rs
git commit -m "test(tcp/handshake): add syn_received coverage for RST, bad seq, window scale"
```

---

### Task 13: `tcp/timers.rs` — timer logic

**Files:**
- Modify: `src/net/handler/tcp/tests/delayed_ack.rs` and/or `keepalive.rs` and/or `retransmission.rs`
- Reference: `src/net/handler/tcp/timers.rs`

- [ ] **Step 1: Read timers.rs and existing timer tests**

Identify which timer paths are already covered by delayed_ack.rs, keepalive.rs, and retransmission.rs.

- [ ] **Step 2: Write tests for uncovered timer logic**

Target:
- Delayed ACK expiry and flush
- Keep-alive probe threshold exceeded → connection removal
- RTO backoff: verify exponential backoff on successive retransmissions
- R2 threshold: verify connection aborted after max retransmissions
- FIN retransmit in FinWait1/Closing/LastAck states

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::tests`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/timers): add coverage for delayed ACK, keepalive max, RTO backoff"
```

---

### Task 14: `tcp/segment.rs` — RST, SYN, SYN-ACK builders

**Files:**
- Modify: `src/net/handler/tcp/segment.rs` (extend existing test module at line 912)

- [ ] **Step 1: Read segment.rs test module and uncovered builders**

Focus on `build_rst` (lines 31-97), `build_syn` (101-181), `build_syn_ack` (185-267), and `build_ack` (275-340).

- [ ] **Step 2: Write tests for uncovered segment builders**

Append to the existing `mod tests` block. Use the existing test patterns (frame allocation from test buffer). Target:
- `build_rst`: RST with ACK flag, RST without ACK flag
- `build_syn`: SYN with all options (MSS, window scale, timestamps, SACK-permitted, ECN)
- `build_syn_ack`: SYN-ACK with and without window scale
- `build_ack`: pure ACK with timestamps

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::segment`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/segment.rs
git commit -m "test(tcp/segment): add coverage for RST, SYN, SYN-ACK, ACK builders"
```

---

### Task 15: `handler/udp.rs` — multi-fragment checksum

**Files:**
- Modify: `src/net/handler/udp.rs` (extend existing test module at line 505)

- [ ] **Step 1: Read the multi-fragment checksum paths**

Read `src/net/handler/udp.rs` focusing on lines 234-270 (IPv4 multi-fragment) and 393-428 (IPv6 multi-fragment).

- [ ] **Step 2: Write tests for multi-fragment checksum verification**

Append to the existing `mod tests` block. Target:
- IPv4 multi-frame packet with valid checksum
- IPv4 multi-frame packet with invalid checksum → drop
- IPv6 multi-frame packet with valid checksum
- IPv6 multi-frame packet with zero checksum → reject (RFC 2460)

- [ ] **Step 3: Run tests**

Run: `cargo test handler::udp`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/udp.rs
git commit -m "test(udp): add multi-fragment checksum verification tests"
```

---

### Task 16: Phase 2 verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Measure coverage improvement**

Run: `cargo llvm-cov --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); t=d['data'][0]['totals']['lines']; print(f\"Coverage: {t['percent']:.1f}% ({t['covered']}/{t['count']})\")"`
Expected: Significant improvement over Phase 1 measurement

---

## Chunk 3: Phase 3 — Moderate Impact Partially Testable

### Task 17: `tcp/state.rs` — is_synchronized and is_remote_closed

**Files:**
- Modify: `src/net/handler/tcp/state.rs`

- [ ] **Step 1: Write exhaustive tests for both methods**

Add a `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_synchronized() {
        let synchronized = [
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::CloseWait,
            TcpState::Closing,
            TcpState::LastAck,
            TcpState::TimeWait,
        ];
        let not_synchronized = [
            TcpState::Closed,
            TcpState::Listen,
            TcpState::SynSent,
            TcpState::SynReceived,
        ];
        for state in synchronized {
            assert!(state.is_synchronized(), "{:?} should be synchronized", state);
        }
        for state in not_synchronized {
            assert!(!state.is_synchronized(), "{:?} should not be synchronized", state);
        }
    }

    #[test]
    fn is_remote_closed() {
        let remote_closed = [
            TcpState::CloseWait,
            TcpState::LastAck,
            TcpState::TimeWait,
            TcpState::Closing,
            TcpState::Closed,
        ];
        let not_remote_closed = [
            TcpState::Listen,
            TcpState::SynSent,
            TcpState::SynReceived,
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::FinWait2,
        ];
        for state in remote_closed {
            assert!(state.is_remote_closed(), "{:?} should be remote_closed", state);
        }
        for state in not_remote_closed {
            assert!(!state.is_remote_closed(), "{:?} should not be remote_closed", state);
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test handler::tcp::state`
Expected: 2 tests pass

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/tcp/state.rs
git commit -m "test(tcp/state): add exhaustive is_synchronized and is_remote_closed tests"
```

---

### Task 18: `tcp/inbound/validate.rs` — segment validation

**Files:**
- Modify: `src/net/handler/tcp/tests/mod.rs` or create `src/net/handler/tcp/tests/validate.rs`
- Reference: `src/net/handler/tcp/inbound/validate.rs`

- [ ] **Step 1: Read validate.rs to understand uncovered paths**

Focus on: frame too short, invalid data offset, checksum verification when `!rx_offload`, TCP options extraction.

- [ ] **Step 2: Write validation tests**

Target:
- Frame too short for TCP header → drop
- Invalid data offset → drop
- Checksum failure when rx_offload is disabled
- Valid segment with TCP options (timestamps, MSS)

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::tests`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/validate): add segment validation edge case tests"
```

---

### Task 19: `tcp/inbound/syn_sent.rs` — option negotiation

**Files:**
- Modify: `src/net/handler/tcp/tests/handshake.rs`
- Reference: `src/net/handler/tcp/inbound/syn_sent.rs`

- [ ] **Step 1: Read syn_sent.rs for uncovered option paths**

Focus on: peer missing timestamps, peer missing SACK, peer missing ECN, simultaneous open, unacceptable ACK.

- [ ] **Step 2: Write tests for option negotiation fallbacks**

Target:
- SYN-ACK without timestamp option → timestamps disabled
- SYN-ACK without SACK-permitted → SACK disabled
- SYN-ACK without ECN → ECN disabled
- Unacceptable ACK (seq out of range) → RST
- Simultaneous open (SYN without ACK) → SYN_RECEIVED

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::tests::handshake`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/handshake.rs
git commit -m "test(tcp/syn_sent): add option negotiation and simultaneous open tests"
```

---

### Task 20: `tcp/listener.rs` — listen/unlisten

**Files:**
- Modify: `src/net/handler/tcp/tests/handshake.rs` or create new test
- Reference: `src/net/handler/tcp/listener.rs`

- [ ] **Step 1: Read listener.rs for uncovered paths**

Focus on: duplicate listener check, `unlisten()` cleanup, SYN-RECEIVED connection cleanup during unlisten.

- [ ] **Step 2: Write listener management tests**

Target:
- Listen on same port twice → error
- Unlisten removes listener
- Unlisten cleans up SYN-RECEIVED connections

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::tests`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/listener): add listen/unlisten lifecycle tests"
```

---

### Task 21: `tcp/handler.rs` — connection management

**Files:**
- Modify: `src/net/handler/tcp/tests/edge_cases.rs` or relevant test file
- Reference: `src/net/handler/tcp/handler.rs`

- [ ] **Step 1: Read handler.rs for uncovered methods**

Focus on: `remove_connection()` RST generation, connection not found case, connection lookup methods.

- [ ] **Step 2: Write connection management tests**

Target:
- Insert and retrieve connection
- Remove connection generates RST when appropriate
- Remove non-existent connection (not found case)

- [ ] **Step 3: Run tests**

Run: `cargo test handler::tcp::tests`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp/handler): add connection insert/remove/lookup tests"
```

---

### Task 22: `wire/ip/traits.rs` — IP version trait methods

**Files:**
- Modify: `src/net/wire/ip/traits.rs`

- [ ] **Step 1: Read traits.rs to understand the trait methods**

Focus on `write_ip_header`, `get_ecn_bits`, `set_ecn_ect`, `pseudo_header_sum` for both IPv4 and IPv6.

- [ ] **Step 2: Write tests for IP version trait implementations**

Add a `#[cfg(test)]` module. Tests should allocate byte buffers, call the trait methods, and verify the written headers. Target:
- IPv4 `write_ip_header`: verify version, IHL, total length, TTL, protocol fields
- IPv6 `write_ip_header`: verify version, payload length, next header, hop limit
- `get_ecn_bits` / `set_ecn_ect` for both versions: set ECT(0), verify bits
- `pseudo_header_sum` for both versions: verify checksum contribution

- [ ] **Step 3: Run tests**

Run: `cargo test wire::ip::traits`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/wire/ip/traits.rs
git commit -m "test(wire/ip): add IpVersion trait implementation tests for v4 and v6"
```

---

### Task 23: `socket/tcp.rs` — accessors

**Files:**
- Modify: `src/net/socket/tcp.rs`
- Reference: existing `from_accepted_for_test()` helper

- [ ] **Step 1: Read socket/tcp.rs test helpers and accessor methods**

Understand what `from_accepted_for_test` constructs and which accessors can be called on it.

- [ ] **Step 2: Write accessor tests**

Extend the test module using `from_accepted_for_test`. Target:
- `nodelay()` default value
- `set_nodelay(true)` then `nodelay()` returns true
- `linger()` default value
- `set_linger(Some(Duration))` then `linger()` returns it
- `local_addr()` and `peer_addr()` return expected values
- `set_keepalive` / `keepalive` round-trip

- [ ] **Step 3: Run tests**

Run: `cargo test socket::tcp`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/socket/tcp.rs
git commit -m "test(socket/tcp): add accessor and setter round-trip tests"
```

---

### Task 24: `socket/udp.rs` — lifecycle and accessors

**Files:**
- Modify: `src/net/socket/udp.rs`
- Reference: existing `with_test_context()` helper

- [ ] **Step 1: Read socket/udp.rs test helpers and uncovered paths**

Understand what `with_test_context` provides and what accessors/lifecycle methods lack coverage.

- [ ] **Step 2: Write lifecycle and accessor tests**

Extend the existing test module. Target:
- Local address accessor after bind
- Port accessor after bind
- Close lifecycle: bind → close → verify unbound
- Extend existing tests with additional assertions

- [ ] **Step 3: Run tests**

Run: `cargo test socket::udp`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/socket/udp.rs
git commit -m "test(socket/udp): add accessor and close lifecycle tests"
```

---

### Task 25: Phase 3 and final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Measure final coverage**

Run: `cargo llvm-cov --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); t=d['data'][0]['totals']['lines']; print(f\"Coverage: {t['percent']:.1f}% ({t['covered']}/{t['count']})\")"`
Expected: ~89-91% coverage (up from 83.8% baseline)

- [ ] **Step 3: Final commit if any cleanup needed**
