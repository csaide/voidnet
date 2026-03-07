# TCP Protocol Correctness, ECN, and Socket API Design

**Goal:** Improve RFC compliance (PSH flag, ECN, simultaneous open), add IPv6 fragment visibility, and surface TCP events as errors in the socket API.

**Architecture:** Five independent features that can be implemented in any order. PSH and simultaneous open are small correctness fixes. ECN is the largest piece (negotiation + send/receive + congestion response). IPv6 fragment visibility is a logging change. Socket API error surfacing connects the existing event_queue to read/write futures.

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure.

---

## 1. PSH Flag on Outgoing Segments

### Problem

PSH flag is never set on outgoing data segments. Peers that buffer received data until PSH may experience unnecessary latency.

### Design

Set `PSH | ACK` (instead of just `ACK`) on the last data segment in a burst from `poll_send`. "Last in burst" means: after sending this segment, either the send buffer has no more data beyond what's in flight, or the send window is exhausted.

**Detection in poll_send:** After computing `to_send`, check if `bytes_in_flight + to_send >= send_buffer.available()` or `to_send >= can_send` (window exhausted). If either is true, this is the last segment — set PSH.

**Implementation:** `build_data_from_slices` currently hardcodes `flags::ACK`. Add a `tcp_flags: u8` parameter (or a `psh: bool` that gets OR'd). Callers in `poll_send` pass `flags::ACK | flags::PSH` when appropriate, `flags::ACK` otherwise. Retransmit paths (fast retransmit, RTO) don't set PSH — they're resending, not originating.

---

## 2. IPv6 Fragment Visibility

### Problem

`src/net/handler/ipv6.rs` silently drops fragmented IPv6 TCP segments with a comment. This makes debugging MTU issues impossible.

### Design

Replace the silent drop with:
1. Increment an atomic counter (`ipv6_fragments_dropped: AtomicU64`) on the handler
2. Log at debug level on first occurrence (avoid log spam)
3. Do NOT implement full reassembly — PMTU discovery should prevent fragmentation in practice

**Optional:** If we have the peer's PMTU cached, we could send ICMPv6 Packet Too Big. But this is complex (need to construct ICMPv6) and the peer should already be doing PMTU discovery. Skip for now — just make it visible.

**Where:** Add counter field to `Ipv6Handler`, increment on fragment drop, expose via a getter.

---

## 3. ECN (RFC 3168)

### Negotiation (in SYN/SYN-ACK)

**Active open (connect):** Set ECE + CWR flags in SYN segment to indicate ECN capability.

**Passive open (listen):** When incoming SYN has ECE + CWR, set ECE flag (only) in SYN-ACK to confirm ECN support.

**Completion:** After handshake, set `tcb.ecn_enabled = true` if both sides agreed. If peer's SYN-ACK lacks ECE, disable.

**New TcpConfig field:** `ecn: bool` (default `true`). Controls whether we offer ECN in SYN.

### Sending (IP header ECT codepoint)

When `ecn_enabled`, set ECT(0) codepoint (`0b10`) in IPv4 ToS / IPv6 Traffic Class field on all outgoing data segments. Do NOT set on pure ACKs or retransmissions (RFC 3168 says retransmits should not be ECT-marked).

**Where:** `build_ipv4_data_segment_slices` / `build_ipv6_data_segment_slices` — add `ecn_ect: bool` parameter. When true, set the 2 ECN bits in the IP header to `10` (ECT(0)).

### Receiving CE (Congestion Experienced)

When an incoming data segment has CE codepoint (`0b11`) in IP header:
1. Set `tcb.ecn_ce_received = true`
2. On next outgoing ACK/data, set ECE flag

Continue sending ECE on every ACK until sender acknowledges with CWR.

**Where:** `process_established` — after parsing IP header, check ECN bits. If CE, set flag. In segment builder calls, pass ECE flag when `ecn_ce_received`.

### Receiving ECE (from peer)

When we receive an ACK with ECE flag set:
1. Halve cwnd (same as loss response): `ssthresh = cwnd / 2; cwnd = ssthresh`
2. Set CWR flag on next outgoing data segment
3. Set `ecn_cwr_sent = true` to avoid reacting multiple times per RTT
4. Reset `ecn_cwr_sent` when new data is ACKed (new RTT)

**Where:** `process_established` ACK processing — check ECE flag. `poll_send` — set CWR on next data if needed.

### Receiving CWR (from peer)

When we receive a segment with CWR flag:
1. Clear `ecn_ce_received` — stop sending ECE

**Where:** `process_established` — check CWR flag before data processing.

### New TCB Fields

- `ecn_enabled: bool` — negotiated during handshake
- `ecn_ce_received: bool` — CE mark seen, send ECE until CWR received
- `ecn_cwr_sent: bool` — we sent CWR, don't react to ECE again this RTT

### New TcpConfig Field

- `ecn: bool` (default `true`)

---

## 4. Socket API — Errors from read/write

### Problem

`TcpEvent` variants (Reset, Timeout) are pushed to `event_queue` on the TCB but the socket layer never reads them. `read()` returns 0 for both EOF and error conditions.

### Design

**Change return types:**
- `TcpStream::read()` → returns `Result<usize, TcpError>` instead of `usize`
- `TcpStream::write()` → returns `Result<usize, TcpError>` instead of `usize`

**Event mapping:**
- `TcpEvent::Reset` → `Err(TcpError::Reset)`
- `TcpEvent::Timeout` → `Err(TcpError::Timeout)`
- `TcpEvent::RemoteClose` → `Ok(0)` on read (EOF), `Err(TcpError::NotConnected)` on write
- `TcpEvent::ConnectionRefused` → Already handled by connect future

**Implementation in TcpRead/TcpWrite futures:**
Before checking the recv/send buffer, poll the event_queue. If an error event is present, return immediately with the corresponding error.

**TcpError** already exists in `tcb.rs`:
```rust
pub enum TcpError {
    ConnectionRefused,
    Timeout,
    Reset,
    NotConnected,
}
```

**Impact on examples:** `tcp-echo-server.rs` and `tcp-echo-client.rs` call `.await` on read/write which return `usize`. They'll need to handle `Result<usize, TcpError>`. Update to use `.await?` or `.await.unwrap()`.

---

## 5. Simultaneous Open Verification

### Problem

Simultaneous open (both sides send SYN before receiving peer's SYN) is a rare but RFC-required scenario. The handler has code for it in `process_syn_sent` (transitions to SynReceived on bare SYN), but it's never been tested.

### Design

**Verify existing code:** Read `process_syn_sent` and trace the SYN → SynReceived → Established path when both sides are in SynSent.

**Add integration test:** Two connections in SynSent, each receives the other's SYN. Verify both reach Established.

**Fix if needed:** If the code path has bugs, fix them. If it works, just add the test.

**Where:** `mod.rs` process_syn_sent (existing code), new test.

---

## Scope

**Modified files:**
- `src/net/handler/tcp/mod.rs` — PSH in poll_send, ECN in handshake/established, simultaneous open test
- `src/net/handler/tcp/tcb.rs` — ECN fields, TcpConfig ecn field
- `src/net/handler/tcp/segment.rs` — flags parameter for build_data_from_slices, ECT in IP header
- `src/net/socket/tcp.rs` — read/write return Result, event consumption
- `src/net/handler/ipv6.rs` — fragment drop counter
- `examples/tcp-echo-server.rs` — handle Result from read/write
- `examples/tcp-echo-client.rs` — handle Result from read/write

**No new files.**
