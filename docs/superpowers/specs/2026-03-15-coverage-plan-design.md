# Unit Test Coverage Improvement Plan

## Context

VoidNet currently has 932 tests with 88.5% line coverage across 21K instrumented source lines (excluding test code and generated code). Several modules have significant gaps, ranging from 0% to ~50% coverage. This plan addresses all gaps through four phases ordered by testability, excluding `rt/local.rs` and `rt/affinity.rs` (which need integration tests).

Note: The `xdp/futures/` subtree (~2,400 lines across local/smol/tokio adapters) is excluded from this plan as it consists of thin runtime adapter layers best covered by integration tests.

## Approach

**Phased by testability**: pure unit tests first, then stateful handler tests, then async/future tests, then integration-adjacent tests. This avoids blocking on infrastructure and delivers steady coverage gains.

## Current State

| Coverage Band | Files |
|---------------|-------|
| 0% | `rt/local.rs` (excluded), `rt/affinity.rs` (excluded), `net/http/listener.rs` |
| <50% | `net/http/response.rs` (34%), `net/socket/tcp.rs` (45%), `xdp/frame/shared.rs` (23%), `rt/task.rs` (12%) |
| 50-80% | `net/socket/udp.rs` (53%), `net/http/body.rs` (70%), `net/http/connection.rs` (77%), `net/checksum/common.rs` (75%), `net/fragment/transport.rs` (79%), `net/handler/tcp/inbound/teardown.rs` (79%), `xdp/program/map.rs` (57%), `netlink/ethtool.rs` (78%), `netlink/ifinfo.rs` (70%), `rt/context.rs` (74%) |
| 80-90% | `net/handler/tcp/inbound/established.rs` (84%), `net/handler/tcp/segment.rs` (88%), `net/handler/tcp/transmit.rs` (91%), `net/handler/tcp/tcb.rs` (91%), `net/neighbor/handler.rs` (89%), `rt/waker.rs` (86%), `xdp/program/prog.rs` (80%), `xdp/socket/rx.rs` (78%), `xdp/socket/tx.rs` (73%), `net/handler/tcp/inbound/listen.rs` (89%) |
| 90-100% (no action) | `net/handler/tcp/recovery.rs` (99%), `net/handler/tcp/congestion.rs` (98%), `net/handler/tcp/ring_buffer.rs` (99%), `net/handler/tcp/connection.rs` (98%), `net/handler/tcp/send_tracker.rs` (100%), `net/handler/tcp/inbound/validate.rs` (100%), `net/handler/tcp/inbound/syn_received.rs` (99%), `net/http/session.rs` (98%), `net/http/request.rs` (100%), `net/http/buffer.rs` (94%), `net/http/codec/parse.rs` (97%), `net/http/error.rs` (97%), `net/handler/ethernet.rs` (100%), `net/handler/icmpv4.rs` (100%), `net/handler/icmpv6.rs` (98%), `net/neighbor/arp.rs` (100%), `net/neighbor/ndp.rs` (98%), `net/fragment/reader.rs` (98%), `net/fragment/writer.rs` (98%), `net/fragment/plan.rs` (100%), `net/fragment/id.rs` (100%), `net/checksum/compute.rs` (100%), `net/checksum/verify.rs` (100%), `net/wire/ethernet.rs` (100%), `net/wire/udp.rs` (100%), `net/wire/ip/addr.rs` (100%), `net/wire/ip/proto.rs` (100%), `net/wire/ip/traits.rs` (100%) |

---

## Phase 1: Pure Unit Tests

No async runtime, no mocking infrastructure. Straightforward struct/function-level tests added to existing inline `#[cfg(test)]` modules.

### Files and Tests

#### `net/fragment/transport.rs` (79% -> 100%)
- `TcpHeader::protocol()` returns `IpProtocols::Tcp`
- `TcpHeader::header_len()` returns `TCP_HEADER_LEN`
- `TcpHeader::write_to()` serialization roundtrip

#### `net/fragment/pkt.rs` (87% -> 95%+)
- `drain_to()` method
- Empty packet edge cases (`is_empty()`, `num_frames()` on Empty variant)
- `From<T>` with len==0 producing Empty
- `size_hint()` boundary conditions

#### `net/handler/tcp/segment.rs` (88% -> 95%+)
- IPv6 variants of `build_rst`, `build_syn`, `build_syn_ack`, `build_ack`, `build_ack_with_sack`, `build_fin_ack`, `build_data`, `build_data_from_slices`
- Mixed v4/v6 address fallthrough (no-op behavior)

#### `net/handler/tcp/tcb.rs` (91% -> 97%+)
- `update_send_window` return value when window transitions 0 -> non-zero

#### `net/pmtu.rs` (91% -> 98%+)
- `with_mtu()` constructor
- `Default` trait implementation
- Mixed v4/v6 addresses in same cache during eviction

#### `net/neighbor/handler.rs` (89% -> 94%+)
- `set_offload()` setter
- `set_local_mac()` setter
- `add_local_ipv6()` deduplication logic
- `lookup_v4()` and `lookup_v6()` convenience wrappers

#### `net/wire/ndp.rs` (83% -> 95%+)
- Untested Display/accessor methods

#### `net/wire/arp.rs` (83% -> 95%+)
- Untested Display/accessor methods

#### `net/wire/tcp.rs` (92% -> 96%+)
- Remaining option parse edge cases

#### `net/checksum/common.rs` (75% -> 90%+)
- ARM NEON vs generic fallback paths (the `neon.rs` SIMD path at 91% has minor gaps too)
- `sum_words_carry` with payloads that exercise carry propagation edge cases
- `fold_checksum` with values near u16::MAX boundary

#### `xdp/frame/shared.rs` (23% -> 90%+)
- `drain()` method
- `Clone` implementation (Rc semantics)
- `From<BasicFrameBuffer>` conversion
- All `FrameBuffer` trait methods: `free_space()`, `num_frames()`, `push()`, `pop()`, `take_frames()`, `iter_frames()`, `iter_frames_mut()`

#### `xdp/program/map.rs` (57% -> 80%+)
- `name()` getter
- Pointer accessors (`as_mut_ptr()`, `as_ptr()`)
- Platform-specific name conversion (aarch64 vs x86_64)
- Note: FFI calls like `update_elem` will stay untested

#### `rt/waker.rs` (86% -> 95%+)
- `wake_main()` consume-and-drop path
- `wake_main_by_ref()` with `mem::forget`
- `drop_main_waker()` drop behavior
- `noop_raw_waker()` and `task_queue_waker()` constructors

**Estimated: ~60-70 tests**

---

## Phase 2: Stateful TCP Handler Tests

Uses existing test harness patterns in `net/handler/tcp/tests/`. Tests exercise state machine transitions and protocol edge cases.

### Files and Tests

#### `net/handler/tcp/inbound/teardown.rs` (79% -> 93%+)
- RST challenge ACK per RFC 5961 (in-window but seq != rcv_nxt)
- FinWait1 partial state: neither FIN ACKed nor received, just process data/ACK
- FinWait2 data reception before remote FIN (ACK but no state change)
- Closing partial ACK stays in Closing (ACK doesn't cover fin_seq)
- LastAck partial ACK persists connection
- TimeWait FIN retransmit restarts deadline
- CloseWait WL1/WL2 window update guard condition
- PAWS staleness edge case (very old ts_recent_age)

#### `net/handler/tcp/inbound/established.rs` (84% -> 93%+)
- RST challenge ACK (seq != rcv_nxt sends challenge ACK)
- Fast-path fallthrough: PAWS failure, recv_buffer full, missing timestamp
- Out-of-order SACK block selection with multiple disjoint ranges (max 3/4 blocks)
- ACK for unsent data (seg_ack > snd_nxt)
- Duplicate data reception (seg_seq < rcv_nxt)
- Out-of-order FIN held until data complete

#### `net/handler/tcp/transmit.rs` (91% -> 96%+)
- Limited transmit (RFC 3042) cwnd inflation on 1st/2nd dup ACK
- SWS avoidance with small windows (max_snd_wnd < 2*MSS)
- Neighbor resolution pending breaks transmit loop
- Persist timer backoff cap at 6 (max interval = RTO * 64)
- Linger deadline expiry sends RST
- FIN state transitions: Established->FinWait1, CloseWait->LastAck

#### `net/handler/tcp/timers.rs` (96% -> 98%+)
- Delayed ACK neighbor pending re-marks for poll_send
- Keep-alive with ECN flag (ECE on probes)
- RTO fires with empty send buffer (no retransmit sent)
- ECN disabled on retransmit per RFC 3168

#### `net/handler/tcp/inbound/syn_sent.rs` (95% -> 98%+)
- Remaining SYN-SENT state edge cases

#### `net/handler/tcp/inbound/listen.rs` (89% -> 95%+)
- Passive open handling edge cases

**Estimated: ~35-45 tests**

---

## Phase 3: Async/Future Tests

Tests `poll()` implementations on socket futures and HTTP async methods.

### Infrastructure Needed

**Test waker**: The codebase already has `noop_raw_waker()` in `rt/waker.rs`. Phase 1 tests will cover this function, and Phase 3 tests can reuse it to construct `std::task::Context` for manual future polling.

**Mock TcpStream**: A minimal struct with pre-loaded read/write buffers and configurable poll results (Ready with data, Pending, error). This should:
- Live in a shared test utility module (e.g., `net/http/test_utils.rs` or inline in the test modules that need it)
- Support `read()` returning pre-loaded byte slices in sequence
- Support `write()` capturing written bytes for assertion
- Support configurable `Poll::Pending` returns to test partial-read/write scenarios

**Socket test context**: For `net/socket/tcp.rs` and `udp.rs`, tests need access to the runtime's handler state (TcpHandler/UdpHandler) to simulate poll responses. The existing `net/handler/tcp/tests/` harness already constructs handler state — the socket tests can follow the same pattern.

### Files and Tests

#### `net/socket/tcp.rs` (45% -> 75%+)
- `Connect::poll()` state transitions (pending, connected, error)
- `Accept::poll()` with pending/ready states
- `TcpRead::poll()` read buffering and EOF
- `TcpWrite::poll()` write buffering and errors
- `TcpSplice::poll()` zero-copy transfer
- `close()` and `shutdown()` lifecycle

#### `net/socket/udp.rs` (53% -> 75%+)
- `SendTo::poll()` with v4/v6 paths
- `RecvFrom::poll()` pending/ready transitions
- `RecvStream::poll_next()` Stream trait
- `Echo::poll()` with backpressure
- `discard()` method
- Split socket send/echo/discard operations

#### `net/socket/queue.rs` (93% -> 97%+)
- `LocalQueue::drain()` range-based drain

#### `net/http/response.rs` (34% -> 80%+)
- `set_status()` with custom reason phrases and HTTP/0.9 no-op
- `add_header()` accumulation and HTTP/0.9 no-op
- `write_body()` HEAD request suppression and chunked encoding flow
- `finish()` Content-Length auto-injection and chunked terminator
- `flush_headers()` status line formatting and Transfer-Encoding injection

#### `net/http/body.rs` (70% -> 90%+)
- `read_all()` with limit enforcement
- `read()` with expect_continue=true (lazy 100 Continue send)
- `read_chunked()` stream EOF mid-chunk
- `read_chunk_size()` UTF-8 decode error and parse overflow
- `consume_crlf()` bare `\n` without `\r`

#### `net/http/connection.rs` (77% -> 90%+)
- `next_request()` buffer compaction, EOF detection, session transitions
- `respond()` integration with Request object

#### `net/http/codec/v1_1.rs` (82% -> 93%+)
- Non-chunked Transfer-Encoding fallthrough to Content-Length
- Expect header case sensitivity edge cases

#### `net/http/codec/v1_0.rs` (88% -> 95%+)
- Multi-offset scenarios
- Additional Content-Length edge cases

#### `net/http/codec/v0_9.rs` (92% -> 97%+)
- Paths with query strings and encoded characters

**Estimated: ~50-60 tests**

---

## Phase 4: Integration-Adjacent Tests

Requires real or mock system infrastructure. Some coverage limits are noted.

### Files and Tests

#### `net/http/listener.rs` (0% -> 60%+)
- `local_addr()` and `local_port()` accessors
- `accept()` poll behavior with mock TcpListener
- `serve()` task spawning mechanics
- Note: Full coverage requires integration tests with real runtime

#### `xdp/socket/rx.rs` (78% -> 85%+)
- `fd()` accessor
- WouldBlock error path
- Frame address masking with `XSK_UNALIGNED_BUF_ADDR_MASK`
- Fragment flag handling (`XDP_PKT_CONTD`)

#### `xdp/socket/tx.rs` (73% -> 85%+)
- `fd()` accessor
- `maybe_wake()` errno variants (ENOBUFS, EAGAIN, EBUSY, ENETDOWN)
- Frame descriptor writing loop with fragment flags

#### `xdp/program/prog.rs` (80% -> 85%+)
- Input validation error paths in `new()` (CString failure, nametoindex==0)
- Drop cleanup verification
- Note: FFI error paths beyond input validation are hard to trigger

#### `rt/task.rs` (12% -> 60%+)
- `TaskQueue::new()` constructor
- `TaskQueue::push()` staging buffer insertion
- `TaskQueue::poll()` drain staging into FuturesUnordered and poll
- `JoinHandle::poll()` completion and pending paths
- `spawn()` closure mechanics
- Note: Needs minimal runtime context; test TaskQueue in isolation

#### `rt/context.rs` (74% -> 85%+)
- `ContextDropGuard` creation and drop cleanup
- `with_runtime_context()` panic when called outside runtime
- `register_capacity_waker()` waker registration

**Estimated: ~25-35 tests**

---

## Summary

| Phase | Tests | Coverage Lift | Blocking Dependencies |
|-------|-------|---------------|----------------------|
| Phase 1 | ~60-70 | +3-4% overall | None |
| Phase 2 | ~35-45 | +2-3% overall | Existing TCP test harness |
| Phase 3 | ~50-60 | +3-4% overall | Mock TcpStream, test waker utilities |
| Phase 4 | ~25-35 | +1-2% overall | Runtime context, veth test_utils |
| **Total** | **~170-210** | **88.5% -> 95-97%** | |

## Out of Scope

- `rt/local.rs` — needs integration tests (0% coverage, 251 lines)
- `rt/affinity.rs` — needs integration tests (0% coverage, 5 lines)
- `netlink/ethtool.rs` and `netlink/ifinfo.rs` — FFI/netlink calls cannot be unit tested; coverage gains require either extracting parse logic into pure functions or writing integration tests with real netlink sockets
- `xdp/futures/` subtree — runtime adapter layers (local/smol/tokio) best covered by integration tests

## Testing Conventions

- All tests use plain `cargo test` (no `--features` or `--all-features`)
- Tests require root (configured via `.cargo/config.toml` with `sudo -E`)
- Tests go in inline `#[cfg(test)] mod tests` blocks within each source file
- Follow existing test naming conventions in each module
