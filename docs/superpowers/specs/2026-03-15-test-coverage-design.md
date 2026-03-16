# Test Coverage Improvement Plan

**Date**: 2026-03-15
**Baseline**: 83.8% line coverage (16,378 / 19,535 lines)
**Target**: ~89–91% line coverage (~1,100–1,300 newly covered lines)
**Approach**: Impact-first — prioritize files with the most uncovered lines that are unit-testable in isolation

## Scope

Unit tests only. No integration tests, no kernel/XDP-dependent code, no async I/O paths.

### Excluded (deferred to integration test pass)

- `rt/local.rs` (251 uncovered lines, kernel event loop)
- `xdp/frame/shared.rs` (34 uncovered lines, kernel UMEM wrapper)
- `xdp/program/map.rs` (13 uncovered lines, kernel BPF maps)
- `http/listener.rs` (35 uncovered lines, requires runtime)
- `rt/affinity.rs` (5 uncovered lines, kernel-dependent)
- `rt/task.rs` (44 uncovered lines, runtime-dependent)

### Not in scope (already well-covered, diminishing returns)

- `checksum/common.rs` (46 uncovered lines, 75.1%)
- `wire/tcp.rs` (37 uncovered lines, 92.2%)
- `handler/tcp/transmit.rs` (26 uncovered lines, 90.6%)
- `handler/tcp/tcb.rs` (19 uncovered lines, 90.5%)
- `handler/tcp/inbound/listen.rs` (17 uncovered lines, 89.1%)
- `http/codec/v0_9.rs` (11 uncovered lines, 92.4%)
- `http/codec/parse.rs` (14 uncovered lines, 96.8%)
- `fragment/pkt.rs` (27 uncovered lines, 86.7%)
- `neighbor/handler.rs` (60 uncovered lines, 88.7%)

## Phase 1: Fully Testable Modules (~498 uncovered lines)

### `http/response.rs` (171 uncovered lines, 26.9% coverage)

- `write_hex_usize()`: values 0, small, large, usize::MAX
- Status line formatting for HTTP/0.9, 1.0, 1.1
- Header serialization: Content-Length, Content-Type, custom headers
- Chunked transfer encoding output formatting
- State machine transitions: Idle → Headers → Body → Done
- Error paths: write failures, invalid state transitions

### `http/body.rs` (115 uncovered lines, 59.5% coverage)

- Chunked decoder state machine: chunk size parsing, extensions, trailers
- Content-Length body tracking: exact, short read, overflow
- Frame boundary handling: chunk header split across reads
- EOF detection and error reporting
- Use existing `make_reader_parts()` test helper pattern

### `wire/ip/addr.rs` (80 uncovered lines, 73.4% coverage)

- IPv4 classification: loopback, multicast, broadcast, link-local, unspecified, private
- IPv6 classification: loopback, multicast, link-local, unspecified
- Conversions to/from `std::net::Ipv4Addr` and `std::net::Ipv6Addr`
- Display formatting for both address types
- Equality and ordering

### `http/codec/v1_1.rs` (33 uncovered), `v1_0.rs` (14 uncovered), `mod.rs` (8 uncovered)

- v1.1: chunked Transfer-Encoding detection edge cases, connection keep-alive
- v1.0: Content-Length handling, connection close semantics
- Codec dispatch: version detection for ambiguous inputs, incomplete data handling

### `http/connection.rs` (41 uncovered lines, 45.3% coverage)

- Buffer compaction logic
- Session state transitions
- Request path resolution

### `wire/ethernet.rs` (21 uncovered lines, 75.0% coverage)

- `MacAddress::new()`, `broadcast()`, `zero()` constructors
- Display formatting
- Equality comparisons

### `wire/ip/proto.rs` (8 uncovered lines, 0% coverage)

- Display impl for all protocol variants (TCP, UDP, ICMP, ICMPv6, etc.)

### `xdp/error.rs` (7 uncovered lines, 0% coverage)

- Display impls for all error variants
- Error conversions

## Phase 2: Partially Testable TCP/UDP Internals (~550+ testable lines)

### `tcp/inbound/established.rs` (~150 testable of 214 uncovered, 69.0% coverage)

- ACK processing: advancing `snd_una`, duplicate ACK detection, window updates
- RTT measurement: timestamp-based and non-timestamp SRTT/RVAR calculations
- SACK processing: marking segments, updating scoreboard
- Data reassembly: in-order vs out-of-order segment handling
- Leverage existing test infrastructure in `src/net/handler/tcp/tests/`

### `tcp/inbound/teardown.rs` (~100 testable of 139 uncovered, 53.5% coverage)

- FIN_WAIT_1 → FIN_WAIT_2 transition
- FIN_WAIT_1 → CLOSING transition (simultaneous close)
- FIN_WAIT_2 → TIME_WAIT transition
- CLOSE_WAIT → LAST_ACK transition
- ACK processing during teardown states

### `tcp/inbound/syn_received.rs` (~60 testable of 84 uncovered, 38.2% coverage)

- Window scaling negotiation
- MSS and timestamp option validation
- ACK validation completing the three-way handshake
- RST handling in SYN_RECEIVED state

### `tcp/timers.rs` (~50 testable of 67 uncovered, 79.9% coverage)

- Delayed ACK deadline logic and expiry
- Keep-alive probe thresholds and counting
- RTO backoff calculations
- Timer scheduling and cancellation

### `tcp/segment.rs` (~100 testable of 171 uncovered, 82.1% coverage)

- RST, SYN, ACK, FIN header field construction
- TCP option serialization: MSS, window scale, timestamps, SACK blocks
- Checksum computation on built segments

### `handler/udp.rs` (~80 testable of 127 uncovered, 82.9% coverage)

- Socket bind/unbind registration
- Port conflict and duplicate detection
- Checksum verification logic
- Multicast and broadcast dispatch paths

## Phase 3: Moderate Impact Partially Testable (~200+ testable lines)

### `socket/tcp.rs` (~50 testable of 344 uncovered, 6.8% coverage)

- Accessors: `local_addr()`, `peer_addr()`, `nodelay()`, `linger()`
- State mutations: `set_nodelay()`, `set_linger()`
- Use existing `from_accepted_for_test()` helper

### `socket/udp.rs` (~60 testable of 227 uncovered, 28.2% coverage)

- Bind lifecycle: bind → bound state → close
- Duplicate bind detection
- Extend existing 3 tests with accessor and lifecycle coverage

### `tcp/inbound/syn_sent.rs` (33 uncovered lines, 77.6% coverage)

- Option parsing: MSS extraction, window scale negotiation
- Simultaneous open (SYN+SYN crossing)

### `tcp/inbound/validate.rs` (27 uncovered lines, 77.5% coverage)

- Segment acceptability: zero-length on zero-window, within-window checks
- Boundary conditions on sequence number wrapping

### `tcp/listener.rs` (29 uncovered lines, 67.8% coverage)

- Listener insertion/removal, queue overflow

### `tcp/handler.rs` (27 uncovered lines, 73.3% coverage)

- Connection slab insertion, key lookup, eviction

### `tcp/state.rs` (5 uncovered lines, 37.5% coverage)

- Display/Debug implementations for TCP state enum

### `wire/ip/traits.rs` (19 uncovered lines, 67.8% coverage)

- IPv4/IPv6 trait method implementations
- ECN bit manipulation
- Header field writing

## Test Conventions

**Location**: `#[cfg(test)] mod tests` within each source file. Extend existing test modules where present. Only create separate test files if tests exceed ~300 lines in a module with no existing test block.

**Naming**: `<function_or_behavior>` — e.g., `write_hex_zero`, `fin_wait1_to_fin_wait2`. Follow existing codebase convention (no `test_` prefix).

**Patterns**:
- Reuse existing test helpers (`make_reader_parts()`, `from_accepted_for_test()`, TCP test harness)
- Direct construction and existing builder patterns — no mocking frameworks
- No new dependencies

**Running tests**: `cargo test` (no feature flags, runs as root via `.cargo/config.toml`)

**Verification**: `cargo llvm-cov --json` after each phase to measure improvement.
