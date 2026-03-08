# TCP Handler Refactor Design

## Problem

`src/net/handler/tcp/mod.rs` is 11,300 lines (3,098 implementation + 8,202 tests). It contains the `TcpHandler` struct, listener management, active open, all state machine handlers, timer polling, transmit path, and 70+ tests. Every other `mod.rs` in the handler layer is a pure export shim. The supporting files (`tcb.rs`, `state.rs`, `congestion.rs`, `recovery.rs`, `ring_buffer.rs`, `isn.rs`, `segment.rs`) are already well-factored.

## Design

### File Structure

```
src/net/handler/tcp/
  mod.rs              # Pure export shim (~15 lines)
  handler.rs          # TcpHandler struct + new() + lookup helpers + evict_stale
  listener.rs         # ListenEntry struct + listen/unlisten/find_listener
  connection.rs       # connect/connect_with_config + initiate_close
  inbound.rs          # process_ipv4/v6, process_segment, per-state handlers
  timers.rs           # poll_timers (delayed ACK, keep-alive, RTO, persist, SACK)
  transmit.rs         # poll_send (data segmentation, congestion window, Nagle)
  tcb.rs              # unchanged
  state.rs            # unchanged
  congestion.rs       # unchanged
  recovery.rs         # unchanged
  ring_buffer.rs      # unchanged
  isn.rs              # unchanged
  segment.rs          # unchanged
  tests/
    mod.rs            # Shared test helpers + mod declarations
    handshake.rs      # 3-way handshake, window scale, backlog (~12 tests)
    data_transfer.rs  # In-order, out-of-order delivery (~2 tests)
    retransmission.rs # RTO, fast retransmit, RTT estimation (~5 tests)
    teardown.rs       # FIN, TIME_WAIT, simultaneous close (~12 tests)
    delayed_ack.rs    # Deferral, flushing, timer (~6 tests)
    nagle.rs          # Small segments, TCP_NODELAY (~5 tests)
    keepalive.rs      # Idle probes, exhaustion, linger (~11 tests)
    timestamps.rs     # Timestamp negotiation, PAWS (~7 tests)
    persist.rs        # Zero-window probing (~4 tests)
    sack.rs           # SACK recovery, scoreboard (~9 tests)
    ecn.rs            # ECN negotiation, CE, CWR (~11 tests)
    edge_cases.rs     # RST validation, challenge ACK, SWS (~10 tests)
    congestion.rs     # CUBIC slow start, F-RTO, limited transmit (~3 tests)
```

### Module Responsibilities

**`mod.rs`** — `mod` declarations and `pub use` re-exports only.

**`handler.rs`** (~80 lines) — `TcpHandler` struct definition with `pub(super)` fields (connections, listeners, isn_generator, rx/tx_offload). Constructor, `get_connection()`, `get_connection_mut()`, `remove_connection()`, `evict_stale()`.

**`listener.rs`** (~120 lines) — `ListenEntry` struct. `impl TcpHandler` block: `listen()`, `listen_with_config()`, `unlisten()`, `find_listener()`, `push_to_accept_queue()`, `decrement_syn_received()`.

**`connection.rs`** (~150 lines) — `impl TcpHandler` block: `connect()`, `connect_with_config()`, `initiate_close()`.

**`inbound.rs`** (~1,600 lines) — `is_segment_acceptable()` free function. `impl TcpHandler` block: `process_ipv4()`, `process_ipv6()`, `process_ipv4_with_now()`, `process_ipv6_with_now()`, `process_segment()`, `process_listen()`, `process_syn_sent()`, `process_syn_received()`, `process_established()`, `process_teardown()`.

**`timers.rs`** (~380 lines) — `impl TcpHandler` block: `poll_timers()`.

**`transmit.rs`** (~300 lines) — `impl TcpHandler` block: `poll_send()`.

### Key Pattern

`handler.rs` owns the struct with `pub(super)` fields. Sibling files extend it with `impl TcpHandler` blocks. No circular dependencies.

### Test Organization

`tests/mod.rs` contains shared helpers (creating handlers, building frames, extracting headers). Each category file uses `use super::*` for helpers. Tests move as-is with no rewriting.

### Migration Strategy

Purely mechanical — no behavior or API changes. Each step is a standalone commit that compiles and passes tests:

1. Extract `listener.rs` (ListenEntry + listener methods)
2. Extract `connection.rs` (connect + close methods)
3. Extract `transmit.rs` (poll_send)
4. Extract `timers.rs` (poll_timers + evict_stale)
5. Extract `handler.rs` (TcpHandler struct + new() + lookup helpers)
6. Extract `inbound.rs` (remaining process_* + state handlers)
7. Reduce `mod.rs` to pure export shim
8. Extract tests into `tests/` (one category at a time)
9. Verify `cargo test` passes after each step
