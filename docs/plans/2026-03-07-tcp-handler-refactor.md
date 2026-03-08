# TCP Handler Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Decompose the 11,300-line `src/net/handler/tcp/mod.rs` into focused modules with categorized test files.

**Architecture:** `handler.rs` owns the `TcpHandler` struct with `pub(super)` fields. Sibling files (`listener.rs`, `connection.rs`, `inbound.rs`, `timers.rs`, `transmit.rs`) extend it with `impl TcpHandler` blocks. Tests move to a `tests/` subdirectory with one file per category. `mod.rs` becomes a pure export shim.

**Tech Stack:** Rust, no new dependencies. Purely mechanical refactor — no behavior or API changes.

**Reference:** Design doc at `docs/plans/2026-03-07-tcp-handler-refactor-design.md`

---

## Important Notes

- This is a **move-only refactor**. Do not change any logic, rename functions, or alter APIs.
- After each task, run `cargo test` (no feature flags) to verify nothing broke.
- Each task produces one commit.
- Fields on `TcpHandler` need `pub(super)` visibility so sibling `impl` blocks can access them.
- `ListenEntry` fields need `pub(super)` visibility for the same reason.
- Use `use super::*` or specific imports in new files to access sibling module items.
- The `listeners` field type changes from `Vec<ListenEntry>` to `Vec<listener::ListenEntry>` in `handler.rs`.

## Source Line Ranges Reference

Current `mod.rs` structure (11,301 lines total):
- Lines 1-7: Module declarations
- Lines 9-40: Imports and `use` statements
- Lines 42-46: Constants (`INITIAL_RTO_MS`, `SYN_R2_THRESHOLD_MS`)
- Lines 48-68: `ListenEntry` struct
- Lines 70-89: `is_segment_acceptable()` free function
- Lines 91-101: `TcpHandler` struct definition
- Lines 103-112: `TcpHandler::new()`
- Lines 114-176: Listener methods (`listen`, `listen_with_config`, `unlisten`)
- Lines 178-327: Connect methods (`connect`, `connect_with_config`)
- Lines 329-553: IPv4/IPv6 process entry points (`process_ipv4`, `process_ipv4_with_now`, `process_ipv6`, `process_ipv6_with_now`)
- Lines 555-726: `process_segment()` dispatcher
- Lines 728-922: `process_listen()`
- Lines 924-1077: `process_syn_received()`
- Lines 1079-1275: `process_syn_sent()`
- Lines 1277-1874: `process_established()`
- Lines 1876-2257: `poll_timers()`
- Lines 2260-2270: `evict_stale()`
- Lines 2272-2563: `poll_send()`
- Lines 2565-2593: `initiate_close()`
- Lines 2595-2602: `find_listener()`
- Lines 2605-2614: `push_to_accept_queue()`
- Lines 2617-2626: `decrement_syn_received()`
- Lines 2629-2631: `get_connection()`
- Lines 2634-2636: `get_connection_mut()`
- Lines 2639-2669: `remove_connection()`
- Lines 2671-3096: `process_teardown()`
- Lines 3099-3098: `#[cfg(test)]` marker
- Lines 3099-11300: Test module

---

### Task 1: Extract `listener.rs`

**Files:**
- Create: `src/net/handler/tcp/listener.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Create `listener.rs`**

Move the following from `mod.rs` into a new `listener.rs` file:
- `ListenEntry` struct (lines 48-68) — change field visibility from `pub` to `pub(super)`
- `listen()` method (lines 115-126) — as `impl TcpHandler` block
- `listen_with_config()` method (lines 129-163) — same block
- `unlisten()` method (lines 166-176) — same block
- `find_listener()` method (lines 2598-2602) — same block
- `push_to_accept_queue()` method (lines 2605-2614) — same block
- `decrement_syn_received()` method (lines 2617-2626) — same block

The file needs these imports:
```rust
use crate::net::{
    handler::udp::BindError,
    socket::LocalQueue,
    wire::ip::IpAddress,
};
use super::handler::TcpHandler;
use super::state::TcpState;
use super::tcb::{ConnectionId, TcpConfig};
```

Note: `find_listener`, `push_to_accept_queue`, and `decrement_syn_received` are called from `inbound.rs` (process_listen), so they need `pub(super)` visibility.

**Step 2: Update `mod.rs`**

- Add `pub(super) mod listener;` to module declarations
- Remove the moved code (ListenEntry struct, all listener methods)
- Replace internal references to `ListenEntry` with `listener::ListenEntry`
- Update the `TcpHandler` struct's `listeners` field type to `Vec<listener::ListenEntry>`

**Step 3: Verify**

Run: `cargo test`
Expected: All tests pass unchanged.

**Step 4: Commit**

```
refactor(tcp): extract listener.rs from mod.rs
```

---

### Task 2: Extract `connection.rs`

**Files:**
- Create: `src/net/handler/tcp/connection.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Create `connection.rs`**

Move from `mod.rs`:
- `connect()` method (lines 181-203)
- `connect_with_config()` method (lines 206-327)
- `initiate_close()` method (lines 2569-2593)

These go in an `impl TcpHandler` block. Imports needed:
```rust
use coarsetime::Instant;
use crate::{
    net::{
        handler::udp::BindError,
        socket::LocalQueue,
        wire::{ethernet::MacAddress, ip::IpAddress},
    },
    xdp::frame::FrameBuffer,
};
use super::handler::TcpHandler;
use super::isn::IsnGenerator;
use super::ring_buffer::RingBuffer;
use super::segment::SegmentBuilder;
use super::state::TcpState;
use super::tcb::{ConnectionId, Tcb, TcpConfig, TcpEvent};
use super::congestion::CubicState;
```

Note: `connect_with_config` creates a `Tcb`, builds a SYN via `SegmentBuilder`, and pushes to `self.connections`. Check all field accesses and ensure the imports cover every type used.

**Step 2: Update `mod.rs`**

- Add `pub(super) mod connection;` to module declarations
- Remove the moved methods

**Step 3: Verify**

Run: `cargo test`
Expected: All tests pass unchanged.

**Step 4: Commit**

```
refactor(tcp): extract connection.rs from mod.rs
```

---

### Task 3: Extract `transmit.rs`

**Files:**
- Create: `src/net/handler/tcp/transmit.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Create `transmit.rs`**

Move from `mod.rs`:
- `poll_send()` method (lines 2276-2563)

This includes all data segmentation logic, congestion window management, Nagle algorithm, persist timer probing, SACK retransmission, linger/RST handling. It's a single large method.

Imports needed will include: `coarsetime::Instant`, wire types, `FrameBuffer`, `Frame`, `SegmentBuilder`, `TcpState`, `TcpEvent`, `seq_lt`/`seq_le`, recovery types, and congestion types. Copy the exact imports used by `poll_send` from mod.rs.

**Step 2: Update `mod.rs`**

- Add `pub(super) mod transmit;`
- Remove `poll_send` method

**Step 3: Verify**

Run: `cargo test`
Expected: All tests pass unchanged.

**Step 4: Commit**

```
refactor(tcp): extract transmit.rs from mod.rs
```

---

### Task 4: Extract `timers.rs`

**Files:**
- Create: `src/net/handler/tcp/timers.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Create `timers.rs`**

Move from `mod.rs`:
- `poll_timers()` method (lines 1879-2257)
- `evict_stale()` method (lines 2260-2270)

`poll_timers` handles: delayed ACK flushing, keep-alive probes, SACK recovery timers, RTO expiry/retransmission, SYN retransmission, linger deadline, and persist timer. It calls `SegmentBuilder` methods to build ACKs, keep-alive probes, retransmissions, and RSTs.

**Step 2: Update `mod.rs`**

- Add `pub(super) mod timers;`
- Remove `poll_timers` and `evict_stale` methods

**Step 3: Verify**

Run: `cargo test`
Expected: All tests pass unchanged.

**Step 4: Commit**

```
refactor(tcp): extract timers.rs from mod.rs
```

---

### Task 5: Extract `handler.rs`

**Files:**
- Create: `src/net/handler/tcp/handler.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Create `handler.rs`**

Move from `mod.rs`:
- `TcpHandler` struct definition (lines 91-101) — change all fields to `pub(super)`
- `TcpHandler::new()` (lines 103-112)
- `get_connection()` (lines 2629-2631)
- `get_connection_mut()` (lines 2634-2636)
- `remove_connection()` (lines 2639-2669)
- Constants: `INITIAL_RTO_MS` (line 43), `SYN_R2_THRESHOLD_MS` (line 45) — make `pub(super)` so `inbound.rs` and `timers.rs` can use them

The struct fields become:
```rust
pub struct TcpHandler {
    pub(super) connections: Vec<Tcb>,
    pub(super) listeners: Vec<super::listener::ListenEntry>,
    pub(super) isn_generator: IsnGenerator,
    pub(super) rx_offload: bool,
    pub(super) tx_offload: bool,
}
```

**Step 2: Update `mod.rs`**

- Add `pub(super) mod handler;` (or `pub(crate)` if needed by socket layer)
- Add `pub use handler::TcpHandler;` for re-export
- Remove struct definition, `new()`, lookup helpers, constants

**Step 3: Verify**

Run: `cargo test`
Expected: All tests pass unchanged.

**Step 4: Commit**

```
refactor(tcp): extract handler.rs from mod.rs
```

---

### Task 6: Extract `inbound.rs`

**Files:**
- Create: `src/net/handler/tcp/inbound.rs`
- Modify: `src/net/handler/tcp/mod.rs`

**Step 1: Create `inbound.rs`**

Move ALL remaining implementation code from `mod.rs`:
- `is_segment_acceptable()` free function (lines 72-89)
- `process_ipv4()` (lines 332-348)
- `process_ipv4_with_now()` (lines 351-442)
- `process_ipv6()` (lines 445-463)
- `process_ipv6_with_now()` (lines 466-553)
- `process_segment()` (lines 555-726)
- `process_listen()` (lines 728-922)
- `process_syn_received()` (lines 924-1077)
- `process_syn_sent()` (lines 1079-1275)
- `process_established()` (lines 1277-1874)
- `process_teardown()` (lines 2671-3096)

This is the largest extraction (~2,400 lines). It will need the most imports since the state machine handlers touch everything: wire parsing, segment building, congestion control, recovery, TCB fields, timestamps, SACK, ECN.

The state handlers call `self.find_listener()`, `self.push_to_accept_queue()`, `self.decrement_syn_received()` from `listener.rs` — these must be `pub(super)`.

**Step 2: Reduce `mod.rs` to export shim**

After this extraction, `mod.rs` should contain ONLY:
```rust
pub(crate) mod congestion;
mod connection;
mod handler;
mod inbound;
mod isn;
pub(crate) mod listener;
pub(crate) mod recovery;
pub(crate) mod ring_buffer;
pub(crate) mod segment;
pub(crate) mod state;
pub(crate) mod tcb;
mod timers;
mod transmit;

pub use handler::TcpHandler;

#[cfg(test)]
mod tests;
```

Adjust visibility (`pub(crate)` vs `pub(super)` vs private) based on what the socket layer and other modules need to access. Currently `mod.rs` declares `congestion`, `recovery`, `ring_buffer`, `segment`, `state`, `tcb` as `pub(crate)`.

**Step 3: Verify**

Run: `cargo test`
Expected: All tests pass unchanged.

**Step 4: Commit**

```
refactor(tcp): extract inbound.rs, mod.rs is now export shim
```

---

### Task 7: Extract test helpers into `tests/mod.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/mod.rs`
- Modify: `src/net/handler/tcp/mod.rs` (remove `#[cfg(test)] mod tests` block)

**Step 1: Create the tests directory and `tests/mod.rs`**

Move from the current test module (lines 3099-11300):
- All `use` statements from the test module
- Helper functions: `new_handler` (3119-3121), `new_neighbor_handler` (3123-3126), `build_tcp_frame` (3128-3198), `build_tcp_frame_with_payload` (3200-3278), `leak` (3280-3282), `alloc_free_frame` (3284-3286)
- Any other shared helpers like `build_ts_option` (7543-7551) and `establish_connection` (7890-7940) and `establish_connection_with_sack` (8178-8234)
- `mod` declarations for all test category submodules (added in subsequent tasks)

Make helpers `pub(super)` so test submodules can use them.

**Step 2: Start with one test category to validate the structure**

Move the segment acceptability tests (lines 7857-7888, 4 tests) into `tests/mod.rs` temporarily to validate the test infrastructure works.

**Step 3: Verify**

Run: `cargo test`
Expected: The moved tests pass.

**Step 4: Commit**

```
refactor(tcp): create tests/ directory with shared helpers
```

---

### Task 8: Extract `tests/handshake.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/handshake.rs`
- Modify: `src/net/handler/tcp/tests/mod.rs`

**Step 1: Move handshake tests**

Move these tests (passive open handshake):
- `syn_to_listener_generates_syn_ack` (3403)
- `handshake_completes_on_ack` (3441)
- `rst_in_syn_received_removes_connection` (3495)
- `backlog_limits_syn_received` (3546)
- `window_scale_negotiation` (3611)
- `simultaneous_open_both_reach_established` (9826)

And active open handshake:
- `active_open_handshake` (6094)
- `active_open_handshake_with_config` (6152)

**Step 2: Add `mod handshake;` to `tests/mod.rs`**

**Step 3: Verify**

Run: `cargo test handshake`
Expected: All handshake tests pass.

**Step 4: Commit**

```
refactor(tcp): extract handshake tests
```

---

### Task 9: Extract `tests/data_transfer.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/data_transfer.rs`

Move:
- `established_receives_in_order_data` (3651)
- `established_out_of_order_reassembly` (3780)
- `poll_send_builds_data_segment` (3902)
- `frame_accounting_through_data_transfer` (4274)
- `poll_send_sets_psh_on_last_segment` (8846)
- `poll_send_no_psh_on_first_segment_when_more_data` (8883)
- `rcv_nxt_advances_only_by_bytes_written_to_recv_buffer` (10006)

Commit: `refactor(tcp): extract data transfer tests`

---

### Task 10: Extract `tests/retransmission.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/retransmission.rs`

Move:
- `fast_retransmit_on_three_dup_acks` (3978)
- `rto_retransmit_on_timer_expiry` (4081)
- `rtt_estimation_updates_rto` (4167)
- `limited_transmit_sends_on_first_dup_ack` (11197)

Commit: `refactor(tcp): extract retransmission tests`

---

### Task 11: Extract `tests/teardown.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/teardown.rs`

Move:
- `established_receives_fin_transitions_to_close_wait` (4380)
- `established_receives_fin_with_data` (4461)
- `poll_send_sends_fin_when_pending` (4551)
- `poll_send_drains_data_before_fin` (4620)
- `active_close_fin_wait1_to_fin_wait2` (4693)
- `fin_wait2_receives_fin_to_time_wait` (4780)
- `simultaneous_close_closing_to_time_wait` (4889)
- `passive_close_last_ack_removes_connection` (4999)
- `time_wait_ignores_rst` (5111)
- `time_wait_evicted_after_deadline` (5231)
- `full_active_close_lifecycle` (5296)
- `full_passive_close_lifecycle` (5464)
- `shutdown_sets_pending_fin` (6439)
- `half_close_writes_blocked_reads_continue` (7116)
- `close_wait_processes_ack_for_sent_data` (10657)
- `fin_retransmitted_in_fin_wait1` (10438)
- `out_of_order_fin_does_not_transition_to_close_wait` (10121)

Commit: `refactor(tcp): extract teardown tests`

---

### Task 12: Extract `tests/delayed_ack.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/delayed_ack.rs`

Move:
- `delayed_ack_defers_ack_for_in_order_data` (5577)
- `delayed_ack_flushes_on_second_segment` (5666)
- `out_of_order_data_sends_immediate_ack` (5775)
- `fin_sends_immediate_ack` (5859)
- `new_connection_has_delayed_ack_fields` (5939)
- `delayed_ack_timer_flushes_pending_ack` (6006)
- `data_send_clears_delayed_ack` (6334)

Commit: `refactor(tcp): extract delayed ACK tests`

---

### Task 13: Extract `tests/nagle.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/nagle.rs`

Move:
- `nagle_holds_small_data_when_bytes_in_flight` (6209)
- `nagle_allows_full_mss_even_with_bytes_in_flight` (6247)
- `tcp_no_delay_sends_small_data_immediately` (6283)

Commit: `refactor(tcp): extract Nagle tests`

---

### Task 14: Extract `tests/keepalive.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/keepalive.rs`

Move:
- `keep_alive_activity_resets_probe_timer` (6518)
- `keep_alive_probe_sent_after_idle_timeout` (6615)
- `keep_alive_no_probe_when_disabled` (6697)
- `keep_alive_connection_aborted_after_max_probes` (6769)
- `linger_zero_sends_rst_on_poll_send` (6860)
- `linger_timeout_sets_deadline` (6956)
- `linger_none_normal_close` (7040)
- `keep_alive_probe_and_recovery` (7207)
- `keep_alive_exhaustion_removes_connection` (7337)
- `linger_zero_immediate_rst` (7445)

Commit: `refactor(tcp): extract keep-alive and linger tests`

---

### Task 15: Extract `tests/timestamps.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/timestamps.rs`

Move:
- `build_ts_option` helper (7543-7551) — if not already in `tests/mod.rs`
- `paws_rejects_old_timestamp` (7552)
- `paws_drops_rst_with_old_timestamp` (7651)
- `paws_accepts_stale_ts_recent` (7747)

Commit: `refactor(tcp): extract timestamp/PAWS tests`

---

### Task 16: Extract `tests/persist.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/persist.rs`

Move:
- `establish_connection` helper (7890-7940) — if not already in `tests/mod.rs`
- `persist_timer_activates_on_zero_window` (7941)
- `persist_probe_sent_when_deadline_expires` (7972)
- `persist_timer_clears_when_window_reopens` (8013)

Commit: `refactor(tcp): extract persist timer tests`

---

### Task 17: Extract `tests/sack.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/sack.rs`

Move:
- `establish_connection_with_sack` helper (8178-8234) — if not already in `tests/mod.rs`
- `ooo_data_sends_sack_blocks_in_dup_ack` (8067)
- `sack_blocks_update_scoreboard_on_ack` (8235)
- `sack_scoreboard_pruned_on_cumulative_ack_advance` (8301)
- `sack_blocks_updated_on_dup_ack` (8392)
- `sack_scoreboard_cleared_on_rto` (8445)
- `fast_retransmit_uses_sack_gap` (8507)
- `fast_retransmit_fallback_when_scoreboard_empty` (8570)
- `sack_recovery_enters_on_3_dup_acks` (8621)
- `sack_recovery_partial_ack_stays_in_recovery` (8724)

Commit: `refactor(tcp): extract SACK recovery tests`

---

### Task 18: Extract `tests/ecn.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/ecn.rs`

Move:
- `ecn_negotiated_when_both_sides_support` (8944)
- `ecn_disabled_when_peer_doesnt_support` (9032)
- `ecn_negotiated_on_passive_open` (9099)
- `ecn_ect_set_on_outgoing_data` (9192)
- `ecn_ect_not_set_on_retransmit` (9265)
- `ecn_ce_detected_on_incoming` (9340)
- `ecn_ece_sent_when_ce_received` (9437)
- `ecn_cwnd_halved_on_ece` (9539)
- `ecn_cwr_sent_on_next_data` (9657)
- `ecn_ce_received_cleared_on_cwr` (9738)

Commit: `refactor(tcp): extract ECN tests`

---

### Task 19: Extract `tests/edge_cases.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/edge_cases.rs`

Move:
- `unmatched_syn_generates_rst` (3288)
- `rst_to_unbound_port_silently_dropped` (3319)
- `invalid_checksum_dropped` (3337)
- `truncated_tcp_header_dropped` (3369)
- `frame_accounting_after_rst` (3581)
- `rst_outside_window_is_dropped` (10239)
- `rst_in_window_but_not_exact_sends_challenge_ack` (10283)
- `syn_in_established_sends_challenge_ack` (10332)
- `segment_without_ack_is_dropped` (10387)
- `ack_beyond_snd_nxt_sends_ack_and_drops` (10500)
- `stale_segment_does_not_regress_window` (10577)
- `sender_sws_avoidance_holds_small_sends` (10797)
- `sender_sws_allows_send_when_all_data_fits` (10884)
- `segment_acceptability_*` tests (7857-7888)

Commit: `refactor(tcp): extract edge case tests`

---

### Task 20: Extract `tests/congestion.rs`

**Files:**
- Create: `src/net/handler/tcp/tests/congestion_tests.rs` (name avoids collision with `congestion.rs` module)

Move:
- `cubic_slow_start_on_new_ack` (10957)
- `frto_restores_cwnd_on_spurious_rto` (11052)

Commit: `refactor(tcp): extract congestion control tests`

---

### Task 21: Final cleanup and verification

**Step 1: Verify `mod.rs` is a pure export shim**

It should look approximately like:
```rust
pub(crate) mod congestion;
mod connection;
mod handler;
mod inbound;
mod isn;
pub(super) mod listener;
pub(crate) mod recovery;
pub(crate) mod ring_buffer;
pub(crate) mod segment;
pub(crate) mod state;
pub(crate) mod tcb;
mod timers;
mod transmit;

pub use handler::TcpHandler;

#[cfg(test)]
mod tests;
```

**Step 2: Verify all tests still pass**

Run: `cargo test`
Expected: All 70+ tests pass with zero failures.

**Step 3: Verify line counts are reasonable**

Run: `wc -l src/net/handler/tcp/*.rs src/net/handler/tcp/tests/*.rs`

Expected approximate sizes:
- `mod.rs`: ~15 lines
- `handler.rs`: ~80 lines
- `listener.rs`: ~120 lines
- `connection.rs`: ~150 lines
- `inbound.rs`: ~1,600 lines
- `timers.rs`: ~380 lines
- `transmit.rs`: ~300 lines
- `tests/mod.rs`: ~200 lines (helpers)
- Individual test files: 200-1200 lines each

**Step 4: Commit**

```
refactor(tcp): final cleanup after mod.rs decomposition
```
