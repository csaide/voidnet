# Neighbor Solicitation on Cache Miss

## Problem

When the neighbor cache misses (no MAC for a destination IP), the TCP transmit path
falls back to `MacAddress::broadcast()` instead of triggering ARP (IPv4) or NDP
Neighbor Solicitation (IPv6). The UDP socket path handles this correctly by manually
calling `resolve_v4`/`resolve_v6`, but TCP does not.

Broadcasting TCP segments on a miss is incorrect — it leaks frames onto the broadcast
domain and relies on luck rather than protocol-correct resolution.

## Solution

### NeighborEntry State Machine

Replace the current `NeighborEntry { mac, expires_at }` with a three-state enum:

```
(no entry) ──solicit──► Incomplete ──reply/traffic──► Reachable ──TTL expires──► Stale
                            │                                                      │
                        evict 3s                          ◄──reply/traffic──    evict 30s
                            │                                                      │
                            ▼                                                      ▼
                        (removed)                                              (removed)
```

The `Reachable → Stale` transition occurs in two places:
- `lookup_or_resolve()`: when a Reachable entry is found past TTL on access
- `evict_stale()`: when sweeping entries that are never looked up again

```rust
pub enum NeighborState {
    Incomplete {
        solicited_at: Instant,
    },
    Reachable {
        mac: MacAddress,
        expires_at: Instant,
    },
    Stale {
        mac: MacAddress,
        stale_since: Instant,
        solicited_at: Option<Instant>,
    },
}
```

### Behavior Per State

| State      | `lookup_or_resolve()` returns | Side effect                          |
|------------|-------------------------------|--------------------------------------|
| No entry   | `None`                        | Insert `Incomplete`, send solicit    |
| Incomplete | `None`                        | Re-solicit if `solicited_at` > 1s ago |
| Reachable (valid) | `Some(mac)`            | None                                 |
| Reachable (expired) | `Some(mac)`          | Transition to Stale, send solicit    |
| Stale      | `Some(mac)` (optimistic)      | Send solicit if not solicited in last 1s |

### New API: `lookup_or_resolve()`

```rust
pub fn lookup_or_resolve<'umem>(
    &self,
    now: Instant,
    addr: &IpAddress,
    src_addr: &IpAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) -> Option<MacAddress>
```

- `src_addr`: the local IP to use as source in the ARP request / NDP solicitation.
  For TCP call sites this is `tcb.id.local_addr`.
- `rx_return`: frame recycling buffer (required by `resolve_v4`/`resolve_v6` for
  capacity errors).

Centralizes lookup + solicitation-on-miss. Prevents callers from forgetting to solicit.

### Timeouts

- **Incomplete eviction**: 3 seconds
- **Stale eviction**: 30 seconds (from `stale_since`, not from `solicited_at`)
- **Reachable TTL**: Existing configurable TTL (default 10 min)
- **Re-solicitation guard**: 1 second (for both Incomplete and Stale states)

### TCP Call Site Changes

**9 total broadcast fallback sites** across two files:

`transmit.rs` (5 sites):
1. Data segment send loop
2. Delayed ACK (count-based immediate flush)
3. Zero-window probe (persist timer)
4. Linger timeout RST
5. FIN-ACK send

`timers.rs` (4 sites):
6. Delayed ACK (timer-based flush)
7. Keep-alive probe
8. SACK recovery retransmit
9. RTO retransmit

All become:

```rust
let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
    now, &tcb.id.remote_addr, &tcb.id.local_addr, free_frames, rx_return, tx_return
) else {
    continue; // drop segment, TCP retransmit recovers
};
```

Dropped segments are recovered by TCP's retransmission timer. By the time the
retransmit fires (~200ms-1s), the ARP/NDP reply will have populated the cache.

### UDP Socket Alignment

Replace the manual `resolve_v4`/`resolve_v6` logic with `lookup_or_resolve()`.

### `learn_from_traffic()` Interaction

`learn_from_traffic()` should respect state transitions:
- No entry → insert `Reachable` (current behavior, unchanged)
- `Incomplete` → transition to `Reachable` (natural race: inbound traffic before
  solicitation reply)
- `Reachable` → refresh `expires_at`
- `Stale` → transition to `Reachable`

### `evict_stale()` Update

Handle all three states:
- Evict `Incomplete` entries where `now - solicited_at > 3s`
- Transition `Reachable` entries where `now >= expires_at` to `Stale`
- Evict `Stale` entries where `now - stale_since > 30s`

### ARP/NDP Reply Handlers

Update `handle_arp` and `handle_ndp` to transition entries through states
(`Incomplete → Reachable`, `Stale → Reachable`) rather than blindly inserting.
Unsolicited replies (no prior entry) go directly to `Reachable`.
