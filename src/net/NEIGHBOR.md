# Neighbor Module

Unified ARP (IPv4) and NDP (IPv6) neighbor resolution handler. Maps protocol addresses to hardware (MAC) addresses with TTL-based expiry. Backed by `DashMap` for concurrent access.

## NeighborHandler

```rust
pub struct NeighborHandler {
    local_mac: MacAddress,
    local_ipv4: Vec<Ipv4Address>,
    local_ipv6: Vec<Ipv6Address>,
    table: DashMap<IpAddress, NeighborEntry>,
    ttl: Duration,
}
```

### Construction

```rust
pub fn new(if_name: &str, local_mac: MacAddress, ttl: Duration) -> Result<Self>
```

Discovers local IPv4/IPv6 addresses from the named interface via `getifaddrs`. The `ttl` controls how long cache entries remain valid.

### Address Registration

```rust
pub fn add_local_ipv4(&mut self, addr: Ipv4Address)
pub fn add_local_ipv6(&mut self, addr: Ipv6Address)
```

Register additional local addresses for ARP/NDP response. Deduplicates.

### Cache Lookup

```rust
pub fn lookup(&self, ip: &IpAddress) -> Option<MacAddress>
pub fn lookup_v4(&self, ip: &Ipv4Address) -> Option<MacAddress>
pub fn lookup_v6(&self, ip: &Ipv6Address) -> Option<MacAddress>
pub fn local_mac(&self) -> MacAddress
```

Returns `None` if the entry is missing or expired.

### Cache Maintenance

```rust
pub fn evict_stale(&self)
```

Removes all entries whose TTL has expired. Called each event loop iteration by LocalRuntime.

### Outbound Resolution

```rust
pub fn resolve_v4(&self, source_ip, target_ip, frame, rx_return, tx_return)
pub fn resolve_v6(&self, source_ip, target_ip, frame, rx_return, tx_return)
```

**resolve_v4:** Constructs a broadcast ARP Request (42 bytes) and pushes to `tx_return`. Falls back to `rx_return` if frame capacity is insufficient.

**resolve_v6:** Constructs an ICMPv6 Neighbor Solicitation (86 bytes) sent to the solicited-node multicast address derived from `target_ip`. Includes Source Link-Layer Address option (type=1) with our MAC. Hop limit = 255 per RFC 4861. Computes ICMPv6 checksum.

### Inbound ARP

```rust
pub fn handle_arp(&self, frame, rx_return, tx_return)
```

**Validation:** frame >= 42 bytes, htype = Ethernet, ptype = IPv4, hlen = 6, plen = 4.

**Cache learning:** Both requests and replies from valid ARP packets update the cache with sender's (IP, MAC) mapping.

**Reply generation:** If the request targets one of our local IPv4 addresses, modifies the frame in-place to an ARP Reply (swaps MACs/IPs, sets oper=Reply) and pushes to `tx_return`. Otherwise pushes to `rx_return`.

### Inbound NDP

```rust
pub fn handle_ndp(&self, frame, icmpv6_offset, icmpv6_len, rx_return, tx_return)
```

**Validation:** ICMPv6 length >= 8, valid ICMPv6 checksum (includes IPv6 pseudo-header).

**Dispatch by ICMPv6 type:**

| Type | Action |
|------|--------|
| Neighbor Solicitation (135) | Cache sender MAC from Source LLA option (if src != ::). If target is our address, build NA reply with S+O flags (or O-only for DAD). Sends to `tx_return`. |
| Neighbor Advertisement (136) | Cache target MAC from Target LLA option (type=2). Passes to `rx_return`. |
| Router Advertisement (134) | Cache router MAC from Source LLA option (type=1). Passes to `rx_return`. |
| RS (133), Redirect (137), other | Passes to `rx_return`. |

**NDP option parsing:** `parse_ndp_link_layer_option()` walks TLV options (8-byte units) looking for Source (type=1) or Target (type=2) Link-Layer Address options. Returns the 6-byte MAC if found.

**DAD handling:** When source is `::` (Duplicate Address Detection), the NA reply is sent to all-nodes multicast (`ff02::1`) with S=0, O=1 flags.

### Constants

- `NDP_NS_FRAME_LEN = 86` — Ethernet (14) + IPv6 (40) + ICMPv6 NS header (8) + target (16) + Source LLA option (8)
- `NDP_MIN_NS_NA_LEN = 24` — ICMPv6 header (8) + target address (16)
- `NDP_MIN_RA_LEN = 16` — ICMPv6 header (8) + RA fields (8)
- `ALL_NODES_MULTICAST = ff02::1`

## Consumer Context

- **LocalRuntime** event loop dispatches ARP frames to `neighbor_handler.handle_arp()` and NDP ICMPv6 types (133-137) to `neighbor_handler.handle_ndp()`.
- **UdpSocket.send_to()** calls `lookup()` to resolve destination MAC. On cache miss, calls `resolve_v4()`/`resolve_v6()` to initiate resolution, returning `Pending` until the reply arrives.
- **TcpHandler.connect()** requires MAC addresses upfront (passed by caller).
- **Ipv6Handler** checks ICMPv6 type before dispatching NDP messages to `neighbor_handler` vs generic ICMPv6 handling.
- Shared via `Rc<NeighborHandler>` across sockets and the runtime.
