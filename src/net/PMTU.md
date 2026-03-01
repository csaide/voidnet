# PMTU Module

Path MTU discovery cache per RFC 1191. Stores discovered MTU values keyed by destination IP address with TTL-based expiry. Backed by `DashMap` for concurrent access.

## PmtuCache

```rust
pub struct PmtuCache {
    table: DashMap<IpAddress, (u32, Instant)>,
    mtu: u32,       // default/interface MTU (returned on cache miss)
    ttl: Duration,  // entry lifetime
}
```

### Construction

```rust
pub fn new() -> Self                                    // mtu=1500, ttl=10min
pub fn with_mtu(mtu: u32) -> Self                       // custom mtu, ttl=10min
pub fn with_mtu_and_ttl(mtu: u32, ttl: Duration) -> Self // fully custom
```

Default TTL is 600 seconds (10 minutes per RFC 1191).

### Methods

```rust
pub fn update(&self, addr: IpAddress, mtu: u32)
pub fn get(&self, addr: &IpAddress) -> u32
pub fn evict_stale(&self)
```

**update:** Records a discovered path MTU. Clamped to protocol minimum before storing:
- IPv4: 68 (RFC 791)
- IPv6: 1280 (RFC 2460)

**get:** Returns cached MTU if present and not expired, otherwise returns the default MTU.

**evict_stale:** Removes all entries older than the configured TTL. Called each event loop iteration by LocalRuntime.

### Constants

```rust
pub const IPV4_MIN_MTU: u32 = 68;
pub const IPV6_MIN_MTU: u32 = 1280;
```

## Consumer Context

- **ICMP handlers** call `pmtu.update()` when receiving ICMP Fragmentation Needed (IPv4 type 3 code 4) or ICMPv6 Packet Too Big (type 2), extracting the next-hop MTU from the message.
- **UdpSocket.send_to()** calls `pmtu.get(&dst_addr)` to determine fragment sizing before calling `FragmentWriter`.
- **LocalRuntime** calls `pmtu.evict_stale()` each event loop iteration.
- Shared via `Rc<PmtuCache>` across sockets and the runtime.
