# Wire Module

Zero-copy wire format types for packet parsing and construction. All header structs are `#[repr(C, packed)]` with multi-byte fields stored as `[u8; N]` to avoid alignment issues. Accessor methods convert to/from network byte order on demand. Headers are cast directly from `Frame` memory via unsafe pointer casts — no copying.

## ethernet.rs

### MacAddress (6 bytes)

```rust
pub const fn new(octets: [u8; 6]) -> Self
pub const fn broadcast() -> Self     // [0xFF; 6]
pub const fn zero() -> Self          // [0x00; 6]
```

Conversions: `From<[u8; 6]>`, `Into<[u8; 6]>`, `Display` (xx:xx:xx:xx:xx:xx).

### EtherType (2 bytes)

Constants in `EtherTypes`:
- `IPv4 = [0x08, 0x00]`
- `IPv6 = [0x86, 0xDD]`
- `Arp = [0x08, 0x06]`

### EthernetFrame (14 bytes)

Fields: `dst_mac`, `src_mac`, `ether_type`.

```rust
pub fn from_frame(frame: &Frame) -> &Self         // zero-copy cast
pub fn from_frame_mut(frame: &mut Frame) -> &mut Self
```

Helper: `pub fn write_ethernet_header(frame, dst_mac, src_mac, ether_type)`

## arp.rs

### ArpPacket (28 bytes, at offset 14 from frame start)

Fields: `htype`, `ptype`, `hlen`, `plen`, `oper`, `sha` (sender MAC), `spa` (sender IPv4), `tha` (target MAC), `tpa` (target IPv4).

```rust
pub fn from_frame(frame: &Frame) -> &Self          // offset 14, requires len >= 42
pub fn from_frame_mut(frame: &mut Frame) -> &mut Self
```

Constants:
- `ArpHardwareTypes::Ethernet = [0x00, 0x01]`
- `ArpOperations::Request = [0x00, 0x01]`, `Reply = [0x00, 0x02]`
- `ARP_FRAME_LEN = 42`

## ip/ — Address Types

### Ipv4Address (4 bytes)

```rust
pub const fn new(octets: [u8; 4]) -> Self
pub const fn loopback() -> Self       // 127.0.0.1
pub const fn unspecified() -> Self    // 0.0.0.0
pub const fn broadcast() -> Self     // 255.255.255.255
pub const fn is_unspecified(&self) -> bool
pub const fn is_broadcast(&self) -> bool
pub const fn is_multicast(&self) -> bool   // 224.0.0.0/4
pub const fn is_loopback(&self) -> bool    // 127.0.0.0/8
```

Conversions: `From/Into<[u8; 4]>`, `From/Into<std::net::Ipv4Addr>`, `FromStr`, `Display`.

### Ipv6Address (16 bytes)

```rust
pub const fn new(octets: [u8; 16]) -> Self
pub const fn loopback() -> Self       // ::1
pub const fn unspecified() -> Self    // ::
pub const fn is_unspecified(&self) -> bool
pub const fn is_multicast(&self) -> bool    // ff00::/8
pub const fn is_loopback(&self) -> bool     // ::1
pub const fn is_link_local(&self) -> bool   // fe80::/10
pub const fn solicited_node_multicast(&self) -> Self  // ff02::1:ffXX:XXXX
pub const fn multicast_mac(&self) -> MacAddress       // 33:33:XX:XX:XX:XX
```

Conversions: `From/Into<[u8; 16]>`, `From/Into<std::net::Ipv6Addr>`, `FromStr`, `Display`.

### IpAddress (enum)

Variants: `V4(Ipv4Address)`, `V6(Ipv6Address)`.
- `pub fn is_unspecified(&self) -> bool`
- Conversions: `From<Ipv4Address>`, `From<Ipv6Address>`, `From<std::net::IpAddr>`, `FromStr`, `Display`.

## ip/v4.rs — Ipv4Header (20 bytes minimum)

Fields: `version_ihl`, `dscp_ecn`, `total_length`, `identification`, `flags_fragment_offset`, `ttl`, `protocol`, `header_checksum`, `src_addr`, `dst_addr`.

**Accessors:**
- `version()`, `ihl()`, `header_len()` (ihl * 4)
- `total_length()`, `identification()`
- `dont_fragment()`, `more_fragments()`, `fragment_offset()` (8-byte units)
- `is_fragment()` — true if MF set or offset != 0
- `payload_offset()` — 14 + header_len (from frame start)
- `payload_len()` — total_length - header_len

**Checksum:**
- `fill_checksum(&mut self)` — compute and fill in-place
- `pub fn compute_ipv4_checksum(header_bytes) -> [u8; 2]` — RFC 1071
- `pub fn verify_ipv4_checksum(header_bytes) -> bool`

**Zero-copy:**
```rust
pub fn from_frame(frame: &Frame) -> &Self          // requires len >= IPV4_MIN_FRAME_LEN (34)
pub fn from_frame_mut(frame: &mut Frame) -> &mut Self
```

Constants: `IPV4_MIN_HEADER_LEN = 20`, `IPV4_MIN_FRAME_LEN = 34`.

## ip/v6.rs — Ipv6Header (40 bytes)

Fields: `version_tc_fl` (version + traffic class + flow label), `payload_length`, `next_header`, `hop_limit`, `src_addr`, `dst_addr`.

**Accessors:** `version()`, `traffic_class()`, `flow_label()`, `payload_length()`.

**Zero-copy:**
```rust
pub fn from_frame(frame: &Frame) -> &Self          // requires len >= IPV6_MIN_FRAME_LEN (54)
pub fn from_frame_mut(frame: &mut Frame) -> &mut Self
```

### Ipv6FragmentHeader (8 bytes, RFC 8200 s4.5)

Fields: `next_header`, `reserved`, `fragment_offset_mf`, `identification`.

**Accessors:** `fragment_offset()` (8-byte units, high 13 bits), `more_fragments()` (LSB), `identification()` (u32), `is_fragment()`.
- `set_fragment_offset_mf(offset_units, more_fragments)` — setter

**Zero-copy:** `from_bytes(bytes, offset)`, `from_bytes_mut(bytes, offset)`.

Constants: `IPV6_HEADER_LEN = 40`, `IPV6_MIN_FRAME_LEN = 54`, `FRAGMENT_EXT_LEN = 8`.

Extension header type constants: `EXT_HOP_BY_HOP = 0`, `EXT_ROUTING = 43`, `EXT_FRAGMENT = 44`, `EXT_AH = 51`, `EXT_DESTINATION = 60`, `NO_NEXT_HEADER = 59`.

## icmpv4.rs

### Icmpv4Header (8 bytes)

Fields: `icmp_type`, `code`, `checksum`, `rest_of_header` (type-dependent: echo ID+seq, unused+MTU).

**Type constants** (`Icmpv4Types`): `EchoReply = 0`, `DestinationUnreachable = 3`, `SourceQuench = 4`, `Redirect = 5`, `EchoRequest = 8`, `TimeExceeded = 11`, `ParameterProblem = 12`.

**Code constants** (`Icmpv4Codes`): `ProtocolUnreachable = 2`, `PortUnreachable = 3`, `FragmentationNeeded = 4`.

**Helper:** `pub fn is_icmp_error(icmp_type) -> bool` — true for error message types per RFC 1122.

Constant: `ICMPV4_HEADER_LEN = 8`.

## icmpv6.rs

### Icmpv6Header (8 bytes)

Fields: `icmp_type`, `code`, `checksum`, `body` (type-dependent: echo ID+seq, MTU, pointer).

**Type constants** (`Icmpv6Types`): `DestinationUnreachable = 1`, `PacketTooBig = 2`, `TimeExceeded = 3`, `ParameterProblem = 4`, `EchoRequest = 128`, `EchoReply = 129`, `RouterSolicitation = 133`, `RouterAdvertisement = 134`, `NeighborSolicitation = 135`, `NeighborAdvertisement = 136`, `Redirect = 137`.

**Code constants** (`Icmpv6Codes`): `NoRouteToDestination = 0`, `AdminProhibited = 1`, `BeyondScope = 2`, `AddressUnreachable = 3`, `PortUnreachable = 4`, `ErroneousHeaderField = 0`, `UnrecognizedNextHeader = 1`, `UnrecognizedOption = 2`.

**Checksum:**
```rust
pub fn compute_icmpv6_checksum(src_addr: &Ipv6Address, dst_addr: &Ipv6Address, icmpv6_data: &[u8]) -> [u8; 2]
```
RFC 4443 s2.3: includes IPv6 pseudo-header (src + dst + packet_len + next_header=58).

**Helper:** `pub fn is_icmpv6_error(icmpv6_type) -> bool` — true if type 0-127 per RFC 4443.

Constants: `ICMPV6_HEADER_LEN = 8`, `MAX_ERROR_PAYLOAD = 1232` (1280 - 40 - 8).

## tcp.rs

### TcpHeader (20 bytes minimum)

Fields: `src_port`, `dst_port`, `seq_num`, `ack_num`, `data_offset_reserved`, `flags`, `window`, `checksum`, `urgent_ptr`.

**Constructor:** `pub fn new(src_port, dst_port, seq_num, ack_num, data_offset, flags, window, checksum, urgent_ptr) -> Self`

**Accessors:** `src_port()`, `dst_port()`, `seq_num()`, `ack_num()`, `data_offset()` (32-bit words), `header_len()` (data_offset * 4), `flags()`, `has_flag(flag)`, `window()`, `urgent_ptr()`.

**Zero-copy:**
```rust
pub unsafe fn from_frame_at(frame: &Frame, offset: usize) -> &Self
pub unsafe fn from_frame_mut_at(frame: &mut Frame, offset: usize) -> &mut Self
```

**Flag constants** (`flags`): `FIN = 0x01`, `SYN = 0x02`, `RST = 0x04`, `PSH = 0x08`, `ACK = 0x10`, `URG = 0x20`, `ECE = 0x40`, `CWR = 0x80`.

**Option constants** (`options`): `END = 0`, `NOP = 1`, `MSS = 2`.

**MSS helpers:** `pub fn parse_mss(options) -> Option<u16>`, `pub fn write_mss_option(buf, mss) -> usize`.

**Sequence helpers:** `pub fn seq_lt(a, b) -> bool`, `pub fn seq_le(a, b) -> bool` — wraparound-aware comparison.

**Checksum:**
```rust
pub fn compute_tcp_checksum(src_addr: &Ipv4Address, dst_addr: &Ipv4Address, tcp_segment: &[u8]) -> [u8; 2]
pub fn verify_tcp_checksum(src_addr, dst_addr, tcp_segment) -> bool  // rejects zero checksum
pub fn compute_tcp_checksum_v6(src_addr: &Ipv6Address, dst_addr: &Ipv6Address, tcp_segment: &[u8]) -> [u8; 2]
pub fn verify_tcp_checksum_v6(src_addr, dst_addr, tcp_segment) -> bool
```

Constant: `TCP_HEADER_LEN = 20`.

## udp.rs

### UdpHeader (8 bytes)

Fields: `src_port`, `dst_port`, `length` (header + payload), `checksum`.

**Constructor:** `pub fn new(src_port, dst_port, length, checksum) -> Self`

**Accessors:** `src_port()`, `dst_port()`, `length()`, `payload_len()` (length - 8).

**Zero-copy:** `pub unsafe fn from_frame_at(frame: &Frame, offset: usize) -> &Self`

**IPv4 Checksum:**
```rust
pub fn compute_udp_checksum(src_addr: &Ipv4Address, dst_addr: &Ipv4Address, udp_segment: &[u8]) -> [u8; 2]
pub fn verify_udp_checksum(src_addr, dst_addr, udp_segment) -> bool  // zero = "no checksum" (valid)
pub fn compute_udp_checksum_from_parts(src_addr, dst_addr, src_port, dst_port, udp_len, payload) -> [u8; 2]
```

**IPv6 Checksum:**
```rust
pub fn compute_udp_checksum_v6(src_addr: &Ipv6Address, dst_addr: &Ipv6Address, udp_segment: &[u8]) -> [u8; 2]
pub fn verify_udp_checksum_v6(src_addr, dst_addr, udp_segment) -> bool  // zero checksum INVALID
pub fn compute_udp_checksum_v6_from_parts(src_addr, dst_addr, src_port, dst_port, udp_len, payload) -> [u8; 2]
```

**Incremental checksum helpers** (pub(crate)):
- `sum_words_carry(data, sum, pending) -> (u64, Option<u8>)` — accumulates 16-bit words across frame boundaries with odd-byte carry. Processes 32 bytes per iteration for pipeline efficiency. Enables multi-frame checksumming without allocation.
- `fold_checksum(sum: u64) -> u16` — folds 64-bit sum to 16 bits, one's complement
- `fold_and_verify(sum, actual) -> bool`
- `pseudo_header_sum_v4(src, dst, udp_len) -> u64`
- `pseudo_header_sum_v6(src, dst, udp_len) -> u64`

Constant: `UDP_HEADER_LEN = 8`.

## ip/mod.rs

`IpProtocol` newtype wrapper around `u8`.

Constants in `IpProtocols`: `Icmp = 1`, `Tcp = 6`, `Udp = 17`, `IcmpV6 = 58`.

## Consumer Context

- **Handlers** parse inbound frames via zero-copy `from_frame()`/`from_frame_at()`. No allocation — headers are read directly from UMEM-mapped memory.
- **Socket layer** (UdpSocket, TcpStream) constructs outbound headers via `new()` constructors and writes them into frames.
- **FragmentWriter** uses `TransportHeader::write_to()` which memcpy's the packed struct bytes directly.
- **Checksum functions** used by both handlers (verification) and sockets (computation). The incremental `sum_words_carry()` is critical for multi-fragment UDP/TCP checksumming.

## File Layout

| File | Contents |
|------|----------|
| `mod.rs` | Submodule declarations |
| `ethernet.rs` | `MacAddress`, `EtherType`, `EthernetFrame`, `EtherTypes` |
| `arp.rs` | `ArpPacket`, `ArpHardwareTypes`, `ArpOperations` |
| `ip/mod.rs` | `IpProtocol`, `IpProtocols`, re-exports |
| `ip/addr.rs` | `Ipv4Address`, `Ipv6Address`, `IpAddress` |
| `ip/v4.rs` | `Ipv4Header`, IPv4 checksum functions |
| `ip/v6.rs` | `Ipv6Header`, `Ipv6FragmentHeader`, extension header constants |
| `icmpv4.rs` | `Icmpv4Header`, type/code constants, error classifier |
| `icmpv6.rs` | `Icmpv6Header`, type/code constants, checksum, error classifier |
| `tcp.rs` | `TcpHeader`, flags, MSS helpers, sequence helpers, checksums |
| `udp.rs` | `UdpHeader`, checksums (IPv4/IPv6/incremental), helpers |
