# Net Module

Protocol stack built on top of the `xdp/` layer. Parses, dispatches, and generates network packets using zero-copy frames from shared UMEM memory.

## Module Map

```
src/net/
├── wire/          Zero-copy wire format types         → WIRE.md
├── fragment/      IP fragmentation & reassembly       → FRAGMENT.md
├── handler/       Protocol dispatch (L3/L4)           → HANDLER.md
├── socket/        User-facing async socket API        → SOCKET.md
├── neighbor.rs    ARP/NDP neighbor resolution cache   → NEIGHBOR.md
├── pmtu.rs        Path MTU discovery cache            → PMTU.md
└── mod.rs         Re-exports
```

## Re-exports (from mod.rs)

```rust
// fragment/
pub use fragment::{FragmentReader, FragmentWriter, Packet, ReassembledPacket, TransportHeader};

// handler/
pub use handler::tcp::{ConnectionId, TcpCommand, TcpEvent, TcpState};
pub use handler::udp::ReceivedUdpPacket;

// socket/
pub use socket::{TcpListener, TcpReadResult, TcpStream};

// top-level
pub use neighbor::NeighborHandler;
pub use pmtu::PmtuCache;
```

Public submodules: `handler`, `socket`, `wire`. The `fragment`, `neighbor`, and `pmtu` modules are private with selected re-exports.

## Packet Flow

```
NIC → XDP BPF → AF_XDP Socket → UMEM Frames
                                      │
                          ┌───────────┴───────────┐
                          │  EtherType dispatch    │
                          │  (LocalRuntime loop)   │
                          └───┬───────┬────────┬───┘
                              │       │        │
                           IPv4    IPv6      ARP
                              │       │        │
                         [handler/]  [handler/]  [neighbor.rs]
                              │       │
                    ┌─────┬───┴───┐   │
                   ICMP  UDP   TCP   (same)
                    │     │     │
                 [wire/] [fragment/] + [handler/]
                          │     │
                    ┌─────┴─────┴─────┐
                    │  [socket/] API   │
                    │  UdpSocket       │
                    │  TcpListener     │
                    │  TcpStream       │
                    └─────────────────┘
                          │
                    User async future
```

## Layer Responsibilities

| Layer | Modules | Role |
|-------|---------|------|
| Wire format | `wire/` | Zero-copy header parsing and construction, checksums |
| Fragmentation | `fragment/` | IPv4/IPv6 fragmentation (TX) and reassembly (RX) |
| Resolution | `neighbor.rs`, `pmtu.rs` | MAC address resolution (ARP/NDP), path MTU discovery |
| Dispatch | `handler/` | L3 validation and dispatch, L4 protocol state machines |
| Socket API | `socket/` | Async futures for user code (recv/send/accept/read/write) |

## Design Invariants

- **Frame ownership:** Every frame is consumed and pushed to exactly one buffer (`rx_return`, `tx_return`, or a socket queue). No implicit drops.
- **Zero-copy:** Headers parsed in-place via `#[repr(C, packed)]` structs cast from frame memory. No allocation for single-frame packets.
- **Busy-poll:** All futures use no-op wakers. Progress driven by the LocalRuntime polling loop, not async wake notifications.
- **Shared state:** `NeighborHandler` and `PmtuCache` are `Rc`-shared between the runtime and sockets. `SharedQueue<T>` (`Arc<ArrayQueue<T>>`) bridges handlers and socket futures.
