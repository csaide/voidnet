# README Redesign Spec

## Goal

Rewrite the VoidNet README.md to accurately represent the library as a full
userspace networking stack (not just AF_XDP bindings), with a professional tone
targeting Rust developers.

## One-Liner

> An ultra low latency and high throughput networking stack for Linux, built on AF_XDP.

## Structure

### 1. Title + Badges + One-liner

Keep existing badges (crates.io, docs.rs, codecov). Replace the current one-liner
with the updated version above.

### 2. Overview

Two paragraphs:
- What it is: userspace networking stack that bypasses the kernel. Packets flow
  directly between NIC and application via shared memory.
- Why you'd care: full protocol stack (TCP, UDP, HTTP/1.1) with familiar async
  socket APIs. Ergonomics of `TcpListener::accept()` with kernel-bypass performance.

### 3. Features

Grouped by layer:

- **Application Layer** — HTTP/1.1 server with keep-alive and chunked encoding,
  `HttpListener::serve()` convenience API.
- **Transport Layer** — TCP (SACK, CUBIC, ECN, delayed ACK, keep-alive, Nagle,
  retransmission timers). UDP (bind/send/recv, split halves, streaming).
- **Network Layer** — IPv4/IPv6 with fragmentation/reassembly. PMTU discovery
  (RFC 1191). SIMD-accelerated checksums (ARM NEON).
- **Link Layer** — ARP/NDP neighbor discovery with TTL-based cache eviction.
  Ethernet frame handling.
- **Core** — Zero-copy packet I/O via AF_XDP shared UMEM regions. Async-first
  with built-in runtimes. `LocalRuntime` (single-threaded) and `Runtime`
  (multi-threaded) with shared-nothing architecture — each thread owns its own
  XDP socket, UMEM, and protocol state. Builder patterns throughout.

### 4. Getting Started

**Requirements:**
- Linux kernel >= 5.4
- Rust >= 1.85 (2024 edition)
- Root privileges or CAP_NET_RAW + CAP_BPF
- XDP-compatible NIC (i40e, mlx5, ice, veth, etc.)
- Note: all major cloud providers supported (AWS, GCP, Azure)

**Installation:** `voidnet = "0.1"` in Cargo.toml.

### 5. Examples

Six collapsible `<details>` sections, each with a trimmed example (~15-25 lines,
no clap/stats/ctrlc boilerplate) and a link to the full source file.

Each example includes the full `LocalRuntime::builder().build()` + `runtime.run()`
skeleton so examples are self-contained and copy-pasteable. The `exit` signal setup
can be abbreviated with a comment. Import statements use `use` declarations with
full paths (e.g., `use libvoid::net::socket::TcpListener`).

1. **TCP Echo Server** — `LocalRuntime` + `TcpListener::listen()` + `accept()` +
   `splice()`. Links to `examples/tcp-echo-server.rs`.
2. **TCP Echo Client** — `LocalRuntime` + `TcpStream::connect()` + `write()` /
   `read()` loop. Links to `examples/tcp-echo-client.rs`.
3. **UDP Server** — `LocalRuntime` + `UdpSocket::new()` + `split()` +
   non-streaming `recv()` (avoid `futures_util::StreamExt` dependency in README).
   Links to `examples/udp-server.rs`.
4. **UDP Client** — `LocalRuntime` + `UdpSocket::new()` + `send_to()`. Links to
   `examples/udp-client.rs`.
5. **HTTP Server** — `LocalRuntime` + `HttpListener::listen()` +
   `next_request()` + `respond()` loop (shows more control than `serve()`
   convenience method). Links to `examples/http-server.rs`.
6. **Low-level XDP** — Raw `XdpContext` + `Umem` + `Socket` for direct packet
   I/O. Links to `examples/sync-rx.rs`.

All examples use `libvoid` as the crate import (the public API name).
No `Runtime` (multi-threaded) examples in the initial README — `LocalRuntime`
is sufficient to demonstrate the APIs.

### 6. Architecture

Mermaid diagram showing the full layered stack:

- Application: HTTP/1.1 (HttpListener, HttpConnection)
- Transport: TCP (TcpListener, TcpStream, SACK, CUBIC, ECN) and UDP (UdpSocket,
  SendHalf, RecvHalf)
- Network: IPv4/IPv6 (fragmentation/reassembly), PMTU Cache, Checksums (SIMD/NEON)
- Link: Ethernet, ARP, NDP, Neighbor Cache
- AF_XDP: Runtime/LocalRuntime, XDP Socket, UMEM (Fill Queue, Completion Queue)
- NIC: Shared Memory (mmap)

Edges show the data flow from Application down through each layer to the NIC.

Below the diagram, brief bullet descriptions of core components:
- `Runtime` / `LocalRuntime`
- `XdpContext`
- `Umem`
- `Socket`

### 7. Related Projects

Keep as-is:
- libxdp, xdp-tools, libbpf-rs, Aya

## Decisions

- **No Configuration section** — builder options are available in the API docs;
  duplicating them in the README adds maintenance burden.
- **No Performance Tips section** — needs more work before including.
- **`<details>` for examples** — keeps the README scannable while showing breadth.
- **Mermaid over ASCII** — renders natively on GitHub, no alignment issues.
- **Lead with high-level APIs** — TCP/UDP/HTTP examples before low-level XDP to
  match the "full stack" framing.
- **`libvoid` crate name** — all examples use `libvoid::` imports, matching the
  public API.
