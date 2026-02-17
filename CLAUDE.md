# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**VoidNet** is a high-performance, zero-copy AF_XDP networking library for Rust. It provides safe bindings to Linux's AF_XDP interface, enabling ultra-low latency packet processing by bypassing the kernel network stack. The library crate is named `libvoid` (crate name `voidnet`).

**Requirements:** Linux kernel >= 5.4, Rust >= 1.85 (2024 edition), root or CAP_NET_RAW + CAP_BPF, XDP-compatible NIC. Supported targets: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu.

**System dependencies:** `libbpf-dev libelf-dev libpcap-dev libmnl-dev linux-headers-$(uname -r)` and `clang` (for BPF compilation).

## Build Commands

```bash
cargo build                         # Build (default, no async features)
cargo build --all-features          # Build with all async runtimes
cargo build --features tokio        # Build with tokio support
cargo build --features smol         # Build with smol support
cargo build --features local        # Build with custom local executor

cargo test                          # Run sync integration tests
cargo test --features local         # Run local executor tests
cargo test --features tokio         # Run tokio tests
cargo test --features smol          # Run smol tests
cargo test --all-features           # Run all tests

cargo test --test sync              # Run a specific test suite
cargo test --test sync test_name    # Run a single test

cargo llvm-cov --all-features --workspace --codecov  # Coverage report
```

## Feature Flags

- `async` — Enables futures-core/futures-util (base for all async features)
- `local` — Custom high-performance local executor (implies `async`)
- `smol` — Smol runtime integration (implies `async`)
- `tokio` — Tokio runtime integration (implies `async`)

## Architecture

### Module Structure

**`xdp/`** — Core AF_XDP abstraction (the heart of the library):
- `context/` — XDP program loading and interface attachment (`XdpContext`, `XdpContextBuilder`)
- `socket/` — AF_XDP socket I/O (`Socket`, `SocketRx`, `SocketTx`, `SocketBuilder`)
- `umem/` — Shared memory management (`Umem`, `UmemBuilder`, `FillQueue`, `CompletionQueue`)
- `frame/` — Packet frame buffers (`Frame`, `FrameBuffer` trait, `BasicFrameBuffer`)
- `program/` — BPF program and map management (`XdpProgram`, `AttachMode`)
- `ring/` — Ring buffer primitives (`Producer`, `Consumer`)
- `futures/` — Async runtime integrations, feature-gated (`tokio/`, `smol/`, `local/`)

**`net/`** — Protocol stack (currently being refactored on `runtime` branch):
- `wire/` — Wire format parsing (ethernet, ARP, IPv4/IPv6, ICMPv4/v6, UDP)
- `packet/` — Packet composition (`PacketReader`, `PacketWriter`)
- `handler/` — Protocol handlers (IPv4, IPv6, ICMPv4, ICMPv6, UDP)
- `socket/` — High-level socket abstractions (`UdpSocket`, `SharedQueue`)
- `neighbor.rs` — ARP neighbor resolution cache
- `pmtu.rs` — Path MTU discovery cache

**`rt/`** — High-level runtime utilities:
- `local.rs` — `LocalRuntimeBuilder` pre-configured packet processing pipeline with integrated protocol handlers
- `affinity.rs` — CPU affinity management
- `thread.rs` — Thread utilities
- `waker.rs` — No-op waker for the local executor

### Key Data Flow

Packets flow: NIC → XDP BPF program → XSKMAP → AF_XDP socket → shared UMEM frames → userspace processing. All via mmap'd shared memory with zero copies.

### Design Patterns

- **Builder pattern** on all major types (`XdpContextBuilder`, `SocketBuilder`, `UmemBuilder`)
- **Ownership tokens** (`UmemOwner`, `SocketOwner`) for resource lifetime safety
- **Split I/O** — `Socket` splits into independent `SocketRx` + `SocketTx`
- **Feature-gated compilation** — async code behind `cfg(feature = "...")` with zero cost for unused runtimes
- **Batch processing** — Frames processed in `FrameBuffer` collections, not individually

### BPF Kernel Program

`bpf/xdp_kern.c` is compiled at build time by `build.rs` using clang. It implements round-robin packet distribution across AF_XDP sockets via XSKMAP. The compiled object (`bpf/xdp_kern.o`) is gitignored.

### Testing Infrastructure

Integration tests use `xdp::test_utils::TestVethPair` to create virtual ethernet pairs. Tests spawn cross-thread packet exchange targeting 1M packets for throughput validation. Tests require root privileges — `.cargo/config.toml` configures `sudo -E` as the test runner for both x86_64 and aarch64 targets.

### Running Examples

```bash
cargo run --example sync-echo -- --if-name eth0 --queue 0
cargo run --example sync-rx -- --if-name eth0 --queue 0
cargo run --example tokio-rx --features tokio -- --if-name eth0 --queue 0
```
