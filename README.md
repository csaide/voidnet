# voidnet

[![Crates.io](https://img.shields.io/crates/v/voidnet.svg)](https://crates.io/crates/voidnet)
[![Documentation](https://docs.rs/voidnet/badge.svg)](https://docs.rs/voidnet)

High-performance, zero-copy AF_XDP networking for Rust with full async/await support.

[Getting Started](#getting-started) | [Examples](#examples) | [API Documentation](https://docs.rs/voidnet)

## Overview

voidnet provides safe Rust bindings to Linux's [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) (Address Family eXpress Data Path) interface, enabling ultra-low latency packet processing by bypassing the kernel network stack entirely. Packets flow directly between the NIC and userspace via shared memory with zero copies.

Key capabilities:

- **Zero-copy packet I/O** — Direct access to kernel packet buffers via shared UMEM regions
- **Async-first design** — Native `async`/`await` with seamless async runtime agnostic integration.
- **High throughput** — Process millions of packets per second per core.
- **Flexible configuration** — Builder patterns for fine-tuned socket and memory settings.
- **Multi-socket support** — Round-robin packet distribution across multiple sockets.

## Getting Started

### Requirements

- **Linux kernel** ≥ 5.4 (for full AF_XDP feature support)
- **Rust** ≥ 1.85 (2024 edition)
- **Root privileges** or `CAP_NET_RAW` + `CAP_BPF` capabilities
- **XDP-compatible NIC** (most modern drivers: `i40e`, `mlx5`, `ice`, `veth`, etc.)

### Installation

Add voidnet to your `Cargo.toml`:

```toml
[dependencies]
voidnet = "0.1"
```

## Examples

### Minimal Packet Receiver

```rust
use libvoid::xdp::{
    context::XdpContext,
    frame::{BasicFrameBuffer, FrameBuffer},
    program::AttachMode,
    socket::Socket,
    umem::Umem,
};

fn process_packet(data: &mut [u8]) {
    // Do something with the packet data here!
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create XDP context — loads and attaches the XDP program
    let mut ctx = XdpContext::new("eth0", AttachMode::default(), false)?;

    // 2. Create UMEM — shared memory region for packet buffers
    let (umem, mut fill_queue, _completion_queue) = Umem::builder()
        .build()?;

    // 3. Create socket bound to interface queue 0
    let mut socket = Socket::builder(&mut ctx, "eth0", 0)
        .build(umem.clone())?;

    // 4. Prime the fill queue with buffers for the kernel to write into
    let mut frames = umem.init_buffer::<BasicFrameBuffer>()?;
    fill_queue.process_queue(&mut frames);

    // 5. Receive packets
    loop {
        if let Ok(count) = socket.recv(&mut frames) {
            for frame in frames.iter_frames() {
                // Process packet data in-place, frame derefs into a `&[u8]`/`&mut [u8]`
                process_packet(&mut frame);
            }
            // Return frames to kernel
            fill_queue.maybe_wake(socket.fd())?;
            fill_queue.process_queue(&mut frames);
        }
    }
}
```

### Async Packet Processing

```rust
use libvoid::xdp::{
    context::XdpContext,
    frame::{BasicFrameBuffer, FrameBuffer},
    socket::Socket,
    umem::Umem,
};

async fn process_packet(data: &mut [u8]) {
    // Do something with the packet data here!
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create XDP context — loads and attaches the XDP program
    let mut ctx = XdpContext::new("eth0", Default::default(), false)?;
    
    // 2. Create UMEM — shared memory region for packet buffers
    let (umem, mut fq, _cq) = Umem::builder()
        .build()?;

    // 3. Create socket bound to interface queue 0
    let mut socket = Socket::builder(&mut ctx, "eth0", 0)
        .build(umem.clone())?;

    // 4. Prime the fill queue with buffers for the kernel to write into
    let mut frames = umem.init_buffer::<BasicFrameBuffer>()?;
    fq.process_queue_async(&mut frames, &[socket.fd()])
        .await
        .unwrap();

    // 5. Receive packets
    loop {
        // Async receive — yields to runtime when no packets available, and returns the number
        // of frames read. Guaranteed to be between 1 and frames.free_space().
        let count = socket.recv_async(&mut frames).await?;
        
        for frame in frames.iter_frames_mut() {
            // Process packet data in-place
            process_packet(&mut frame[..]).await;
        }

        // Return frames to kernel.
        fq.process_queue_async(&mut frames, &[socket.fd()])
            .await
            .unwrap();
    }
}
```

### Complete examples

For a complete echo server that swaps MAC/IP addresses and reflects packets back:

```sh
cargo run --example echo -- --if-name eth0 --queue 0
```

See the [`examples/`](examples/) directory for more:

| Example | Description |
|---------|-------------|
| `echo` | Zero-copy packet reflection with address swapping |
| `info` | Example programing dumping XDP capabilities for a given interface |
| `rx-async-ms` | Async mutli-socket packet reception with Tokio |
| `rx-async` | Async packet reception with Tokio |
| `rx-bench` | RX throughput benchmarking |
| `rx-mt` | Multi-threaded RX throughput benchmarking |
| `tx-async` | Async packet sending with Tokio |
| `tx-bench` | TX throughput benchmarking |
| `tx-mt` | Multi-threaded TX throughput benchmarking |


## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                        User Space                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ XdpContext  │  │   Socket    │  │        Umem         │  │
│  │             │  │  (rx + tx)  │  │  ┌───────────────┐  │  │
│  │ • XDP prog  │  │             │  │  │ Frame Buffers │  │  │
│  │ • Attach    │  │ • recv()    │  │  └───────────────┘  │  │
│  │ • Detach    │  │ • send()    │  │  ┌────┐    ┌────┐   │  │
│  └─────────────┘  │ • async     │  │  │ FQ │    │ CQ │   │  │
│                   └─────────────┘  │  └────┘    └────┘   │  │
│                                    └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      Shared Memory (mmap)                   │
├─────────────────────────────────────────────────────────────┤
│                        Kernel Space                         │
│              XDP Program → XSKMAP → AF_XDP Socket           │
└─────────────────────────────────────────────────────────────┘
```

- **`XdpContext`** — Loads and attaches the XDP eBPF program to the network interface
- **`Umem`** — Manages the shared memory region containing packet frame buffers
- **`FillQueue`** — Passes empty buffers from userspace → kernel for RX
- **`CompletionQueue`** — Returns transmitted buffers from kernel → userspace
- **`Socket`** — Main interface for sending/receiving packets; can be split into separate RX/TX handles

### Data Flow

**Receiving packets:**
1. Submit empty frames to the Fill Queue
2. Kernel writes packet data into frames
3. Read filled frames from RX ring via `socket.recv()`
4. Process packets, return frames to Fill Queue

**Sending packets:**
1. Write packet data into frames
2. Submit frames to TX ring via `socket.send()`
3. Kernel transmits packets
4. Reclaim frames from Completion Queue

## Configuration

### Socket Options

```rust
Socket::builder(&mut ctx, "eth0", 0)
    .rx_ring_size(4096)              // RX descriptor ring size
    .tx_ring_size(4096)              // TX descriptor ring size
    .busy_poll(true)                 // Enable busy polling
    .busy_poll_batch_size(64)        // Frames per busy poll cycle
    .busy_poll_timeout_us(20)        // Busy poll timeout
    .copy_mode(CopyMode::ZeroCopy)   // Zero-copy or copy mode
    .enable_fragmentation(true)      // Multi-buffer packets (jumbo frames)
    .build(umem)?;
```

### UMEM Options

```rust
Umem::builder()
    .num_frames(8192)           // Total frame count
    .frame_size(4096)           // Bytes per frame
    .fill_ring_size(4096)       // Fill queue size
    .completion_ring_size(2048) // Completion queue size
    .huge_tables(true)          // Use huge pages
    .unaligned(true)            // Allow non-power-of-2 frame sizes
    .build()?;
```

## Performance Tips

- **Pin threads to cores** — Use CPU affinity for predictable latency
- **Match queue to core** — Bind each socket to the NIC queue handled by that CPU
- **Tune ring sizes** — Larger rings reduce syscall overhead but increase latency
- **Enable busy polling** — Reduces latency at the cost of CPU usage
- **Use zero-copy mode** — Requires driver support but eliminates all copies
- **Batch operations** — Process packets in batches to amortize overhead

## Related Projects

- [libxdp](https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp) — C library for XDP program loading
- [xdp-tools](https://github.com/xdp-project/xdp-tools) — XDP utilities and examples
- [libbpf-rs](https://github.com/libbpf/libbpf-rs) — Rust bindings for libbpf
- [Aya](https://github.com/aya-rs/aya) — Pure Rust eBPF library
