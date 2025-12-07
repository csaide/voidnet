# Voidnet

Voidnet is a fully functional AF_XDP rust wrapper that supports full async/await syntax and the overall rust async ecosystem.

## Overview

Voidnet provides a high-performance, zero-copy networking library built on top of Linux's AF_XDP (Address Family eXpress Data Path) interface. It enables developers to build ultra-low latency network applications with full async/await support, seamlessly integrating with popular async runtimes like Tokio and async-std.

The library is designed from the ground up to eliminate unnecessary data copies, allowing applications to process network packets directly from kernel space with minimal overhead. This makes it ideal for high-frequency trading, real-time data processing, network monitoring, and other latency-sensitive applications.

## Features

- **Zero-Copy Networking**: Direct access to kernel packet buffers via AF_XDP
- **Full Async/Await Support**: Native integration with Tokio, async-std, and other async runtimes
- **Type-Safe Packet Handling**: Leverages `zerocopy` for safe, zero-copy packet parsing
- **High Performance**: Optimized for low latency and high throughput
- **Cross-Platform Ready**: Designed with Linux AF_XDP support (with potential for future platform expansion)

## Architecture

### Core Components

- **AF_XDP Socket Abstraction**: High-level wrapper around Linux AF_XDP sockets
- **Async Runtime Integration**: Seamless integration with async runtimes through custom futures and executors
- **Zero-Copy Buffer Management**: Efficient memory management for packet buffers
- **Packet Sharding**: Intelligent packet fragmentation and reassembly

### Design Principles

1. **Zero-Copy First**: All operations are designed to avoid unnecessary memory copies
2. **Async-Native**: Built with async/await as a first-class citizen
3. **Runtime Agnostic**: Works with any async runtime that implements the necessary traits
4. **Type Safety**: Leverages Rust's type system to prevent common networking errors
5. **Performance**: Optimized for both latency and throughput

## Installation

Add voidnet to your `Cargo.toml`:

```toml
[dependencies]
voidnet = "0.1.0"
```

For async runtime support, you'll also need one of:

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
# or
async-std = "1.12"
```

## Quick Start

### Basic Example

```rust
use voidnet::Socket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an AF_XDP socket bound to a network interface
    let mut socket = Socket::bind("eth0", 0)?;
    
    // Read packets asynchronously
    loop {
        let packet = socket.read().await?;
        // Process packet with zero-copy access
        println!("Received packet: {} bytes", packet.len());
    }
}
```

## Requirements

- **Linux Kernel**: 4.18+ (for AF_XDP support)
- **Rust**: 1.70+ (2024 edition)
- **Privileges**: Root or `CAP_NET_RAW` capability for raw socket operations
- **Network Interface**: XDP-compatible network interface

## Performance Considerations

- **Memory**: AF_XDP uses shared memory between kernel and userspace - ensure adequate memory allocation
- **CPU Affinity**: For best performance, pin threads to specific CPU cores
- **Batch Processing**: Process packets in batches when possible to amortize syscall overhead
- **Buffer Sizes**: Tune UMEM and ring buffer sizes based on your workload

## API Documentation

Full API documentation is available at [docs.rs/voidnet](https://docs.rs/voidnet) (once published).

Key modules:
- `voidnet::socket` - Main AF_XDP socket interface
- `voidnet::packet` - Zero-copy packet types

## Examples

See the `examples/` directory for more comprehensive examples:
- Basic packet capture
- High-throughput forwarding
- Erasure-coded transmission
- Integration with Tokio streams

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

[License information to be added]

## Related Projects

- [libbpf-rs](https://github.com/libbpf/libbpf-rs) - Rust bindings for libbpf
- [xdp-tools](https://github.com/xdp-project/xdp-tools) - XDP utilities and examples
