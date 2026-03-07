# TCP Echo Examples Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Write TCP echo server and client examples to validate the TCP stack end-to-end on real hardware.

**Architecture:** Two standalone example binaries mirroring the existing `udp-server.rs`/`udp-client.rs` pattern. Both use `BaseArgs` from `examples/common/mod.rs`, `LocalRuntime::builder()`, `ctrlc` for Ctrl-C, and the `libvoid` TCP socket API. No library code changes.

**Tech Stack:** Rust, `clap` (CLI args), `ctrlc` (signal handling), `libvoid` (`TcpListener`, `TcpStream`, `LocalRuntime`)

---

### Task 1: TCP Echo Server

**Files:**
- Create: `examples/tcp-echo-server.rs`
- Reference: `examples/udp-server.rs` (pattern to follow)
- Reference: `examples/common/mod.rs` (`BaseArgs`, `Stats`)
- Reference: `src/net/socket/tcp.rs` (`TcpListener`, `TcpStream` API)
- Reference: `src/net/socket/mod.rs` (public exports)

**Context:**

The existing UDP server pattern is:
1. Parse `Args` with `#[derive(Parser)]` containing `#[command(flatten)] base: BaseArgs` plus custom args
2. Implement `Deref`/`DerefMut` to `BaseArgs` so `args.if_name`, `args.queue`, etc. work directly
3. Build `LocalRuntime` from all base args
4. Set up `ctrlc` handler with `Arc<AtomicBool>`
5. Call `runtime.run(exit, async move { ... })`

The TCP socket API:
- `TcpListener::listen(addr: IpAddress, port: u16) -> Result<Self, BindError>`
- `listener.accept() -> Accept` (future resolving to `TcpStream`)
- `stream.read(buf: &mut [u8]) -> TcpRead` (future resolving to `usize`, 0 = EOF)
- `stream.write(data: &[u8]) -> TcpWrite` (future resolving to `usize`)
- `stream.remote_addr() -> IpAddress` and `stream.remote_port() -> u16`
- Stream drops trigger graceful FIN close automatically

**Step 1: Write the server example**

Create `examples/tcp-echo-server.rs` with this content:

```rust
use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;

use libvoid::net::{
    socket::TcpListener,
    wire::ip::SocketAddr,
};
use libvoid::rt::LocalRuntime;

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about = "TCP echo server", long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:8080")]
    local_addr: SocketAddr,
}

impl Deref for Args {
    type Target = BaseArgs;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

    let mut runtime = LocalRuntime::builder(&args.if_name, args.queue)
        .arp_ttl(Duration::from_secs(1200))
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .copy_mode(args.copy_mode)
        .build()
        .expect("Failed to create runtime");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    runtime
        .run(exit, async move {
            let listener = TcpListener::listen(args.local_addr.ip, args.local_addr.port)
                .expect("Failed to listen");
            println!("Listening on {}", args.local_addr);

            loop {
                let stream = listener.accept().await;
                println!(
                    "Accepted connection from {}:{}",
                    stream.remote_addr(),
                    stream.remote_port()
                );

                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).await;
                    if n == 0 {
                        println!(
                            "Connection closed from {}:{}",
                            stream.remote_addr(),
                            stream.remote_port()
                        );
                        break;
                    }
                    stream.write(&buf[..n]).await;
                    stats.update(n, false);
                    stats.maybe_print();
                }
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
```

**Step 2: Verify it compiles**

Run: `cargo build --example tcp-echo-server --features local`
Expected: Compiles successfully (may have warnings, no errors)

**Step 3: Commit**

```bash
git add examples/tcp-echo-server.rs
git commit -m "feat: add TCP echo server example"
```

---

### Task 2: TCP Echo Client

**Files:**
- Create: `examples/tcp-echo-client.rs`
- Reference: `examples/udp-client.rs` (pattern to follow)
- Reference: `examples/common/mod.rs` (`BaseArgs`, `Stats`)
- Reference: `src/net/socket/tcp.rs` (`TcpStream::connect` API)

**Context:**

The TCP connect API:
- `TcpStream::connect(local_addr, local_port, remote_addr, remote_port) -> Result<Connect, TcpError>`
- `Connect` is a future resolving to `Result<TcpStream, TcpError>`
- Once connected, use `stream.write()` and `stream.read()` as in the server

**Step 1: Write the client example**

Create `examples/tcp-echo-client.rs` with this content:

```rust
use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;

use libvoid::net::{
    socket::TcpStream,
    wire::ip::SocketAddr,
};
use libvoid::rt::LocalRuntime;

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about = "TCP echo client", long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::2]:8080")]
    local_addr: SocketAddr,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:8080")]
    remote_addr: SocketAddr,
    #[arg(short, long, default_value = "64")]
    message_size: usize,
}

impl Deref for Args {
    type Target = BaseArgs;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

    let mut runtime = LocalRuntime::builder(&args.if_name, args.queue)
        .arp_ttl(Duration::from_secs(1200))
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .copy_mode(args.copy_mode)
        .build()
        .expect("Failed to create runtime");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let message_size = args.message_size;

    runtime
        .run(exit, async move {
            println!(
                "Connecting from {} to {}...",
                args.local_addr, args.remote_addr
            );

            let stream = TcpStream::connect(
                args.local_addr.ip,
                args.local_addr.port,
                args.remote_addr.ip,
                args.remote_addr.port,
            )
            .expect("Failed to initiate connection")
            .await
            .expect("Connection failed");

            println!(
                "Connected to {}:{}",
                stream.remote_addr(),
                stream.remote_port()
            );

            let payload = vec![0xABu8; message_size];
            let mut read_buf = vec![0u8; message_size];

            loop {
                stream.write(&payload).await;

                let mut total_read = 0;
                while total_read < message_size {
                    let n = stream.read(&mut read_buf[total_read..]).await;
                    if n == 0 {
                        println!("Server closed connection");
                        return;
                    }
                    total_read += n;
                }

                stats.update(total_read, false);
                stats.maybe_print();
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
```

**Step 2: Verify it compiles**

Run: `cargo build --example tcp-echo-client --features local`
Expected: Compiles successfully (may have warnings, no errors)

**Step 3: Commit**

```bash
git add examples/tcp-echo-client.rs
git commit -m "feat: add TCP echo client example"
```

---

### Dependency Graph

```
Task 1 (server) ──┐
                   ├── independent, can be done in parallel
Task 2 (client) ──┘
```

Both tasks are independent — no shared code changes, no ordering dependency.

### How to Test End-to-End

After both examples compile, test on two machines (or two network namespaces) connected via XDP-compatible interfaces:

**Terminal 1 (server):**
```bash
cargo run --example tcp-echo-server --features local -- --if-name eth0 --queue 0 --local-addr "[fc00:dead:cafe:1::1]:8080"
```

**Terminal 2 (client):**
```bash
cargo run --example tcp-echo-client --features local -- --if-name eth0 --queue 0 --local-addr "[fc00:dead:cafe:1::2]:8080" --remote-addr "[fc00:dead:cafe:1::1]:8080" --message-size 64
```

Expected: Client connects, sends 64-byte messages, receives echoes, prints stats periodically. Ctrl-C on either side triggers graceful close.
