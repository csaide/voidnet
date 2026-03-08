# TCP Per-Connection Benchmarks Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement criterion-based TCP throughput and latency benchmarks over a veth pair, with data integrity validation.

**Architecture:** Two benchmark files using `criterion::iter_custom` with `TestVethPair` + two `LocalRuntime` instances on separate threads. Each benchmark times only the data transfer phase, not setup/teardown.

**Tech Stack:** criterion 0.8, `TestVethPair`, `LocalRuntime`, `TcpListener`/`TcpStream`, `std::thread`, `std::sync::Barrier`

---

## Context for the Implementer

### Key APIs

**`TestVethPair`** (`src/xdp/test_utils.rs`):
- `TestVethPair::new()` creates a veth pair with unique names/addresses
- `.outer_name()` / `.inner_name()` — interface names for each end
- `.addresses()` returns `VethAddresses` with `.outer_ipv4`, `.inner_ipv4`, `.outer_ipv6`, `.inner_ipv6`
- Automatically cleaned up on `Drop`

**`LocalRuntime`** (`src/rt/local.rs`):
- `LocalRuntime::builder(if_name, queue).build()` creates a runtime
- `.run(exit: Arc<AtomicBool>, fut: impl Future<Output=()>)` runs the event loop
- Returns `Ok(())` when the future completes or `exit` flag is set
- Must be called with root privileges

**`TcpListener`** / **`TcpStream`** (`src/net/socket/tcp.rs`):
- `TcpListener::listen(addr, port)` — must be called inside `runtime.run()`
- `.accept().await` returns `TcpStream`
- `TcpStream::connect(local_addr, local_port, remote_addr, remote_port)?.await?`
- `.write(data).await -> Result<usize, TcpError>`
- `.read(buf).await -> Result<usize, TcpError>`
- `.shutdown()` — half-close (sends FIN, keeps read side open)
- `.close()` — full close

**IP Addresses**: use IPv4 addresses from `VethAddresses` — `.outer_ipv4` and `.inner_ipv4` (e.g. `10.11.0.1`, `10.11.0.2`). Wrap them with `IpAddress::Ipv4(addr)`.

**Import paths**:
```rust
use libvoid::xdp::test_utils::TestVethPair;
use libvoid::rt::LocalRuntime;
use libvoid::net::socket::{TcpListener, TcpStream};
use libvoid::net::wire::ip::IpAddress;
```

### Criterion `iter_custom` pattern

```rust
use criterion::{Criterion, criterion_group, criterion_main, BenchmarkId, Throughput};
use std::time::Instant;

// Inside a benchmark function:
group.bench_function("name", |b| {
    b.iter_custom(|iters| {
        // iters = number of iterations criterion wants
        // Return total Duration for all iterations
        let start = Instant::now();
        for _ in 0..iters {
            // do the work
        }
        start.elapsed()
    });
});
```

### Thread coordination pattern

Each benchmark needs two `LocalRuntime` instances on separate threads because `LocalRuntime::run()` blocks. The pattern:

1. Create `TestVethPair` (lives on the main/benchmark thread)
2. Create `Arc<AtomicBool>` exit flag and `std::sync::Barrier(2)`
3. Spawn server thread: builds runtime on one veth end, signals barrier, runs workload
4. In benchmark closure: build runtime on other veth end, signal barrier, run measurement
5. After measurement: set exit flag, join server thread

**IMPORTANT**: `TestVethPair` is NOT `Send` — it must stay on the thread that created it. Pass `.outer_name().to_owned()` and `.inner_name().to_owned()` (as `String`) plus addresses to the spawned thread.

**IMPORTANT**: Each `LocalRuntime` must be built on the thread that calls `.run()`. Do not build a runtime and move it across threads.

### Running benchmarks

```bash
cargo bench --bench tcp_throughput
cargo bench --bench tcp_latency
```

Requires root — `.cargo/config.toml` configures `sudo -E` as the runner.

### Port allocation

Use a fixed base port and add the veth pair_id to avoid conflicts if multiple benchmarks run:
```rust
let port = 9000 + veth.pair_id() as u16;
```

---

## Task 1: Add bench entries to Cargo.toml

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add the bench entries**

Add at the end of `Cargo.toml`:

```toml
[[bench]]
name = "tcp_throughput"
harness = false

[[bench]]
name = "tcp_latency"
harness = false
```

**Step 2: Create empty bench files**

Create `benches/tcp_throughput.rs`:
```rust
use criterion::{Criterion, criterion_group, criterion_main};

fn tcp_throughput(_c: &mut Criterion) {
    // TODO: implement
}

criterion_group!(benches, tcp_throughput);
criterion_main!(benches);
```

Create `benches/tcp_latency.rs`:
```rust
use criterion::{Criterion, criterion_group, criterion_main};

fn tcp_latency(_c: &mut Criterion) {
    // TODO: implement
}

criterion_group!(benches, tcp_latency);
criterion_main!(benches);
```

**Step 3: Verify it compiles**

Run: `cargo bench --bench tcp_throughput --no-run && cargo bench --bench tcp_latency --no-run`
Expected: compiles successfully (no tests run)

**Step 4: Commit**

```bash
git add Cargo.toml benches/tcp_throughput.rs benches/tcp_latency.rs
git commit -m "feat(bench): add skeleton criterion bench files for TCP throughput and latency"
```

---

## Task 2: Implement throughput benchmark

**Files:**
- Modify: `benches/tcp_throughput.rs`

**Step 1: Write the full benchmark**

Replace `benches/tcp_throughput.rs` with:

```rust
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use libvoid::net::socket::TcpListener;
use libvoid::net::socket::TcpStream;
use libvoid::net::wire::ip::IpAddress;
use libvoid::rt::LocalRuntime;
use libvoid::xdp::test_utils::TestVethPair;

const TRANSFER_SIZE: u64 = 1_024 * 1_024 * 1_024; // 1 GB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Fill a buffer with a deterministic pattern for integrity checking.
/// Uses (byte_offset % 251) — 251 is prime to avoid alignment tricks.
fn fill_pattern(buf: &mut [u8], offset: u64) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = ((offset + i as u64) % 251) as u8;
    }
}

/// Compute a simple checksum over a buffer starting at a given byte offset.
/// Returns the running sum.
fn checksum_pattern(buf: &[u8], offset: u64) -> u64 {
    let mut bad = 0u64;
    for (i, &byte) in buf.iter().enumerate() {
        let expected = ((offset + i as u64) % 251) as u8;
        if byte != expected {
            bad += 1;
        }
    }
    bad
}

fn tcp_throughput(c: &mut Criterion) {
    let veth = TestVethPair::new().expect("failed to create veth pair");
    let addrs = *veth.addresses();
    let server_if = veth.inner_name().to_owned();
    let client_if = veth.outer_name().to_owned();
    let port = 9000 + veth.pair_id() as u16;

    let server_ip = IpAddress::Ipv4(addrs.inner_ipv4);
    let client_ip = IpAddress::Ipv4(addrs.outer_ipv4);

    let mut group = c.benchmark_group("tcp_throughput");
    group.throughput(Throughput::Bytes(TRANSFER_SIZE));
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(120));

    group.bench_function("1GB_transfer", |b| {
        b.iter_custom(|iters| {
            let mut total_elapsed = std::time::Duration::ZERO;

            for _ in 0..iters {
                let exit = Arc::new(AtomicBool::new(false));
                let barrier = Arc::new(Barrier::new(2));
                let integrity_errors = Arc::new(AtomicU64::new(0));

                // Server thread: receive and verify data.
                let server_exit = exit.clone();
                let server_barrier = barrier.clone();
                let server_errors = integrity_errors.clone();
                let server_if = server_if.clone();

                let server_handle = std::thread::spawn(move || {
                    let mut runtime = LocalRuntime::builder(&server_if, 0)
                        .build()
                        .expect("server runtime build failed");

                    runtime
                        .run(server_exit, async move {
                            let listener = TcpListener::listen(server_ip, port)
                                .expect("listen failed");

                            server_barrier.wait();

                            let stream = listener.accept().await;
                            let mut buf = vec![0u8; CHUNK_SIZE];
                            let mut total_received: u64 = 0;
                            let mut errors: u64 = 0;

                            loop {
                                let n = match stream.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => n,
                                    Err(_) => break,
                                };
                                errors += checksum_pattern(&buf[..n], total_received);
                                total_received += n as u64;
                            }

                            server_errors.store(errors, Ordering::Relaxed);
                        })
                        .expect("server runtime run failed");
                });

                // Wait for server to be listening.
                barrier.wait();

                // Give server a moment to set up the listen socket.
                std::thread::sleep(std::time::Duration::from_millis(50));

                // Client: connect, send 1 GB, measure time.
                let client_exit = exit.clone();
                let client_if = client_if.clone();

                let elapsed = {
                    let (tx, rx) = std::sync::mpsc::channel();
                    let client_handle = std::thread::spawn(move || {
                        let mut runtime = LocalRuntime::builder(&client_if, 0)
                            .build()
                            .expect("client runtime build failed");

                        runtime
                            .run(client_exit, async move {
                                let mut stream = TcpStream::connect(
                                    client_ip, port, server_ip, port,
                                )
                                .expect("connect initiation failed")
                                .await
                                .expect("connect failed");

                                let mut send_buf = vec![0u8; CHUNK_SIZE];
                                let mut bytes_sent: u64 = 0;

                                let start = Instant::now();

                                while bytes_sent < TRANSFER_SIZE {
                                    let remaining = (TRANSFER_SIZE - bytes_sent) as usize;
                                    let chunk = remaining.min(CHUNK_SIZE);
                                    fill_pattern(&mut send_buf[..chunk], bytes_sent);

                                    stream.write(&send_buf[..chunk]).await
                                        .expect("write failed");
                                    bytes_sent += chunk as u64;
                                }

                                stream.shutdown();

                                let elapsed = start.elapsed();
                                tx.send(elapsed).unwrap();
                            })
                            .expect("client runtime run failed");
                    });

                    let elapsed = rx.recv().expect("failed to receive elapsed time");
                    client_handle.join().expect("client thread panicked");
                    elapsed
                };

                // Wait for server to finish.
                exit.store(true, Ordering::Relaxed);
                server_handle.join().expect("server thread panicked");

                let errors = integrity_errors.load(Ordering::Relaxed);
                assert_eq!(errors, 0, "data integrity check failed: {} byte mismatches", errors);

                total_elapsed += elapsed;
            }

            total_elapsed
        });
    });

    group.finish();
}

criterion_group!(benches, tcp_throughput);
criterion_main!(benches);
```

**Step 2: Verify it compiles**

Run: `cargo bench --bench tcp_throughput --no-run`
Expected: compiles successfully

**Step 3: Run the benchmark**

Run: `cargo bench --bench tcp_throughput`
Expected: criterion runs 10 samples, reports throughput in GB/s or MB/s, no integrity errors

**Step 4: Commit**

```bash
git add benches/tcp_throughput.rs
git commit -m "feat(bench): implement 1GB TCP throughput benchmark with integrity check"
```

---

## Task 3: Implement latency benchmark

**Files:**
- Modify: `benches/tcp_latency.rs`

**Step 1: Write the full benchmark**

Replace `benches/tcp_latency.rs` with:

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use libvoid::net::socket::TcpListener;
use libvoid::net::socket::TcpStream;
use libvoid::net::wire::ip::IpAddress;
use libvoid::rt::LocalRuntime;
use libvoid::xdp::test_utils::TestVethPair;

const ROUND_TRIPS: u64 = 10_000;

fn tcp_latency(c: &mut Criterion) {
    let veth = TestVethPair::new().expect("failed to create veth pair");
    let addrs = *veth.addresses();
    let server_if = veth.inner_name().to_owned();
    let client_if = veth.outer_name().to_owned();
    let port = 9100 + veth.pair_id() as u16;

    let server_ip = IpAddress::Ipv4(addrs.inner_ipv4);
    let client_ip = IpAddress::Ipv4(addrs.outer_ipv4);

    let mut group = c.benchmark_group("tcp_latency");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(60));

    for msg_size in [64usize, 1024] {
        group.bench_with_input(
            BenchmarkId::new("round_trip", format!("{}B", msg_size)),
            &msg_size,
            |b, &msg_size| {
                b.iter_custom(|iters| {
                    let mut total_elapsed = std::time::Duration::ZERO;

                    for _ in 0..iters {
                        let exit = Arc::new(AtomicBool::new(false));
                        let barrier = Arc::new(Barrier::new(2));

                        // Server thread: echo loop.
                        let server_exit = exit.clone();
                        let server_barrier = barrier.clone();
                        let server_if = server_if.clone();

                        let server_handle = std::thread::spawn(move || {
                            let mut runtime = LocalRuntime::builder(&server_if, 0)
                                .build()
                                .expect("server runtime build failed");

                            runtime
                                .run(server_exit, async move {
                                    let listener = TcpListener::listen(server_ip, port)
                                        .expect("listen failed");

                                    server_barrier.wait();

                                    let stream = listener.accept().await;
                                    let mut buf = vec![0u8; msg_size];

                                    loop {
                                        // Read exactly msg_size bytes.
                                        let mut total_read = 0;
                                        while total_read < msg_size {
                                            let n = match stream.read(&mut buf[total_read..]).await {
                                                Ok(0) => return,
                                                Ok(n) => n,
                                                Err(_) => return,
                                            };
                                            total_read += n;
                                        }

                                        // Echo back.
                                        if stream.write(&buf[..msg_size]).await.is_err() {
                                            return;
                                        }
                                    }
                                })
                                .expect("server runtime run failed");
                        });

                        // Wait for server to be listening.
                        barrier.wait();
                        std::thread::sleep(std::time::Duration::from_millis(50));

                        // Client: connect, do round-trips, measure time.
                        let client_exit = exit.clone();
                        let client_if = client_if.clone();

                        let elapsed = {
                            let (tx, rx) = std::sync::mpsc::channel();

                            let client_handle = std::thread::spawn(move || {
                                let mut runtime = LocalRuntime::builder(&client_if, 0)
                                    .build()
                                    .expect("client runtime build failed");

                                runtime
                                    .run(client_exit, async move {
                                        let mut stream = TcpStream::connect(
                                            client_ip, port, server_ip, port,
                                        )
                                        .expect("connect initiation failed")
                                        .await
                                        .expect("connect failed");

                                        let send_buf = vec![0xABu8; msg_size];
                                        let mut recv_buf = vec![0u8; msg_size];

                                        let start = Instant::now();

                                        for _ in 0..ROUND_TRIPS {
                                            stream.write(&send_buf).await
                                                .expect("write failed");

                                            let mut total_read = 0;
                                            while total_read < msg_size {
                                                let n = stream.read(&mut recv_buf[total_read..]).await
                                                    .expect("read failed");
                                                assert!(n > 0, "unexpected EOF");
                                                total_read += n;
                                            }

                                            assert_eq!(
                                                &recv_buf[..msg_size],
                                                &send_buf[..msg_size],
                                                "echo response mismatch"
                                            );
                                        }

                                        let elapsed = start.elapsed();
                                        stream.shutdown();
                                        tx.send(elapsed).unwrap();
                                    })
                                    .expect("client runtime run failed");
                            });

                            let elapsed = rx.recv().expect("failed to receive elapsed time");
                            client_handle.join().expect("client thread panicked");
                            elapsed
                        };

                        exit.store(true, Ordering::Relaxed);
                        server_handle.join().expect("server thread panicked");

                        total_elapsed += elapsed;
                    }

                    total_elapsed
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, tcp_latency);
criterion_main!(benches);
```

**Step 2: Verify it compiles**

Run: `cargo bench --bench tcp_latency --no-run`
Expected: compiles successfully

**Step 3: Run the benchmark**

Run: `cargo bench --bench tcp_latency`
Expected: criterion runs 10 samples for each payload size (64B, 1KB), reports per-round-trip latency stats

**Step 4: Commit**

```bash
git add benches/tcp_latency.rs
git commit -m "feat(bench): implement TCP request-response latency benchmark at 64B and 1KB"
```

---

## Task 4: Run full test suite and both benchmarks

**Files:** None (verification only)

**Step 1: Run tests**

Run: `cargo test`
Expected: all tests pass (546+ unit, 1 integration, 5 doctests)

**Step 2: Run throughput benchmark**

Run: `cargo bench --bench tcp_throughput`
Expected: completes without errors, reports throughput numbers

**Step 3: Run latency benchmark**

Run: `cargo bench --bench tcp_latency`
Expected: completes without errors, reports latency numbers for both 64B and 1KB

**Step 4: Commit (if any fixes were needed)**

Only commit if you had to fix something. Otherwise, this task is just verification.
