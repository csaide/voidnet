# TCP Benchmarks Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite tcp_throughput and tcp_latency benchmarks so the iteration loop runs inside the async future over a single TCP connection, not per-iteration infrastructure teardown/rebuild.

**Architecture:** Each benchmark creates a `TestVethPair` once at group level. Each `iter_custom` call spawns server/client threads with one `LocalRuntime` each, establishes one TCP connection, then loops `iters` times over the measured work inside the async future. An `AtomicU16` port counter prevents TIME_WAIT collisions between samples.

**Tech Stack:** Rust, criterion, libvoid (TcpListener, TcpStream, LocalRuntime, TestVethPair)

---

### Task 1: Rewrite `benches/tcp_throughput.rs`

**Files:**
- Modify: `benches/tcp_throughput.rs` (full rewrite)

**Step 1: Replace file contents**

```rust
use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU16, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use libvoid::net::socket::{TcpListener, TcpStream};
use libvoid::net::wire::ip::{IpAddress, Ipv4Address};
use libvoid::rt::LocalRuntime;
use libvoid::xdp::test_utils::TestVethPair;

const TRANSFER_SIZE: u64 = 1_024 * 1_024 * 1_024; // 1 GB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB

fn tcp_throughput(c: &mut Criterion) {
    let veth = TestVethPair::new().expect("failed to create veth pair");
    let addrs = *veth.addresses();
    let server_if = veth.inner_name().to_owned();
    let client_if = veth.outer_name().to_owned();
    let base_port = 9000 + (veth.pair_id() as u16) * 100;
    let port_counter = AtomicU16::new(0);

    let server_ip = IpAddress::V4(Ipv4Address::new(addrs.inner_ipv4.octets()));
    let client_ip = IpAddress::V4(Ipv4Address::new(addrs.outer_ipv4.octets()));

    let mut group = c.benchmark_group("tcp_throughput");
    group.throughput(Throughput::Bytes(TRANSFER_SIZE));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(300));

    group.bench_function("1gb_transfer", |b| {
        b.iter_custom(|iters| {
            let port = base_port + port_counter.fetch_add(1, Ordering::Relaxed);
            let exit = Arc::new(AtomicBool::new(false));
            let barrier = Arc::new(Barrier::new(2));

            // --- Server thread (sink) ---
            let server_exit = exit.clone();
            let server_barrier = barrier.clone();
            let server_if = server_if.clone();

            let server_handle = thread::spawn(move || {
                let mut runtime = LocalRuntime::builder(&server_if, 0)
                    .build()
                    .expect("server runtime build failed");

                runtime
                    .run(server_exit, async move {
                        let listener =
                            TcpListener::listen(server_ip, port).expect("listen failed");

                        server_barrier.wait();

                        let stream = listener.accept().await;
                        let mut buf = vec![0u8; CHUNK_SIZE];

                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    })
                    .expect("server runtime run failed");
            });

            barrier.wait();
            thread::sleep(Duration::from_millis(50));

            // --- Client thread (sender) ---
            let client_if = client_if.clone();
            let (time_tx, time_rx) = mpsc::channel();
            let client_port = port + 50;

            let client_handle = thread::spawn(move || {
                let mut runtime = LocalRuntime::builder(&client_if, 0)
                    .build()
                    .expect("client runtime build failed");

                runtime
                    .run(Arc::new(AtomicBool::new(false)), async move {
                        let mut stream = TcpStream::connect(
                            client_ip,
                            client_port,
                            server_ip,
                            port,
                        )
                        .expect("connect initiation failed")
                        .await
                        .expect("connect failed");

                        let send_buf = vec![0u8; CHUNK_SIZE];

                        let start = Instant::now();

                        for _ in 0..iters {
                            let mut bytes_sent: u64 = 0;
                            while bytes_sent < TRANSFER_SIZE {
                                let remaining = (TRANSFER_SIZE - bytes_sent) as usize;
                                let chunk = remaining.min(CHUNK_SIZE);
                                stream
                                    .write(&send_buf[..chunk])
                                    .await
                                    .expect("write failed");
                                bytes_sent += chunk as u64;
                            }
                        }

                        let elapsed = start.elapsed();
                        time_tx.send(elapsed).unwrap();

                        stream.shutdown();
                    })
                    .expect("client runtime run failed");
            });

            let elapsed = time_rx.recv().expect("failed to receive elapsed time");
            client_handle.join().expect("client thread panicked");

            exit.store(true, Ordering::Relaxed);
            server_handle.join().expect("server thread panicked");

            elapsed
        });
    });

    group.finish();
}

criterion_group!(benches, tcp_throughput);
criterion_main!(benches);
```

Key changes from the broken version:
- Removed `fill_pattern`, `checksum_pattern`, `WaitForFlag`, integrity checking
- `for _ in 0..iters` loop is INSIDE the async block, after connect, wrapping only sends
- Single TCP connection serves all iterations within a sample
- `AtomicU16` port counter prevents TIME_WAIT collisions between samples
- Client future completes naturally after shutdown (no `WaitForFlag`)
- Client gets its own private exit flag (never set) — runtime exits when future completes
- `send_buf` is zeroed once — no `fill_pattern` overhead

**Step 2: Verify it compiles**

Run: `cargo build --bench tcp_throughput`
Expected: compiles without errors

**Step 3: Commit**

```bash
git add benches/tcp_throughput.rs
git commit -m "fix(bench): rewrite tcp_throughput to iterate inside async future

Move the criterion iteration loop inside the async block so a single
TCP connection serves all iterations. Removes per-iteration veth/runtime
teardown that dominated measurement time."
```

---

### Task 2: Rewrite `benches/tcp_latency.rs`

**Files:**
- Modify: `benches/tcp_latency.rs` (full rewrite)

**Step 1: Replace file contents**

```rust
use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use libvoid::net::socket::{TcpListener, TcpStream};
use libvoid::net::wire::ip::{IpAddress, Ipv4Address};
use libvoid::rt::LocalRuntime;
use libvoid::xdp::test_utils::TestVethPair;

const ROUND_TRIPS: u64 = 10_000;

/// Fill a buffer with a deterministic pattern.
fn fill_pattern(buf: &mut [u8], seed: u64) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = ((seed + i as u64) % 251) as u8;
    }
}

fn tcp_latency(c: &mut Criterion) {
    let veth = TestVethPair::new().expect("failed to create veth pair");
    let addrs = *veth.addresses();
    let server_if = veth.inner_name().to_owned();
    let client_if = veth.outer_name().to_owned();
    let base_port = 9100 + (veth.pair_id() as u16) * 100;
    let port_counter = AtomicU16::new(0);

    let server_ip = IpAddress::V4(Ipv4Address::new(addrs.inner_ipv4.octets()));
    let client_ip = IpAddress::V4(Ipv4Address::new(addrs.outer_ipv4.octets()));

    let mut group = c.benchmark_group("tcp_latency");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(300));

    for payload_size in [64, 1024] {
        group.bench_with_input(
            BenchmarkId::new("rtt", payload_size),
            &payload_size,
            |b, &size| {
                b.iter_custom(|iters| {
                    let port = base_port + port_counter.fetch_add(1, Ordering::Relaxed);
                    let exit = Arc::new(AtomicBool::new(false));
                    let barrier = Arc::new(Barrier::new(2));
                    let errors = Arc::new(AtomicU64::new(0));

                    // --- Server thread (echo loop) ---
                    let server_exit = exit.clone();
                    let server_barrier = barrier.clone();
                    let server_if = server_if.clone();

                    let server_handle = thread::spawn(move || {
                        let mut runtime = LocalRuntime::builder(&server_if, 0)
                            .build()
                            .expect("server runtime build failed");

                        runtime
                            .run(server_exit, async move {
                                let listener = TcpListener::listen(server_ip, port)
                                    .expect("listen failed");

                                server_barrier.wait();

                                let stream = listener.accept().await;
                                let mut buf = vec![0u8; size];

                                loop {
                                    let n = match stream.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => n,
                                    };
                                    if stream.write(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            })
                            .expect("server runtime run failed");
                    });

                    barrier.wait();
                    thread::sleep(Duration::from_millis(50));

                    // --- Client thread (request-response loop) ---
                    let client_if = client_if.clone();
                    let (time_tx, time_rx) = mpsc::channel();
                    let client_port = port + 50;
                    let client_errors = errors.clone();

                    let client_handle = thread::spawn(move || {
                        let mut runtime = LocalRuntime::builder(&client_if, 0)
                            .build()
                            .expect("client runtime build failed");

                        runtime
                            .run(Arc::new(AtomicBool::new(false)), async move {
                                let mut stream = TcpStream::connect(
                                    client_ip,
                                    client_port,
                                    server_ip,
                                    port,
                                )
                                .expect("connect initiation failed")
                                .await
                                .expect("connect failed");

                                let mut send_buf = vec![0u8; size];
                                let mut recv_buf = vec![0u8; size];
                                let total_rounds = iters * ROUND_TRIPS;

                                let start = Instant::now();

                                for round in 0..total_rounds {
                                    fill_pattern(&mut send_buf, round);

                                    stream.write(&send_buf).await.expect("write failed");

                                    let mut received = 0;
                                    while received < size {
                                        let n = stream
                                            .read(&mut recv_buf[received..])
                                            .await
                                            .expect("read failed");
                                        if n == 0 {
                                            break;
                                        }
                                        received += n;
                                    }

                                    if recv_buf[..received] != send_buf[..received] {
                                        client_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }

                                let elapsed = start.elapsed();
                                time_tx.send(elapsed).unwrap();

                                stream.shutdown();
                            })
                            .expect("client runtime run failed");
                    });

                    let elapsed = time_rx.recv().expect("failed to receive elapsed time");
                    client_handle.join().expect("client thread panicked");

                    exit.store(true, Ordering::Relaxed);
                    server_handle.join().expect("server thread panicked");

                    let errs = errors.load(Ordering::Relaxed);
                    assert_eq!(
                        errs, 0,
                        "echo integrity check failed: {} mismatches",
                        errs
                    );

                    elapsed
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, tcp_latency);
criterion_main!(benches);
```

Key changes from the broken version:
- Eliminated `run_latency_iteration()` — no per-iteration veth/runtime creation
- Removed `WaitForFlag` future
- `iters * ROUND_TRIPS` loop is INSIDE the async block over a single connection
- Raw elapsed returned — criterion divides by `iters` to get per-iteration (= per ROUND_TRIPS batch) time
- `AtomicU16` port counter prevents TIME_WAIT collisions
- Echo integrity check retained (lightweight validation)
- Client gets its own private exit flag — runtime exits when future completes

**Step 2: Verify it compiles**

Run: `cargo build --bench tcp_latency`
Expected: compiles without errors

**Step 3: Commit**

```bash
git add benches/tcp_latency.rs
git commit -m "fix(bench): rewrite tcp_latency to iterate inside async future

Move the criterion iteration loop inside the async block so a single
TCP connection serves all iterations. Eliminates per-iteration veth/runtime
teardown that dominated measurement time."
```

---

### Task 3: Clean up stale example files

**Files:**
- Delete: `examples/tcp-bench-debug.rs` (if related to old benchmark scaffolding)
- Delete: `examples/tcp-bench-test.rs` (if related to old benchmark scaffolding)

**Step 1: Check if these files are benchmark scaffolding**

Run: `head -20 examples/tcp-bench-debug.rs examples/tcp-bench-test.rs`

If they are old benchmark test harnesses, delete them. If they serve a different purpose, leave them.

**Step 2: Commit (if deleted)**

```bash
git rm examples/tcp-bench-debug.rs examples/tcp-bench-test.rs
git commit -m "chore: remove stale benchmark scaffolding examples"
```
