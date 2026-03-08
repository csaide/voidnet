use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use libvoid::net::socket::{TcpListener, TcpStream};
use libvoid::net::wire::ip::{IpAddress, Ipv4Address};
use libvoid::rt::LocalRuntime;
use libvoid::xdp::test_utils::TestVethPair;

const ROUND_TRIPS: u64 = 10_000;

/// A future that resolves when a flag is set.
struct WaitForFlag(Arc<AtomicBool>);

impl Future for WaitForFlag {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.0.load(Ordering::Relaxed) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Fill a buffer with a deterministic pattern.
fn fill_pattern(buf: &mut [u8], seed: u64) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = ((seed + i as u64) % 251) as u8;
    }
}

/// Run a single latency measurement: `round_trips` request-response exchanges
/// of `size` bytes over a fresh veth pair. Returns the total wall-clock time
/// for all round trips.
fn run_latency_iteration(size: usize) -> Duration {
    let veth = TestVethPair::new().expect("failed to create veth pair");
    let addrs = *veth.addresses();
    let server_if = veth.inner_name().to_owned();
    let client_if = veth.outer_name().to_owned();
    let port = 9100 + veth.pair_id() as u16;

    let server_ip = IpAddress::V4(Ipv4Address::new(addrs.inner_ipv4.octets()));
    let client_ip = IpAddress::V4(Ipv4Address::new(addrs.outer_ipv4.octets()));

    let exit = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let server_done = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicU64::new(0));

    // --- Server thread (echo loop) ---
    let server_exit = exit.clone();
    let server_barrier = barrier.clone();
    let server_done_flag = server_done.clone();

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
                let mut buf = vec![0u8; size];

                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if stream.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }

                server_done_flag.store(true, Ordering::Relaxed);
            })
            .expect("server runtime run failed");
    });

    barrier.wait();
    thread::sleep(Duration::from_millis(50));

    // --- Client thread (request-response loop) ---
    let client_exit = exit.clone();
    let (time_tx, time_rx) = mpsc::channel();
    let client_port = port + 1;
    let client_done = server_done.clone();
    let client_errors = errors.clone();

    let client_handle = thread::spawn(move || {
        let mut runtime = LocalRuntime::builder(&client_if, 0)
            .build()
            .expect("client runtime build failed");

        runtime
            .run(client_exit.clone(), async move {
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

                let start = Instant::now();

                for round in 0..ROUND_TRIPS {
                    fill_pattern(&mut send_buf, round);

                    stream.write(&send_buf).await.expect("write failed");

                    // Read back full response.
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

                    // Verify echo matches.
                    if recv_buf[..received] != send_buf[..received] {
                        client_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                let elapsed = start.elapsed();
                time_tx.send(elapsed).unwrap();

                stream.shutdown();
                WaitForFlag(client_done).await;
            })
            .expect("client runtime run failed");
    });

    let elapsed = time_rx.recv().expect("failed to receive elapsed time");
    client_handle.join().expect("client thread panicked");

    exit.store(true, Ordering::Relaxed);
    server_handle.join().expect("server thread panicked");

    let errs = errors.load(Ordering::Relaxed);
    assert_eq!(errs, 0, "echo integrity check failed: {} mismatches", errs);

    elapsed
}

fn tcp_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_latency");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(300));

    for payload_size in [64, 1024] {
        group.bench_with_input(
            BenchmarkId::new("rtt", payload_size),
            &payload_size,
            |b, &size| {
                b.iter_custom(|iters| {
                    let mut total_elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        let elapsed = run_latency_iteration(size);
                        // Report per-round-trip time.
                        total_elapsed += elapsed / ROUND_TRIPS as u32;
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
