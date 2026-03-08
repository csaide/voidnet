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

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use libvoid::net::socket::{TcpListener, TcpStream};
use libvoid::net::wire::ip::{IpAddress, Ipv4Address};
use libvoid::rt::LocalRuntime;
use libvoid::xdp::test_utils::TestVethPair;

const TRANSFER_SIZE: u64 = 1_024 * 1_024 * 1_024; // 1 GB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Fill a buffer with a deterministic pattern for integrity checking.
fn fill_pattern(buf: &mut [u8], offset: u64) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = ((offset + i as u64) % 251) as u8;
    }
}

/// Check buffer against expected pattern. Returns number of mismatches.
fn checksum_pattern(buf: &[u8], offset: u64) -> u64 {
    let mut errors = 0u64;
    for (i, &byte) in buf.iter().enumerate() {
        let expected = ((offset + i as u64) % 251) as u8;
        if byte != expected {
            errors += 1;
        }
    }
    errors
}

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

fn tcp_throughput(c: &mut Criterion) {
    let veth = TestVethPair::new().expect("failed to create veth pair");
    let addrs = *veth.addresses();
    let server_if = veth.inner_name().to_owned();
    let client_if = veth.outer_name().to_owned();
    let port = 9000 + veth.pair_id() as u16;

    let server_ip = IpAddress::V4(Ipv4Address::new(addrs.inner_ipv4.octets()));
    let client_ip = IpAddress::V4(Ipv4Address::new(addrs.outer_ipv4.octets()));

    let mut group = c.benchmark_group("tcp_throughput");
    group.throughput(Throughput::Bytes(TRANSFER_SIZE));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(300));

    group.bench_function("1gb_transfer", |b| {
        b.iter_custom(|iters| {
            let mut total_elapsed = Duration::ZERO;

            for _ in 0..iters {
                let exit = Arc::new(AtomicBool::new(false));
                let barrier = Arc::new(Barrier::new(2));
                let integrity_errors = Arc::new(AtomicU64::new(0));
                let server_done = Arc::new(AtomicBool::new(false));

                // --- Server thread ---
                let server_exit = exit.clone();
                let server_barrier = barrier.clone();
                let server_errors = integrity_errors.clone();
                let server_if = server_if.clone();
                let server_done_flag = server_done.clone();

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
                            let mut buf = vec![0u8; CHUNK_SIZE];
                            let mut total_received: u64 = 0;

                            loop {
                                let n = match stream.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => n,
                                    Err(_) => break,
                                };
                                let errs = checksum_pattern(&buf[..n], total_received);
                                if errs > 0 {
                                    server_errors.fetch_add(errs, Ordering::Relaxed);
                                }
                                total_received += n as u64;
                            }

                            server_done_flag.store(true, Ordering::Relaxed);
                        })
                        .expect("server runtime run failed");
                });

                barrier.wait();
                thread::sleep(Duration::from_millis(50));

                // --- Client thread ---
                let client_exit = exit.clone();
                let client_if = client_if.clone();
                let (time_tx, time_rx) = mpsc::channel();
                let client_port = port + 1;
                let client_done = server_done.clone();

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

                            let mut send_buf = vec![0u8; CHUNK_SIZE];
                            let mut bytes_sent: u64 = 0;

                            let start = Instant::now();

                            while bytes_sent < TRANSFER_SIZE {
                                let remaining = (TRANSFER_SIZE - bytes_sent) as usize;
                                let chunk = remaining.min(CHUNK_SIZE);
                                fill_pattern(&mut send_buf[..chunk], bytes_sent);

                                stream
                                    .write(&send_buf[..chunk])
                                    .await
                                    .expect("write failed");
                                bytes_sent += chunk as u64;
                            }

                            stream.shutdown();

                            // Keep runtime alive until server confirms receipt.
                            WaitForFlag(client_done).await;

                            let elapsed = start.elapsed();
                            time_tx.send(elapsed).unwrap();
                        })
                        .expect("client runtime run failed");
                });

                let elapsed = time_rx.recv().expect("failed to receive elapsed time");
                client_handle.join().expect("client thread panicked");

                exit.store(true, Ordering::Relaxed);
                server_handle.join().expect("server thread panicked");

                let errors = integrity_errors.load(Ordering::Relaxed);
                assert_eq!(
                    errors, 0,
                    "data integrity check failed: {} byte mismatches",
                    errors
                );

                total_elapsed += elapsed;
            }

            total_elapsed
        });
    });

    group.finish();
}

criterion_group!(benches, tcp_throughput);
criterion_main!(benches);
