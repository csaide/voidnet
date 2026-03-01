use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use libvoid::{
    net::{
        TcpRecvResult,
        wire::{ethernet::MacAddress as WireMac, ip::IpAddress},
    },
    rt::LocalRuntime,
    xdp::test_utils::TestVethPair,
};

#[test]
fn test_tcp_connect() {
    let veth = TestVethPair::new().expect("failed to create veth pair");

    let server_ip: IpAddress = veth.addresses().inner_ipv4.into();
    let client_ip: IpAddress = veth.addresses().outer_ipv4.into();
    let server_mac_bytes = *veth.inner_mac().as_bytes();
    let client_mac_bytes = *veth.outer_mac().as_bytes();

    let server_exit = Arc::new(AtomicBool::new(false));
    let client_exit = Arc::new(AtomicBool::new(false));
    let client_done = Arc::new(AtomicBool::new(false));

    let start = Instant::now();

    // Watchdog: force exit after 5 seconds.
    let wd_server_exit = server_exit.clone();
    let wd_client_exit = client_exit.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(5));
        wd_server_exit.store(true, Ordering::Relaxed);
        wd_client_exit.store(true, Ordering::Relaxed);
    });

    // --- Server thread (inner veth side) ---
    let srv_exit = server_exit.clone();
    let inner_name = veth.inner_name().to_string();
    let server_handle = thread::spawn(move || {
        let mut runtime = LocalRuntime::builder(&inner_name, 0, server_mac_bytes)
            .build()
            .expect("failed to build server runtime");

        let listener = runtime.listen_tcp(server_ip, 9876, 16);

        runtime
            .run(srv_exit, async {
                let mut stream = listener.accept().await;

                // Read until we get the client's message.
                loop {
                    match stream.receive().await {
                        TcpRecvResult::Data(frame) => {
                            let msg = std::str::from_utf8(&frame).unwrap();
                            assert_eq!(msg, "Hello world TCP in XDP!!!");
                            break;
                        }
                        TcpRecvResult::Connected => continue,
                        TcpRecvResult::Fin
                        | TcpRecvResult::Reset
                        | TcpRecvResult::Closed => {
                            panic!("server: connection ended before receiving data");
                        }
                    }
                }

                // Send response.
                stream
                    .send(b"Acknowledged receipt of first ever request!!!")
                    .await;

                // Keep the runtime alive to transmit the response.
                loop {
                    match stream.receive().await {
                        TcpRecvResult::Fin
                        | TcpRecvResult::Reset
                        | TcpRecvResult::Closed => break,
                        _ => continue,
                    }
                }
            })
            .expect("server runtime error");
    });

    // Let the server bind and start listening before the client connects.
    thread::sleep(Duration::from_millis(100));

    // --- Client thread (outer veth side) ---
    let cli_exit = client_exit.clone();
    let cli_done = client_done.clone();
    let outer_name = veth.outer_name().to_string();
    let client_handle = thread::spawn(move || {
        let mut runtime = LocalRuntime::builder(&outer_name, 0, client_mac_bytes)
            .build()
            .expect("failed to build client runtime");

        let connect_fut = runtime
            .connect_tcp(
                client_ip,
                54321,
                server_ip,
                9876,
                WireMac::new(client_mac_bytes),
                WireMac::new(server_mac_bytes),
            )
            .expect("failed to initiate TCP connect");

        runtime
            .run(cli_exit, async {
                // Wait for the handshake to complete.
                let mut stream = connect_fut.await.expect("TCP connect failed");

                // Send data.
                stream.send(b"Hello world TCP in XDP!!!").await;

                // Read server response.
                loop {
                    match stream.receive().await {
                        TcpRecvResult::Data(frame) => {
                            let msg = std::str::from_utf8(&frame).unwrap();
                            assert_eq!(msg, "Acknowledged receipt of first ever request!!!");
                            break;
                        }
                        TcpRecvResult::Fin
                        | TcpRecvResult::Reset
                        | TcpRecvResult::Closed => {
                            panic!("client: connection ended before receiving response");
                        }
                        _ => continue,
                    }
                }

                cli_done.store(true, Ordering::Relaxed);
            })
            .expect("client runtime error");
    });

    client_handle.join().expect("client thread panicked");
    server_exit.store(true, Ordering::Relaxed);
    server_handle.join().expect("server thread panicked");

    assert!(
        client_done.load(Ordering::Relaxed),
        "client did not complete"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "test timed out (took {:?})",
        start.elapsed()
    );
}
