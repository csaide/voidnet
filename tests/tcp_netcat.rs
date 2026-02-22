use std::{
    io::Write,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use libvoid::{
    net::{TcpReadResult, wire::ip::IpAddress},
    rt::LocalRuntime,
    xdp::test_utils::TestVethPair,
};

/// Tests that a standard TCP client (netcat) can connect to an AF_XDP TCP server.
///
/// The server runs on the inner veth with AF_XDP (bypassing the kernel). The client
/// is plain netcat using the kernel's TCP stack on the outer veth. This validates
/// interoperability between the AF_XDP TCP implementation and the Linux kernel.
#[test]
fn test_tcp_netcat_client() {
    let veth = TestVethPair::new().expect("failed to create veth pair");

    let server_ip: IpAddress = veth.addresses().inner_ipv4.into();
    let server_mac_bytes = *veth.inner_mac().as_bytes();
    let server_ipv4_str = veth.addresses().inner_ipv4.to_string();
    let inner_name = veth.inner_name().to_string();
    let outer_name = veth.outer_name().to_string();

    // Disable offloads on the outer interface so the kernel computes full TCP
    // checksums and doesn't generate GSO/GRO super-frames.
    let _ = Command::new("/usr/sbin/ethtool")
        .args([
            "-K",
            &outer_name,
            "tx",
            "off",
            "rx",
            "off",
            "sg",
            "off",
            "tso",
            "off",
            "gso",
            "off",
            "gro",
            "off",
        ])
        .output();

    let server_exit = Arc::new(AtomicBool::new(false));
    let server_done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    // Watchdog: force exit after 10 seconds.
    let wd_exit = server_exit.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(10));
        wd_exit.store(true, Ordering::Relaxed);
    });

    // Channel: server thread signals when the runtime is built (and thus the
    // NeighborHandler has captured the inner interface's IP addresses).
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(0);

    // --- Server thread (inner veth, AF_XDP) ---
    let srv_exit = server_exit.clone();
    let srv_done = server_done.clone();
    let srv_inner = inner_name.clone();
    let server_handle = thread::spawn(move || {
        let mut runtime = LocalRuntime::builder(&srv_inner, 0, server_mac_bytes)
            .build()
            .expect("failed to build server runtime");

        let listener = runtime.listen_tcp(server_ip, 9877, 16);

        // Signal that the runtime is fully built.
        ready_tx.send(()).unwrap();

        runtime
            .run(srv_exit, async {
                let mut stream = listener.accept().await;
                let mut buf = [0u8; 1024];

                // Read data from netcat.
                loop {
                    match stream.read(&mut buf).await {
                        TcpReadResult::Data(n) => {
                            let msg = std::str::from_utf8(&buf[..n]).unwrap();
                            assert_eq!(msg.trim(), "Hello from netcat!");
                            break;
                        }
                        TcpReadResult::Connected => continue,
                        TcpReadResult::PeerClosed
                        | TcpReadResult::Reset
                        | TcpReadResult::Closed => {
                            panic!("server: connection ended before receiving data");
                        }
                    }
                }

                srv_done.store(true, Ordering::Relaxed);

                // Send response.
                stream.write(b"XDP server says hello!").await;

                // Keep the runtime alive so tick() drains the send buffer and
                // transmits the response. The exit flag terminates us.
                loop {
                    match stream.read(&mut buf).await {
                        TcpReadResult::PeerClosed
                        | TcpReadResult::Reset
                        | TcpReadResult::Closed => break,
                        _ => continue,
                    }
                }
            })
            .expect("server runtime error");
    });

    // Wait for the runtime to be built before removing the inner IP.
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server failed to signal readiness");

    // Remove the inner IPv4 address from the kernel so it doesn't consider it
    // a local address and route via loopback. The NeighborHandler already
    // captured the address during construction and will still respond to ARP.
    let inner_ipv4_cidr = format!("{}/24", veth.addresses().inner_ipv4);
    let _ = Command::new("/usr/sbin/ip")
        .args(["addr", "del", &inner_ipv4_cidr, "dev", &inner_name])
        .output();

    // Give the server time to enter the run loop.
    thread::sleep(Duration::from_millis(200));

    // --- Netcat client (kernel TCP on outer veth) ---
    let mut nc = Command::new("/usr/bin/nc")
        .args(["-w", "3", &server_ipv4_str, "9877"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netcat");

    // Write data and close stdin.
    let mut stdin = nc.stdin.take().unwrap();
    stdin.write_all(b"Hello from netcat!\n").unwrap();
    drop(stdin);

    let output = nc.wait_with_output().expect("failed to wait for netcat");
    let response = String::from_utf8_lossy(&output.stdout);

    // Stop the server.
    server_exit.store(true, Ordering::Relaxed);
    server_handle.join().expect("server thread panicked");

    assert!(
        server_done.load(Ordering::Relaxed),
        "server did not receive the message"
    );
    assert_eq!(
        response.trim(),
        "XDP server says hello!",
        "netcat did not receive the expected response (got: {:?})",
        response
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "test timed out (took {:?})",
        start.elapsed()
    );
}
