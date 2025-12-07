use core::panic;
use std::{
    os::raw::c_void,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use libc::{
    AF_INET6, IPPROTO_UDP, SOCK_DGRAM, bind, htons, in6addr_any, recvfrom, sockaddr, sockaddr_in6,
    socket,
};
use libxdp_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS};
// use pnet::packet::{
//     Packet,
//     ethernet::{EtherTypes, EthernetPacket},
//     icmpv6::{Icmpv6Packet, Icmpv6Types, echo_request::EchoRequestPacket},
//     ip::IpNextHeaderProtocols,
//     ipv6::Ipv6Packet,
//     udp::UdpPacket,
// };

use libvoid::xdp::{
    socket::{Error, Socket},
    umem::{Frame, Umem},
};

const FILL_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
const COMPLETION_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const RX_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const TX_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;
const FRAME_SIZE: usize = 2048;
const NUM_FRAMES: usize = (COMPLETION_RING_SIZE + FILL_RING_SIZE) as usize;

struct Stats {
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    last_packets: AtomicU64,
    last_bytes: AtomicU64,
    last_display_time: AtomicU64,
}

impl Stats {
    const fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_packets: AtomicU64::new(0),
            last_bytes: AtomicU64::new(0),
            last_display_time: AtomicU64::new(0),
        }
    }

    fn update(&self, size: usize) {
        let packets = self.packets_received.fetch_add(1, Ordering::Relaxed);
        let bytes = self
            .bytes_received
            .fetch_add(size as u64, Ordering::Relaxed);

        // Get current time as nanoseconds since UNIX epoch
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let last_display_time_ns = self.last_display_time.load(Ordering::Relaxed);

        // Calculate time elapsed since last display (or since start if first time)
        let elapsed_ns = if last_display_time_ns == 0 {
            // First time: calculate elapsed since application start
            1_000_000_000
        } else {
            // Subsequent times: calculate elapsed since last display
            now_ns - last_display_time_ns
        };

        if elapsed_ns >= 1_000_000_000 {
            let last_packets = self.last_packets.swap(packets, Ordering::Relaxed);
            let last_bytes = self.last_bytes.swap(bytes, Ordering::Relaxed);
            self.last_display_time.store(now_ns, Ordering::Relaxed);
            let elapsed_secs = elapsed_ns as f64 / 1_000_000_000.0;

            // Calculate rates (packets/sec and bytes/sec)
            let packet_rate = (packets - last_packets) as f64 / elapsed_secs;
            let byte_rate = (bytes - last_bytes) as f64 / elapsed_secs;

            // Print rates
            println!(
                "Elapsed: {:.2}s | Packets: {}M | Bytes: {:.2}GB | Packet rate: {:.2} Mpps | Byte rate: {:.2} Gbps",
                elapsed_secs,
                packets / 1_000_000,
                bytes as f64 / 1024.0 / 1024.0 / 1024.0,
                packet_rate / 1_000_000.0,
                byte_rate * 8.0 / 1_000_000_000.0
            );
        }
    }
}

static STATS: Stats = Stats::new();

pub fn handle_frame(frame: Frame<'_>) {
    STATS.update(frame.len());
}

fn xdp() {
    let umem = Umem::builder()
        .completion_ring_size(COMPLETION_RING_SIZE)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .num_frames(NUM_FRAMES)
        .build()
        .expect("Failed to create umem");
    let mut socket =
        Socket::new("test", 0, umem, RX_RING_SIZE, TX_RING_SIZE).expect("Failed to create socket");

    println!("Socket created");
    loop {
        match socket.recv_cb(1_000_000, handle_frame) {
            Ok(_) => {}
            Err(Error::WouldBlock) => {
                // thread::sleep(Duration::from_millis(100));
                // println!("Would block");
                continue;
            }
            Err(e) => {
                println!("Error receiving frame: {:?}", e);
                break;
            }
        };
    }
}

fn std() {
    let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) };
    if fd == -1 {
        eprintln!(
            "Failed to create socket: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let server_addr = unsafe {
        sockaddr_in6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: htons(8008),
            sin6_addr: in6addr_any,
            sin6_scope_id: 0,
            sin6_flowinfo: 0,
        }
    };
    let mut client_addr_len = std::mem::size_of::<sockaddr_in6>() as u32;
    let mut client_addr = unsafe {
        sockaddr_in6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: 0,
            sin6_addr: in6addr_any,
            sin6_scope_id: 0,
            sin6_flowinfo: 0,
        }
    };

    let ret = unsafe {
        bind(
            fd,
            &server_addr as *const sockaddr_in6 as *const sockaddr,
            std::mem::size_of::<sockaddr_in6>() as u32,
        )
    };
    if ret == -1 {
        eprintln!("Failed to bind socket: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    println!("Socket created");
    let mut buf = [0; 2048];
    loop {
        let n = unsafe {
            recvfrom(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut client_addr as *mut sockaddr_in6 as *mut sockaddr,
                &mut client_addr_len,
            )
        };
        if n < 0 {
            panic!(
                "Failed to receive data: {}",
                std::io::Error::last_os_error()
            );
        }
        STATS.update(n as usize);
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
enum Args {
    #[command(about = "Run XDP program")]
    Xdp,
    #[command(about = "Run standard program")]
    Std,
}

fn main() {
    let args = Args::parse();
    match args {
        Args::Xdp => xdp(),
        Args::Std => std(),
    }
}
