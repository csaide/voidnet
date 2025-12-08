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
use pnet::packet::{
    Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::{MutableUdpPacket, UdpPacket},
};
use pnet::util::MacAddr;
use std::net::Ipv6Addr;

use libvoid::xdp::{
    socket::{Error, Socket},
    umem::{FinalizedFrame, Frame, SendFrame, Umem},
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

pub fn handle_frame(frame: Frame) {
    STATS.update(frame.len());
}

pub fn build_frame() -> Vec<u8> {
    // Placeholder values - user will fill these in
    // MAC addresses can be specified as strings like "00:11:22:33:44:55"
    let src_mac = MacAddr::new(0xd2, 0x6d, 0xa5, 0x32, 0x99, 0x7a);
    let dst_mac = MacAddr::new(0x3a, 0xc4, 0x65, 0xac, 0x1b, 0xe7);
    let src_ip: Ipv6Addr = "fc00:dead:cafe:1::1".parse().unwrap();
    let dst_ip: Ipv6Addr = "fc00:dead:cafe:1::2".parse().unwrap();
    let src_port: u16 = 8008;
    let dst_port: u16 = 8008;

    // UDP payload (empty for now, can be customized)
    let udp_payload: &[u8] = b"Hello, UDP!";

    // Calculate packet sizes
    let ethernet_header_size = EthernetPacket::minimum_packet_size();
    let ipv6_header_size = Ipv6Packet::minimum_packet_size();
    let udp_header_size = UdpPacket::minimum_packet_size();
    let total_packet_size =
        ethernet_header_size + ipv6_header_size + udp_header_size + udp_payload.len();

    // Get access to the data buffer
    let mut data = vec![0; total_packet_size];

    // Build Ethernet header
    let mut ethernet_packet = MutableEthernetPacket::new(&mut data).unwrap();
    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);

    // Build IPv6 header
    let ipv6_data = &mut data[ethernet_header_size..];
    let mut ipv6_packet = MutableIpv6Packet::new(ipv6_data).unwrap();
    ipv6_packet.set_version(6);
    ipv6_packet.set_traffic_class(0);
    ipv6_packet.set_flow_label(0);
    ipv6_packet.set_payload_length((udp_header_size + udp_payload.len()) as u16);
    ipv6_packet.set_next_header(IpNextHeaderProtocols::Udp);
    ipv6_packet.set_hop_limit(64);
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);

    // Build UDP header
    let udp_data = &mut data[ethernet_header_size + ipv6_header_size..];
    let mut udp_packet = MutableUdpPacket::new(udp_data).unwrap();
    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    udp_packet.set_length((udp_header_size + udp_payload.len()) as u16);

    // Calculate UDP checksum (IPv6 pseudo-header + UDP header + payload)
    let udp_len = udp_header_size + udp_payload.len();
    let mut checksum_data = Vec::with_capacity(40 + udp_len);
    checksum_data.extend_from_slice(&src_ip.octets());
    checksum_data.extend_from_slice(&dst_ip.octets());
    checksum_data.extend_from_slice(&(udp_len as u32).to_be_bytes());
    checksum_data.push(0);
    checksum_data.push(IpNextHeaderProtocols::Udp.0);
    checksum_data.extend_from_slice(&udp_packet.packet()[..udp_header_size]);
    checksum_data.extend_from_slice(udp_payload);

    let checksum = pnet::util::checksum(&checksum_data, 1);
    udp_packet.set_checksum(checksum);

    // Copy UDP payload
    let payload_start = ethernet_header_size + ipv6_header_size + udp_header_size;
    data[payload_start..payload_start + udp_payload.len()].copy_from_slice(udp_payload);

    data
}

fn send_frame() -> impl FnMut(SendFrame) -> FinalizedFrame {
    let data = build_frame();
    move |mut frame: SendFrame| {
        unsafe { frame.copy_from(&data) };
        STATS.update(data.len());
        frame.commit()
    }
}

fn xdp_rx() {
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

fn xdp_tx() {
    let umem = Umem::builder()
        .completion_ring_size(COMPLETION_RING_SIZE / 2)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .num_frames(NUM_FRAMES)
        .build()
        .expect("Failed to create umem");
    let mut socket =
        Socket::new("test", 0, umem, RX_RING_SIZE, TX_RING_SIZE).expect("Failed to create socket");

    println!("Socket created");
    loop {
        match socket.send_cb(COMPLETION_RING_SIZE, send_frame()) {
            Ok(_) => {}
            Err(Error::WouldBlock) => {
                continue;
            }
            Err(e) => {
                println!("Error sending frame: {:?}", e);
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
    #[command(about = "Run XDP RX program")]
    XdpRx,
    #[command(about = "Run XDP TX program")]
    XdpTx,
    #[command(about = "Run standard program")]
    Std,
}

fn main() {
    let args = Args::parse();
    match args {
        Args::XdpRx => xdp_rx(),
        Args::XdpTx => xdp_tx(),
        Args::Std => std(),
    }
}
