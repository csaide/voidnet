use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use libxdp_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS};
use pnet::packet::{
    Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::{MutableUdpPacket, UdpPacket},
};
use pnet::util::MacAddr;
use std::net::Ipv6Addr;

use libvoid::xdp::socket::{Error as SocketError, Socket};

const FILL_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
const COMPLETION_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const RX_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const TX_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;
const FRAME_SIZE: usize = 2048;

struct Stats {
    packets_received: u64,
    bytes_received: u64,
    cycles: u64,
    would_block_count: u64,
    batch_size_cnt: u64,
    num_batches: u64,
    last_packets: u64,
    last_bytes: u64,
    last_display_time: u64,
    last_cycles: u64,
    last_would_block_count: u64,
}

impl Stats {
    const fn new() -> Self {
        Self {
            packets_received: 0,
            bytes_received: 0,
            cycles: 0,
            would_block_count: 0,
            batch_size_cnt: 0,
            num_batches: 0,
            last_packets: 0,
            last_bytes: 0,
            last_display_time: 0,
            last_cycles: 0,
            last_would_block_count: 0,
        }
    }

    fn update(&mut self, size: usize) {
        self.packets_received += 1;
        self.bytes_received += size as u64;
    }

    fn increment_would_block(&mut self) {
        self.would_block_count += 1;
    }

    fn increment_cycles(&mut self) {
        self.cycles += 1;
    }

    fn observe_batch_size(&mut self, size: usize) {
        self.batch_size_cnt += size as u64;
        self.num_batches += 1;
    }

    pub fn maybe_print_stats(&mut self) {
        const PACKETS_PER_PRINT: u64 = 20_000_000;
        // Only print if 10M packets have been received since last print
        if self.packets_received < self.last_packets + PACKETS_PER_PRINT {
            return;
        }

        let packets = self.packets_received;
        let last_packets = self.last_packets;

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let elapsed_ns = if self.last_display_time == 0 {
            // First time: calculate elapsed since application start
            now_ns
        } else {
            // Subsequent times: calculate elapsed since last display
            now_ns - self.last_display_time
        };

        let bytes = self.bytes_received;
        let would_block_count = self.would_block_count;
        let cycles = self.cycles;
        let batch_size_cnt = self.batch_size_cnt;
        let num_batches = self.num_batches;

        let last_bytes = self.last_bytes;
        let last_would_block_count = self.last_would_block_count;
        let last_cycles = self.last_cycles;

        // Update last values
        self.last_packets = packets;
        self.last_bytes = bytes;
        self.last_would_block_count = would_block_count;
        self.last_cycles = cycles;
        self.last_display_time = now_ns;

        let elapsed_secs = elapsed_ns as f64 / 1_000_000_000.0;

        // Calculate rates (packets/sec and bytes/sec)
        let packet_rate = (packets - last_packets) as f64 / elapsed_secs;
        let byte_rate = (bytes - last_bytes) as f64 / elapsed_secs;
        let would_block_rate = (would_block_count - last_would_block_count) as f64 / elapsed_secs;
        let cycle_rate = (cycles - last_cycles) as f64 / elapsed_secs;

        // Print rates
        println!(
            "Packets: {}M | Bytes: {:.2}GiB | Packet rate: {:.2} Mpps | Byte rate: {:.2} Gbps | WB rate: {:.2} Mps | Cycle rate: {:.2} Mps | Batch size: {:.2} frames",
            packets / 1_000_000,
            bytes as f64 / 1024.0 / 1024.0 / 1024.0,
            packet_rate / 1_000_000.0,
            byte_rate * 8.0 / 1_000_000_000.0,
            would_block_rate / 1_000_000.0,
            cycle_rate / 1_000_000.0,
            batch_size_cnt as f64 / num_batches as f64
        );
    }
}

pub fn build_frame() -> Vec<u8> {
    // Placeholder values - user will fill these in
    // MAC addresses can be specified as strings like "00:11:22:33:44:55"
    let src_mac = MacAddr::new(0xd2, 0x6d, 0xa5, 0x32, 0x99, 0x7a);
    let dst_mac = MacAddr::new(0xf6, 0x5a, 0x6c, 0x34, 0xa1, 0x6f);
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

fn echo_udp(if_name: &str, queue: u32) {
    let mut socket = Socket::builder(if_name, queue)
        .completion_ring_size(COMPLETION_RING_SIZE)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .rx_ring_size(RX_RING_SIZE)
        .tx_ring_size(TX_RING_SIZE)
        .build()
        .expect("Failed to create socket");

    println!("Socket created");
    let mut stats = Stats::new();
    let mut to_write = Vec::with_capacity(1024);
    loop {
        stats.increment_cycles();
        let mut frames = match socket.recv(1024) {
            Ok(frames) => {
                stats.observe_batch_size(frames.len());
                frames
            }
            Err(SocketError::WouldBlock) => {
                stats.increment_would_block();
                continue;
            }
            Err(e) => {
                println!("Error receiving frame: {:?}", e);
                break;
            }
        };
        for mut frame in frames.drain(..) {
            stats.update(frame.len());

            let mut ether = match MutableEthernetPacket::new(&mut frame) {
                Some(ether) => ether,
                None => continue,
            };

            let dst = ether.get_destination();
            ether.set_destination(ether.get_source());
            ether.set_source(dst);

            match ether.get_ethertype() {
                EtherTypes::Ipv6 => {
                    let mut ip = match MutableIpv6Packet::new(&mut frame) {
                        Some(ip) => ip,
                        None => continue,
                    };
                    let dst = ip.get_destination();
                    ip.set_destination(ip.get_source());
                    ip.set_source(dst);
                }
                EtherTypes::Ipv4 => {
                    let mut ip = match MutableIpv4Packet::new(&mut frame) {
                        Some(ip) => ip,
                        None => continue,
                    };
                    let dst = ip.get_destination();
                    ip.set_destination(ip.get_source());
                    ip.set_source(dst);
                }
                _ => continue,
            }

            to_write.push(frame);
        }
        if to_write.len() > 0 {
            loop {
                match socket.send(&mut to_write) {
                    Ok(_) => break,
                    Err(SocketError::WouldBlock) => {
                        stats.increment_would_block();
                        continue;
                    }
                    Err(e) => {
                        println!("Error sending frame: {:?}", e);
                        break;
                    }
                }
            }
        }

        stats.maybe_print_stats();
    }
}

fn xdp_rx(if_name: &str, queue: u32) {
    let mut socket = Socket::builder(if_name, queue)
        .completion_ring_size(COMPLETION_RING_SIZE)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .rx_ring_size(RX_RING_SIZE)
        .tx_ring_size(TX_RING_SIZE)
        .build()
        .expect("Failed to create socket");

    println!("Socket created");
    let mut stats = Stats::new();
    loop {
        stats.increment_cycles();
        match socket.recv(1024) {
            Ok(frames) => {
                stats.observe_batch_size(frames.len());
                for frame in frames {
                    stats.update(frame.len());
                }
            }
            Err(SocketError::WouldBlock) => {
                stats.increment_would_block();
                continue;
            }
            Err(e) => {
                println!("Error receiving frame: {:?}", e);
                break;
            }
        };
        stats.maybe_print_stats();
    }
}

fn xdp_tx(if_name: &str, queue: u32) {
    let mut socket = Socket::builder(if_name, queue)
        .completion_ring_size(COMPLETION_RING_SIZE)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .rx_ring_size(RX_RING_SIZE)
        .tx_ring_size(TX_RING_SIZE)
        .build()
        .expect("Failed to create socket");

    println!("Socket created");
    let mut stats = Stats::new();
    let data = build_frame();
    loop {
        stats.increment_cycles();
        let mut frames = match socket.prepare_frames(2048) {
            Ok(frames) => {
                stats.observe_batch_size(frames.len());
                frames
            }
            Err(SocketError::WouldBlock) => {
                stats.increment_would_block();
                continue;
            }
            Err(e) => {
                println!("Error preparing frames: {:?}", e);
                break;
            }
        };

        for frame in frames.iter_mut() {
            unsafe { frame.copy_from(&data) };
            stats.update(frame.len());
        }
        while frames.len() > 0 {
            match socket.send(&mut frames) {
                Ok(_) => {}
                Err(SocketError::WouldBlock) => {
                    stats.increment_would_block();
                    continue;
                }
                Err(e) => {
                    println!("Error sending frames: {:?}", e);
                    break;
                }
            };
        }
        stats.maybe_print_stats();
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
enum Args {
    #[command(about = "Run XDP RX program")]
    XdpRx {
        #[arg(short, long)]
        if_name: String,
        #[arg(short, long)]
        queue: u32,
    },
    #[command(about = "Run XDP TX program")]
    XdpTx {
        #[arg(short, long)]
        if_name: String,
        #[arg(short, long)]
        queue: u32,
    },
    #[command(about = "Run UDP echo program")]
    Echo {
        #[arg(short, long)]
        if_name: String,
        #[arg(short, long)]
        queue: u32,
    },
}

fn main() {
    let args = Args::parse();

    match args {
        Args::XdpRx { if_name, queue } => xdp_rx(&if_name, queue),
        Args::XdpTx { if_name, queue } => xdp_tx(&if_name, queue),
        Args::Echo { if_name, queue } => echo_udp(&if_name, queue),
    }
}
