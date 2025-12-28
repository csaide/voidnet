#![allow(dead_code)]

use std::{
    net::Ipv6Addr,
    time::{SystemTime, UNIX_EPOCH},
};

use libvoid::xdp::{program::AttachMode, socket::CopyMode};
use pnet::{
    packet::{
        Packet,
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        udp::{MutableUdpPacket, UdpPacket},
    },
    util::MacAddr,
};
use rand::RngCore;

pub struct Stats {
    pub id: Option<usize>,
    pub packets_received: u64,
    pub fragments_received: u64,
    pub bytes_received: u64,
    pub last_packets_received: u64,
    pub last_fragments_received: u64,
    pub last_bytes_received: u64,
    pub last_time: u64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            id: None,
            packets_received: 0,
            fragments_received: 0,
            bytes_received: 0,
            last_packets_received: 0,
            last_fragments_received: 0,
            last_bytes_received: 0,
            last_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }
    pub fn new_with_id(id: usize) -> Self {
        Self {
            id: Some(id),
            ..Self::new()
        }
    }

    #[inline(always)]
    pub fn update(&mut self, bytes: usize, is_fragment: bool) {
        self.bytes_received += bytes as u64;
        if is_fragment {
            self.fragments_received += 1;
        } else {
            self.packets_received += 1;
        }
    }

    pub fn update_batch(&mut self, frames: usize, frame_size: usize) {
        self.packets_received += frames as u64;
        self.bytes_received += frames as u64 * frame_size as u64;
    }

    #[inline(always)]
    pub fn maybe_print(&mut self) {
        const PACKETS_PER_PRINT: u64 = 20_000_000;
        if self.packets_received - self.last_packets_received < PACKETS_PER_PRINT {
            return;
        }

        let packets_received = self.packets_received;
        let fragments_received = self.fragments_received;
        let bytes_received = self.bytes_received;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let elapsed_time = (now - self.last_time) as f64 / 1_000_000_000.0;

        let packets_per_second =
            (packets_received - self.last_packets_received) as f64 / elapsed_time;
        let fragments_per_second =
            (fragments_received - self.last_fragments_received) as f64 / elapsed_time;
        let bytes_per_second = (bytes_received - self.last_bytes_received) as f64 / elapsed_time;

        self.last_packets_received = packets_received;
        self.last_fragments_received = fragments_received;
        self.last_bytes_received = bytes_received;
        self.last_time = now;

        println!(
            "{}Packets: {}M | Fragments: {}M | Bytes: {:.2}GiB | Packet rate: {:.2} Mpps | Fragment rate: {:.2} Mfps | Byte rate: {:.2} Gbps",
            self.id
                .map(|id| format!("Worker {} |", id))
                .unwrap_or_default(),
            packets_received / 1_000_000,
            fragments_received / 1_000_000,
            bytes_received as f64 / 1024.0 / 1024.0 / 1024.0,
            packets_per_second / 1_000_000.0,
            fragments_per_second / 1_000_000.0,
            bytes_per_second * 8.0 / 1_000_000_000.0
        );
    }
}

pub fn swap_addresses(frame: &mut [u8]) -> Option<()> {
    let mut ether = MutableEthernetPacket::new(frame)?;

    let dst = ether.get_destination();
    ether.set_destination(ether.get_source());
    ether.set_source(dst);

    let payload_offset = EthernetPacket::minimum_packet_size();
    let (transport, payload_offset) = match ether.get_ethertype() {
        EtherTypes::Ipv6 => {
            let mut ip = MutableIpv6Packet::new(&mut frame[payload_offset..])?;
            let dst = ip.get_destination();
            ip.set_destination(ip.get_source());
            ip.set_source(dst);
            (ip.get_next_header(), Ipv6Packet::minimum_packet_size())
        }
        EtherTypes::Ipv4 => {
            let mut ip = MutableIpv4Packet::new(&mut frame[payload_offset..])?;
            let dst = ip.get_destination();
            ip.set_destination(ip.get_source());
            ip.set_source(dst);
            (
                ip.get_next_level_protocol(),
                ip.get_header_length() as usize * 4,
            )
        }
        _ => return None,
    };

    match transport {
        IpNextHeaderProtocols::Udp => {
            let mut udp = MutableUdpPacket::new(&mut frame[payload_offset..])?;
            let dst = udp.get_destination();
            udp.set_destination(udp.get_source());
            udp.set_source(dst);
        }
        _ => return None,
    }

    Some(())
}

// Build a frame for the given arguments. This is a simple example and can be customized as needed.
pub fn build_frame(args: &GeneratorArgs) -> Vec<u8> {
    // UDP payload of random data for now.
    let mut udp_payload = Vec::with_capacity(args.payload_size);
    rand::rng().fill_bytes(&mut udp_payload);

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
    ethernet_packet.set_destination(args.dst_mac);
    ethernet_packet.set_source(args.src_mac);
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
    ipv6_packet.set_source(args.src_ip);
    ipv6_packet.set_destination(args.dst_ip);

    // Build UDP header
    let udp_data = &mut data[ethernet_header_size + ipv6_header_size..];
    let mut udp_packet = MutableUdpPacket::new(udp_data).unwrap();
    udp_packet.set_source(args.src_port);
    udp_packet.set_destination(args.dst_port);
    udp_packet.set_length((udp_header_size + udp_payload.len()) as u16);

    // Calculate UDP checksum (IPv6 pseudo-header + UDP header + payload)
    let udp_len = udp_header_size + udp_payload.len();
    let mut checksum_data = Vec::with_capacity(40 + udp_len);
    checksum_data.extend_from_slice(&args.src_ip.octets());
    checksum_data.extend_from_slice(&args.dst_ip.octets());
    checksum_data.extend_from_slice(&(udp_len as u32).to_be_bytes());
    checksum_data.push(0);
    checksum_data.push(IpNextHeaderProtocols::Udp.0);
    checksum_data.extend_from_slice(&udp_packet.packet()[..udp_header_size]);
    checksum_data.extend_from_slice(&udp_payload);

    let checksum = pnet::util::checksum(&checksum_data, 1);
    udp_packet.set_checksum(checksum);

    // Copy UDP payload
    let payload_start = ethernet_header_size + ipv6_header_size + udp_header_size;
    data[payload_start..payload_start + udp_payload.len()].copy_from_slice(&udp_payload);

    data
}

#[derive(clap::Args)]
pub struct BaseArgs {
    #[arg(short, long, help = "The name of the network interface to use.")]
    pub if_name: String,
    #[arg(
        short,
        long,
        help = "The queue number to use on the specified interface."
    )]
    pub queue: u32,
    #[arg(
        short,
        long,
        default_value = "unspec",
        help = "The attach mode to use for the attaching the XDP router program."
    )]
    pub attach_mode: AttachMode,
    #[arg(
        long,
        default_value = "copy",
        help = "The copy mode to use for the socket."
    )]
    pub copy_mode: CopyMode,
    #[arg(
        short,
        long,
        default_value = "false",
        help = "Enale busy polling on the socket."
    )]
    pub busy_poll: bool,
    #[arg(
        long,
        default_value = "64",
        help = "The target batch size for busy polling."
    )]
    pub busy_poll_batch_size: usize,
    #[arg(
        long,
        default_value = "20",
        help = "The timeout in microseconds for busy polling."
    )]
    pub busy_poll_timeout_us: i32,
    #[arg(
        long,
        default_value = "4096",
        help = "The size of each individual frame in the umem."
    )]
    pub frame_size: usize,
    #[arg(
        long,
        default_value = "2048",
        help = "The number of slots in the completion ring in the umem."
    )]
    pub completion_ring_size: u32,
    #[arg(
        long,
        default_value = "4096",
        help = "The number of slots in the fill ring in the umem."
    )]
    pub fill_ring_size: u32,
    #[arg(
        long,
        default_value = "false",
        help = "Enable huge tables for the umem."
    )]
    pub huge_tables: bool,
    #[arg(
        long,
        default_value = "2048",
        help = "The number of slots in the RX ring in the socket."
    )]
    pub rx_ring_size: u32,
    #[arg(
        long,
        default_value = "2048",
        help = "The number of slots in the TX ring in the socket."
    )]
    pub tx_ring_size: u32,
    #[arg(
        long,
        default_value = "false",
        help = "Enable fragmentation support on the socket, this is only useful for devices with MTU's greater than ~3000 bytes."
    )]
    pub enable_fragmentation: bool,
}

#[derive(clap::Args)]
pub struct GeneratorArgs {
    #[arg(
        short = 'p',
        long,
        default_value = "8008",
        help = "The source port for the UDP packet."
    )]
    src_port: u16,
    #[arg(
        short = 'P',
        long,
        default_value = "8008",
        help = "The destination port for the UDP packet."
    )]
    dst_port: u16,
    #[arg(
        short = 'i',
        long,
        default_value = "fc00:dead:cafe:1::1",
        help = "The source IP address for the UDP packet."
    )]
    src_ip: Ipv6Addr,
    #[arg(
        short = 'I',
        long,
        default_value = "fc00:dead:cafe:1::2",
        help = "The destination IP address for the UDP packet."
    )]
    dst_ip: Ipv6Addr,
    #[arg(
        short = 'm',
        long,
        help = "The source MAC address for the Ethernet packet."
    )]
    src_mac: MacAddr,
    #[arg(
        short = 'M',
        long,
        help = "The destination MAC address for the Ethernet packet."
    )]
    dst_mac: MacAddr,
    #[arg(
        short,
        long,
        default_value = "64",
        help = "The size of the UDP payload in bytes."
    )]
    payload_size: usize,
}
