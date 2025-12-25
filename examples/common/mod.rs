#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use libvoid::xdp::{program::AttachMode, socket::CopyMode};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::MutableUdpPacket,
};

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
