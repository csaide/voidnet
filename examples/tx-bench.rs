use std::{
    collections::VecDeque,
    net::Ipv6Addr,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use pnet::{
    packet::{
        Packet,
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        udp::{MutableUdpPacket, UdpPacket},
    },
    util::MacAddr,
};

use libvoid::xdp::{context::XdpContext, frame::Frame, socket::Socket, umem::Umem};

mod common;
use common::{BaseArgs, Stats};

// Build a frame for the given arguments. This is a simple example and can be customized as needed.
fn build_frame(args: &Args) -> Vec<u8> {
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
    checksum_data.extend_from_slice(udp_payload);

    let checksum = pnet::util::checksum(&checksum_data, 1);
    udp_packet.set_checksum(checksum);

    // Copy UDP payload
    let payload_start = ethernet_header_size + ipv6_header_size + udp_header_size;
    data[payload_start..payload_start + udp_payload.len()].copy_from_slice(udp_payload);

    data
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(
        short,
        long,
        default_value = "8008",
        help = "The source port for the UDP packet."
    )]
    src_port: u16,
    #[arg(
        short,
        long,
        default_value = "8008",
        help = "The destination port for the UDP packet."
    )]
    dst_port: u16,
    #[arg(
        short,
        long,
        default_value = "fc00:dead:cafe:1::1",
        help = "The source IP address for the UDP packet."
    )]
    src_ip: Ipv6Addr,
    #[arg(
        short,
        long,
        default_value = "fc00:dead:cafe:1::2",
        help = "The destination IP address for the UDP packet."
    )]
    dst_ip: Ipv6Addr,
    #[arg(short, long, help = "The source MAC address for the Ethernet packet.")]
    src_mac: MacAddr,
    #[arg(
        short,
        long,
        help = "The destination MAC address for the Ethernet packet."
    )]
    dst_mac: MacAddr,
}

impl Deref for Args {
    type Target = BaseArgs;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_context =
        XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
            .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use.
    //
    // Each Umem comes associated with three key components:
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    // - Write Frames (write_frames) > A set of frames that are backed by the umem which can be used for immediate writes.
    let (umem, mut fq, mut cq, mut write_frames) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.busy_poll_batch_size)
        .build::<VecDeque<Frame>>()
        .expect("Failed to create umem");

    // A socket represents a standard means of reading/writing packets from/to a network interface.
    //
    // This is the main handle for interacting with the network data, if needed this can be split into its owner, rx, and tx
    // components using the split() function.
    let mut socket = Socket::builder(&mut xdp_context, &args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .busy_poll(args.busy_poll)
        .copy_mode(args.copy_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .shared_umem(false)
        .build(umem, &mut fq, &mut cq)
        .expect("Failed to create socket");

    // Always catch SIGINT/SIGTERM to ensure we clean up properly, we have a running XDP program attached to the interface.
    //
    // Note: In other words its very important to ensure that the Drop impl for XdpContext is run to detach the XDP program from
    // the interface, OR manually call detach().
    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    // Initial copy of the data into the frames.
    let data = build_frame(&args);
    for frame in write_frames.iter_mut() {
        unsafe { frame.copy_from(&data) };
    }

    println!("Socket created, sending packets...");

    let frames = write_frames.len();
    while !exit.load(Ordering::Relaxed) {
        // Send the prepared frames to the socket.
        //
        // Note this will completely consume the input buffer.
        let sent = match socket.send(&mut write_frames) {
            Ok(sent) => {
                debug_assert!(
                    sent == frames as u32,
                    "Sent a different number of frames than the input buffer, this should never happen!"
                );

                stats.update_batch(sent as usize, data.len());
                sent
            }
            Err(_) => {
                // We would have blocked.
                continue;
            }
        };

        // We should have sent all the frames.
        debug_assert_eq!(
            write_frames.len(),
            0,
            "Write frames is not empty after sending, this should never happen!"
        );

        // Process any outstanding descriptors on the completion queue retrieving the sent frames.
        //
        // This should be a loop because the kernel can only transmit a limited number of frames at a time.
        while write_frames.len() < sent as usize {
            // First wake up the kernel, it may skip the wake syscall if it can, but it must always be checked.
            socket.maybe_wake().unwrap();

            // Process the writen frames, this will consume as many frames as possible from the kernel, but it
            // will be limited to the devices descriptor count.
            cq.process_queue(&mut write_frames, Some(data.len()));
        }

        stats.maybe_print();
    }
}
