use std::{
    net::Ipv6Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};

use libvoid::xdp::{context::XdpContext, error::Error as XdpError, socket::Socket, umem::Umem};
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

mod common;
use common::Stats;

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
    #[arg(short, long)]
    if_name: String,
    #[arg(short, long)]
    queue: u32,
    #[arg(short, long, default_value = "64")]
    batch_size: usize,
    #[arg(short, long, default_value = "8008")]
    src_port: u16,
    #[arg(short, long, default_value = "8008")]
    dst_port: u16,
    #[arg(short, long, default_value = "fc00:dead:cafe:1::1")]
    src_ip: Ipv6Addr,
    #[arg(short, long, default_value = "fc00:dead:cafe:1::2")]
    dst_ip: Ipv6Addr,
    #[arg(short, long)]
    src_mac: MacAddr,
    #[arg(short, long)]
    dst_mac: MacAddr,
}

fn main() {
    let args = Args::parse();

    let mut xdp_context = XdpContext::new(&args.if_name).expect("Failed to create xdp context");

    let (umem, _fq, mut cq) = Umem::builder()
        .completion_ring_size(XSK_RING_CONS__DEFAULT_NUM_DESCS)
        .fill_ring_size(XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
        .frame_size(XSK_UMEM__DEFAULT_FRAME_SIZE as usize)
        .build()
        .expect("Failed to create umem");
    let mut socket = Socket::builder(&mut xdp_context, &args.if_name, args.queue)
        .rx_ring_size(XSK_RING_CONS__DEFAULT_NUM_DESCS)
        .tx_ring_size(XSK_RING_PROD__DEFAULT_NUM_DESCS)
        .build(umem)
        .expect("Failed to create socket");

    // Setup some maintenance logic so we are good stewards and ensure we clean up.
    //
    // Note: if the XdpContext isn't safely dropped (destructor run) then the interface will retain
    // the XDP program attached to it, breaking things in weird ways.... cleanup is important :).
    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let data = build_frame(&args);

    println!("Socket created, sending packets...");

    // Setup some stats to track the number of packets and bytes received.
    let mut stats = Stats::new();
    while !exit.load(Ordering::Relaxed) {
        // Prepare a batch of frames for sending on the socket, these frames are backed
        // by the internal umem and if dropped before being sent will be returned to the umem.
        let mut frames = match socket.prepare_frames(args.batch_size) {
            Ok(frames) => frames,
            Err(XdpError::WouldBlock) => {
                // We would have blocked trying to prepare any of the frames, process any outstanding descriptors on the completion queue.
                cq.process_queue();
                continue;
            }
            Err(e) => {
                // An unrecoverable error occurred, exit the loop.
                println!("Error preparing frames: {:?}", e);
                break;
            }
        };

        // Copy the data into the frames.
        for frame in frames.iter_mut() {
            unsafe { frame.copy_from(&data) };
            stats.update(frame.len());
        }

        // Send the prepared frames to the socket.
        while frames.len() > 0 {
            match socket.send(&mut frames) {
                Ok(_) => {}
                Err(XdpError::WouldBlock) => {
                    // We would have blocked trying to send any of the frames, process any outstanding descriptors on the completion queue.
                    cq.process_queue();
                    continue;
                }
                Err(e) => {
                    // An unrecoverable error occurred, exit the loop.
                    println!("Error sending frames: {:?}", e);
                    break;
                }
            };
        }

        stats.maybe_print();
    }

    println!("Exiting...");
}
