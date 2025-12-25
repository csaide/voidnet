use std::{
    collections::VecDeque,
    net::Ipv6Addr,
    num::NonZero,
    ops::{Deref, DerefMut},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
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

use libvoid::xdp::{
    context::XdpContext,
    frame::Frame,
    socket::Socket,
    umem::{CompletionQueue, Umem},
};

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
    #[arg(short, long, default_value = "1")]
    num_threads: NonZero<usize>,
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

fn worker_thread(
    exit: Arc<AtomicBool>,
    mut stats: Stats,
    frame_stack: Arc<Mutex<VecDeque<Frame>>>,
    mut socket: Socket,
    batch_size: usize,
    data_len: usize,
) {
    while !exit.load(Ordering::Relaxed) {
        let mut frame_stack = frame_stack.lock().unwrap();
        let batch_size = frame_stack.len().min(batch_size);
        if batch_size == 0 {
            socket.maybe_wake().unwrap();
            continue;
        }

        let mut frames = frame_stack.drain(..batch_size).collect::<VecDeque<Frame>>();
        match socket.send(&mut frames) {
            Ok(sent) => {
                stats.update_batch(sent as usize, data_len);
            }
            Err(_) => {
                // We would have blocked, loop back and try again.
                continue;
            }
        };

        socket.maybe_wake().unwrap();
        stats.maybe_print();
    }
}

fn umem_thread(
    exit: Arc<AtomicBool>,
    mut completion_queue: CompletionQueue,
    frame_stack: Arc<Mutex<VecDeque<Frame>>>,
    data_len: usize,
) {
    while !exit.load(Ordering::Relaxed) {
        let mut guard = frame_stack.lock().unwrap();
        completion_queue.process_queue(&mut guard, Some(data_len));
    }
}

fn main() {
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    //
    // You will need one of these for each unique device + queue ID tuple you want to use. In the case of this example, we
    // are using a single device and a single queue on that device so hence a single Umem instance.
    //
    // Each Umem comes associated with three key components:
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    // - Frames (frames) > A set of frames that are backed by the umem which are shared between the kernel and user space.
    let (umem, mut fq, mut cq, mut frames) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.busy_poll_batch_size * args.num_threads.get())
        .build::<VecDeque<Frame>>()
        .expect("Failed to create umem");

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

    // For writes we need to write some data :), so fill up our frames with our mock UDP packet.
    let data = build_frame(&args);
    for frame in frames.iter_mut() {
        unsafe { frame.copy_from(&data) };
    }

    // Since we are going to be using multiple threads, we need to wrap up our frame stack in a arc/mutex to
    // share it between the workers and umem threads
    let frame_stack = Arc::new(Mutex::new(frames));

    // Create some backing collections so we can join our threads.
    let mut threads = Vec::with_capacity(args.num_threads.get() + 1);
    let data_len = data.len();
    for i in 0..args.num_threads.get() {
        let exit = exit.clone();
        let stats = Stats::new_with_id(i);
        let frame_stack = frame_stack.clone();
        let batch_size = args.busy_poll_batch_size;

        // Create a new socket for each thread, in this case passing in the already created umem instance.
        let socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
            .rx_ring_size(args.rx_ring_size)
            .tx_ring_size(args.tx_ring_size)
            .busy_poll(args.busy_poll)
            .busy_poll_batch_size(args.busy_poll_batch_size)
            .busy_poll_timeout_us(args.busy_poll_timeout_us)
            .copy_mode(args.copy_mode)
            // If we are using multiple threads, we need to share the umem instance, otherwise its an error
            // to use a shared umem with a single socket, though it will "work".
            .shared_umem(args.num_threads.get() > 1)
            .build(umem.clone(), &mut fq, &mut cq)
            .expect("Failed to create socket");

        // Spawn our worker thread, this will handle sending frames to the socket.
        let thread = thread::spawn(move || {
            worker_thread(exit, stats, frame_stack, socket, batch_size, data_len)
        });
        threads.push(thread);
    }

    // Spawn our Umem thread, this will handle actually retrieving handled frames from the completion queue.
    threads.push(thread::spawn(move || {
        umem_thread(exit, cq, frame_stack, data_len)
    }));

    println!("All threads created, sending packets...");

    // Wait for exit of all threads.
    for thread in threads.drain(..) {
        thread.join().unwrap();
    }
}
