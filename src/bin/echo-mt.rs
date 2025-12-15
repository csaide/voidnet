use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use libc::c_int;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::MutableUdpPacket,
};

use libvoid::xdp::{
    socket::{Error as SocketError, Socket},
    umem::{CompletionQueue, FillQueue, Umem},
};

const FILL_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
const COMPLETION_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const RX_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const TX_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;
const FRAME_SIZE: usize = XSK_UMEM__DEFAULT_FRAME_SIZE as usize;

struct WorkerStats {
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
}

impl WorkerStats {
    pub fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    pub fn update(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::AcqRel);
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::AcqRel);
    }
}

struct Stats {
    workers: Vec<WorkerStats>,
}

impl Stats {
    pub fn new(num_workers: usize) -> Self {
        Self {
            workers: (0..num_workers).map(|_| WorkerStats::new()).collect(),
        }
    }

    pub fn update(&self, worker_id: usize, bytes: usize) {
        self.workers[worker_id].update(bytes);
    }
}

fn swap_addresses(frame: &mut [u8]) -> Option<()> {
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

fn worker_main(
    id: usize,
    exit: Arc<AtomicBool>,
    stats: Arc<Stats>,
    mut socket: Socket,
    batch_size: u32,
) {
    println!("Worker {} started", id);
    let mut to_write = Vec::with_capacity(batch_size as usize);
    while !exit.load(Ordering::Relaxed) {
        let mut frames = match socket.recv(batch_size) {
            Ok(frames) => frames,
            Err(SocketError::WouldBlock) => {
                continue;
            }
            Err(e) => {
                eprintln!("Worker {} failed to receive frames: {:?}", id, e);
                break;
            }
        };

        for mut frame in frames.drain(..) {
            stats.update(id, frame.len());

            if let None = swap_addresses(&mut frame) {
                continue;
            }

            to_write.push(frame);
        }

        // Send the updated frames to the socket.
        while to_write.len() > 0 {
            match socket.send(&mut to_write) {
                Ok(_) => break,
                Err(SocketError::WouldBlock) => {
                    break;
                }
                Err(e) => {
                    eprintln!("Worker {} failed to send frames: {:?}", id, e);
                    break;
                }
            };
        }
    }
    println!("Worker {} exiting", id);
}

fn umem_main(exit: Arc<AtomicBool>, mut fq: FillQueue, mut cq: CompletionQueue, fds: Vec<c_int>) {
    while !exit.load(Ordering::Relaxed) {
        for fd in fds.iter() {
            if let Err(e) = fq.maybe_wake(*fd) {
                eprintln!("Failed to wake fill queue for fd {}: {:?}", fd, e);
                exit.store(true, Ordering::Relaxed);
                break;
            }
        }

        fq.process_queue();
        cq.process_queue();
    }
}

fn stats_main(exit: Arc<AtomicBool>, stats: Arc<Stats>) {
    struct Tracker {
        packets_received: u64,
        bytes_received: u64,
        last_time: u64,
    }
    let mut trackers = Vec::with_capacity(stats.workers.len());
    for _ in 0..stats.workers.len() {
        trackers.push(Tracker {
            packets_received: 0,
            bytes_received: 0,
            last_time: 0,
        });
    }
    let interval = Duration::from_secs(1);

    while !exit.load(Ordering::Relaxed) {
        thread::sleep(interval);

        for (worker_id, stats) in stats.workers.iter().enumerate() {
            let packets_received = stats.packets_received.load(Ordering::Relaxed);
            let bytes_received = stats.bytes_received.load(Ordering::Relaxed);
            let tracker = &mut trackers[worker_id];

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            let elapsed_time = (now - tracker.last_time) as f64 / 1_000_000_000.0;

            let packets_per_second =
                (packets_received - tracker.packets_received) as f64 / elapsed_time;
            let bytes_per_second = (bytes_received - tracker.bytes_received) as f64 / elapsed_time;

            tracker.packets_received = packets_received;
            tracker.bytes_received = bytes_received;
            tracker.last_time = now;

            println!(
                "Worker {} | Packets: {}M | Bytes: {:.2}GiB | Packet rate: {:.2} Mpps | Byte rate: {:.2} Gbps",
                worker_id,
                packets_received / 1_000_000,
                bytes_received as f64 / 1024.0 / 1024.0 / 1024.0,
                packets_per_second / 1_000_000.0,
                bytes_per_second * 8.0 / 1_000_000_000.0
            );
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    if_name: String,
    #[arg(short, long)]
    queue: u32,
    #[arg(short, long, default_value = "2")]
    num_workers: usize,
    #[arg(short, long, default_value = "64")]
    batch_size: usize,
}
fn main() {
    let args = Args::parse();

    let (umem, mut fq, mut cq) = Umem::builder()
        .completion_ring_size(COMPLETION_RING_SIZE)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .build()
        .expect("Failed to create umem");

    let mut fds = Vec::with_capacity(args.num_workers);
    let mut threads = Vec::with_capacity(args.num_workers);
    let exit = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::new(args.num_workers));
    for i in 0..args.num_workers {
        let socket = if args.num_workers == 1 {
            Socket::builder(&args.if_name, args.queue)
                .rx_ring_size(RX_RING_SIZE)
                .tx_ring_size(TX_RING_SIZE)
                .build(umem.clone())
                .expect("Failed to create socket")
        } else {
            Socket::builder(&args.if_name, args.queue)
                .rx_ring_size(RX_RING_SIZE)
                .tx_ring_size(TX_RING_SIZE)
                .build_shared(umem.clone(), &mut fq, &mut cq)
                .expect("Failed to create socket")
        };
        fds.push(socket.fd());

        let t = thread::spawn({
            let exit = exit.clone();
            let stats = stats.clone();
            move || worker_main(i, exit, stats, socket, args.batch_size as u32)
        });
        threads.push(t);
    }

    let t = thread::spawn({
        let exit = exit.clone();
        move || umem_main(exit, fq, cq, fds)
    });
    threads.push(t);

    let t = thread::spawn(move || stats_main(exit, stats));
    threads.push(t);

    for t in threads {
        t.join().expect("Thread panicked");
    }
}
