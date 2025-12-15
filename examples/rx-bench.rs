use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use clap::Parser;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};

use libvoid::xdp::{context::XdpContext, error::Error as XdpError, socket::Socket, umem::Umem};

mod common;
use common::{WorkerStats, stats_single_main};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    if_name: String,
    #[arg(short, long)]
    queue: u32,
}

fn main() {
    let args = Args::parse();

    // Every XDP program starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name).expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use, you can however have multiple
    // sockets attached to the same Umem.
    let (umem, mut fq, _cq) = Umem::builder()
        .completion_ring_size(XSK_RING_CONS__DEFAULT_NUM_DESCS)
        .fill_ring_size(XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
        .frame_size(XSK_UMEM__DEFAULT_FRAME_SIZE as usize)
        .build()
        .expect("Failed to create umem");

    // A socket represents a standard means of reading/writing packets from/to a network interface.
    let mut socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
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

    // Setup some stats to track the number of packets and bytes received.
    let stats = Arc::new(WorkerStats::new());

    // Spawn a thread to print out the stats.
    let t = std::thread::spawn({
        let exit = exit.clone();
        let stats = stats.clone();
        move || stats_single_main(exit, stats)
    });

    println!("Socket created, listening for packets...");

    // The XDP subsystem is designed for low latency and high throughput, so we always batch receive packets
    // to avoid context switching overhead. The batch size is a maximum value and not necessarily the number
    // of frames operated on at a time.
    let batch_size = 64;
    while !exit.load(Ordering::Relaxed) {
        // This is different than what you might expect, since we are using a Umem we don't specify buffers to fill
        // during recv() instead we request a batch up to a maximum size to read at a time.
        //
        // If no frames are available to read this returns an error of type [Error::WouldBlock]. All other errors are considered fatal.
        match socket.recv(batch_size) {
            Ok(frames) => {
                for frame in frames {
                    // Do something with the frame!
                    stats.update(frame.len());
                }
            }
            Err(XdpError::WouldBlock) => {
                fq.maybe_wake(socket.fd()).unwrap();
                fq.process_queue();
                continue;
            }
            Err(e) => {
                println!("Fatal error receiving frame: {:?}", e);
                break;
            }
        }
    }

    t.join().expect("Stats thread panicked");

    println!("Exiting...");
}
