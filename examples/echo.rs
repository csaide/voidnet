use std::{
    collections::VecDeque,
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

use libvoid::xdp_v2::{context::XdpContext, socket::Socket, umem::Umem};

mod common;
use common::{Stats, swap_addresses};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    if_name: String,
    #[arg(short, long)]
    queue: u32,
    #[arg(short, long, default_value = "64")]
    batch_size: usize,
}

fn main() {
    let args = Args::parse();

    // Every XDP program starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name).expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use, you can however have multiple
    // sockets attached to the same Umem.
    let (umem, mut fq, mut cq, mut _write_frames) = Umem::builder()
        .completion_ring_size(XSK_RING_CONS__DEFAULT_NUM_DESCS)
        .fill_ring_size(XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
        .frame_size(XSK_UMEM__DEFAULT_FRAME_SIZE as usize)
        .fill_process_threshold(1)
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

    println!("Socket created, listening for packets...");

    // Setup some stats to track the number of packets and bytes received.
    let mut stats = Stats::new();
    let mut frames = VecDeque::with_capacity(args.batch_size);
    while !exit.load(Ordering::Relaxed) {
        fq.maybe_wake(socket.fd()).unwrap();
        fq.process_queue(&mut frames);
        assert_eq!(frames.len(), 0);

        // First read some frames off the socket.
        let received = socket.recv(&mut frames);
        if received == 0 {
            // There were no frames available to read, wake the fill queue and process any outstanding descriptors.
            continue;
        }

        // For each received frame, attempt to swap the addresses, and then queue them for writes.
        for mut frame in frames.iter_mut() {
            stats.update(frame.len());

            swap_addresses(&mut frame).unwrap();
        }

        // Send the updated frames to the socket.
        let _ = socket.send(&mut frames);

        while frames.len() < received {
            socket.maybe_wake().expect("Failed to wake tx queue");
            cq.process_queue(&mut frames);
        }

        stats.maybe_print();
    }

    println!("Exiting...");
}
