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
    let (umem, mut fq, mut cq) = Umem::builder()
        .completion_ring_size(XSK_RING_CONS__DEFAULT_NUM_DESCS)
        .fill_ring_size(XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
        .frame_size(XSK_UMEM__DEFAULT_FRAME_SIZE as usize)
        .build()
        .expect("Failed to create umem");

    umem.init_thread_local();

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

    let mut to_write = Vec::with_capacity(args.batch_size);

    println!("Socket created, listening for packets...");

    // Setup some stats to track the number of packets and bytes received.
    let mut stats = Stats::new();
    while !exit.load(Ordering::Relaxed) {
        // First read some frames off the socket.
        let mut frames = match socket.recv(args.batch_size as u32) {
            Some(frames) => frames,
            None => {
                // There were no frames available to read, wake the fill queue and process any outstanding descriptors.
                fq.maybe_wake(socket.fd()).unwrap();
                fq.process_queue(args.batch_size as u32);
                continue;
            }
        };

        // For each received frame, attempt to swap the addresses, and then queue them for writes.
        for mut frame in frames.drain(..) {
            stats.update(frame.len());

            if let None = swap_addresses(&mut frame) {
                continue;
            }

            to_write.push(frame);
        }

        // Send the updated frames to the socket.
        while to_write.len() > 0 {
            match socket.send(&mut to_write) {
                Ok(_) => break,
                Err(XdpError::WouldBlock) => {
                    // We would have blocked trying to send any of the frames, process any outstanding descriptors on the completion queue.
                    cq.process_queue();
                    continue;
                }
                Err(e) => {
                    println!("Error sending frame: {:?}", e);
                    break;
                }
            }
        }

        stats.maybe_print();
    }

    println!("Exiting...");
}
