use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use clap::Parser;
use libc::c_int;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};

use libvoid::xdp::{
    context::XdpContext,
    error::Error,
    socket::Socket,
    umem::{CompletionQueue, FillQueue, Umem},
};

mod common;
use common::{Stats, stats_multi_main, swap_addresses};

const FILL_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
const COMPLETION_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const RX_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const TX_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;
const FRAME_SIZE: usize = XSK_UMEM__DEFAULT_FRAME_SIZE as usize;

fn worker_main(
    id: usize,
    exit: Arc<AtomicBool>,
    stats: Arc<Stats>,
    mut socket: Socket,
    batch_size: u32,
) {
    println!("Worker {} started", id);

    // Prepare a backing store for frames to write back to the socket, normally you could
    let mut to_write = Vec::with_capacity(batch_size as usize);
    while !exit.load(Ordering::Relaxed) {
        let mut frames = match socket.recv(batch_size) {
            Ok(frames) => frames,
            Err(Error::WouldBlock) => {
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
                Err(Error::WouldBlock) => {
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

    let mut xdp_program = XdpContext::new(&args.if_name).expect("Failed to create xdp program");

    let (umem, mut fq, mut cq) = Umem::builder()
        .completion_ring_size(COMPLETION_RING_SIZE)
        .fill_ring_size(FILL_RING_SIZE)
        .frame_size(FRAME_SIZE)
        .build()
        .expect("Failed to create umem");

    let mut fds = Vec::with_capacity(args.num_workers);
    let mut threads = Vec::with_capacity(args.num_workers);
    let exit = Arc::new(AtomicBool::new(false));

    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let stats = Arc::new(Stats::new(args.num_workers));
    for i in 0..args.num_workers {
        let socket = if args.num_workers == 1 {
            Socket::builder(&mut xdp_program, &args.if_name, args.queue)
                .rx_ring_size(RX_RING_SIZE)
                .tx_ring_size(TX_RING_SIZE)
                .build(umem.clone())
                .expect("Failed to create socket")
        } else {
            Socket::builder(&mut xdp_program, &args.if_name, args.queue)
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

    let t = thread::spawn(move || stats_multi_main(exit, stats));
    threads.push(t);

    for t in threads {
        t.join().expect("Thread panicked");
    }
    println!("Exiting...");
}
