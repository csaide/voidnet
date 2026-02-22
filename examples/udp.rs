use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::Parser;

use libvoid::rt::LocalRuntime;

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
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

    let mut runtime = LocalRuntime::builder(
        &args.if_name,
        args.queue,
        [0xe2, 0x9a, 0x1b, 0xd4, 0xa7, 0x1c],
    )
    .arp_ttl(Duration::from_secs(1200))
    .attach_mode(args.attach_mode)
    .enable_fragmentation(args.enable_fragmentation)
    .completion_ring_size(args.completion_ring_size)
    .fill_ring_size(args.fill_ring_size)
    .frame_size(args.frame_size)
    .busy_poll(args.busy_poll)
    .busy_poll_batch_size(args.busy_poll_batch_size)
    .busy_poll_timeout_us(args.busy_poll_timeout_us)
    .huge_tables(args.huge_tables)
    .unaligned(args.unaligned)
    .rx_ring_size(args.rx_ring_size)
    .tx_ring_size(args.tx_ring_size)
    .copy_mode(args.copy_mode)
    .build()
    .expect("Failed to create runtime");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let addr = "fc00:dead:cafe:1::1"
        .parse()
        .expect("Failed to parse IPv6 address");
    let mut socket = runtime
        .bind_udp(addr, 8080)
        .expect("Failed to bind UDP socket");

    runtime
        .run(exit, async move {
            println!("Listening on {:?}:8080", addr);

            loop {
                let packet = socket.recv_from().await;
                stats.update(packet.packet.len(), false);
                socket.discard_packet(packet);

                stats.maybe_print();
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
