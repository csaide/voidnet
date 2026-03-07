use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;

use libvoid::net::{socket::TcpStream, wire::ip::SocketAddr};
use libvoid::rt::LocalRuntime;

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::2]:8080")]
    local_addr: SocketAddr,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:8080")]
    remote_addr: SocketAddr,
    #[arg(short, long, default_value = "64")]
    message_size: usize,
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

    let mut runtime = LocalRuntime::builder(&args.if_name, args.queue)
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

    let message_size = args.message_size;

    runtime
        .run(exit, async move {
            println!(
                "Connecting from {} to {}...",
                args.local_addr, args.remote_addr
            );

            let stream = TcpStream::connect(
                args.local_addr.ip,
                args.local_addr.port,
                args.remote_addr.ip,
                args.remote_addr.port,
            )
            .expect("Failed to initiate connection")
            .await
            .expect("Connection failed");

            println!(
                "Connected to {}:{}",
                stream.remote_addr(),
                stream.remote_port()
            );

            let payload = vec![0xABu8; message_size];
            let mut read_buf = vec![0u8; message_size];

            loop {
                stream.write(&payload).await;

                let mut total_read = 0;
                while total_read < message_size {
                    let n = stream.read(&mut read_buf[total_read..]).await;
                    if n == 0 {
                        println!("Server closed connection");
                        return;
                    }
                    total_read += n;
                }

                stats.update(total_read, false);
                stats.maybe_print();
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
