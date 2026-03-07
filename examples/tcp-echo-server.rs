use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;

use libvoid::net::{socket::TcpListener, wire::ip::SocketAddr};
use libvoid::rt::LocalRuntime;

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:8080")]
    local_addr: SocketAddr,
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
    let mut stats = Stats::new_with_packets_per_print(1_000_000);
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

    runtime
        .run(exit, async move {
            let listener = TcpListener::listen(args.local_addr.ip, args.local_addr.port)
                .expect("Failed to listen");
            println!("Listening on {}", args.local_addr);

            loop {
                let stream = listener.accept().await;
                println!(
                    "Accepted connection from {}:{}",
                    stream.remote_addr(),
                    stream.remote_port()
                );

                let mut buf = [0u8; 65535];
                loop {
                    let n = stream.read(&mut buf).await;
                    if n == 0 {
                        println!(
                            "Disconnected from {}:{}",
                            stream.remote_addr(),
                            stream.remote_port()
                        );
                        break;
                    }
                    stream.write(&buf[..n]).await;
                    stats.update(n, false);
                    stats.maybe_print();
                }
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
