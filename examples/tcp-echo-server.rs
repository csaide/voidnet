use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;

use libvoid::rt::LocalRuntime;
use libvoid::{
    net::{socket::TcpListener, wire::ip::SocketAddr},
    rt::spawn,
};

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

                spawn(async move {
                    let mut stats = Stats::new_with_id_and_packets_per_print(
                        stream.remote_port() as usize,
                        1_000_000,
                    );
                    loop {
                        match stream.splice(65535).await {
                            Ok(0) => {
                                println!(
                                    "Disconnected from {}:{}",
                                    stream.remote_addr(),
                                    stream.remote_port()
                                );
                                break;
                            }
                            Ok(n) => {
                                stats.update(n, false);
                                stats.maybe_print();
                            }
                            Err(e) => {
                                println!("Splice error: {:?}", e);
                                break;
                            }
                        }
                    }
                });
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
