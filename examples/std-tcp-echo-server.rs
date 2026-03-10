use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Parser)]
#[command(author, version, about = "Standard TCP echo server baseline")]
struct Args {
    #[arg(short, long, default_value = "[::1]:8080")]
    listen_addr: String,
}

struct Stats {
    bytes: u64,
    packets: u64,
    last_bytes: u64,
    last_packets: u64,
    last_time: u64,
    packets_per_print: u64,
}

impl Stats {
    fn new(packets_per_print: u64) -> Self {
        Self {
            bytes: 0,
            packets: 0,
            last_bytes: 0,
            last_packets: 0,
            last_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            packets_per_print,
        }
    }

    #[inline(always)]
    fn update(&mut self, bytes: usize) {
        self.bytes += bytes as u64;
        self.packets += 1;
    }

    #[inline(always)]
    fn maybe_print(&mut self) {
        if self.packets - self.last_packets < self.packets_per_print {
            return;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let elapsed = (now - self.last_time) as f64 / 1_000_000_000.0;

        let pps = (self.packets - self.last_packets) as f64 / elapsed;
        let bps = (self.bytes - self.last_bytes) as f64 / elapsed;

        println!(
            "Packets: {}K | Bytes: {:.2}GiB | Packet rate: {:.2} Kpps | Byte rate: {:.2} Gbps",
            self.packets / 1_000,
            self.bytes as f64 / 1024.0 / 1024.0 / 1024.0,
            pps / 1_000.0,
            (bps / 1024.0 / 1024.0 / 1024.0) * 8.0
        );

        self.last_packets = self.packets;
        self.last_bytes = self.bytes;
        self.last_time = now;
    }
}

fn main() {
    let args = Args::parse();

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async move {
        let listener = TcpListener::bind(&args.listen_addr)
            .await
            .expect("Failed to bind");
        println!("Listening on {}", args.listen_addr);

        listener.set_ttl(64).ok();

        while !exit.load(Ordering::Relaxed) {
            let (mut stream, addr) = listener.accept().await.expect("Failed to accept");
            println!("Accepted connection from {}", addr);

            stream.set_nodelay(true).ok();

            let mut stats = Stats::new(100_000);
            let mut buf = vec![0u8; 65535];

            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) => {
                        println!("Disconnected from {}", addr);
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        println!("Read error: {:?}", e);
                        break;
                    }
                };

                if let Err(e) = stream.write_all(&buf[..n]).await {
                    println!("Write error: {:?}", e);
                    break;
                }

                stats.update(n);
                stats.maybe_print();
            }
        }
    });

    println!("Exiting...");
}
