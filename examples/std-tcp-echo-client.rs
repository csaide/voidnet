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
    net::TcpStream,
};

#[derive(Parser)]
#[command(author, version, about = "Standard TCP echo client baseline")]
struct Args {
    #[arg(short, long, default_value = "[::1]:8080")]
    remote_addr: String,
    #[arg(short, long, default_value = "64")]
    message_size: usize,
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
        println!("Connecting to {}...", args.remote_addr);

        let mut stream = TcpStream::connect(&args.remote_addr)
            .await
            .expect("Failed to connect");

        stream.set_nodelay(true).ok();

        println!("Connected to {}", args.remote_addr);

        let payload = vec![0xABu8; args.message_size];
        let mut read_buf = vec![0u8; args.message_size];
        let mut stats = Stats::new(100_000);

        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }

            if let Err(e) = stream.write_all(&payload).await {
                println!("Write error: {:?}", e);
                break;
            }

            let mut total_read = 0;
            while total_read < args.message_size {
                let n = match stream.read(&mut read_buf[total_read..]).await {
                    Ok(0) => {
                        println!("Server closed connection");
                        return;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        println!("Read error: {:?}", e);
                        return;
                    }
                };
                total_read += n;
            }

            stats.update(total_read);
            stats.maybe_print();
        }
    });

    println!("Exiting...");
}
