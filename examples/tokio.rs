use std::ops::{Deref, DerefMut};

use clap::Parser;
use tokio::net::UdpSocket;

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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut stats = Stats::new_with_packets_per_print(1);

    let udp = UdpSocket::bind("[fc00:dead:cafe:1::2]:8080")
        .await
        .expect("Failed to bind UDP socket");

    println!("Listening on [fc00:dead:cafe:1::2]:8080");
    let mut buf = [0; 1024];
    loop {
        let (n, _) = udp
            .recv_from(&mut buf)
            .await
            .expect("Failed to receive packet");
        stats.update(n, false);
        stats.maybe_print();
    }
}
