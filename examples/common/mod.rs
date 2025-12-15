#![allow(dead_code)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::MutableUdpPacket,
};

pub struct WorkerStats {
    pub packets_received: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl WorkerStats {
    pub fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    pub fn update(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

pub struct MultiThreadedStats {
    pub workers: Vec<WorkerStats>,
}

impl MultiThreadedStats {
    pub fn new(num_workers: usize) -> Self {
        Self {
            workers: (0..num_workers).map(|_| WorkerStats::new()).collect(),
        }
    }

    pub fn update(&self, worker_id: usize, bytes: usize) {
        self.workers[worker_id].update(bytes);
    }
}

pub fn stats_multi_main(exit: Arc<AtomicBool>, stats: Arc<MultiThreadedStats>) {
    struct Tracker {
        packets_received: u64,
        bytes_received: u64,
        last_time: u64,
    }
    let mut trackers = Vec::with_capacity(stats.workers.len());
    for _ in 0..stats.workers.len() {
        trackers.push(Tracker {
            packets_received: 0,
            bytes_received: 0,
            last_time: 0,
        });
    }
    let interval = Duration::from_secs(1);

    while !exit.load(Ordering::Relaxed) {
        thread::sleep(interval);

        for (worker_id, stats) in stats.workers.iter().enumerate() {
            let packets_received = stats.packets_received.load(Ordering::Relaxed);
            let bytes_received = stats.bytes_received.load(Ordering::Relaxed);
            let tracker = &mut trackers[worker_id];

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            let elapsed_time = (now - tracker.last_time) as f64 / 1_000_000_000.0;

            let packets_per_second =
                (packets_received - tracker.packets_received) as f64 / elapsed_time;
            let bytes_per_second = (bytes_received - tracker.bytes_received) as f64 / elapsed_time;

            tracker.packets_received = packets_received;
            tracker.bytes_received = bytes_received;
            tracker.last_time = now;

            println!(
                "Worker {} | Packets: {}M | Bytes: {:.2}GiB | Packet rate: {:.2} Mpps | Byte rate: {:.2} Gbps",
                worker_id,
                packets_received / 1_000_000,
                bytes_received as f64 / 1024.0 / 1024.0 / 1024.0,
                packets_per_second / 1_000_000.0,
                bytes_per_second * 8.0 / 1_000_000_000.0
            );
        }
    }
}

pub struct Stats {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub last_packets_received: u64,
    pub last_bytes_received: u64,
    pub last_time: u64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            packets_received: 0,
            bytes_received: 0,
            last_packets_received: 0,
            last_bytes_received: 0,
            last_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }

    pub fn update(&mut self, bytes: usize) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
    }

    pub fn maybe_print(&mut self) {
        const PACKETS_PER_PRINT: u64 = 20_000_000;
        if self.packets_received - self.last_packets_received < PACKETS_PER_PRINT {
            return;
        }

        let packets_received = self.packets_received;
        let bytes_received = self.bytes_received;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let elapsed_time = (now - self.last_time) as f64 / 1_000_000_000.0;

        let packets_per_second =
            (packets_received - self.last_packets_received) as f64 / elapsed_time;
        let bytes_per_second = (bytes_received - self.last_bytes_received) as f64 / elapsed_time;

        self.last_packets_received = packets_received;
        self.last_bytes_received = bytes_received;
        self.last_time = now;

        println!(
            "Packets: {}M | Bytes: {:.2}GiB | Packet rate: {:.2} Mpps | Byte rate: {:.2} Gbps",
            packets_received / 1_000_000,
            bytes_received as f64 / 1024.0 / 1024.0 / 1024.0,
            packets_per_second / 1_000_000.0,
            bytes_per_second * 8.0 / 1_000_000_000.0
        );
    }
}

pub fn swap_addresses(frame: &mut [u8]) -> Option<()> {
    let mut ether = MutableEthernetPacket::new(frame)?;

    let dst = ether.get_destination();
    ether.set_destination(ether.get_source());
    ether.set_source(dst);

    let payload_offset = EthernetPacket::minimum_packet_size();
    let (transport, payload_offset) = match ether.get_ethertype() {
        EtherTypes::Ipv6 => {
            let mut ip = MutableIpv6Packet::new(&mut frame[payload_offset..])?;
            let dst = ip.get_destination();
            ip.set_destination(ip.get_source());
            ip.set_source(dst);
            (ip.get_next_header(), Ipv6Packet::minimum_packet_size())
        }
        EtherTypes::Ipv4 => {
            let mut ip = MutableIpv4Packet::new(&mut frame[payload_offset..])?;
            let dst = ip.get_destination();
            ip.set_destination(ip.get_source());
            ip.set_source(dst);
            (
                ip.get_next_level_protocol(),
                ip.get_header_length() as usize * 4,
            )
        }
        _ => return None,
    };

    match transport {
        IpNextHeaderProtocols::Udp => {
            let mut udp = MutableUdpPacket::new(&mut frame[payload_offset..])?;
            let dst = udp.get_destination();
            udp.set_destination(udp.get_source());
            udp.set_source(dst);
        }
        _ => return None,
    }

    Some(())
}
