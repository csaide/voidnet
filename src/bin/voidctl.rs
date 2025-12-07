use std::{thread, time::Duration};

use libvoid::xdp::{
    socket::{Error, Socket},
    umem::{Mmap, Umem},
};
use pnet::packet::{
    Packet,
    ethernet::{EtherTypes, EthernetPacket},
    icmpv6::{Icmpv6Packet, Icmpv6Types, echo_request::EchoRequestPacket},
    ip::IpNextHeaderProtocols,
    ipv6::Ipv6Packet,
};

fn main() {
    let pool = Mmap::new(1024, 4096).expect("Failed to create mmap");
    let umem = Umem::new(pool, 32, 32).expect("Failed to create umem");
    let mut socket = Socket::new("test", 0, umem, 32, 32).expect("Failed to create socket");

    println!("Socket created");
    loop {
        let frame = match socket.recv() {
            Ok(frame) => frame,
            Err(Error::WouldBlock) => {
                thread::sleep(Duration::from_millis(100));
                // println!("Would block");
                continue;
            }
            Err(e) => {
                println!("Error receiving frame: {:?}", e);
                break;
            }
        };
        let ether = match EthernetPacket::new(frame.data()) {
            Some(packet) => packet,
            None => {
                println!("Got invalid Ethernet packet");
                continue;
            }
        };
        let ip = match ether.get_ethertype() {
            EtherTypes::Ipv6 => Ipv6Packet::new(ether.payload()).expect("invalid IPv6 packet"),
            _ => {
                println!("Got unknown Ethernet packet");
                continue;
            }
        };
        let icmp = match ip.get_next_header() {
            IpNextHeaderProtocols::Icmpv6 => {
                Icmpv6Packet::new(ip.payload()).expect("invalid ICMPv6 packet")
            }
            _ => {
                println!("Got unknown IP packet");
                continue;
            }
        };
        let req = match icmp.get_icmpv6_type() {
            Icmpv6Types::EchoRequest => {
                EchoRequestPacket::new(icmp.payload()).expect("invalid Echo Request packet")
            }
            _ => {
                println!("Got unknown ICMPv6 packet");
                continue;
            }
        };
        println!("Received frame: {:?}", req);
    }
}
