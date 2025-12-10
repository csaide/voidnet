use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use pnet::{
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
    util::MacAddr,
};

use super::{Error, LookupTable, Result};

const ETH_HEADER_SIZE: usize = 14;
const ARP_PACKET_SIZE: usize = 42;

pub enum DecodeResult {
    NeedsReply,
    Done,
}

pub struct Arp {
    precomputed: Vec<u8>,
    lookup_table: Arc<LookupTable>,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
}

impl Arp {
    pub fn new(src_mac: MacAddr, src_ip: Ipv4Addr, lookup_table: Arc<LookupTable>) -> Result<Self> {
        let mut precomputed = vec![0u8; ARP_PACKET_SIZE];

        let mut pkt = MutableEthernetPacket::new(&mut precomputed[..ETH_HEADER_SIZE])
            .ok_or(Error::MemoryExhausted)?;
        pkt.set_destination(MacAddr::broadcast());
        pkt.set_source(src_mac);
        pkt.set_ethertype(EtherTypes::Arp);

        let mut pkt = MutableArpPacket::new(&mut precomputed[ETH_HEADER_SIZE..])
            .ok_or(Error::MemoryExhausted)?;
        pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
        pkt.set_protocol_type(EtherTypes::Ipv4);
        pkt.set_hw_addr_len(6);
        pkt.set_proto_addr_len(4);
        pkt.set_operation(ArpOperations::Request);
        pkt.set_sender_hw_addr(src_mac);
        pkt.set_sender_proto_addr(src_ip);
        pkt.set_target_hw_addr(MacAddr::zero());
        pkt.set_target_proto_addr(Ipv4Addr::UNSPECIFIED);

        Ok(Self {
            precomputed,
            lookup_table,
            src_mac,
            src_ip,
        })
    }

    pub fn fill_frame(&self, dst_ip: Ipv4Addr, data: &mut [u8]) -> Result<usize> {
        // Ensure the data is large enough to hold the ARP packet, this should always be true but one never knows.
        if data.len() < ARP_PACKET_SIZE {
            return Err(Error::BufferTooSmall {
                needed: ARP_PACKET_SIZE,
                available: data.len(),
            });
        }

        // SAFETY: We know the data is large enough to hold the precomputed packet, and we know its initialized and cannot possibly be overlapping.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.precomputed.as_ptr(),
                data.as_mut_ptr(),
                ARP_PACKET_SIZE,
            );
        }

        // Update the target protocol address to the specified destination IP address.
        let mut pkt = MutableArpPacket::new(&mut data[ETH_HEADER_SIZE..ARP_PACKET_SIZE])
            .ok_or(Error::MemoryExhausted)?;
        pkt.set_target_proto_addr(dst_ip);

        Ok(ARP_PACKET_SIZE)
    }

    pub fn decode_frame(&self, data: &mut [u8]) -> Result<DecodeResult> {
        if data.len() < ARP_PACKET_SIZE {
            return Err(Error::BufferTooSmall {
                needed: ARP_PACKET_SIZE,
                available: data.len(),
            });
        }

        let mut pkt =
            MutableArpPacket::new(&mut data[14..ARP_PACKET_SIZE]).ok_or(Error::InvalidArpPacket)?;

        // Hard code support for Ethernet only for now.
        if pkt.get_hardware_type() != ArpHardwareTypes::Ethernet || pkt.get_hw_addr_len() != 6 {
            return Err(Error::InvalidArpPacket);
        }

        // IPv6 will be supported using NDP not ARP, so hard code support for IPv4 only for now.
        if pkt.get_protocol_type() != EtherTypes::Ipv4 || pkt.get_proto_addr_len() != 4 {
            return Err(Error::InvalidArpPacket);
        }

        self.lookup_table.insert(
            IpAddr::V4(pkt.get_sender_proto_addr()),
            pkt.get_sender_hw_addr(),
        );

        if self.src_ip != pkt.get_target_proto_addr() {
            return Ok(DecodeResult::Done);
        }

        match pkt.get_operation() {
            ArpOperations::Request => {
                // Handle ARP requests by returning a request result.
                let sender_hw_addr = pkt.get_sender_hw_addr();
                let sender_proto_addr = pkt.get_sender_proto_addr();
                pkt.set_operation(ArpOperations::Reply);
                pkt.set_sender_hw_addr(self.src_mac);
                pkt.set_sender_proto_addr(self.src_ip);
                pkt.set_target_hw_addr(sender_hw_addr);
                pkt.set_target_proto_addr(sender_proto_addr);

                Ok(DecodeResult::NeedsReply)
            }
            ArpOperations::Reply => Ok(DecodeResult::Done),
            _ => Err(Error::InvalidArpPacket),
        }
    }
}
