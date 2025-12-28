use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes};

use crate::xdp::frame::Frame;

#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, KnownLayout, Immutable, IntoBytes, FromBytes,
)]
#[repr(C)]
pub struct MacAddress {
    pub address: [u8; 6],
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
            self.address[4],
            self.address[5]
        )
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    KnownLayout,
    Immutable,
    IntoBytes,
    TryFromBytes,
)]
#[repr(u16)]
pub enum EthernetType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
}

impl std::fmt::Debug for EthernetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EthernetType::Ipv4 => write!(f, "IPv4"),
            EthernetType::Arp => write!(f, "ARP"),
            EthernetType::Ipv6 => write!(f, "IPv6"),
        }
    }
}

impl std::fmt::Display for EthernetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(PartialEq, Eq, Hash, KnownLayout, Immutable, IntoBytes, TryFromBytes)]
#[repr(C)]
pub struct EthernetHeader {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: EthernetType,
}

impl std::fmt::Debug for EthernetHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EthernetHeader(destination: {}, source: {}, ethertype: {})",
            self.destination, self.source, self.ethertype
        )
    }
}

impl std::fmt::Display for EthernetHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl EthernetHeader {
    pub fn swap_addresses(&mut self) {
        // SAFETY: We are guaranteed that source/destination are the same size, valid values, and can't possibly be overlapping.
        unsafe { std::ptr::swap_nonoverlapping(&mut self.source, &mut self.destination, 1) };
    }
}

#[derive(Debug, PartialEq, Eq, Hash, KnownLayout, Immutable, TryFromBytes)]
#[repr(C)]
pub struct EthernetPacket {
    pub header: EthernetHeader,
    pub payload: [u8],
}

pub struct EthernetFrame {
    _frame: Ref<Frame, EthernetPacket>,
}
