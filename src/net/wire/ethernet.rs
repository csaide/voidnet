use std::fmt::Display;

use crate::xdp::frame::Frame;

/// A MAC address representation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(C, packed)]
pub struct MacAddress {
    pub octets: [u8; 6],
}

impl MacAddress {
    /// Creates a new MAC address.
    pub const fn new(octets: [u8; 6]) -> Self {
        Self { octets }
    }

    /// Creates a broadcast MAC address.
    pub const fn broadcast() -> Self {
        Self::new([0xFF; 6])
    }

    /// Creates a zero MAC address.
    pub const fn zero() -> Self {
        Self::new([0x00; 6])
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(mac: MacAddress) -> Self {
        mac.octets
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

/// An EtherType representation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(C, packed)]
pub struct EtherType {
    pub octets: [u8; 2],
}

impl Display for EtherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            EtherTypes::IPv4 => write!(f, "IPv4"),
            EtherTypes::IPv6 => write!(f, "IPv6"),
            EtherTypes::Arp => write!(f, "ARP"),
            _ => write!(f, "Unknown"),
        }
    }
}

/// EtherTypes.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod EtherTypes {
    use super::EtherType;

    /// IPv4 EtherType.
    pub const IPv4: EtherType = EtherType {
        octets: [0x08, 0x00],
    };

    /// IPv6 EtherType.
    pub const IPv6: EtherType = EtherType {
        octets: [0x86, 0xDD],
    };

    /// ARP EtherType.
    pub const Arp: EtherType = EtherType {
        octets: [0x08, 0x06],
    };
}

/// An Ethernet frame representation.
#[derive(Debug)]
#[repr(C, packed)]
pub struct EthernetFrame {
    /// Destination MAC address.
    pub dst_mac: MacAddress,
    /// Source MAC address.
    pub src_mac: MacAddress,
    /// EtherType.
    pub ether_type: EtherType,
}

impl EthernetFrame {
    /// Zero-copy borrow of the Ethernet header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= size_of::<EthernetFrame>()`.
    pub fn from_frame<'frame, 'umem>(frame: &'frame Frame<'umem>) -> &'frame Self {
        debug_assert!(frame.len() >= size_of::<EthernetFrame>());
        unsafe { &*(frame.as_ptr() as *const Self) }
    }

    /// Mutable zero-copy borrow of the Ethernet header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= size_of::<EthernetFrame>()`.
    pub fn from_frame_mut<'frame, 'umem>(frame: &'frame mut Frame<'umem>) -> &'frame mut Self {
        debug_assert!(frame.len() >= size_of::<EthernetFrame>());
        unsafe { &mut *(frame.as_mut_ptr() as *mut Self) }
    }
}

impl Display for EthernetFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EthernetFrame {{ src_mac: {}, dst_mac: {}, ether_type: {} }}",
            self.src_mac, self.dst_mac, self.ether_type
        )
    }
}

#[inline]
pub fn write_ethernet_header(
    frame: &mut Frame<'_>,
    dst_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: EtherType,
) {
    let eth = EthernetFrame::from_frame_mut(frame);
    eth.dst_mac = dst_mac;
    eth.src_mac = src_mac;
    eth.ether_type = ether_type;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_address_constructors() {
        let mac = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(mac.octets, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(MacAddress::broadcast().octets, [0xFF; 6]);
        assert_eq!(MacAddress::zero().octets, [0x00; 6]);
    }

    #[test]
    fn mac_address_from_conversions() {
        let mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(mac.octets, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let arr: [u8; 6] = mac.into();
        assert_eq!(arr, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn ether_type_constants() {
        assert_eq!(EtherTypes::IPv4.octets, [0x08, 0x00]);
        assert_eq!(EtherTypes::IPv6.octets, [0x86, 0xDD]);
        assert_eq!(EtherTypes::Arp.octets, [0x08, 0x06]);
    }

    #[test]
    fn ethernet_frame_layout() {
        assert_eq!(size_of::<EthernetFrame>(), 14);
    }
}
