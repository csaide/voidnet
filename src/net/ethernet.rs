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

/// An EtherType representation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(C, packed)]
pub struct EtherType {
    pub octets: [u8; 2],
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
