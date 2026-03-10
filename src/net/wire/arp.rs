use std::mem::size_of;

use super::{
    ethernet::{EtherType, EthernetFrame, MacAddress},
    ip::Ipv4Address,
};

/// ARP hardware type representation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(C, packed)]
pub struct ArpHardwareType {
    pub octets: [u8; 2],
}

/// ARP hardware types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ArpHardwareTypes {
    use super::ArpHardwareType;

    /// Ethernet hardware type.
    pub const Ethernet: ArpHardwareType = ArpHardwareType {
        octets: [0x00, 0x01],
    };
}

/// ARP operation representation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(C, packed)]
pub struct ArpOperation {
    pub octets: [u8; 2],
}

/// ARP operations.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ArpOperations {
    use super::ArpOperation;

    /// ARP request operation.
    pub const Request: ArpOperation = ArpOperation {
        octets: [0x00, 0x01],
    };

    /// ARP reply operation.
    pub const Reply: ArpOperation = ArpOperation {
        octets: [0x00, 0x02],
    };
}

/// An ARP packet for Ethernet / IPv4.
///
/// This is the 28-byte ARP payload that immediately follows the 14-byte
/// Ethernet header. The struct is `repr(C, packed)` so it can be
/// zero-copy-cast directly from a received frame.
#[repr(C, packed)]
pub struct ArpPacket {
    /// ARP hardware type.
    pub htype: ArpHardwareType,
    /// ARP protocol type.
    pub ptype: EtherType,
    /// ARP hardware address length.
    pub hlen: u8,
    /// ARP protocol address length.
    pub plen: u8,
    /// ARP operation.
    pub oper: ArpOperation,
    /// ARP sender hardware address.
    pub sha: MacAddress,
    /// ARP sender protocol address.
    pub spa: Ipv4Address,
    /// ARP target hardware address.
    pub tha: MacAddress,
    /// ARP target protocol address.
    pub tpa: Ipv4Address,
}

/// Complete ARP Ethernet frame (Ethernet header + ARP packet).
#[repr(C, packed)]
pub struct ArpFrame {
    pub ethernet: EthernetFrame,
    pub arp: ArpPacket,
}

impl ArpFrame {
    /// Returns the raw bytes of the ARP frame.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Mutable zero-copy borrow of the ARP frame from a received frame.
    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        debug_assert!(bytes.len() >= ARP_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }
}

/// Minimum frame length for an Ethernet + ARP packet.
pub const ARP_FRAME_LEN: usize = size_of::<ArpFrame>();
const _: () = assert!(ARP_FRAME_LEN == 42);

impl ArpPacket {
    /// Zero-copy borrow of the ARP header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= ARP_FRAME_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        debug_assert!(bytes.len() >= ARP_FRAME_LEN);
        unsafe { &*(bytes.as_ptr().add(size_of::<EthernetFrame>()) as *const Self) }
    }

    /// Mutable zero-copy borrow of the ARP header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= ARP_FRAME_LEN`.
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        debug_assert!(bytes.len() >= ARP_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr().add(size_of::<EthernetFrame>()) as *mut Self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_constants() {
        assert_eq!(ArpHardwareTypes::Ethernet.octets, [0x00, 0x01]);
        assert_eq!(ArpOperations::Request.octets, [0x00, 0x01]);
        assert_eq!(ArpOperations::Reply.octets, [0x00, 0x02]);
    }

    #[test]
    fn arp_packet_layout() {
        assert_eq!(size_of::<ArpPacket>(), 28);
        assert_eq!(ARP_FRAME_LEN, 42);
    }
}
