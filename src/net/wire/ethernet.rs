use std::fmt::Display;

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
    pub fn from_bytes(frame: &[u8]) -> &Self {
        assert!(frame.len() >= size_of::<EthernetFrame>());
        unsafe { &*(frame.as_ptr() as *const Self) }
    }

    /// Mutable zero-copy borrow of the Ethernet header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= size_of::<EthernetFrame>()`.
    pub fn from_bytes_mut(frame: &mut [u8]) -> &mut Self {
        assert!(frame.len() >= size_of::<EthernetFrame>());
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

/// Writes the Ethernet header to a frame.
#[inline]
pub fn write_ethernet_header(
    frame: &mut [u8],
    dst_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: EtherType,
) {
    let eth = EthernetFrame::from_bytes_mut(frame);
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

    #[test]
    #[should_panic(expected = "assertion")]
    fn from_bytes_rejects_truncated_frame() {
        let short = [0u8; 13]; // EthernetFrame needs 14 bytes
        let _ = EthernetFrame::from_bytes(&short);
    }

    #[test]
    fn from_bytes_accepts_minimum_frame() {
        let exact = [0u8; 14];
        let frame = EthernetFrame::from_bytes(&exact);
        let _ = frame.ether_type;
    }

    #[test]
    fn mac_address_display() {
        let mac = MacAddress::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(format!("{}", mac), "01:23:45:67:89:ab");

        assert_eq!(format!("{}", MacAddress::zero()), "00:00:00:00:00:00");
        assert_eq!(format!("{}", MacAddress::broadcast()), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn ether_type_display() {
        assert_eq!(format!("{}", EtherTypes::IPv4), "IPv4");
        assert_eq!(format!("{}", EtherTypes::IPv6), "IPv6");
        assert_eq!(format!("{}", EtherTypes::Arp), "ARP");
        assert_eq!(
            format!(
                "{}",
                EtherType {
                    octets: [0x00, 0x00]
                }
            ),
            "Unknown"
        );
    }

    #[test]
    fn ethernet_frame_display() {
        let mut data = [0u8; 14];
        let src = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let dst = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        write_ethernet_header(&mut data, dst, src, EtherTypes::IPv4);
        let frame = EthernetFrame::from_bytes(&data);
        let display = format!("{}", frame);
        assert!(display.contains("aa:bb:cc:dd:ee:ff"));
        assert!(display.contains("11:22:33:44:55:66"));
        assert!(display.contains("IPv4"));
    }

    #[test]
    fn write_ethernet_header_sets_fields() {
        let mut data = [0u8; 14];
        let src = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let dst = MacAddress::broadcast();
        write_ethernet_header(&mut data, dst, src, EtherTypes::Arp);
        let frame = EthernetFrame::from_bytes(&data);
        assert_eq!(frame.dst_mac, MacAddress::broadcast());
        assert_eq!(frame.src_mac, src);
        assert_eq!(frame.ether_type, EtherTypes::Arp);
    }

    #[test]
    fn from_bytes_mut_allows_mutation() {
        let mut data = [0u8; 14];
        let frame = EthernetFrame::from_bytes_mut(&mut data);
        frame.dst_mac = MacAddress::broadcast();
        frame.ether_type = EtherTypes::IPv6;
        let frame = EthernetFrame::from_bytes(&data);
        assert_eq!(frame.dst_mac, MacAddress::broadcast());
        assert_eq!(frame.ether_type, EtherTypes::IPv6);
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn from_bytes_mut_rejects_truncated_frame() {
        let mut short = [0u8; 13];
        let _ = EthernetFrame::from_bytes_mut(&mut short);
    }
}
