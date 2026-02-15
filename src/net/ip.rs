/// IP protocols.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod IpProtocols {
    pub const Icmp: u8 = 1;
    pub const IcmpV6: u8 = 58;
    pub const Udp: u8 = 17;
    pub const Tcp: u8 = 6;
}

/// An IPv4 address representation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(C, packed)]
pub struct Ipv4Address {
    pub octets: [u8; 4],
}

impl Ipv4Address {
    /// Creates a new IPv4 address.
    pub const fn new(octets: [u8; 4]) -> Self {
        Self { octets }
    }

    /// Creates a loopback IPv4 address (127.0.0.1).
    pub const fn loopback() -> Self {
        Self::new([127, 0, 0, 1])
    }

    /// Creates an unspecified IPv4 address (0.0.0.0).
    pub const fn unspecified() -> Self {
        Self::new([0; 4])
    }

    /// Creates a limited broadcast IPv4 address (255.255.255.255).
    pub const fn broadcast() -> Self {
        Self::new([255; 4])
    }

    /// Returns `true` if this is the unspecified address (0.0.0.0).
    #[inline]
    pub const fn is_unspecified(&self) -> bool {
        self.octets[0] == 0 && self.octets[1] == 0 && self.octets[2] == 0 && self.octets[3] == 0
    }

    /// Returns `true` if this is the limited broadcast address (255.255.255.255).
    #[inline]
    pub const fn is_broadcast(&self) -> bool {
        self.octets[0] == 255
            && self.octets[1] == 255
            && self.octets[2] == 255
            && self.octets[3] == 255
    }

    /// Returns `true` if this is a multicast address (224.0.0.0/4).
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        (self.octets[0] & 0xF0) == 0xE0
    }

    /// Returns `true` if this is a loopback address (127.0.0.0/8).
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        self.octets[0] == 127
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(octets: [u8; 4]) -> Self {
        Self { octets }
    }
}

impl From<Ipv4Address> for [u8; 4] {
    fn from(addr: Ipv4Address) -> Self {
        addr.octets
    }
}

/// An IPv6 address representation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(C, packed)]
pub struct Ipv6Address {
    pub octets: [u8; 16],
}

impl Ipv6Address {
    /// Creates a new IPv6 address.
    pub const fn new(octets: [u8; 16]) -> Self {
        Self { octets }
    }

    /// Creates a loopback IPv6 address (::1).
    pub const fn loopback() -> Self {
        Self::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    /// Creates an unspecified IPv6 address (::).
    pub const fn unspecified() -> Self {
        Self::new([0; 16])
    }

    /// Returns `true` if this is the unspecified address (::).
    #[inline]
    pub const fn is_unspecified(&self) -> bool {
        self.octets[0] == 0
            && self.octets[1] == 0
            && self.octets[2] == 0
            && self.octets[3] == 0
            && self.octets[4] == 0
            && self.octets[5] == 0
            && self.octets[6] == 0
            && self.octets[7] == 0
            && self.octets[8] == 0
            && self.octets[9] == 0
            && self.octets[10] == 0
            && self.octets[11] == 0
            && self.octets[12] == 0
            && self.octets[13] == 0
            && self.octets[14] == 0
            && self.octets[15] == 0
    }

    /// Returns `true` if this is a multicast address (ff00::/8).
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        self.octets[0] == 0xFF
    }

    /// Returns `true` if this is the loopback address (::1).
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        self.octets[0] == 0
            && self.octets[1] == 0
            && self.octets[2] == 0
            && self.octets[3] == 0
            && self.octets[4] == 0
            && self.octets[5] == 0
            && self.octets[6] == 0
            && self.octets[7] == 0
            && self.octets[8] == 0
            && self.octets[9] == 0
            && self.octets[10] == 0
            && self.octets[11] == 0
            && self.octets[12] == 0
            && self.octets[13] == 0
            && self.octets[14] == 0
            && self.octets[15] == 1
    }

    /// Returns `true` if this is a link-local address (fe80::/10).
    #[inline]
    pub const fn is_link_local(&self) -> bool {
        self.octets[0] == 0xFE && (self.octets[1] & 0xC0) == 0x80
    }

    /// Computes the solicited-node multicast address (`ff02::1:ffXX:XXXX`)
    /// from the last 24 bits of this address.
    pub const fn solicited_node_multicast(&self) -> Self {
        Self::new([
            0xFF,
            0x02,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x01,
            0xFF,
            self.octets[13],
            self.octets[14],
            self.octets[15],
        ])
    }

    /// Computes the IPv6 multicast MAC address (`33:33:XX:XX:XX:XX`)
    /// from the last 4 bytes of this address.
    pub const fn multicast_mac(&self) -> super::ethernet::MacAddress {
        super::ethernet::MacAddress::new([
            0x33,
            0x33,
            self.octets[12],
            self.octets[13],
            self.octets[14],
            self.octets[15],
        ])
    }
}

impl From<[u8; 16]> for Ipv6Address {
    fn from(octets: [u8; 16]) -> Self {
        Self { octets }
    }
}

impl From<Ipv6Address> for [u8; 16] {
    fn from(addr: Ipv6Address) -> Self {
        addr.octets
    }
}

/// Protocol-agnostic IP address used as the key in the neighbor cache.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum IpAddress {
    /// IPv4 address.
    V4(Ipv4Address),
    /// IPv6 address.
    V6(Ipv6Address),
}

impl From<Ipv4Address> for IpAddress {
    fn from(addr: Ipv4Address) -> Self {
        Self::V4(addr)
    }
}

impl From<Ipv6Address> for IpAddress {
    fn from(addr: Ipv6Address) -> Self {
        Self::V6(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solicited_node_multicast_correctness() {
        let addr = Ipv6Address::new([
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56,
        ]);
        let sol = addr.solicited_node_multicast();
        let expected = Ipv6Address::new([
            0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0x12, 0x34, 0x56,
        ]);
        assert_eq!(sol, expected);
    }

    #[test]
    fn multicast_mac_correctness() {
        let addr = Ipv6Address::new([
            0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0x12, 0x34, 0x56,
        ]);
        let mac = addr.multicast_mac();
        let expected =
            super::super::ethernet::MacAddress::new([0x33, 0x33, 0xFF, 0x12, 0x34, 0x56]);
        assert_eq!(mac, expected);
    }
}
