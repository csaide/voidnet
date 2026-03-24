use std::{fmt::Display, str::FromStr};

/// An IPv4 address representation.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
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

impl From<std::net::Ipv4Addr> for Ipv4Address {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self::new(addr.octets())
    }
}

impl From<Ipv4Address> for std::net::Ipv4Addr {
    fn from(addr: Ipv4Address) -> Self {
        std::net::Ipv4Addr::from(addr.octets)
    }
}

impl FromStr for Ipv4Address {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = std::net::Ipv4Addr::from_str(s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok(addr.into())
    }
}

impl Display for Ipv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v4: std::net::Ipv4Addr = (*self).into();
        write!(f, "{}", v4)
    }
}

/// An IPv6 address representation.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
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

impl From<std::net::Ipv6Addr> for Ipv6Address {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self::new(addr.octets())
    }
}

impl From<Ipv6Address> for std::net::Ipv6Addr {
    fn from(addr: Ipv6Address) -> Self {
        std::net::Ipv6Addr::from(addr.octets)
    }
}

impl FromStr for Ipv6Address {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = std::net::Ipv6Addr::from_str(s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok(addr.into())
    }
}

impl Display for Ipv6Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v6: std::net::Ipv6Addr = (*self).into();
        write!(f, "{}", v6)
    }
}

/// Protocol-agnostic IP address used as the key in the neighbor cache.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum IpAddress {
    /// IPv4 address.
    V4(Ipv4Address),
    /// IPv6 address.
    V6(Ipv6Address),
}

impl IpAddress {
    /// Returns `true` if this is the unspecified address for its protocol.
    #[inline]
    pub fn is_unspecified(&self) -> bool {
        match self {
            IpAddress::V4(v4) => v4.is_unspecified(),
            IpAddress::V6(v6) => v6.is_unspecified(),
        }
    }

    /// Return the raw octets as a slice without heap allocation.
    ///
    /// Uses a caller-provided stack buffer to hold up to 16 bytes.
    /// Returns the subslice containing the actual address bytes.
    #[inline]
    pub fn ip_bytes<'a>(&self, buf: &'a mut [u8; 16]) -> &'a [u8] {
        match self {
            IpAddress::V4(v4) => {
                buf[..4].copy_from_slice(&v4.octets);
                &buf[..4]
            }
            IpAddress::V6(v6) => {
                *buf = v6.octets;
                buf
            }
        }
    }
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

impl From<std::net::IpAddr> for IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(addr) => Self::V4(addr.into()),
            std::net::IpAddr::V6(addr) => Self::V6(addr.into()),
        }
    }
}

impl From<IpAddress> for std::net::IpAddr {
    fn from(addr: IpAddress) -> Self {
        match addr {
            IpAddress::V4(v4) => std::net::IpAddr::V4(v4.into()),
            IpAddress::V6(v6) => std::net::IpAddr::V6(v6.into()),
        }
    }
}

impl From<std::net::Ipv4Addr> for IpAddress {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self::V4(addr.into())
    }
}

impl From<std::net::Ipv6Addr> for IpAddress {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self::V6(addr.into())
    }
}

impl FromStr for IpAddress {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = std::net::IpAddr::from_str(s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok(Self::from(addr))
    }
}

impl Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddress::V4(v4) => write!(f, "{}", v4),
            IpAddress::V6(v6) => write!(f, "{}", v6),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SocketAddr {
    pub ip: IpAddress,
    pub port: u16,
}

impl SocketAddr {
    pub fn new(ip: IpAddress, port: u16) -> Self {
        Self { ip, port }
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(addr: std::net::SocketAddr) -> Self {
        Self {
            ip: addr.ip().into(),
            port: addr.port(),
        }
    }
}

impl From<SocketAddr> for std::net::SocketAddr {
    fn from(addr: SocketAddr) -> Self {
        std::net::SocketAddr::new(addr.ip.into(), addr.port)
    }
}

impl FromStr for SocketAddr {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = std::net::SocketAddr::from_str(s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok(addr.into())
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_special_addresses() {
        assert_eq!(Ipv4Address::loopback().octets, [127, 0, 0, 1]);
        assert_eq!(Ipv4Address::unspecified().octets, [0; 4]);
        assert_eq!(Ipv4Address::broadcast().octets, [255; 4]);
    }

    #[test]
    fn ipv4_classifiers() {
        assert!(Ipv4Address::loopback().is_loopback());
        assert!(Ipv4Address::new([127, 255, 0, 0]).is_loopback());
        assert!(!Ipv4Address::new([128, 0, 0, 1]).is_loopback());

        assert!(Ipv4Address::unspecified().is_unspecified());
        assert!(!Ipv4Address::new([0, 0, 0, 1]).is_unspecified());

        assert!(Ipv4Address::broadcast().is_broadcast());
        assert!(!Ipv4Address::new([255, 255, 255, 0]).is_broadcast());

        // Multicast: 224.0.0.0/4 (first nibble 0xE)
        assert!(Ipv4Address::new([224, 0, 0, 1]).is_multicast());
        assert!(Ipv4Address::new([239, 255, 255, 255]).is_multicast());
        assert!(!Ipv4Address::new([240, 0, 0, 1]).is_multicast());
        assert!(!Ipv4Address::new([223, 255, 255, 255]).is_multicast());
    }

    #[test]
    fn ipv4_from_conversions() {
        let addr = Ipv4Address::from([10, 0, 0, 1]);
        assert_eq!(addr.octets, [10, 0, 0, 1]);
        let arr: [u8; 4] = addr.into();
        assert_eq!(arr, [10, 0, 0, 1]);
    }

    #[test]
    fn ipv6_special_addresses() {
        let loopback = Ipv6Address::loopback();
        assert_eq!(loopback.octets[15], 1);
        assert!(loopback.octets[..15].iter().all(|&b| b == 0));

        let unspec = Ipv6Address::unspecified();
        assert!(unspec.octets.iter().all(|&b| b == 0));
    }

    #[test]
    fn ipv6_classifiers() {
        assert!(Ipv6Address::loopback().is_loopback());
        assert!(!Ipv6Address::loopback().is_unspecified());
        assert!(Ipv6Address::unspecified().is_unspecified());
        assert!(!Ipv6Address::unspecified().is_loopback());

        // Multicast ff00::/8
        assert!(
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_multicast()
        );
        assert!(
            !Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .is_multicast()
        );

        // Link-local fe80::/10
        assert!(
            Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .is_link_local()
        );
        assert!(
            Ipv6Address::new([0xFE, 0xBF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .is_link_local()
        );
        // fe_c0 is outside /10
        assert!(
            !Ipv6Address::new([0xFE, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .is_link_local()
        );
        assert!(
            !Ipv6Address::new([0xFE, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .is_link_local()
        );
    }

    #[test]
    fn ipv6_from_conversions() {
        let octets = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let addr = Ipv6Address::from(octets);
        assert_eq!(addr.octets, octets);
        let arr: [u8; 16] = addr.into();
        assert_eq!(arr, octets);
    }

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

    #[test]
    fn ip_address_from_conversions() {
        let v4 = Ipv4Address::loopback();
        let ip: IpAddress = v4.into();
        assert_eq!(ip, IpAddress::V4(Ipv4Address::loopback()));

        let v6 = Ipv6Address::loopback();
        let ip: IpAddress = v6.into();
        assert_eq!(ip, IpAddress::V6(Ipv6Address::loopback()));
    }

    #[test]
    fn ipv4_display() {
        assert_eq!(format!("{}", Ipv4Address::loopback()), "127.0.0.1");
        assert_eq!(format!("{}", Ipv4Address::unspecified()), "0.0.0.0");
        assert_eq!(format!("{}", Ipv4Address::broadcast()), "255.255.255.255");
        assert_eq!(
            format!("{}", Ipv4Address::new([192, 168, 1, 1])),
            "192.168.1.1"
        );
    }

    #[test]
    fn ipv4_from_str() {
        let addr: Ipv4Address = "10.0.0.1".parse().unwrap();
        assert_eq!(addr.octets, [10, 0, 0, 1]);

        let addr: Ipv4Address = "255.255.255.255".parse().unwrap();
        assert_eq!(addr, Ipv4Address::broadcast());

        assert!("not.an.ip".parse::<Ipv4Address>().is_err());
        assert!("".parse::<Ipv4Address>().is_err());
    }

    #[test]
    fn ipv4_std_conversions() {
        let std_addr = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let our_addr: Ipv4Address = std_addr.into();
        assert_eq!(our_addr.octets, [192, 168, 0, 1]);

        let back: std::net::Ipv4Addr = our_addr.into();
        assert_eq!(back, std_addr);
    }

    #[test]
    fn ipv6_display() {
        assert_eq!(format!("{}", Ipv6Address::loopback()), "::1");
        assert_eq!(format!("{}", Ipv6Address::unspecified()), "::");
    }

    #[test]
    fn ipv6_from_str() {
        let addr: Ipv6Address = "::1".parse().unwrap();
        assert_eq!(addr, Ipv6Address::loopback());

        let addr: Ipv6Address = "fe80::1".parse().unwrap();
        assert!(addr.is_link_local());

        assert!("not-an-ipv6".parse::<Ipv6Address>().is_err());
    }

    #[test]
    fn ipv6_std_conversions() {
        let std_addr = std::net::Ipv6Addr::LOCALHOST;
        let our_addr: Ipv6Address = std_addr.into();
        assert_eq!(our_addr, Ipv6Address::loopback());

        let back: std::net::Ipv6Addr = our_addr.into();
        assert_eq!(back, std_addr);
    }

    #[test]
    fn ip_address_display() {
        assert_eq!(
            format!("{}", IpAddress::V4(Ipv4Address::loopback())),
            "127.0.0.1"
        );
        assert_eq!(format!("{}", IpAddress::V6(Ipv6Address::loopback())), "::1");
    }

    #[test]
    fn ip_address_from_str() {
        let addr: IpAddress = "10.0.0.1".parse().unwrap();
        assert_eq!(addr, IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])));

        let addr: IpAddress = "::1".parse().unwrap();
        assert_eq!(addr, IpAddress::V6(Ipv6Address::loopback()));

        assert!("garbage".parse::<IpAddress>().is_err());
    }

    #[test]
    fn ip_address_std_conversions() {
        let std_v4 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let our: IpAddress = std_v4.into();
        assert_eq!(our, IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])));
        let back: std::net::IpAddr = our.into();
        assert_eq!(back, std_v4);

        let std_v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let our: IpAddress = std_v6.into();
        assert_eq!(our, IpAddress::V6(Ipv6Address::loopback()));
        let back: std::net::IpAddr = our.into();
        assert_eq!(back, std_v6);
    }

    #[test]
    fn ip_address_from_std_ipv4() {
        let std_addr = std::net::Ipv4Addr::new(1, 2, 3, 4);
        let our: IpAddress = std_addr.into();
        assert_eq!(our, IpAddress::V4(Ipv4Address::new([1, 2, 3, 4])));
    }

    #[test]
    fn ip_address_from_std_ipv6() {
        let std_addr = std::net::Ipv6Addr::LOCALHOST;
        let our: IpAddress = std_addr.into();
        assert_eq!(our, IpAddress::V6(Ipv6Address::loopback()));
    }

    #[test]
    fn ip_address_is_unspecified() {
        assert!(IpAddress::V4(Ipv4Address::unspecified()).is_unspecified());
        assert!(IpAddress::V6(Ipv6Address::unspecified()).is_unspecified());
        assert!(!IpAddress::V4(Ipv4Address::loopback()).is_unspecified());
        assert!(!IpAddress::V6(Ipv6Address::loopback()).is_unspecified());
    }

    #[test]
    fn socket_addr_new() {
        let sa = SocketAddr::new(IpAddress::V4(Ipv4Address::loopback()), 8080);
        assert_eq!(sa.ip, IpAddress::V4(Ipv4Address::loopback()));
        assert_eq!(sa.port, 8080);
    }

    #[test]
    fn socket_addr_display() {
        let sa = SocketAddr::new(IpAddress::V4(Ipv4Address::loopback()), 443);
        assert_eq!(format!("{}", sa), "127.0.0.1:443");

        let sa = SocketAddr::new(IpAddress::V6(Ipv6Address::loopback()), 80);
        assert_eq!(format!("{}", sa), "::1:80");
    }

    #[test]
    fn socket_addr_from_str() {
        let sa: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(sa.ip, IpAddress::V4(Ipv4Address::loopback()));
        assert_eq!(sa.port, 8080);

        let sa: SocketAddr = "[::1]:443".parse().unwrap();
        assert_eq!(sa.ip, IpAddress::V6(Ipv6Address::loopback()));
        assert_eq!(sa.port, 443);

        assert!("not-a-socket-addr".parse::<SocketAddr>().is_err());
    }

    #[test]
    fn socket_addr_std_conversions() {
        let std_sa = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            3000,
        );
        let our: SocketAddr = std_sa.into();
        assert_eq!(our.ip, IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])));
        assert_eq!(our.port, 3000);

        let back: std::net::SocketAddr = our.into();
        assert_eq!(back, std_sa);
    }
}
