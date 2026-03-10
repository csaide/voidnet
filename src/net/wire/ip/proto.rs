use std::fmt::Display;

#[derive(Debug)]
#[repr(transparent)]
pub struct IpProtocol(pub u8);

impl Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            IpProtocols::Icmp => write!(f, "ICMP"),
            IpProtocols::IcmpV6 => write!(f, "ICMPv6"),
            IpProtocols::Udp => write!(f, "UDP"),
            IpProtocols::Tcp => write!(f, "TCP"),
            _ => write!(f, "Unknown"),
        }
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod IpProtocols {
    pub const Icmp: u8 = 1;
    pub const IcmpV6: u8 = 58;
    pub const Udp: u8 = 17;
    pub const Tcp: u8 = 6;
}
