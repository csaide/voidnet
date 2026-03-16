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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_known_protocols() {
        assert_eq!(format!("{}", IpProtocol(IpProtocols::Icmp)), "ICMP");
        assert_eq!(format!("{}", IpProtocol(IpProtocols::IcmpV6)), "ICMPv6");
        assert_eq!(format!("{}", IpProtocol(IpProtocols::Udp)), "UDP");
        assert_eq!(format!("{}", IpProtocol(IpProtocols::Tcp)), "TCP");
    }

    #[test]
    fn display_unknown_protocol() {
        assert_eq!(format!("{}", IpProtocol(255)), "Unknown");
        assert_eq!(format!("{}", IpProtocol(0)), "Unknown");
    }

    #[test]
    fn protocol_constants() {
        assert_eq!(IpProtocols::Icmp, 1);
        assert_eq!(IpProtocols::IcmpV6, 58);
        assert_eq!(IpProtocols::Udp, 17);
        assert_eq!(IpProtocols::Tcp, 6);
    }
}
