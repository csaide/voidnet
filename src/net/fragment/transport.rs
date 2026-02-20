use crate::net::wire::{
    ip::IpProtocols,
    udp::{UDP_HEADER_LEN, UdpHeader},
};

/// Describes a transport-layer header for use with generic IP fragmentation.
///
/// Implementations provide the protocol number, header size, and serialization
/// so that `FragmentWriter` can place the transport header in the first fragment
/// without being coupled to any particular protocol.
pub trait TransportHeader {
    /// IP protocol number (e.g. 17 for UDP, 6 for TCP).
    fn protocol(&self) -> u8;

    /// Serialized header length in bytes.
    fn header_len(&self) -> usize;

    /// Write the header bytes into `buf[0..header_len()]`.
    ///
    /// The caller guarantees `buf.len() >= header_len()`.
    fn write_to(&self, buf: &mut [u8]);
}

impl TransportHeader for UdpHeader {
    #[inline]
    fn protocol(&self) -> u8 {
        IpProtocols::Udp
    }

    #[inline]
    fn header_len(&self) -> usize {
        UDP_HEADER_LEN
    }

    #[inline]
    fn write_to(&self, buf: &mut [u8]) {
        let bytes =
            unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, UDP_HEADER_LEN) };
        buf[..UDP_HEADER_LEN].copy_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_as_transport_protocol() {
        let hdr = UdpHeader::new(1234, 5678, 100, [0xAB, 0xCD]);
        assert_eq!(hdr.protocol(), 17);
    }

    #[test]
    fn udp_header_as_transport_len() {
        let hdr = UdpHeader::new(0, 0, 0, [0; 2]);
        assert_eq!(hdr.header_len(), 8);
    }

    #[test]
    fn udp_header_as_transport_write() {
        let hdr = UdpHeader::new(0x3039, 0x0035, 0x000C, [0xAB, 0xCD]);
        let mut buf = [0u8; 8];
        hdr.write_to(&mut buf);
        assert_eq!(buf, [0x30, 0x39, 0x00, 0x35, 0x00, 0x0C, 0xAB, 0xCD]);
    }

    /// Custom transport header to verify trait generality.
    struct FakeTransport;

    impl TransportHeader for FakeTransport {
        fn protocol(&self) -> u8 { 99 }
        fn header_len(&self) -> usize { 4 }
        fn write_to(&self, buf: &mut [u8]) {
            buf[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }
    }

    #[test]
    fn custom_transport_header() {
        let hdr = FakeTransport;
        assert_eq!(hdr.protocol(), 99);
        assert_eq!(hdr.header_len(), 4);
        let mut buf = [0u8; 4];
        hdr.write_to(&mut buf);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
