/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<UdpHeader>() == UDP_HEADER_LEN);

/// UDP header wire format (8 bytes).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory.
///
/// Multi-byte fields are stored in network byte order as `[u8; 2]` to
/// avoid alignment issues on packed structs. Use the accessor methods
/// for host-order values.
#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: [u8; 2],
    pub checksum: [u8; 2],
}

impl UdpHeader {
    /// Create a UDP header from host-order values.
    ///
    /// Multi-byte fields are converted to network byte order internally.
    #[inline]
    pub fn new(src_port: u16, dst_port: u16, length: u16, checksum: [u8; 2]) -> Self {
        UdpHeader {
            src_port: src_port.to_be_bytes(),
            dst_port: dst_port.to_be_bytes(),
            length: length.to_be_bytes(),
            checksum,
        }
    }

    /// Returns the source port in host byte order.
    #[inline]
    pub const fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    /// Returns the destination port in host byte order.
    #[inline]
    pub const fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    /// Returns the UDP length (header + payload) in host byte order.
    #[inline]
    pub const fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Returns the payload length (total length minus header).
    ///
    /// Returns 0 if the length field is less than the header size (malformed).
    #[inline]
    pub const fn payload_len(&self) -> usize {
        let total = self.length() as usize;
        total.saturating_sub(UDP_HEADER_LEN)
    }

    /// Zero-copy reference to a UDP header at `offset` within a frame.
    ///
    /// # Safety
    /// Caller must ensure `frame.len() >= offset + UDP_HEADER_LEN`.
    #[inline]
    pub unsafe fn from_bytes_at(bytes: &[u8], offset: usize) -> &Self {
        assert!(offset + UDP_HEADER_LEN <= bytes.len());
        unsafe { &*(bytes.as_ptr().add(offset) as *const Self) }
    }

    /// Mutable zero-copy reference to a UDP header at `offset` within a frame.
    ///
    /// # Safety
    /// Caller must ensure `frame.len() >= offset + UDP_HEADER_LEN`.
    #[inline]
    pub unsafe fn from_bytes_at_mut(bytes: &mut [u8], offset: usize) -> &mut Self {
        assert!(offset + UDP_HEADER_LEN <= bytes.len());
        unsafe { &mut *(bytes.as_mut_ptr().add(offset) as *mut Self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_accessors() {
        let hdr = UdpHeader {
            src_port: [0x12, 0x34],
            dst_port: [0x00, 0x35],
            length: [0x00, 0x0C], // 12
            checksum: [0x00, 0x00],
        };
        assert_eq!(hdr.src_port(), 0x1234);
        assert_eq!(hdr.dst_port(), 53);
        assert_eq!(hdr.length(), 12);
        assert_eq!(hdr.payload_len(), 4);
    }

    #[test]
    fn payload_len_malformed() {
        let hdr = UdpHeader {
            src_port: [0; 2],
            dst_port: [0; 2],
            length: [0x00, 0x04], // 4 < 8 header
            checksum: [0; 2],
        };
        assert_eq!(hdr.payload_len(), 0);
    }

    #[test]
    fn payload_len_exact_header() {
        let hdr = UdpHeader {
            src_port: [0; 2],
            dst_port: [0; 2],
            length: [0x00, 0x08], // exactly header size
            checksum: [0; 2],
        };
        assert_eq!(hdr.payload_len(), 0);
    }

    #[test]
    fn udp_header_layout() {
        assert_eq!(UDP_HEADER_LEN, 8);
        assert_eq!(size_of::<UdpHeader>(), 8);
    }
}
