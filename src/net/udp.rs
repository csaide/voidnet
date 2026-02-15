use std::mem::size_of;

use super::ip::Ipv4Address;

/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<UdpHeader>() == UDP_HEADER_LEN);

/// UDP header wire format (8 bytes).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory,
/// following the same pattern as [`Ipv4Header`] and [`Icmpv4Header`].
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
    /// Returns the source port in host byte order.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    /// Returns the destination port in host byte order.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    /// Returns the UDP length (header + payload) in host byte order.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Returns the payload length (total length minus header).
    ///
    /// Returns 0 if the length field is less than the header size (malformed).
    #[inline]
    pub fn payload_len(&self) -> usize {
        let total = self.length() as usize;
        if total > UDP_HEADER_LEN {
            total - UDP_HEADER_LEN
        } else {
            0
        }
    }
}

/// Computes the UDP checksum over the IPv4 pseudo-header and full UDP segment.
///
/// Per RFC 768, the checksum covers a pseudo-header (src IP, dst IP,
/// zero, protocol, UDP length) concatenated with the UDP header and data.
///
/// `udp_segment` must contain the full UDP header + payload with the
/// checksum field set to zero.
///
/// Returns the two-byte checksum in network byte order. If the computed
/// checksum is zero, returns `[0xFF, 0xFF]` per RFC 768 (a transmitted
/// checksum of zero means "no checksum").
#[inline]
pub fn compute_udp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    udp_segment: &[u8],
) -> [u8; 2] {
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;

    // Pseudo-header: src IP (4 bytes)
    sum += ((src_addr.octets[0] as u32) << 8) | (src_addr.octets[1] as u32);
    sum += ((src_addr.octets[2] as u32) << 8) | (src_addr.octets[3] as u32);

    // Pseudo-header: dst IP (4 bytes)
    sum += ((dst_addr.octets[0] as u32) << 8) | (dst_addr.octets[1] as u32);
    sum += ((dst_addr.octets[2] as u32) << 8) | (dst_addr.octets[3] as u32);

    // Pseudo-header: zero + protocol (2 bytes)
    sum += 17u32; // UDP protocol number

    // Pseudo-header: UDP length (2 bytes)
    sum += udp_len as u32;

    // UDP header + data
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        let word = ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32);
        sum += word;
        i += 2;
    }

    // Pad odd byte
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    // Fold carry bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);

    // RFC 768: a computed checksum of zero is transmitted as 0xFFFF.
    if checksum == 0 {
        [0xFF, 0xFF]
    } else {
        checksum.to_be_bytes()
    }
}

/// Verifies the UDP checksum.
///
/// Returns `true` if the checksum field is zero (no checksum, per RFC 768)
/// or if the one's complement sum of the pseudo-header and full UDP segment
/// yields the expected result.
#[inline]
pub fn verify_udp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    udp_segment: &[u8],
) -> bool {
    if udp_segment.len() < UDP_HEADER_LEN {
        return false;
    }

    // RFC 768: checksum field of zero means no checksum was computed.
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return true;
    }

    // When the checksum is included in the sum, the result should be 0xFFFF
    // (all ones), which after one's complement negation gives 0x0000.
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += ((src_addr.octets[0] as u32) << 8) | (src_addr.octets[1] as u32);
    sum += ((src_addr.octets[2] as u32) << 8) | (src_addr.octets[3] as u32);
    sum += ((dst_addr.octets[0] as u32) << 8) | (dst_addr.octets[1] as u32);
    sum += ((dst_addr.octets[2] as u32) << 8) | (dst_addr.octets[3] as u32);
    sum += 17u32;
    sum += udp_len as u32;

    // UDP segment (including checksum field)
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        let word = ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32);
        sum += word;
        i += 2;
    }

    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const DST_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);

    /// Builds a UDP segment (header + payload) with checksum zeroed.
    fn build_udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut seg = vec![0u8; UDP_HEADER_LEN + payload.len()];
        seg[0..2].copy_from_slice(&src_port.to_be_bytes());
        seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
        seg[4..6].copy_from_slice(&udp_len.to_be_bytes());
        // checksum = 0 (will be filled by compute)
        seg[UDP_HEADER_LEN..].copy_from_slice(payload);
        seg
    }

    #[test]
    fn struct_size() {
        assert_eq!(size_of::<UdpHeader>(), 8);
    }

    #[test]
    fn accessors() {
        let hdr = UdpHeader {
            src_port: 1234u16.to_be_bytes(),
            dst_port: 5678u16.to_be_bytes(),
            length: 28u16.to_be_bytes(),
            checksum: [0, 0],
        };
        assert_eq!(hdr.src_port(), 1234);
        assert_eq!(hdr.dst_port(), 5678);
        assert_eq!(hdr.length(), 28);
        assert_eq!(hdr.payload_len(), 20);
    }

    #[test]
    fn payload_len_malformed() {
        let hdr = UdpHeader {
            src_port: [0, 0],
            dst_port: [0, 0],
            length: 4u16.to_be_bytes(), // less than header
            checksum: [0, 0],
        };
        assert_eq!(hdr.payload_len(), 0);
    }

    #[test]
    fn compute_and_verify_roundtrip() {
        let mut seg = build_udp_segment(12345, 53, b"hello");
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn corrupted_checksum_fails_verify() {
        let mut seg = build_udp_segment(12345, 53, b"hello");
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        // Corrupt one byte of payload
        seg[UDP_HEADER_LEN] ^= 0xFF;
        assert!(!verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn zero_checksum_field_means_no_checksum() {
        let seg = build_udp_segment(80, 80, b"anything");
        // checksum field is already zero
        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn verify_rejects_too_short_segment() {
        let short = [0u8; 4];
        assert!(!verify_udp_checksum(&SRC_IP, &DST_IP, &short));
    }

    #[test]
    fn compute_checksum_never_returns_zero() {
        // RFC 768: transmitted checksum must never be 0x0000.
        // We can't easily force a zero checksum, but we verify the
        // function handles it by checking the contract holds for
        // a variety of inputs.
        for port in [0u16, 1, 255, 1024, 65535] {
            let seg = build_udp_segment(port, port, &[]);
            let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
            assert_ne!(cksum, [0x00, 0x00]);
        }
    }

    #[test]
    fn odd_length_payload() {
        // Odd-length payload exercises the padding branch.
        let mut seg = build_udp_segment(1000, 2000, &[0xAB; 13]);
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn empty_payload() {
        let mut seg = build_udp_segment(5000, 5001, &[]);
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn different_addresses_produce_different_checksums() {
        let seg = build_udp_segment(1234, 5678, b"test");
        let cksum1 = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);

        let other_dst = Ipv4Address::new([10, 0, 0, 99]);
        let cksum2 = compute_udp_checksum(&SRC_IP, &other_dst, &seg);

        assert_ne!(cksum1, cksum2);
    }

    #[test]
    fn wrong_addresses_fail_verify() {
        let mut seg = build_udp_segment(1234, 5678, b"test");
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        // Verify with wrong source address
        let wrong_src = Ipv4Address::new([172, 16, 0, 1]);
        assert!(!verify_udp_checksum(&wrong_src, &DST_IP, &seg));
    }
}
