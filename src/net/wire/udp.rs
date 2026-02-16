use crate::xdp::frame::Frame;

use super::ip::{Ipv4Address, Ipv6Address};

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

/// Computes the UDP checksum over the IPv6 pseudo-header and full UDP segment.
///
/// Per RFC 2460 §8.1, the pseudo-header for IPv6 contains:
/// source address (16), destination address (16), UDP length as u32 (4),
/// three zero bytes (3), and next header = 17 (1) — totalling 40 bytes.
///
/// Unlike IPv4, the UDP checksum is **mandatory** for IPv6 — a zero
/// checksum is not permitted on transmit.
///
/// `udp_segment` must contain the full UDP header + payload with the
/// checksum field set to zero.
///
/// Returns the two-byte checksum in network byte order.
#[inline]
pub fn compute_udp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    udp_segment: &[u8],
) -> [u8; 2] {
    let udp_len = udp_segment.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header: src address (16 bytes)
    let mut i = 0;
    while i < 16 {
        sum += ((src_addr.octets[i] as u32) << 8) | (src_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: dst address (16 bytes)
    i = 0;
    while i < 16 {
        sum += ((dst_addr.octets[i] as u32) << 8) | (dst_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: UDP length as u32 (4 bytes)
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;

    // Pseudo-header: zero (3 bytes) + next header = 17 (1 byte)
    sum += 17u32;

    // UDP header + data
    i = 0;
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

    // IPv6 UDP checksum must never be zero on the wire; 0xFFFF is the
    // one's-complement representation of zero.
    if checksum == 0 {
        [0xFF, 0xFF]
    } else {
        checksum.to_be_bytes()
    }
}

/// Verifies the UDP checksum for an IPv6 packet.
///
/// Returns `true` if the one's complement sum of the pseudo-header and
/// full UDP segment yields the expected result. Unlike IPv4, a zero
/// checksum field is **invalid** for IPv6 and will cause this to return
/// `false`.
#[inline]
pub fn verify_udp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    udp_segment: &[u8],
) -> bool {
    if udp_segment.len() < UDP_HEADER_LEN {
        return false;
    }

    // IPv6 does not allow a zero checksum field.
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return false;
    }

    let udp_len = udp_segment.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header: src address
    let mut i = 0;
    while i < 16 {
        sum += ((src_addr.octets[i] as u32) << 8) | (src_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: dst address
    i = 0;
    while i < 16 {
        sum += ((dst_addr.octets[i] as u32) << 8) | (dst_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: UDP length as u32
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;

    // Pseudo-header: next header
    sum += 17u32;

    // UDP segment (including checksum field)
    i = 0;
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

/// Writes a UDP header at the given offset in a frame.
#[inline]
pub fn write_udp_header(
    frame: &mut Frame<'_>,
    offset: usize,
    src_port: u16,
    dst_port: u16,
    length: u16,
) {
    frame[offset..offset + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[offset + 2..offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[offset + 4..offset + 6].copy_from_slice(&length.to_be_bytes());
    frame[offset + 6] = 0; // checksum placeholder
    frame[offset + 7] = 0;
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
    fn udp_checksum_v4_compute_and_verify() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let checksum = compute_udp_checksum(&src, &dst, &segment);
        assert_eq!(checksum, [0x1D, 0xBD]);

        segment[6] = checksum[0];
        segment[7] = checksum[1];
        assert!(verify_udp_checksum(&src, &dst, &segment));
    }

    #[test]
    fn udp_checksum_v4_zero_means_no_checksum() {
        let src = Ipv4Address::new([0; 4]);
        let dst = Ipv4Address::new([0; 4]);
        // Checksum field is zero = "no checksum" per RFC 768
        let segment = [0u8; 8];
        assert!(verify_udp_checksum(&src, &dst, &segment));
    }

    #[test]
    fn udp_checksum_v4_too_short() {
        let src = Ipv4Address::new([0; 4]);
        let dst = Ipv4Address::new([0; 4]);
        assert!(!verify_udp_checksum(&src, &dst, &[0; 7]));
    }

    #[test]
    fn udp_checksum_v4_rejects_bad_checksum() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0xFF, 0xFF, // wrong checksum
            0x01, 0x02, 0x03, 0x04,
        ];
        assert!(!verify_udp_checksum(&src, &dst, &segment));
    }

    #[test]
    fn udp_checksum_v6_compute_and_verify() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let checksum = compute_udp_checksum_v6(&src, &dst, &segment);
        assert_eq!(checksum, [0xEC, 0x62]);

        segment[6] = checksum[0];
        segment[7] = checksum[1];
        assert!(verify_udp_checksum_v6(&src, &dst, &segment));
    }

    #[test]
    fn udp_checksum_v6_zero_is_invalid() {
        let src = Ipv6Address::new([0; 16]);
        let dst = Ipv6Address::new([0; 16]);
        // IPv6 does not allow zero checksum field
        let segment = [0u8; 8];
        assert!(!verify_udp_checksum_v6(&src, &dst, &segment));
    }

    #[test]
    fn udp_checksum_v6_too_short() {
        let src = Ipv6Address::new([0; 16]);
        let dst = Ipv6Address::new([0; 16]);
        assert!(!verify_udp_checksum_v6(&src, &dst, &[0; 7]));
    }

    #[test]
    fn udp_checksum_v6_odd_length_payload() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0D, // length = 13
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, 0x05, // 5-byte payload (odd)
        ];

        let checksum = compute_udp_checksum_v6(&src, &dst, &segment);
        segment[6] = checksum[0];
        segment[7] = checksum[1];
        assert!(verify_udp_checksum_v6(&src, &dst, &segment));
    }

    #[test]
    fn udp_header_layout() {
        assert_eq!(UDP_HEADER_LEN, 8);
        assert_eq!(size_of::<UdpHeader>(), 8);
    }
}
