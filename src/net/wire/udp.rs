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

    /// Zero-copy reference to a UDP header at `offset` within a frame.
    ///
    /// # Safety
    /// Caller must ensure `frame.len() >= offset + UDP_HEADER_LEN`.
    #[inline]
    pub unsafe fn from_bytes_at(bytes: &[u8], offset: usize) -> &Self {
        debug_assert!(offset + UDP_HEADER_LEN <= bytes.len());
        unsafe { &*(bytes.as_ptr().add(offset) as *const Self) }
    }

    /// Mutable zero-copy reference to a UDP header at `offset` within a frame.
    ///
    /// # Safety
    /// Caller must ensure `frame.len() >= offset + UDP_HEADER_LEN`.
    #[inline]
    pub unsafe fn from_bytes_at_mut(bytes: &mut [u8], offset: usize) -> &mut Self {
        debug_assert!(offset + UDP_HEADER_LEN <= bytes.len());
        unsafe { &mut *(bytes.as_mut_ptr().add(offset) as *mut Self) }
    }
}

/// Sum all 16-bit words in `data`, handling trailing bytes.
///
/// Uses a `u64` accumulator and processes 32 bytes (sixteen 16-bit words)
/// per iteration to reduce loop overhead and let the CPU pipeline loads.
#[inline]
fn sum_words(data: &[u8]) -> u64 {
    let (mut sum, pending) = sum_words_carry(data, 0, None);
    if let Some(hi) = pending {
        sum += (hi as u64) << 8;
    }
    sum
}

/// Sum 16-bit words across a slice, carrying a pending odd byte in/out.
///
/// This is the building block for checksumming fragmented (multi-frame)
/// packets without heap-allocating a `Vec` of slices. Call it once per
/// fragment and thread the `(sum, pending)` state through.
#[inline]
pub(crate) fn sum_words_carry(data: &[u8], mut sum: u64, pending: Option<u8>) -> (u64, Option<u8>) {
    let len = data.len();
    let mut i = 0;

    if let Some(hi) = pending {
        if len > 0 {
            sum += ((hi as u64) << 8) | (data[0] as u64);
            i = 1;
        } else {
            return (sum, Some(hi));
        }
    }

    // Process 32 bytes per iteration using 4x u64 wide reads.
    // Each u64 is split into 4 u16 words via shifts — safe for unaligned data
    // because from_be_bytes copies rather than casting pointers.
    while i + 31 < len {
        let w0 = u64::from_be_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        let w1 = u64::from_be_bytes([
            data[i + 8],
            data[i + 9],
            data[i + 10],
            data[i + 11],
            data[i + 12],
            data[i + 13],
            data[i + 14],
            data[i + 15],
        ]);
        let w2 = u64::from_be_bytes([
            data[i + 16],
            data[i + 17],
            data[i + 18],
            data[i + 19],
            data[i + 20],
            data[i + 21],
            data[i + 22],
            data[i + 23],
        ]);
        let w3 = u64::from_be_bytes([
            data[i + 24],
            data[i + 25],
            data[i + 26],
            data[i + 27],
            data[i + 28],
            data[i + 29],
            data[i + 30],
            data[i + 31],
        ]);
        sum += (w0 >> 48) + ((w0 >> 32) & 0xFFFF) + ((w0 >> 16) & 0xFFFF) + (w0 & 0xFFFF);
        sum += (w1 >> 48) + ((w1 >> 32) & 0xFFFF) + ((w1 >> 16) & 0xFFFF) + (w1 & 0xFFFF);
        sum += (w2 >> 48) + ((w2 >> 32) & 0xFFFF) + ((w2 >> 16) & 0xFFFF) + (w2 & 0xFFFF);
        sum += (w3 >> 48) + ((w3 >> 32) & 0xFFFF) + ((w3 >> 16) & 0xFFFF) + (w3 & 0xFFFF);
        i += 32;
    }

    // Handle remaining 4 bytes at a time.
    while i + 3 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        sum += ((data[i + 2] as u64) << 8) | (data[i + 3] as u64);
        i += 4;
    }

    if i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        return (sum, Some(data[i]));
    }

    (sum, None)
}

/// Fold 64-bit running sum to 16 bits, then one's-complement.
#[inline]
pub(crate) fn fold_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fold and check for 0xFFFF (verification path).
#[inline]
pub(crate) fn fold_and_verify(mut sum: u64, actual: u16) -> bool {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16) == actual
}

/// Build the IPv4 pseudo-header sum: src IP + dst IP + protocol(17) + UDP length.
#[inline]
pub(crate) fn pseudo_header_sum_v4(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    udp_len: u16,
) -> u64 {
    sum_words(&src_addr.octets) + sum_words(&dst_addr.octets) + 17u64 + udp_len as u64
}

/// Build the IPv6 pseudo-header sum: src IP + dst IP + UDP length (u32) + next header(17).
#[inline]
pub(crate) fn pseudo_header_sum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    udp_len: u32,
) -> u64 {
    sum_words(&src_addr.octets)
        + sum_words(&dst_addr.octets)
        + (udp_len >> 16) as u64
        + (udp_len & 0xFFFF) as u64
        + 17u64
}

/// Convert a folded checksum to wire bytes, mapping zero to 0xFFFF per RFC 768.
#[inline]
fn checksum_to_bytes(checksum: u16) -> [u8; 2] {
    if checksum == 0 {
        [0xFF, 0xFF]
    } else {
        checksum.to_be_bytes()
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
    let sum =
        pseudo_header_sum_v4(src_addr, dst_addr, udp_segment.len() as u16) + sum_words(udp_segment);
    checksum_to_bytes(fold_checksum(sum))
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
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return true;
    }
    let sum =
        pseudo_header_sum_v4(src_addr, dst_addr, udp_segment.len() as u16) + sum_words(udp_segment);
    fold_and_verify(sum, 0x0000)
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
    let sum =
        pseudo_header_sum_v6(src_addr, dst_addr, udp_segment.len() as u32) + sum_words(udp_segment);
    checksum_to_bytes(fold_checksum(sum))
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
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return false;
    }
    let sum =
        pseudo_header_sum_v6(src_addr, dst_addr, udp_segment.len() as u32) + sum_words(udp_segment);
    fold_and_verify(sum, 0x0000)
}

/// Compute IPv4 UDP checksum without allocating (from port/payload parts).
#[inline]
pub fn compute_udp_checksum_from_parts(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    payload: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v4(src_addr, dst_addr, udp_len)
        + src_port as u64
        + dst_port as u64
        + udp_len as u64
        // checksum field is zero, contributes nothing
        + sum_words(payload);
    checksum_to_bytes(fold_checksum(sum))
}

/// Compute IPv6 UDP checksum without allocating (from port/payload parts).
#[inline]
pub fn compute_udp_checksum_v6_from_parts(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    payload: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v6(src_addr, dst_addr, udp_len as u32)
        + src_port as u64
        + dst_port as u64
        + udp_len as u64
        // checksum field is zero, contributes nothing
        + sum_words(payload);
    checksum_to_bytes(fold_checksum(sum))
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

    #[test]
    fn from_parts_v4_matches_segment() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let payload = [0x01, 0x02, 0x03, 0x04];
        let src_port: u16 = 0x1234;
        let dst_port: u16 = 53;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, // payload
        ];
        let expected = compute_udp_checksum(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_parts_v6_matches_segment() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload = [0x01, 0x02, 0x03, 0x04];
        let src_port: u16 = 0x1234;
        let dst_port: u16 = 53;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, // payload
        ];
        let expected = compute_udp_checksum_v6(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_v6_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_parts_v4_odd_payload() {
        let src = Ipv4Address::new([10, 0, 0, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 2]);
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05]; // odd
        let src_port: u16 = 8000;
        let dst_port: u16 = 9000;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let mut segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
        segment.extend_from_slice(&src_port.to_be_bytes());
        segment.extend_from_slice(&dst_port.to_be_bytes());
        segment.extend_from_slice(&udp_len.to_be_bytes());
        segment.extend_from_slice(&[0u8; 2]);
        segment.extend_from_slice(&payload);

        let expected = compute_udp_checksum(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_parts_v6_odd_payload() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05]; // odd
        let src_port: u16 = 8000;
        let dst_port: u16 = 9000;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let mut segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
        segment.extend_from_slice(&src_port.to_be_bytes());
        segment.extend_from_slice(&dst_port.to_be_bytes());
        segment.extend_from_slice(&udp_len.to_be_bytes());
        segment.extend_from_slice(&[0u8; 2]);
        segment.extend_from_slice(&payload);

        let expected = compute_udp_checksum_v6(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_v6_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn sum_words_carry_even_boundary() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let checksum = compute_udp_checksum(&src, &dst, &segment);
        segment[6] = checksum[0];
        segment[7] = checksum[1];

        // Sum across two slices split at an even boundary
        let (a, b) = segment.split_at(8);
        let mut sum = pseudo_header_sum_v4(&src, &dst, segment.len() as u16);
        let pending;
        (sum, pending) = sum_words_carry(a, sum, None);
        (sum, _) = sum_words_carry(b, sum, pending);
        assert!(fold_and_verify(sum, 0x0000));
    }

    #[test]
    fn sum_words_carry_odd_boundary() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let checksum = compute_udp_checksum(&src, &dst, &segment);
        segment[6] = checksum[0];
        segment[7] = checksum[1];

        // Split at an odd boundary (9 bytes + 4 bytes)
        let (a, b) = segment.split_at(9);
        let mut sum = pseudo_header_sum_v4(&src, &dst, segment.len() as u16);
        let pending;
        (sum, pending) = sum_words_carry(a, sum, None);
        let trailing;
        (sum, trailing) = sum_words_carry(b, sum, pending);
        if let Some(hi) = trailing {
            sum += (hi as u64) << 8;
        }
        assert!(fold_and_verify(sum, 0x0000));
    }

    #[test]
    fn sum_words_carry_empty_slice() {
        let (sum, pending) = sum_words_carry(&[], 42, Some(0xAB));
        assert_eq!(sum, 42);
        assert_eq!(pending, Some(0xAB));
    }
}
