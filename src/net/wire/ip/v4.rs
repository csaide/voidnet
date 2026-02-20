use crate::xdp::frame::Frame;

use super::{Ipv4Address, ethernet::EthernetFrame};

/// Minimum IPv4 header length in bytes (no options, IHL = 5).
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<Ipv4Header>() == IPV4_MIN_HEADER_LEN);

/// Minimum Ethernet + IPv4 frame length.
pub const IPV4_MIN_FRAME_LEN: usize = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;

/// IPv4 header wire format (20 bytes, no options).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory.
///
/// Multi-byte fields are stored in network byte order as `[u8; 2]` to
/// avoid alignment issues on packed structs. Use the accessor methods
/// for host-order values.
#[repr(C, packed)]
pub struct Ipv4Header {
    /// Version (high 4 bits) + Internet Header Length (low 4 bits).
    pub version_ihl: u8,
    /// DSCP (high 6 bits) + ECN (low 2 bits).
    pub dscp_ecn: u8,
    /// Total length of the IP packet (header + payload), network byte order.
    pub total_length: [u8; 2],
    /// Identification field for fragment reassembly, network byte order.
    pub identification: [u8; 2],
    /// Flags (high 3 bits) + Fragment Offset (low 13 bits), network byte order.
    pub flags_fragment_offset: [u8; 2],
    /// Time to Live.
    pub ttl: u8,
    /// Upper-layer protocol number (e.g. TCP = 6, UDP = 17).
    pub protocol: u8,
    /// Header checksum, network byte order.
    pub header_checksum: [u8; 2],
    /// Source IPv4 address.
    pub src_addr: Ipv4Address,
    /// Destination IPv4 address.
    pub dst_addr: Ipv4Address,
}

impl Ipv4Header {
    /// Returns the IP version (should be 4).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.version_ihl >> 4) & 0x0F
    }

    /// Returns the Internet Header Length in 32-bit words.
    ///
    /// A value of 5 means 20 bytes (no options). Values > 5 indicate
    /// options are present.
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Returns the header length in bytes (`ihl() * 4`).
    #[inline]
    pub fn header_len(&self) -> usize {
        self.ihl() as usize * 4
    }

    /// Returns the total length of the IPv4 packet (header + payload).
    #[inline]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }

    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes(self.identification)
    }

    /// Returns `true` if the Don't Fragment (DF) flag is set.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.flags_fragment_offset[0] & 0x40 != 0
    }

    /// Returns `true` if the More Fragments (MF) flag is set.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.flags_fragment_offset[0] & 0x20 != 0
    }

    /// Returns the fragment offset in 8-byte units.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        let hi = (self.flags_fragment_offset[0] & 0x1F) as u16;
        let lo = self.flags_fragment_offset[1] as u16;
        (hi << 8) | lo
    }

    /// Returns `true` if this packet is an IP fragment.
    ///
    /// A packet is a fragment if MF is set or the fragment offset is non-zero.
    /// This is the single-branch fast-path check used by the handler.
    #[inline]
    pub fn is_fragment(&self) -> bool {
        let combined = u16::from_be_bytes(self.flags_fragment_offset);
        (combined & 0x3FFF) != 0
    }

    /// Byte offset from the start of the Ethernet frame to the IP payload.
    ///
    /// Equal to `sizeof(EthernetFrame) + header_len()`. When IHL == 5
    /// (no options) this compiles to a constant 34.
    #[inline]
    pub fn payload_offset(&self) -> usize {
        size_of::<EthernetFrame>() + self.header_len()
    }

    /// Returns the IP payload length (total_length minus header_len).
    ///
    /// Returns 0 if total_length < header_len (malformed).
    #[inline]
    pub fn payload_len(&self) -> usize {
        let total = self.total_length() as usize;
        let hdr = self.header_len();
        if total > hdr { total - hdr } else { 0 }
    }

    /// Fills `header_checksum` with the correct value.
    ///
    /// # Precondition
    ///
    /// When `IHL > 5` (options present), this reads `header_len()` bytes
    /// starting from `self`. The caller must ensure the struct is backed
    /// by at least `header_len()` bytes of accessible memory. This is
    /// always true when obtained via [`from_frame_mut`](Self::from_frame_mut),
    /// since the underlying frame memory extends beyond the 20-byte struct.
    #[inline]
    pub fn fill_checksum(&mut self) {
        self.header_checksum = [0, 0];
        let bytes = unsafe {
            std::slice::from_raw_parts(self as *const Self as *const u8, self.header_len())
        };
        self.header_checksum = compute_ipv4_checksum(bytes);
    }

    /// Zero-copy borrow of the IPv4 header from a received frame.
    ///
    /// The header starts immediately after the Ethernet header.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV4_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_frame<'f, 'u>(frame: &'f Frame<'u>) -> &'f Self {
        debug_assert!(frame.len() >= IPV4_MIN_FRAME_LEN);
        unsafe { &*(frame.as_ptr().add(size_of::<EthernetFrame>()) as *const Self) }
    }

    /// Mutable zero-copy borrow of the IPv4 header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV4_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_frame_mut<'f, 'u>(frame: &'f mut Frame<'u>) -> &'f mut Self {
        debug_assert!(frame.len() >= IPV4_MIN_FRAME_LEN);
        unsafe { &mut *(frame.as_mut_ptr().add(size_of::<EthernetFrame>()) as *mut Self) }
    }
}

/// Computes the IPv4 header checksum per RFC 1071.
///
/// `header_bytes` must contain the full header with the checksum field
/// set to zero. Returns the two-byte checksum in network byte order.
#[inline]
pub fn compute_ipv4_checksum(header_bytes: &[u8]) -> [u8; 2] {
    let mut sum: u32 = 0;
    let len = header_bytes.len();

    let mut i = 0;
    while i + 1 < len {
        let word = ((header_bytes[i] as u32) << 8) | (header_bytes[i + 1] as u32);
        sum += word;
        i += 2;
    }

    if i < len {
        sum += (header_bytes[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    checksum.to_be_bytes()
}

/// Verifies the IPv4 header checksum.
///
/// Returns `true` if the checksum is valid (the one's complement sum
/// of the entire header including the checksum field yields zero).
#[inline]
pub fn verify_ipv4_checksum(header_bytes: &[u8]) -> bool {
    let result = compute_ipv4_checksum(header_bytes);
    result == [0x00, 0x00]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Ipv4Header {
        Ipv4Header {
            version_ihl: 0x45, // version 4, IHL 5
            dscp_ecn: 0x00,
            total_length: [0x00, 0x28], // 40 bytes
            identification: [0x00, 0x01],
            flags_fragment_offset: [0x40, 0x00], // DF set
            ttl: 64,
            protocol: 17, // UDP
            header_checksum: [0x00, 0x00],
            src_addr: Ipv4Address::new([192, 168, 1, 1]),
            dst_addr: Ipv4Address::new([10, 0, 0, 1]),
        }
    }

    #[test]
    fn header_accessors() {
        let hdr = sample_header();
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 5);
        assert_eq!(hdr.header_len(), 20);
        assert_eq!(hdr.total_length(), 40);
        assert_eq!(hdr.identification(), 1);
        assert_eq!(hdr.payload_len(), 20);
        assert_eq!(hdr.payload_offset(), 34); // 14 (eth) + 20 (ip)
    }

    #[test]
    fn header_accessors_with_options() {
        let mut hdr = sample_header();
        hdr.version_ihl = 0x46; // IHL 6 = 24 bytes (with options)
        hdr.total_length = [0x00, 0x2C]; // 44 bytes
        assert_eq!(hdr.ihl(), 6);
        assert_eq!(hdr.header_len(), 24);
        assert_eq!(hdr.payload_len(), 20);
        assert_eq!(hdr.payload_offset(), 38); // 14 + 24
    }

    #[test]
    fn fragment_flags_df_only() {
        let hdr = sample_header(); // flags = [0x40, 0x00] (DF set)
        assert!(hdr.dont_fragment());
        assert!(!hdr.more_fragments());
        assert_eq!(hdr.fragment_offset(), 0);
        assert!(!hdr.is_fragment());
    }

    #[test]
    fn fragment_flags_mf_set() {
        let mut hdr = sample_header();
        hdr.flags_fragment_offset = [0x20, 0x00]; // MF set, offset 0
        assert!(!hdr.dont_fragment());
        assert!(hdr.more_fragments());
        assert_eq!(hdr.fragment_offset(), 0);
        assert!(hdr.is_fragment());
    }

    #[test]
    fn fragment_flags_offset_nonzero() {
        let mut hdr = sample_header();
        hdr.flags_fragment_offset = [0x00, 0x01]; // offset = 1
        assert!(!hdr.dont_fragment());
        assert!(!hdr.more_fragments());
        assert_eq!(hdr.fragment_offset(), 1);
        assert!(hdr.is_fragment());
    }

    #[test]
    fn payload_len_malformed() {
        let mut hdr = sample_header();
        hdr.total_length = [0x00, 0x0A]; // 10 < 20 header
        assert_eq!(hdr.payload_len(), 0);
    }

    #[test]
    fn checksum_compute_and_verify() {
        let bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        let checksum = compute_ipv4_checksum(&bytes);
        assert_eq!(checksum, [0x6F, 0x1A]);

        let mut with_checksum = bytes;
        with_checksum[10] = checksum[0];
        with_checksum[11] = checksum[1];
        assert!(verify_ipv4_checksum(&with_checksum));
    }

    #[test]
    fn fill_checksum_sets_correct_value() {
        let mut hdr = sample_header();
        hdr.fill_checksum();
        assert_eq!(hdr.header_checksum, [0x6F, 0x1A]);
    }

    #[test]
    fn verify_checksum_rejects_bad_header() {
        let bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0xFF, 0xFF, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        assert!(!verify_ipv4_checksum(&bytes));
    }

    #[test]
    fn header_layout() {
        assert_eq!(IPV4_MIN_HEADER_LEN, 20);
        assert_eq!(IPV4_MIN_FRAME_LEN, 34);
    }
}
