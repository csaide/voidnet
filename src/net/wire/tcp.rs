use std::fmt::Display;

/// TCP header length in bytes (minimum, without options).
pub const TCP_HEADER_LEN: usize = 20;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<TcpHeader>() == TCP_HEADER_LEN);

/// TCP flag constants.
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// TCP option kind constants.
pub mod options {
    pub const END: u8 = 0;
    pub const NOP: u8 = 1;
    pub const MSS: u8 = 2;
    pub const WINDOW_SCALE: u8 = 3;
}

/// TCP header wire format (20 bytes, minimum).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory.
///
/// Multi-byte fields are stored in network byte order as `[u8; N]` to
/// avoid alignment issues on packed structs. Use the accessor methods
/// for host-order values.
#[derive(Debug)]
#[repr(C, packed)]
pub struct TcpHeader {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub seq_num: [u8; 4],
    pub ack_num: [u8; 4],
    pub data_offset_reserved: u8,
    pub flags: u8,
    pub window: [u8; 2],
    pub checksum: [u8; 2],
    pub urgent_ptr: [u8; 2],
}

impl TcpHeader {
    /// Create a TCP header from host-order values.
    #[inline]
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        data_offset: u8,
        flags: u8,
        window: u16,
        checksum: [u8; 2],
        urgent_ptr: u16,
    ) -> Self {
        TcpHeader {
            src_port: src_port.to_be_bytes(),
            dst_port: dst_port.to_be_bytes(),
            seq_num: seq_num.to_be_bytes(),
            ack_num: ack_num.to_be_bytes(),
            data_offset_reserved: data_offset << 4,
            flags,
            window: window.to_be_bytes(),
            checksum,
            urgent_ptr: urgent_ptr.to_be_bytes(),
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

    /// Returns the sequence number in host byte order.
    #[inline]
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes(self.seq_num)
    }

    /// Returns the acknowledgment number in host byte order.
    #[inline]
    pub fn ack_num(&self) -> u32 {
        u32::from_be_bytes(self.ack_num)
    }

    /// Returns the data offset (number of 32-bit words in the header).
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.data_offset_reserved >> 4
    }

    /// Returns the header length in bytes (data_offset * 4).
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.data_offset() as usize) * 4
    }

    /// Returns the flags byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns true if the given flag bit(s) are set.
    #[inline]
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag == flag
    }

    /// Returns the window size in host byte order.
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(self.window)
    }

    /// Returns the urgent pointer in host byte order.
    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be_bytes(self.urgent_ptr)
    }

    /// Zero-copy reference to a TCP header at `offset` within a frame.
    ///
    /// # Safety
    /// Caller must ensure `frame.len() >= offset + TCP_HEADER_LEN`.
    #[inline]
    pub unsafe fn from_bytes_at(bytes: &[u8], offset: usize) -> &Self {
        debug_assert!(offset + TCP_HEADER_LEN <= bytes.len());
        unsafe { &*(bytes.as_ptr().add(offset) as *const Self) }
    }

    /// Zero-copy mutable reference to a TCP header at `offset` within a frame.
    ///
    /// # Safety
    /// Caller must ensure `frame.len() >= offset + TCP_HEADER_LEN`.
    #[inline]
    pub unsafe fn from_bytes_mut_at(bytes: &mut [u8], offset: usize) -> &mut Self {
        debug_assert!(offset + TCP_HEADER_LEN <= bytes.len());
        unsafe { &mut *(bytes.as_mut_ptr().add(offset) as *mut Self) }
    }
}

impl Display for TcpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TcpHeader {{ src_port: {}, dst_port: {}, seq_num: {}, ack_num: {}, data_offset: {}, flags: {}, window: {}, checksum: {}, urgent_ptr: {} }}",
            self.src_port(),
            self.dst_port(),
            self.seq_num(),
            self.ack_num(),
            self.data_offset(),
            self.flags(),
            self.window(),
            u16::from_be_bytes(self.checksum),
            self.urgent_ptr(),
        )
    }
}

/// Parse MSS (Maximum Segment Size) from TCP options.
///
/// Scans the options bytes for Kind=2, Len=4 and returns the MSS value.
/// Returns `None` if MSS option is not present or malformed.
pub fn parse_mss(options: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            options::END => break,
            options::NOP => {
                i += 1;
            }
            options::MSS => {
                if i + 4 > options.len() {
                    return None;
                }
                if options[i + 1] != 4 {
                    return None;
                }
                return Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
            }
            _ => {
                // Unknown option — skip using length byte.
                if i + 1 >= options.len() {
                    return None;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    return None;
                }
                i += len;
            }
        }
    }
    None
}

/// Write a 4-byte MSS option into `buf`.
///
/// Returns the number of bytes written (4).
///
/// # Panics
/// Panics if `buf.len() < 4`.
pub fn write_mss_option(buf: &mut [u8], mss: u16) -> usize {
    buf[0] = options::MSS;
    buf[1] = 4;
    buf[2..4].copy_from_slice(&mss.to_be_bytes());
    4
}

/// Parse Window Scale option from TCP options.
///
/// Scans the options bytes for Kind=3, Len=3 and returns the shift count.
/// Returns `None` if the option is not present or malformed.
pub fn parse_window_scale(options: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            options::END => break,
            options::NOP => {
                i += 1;
            }
            options::WINDOW_SCALE => {
                if i + 3 > options.len() {
                    return None;
                }
                if options[i + 1] != 3 {
                    return None;
                }
                // RFC 7323: shift count capped at 14
                return Some(options[i + 2].min(14));
            }
            _ => {
                if i + 1 >= options.len() {
                    return None;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    return None;
                }
                i += len;
            }
        }
    }
    None
}

/// Write a 3-byte Window Scale option into `buf`.
///
/// Returns the number of bytes written (3).
///
/// # Panics
/// Panics if `buf.len() < 3`.
pub fn write_window_scale_option(buf: &mut [u8], shift: u8) -> usize {
    buf[0] = options::WINDOW_SCALE;
    buf[1] = 3;
    buf[2] = shift;
    3
}

/// Sequence number less-than comparison with wraparound.
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Sequence number less-than-or-equal comparison with wraparound.
#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        assert_eq!(TCP_HEADER_LEN, 20);
        assert_eq!(size_of::<TcpHeader>(), 20);
    }

    #[test]
    fn header_accessors() {
        let hdr = TcpHeader::new(
            0x1234, // src_port
            0x0050, // dst_port (80)
            0xAABBCCDD,
            0x11223344,
            5, // data_offset (20 bytes)
            flags::SYN | flags::ACK,
            0x7FFF,
            [0x00, 0x00],
            0,
        );
        assert_eq!(hdr.src_port(), 0x1234);
        assert_eq!(hdr.dst_port(), 0x0050);
        assert_eq!(hdr.seq_num(), 0xAABBCCDD);
        assert_eq!(hdr.ack_num(), 0x11223344);
        assert_eq!(hdr.data_offset(), 5);
        assert_eq!(hdr.header_len(), 20);
        assert!(hdr.has_flag(flags::SYN));
        assert!(hdr.has_flag(flags::ACK));
        assert!(!hdr.has_flag(flags::FIN));
        assert!(!hdr.has_flag(flags::RST));
        assert_eq!(hdr.window(), 0x7FFF);
        assert_eq!(hdr.urgent_ptr(), 0);
    }

    #[test]
    fn data_offset_with_options() {
        // data_offset = 8 means 32 bytes header (12 bytes of options)
        let hdr = TcpHeader::new(0, 0, 0, 0, 8, 0, 0, [0; 2], 0);
        assert_eq!(hdr.data_offset(), 8);
        assert_eq!(hdr.header_len(), 32);
    }

    #[test]
    fn flag_helpers() {
        let hdr = TcpHeader::new(0, 0, 0, 0, 5, flags::FIN | flags::PSH, 0, [0; 2], 0);
        assert!(hdr.has_flag(flags::FIN));
        assert!(hdr.has_flag(flags::PSH));
        assert!(hdr.has_flag(flags::FIN | flags::PSH));
        assert!(!hdr.has_flag(flags::SYN));
        assert!(!hdr.has_flag(flags::ACK));
        assert!(!hdr.has_flag(flags::RST));
    }

    #[test]
    fn parse_mss_valid() {
        let opts = [options::MSS, 4, 0x05, 0xB4]; // MSS = 1460
        assert_eq!(parse_mss(&opts), Some(1460));
    }

    #[test]
    fn parse_mss_absent() {
        let opts = [options::NOP, options::NOP, options::END];
        assert_eq!(parse_mss(&opts), None);
    }

    #[test]
    fn parse_mss_empty() {
        assert_eq!(parse_mss(&[]), None);
    }

    #[test]
    fn parse_mss_after_nop() {
        let opts = [options::NOP, options::MSS, 4, 0x02, 0x04]; // MSS = 516
        assert_eq!(parse_mss(&opts), Some(516));
    }

    #[test]
    fn parse_mss_malformed_length() {
        // MSS option with wrong length byte
        let opts = [options::MSS, 3, 0x05, 0xB4];
        assert_eq!(parse_mss(&opts), None);
    }

    #[test]
    fn parse_mss_truncated() {
        let opts = [options::MSS, 4, 0x05]; // missing last byte
        assert_eq!(parse_mss(&opts), None);
    }

    #[test]
    fn write_mss_option_test() {
        let mut buf = [0u8; 4];
        let written = write_mss_option(&mut buf, 1460);
        assert_eq!(written, 4);
        assert_eq!(buf, [options::MSS, 4, 0x05, 0xB4]);
    }

    #[test]
    fn parse_window_scale_valid() {
        let opts = [options::WINDOW_SCALE, 3, 7];
        assert_eq!(parse_window_scale(&opts), Some(7));
    }

    #[test]
    fn parse_window_scale_capped_at_14() {
        let opts = [options::WINDOW_SCALE, 3, 20];
        assert_eq!(parse_window_scale(&opts), Some(14));
    }

    #[test]
    fn parse_window_scale_absent() {
        let opts = [options::MSS, 4, 0x05, 0xB4];
        assert_eq!(parse_window_scale(&opts), None);
    }

    #[test]
    fn parse_window_scale_after_mss() {
        let opts = [
            options::MSS,
            4,
            0x05,
            0xB4,
            options::NOP,
            options::WINDOW_SCALE,
            3,
            7,
        ];
        assert_eq!(parse_window_scale(&opts), Some(7));
    }

    #[test]
    fn write_window_scale_option_test() {
        let mut buf = [0u8; 3];
        let written = write_window_scale_option(&mut buf, 7);
        assert_eq!(written, 3);
        assert_eq!(buf, [options::WINDOW_SCALE, 3, 7]);
    }

    #[test]
    fn seq_lt_basic() {
        assert!(seq_lt(1, 2));
        assert!(!seq_lt(2, 1));
        assert!(!seq_lt(1, 1));
    }

    #[test]
    fn seq_le_basic() {
        assert!(seq_le(1, 2));
        assert!(!seq_le(2, 1));
        assert!(seq_le(1, 1));
    }

    #[test]
    fn seq_lt_wraparound() {
        // Near max wrapping to near zero.
        assert!(seq_lt(u32::MAX - 1, u32::MAX));
        assert!(seq_lt(u32::MAX, 0));
        assert!(seq_lt(u32::MAX, 1));
        assert!(!seq_lt(1, u32::MAX));
    }

    #[test]
    fn seq_le_wraparound() {
        assert!(seq_le(u32::MAX, 0));
        assert!(seq_le(u32::MAX, u32::MAX));
        assert!(seq_le(0, 0));
    }

    #[test]
    fn seq_lt_half_space() {
        // Values in the lower half of the sequence space are "less than"
        // values in the upper half when they differ by ~2^31.
        let a = 0x80000000u32;
        let b = 0x80000001u32;
        assert!(seq_lt(a, b));
        assert!(!seq_lt(b, a));
    }
}
