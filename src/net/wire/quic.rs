/// QUIC packet header parsing (RFC 9000 §17).
///
/// Zero-copy: `ConnectionIdRef` borrows directly from the input buffer.
use crate::net::handler::quic::connection_id::ConnectionIdRef;
use crate::net::handler::quic::transport::version::{QUIC_VERSION_1, QUIC_VERSION_2};

/// QUIC packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    /// Short header (1-RTT).
    OneRtt,
    /// Unrecognised version — invariant fields still valid (RFC 8999 §5.4).
    Unknown,
}

/// Parsed QUIC packet header.
#[derive(Debug)]
pub enum PacketHeader<'a> {
    Long(LongHeader<'a>),
    Short(ShortHeader<'a>),
    VersionNegotiation(VnHeader<'a>),
}

/// Long header (§17.2).
#[derive(Debug)]
pub struct LongHeader<'a> {
    pub packet_type: PacketType,
    pub version: u32,
    pub dcid: ConnectionIdRef<'a>,
    pub scid: ConnectionIdRef<'a>,
    /// Byte offset where type-specific payload begins (after SCID).
    pub payload_offset: usize,
    /// Raw first byte (needed for header protection removal).
    pub first_byte: u8,
}

/// Short header (§17.3, 1-RTT only).
#[derive(Debug)]
pub struct ShortHeader<'a> {
    pub dcid: ConnectionIdRef<'a>,
    /// Byte offset where the packet number begins.
    pub pn_offset: usize,
    /// Key phase bit.
    pub key_phase: bool,
    /// Raw first byte.
    pub first_byte: u8,
}

/// Version Negotiation packet (§17.2.1).
#[derive(Debug)]
pub struct VnHeader<'a> {
    pub dcid: ConnectionIdRef<'a>,
    pub scid: ConnectionIdRef<'a>,
    /// Raw slice containing supported versions (4 bytes each, big-endian).
    pub versions: &'a [u8],
}

/// Error type for header parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderParseError {
    BufferTooShort,
    /// A CID length field exceeded 255 bytes (RFC 8999 invariant).
    InvalidDcidLength(u8),
    /// Version field is not a recognised version.
    UnknownVersion(u32),
}

/// Parse a QUIC packet header from `buf`.
///
/// `short_dcid_len` is required for short headers because the DCID length is
/// not encoded on the wire — it is known from the connection context.
///
/// Returns `(header, bytes_consumed)`.
#[inline]
pub fn parse_header(
    buf: &[u8],
    short_dcid_len: usize,
) -> Result<(PacketHeader<'_>, usize), HeaderParseError> {
    if buf.is_empty() {
        return Err(HeaderParseError::BufferTooShort);
    }
    let first_byte = buf[0];

    if is_long_header(first_byte) {
        parse_long_header(buf, first_byte)
    } else {
        parse_short_header_inner(buf, first_byte, short_dcid_len)
    }
}

/// Returns `true` when the first byte indicates a long header (bit 7 set).
#[inline]
pub fn is_long_header(first_byte: u8) -> bool {
    first_byte & 0x80 != 0
}

/// Extract the DCID from a long header without full parsing.
///
/// Returns `None` if the buffer is too short or the DCID length exceeds 255.
#[inline]
pub fn peek_dcid(buf: &[u8]) -> Option<ConnectionIdRef<'_>> {
    // Long header layout: [0]=first_byte [1..5]=version [5]=dcid_len [6..]=dcid
    if buf.len() < 6 {
        return None;
    }
    let dcid_len = buf[5] as usize;
    if dcid_len > 255 {
        return None;
    }
    let end = 6 + dcid_len;
    if buf.len() < end {
        return None;
    }
    Some(ConnectionIdRef::from_slice(&buf[6..end]))
}

// ── internal helpers ──────────────────────────────────────────────────────────

fn parse_long_header(
    buf: &[u8],
    first_byte: u8,
) -> Result<(PacketHeader<'_>, usize), HeaderParseError> {
    // Minimum: first_byte(1) + version(4) + dcid_len(1) = 6 bytes before DCID.
    if buf.len() < 6 {
        return Err(HeaderParseError::BufferTooShort);
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    // DCID
    let dcid_len = buf[5] as usize;
    if dcid_len > 255 {
        return Err(HeaderParseError::InvalidDcidLength(buf[5]));
    }
    let dcid_end = 6 + dcid_len;
    if buf.len() < dcid_end + 1 {
        // +1 for scid_len byte
        return Err(HeaderParseError::BufferTooShort);
    }
    let dcid = ConnectionIdRef::from_slice(&buf[6..dcid_end]);

    // SCID
    let scid_len = buf[dcid_end] as usize;
    if scid_len > 255 {
        return Err(HeaderParseError::InvalidDcidLength(buf[dcid_end]));
    }
    let scid_start = dcid_end + 1;
    let scid_end = scid_start + scid_len;
    if buf.len() < scid_end {
        return Err(HeaderParseError::BufferTooShort);
    }
    let scid = ConnectionIdRef::from_slice(&buf[scid_start..scid_end]);

    // Version Negotiation: version == 0x00000000
    if version == 0x00000000 {
        // Supported versions follow SCID, 4 bytes each.
        let versions = &buf[scid_end..];
        if versions.is_empty() || versions.len() % 4 != 0 {
            return Err(HeaderParseError::BufferTooShort);
        }
        let total = scid_end + versions.len();
        return Ok((
            PacketHeader::VersionNegotiation(VnHeader {
                dcid,
                scid,
                versions,
            }),
            total,
        ));
    }

    let packet_type = decode_long_packet_type(first_byte, version)?;

    Ok((
        PacketHeader::Long(LongHeader {
            packet_type,
            version,
            dcid,
            scid,
            payload_offset: scid_end,
            first_byte,
        }),
        scid_end,
    ))
}

fn parse_short_header_inner(
    buf: &[u8],
    first_byte: u8,
    dcid_len: usize,
) -> Result<(PacketHeader<'_>, usize), HeaderParseError> {
    // RFC 9000 §17.3.1: fixed bit (0x40) MUST be 1; discard packets with 0.
    if first_byte & 0x40 == 0 {
        return Err(HeaderParseError::BufferTooShort); // invalid packet
    }
    // Short header: first_byte(1) + dcid(dcid_len) + packet_number(1..4)
    let dcid_end = 1 + dcid_len;
    if buf.len() < dcid_end {
        return Err(HeaderParseError::BufferTooShort);
    }
    let dcid = ConnectionIdRef::from_slice(&buf[1..dcid_end]);
    // Bit 2 (0x04) is the key phase bit (§17.3.1).
    let key_phase = (first_byte & 0x04) != 0;

    Ok((
        PacketHeader::Short(ShortHeader {
            dcid,
            pn_offset: dcid_end,
            key_phase,
            first_byte,
        }),
        dcid_end,
    ))
}

/// Decode the long-header packet type for the given version (anti-ossification).
fn decode_long_packet_type(first_byte: u8, version: u32) -> Result<PacketType, HeaderParseError> {
    match version {
        QUIC_VERSION_1 => match (first_byte & 0x30) >> 4 {
            0 => Ok(PacketType::Initial),
            1 => Ok(PacketType::ZeroRtt),
            2 => Ok(PacketType::Handshake),
            3 => Ok(PacketType::Retry),
            _ => unreachable!(),
        },
        QUIC_VERSION_2 => match (first_byte & 0x30) >> 4 {
            0 => Ok(PacketType::Retry),
            1 => Ok(PacketType::Initial),
            2 => Ok(PacketType::ZeroRtt),
            3 => Ok(PacketType::Handshake),
            _ => unreachable!(),
        },
        0x00000000 => Ok(PacketType::Initial), // Version Negotiation handled separately
        _ => Ok(PacketType::Unknown),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal long-header buffer.
    ///
    /// Layout: first_byte | version(4) | dcid_len | dcid | scid_len | scid
    fn make_long_header(first_byte: u8, version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(first_byte);
        buf.extend_from_slice(&version.to_be_bytes());
        buf.push(dcid.len() as u8);
        buf.extend_from_slice(dcid);
        buf.push(scid.len() as u8);
        buf.extend_from_slice(scid);
        buf
    }

    // ── parse_long_header_initial ────────────────────────────────────────────

    #[test]
    fn parse_long_header_initial() {
        // first_byte: 1 (long) | 1 (fixed) | 00 (Initial) | 0000 (reserved+pn_len)
        // = 1100_0000 = 0xC0
        let first_byte = 0xC0u8; // long, fixed=1, type=Initial(00)
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let scid = [0xAA, 0xBB, 0xCC];
        let buf = make_long_header(first_byte, QUIC_VERSION_1, &dcid, &scid);

        let (hdr, consumed) = parse_header(&buf, 0).expect("parse should succeed");
        assert_eq!(consumed, buf.len());

        match hdr {
            PacketHeader::Long(lh) => {
                assert_eq!(lh.packet_type, PacketType::Initial);
                assert_eq!(lh.version, QUIC_VERSION_1);
                assert_eq!(lh.dcid.as_bytes(), &dcid);
                assert_eq!(lh.scid.as_bytes(), &scid);
                assert_eq!(lh.first_byte, first_byte);
                // payload_offset = 1(first)+4(ver)+1(dcid_len)+8(dcid)+1(scid_len)+3(scid)
                assert_eq!(lh.payload_offset, 18);
            }
            other => panic!("expected LongHeader, got {:?}", other),
        }
    }

    // ── parse_long_header_handshake ──────────────────────────────────────────

    #[test]
    fn parse_long_header_handshake() {
        // type bits 5-4 = 10 → Handshake → first_byte = 1110_0000 = 0xE0
        let first_byte = 0xE0u8;
        let dcid = [0xDE, 0xAD, 0xBE, 0xEF];
        let scid = [0xCA, 0xFE];
        let buf = make_long_header(first_byte, QUIC_VERSION_1, &dcid, &scid);

        let (hdr, _) = parse_header(&buf, 0).expect("parse should succeed");
        match hdr {
            PacketHeader::Long(lh) => {
                assert_eq!(lh.packet_type, PacketType::Handshake);
                assert_eq!(lh.dcid.as_bytes(), &dcid);
                assert_eq!(lh.scid.as_bytes(), &scid);
            }
            other => panic!("expected LongHeader, got {:?}", other),
        }
    }

    // ── parse_short_header ───────────────────────────────────────────────────

    #[test]
    fn parse_short_header() {
        let dcid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        // Short header: bit 7 = 0, fixed bit = 1 → 0100_0000 = 0x40
        // key_phase bit (bit 2) set → 0x44
        let first_byte = 0x44u8;
        let mut buf = vec![first_byte];
        buf.extend_from_slice(&dcid);
        // Append a dummy packet number byte.
        buf.push(0x00);

        let dcid_len = dcid.len();
        let (hdr, consumed) = parse_header(&buf, dcid_len).expect("parse should succeed");
        // consumed = 1(first) + dcid_len
        assert_eq!(consumed, 1 + dcid_len);

        match hdr {
            PacketHeader::Short(sh) => {
                assert_eq!(sh.dcid.as_bytes(), &dcid);
                assert_eq!(sh.pn_offset, 1 + dcid_len);
                assert!(sh.key_phase);
                assert_eq!(sh.first_byte, first_byte);
            }
            other => panic!("expected ShortHeader, got {:?}", other),
        }
    }

    // ── parse_version_negotiation ────────────────────────────────────────────

    #[test]
    fn parse_version_negotiation() {
        let dcid = [0x01, 0x02];
        let scid = [0x03, 0x04];
        // Version Negotiation: first_byte has bit 7 set; version = 0x00000000.
        let first_byte = 0x80u8;
        let mut buf = make_long_header(first_byte, 0x00000000, &dcid, &scid);

        // Append two supported versions.
        buf.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);

        let (hdr, consumed) = parse_header(&buf, 0).expect("parse should succeed");
        assert_eq!(consumed, buf.len());

        match hdr {
            PacketHeader::VersionNegotiation(vn) => {
                assert_eq!(vn.dcid.as_bytes(), &dcid);
                assert_eq!(vn.scid.as_bytes(), &scid);
                assert_eq!(vn.versions.len(), 8); // 2 × 4 bytes
                assert_eq!(&vn.versions[0..4], &QUIC_VERSION_1.to_be_bytes());
                assert_eq!(&vn.versions[4..8], &[0x00, 0x00, 0x00, 0x02]);
            }
            other => panic!("expected VersionNegotiation, got {:?}", other),
        }
    }

    // ── is_long_header_check ─────────────────────────────────────────────────

    #[test]
    fn is_long_header_check() {
        assert!(is_long_header(0x80));
        assert!(is_long_header(0xFF));
        assert!(is_long_header(0xC0));
        assert!(!is_long_header(0x00));
        assert!(!is_long_header(0x40));
        assert!(!is_long_header(0x7F));
    }

    // ── peek_dcid_long_header ────────────────────────────────────────────────

    #[test]
    fn peek_dcid_long_header() {
        let dcid = [0xAA, 0xBB, 0xCC, 0xDD];
        let scid = [];
        let buf = make_long_header(0xC0, QUIC_VERSION_1, &dcid, &scid);

        let cid_ref = peek_dcid(&buf).expect("peek_dcid should return Some");
        assert_eq!(cid_ref.as_bytes(), &dcid);
    }

    #[test]
    fn peek_dcid_buffer_too_short() {
        // Only 5 bytes — not enough for dcid_len field.
        let buf = [0xC0, 0x00, 0x00, 0x00, 0x01];
        assert!(peek_dcid(&buf).is_none());
    }

    // ── parse_valid_max_dcid_length ────────────────────────────────────────────

    #[test]
    fn parse_valid_max_dcid_length() {
        // dcid_len = 255, which is the maximum per RFC 8999 version-independent parser.
        let first_byte = 0xC0u8;
        let mut buf = vec![first_byte];
        buf.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        buf.push(255u8); // maximum valid dcid_len per RFC 8999
        // Append 255 bytes for DCID.
        buf.extend_from_slice(&[0u8; 255]);
        // Append scid_len (minimum 1 byte for the field).
        buf.push(1u8); // scid_len = 1
        buf.push(0xAAu8); // 1 byte of SCID

        let (hdr, _) = parse_header(&buf, 0).expect("parse should succeed with 255-byte DCID");
        match hdr {
            PacketHeader::Long(lh) => {
                assert_eq!(lh.dcid.len(), 255);
            }
            other => panic!("expected LongHeader, got {:?}", other),
        }
    }

    // ── parse_buffer_too_short ───────────────────────────────────────────────

    #[test]
    fn parse_buffer_too_short_empty() {
        let err = parse_header(&[], 0).expect_err("should fail on empty buffer");
        assert_eq!(err, HeaderParseError::BufferTooShort);
    }

    #[test]
    fn parse_buffer_too_short_truncated_long() {
        // Long header but truncated before DCID data.
        let buf = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x08]; // dcid_len=8 but no dcid bytes
        let err = parse_header(&buf, 0).expect_err("should fail with truncated buffer");
        assert_eq!(err, HeaderParseError::BufferTooShort);
    }

    #[test]
    fn parse_buffer_too_short_short_header() {
        // Short header, dcid_len=8 but only 4 bytes total.
        let buf = [0x40, 0x01, 0x02, 0x03]; // 1(first) + 3 bytes, but dcid_len=8
        let err = parse_header(&buf, 8).expect_err("should fail with truncated buffer");
        assert_eq!(err, HeaderParseError::BufferTooShort);
    }

    // ── zero_rtt and retry ───────────────────────────────────────────────────

    #[test]
    fn parse_long_header_zero_rtt() {
        // type bits = 01 → 0-RTT → first_byte = 1101_0000 = 0xD0
        let first_byte = 0xD0u8;
        let buf = make_long_header(first_byte, QUIC_VERSION_1, &[0x01], &[0x02]);
        let (hdr, _) = parse_header(&buf, 0).unwrap();
        match hdr {
            PacketHeader::Long(lh) => assert_eq!(lh.packet_type, PacketType::ZeroRtt),
            other => panic!("expected Long, got {:?}", other),
        }
    }

    #[test]
    fn parse_long_header_retry() {
        // type bits = 11 → Retry → first_byte = 1111_0000 = 0xF0
        let first_byte = 0xF0u8;
        let buf = make_long_header(first_byte, QUIC_VERSION_1, &[0x01], &[0x02]);
        let (hdr, _) = parse_header(&buf, 0).unwrap();
        match hdr {
            PacketHeader::Long(lh) => assert_eq!(lh.packet_type, PacketType::Retry),
            other => panic!("expected Long, got {:?}", other),
        }
    }

    #[test]
    fn unknown_version_parses_as_long_header() {
        let mut buf = vec![0xC0]; // long header
        buf.extend_from_slice(&0xDEADBEEFu32.to_be_bytes());
        buf.push(4); // dcid_len
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.push(4); // scid_len
        buf.extend_from_slice(&[5, 6, 7, 8]);
        let (header, _) = parse_header(&buf, 0).unwrap();
        match header {
            PacketHeader::Long(lh) => assert_eq!(lh.packet_type, PacketType::Unknown),
            _ => panic!("expected long header"),
        }
    }
}
