//! Hardening tests for malformed QUIC packet handling.
//!
//! These tests verify that the header and frame parsers handle bad input
//! gracefully — returning structured errors without panicking.

use crate::net::handler::quic::transport::frame::{FrameParseError, parse_frame};
use crate::net::wire::quic::{HeaderParseError, PacketHeader, PacketType, parse_header};

// ── header hardening ──────────────────────────────────────────────────────────

/// A buffer shorter than 7 bytes with the long-header bit set cannot contain
/// the mandatory first_byte + version(4) + dcid_len fields. The parser must
/// return `BufferTooShort` before attempting any CID reads.
#[test]
fn truncated_long_header_too_short() {
    // Long header bit set (0x80), plus fixed bit (0x40) = 0xC0.
    // Only 5 bytes — missing the dcid_len byte at offset 5.
    let buf = [0xC0u8, 0x00, 0x00, 0x00, 0x01];
    assert!(buf.len() < 7);
    let err = parse_header(&buf, 0).expect_err("must reject truncated long header");
    assert_eq!(err, HeaderParseError::BufferTooShort);
}

/// Long header where the dcid_len field claims more bytes than remain in the
/// buffer. The parser must detect the overflow and return `BufferTooShort`.
#[test]
fn cid_length_overflow() {
    // Layout: first_byte | version(4) | dcid_len=8 | <only 2 dcid bytes>
    // dcid_len claims 8 bytes, but only 2 follow — overflow by 6.
    let buf = [
        0xC0u8, // long header, fixed=1, Initial
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x08, // dcid_len = 8
        0xAA, 0xBB, // only 2 bytes of DCID — truncated
    ];
    let err = parse_header(&buf, 0).expect_err("must reject CID length overflow");
    assert_eq!(err, HeaderParseError::BufferTooShort);
}

/// A well-formed long header with zero-length CID fields but no trailing
/// payload bytes. Header parsing must succeed — payload parsing is separate.
/// The returned `payload_offset` should point just past the header.
#[test]
fn zero_length_payload_header_parses_ok() {
    // Minimal valid long header: first_byte | version(4) | dcid_len=0 | scid_len=0
    // No payload bytes follow — that is legal for the header parser.
    let buf = [
        0xC0u8, // long header, fixed=1, Initial
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x00, // dcid_len = 0
        0x00, // scid_len = 0
    ];
    let (hdr, consumed) =
        parse_header(&buf, 0).expect("valid header structure must parse even with no payload");
    assert_eq!(consumed, buf.len());
    match hdr {
        PacketHeader::Long(lh) => {
            assert_eq!(lh.packet_type, PacketType::Initial);
            assert_eq!(lh.dcid.len(), 0);
            assert_eq!(lh.scid.len(), 0);
            // payload_offset == scid_end == 7 (all header bytes consumed)
            assert_eq!(lh.payload_offset, 7);
        }
        other => panic!("expected LongHeader, got {:?}", other),
    }
}

/// Short-header parsing with dcid_len = 0 on a minimal single-byte buffer.
/// The fixed bit (0x40) must be set or the parser rejects the packet.
/// With dcid_len = 0, only the first byte is required.
#[test]
fn short_header_dcid_len_zero() {
    // bit7=0 (short), fixed-bit=1 (0x40) — bare minimum valid short header.
    let buf = [0x40u8];
    let (hdr, consumed) = parse_header(&buf, 0).expect("short header with dcid_len=0 must parse");
    assert_eq!(consumed, 1);
    match hdr {
        PacketHeader::Short(sh) => {
            assert_eq!(sh.dcid.len(), 0);
            assert_eq!(sh.pn_offset, 1);
        }
        other => panic!("expected ShortHeader, got {:?}", other),
    }
}

/// Short-header parsing with dcid_len = 8 on an exactly-sized buffer.
/// Buffer contains 1 (first_byte) + 8 (dcid) = 9 bytes.
#[test]
fn short_header_dcid_len_eight_exact() {
    let dcid = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut buf = vec![0x40u8]; // short, fixed-bit=1
    buf.extend_from_slice(&dcid);
    // No extra packet-number byte — parser only reads up to dcid_end.

    let (hdr, consumed) =
        parse_header(&buf, 8).expect("short header with dcid_len=8 on exact buffer must parse");
    assert_eq!(consumed, 9);
    match hdr {
        PacketHeader::Short(sh) => {
            assert_eq!(sh.dcid.as_bytes(), &dcid);
            assert_eq!(sh.pn_offset, 9);
        }
        other => panic!("expected ShortHeader, got {:?}", other),
    }
}

/// Short-header parsing with dcid_len = 20 on a buffer that is one byte short.
/// Must return `BufferTooShort` rather than panicking.
#[test]
fn short_header_dcid_len_twenty_truncated() {
    // 1 (first_byte) + 19 (dcid bytes) — one byte short of dcid_len=20.
    let mut buf = vec![0x40u8];
    buf.extend_from_slice(&[0u8; 19]);
    let err = parse_header(&buf, 20)
        .expect_err("truncated short header (dcid_len=20, 19 bytes) must fail");
    assert_eq!(err, HeaderParseError::BufferTooShort);
}

/// Zero-length input must return `BufferTooShort` immediately.
#[test]
fn empty_buffer_returns_buffer_too_short() {
    let err = parse_header(&[], 0).expect_err("empty buffer must return BufferTooShort");
    assert_eq!(err, HeaderParseError::BufferTooShort);
}

/// A version that is not v1 (0x00000001), v2 (0x6b3343cf), or VN (0x00000000)
/// is not an error at the header level. The parser accepts it and returns a
/// `LongHeader` with `PacketType::Unknown` (RFC 8999 §5.4 — version-agnostic
/// invariants still hold).
#[test]
fn unknown_version_yields_unknown_packet_type_not_error() {
    // Use an arbitrary unrecognised version.
    let unknown_version: u32 = 0xDEAD_BEEF;
    let mut buf = vec![0xC0u8]; // long header
    buf.extend_from_slice(&unknown_version.to_be_bytes());
    buf.push(4u8); // dcid_len = 4
    buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    buf.push(4u8); // scid_len = 4
    buf.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]);

    // Must NOT return an error — unknown versions are forwarded as Unknown type.
    let (hdr, _) = parse_header(&buf, 0)
        .expect("unknown version must not return an error at the header level");
    match hdr {
        PacketHeader::Long(lh) => {
            assert_eq!(
                lh.packet_type,
                PacketType::Unknown,
                "unrecognised version must map to PacketType::Unknown"
            );
            assert_eq!(lh.version, unknown_version);
        }
        other => panic!("expected LongHeader, got {:?}", other),
    }
}

// ── frame hardening ───────────────────────────────────────────────────────────

/// Empty buffer passed to `parse_frame` must return `BufferTooShort`.
#[test]
fn frame_empty_buffer_returns_buffer_too_short() {
    let err = parse_frame(&[]).expect_err("empty buffer must return BufferTooShort");
    assert_eq!(err, FrameParseError::BufferTooShort);
}

/// A truncated ACK frame (type byte only, no varint fields following) must
/// return `BufferTooShort` rather than panicking.
#[test]
fn frame_truncated_ack_returns_buffer_too_short() {
    // 0x02 = ACK frame type; no fields follow.
    let buf = [0x02u8];
    let err = parse_frame(&buf).expect_err("truncated ACK must return BufferTooShort");
    assert_eq!(err, FrameParseError::BufferTooShort);
}

/// A CRYPTO frame with a length field claiming more bytes than remain in the
/// buffer must return `BufferTooShort`.
#[test]
fn frame_crypto_length_overflow_returns_buffer_too_short() {
    // CRYPTO frame type = 0x06, offset varint = 0x00, length varint = 0x20 (32),
    // but only 4 data bytes follow instead of 32.
    let buf = [
        0x06u8, // CRYPTO type
        0x00,   // offset = 0 (1-byte varint)
        0x20,   // length = 32 (1-byte varint)
        0xAA, 0xBB, 0xCC, 0xDD, // only 4 bytes of data — 28 short
    ];
    let err = parse_frame(&buf).expect_err("CRYPTO frame with length overflow must return error");
    assert_eq!(err, FrameParseError::BufferTooShort);
}
