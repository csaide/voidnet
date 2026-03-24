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

/// STREAM frame (type 0x0F = OFF+LEN+FIN) with a maximum-varint offset
/// (2^62 - 1) and a declared data length larger than the remaining buffer.
///
/// The parser stores offset and length independently; it never computes
/// `offset + length` at parse time. The declared length (4 bytes) exceeds the
/// zero bytes actually present after the length varint, so the parser must
/// return `BufferTooShort` without panicking.
#[test]
fn frame_stream_large_offset_length_overflow_returns_buffer_too_short() {
    use crate::net::handler::quic::transport::varint::encode_varint;

    // VARINT_MAX = 2^62 - 1, encoded as an 8-byte varint (prefix 0b11).
    const VARINT_MAX: u64 = (1 << 62) - 1;

    let mut buf = Vec::new();
    buf.push(0x0Fu8); // STREAM type: OFF(1) + LEN(1) + FIN(1)

    // stream_id = 0 (1-byte varint)
    buf.push(0x00);

    // offset = VARINT_MAX (8-byte varint)
    let mut tmp = [0u8; 8];
    let n = encode_varint(VARINT_MAX, &mut tmp);
    assert_eq!(n, 8);
    buf.extend_from_slice(&tmp[..n]);

    // length = 4 (1-byte varint) — but NO data bytes follow
    buf.push(0x04);

    // No data bytes — the buffer ends here, triggering BufferTooShort.
    let err = parse_frame(&buf)
        .expect_err("STREAM with large offset and truncated data must return BufferTooShort");
    assert_eq!(err, FrameParseError::BufferTooShort);
}

/// ACK frame where the additional gap/range pairs contain very large varint
/// values (close to 2^62 - 1). The parser only decodes gap/range varints for
/// iteration and borrows the raw bytes; it never subtracts them from
/// `largest_acked`. The frame must parse successfully without overflow or panic.
#[test]
fn frame_ack_large_gap_and_range_parses_ok() {
    use crate::net::handler::quic::transport::frame::QuicFrame;
    use crate::net::handler::quic::transport::varint::encode_varint;

    const VARINT_MAX: u64 = (1 << 62) - 1;

    let mut buf = Vec::new();
    buf.push(0x02u8); // ACK type (no ECN)

    // largest_acked = 50 (fits in a 1-byte varint, value <= 63)
    buf.push(50u8);

    // ack_delay = 0
    buf.push(0x00);

    // range_count = 1 (one additional gap+range pair; fits in 1-byte varint)
    buf.push(0x01);

    // first_ack_range = 0
    buf.push(0x00);

    // gap = VARINT_MAX (8-byte varint) — would underflow if subtracted naively
    let mut tmp = [0u8; 8];
    let n = encode_varint(VARINT_MAX, &mut tmp);
    assert_eq!(n, 8, "VARINT_MAX must encode to 8 bytes");
    buf.extend_from_slice(&tmp[..n]);

    // ack range = VARINT_MAX (8-byte varint)
    let n = encode_varint(VARINT_MAX, &mut tmp);
    assert_eq!(n, 8, "VARINT_MAX must encode to 8 bytes");
    buf.extend_from_slice(&tmp[..n]);

    let (frame, consumed) =
        parse_frame(&buf).expect("ACK with large gap/range values must parse without error");
    assert_eq!(consumed, buf.len());
    match frame {
        QuicFrame::Ack(ack) => {
            assert_eq!(ack.largest_acked, 50);
            assert_eq!(ack.range_count, 1);
            // The raw gap+range bytes are borrowed; each field is 8 bytes.
            assert_eq!(ack.ranges.len(), 16);
        }
        other => panic!("expected Ack frame, got {:?}", other),
    }
}

/// MAX_STREAMS frame (type 0x12 = bidi) with the maximum varint value (2^62 - 1).
///
/// The parser decodes the value directly into a u64 without range-checking it
/// against the QUIC stream limit (2^60). Limit enforcement is a higher-level
/// concern; the frame parser must return `Ok` here.
#[test]
fn frame_max_streams_varint_max_parses_ok() {
    use crate::net::handler::quic::transport::frame::QuicFrame;
    use crate::net::handler::quic::transport::varint::encode_varint;

    const VARINT_MAX: u64 = (1 << 62) - 1;

    let mut buf = Vec::new();
    buf.push(0x12u8); // MAX_STREAMS bidi

    let mut tmp = [0u8; 8];
    let n = encode_varint(VARINT_MAX, &mut tmp);
    buf.extend_from_slice(&tmp[..n]);

    let (frame, consumed) =
        parse_frame(&buf).expect("MAX_STREAMS with VARINT_MAX must parse without error");
    assert_eq!(consumed, buf.len());
    match frame {
        QuicFrame::MaxStreams { max, bidi } => {
            assert_eq!(max, VARINT_MAX);
            assert!(bidi, "type 0x12 must be bidi");
        }
        other => panic!("expected MaxStreams frame, got {:?}", other),
    }
}

/// CRYPTO frame where the offset is VARINT_MAX and the declared length exceeds
/// the remaining buffer. The parser bounds-checks `rest.len() < pos + length`
/// before slicing, so this must return `BufferTooShort` rather than panicking.
#[test]
fn frame_crypto_large_offset_truncated_data_returns_buffer_too_short() {
    use crate::net::handler::quic::transport::varint::encode_varint;

    const VARINT_MAX: u64 = (1 << 62) - 1;

    let mut buf = Vec::new();
    buf.push(0x06u8); // CRYPTO type

    // offset = VARINT_MAX (8-byte varint)
    let mut tmp = [0u8; 8];
    let n = encode_varint(VARINT_MAX, &mut tmp);
    buf.extend_from_slice(&tmp[..n]);

    // length = 16 (1-byte varint) — but NO data bytes follow
    buf.push(0x10);

    let err = parse_frame(&buf)
        .expect_err("CRYPTO with large offset and truncated data must return BufferTooShort");
    assert_eq!(err, FrameParseError::BufferTooShort);
}

/// A frame type in the reserved range (0x20) that is not a known frame and is
/// not a GREASE value (type % 0x1f == 0x1e) must return `UnknownFrameType`.
///
/// 0x20 % 0x1f = 1, so it is not GREASE. RFC 9000 §12.4 requires treating
/// unknown frame types as FRAME_ENCODING_ERROR.
#[test]
fn frame_unknown_type_returns_unknown_frame_type_error() {
    // 0x20 is not assigned and not GREASE (0x20 % 0x1f = 1).
    let buf = [0x20u8];
    let err = parse_frame(&buf).expect_err("unknown frame type must return UnknownFrameType");
    assert_eq!(err, FrameParseError::UnknownFrameType(0x20));
}

/// STREAM frame type 0x09 = FIN(1) + no LEN(0) + no OFF(0).
///
/// With no LEN bit, the data field extends to the end of the packet. With
/// stream_id = 0 and no remaining bytes after it, the data slice is empty.
/// This is a valid per-RFC edge case (FIN-only stream segment with no data).
/// The parser must succeed and return an empty data slice with fin=true.
#[test]
fn frame_stream_fin_only_zero_length_data_parses_ok() {
    use crate::net::handler::quic::transport::frame::QuicFrame;

    let buf = [
        0x09u8, // STREAM type: FIN(1), no LEN, no OFF
        0x00,   // stream_id = 0 (1-byte varint)
                // No offset field (has_off = false).
                // No length field (has_len = false) — data extends to end of buf.
                // No data bytes — empty slice.
    ];

    let (frame, consumed) =
        parse_frame(&buf).expect("FIN-only STREAM frame must parse without error");
    assert_eq!(consumed, buf.len());
    match frame {
        QuicFrame::Stream(sf) => {
            assert_eq!(sf.stream_id.0, 0);
            assert_eq!(sf.offset, 0);
            assert!(sf.fin, "FIN bit must be set");
            assert!(sf.data.is_empty(), "data must be empty (no payload bytes)");
        }
        other => panic!("expected Stream frame, got {:?}", other),
    }
}
