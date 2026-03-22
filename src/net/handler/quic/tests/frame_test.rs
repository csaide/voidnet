use crate::net::handler::quic::transport::frame::*;
use crate::net::handler::quic::transport::frame_writer;
use crate::net::handler::quic::transport::varint::encode_varint;

#[test]
fn parse_padding() {
    let buf = [0x00];
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 1);
    assert!(matches!(frame, QuicFrame::Padding));
}

#[test]
fn parse_ping() {
    let buf = [0x01];
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 1);
    assert!(matches!(frame, QuicFrame::Ping));
}

#[test]
fn parse_stream_no_offset_no_len() {
    // Type 0x08: no FIN, no LEN, no OFF
    // Stream ID = 4 (varint 1 byte), then data goes to end of buffer
    let mut buf = [0u8; 32];
    buf[0] = 0x08;
    let n = encode_varint(4, &mut buf[1..]);
    let data = b"hello";
    buf[1 + n..1 + n + data.len()].copy_from_slice(data);
    let total = 1 + n + data.len();

    let (frame, consumed) = parse_frame(&buf[..total]).unwrap();
    assert_eq!(consumed, total);
    match frame {
        QuicFrame::Stream(sf) => {
            assert_eq!(sf.stream_id, StreamId(4));
            assert_eq!(sf.offset, 0);
            assert_eq!(sf.data, b"hello");
            assert!(!sf.fin);
        }
        _ => panic!("expected Stream frame"),
    }
}

#[test]
fn parse_stream_with_offset_len_fin() {
    // Type 0x0f: FIN(0x01) + LEN(0x02) + OFF(0x04) = 0x0f
    let mut buf = [0u8; 64];
    buf[0] = 0x0f;
    let mut pos = 1;
    pos += encode_varint(8, &mut buf[pos..]); // stream_id
    pos += encode_varint(100, &mut buf[pos..]); // offset
    let data = b"world";
    pos += encode_varint(data.len() as u64, &mut buf[pos..]); // length
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::Stream(sf) => {
            assert_eq!(sf.stream_id, StreamId(8));
            assert_eq!(sf.offset, 100);
            assert_eq!(sf.data, b"world");
            assert!(sf.fin);
        }
        _ => panic!("expected Stream frame"),
    }
}

#[test]
fn parse_crypto_frame() {
    let mut buf = [0u8; 64];
    buf[0] = 0x06;
    let mut pos = 1;
    pos += encode_varint(0, &mut buf[pos..]); // offset
    let data = b"crypto payload";
    pos += encode_varint(data.len() as u64, &mut buf[pos..]);
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::Crypto(cf) => {
            assert_eq!(cf.offset, 0);
            assert_eq!(cf.data, b"crypto payload");
        }
        _ => panic!("expected Crypto frame"),
    }
}

#[test]
fn parse_ack_no_ecn() {
    // Type 0x02, largest_acked=10, ack_delay=5, range_count=1, first_range=3,
    // then gap=1, ack_range=2
    let mut buf = [0u8; 64];
    buf[0] = 0x02;
    let mut pos = 1;
    pos += encode_varint(10, &mut buf[pos..]); // largest_acked
    pos += encode_varint(5, &mut buf[pos..]); // ack_delay
    pos += encode_varint(1, &mut buf[pos..]); // range_count
    pos += encode_varint(3, &mut buf[pos..]); // first_ack_range
    pos += encode_varint(1, &mut buf[pos..]); // gap
    pos += encode_varint(2, &mut buf[pos..]); // ack_range

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::Ack(af) => {
            assert_eq!(af.largest_acked, 10);
            assert_eq!(af.ack_delay, 5);
            assert_eq!(af.first_ack_range, 3);
            assert_eq!(af.range_count, 1);
            assert!(af.ecn.is_none());
            // ranges should contain the raw bytes of [gap=1, range=2]
            assert!(!af.ranges.is_empty());
        }
        _ => panic!("expected Ack frame"),
    }
}

#[test]
fn parse_ack_with_ecn() {
    // Type 0x03
    let mut buf = [0u8; 64];
    buf[0] = 0x03;
    let mut pos = 1;
    pos += encode_varint(20, &mut buf[pos..]); // largest_acked
    pos += encode_varint(3, &mut buf[pos..]); // ack_delay
    pos += encode_varint(0, &mut buf[pos..]); // range_count (no additional ranges)
    pos += encode_varint(5, &mut buf[pos..]); // first_ack_range
    // ECN counts
    pos += encode_varint(100, &mut buf[pos..]); // ect0
    pos += encode_varint(200, &mut buf[pos..]); // ect1
    pos += encode_varint(50, &mut buf[pos..]); // ecn_ce

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::Ack(af) => {
            assert_eq!(af.largest_acked, 20);
            assert_eq!(af.range_count, 0);
            let ecn = af.ecn.unwrap();
            assert_eq!(ecn.ect0, 100);
            assert_eq!(ecn.ect1, 200);
            assert_eq!(ecn.ecn_ce, 50);
        }
        _ => panic!("expected Ack frame"),
    }
}

#[test]
fn parse_connection_close_quic() {
    // Type 0x1c (transport close) with frame_type field
    let mut buf = [0u8; 64];
    buf[0] = 0x1c;
    let mut pos = 1;
    pos += encode_varint(0x0a, &mut buf[pos..]); // error_code
    pos += encode_varint(0x06, &mut buf[pos..]); // frame_type (CRYPTO)
    let reason = b"bad crypto";
    pos += encode_varint(reason.len() as u64, &mut buf[pos..]);
    buf[pos..pos + reason.len()].copy_from_slice(reason);
    pos += reason.len();

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::ConnectionClose(cc) => {
            assert_eq!(cc.error_code, 0x0a);
            assert_eq!(cc.frame_type, Some(0x06));
            assert_eq!(cc.reason, b"bad crypto");
        }
        _ => panic!("expected ConnectionClose frame"),
    }
}

#[test]
fn parse_connection_close_app() {
    // Type 0x1d (application close) without frame_type field
    let mut buf = [0u8; 64];
    buf[0] = 0x1d;
    let mut pos = 1;
    pos += encode_varint(42, &mut buf[pos..]); // error_code
    let reason = b"app error";
    pos += encode_varint(reason.len() as u64, &mut buf[pos..]);
    buf[pos..pos + reason.len()].copy_from_slice(reason);
    pos += reason.len();

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::ConnectionClose(cc) => {
            assert_eq!(cc.error_code, 42);
            assert!(cc.frame_type.is_none());
            assert_eq!(cc.reason, b"app error");
        }
        _ => panic!("expected ConnectionClose frame"),
    }
}

#[test]
fn parse_handshake_done() {
    let buf = [0x1e];
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 1);
    assert!(matches!(frame, QuicFrame::HandshakeDone));
}

#[test]
fn parse_new_connection_id() {
    let mut buf = [0u8; 64];
    buf[0] = 0x18;
    let mut pos = 1;
    pos += encode_varint(1, &mut buf[pos..]); // sequence
    pos += encode_varint(0, &mut buf[pos..]); // retire_prior_to
    let cid = [0xaa, 0xbb, 0xcc, 0xdd];
    buf[pos] = cid.len() as u8; // cid length (1 byte, not varint)
    pos += 1;
    buf[pos..pos + cid.len()].copy_from_slice(&cid);
    pos += cid.len();
    let token = [0x01u8; 16];
    buf[pos..pos + 16].copy_from_slice(&token);
    pos += 16;

    let (frame, consumed) = parse_frame(&buf[..pos]).unwrap();
    assert_eq!(consumed, pos);
    match frame {
        QuicFrame::NewConnectionId(ncid) => {
            assert_eq!(ncid.sequence, 1);
            assert_eq!(ncid.retire_prior_to, 0);
            assert_eq!(ncid.connection_id.as_bytes(), &cid);
            assert_eq!(ncid.stateless_reset_token, token);
        }
        _ => panic!("expected NewConnectionId frame"),
    }
}

#[test]
fn parse_path_challenge_response() {
    let challenge_data = [1u8, 2, 3, 4, 5, 6, 7, 8];

    // PATH_CHALLENGE
    let mut buf = [0u8; 9];
    buf[0] = 0x1a;
    buf[1..9].copy_from_slice(&challenge_data);
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 9);
    match frame {
        QuicFrame::PathChallenge(d) => assert_eq!(d, challenge_data),
        _ => panic!("expected PathChallenge"),
    }

    // PATH_RESPONSE
    buf[0] = 0x1b;
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 9);
    match frame {
        QuicFrame::PathResponse(d) => assert_eq!(d, challenge_data),
        _ => panic!("expected PathResponse"),
    }
}

#[test]
fn parse_max_data() {
    let mut buf = [0u8; 16];
    buf[0] = 0x10;
    let n = encode_varint(1_000_000, &mut buf[1..]);
    let (frame, consumed) = parse_frame(&buf[..1 + n]).unwrap();
    assert_eq!(consumed, 1 + n);
    match frame {
        QuicFrame::MaxData(max) => assert_eq!(max, 1_000_000),
        _ => panic!("expected MaxData"),
    }
}

#[test]
fn parse_max_streams() {
    // Bidi (0x12)
    let mut buf = [0u8; 16];
    buf[0] = 0x12;
    let n = encode_varint(100, &mut buf[1..]);
    let (frame, consumed) = parse_frame(&buf[..1 + n]).unwrap();
    assert_eq!(consumed, 1 + n);
    match frame {
        QuicFrame::MaxStreams { max, bidi } => {
            assert_eq!(max, 100);
            assert!(bidi);
        }
        _ => panic!("expected MaxStreams"),
    }

    // Uni (0x13)
    buf[0] = 0x13;
    let (frame, _) = parse_frame(&buf[..1 + n]).unwrap();
    match frame {
        QuicFrame::MaxStreams { max, bidi } => {
            assert_eq!(max, 100);
            assert!(!bidi);
        }
        _ => panic!("expected MaxStreams"),
    }
}

#[test]
fn write_then_parse_stream_roundtrip() {
    let mut buf = [0u8; 128];
    let stream_id = StreamId(4);
    let offset = 256u64;
    let data = b"roundtrip stream data";

    let written = frame_writer::write_stream(&mut buf, stream_id, offset, data, true);
    let (frame, consumed) = parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match frame {
        QuicFrame::Stream(sf) => {
            assert_eq!(sf.stream_id, StreamId(4));
            assert_eq!(sf.offset, 256);
            assert_eq!(sf.data, b"roundtrip stream data");
            assert!(sf.fin);
        }
        _ => panic!("expected Stream frame"),
    }
}

#[test]
fn write_then_parse_crypto_roundtrip() {
    let mut buf = [0u8; 128];
    let offset = 0u64;
    let data = b"tls client hello data";

    let written = frame_writer::write_crypto(&mut buf, offset, data);
    let (frame, consumed) = parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match frame {
        QuicFrame::Crypto(cf) => {
            assert_eq!(cf.offset, 0);
            assert_eq!(cf.data, b"tls client hello data");
        }
        _ => panic!("expected Crypto frame"),
    }
}

#[test]
fn parse_multiple_frames() {
    let mut buf = [0u8; 256];
    let mut pos = 0;

    // Frame 1: PING
    pos += frame_writer::write_ping(&mut buf[pos..]);
    // Frame 2: CRYPTO
    pos += frame_writer::write_crypto(&mut buf[pos..], 0, b"data");
    // Frame 3: HANDSHAKE_DONE
    pos += frame_writer::write_handshake_done(&mut buf[pos..]);

    let total = pos;
    let mut cursor = 0;

    // Parse frame 1
    let (frame, n) = parse_frame(&buf[cursor..total]).unwrap();
    assert!(matches!(frame, QuicFrame::Ping));
    cursor += n;

    // Parse frame 2
    let (frame, n) = parse_frame(&buf[cursor..total]).unwrap();
    match frame {
        QuicFrame::Crypto(cf) => assert_eq!(cf.data, b"data"),
        _ => panic!("expected Crypto"),
    }
    cursor += n;

    // Parse frame 3
    let (frame, n) = parse_frame(&buf[cursor..total]).unwrap();
    assert!(matches!(frame, QuicFrame::HandshakeDone));
    cursor += n;

    assert_eq!(cursor, total);
}

#[test]
fn parse_unknown_frame_type() {
    // Use a type byte that encodes to a large unknown value.
    // 0x40 | 0x30 = varint for value 0x30 = 48, which is in the valid 2-byte range
    // But let's use a simpler approach: single byte 0x20 (value 32, unknown)
    let buf = [0x20];
    let result = parse_frame(&buf);
    match result {
        Err(FrameParseError::InvalidFrameType(ft)) => assert_eq!(ft, 0x20),
        _ => panic!("expected InvalidFrameType error"),
    }
}

#[test]
fn parse_new_connection_id_cid_len_zero_fails() {
    let mut buf = [0u8; 64];
    buf[0] = 0x18;
    let mut pos = 1;
    pos += encode_varint(1, &mut buf[pos..]); // sequence
    pos += encode_varint(0, &mut buf[pos..]); // retire_prior_to
    buf[pos] = 0; // cid_len = 0
    pos += 1;
    // 16 bytes for stateless reset token
    pos += 16;
    assert!(parse_frame(&buf[..pos]).is_err());
}

#[test]
fn parse_new_connection_id_cid_len_21_fails() {
    let mut buf = [0u8; 64];
    buf[0] = 0x18;
    let mut pos = 1;
    pos += encode_varint(1, &mut buf[pos..]); // sequence
    pos += encode_varint(0, &mut buf[pos..]); // retire_prior_to
    buf[pos] = 21; // cid_len too long
    pos += 1;
    // Fill 21 + 16 bytes
    pos += 21 + 16;
    assert!(parse_frame(&buf[..pos]).is_err());
}

#[test]
fn parse_new_connection_id_retire_gt_sequence_fails() {
    let mut buf = [0u8; 64];
    buf[0] = 0x18;
    let mut pos = 1;
    pos += encode_varint(5, &mut buf[pos..]); // sequence
    pos += encode_varint(6, &mut buf[pos..]); // retire > sequence
    buf[pos] = 4; // cid_len
    pos += 1;
    buf[pos..pos + 4].copy_from_slice(&[1, 2, 3, 4]);
    pos += 4;
    // 16 bytes for stateless reset token
    pos += 16;
    assert!(parse_frame(&buf[..pos]).is_err());
}

#[test]
fn parse_new_token_empty_fails() {
    let mut buf = [0u8; 16];
    buf[0] = 0x07;
    let mut pos = 1;
    pos += encode_varint(0, &mut buf[pos..]); // empty token
    assert!(parse_frame(&buf[..pos]).is_err());
}
