use crate::net::handler::quic::transport::frame::{QuicFrame, parse_frame};
use crate::net::handler::quic::transport::frame_writer::write_datagram_with_length;
use crate::net::handler::quic::transport::varint::encode_varint;

#[test]
fn parse_datagram_no_length() {
    // DATAGRAM (0x30): type byte + data extends to end of buffer
    let mut buf = vec![0x30]; // type
    buf.extend_from_slice(b"hello datagram");
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, buf.len());
    match frame {
        QuicFrame::Datagram { data } => {
            assert_eq!(data, b"hello datagram");
        }
        _ => panic!("expected Datagram frame"),
    }
}

#[test]
fn parse_datagram_no_length_empty() {
    // DATAGRAM (0x30) with empty data
    let buf = vec![0x30];
    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 1);
    match frame {
        QuicFrame::Datagram { data } => {
            assert!(data.is_empty());
        }
        _ => panic!("expected Datagram frame"),
    }
}

#[test]
fn parse_datagram_with_length() {
    // DATAGRAM_WITH_LENGTH (0x31): type + varint length + data
    let payload = b"test payload";
    let mut buf = vec![0x31];
    let mut len_buf = [0u8; 8];
    let len_size = encode_varint(payload.len() as u64, &mut len_buf);
    buf.extend_from_slice(&len_buf[..len_size]);
    buf.extend_from_slice(payload);
    // Add trailing bytes that should NOT be consumed
    buf.extend_from_slice(b"extra");

    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert_eq!(consumed, 1 + len_size + payload.len());
    match frame {
        QuicFrame::Datagram { data } => {
            assert_eq!(data, payload);
        }
        _ => panic!("expected Datagram frame"),
    }
}

#[test]
fn parse_datagram_with_length_truncated() {
    // DATAGRAM_WITH_LENGTH (0x31) with length exceeding buffer
    let mut buf = vec![0x31];
    let mut len_buf = [0u8; 8];
    let len_size = encode_varint(100, &mut len_buf); // claims 100 bytes
    buf.extend_from_slice(&len_buf[..len_size]);
    buf.extend_from_slice(b"short"); // only 5 bytes

    let result = parse_frame(&buf);
    assert!(result.is_err());
}

#[test]
fn datagram_round_trip() {
    let payload = b"round trip data 12345";
    let mut buf = [0u8; 256];
    let written = write_datagram_with_length(&mut buf, payload);

    // Parse back
    let (frame, consumed) = parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match frame {
        QuicFrame::Datagram { data } => {
            assert_eq!(data, payload);
        }
        _ => panic!("expected Datagram frame"),
    }
}

#[test]
fn datagram_round_trip_empty() {
    let mut buf = [0u8; 64];
    let written = write_datagram_with_length(&mut buf, &[]);

    let (frame, consumed) = parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match frame {
        QuicFrame::Datagram { data } => {
            assert!(data.is_empty());
        }
        _ => panic!("expected Datagram frame"),
    }
}

#[test]
fn datagram_round_trip_large() {
    let payload: Vec<u8> = (0..1200).map(|i| (i % 256) as u8).collect();
    let mut buf = [0u8; 1300];
    let written = write_datagram_with_length(&mut buf, &payload);

    let (frame, consumed) = parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match frame {
        QuicFrame::Datagram { data } => {
            assert_eq!(data, payload);
        }
        _ => panic!("expected Datagram frame"),
    }
}
