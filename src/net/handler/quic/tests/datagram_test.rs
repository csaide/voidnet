use crate::net::handler::quic::datagram::{DatagramError, DatagramQueue};
use crate::net::handler::quic::transport::frame::{QuicFrame, parse_frame};
use crate::net::handler::quic::transport::frame_writer::write_datagram_with_length;
use crate::net::handler::quic::transport::params::TransportParams;
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

// --- Queue tests ---

#[test]
fn datagram_queue_send_recv() {
    let mut q = DatagramQueue::new();
    q.max_send_size = Some(1200);

    q.queue_send(b"msg1".to_vec()).unwrap();
    q.queue_send(b"msg2".to_vec()).unwrap();

    assert!(q.has_pending_send());
    assert_eq!(q.pop_send().unwrap(), b"msg1");
    assert_eq!(q.pop_send().unwrap(), b"msg2");
    assert!(q.pop_send().is_none());
    assert!(!q.has_pending_send());
}

#[test]
fn datagram_queue_deliver_recv() {
    let mut q = DatagramQueue::new();
    q.max_recv_size = Some(1200);

    q.deliver(b"recv1".to_vec());
    q.deliver(b"recv2".to_vec());

    assert_eq!(q.pop_recv().unwrap(), b"recv1");
    assert_eq!(q.pop_recv().unwrap(), b"recv2");
    assert!(q.pop_recv().is_none());
}

#[test]
fn datagram_overflow_drops_oldest() {
    let mut q = DatagramQueue::new();
    q.max_send_size = Some(1200);

    // Fill to capacity (64) then add one more
    for i in 0..65u8 {
        q.queue_send(vec![i]).unwrap();
    }

    // First item should be #1 (item #0 was dropped)
    assert_eq!(q.pop_send().unwrap(), vec![1]);
}

#[test]
fn datagram_too_large_rejected() {
    let mut q = DatagramQueue::new();
    q.max_send_size = Some(10); // max 10 bytes

    let result = q.queue_send(vec![0; 11]);
    assert_eq!(result, Err(DatagramError::TooLarge));

    // Exactly 10 bytes should work
    assert!(q.queue_send(vec![0; 10]).is_ok());
}

#[test]
fn datagram_not_negotiated_rejected() {
    let mut q = DatagramQueue::new();
    // max_send_size is None (not negotiated)

    let result = q.queue_send(b"test".to_vec());
    assert_eq!(result, Err(DatagramError::NotNegotiated));
}

#[test]
fn transport_params_datagram_round_trip() {
    let mut params = TransportParams::default();
    params.max_datagram_frame_size = Some(65535);

    let mut buf = [0u8; 512];
    let encoded_len = params.encode(&mut buf);

    let decoded = TransportParams::decode(&buf[..encoded_len]).unwrap();
    assert_eq!(decoded.max_datagram_frame_size, Some(65535));
}

#[test]
fn transport_params_datagram_absent() {
    let params = TransportParams::default();
    assert!(params.max_datagram_frame_size.is_none());

    let mut buf = [0u8; 512];
    let encoded_len = params.encode(&mut buf);

    let decoded = TransportParams::decode(&buf[..encoded_len]).unwrap();
    assert!(decoded.max_datagram_frame_size.is_none());
}
