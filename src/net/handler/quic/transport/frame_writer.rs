//! QUIC frame writer (RFC 9000 §19).
//!
//! Each function writes a single frame into `&mut [u8]` and returns bytes written.
//! No heap allocations.

use super::frame::StreamId;
use super::varint::encode_varint;
use crate::net::handler::quic::connection_id::ConnectionIdRef;

/// Write a PADDING frame (single zero byte). Returns 1.
#[allow(dead_code)]
pub fn write_padding(buf: &mut [u8]) -> usize {
    buf[0] = 0x00;
    1
}

/// Write a PING frame. Returns 1.
#[allow(dead_code)]
pub fn write_ping(buf: &mut [u8]) -> usize {
    buf[0] = 0x01;
    1
}

/// Write a CRYPTO frame. Returns bytes written.
pub fn write_crypto(buf: &mut [u8], offset: u64, data: &[u8]) -> usize {
    let mut pos = 0;
    buf[pos] = 0x06;
    pos += 1;
    pos += encode_varint(offset, &mut buf[pos..]);
    pos += encode_varint(data.len() as u64, &mut buf[pos..]);
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();
    pos
}

/// Write a STREAM frame. Returns bytes written.
///
/// Always sets the LEN bit (0x02) so frames can be concatenated.
/// Sets OFF bit (0x04) if offset > 0, FIN bit (0x01) if fin is true.
pub fn write_stream(
    buf: &mut [u8],
    stream_id: StreamId,
    offset: u64,
    data: &[u8],
    fin: bool,
) -> usize {
    let mut frame_type: u8 = 0x08;
    frame_type |= 0x02; // LEN always set
    if offset > 0 {
        frame_type |= 0x04; // OFF
    }
    if fin {
        frame_type |= 0x01; // FIN
    }

    let mut pos = 0;
    buf[pos] = frame_type;
    pos += 1;
    pos += encode_varint(stream_id.0, &mut buf[pos..]);
    if offset > 0 {
        pos += encode_varint(offset, &mut buf[pos..]);
    }
    pos += encode_varint(data.len() as u64, &mut buf[pos..]);
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();
    pos
}

/// Write a MAX_DATA frame. Returns bytes written.
pub fn write_max_data(buf: &mut [u8], max: u64) -> usize {
    let mut pos = 0;
    buf[pos] = 0x10;
    pos += 1;
    pos += encode_varint(max, &mut buf[pos..]);
    pos
}

/// Write a MAX_STREAM_DATA frame. Returns bytes written.
pub fn write_max_stream_data(buf: &mut [u8], stream_id: StreamId, max: u64) -> usize {
    let mut pos = 0;
    buf[pos] = 0x11;
    pos += 1;
    pos += encode_varint(stream_id.0, &mut buf[pos..]);
    pos += encode_varint(max, &mut buf[pos..]);
    pos
}

/// Write a MAX_STREAMS frame. Returns bytes written.
pub fn write_max_streams(buf: &mut [u8], max: u64, bidi: bool) -> usize {
    let mut pos = 0;
    buf[pos] = if bidi { 0x12 } else { 0x13 };
    pos += 1;
    pos += encode_varint(max, &mut buf[pos..]);
    pos
}

/// Write a CONNECTION_CLOSE frame (type 0x1c, transport error). Returns bytes written.
pub fn write_connection_close(
    buf: &mut [u8],
    error_code: u64,
    frame_type: u64,
    reason: &[u8],
) -> usize {
    let mut pos = 0;
    buf[pos] = 0x1c;
    pos += 1;
    pos += encode_varint(error_code, &mut buf[pos..]);
    pos += encode_varint(frame_type, &mut buf[pos..]);
    pos += encode_varint(reason.len() as u64, &mut buf[pos..]);
    buf[pos..pos + reason.len()].copy_from_slice(reason);
    pos += reason.len();
    pos
}

/// Write a CONNECTION_CLOSE frame (type 0x1d, application error). Returns bytes written.
pub fn write_connection_close_app(buf: &mut [u8], error_code: u64, reason: &[u8]) -> usize {
    let mut pos = 0;
    buf[pos] = 0x1d;
    pos += 1;
    pos += encode_varint(error_code, &mut buf[pos..]);
    pos += encode_varint(reason.len() as u64, &mut buf[pos..]);
    buf[pos..pos + reason.len()].copy_from_slice(reason);
    pos += reason.len();
    pos
}

/// Write a HANDSHAKE_DONE frame. Returns 1.
#[allow(dead_code)]
pub fn write_handshake_done(buf: &mut [u8]) -> usize {
    buf[0] = 0x1e;
    1
}

/// Write a PATH_CHALLENGE frame. Returns 9.
#[allow(dead_code)]
pub fn write_path_challenge(buf: &mut [u8], data: [u8; 8]) -> usize {
    buf[0] = 0x1a;
    buf[1..9].copy_from_slice(&data);
    9
}

/// Write a PATH_RESPONSE frame. Returns 9.
#[allow(dead_code)]
pub fn write_path_response(buf: &mut [u8], data: [u8; 8]) -> usize {
    buf[0] = 0x1b;
    buf[1..9].copy_from_slice(&data);
    9
}

/// Write a NEW_CONNECTION_ID frame. Returns bytes written.
pub fn write_new_connection_id(
    buf: &mut [u8],
    sequence: u64,
    retire_prior_to: u64,
    connection_id: ConnectionIdRef<'_>,
    stateless_reset_token: [u8; 16],
) -> usize {
    let mut pos = 0;
    buf[pos] = 0x18;
    pos += 1;
    pos += encode_varint(sequence, &mut buf[pos..]);
    pos += encode_varint(retire_prior_to, &mut buf[pos..]);
    let cid_bytes = connection_id.as_bytes();
    buf[pos] = cid_bytes.len() as u8;
    pos += 1;
    buf[pos..pos + cid_bytes.len()].copy_from_slice(cid_bytes);
    pos += cid_bytes.len();
    buf[pos..pos + 16].copy_from_slice(&stateless_reset_token);
    pos += 16;
    pos
}

/// Write a RESET_STREAM frame. Returns bytes written.
pub fn write_reset_stream(
    buf: &mut [u8],
    stream_id: StreamId,
    error_code: u64,
    final_size: u64,
) -> usize {
    let mut pos = 0;
    buf[pos] = 0x04;
    pos += 1;
    pos += encode_varint(stream_id.0, &mut buf[pos..]);
    pos += encode_varint(error_code, &mut buf[pos..]);
    pos += encode_varint(final_size, &mut buf[pos..]);
    pos
}

/// Write a STOP_SENDING frame. Returns bytes written.
pub fn write_stop_sending(buf: &mut [u8], stream_id: StreamId, error_code: u64) -> usize {
    let mut pos = 0;
    buf[pos] = 0x05;
    pos += 1;
    pos += encode_varint(stream_id.0, &mut buf[pos..]);
    pos += encode_varint(error_code, &mut buf[pos..]);
    pos
}

/// Write a RETIRE_CONNECTION_ID frame. Returns bytes written.
pub fn write_retire_connection_id(buf: &mut [u8], sequence: u64) -> usize {
    let mut pos = 0;
    buf[pos] = 0x19;
    pos += 1;
    pos += encode_varint(sequence, &mut buf[pos..]);
    pos
}

/// Write a DATA_BLOCKED frame. Returns bytes written.
#[allow(dead_code)]
pub fn write_data_blocked(buf: &mut [u8], limit: u64) -> usize {
    let mut pos = 0;
    buf[pos] = 0x14;
    pos += 1;
    pos += encode_varint(limit, &mut buf[pos..]);
    pos
}

/// Write a STREAM_DATA_BLOCKED frame. Returns bytes written.
#[allow(dead_code)]
pub fn write_stream_data_blocked(buf: &mut [u8], stream_id: StreamId, limit: u64) -> usize {
    let mut pos = 0;
    buf[pos] = 0x15;
    pos += 1;
    pos += encode_varint(stream_id.0, &mut buf[pos..]);
    pos += encode_varint(limit, &mut buf[pos..]);
    pos
}

/// Write a STREAMS_BLOCKED frame. Returns bytes written.
#[allow(dead_code)]
pub fn write_streams_blocked(buf: &mut [u8], max: u64, bidi: bool) -> usize {
    let mut pos = 0;
    buf[pos] = if bidi { 0x16 } else { 0x17 };
    pos += 1;
    pos += encode_varint(max, &mut buf[pos..]);
    pos
}

/// Write a DATAGRAM_WITH_LENGTH frame (type 0x31, RFC 9221). Returns bytes written.
pub fn write_datagram_with_length(buf: &mut [u8], data: &[u8]) -> usize {
    let mut pos = 0;
    buf[pos] = 0x31; // DATAGRAM_WITH_LENGTH
    pos += 1;
    pos += encode_varint(data.len() as u64, &mut buf[pos..]);
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();
    pos
}

/// Write a NEW_TOKEN frame. Returns bytes written.
pub fn write_new_token(buf: &mut [u8], token: &[u8]) -> usize {
    let mut pos = 0;
    buf[pos] = 0x07;
    pos += 1;
    pos += encode_varint(token.len() as u64, &mut buf[pos..]);
    buf[pos..pos + token.len()].copy_from_slice(token);
    pos += token.len();
    pos
}
