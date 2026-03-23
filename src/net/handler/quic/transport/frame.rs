//! QUIC frame parser (RFC 9000 §19).
//!
//! All data-carrying variants borrow zero-copy from the input packet buffer.

use super::varint::decode_varint;
use crate::net::handler::quic::connection_id::ConnectionIdRef;

/// Stream ID (RFC 9000 §2.1). Low 2 bits encode initiator + direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn initiator_is_client(&self) -> bool {
        self.0 & 0x01 == 0
    }
    pub fn is_bidi(&self) -> bool {
        self.0 & 0x02 == 0
    }
    pub fn index(&self) -> u64 {
        self.0 >> 2
    }
}

/// All QUIC frame types (RFC 9000 §19).
#[derive(Debug)]
pub enum QuicFrame<'a> {
    Padding,                       // §19.1 (type 0x00)
    Ping,                          // §19.2 (type 0x01)
    Ack(AckFrame<'a>),             // §19.3 (type 0x02/0x03)
    ResetStream(ResetStreamFrame), // §19.4 (type 0x04)
    StopSending(StopSendingFrame), // §19.5 (type 0x05)
    Crypto(CryptoFrame<'a>),       // §19.6 (type 0x06)
    NewToken(NewTokenFrame<'a>),   // §19.7 (type 0x07)
    Stream(StreamFrame<'a>),       // §19.8 (type 0x08-0x0f)
    MaxData(u64),                  // §19.9 (type 0x10)
    MaxStreamData {
        stream_id: StreamId,
        max: u64,
    }, // §19.10 (type 0x11)
    MaxStreams {
        max: u64,
        bidi: bool,
    }, // §19.11 (type 0x12/0x13)
    DataBlocked(u64),              // §19.12 (type 0x14)
    StreamDataBlocked {
        stream_id: StreamId,
        limit: u64,
    }, // §19.13 (type 0x15)
    StreamsBlocked {
        max: u64,
        bidi: bool,
    }, // §19.14 (type 0x16/0x17)
    NewConnectionId(NewConnectionIdFrame<'a>), // §19.15 (type 0x18)
    RetireConnectionId {
        sequence: u64,
    }, // §19.16 (type 0x19)
    PathChallenge([u8; 8]),        // §19.17 (type 0x1a)
    PathResponse([u8; 8]),         // §19.18 (type 0x1b)
    ConnectionClose(ConnectionCloseFrame<'a>), // §19.19 (type 0x1c/0x1d)
    HandshakeDone,                 // §19.20 (type 0x1e)
    /// DATAGRAM frame (RFC 9221, type 0x30/0x31)
    Datagram {
        data: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct AckFrame<'a> {
    pub largest_acked: u64,
    pub ack_delay: u64,
    pub first_ack_range: u64,
    pub ranges: &'a [u8],
    pub range_count: u64,
    pub ecn: Option<EcnCounts>,
}

#[derive(Debug, Clone, Copy)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ecn_ce: u64,
}

#[derive(Debug)]
pub struct ResetStreamFrame {
    pub stream_id: StreamId,
    pub error_code: u64,
    pub final_size: u64,
}

#[derive(Debug)]
pub struct StopSendingFrame {
    pub stream_id: StreamId,
    pub error_code: u64,
}

#[derive(Debug)]
pub struct CryptoFrame<'a> {
    pub offset: u64,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct NewTokenFrame<'a> {
    pub token: &'a [u8],
}

#[derive(Debug)]
pub struct StreamFrame<'a> {
    pub stream_id: StreamId,
    pub offset: u64,
    pub data: &'a [u8],
    pub fin: bool,
}

#[derive(Debug)]
pub struct NewConnectionIdFrame<'a> {
    pub sequence: u64,
    pub retire_prior_to: u64,
    pub connection_id: ConnectionIdRef<'a>,
    pub stateless_reset_token: [u8; 16],
}

#[derive(Debug)]
pub struct ConnectionCloseFrame<'a> {
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub reason: &'a [u8],
}

/// Error type for frame parsing.
#[derive(Debug, PartialEq)]
pub enum FrameParseError {
    BufferTooShort,
    InvalidFrameType(u64),
    InvalidFrame,
    /// Unknown frame type that is not in the GREASE range (RFC 9000 §12.4).
    UnknownFrameType(u64),
}

/// Parse one frame from buffer. Returns (frame, bytes_consumed) or error.
#[inline]
pub fn parse_frame(buf: &[u8]) -> Result<(QuicFrame<'_>, usize), FrameParseError> {
    if buf.is_empty() {
        return Err(FrameParseError::BufferTooShort);
    }

    let (frame_type, type_len) = decode_varint(buf).ok_or(FrameParseError::BufferTooShort)?;
    let rest = &buf[type_len..];

    match frame_type {
        0x00 => Ok((QuicFrame::Padding, type_len)),
        0x01 => Ok((QuicFrame::Ping, type_len)),

        // ACK (0x02 = no ECN, 0x03 = with ECN)
        0x02 | 0x03 => {
            let has_ecn = frame_type == 0x03;
            let mut pos = 0;

            let (largest_acked, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            let (ack_delay, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            let (range_count, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            let (first_ack_range, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            // The remaining gap/range pairs: we borrow the raw bytes
            let ranges_start = pos;
            for _ in 0..range_count {
                // gap
                let (_, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                // ack range
                let (_, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
            }
            let ranges = &rest[ranges_start..pos];

            let ecn = if has_ecn {
                let (ect0, n) =
                    decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                let (ect1, n) =
                    decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                let (ecn_ce, n) =
                    decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                Some(EcnCounts { ect0, ect1, ecn_ce })
            } else {
                None
            };

            Ok((
                QuicFrame::Ack(AckFrame {
                    largest_acked,
                    ack_delay,
                    first_ack_range,
                    ranges,
                    range_count,
                    ecn,
                }),
                type_len + pos,
            ))
        }

        // RESET_STREAM (0x04)
        0x04 => {
            let mut pos = 0;
            let (stream_id, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (error_code, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (final_size, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            Ok((
                QuicFrame::ResetStream(ResetStreamFrame {
                    stream_id: StreamId(stream_id),
                    error_code,
                    final_size,
                }),
                type_len + pos,
            ))
        }

        // STOP_SENDING (0x05)
        0x05 => {
            let mut pos = 0;
            let (stream_id, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (error_code, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            Ok((
                QuicFrame::StopSending(StopSendingFrame {
                    stream_id: StreamId(stream_id),
                    error_code,
                }),
                type_len + pos,
            ))
        }

        // CRYPTO (0x06)
        0x06 => {
            let mut pos = 0;
            let (offset, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (length, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let length = length as usize;
            if rest.len() < pos + length {
                return Err(FrameParseError::BufferTooShort);
            }
            let data = &rest[pos..pos + length];
            pos += length;
            Ok((
                QuicFrame::Crypto(CryptoFrame { offset, data }),
                type_len + pos,
            ))
        }

        // NEW_TOKEN (0x07)
        0x07 => {
            let mut pos = 0;
            let (length, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let length = length as usize;
            if length == 0 {
                return Err(FrameParseError::InvalidFrame);
            }
            if rest.len() < pos + length {
                return Err(FrameParseError::BufferTooShort);
            }
            let token = &rest[pos..pos + length];
            pos += length;
            Ok((QuicFrame::NewToken(NewTokenFrame { token }), type_len + pos))
        }

        // STREAM (0x08-0x0f)
        0x08..=0x0f => {
            let fin = (frame_type & 0x01) != 0;
            let has_len = (frame_type & 0x02) != 0;
            let has_off = (frame_type & 0x04) != 0;

            let mut pos = 0;
            let (stream_id, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            let offset = if has_off {
                let (off, n) =
                    decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                off
            } else {
                0
            };

            let data = if has_len {
                let (length, n) =
                    decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                let length = length as usize;
                if rest.len() < pos + length {
                    return Err(FrameParseError::BufferTooShort);
                }
                let d = &rest[pos..pos + length];
                pos += length;
                d
            } else {
                // No length field: data extends to end of packet
                let d = &rest[pos..];
                pos = rest.len();
                d
            };

            Ok((
                QuicFrame::Stream(StreamFrame {
                    stream_id: StreamId(stream_id),
                    offset,
                    data,
                    fin,
                }),
                type_len + pos,
            ))
        }

        // MAX_DATA (0x10)
        0x10 => {
            let (max, n) = decode_varint(rest).ok_or(FrameParseError::BufferTooShort)?;
            Ok((QuicFrame::MaxData(max), type_len + n))
        }

        // MAX_STREAM_DATA (0x11)
        0x11 => {
            let mut pos = 0;
            let (stream_id, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (max, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            Ok((
                QuicFrame::MaxStreamData {
                    stream_id: StreamId(stream_id),
                    max,
                },
                type_len + pos,
            ))
        }

        // MAX_STREAMS (0x12 = bidi, 0x13 = uni)
        0x12 | 0x13 => {
            let (max, n) = decode_varint(rest).ok_or(FrameParseError::BufferTooShort)?;
            Ok((
                QuicFrame::MaxStreams {
                    max,
                    bidi: frame_type == 0x12,
                },
                type_len + n,
            ))
        }

        // DATA_BLOCKED (0x14)
        0x14 => {
            let (limit, n) = decode_varint(rest).ok_or(FrameParseError::BufferTooShort)?;
            Ok((QuicFrame::DataBlocked(limit), type_len + n))
        }

        // STREAM_DATA_BLOCKED (0x15)
        0x15 => {
            let mut pos = 0;
            let (stream_id, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (limit, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            Ok((
                QuicFrame::StreamDataBlocked {
                    stream_id: StreamId(stream_id),
                    limit,
                },
                type_len + pos,
            ))
        }

        // STREAMS_BLOCKED (0x16 = bidi, 0x17 = uni)
        0x16 | 0x17 => {
            let (max, n) = decode_varint(rest).ok_or(FrameParseError::BufferTooShort)?;
            Ok((
                QuicFrame::StreamsBlocked {
                    max,
                    bidi: frame_type == 0x16,
                },
                type_len + n,
            ))
        }

        // NEW_CONNECTION_ID (0x18)
        0x18 => {
            let mut pos = 0;
            let (sequence, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let (retire_prior_to, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            // Connection ID length is a single byte (not varint)
            if rest.len() < pos + 1 {
                return Err(FrameParseError::BufferTooShort);
            }
            let cid_len = rest[pos] as usize;
            pos += 1;

            if cid_len == 0 || cid_len > 20 {
                return Err(FrameParseError::InvalidFrame);
            }
            if retire_prior_to > sequence {
                return Err(FrameParseError::InvalidFrame);
            }

            if rest.len() < pos + cid_len + 16 {
                return Err(FrameParseError::BufferTooShort);
            }
            let connection_id = ConnectionIdRef::from_slice(&rest[pos..pos + cid_len]);
            pos += cid_len;

            let mut stateless_reset_token = [0u8; 16];
            stateless_reset_token.copy_from_slice(&rest[pos..pos + 16]);
            pos += 16;

            Ok((
                QuicFrame::NewConnectionId(NewConnectionIdFrame {
                    sequence,
                    retire_prior_to,
                    connection_id,
                    stateless_reset_token,
                }),
                type_len + pos,
            ))
        }

        // RETIRE_CONNECTION_ID (0x19)
        0x19 => {
            let (sequence, n) = decode_varint(rest).ok_or(FrameParseError::BufferTooShort)?;
            Ok((QuicFrame::RetireConnectionId { sequence }, type_len + n))
        }

        // PATH_CHALLENGE (0x1a)
        0x1a => {
            if rest.len() < 8 {
                return Err(FrameParseError::BufferTooShort);
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(&rest[..8]);
            Ok((QuicFrame::PathChallenge(data), type_len + 8))
        }

        // PATH_RESPONSE (0x1b)
        0x1b => {
            if rest.len() < 8 {
                return Err(FrameParseError::BufferTooShort);
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(&rest[..8]);
            Ok((QuicFrame::PathResponse(data), type_len + 8))
        }

        // CONNECTION_CLOSE (0x1c = QUIC transport, 0x1d = application)
        0x1c | 0x1d => {
            let is_transport = frame_type == 0x1c;
            let mut pos = 0;

            let (error_code, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;

            let frame_type_field = if is_transport {
                let (ft, n) = decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
                pos += n;
                Some(ft)
            } else {
                None
            };

            let (reason_len, n) =
                decode_varint(&rest[pos..]).ok_or(FrameParseError::BufferTooShort)?;
            pos += n;
            let reason_len = reason_len as usize;
            if rest.len() < pos + reason_len {
                return Err(FrameParseError::BufferTooShort);
            }
            let reason = &rest[pos..pos + reason_len];
            pos += reason_len;

            Ok((
                QuicFrame::ConnectionClose(ConnectionCloseFrame {
                    error_code,
                    frame_type: frame_type_field,
                    reason,
                }),
                type_len + pos,
            ))
        }

        // HANDSHAKE_DONE (0x1e)
        0x1e => Ok((QuicFrame::HandshakeDone, type_len)),

        // DATAGRAM (0x30) — no length field, extends to end of packet (RFC 9221)
        0x30 => {
            let data = buf[type_len..].to_vec();
            Ok((QuicFrame::Datagram { data }, buf.len()))
        }

        // DATAGRAM_WITH_LENGTH (0x31) — has explicit length field (RFC 9221)
        0x31 => {
            let (length, len_size) =
                decode_varint(&buf[type_len..]).ok_or(FrameParseError::BufferTooShort)?;
            let start = type_len + len_size;
            let end = start + length as usize;
            if end > buf.len() {
                return Err(FrameParseError::BufferTooShort);
            }
            let data = buf[start..end].to_vec();
            Ok((QuicFrame::Datagram { data }, end))
        }

        _ => {
            // RFC 9000 §19.21: GREASE frames (type % 0x1f == 0x1e) MUST be ignored.
            if frame_type % 0x1f == 0x1e {
                // GREASE frame — silently skip the type varint only.
                // These have no defined payload, so consume just the type.
                Ok((QuicFrame::Padding, type_len))
            } else {
                // RFC 9000 §12.4: unknown frame type is FRAME_ENCODING_ERROR.
                Err(FrameParseError::UnknownFrameType(frame_type))
            }
        }
    }
}
