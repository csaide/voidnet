//! QUIC Transport Parameters encode/decode (RFC 9000 §18).
//!
//! Each parameter is encoded as TLV: varint type, varint length, value bytes.
//! Unknown parameter IDs are skipped for forward compatibility.

use super::varint::{decode_varint, encode_varint, varint_len};
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::error::TransportError;

// Parameter IDs (RFC 9000 §18.2)
const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
const MAX_IDLE_TIMEOUT: u64 = 0x01;
const STATELESS_RESET_TOKEN: u64 = 0x02;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;

// RFC defaults
const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;
const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
const DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;

/// QUIC Transport Parameters (RFC 9000 §18).
#[derive(Debug, Clone)]
pub struct TransportParams {
    // Connection limits
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u64,
    pub active_connection_id_limit: u64,

    // Flow control initial values
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,

    // Timing
    pub max_ack_delay_ms: u64,
    pub ack_delay_exponent: u64,

    // Features
    pub disable_active_migration: bool,

    // CID authentication (RFC 9000 §7.3)
    pub original_destination_connection_id: Option<ConnectionId>,
    pub initial_source_connection_id: Option<ConnectionId>,
    pub retry_source_connection_id: Option<ConnectionId>,

    // Tokens
    pub stateless_reset_token: Option<[u8; 16]>,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 0,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_ack_delay_ms: DEFAULT_MAX_ACK_DELAY_MS,
            ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            disable_active_migration: false,
            original_destination_connection_id: None,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            stateless_reset_token: None,
        }
    }
}

impl TransportParams {
    /// Encode transport parameters to wire format.
    ///
    /// Only non-default values are written. Returns number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Helper: encode a varint TLV parameter whose value is a varint
        macro_rules! encode_varint_param {
            ($id:expr, $val:expr, $default:expr) => {
                if $val != $default {
                    let vlen = varint_len($val);
                    pos += encode_varint($id, &mut buf[pos..]);
                    pos += encode_varint(vlen as u64, &mut buf[pos..]);
                    pos += encode_varint($val, &mut buf[pos..]);
                }
            };
        }

        // 0x00: original_destination_connection_id
        if let Some(ref cid) = self.original_destination_connection_id {
            let cid_bytes = cid.as_bytes();
            pos += encode_varint(ORIGINAL_DESTINATION_CONNECTION_ID, &mut buf[pos..]);
            pos += encode_varint(cid_bytes.len() as u64, &mut buf[pos..]);
            buf[pos..pos + cid_bytes.len()].copy_from_slice(cid_bytes);
            pos += cid_bytes.len();
        }

        // 0x01: max_idle_timeout (default 0)
        encode_varint_param!(MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms, 0u64);

        // 0x02: stateless_reset_token
        if let Some(ref token) = self.stateless_reset_token {
            pos += encode_varint(STATELESS_RESET_TOKEN, &mut buf[pos..]);
            pos += encode_varint(16u64, &mut buf[pos..]);
            buf[pos..pos + 16].copy_from_slice(token);
            pos += 16;
        }

        // 0x03: max_udp_payload_size (default 65527)
        encode_varint_param!(
            MAX_UDP_PAYLOAD_SIZE,
            self.max_udp_payload_size,
            DEFAULT_MAX_UDP_PAYLOAD_SIZE
        );

        // 0x04: initial_max_data (default 0)
        encode_varint_param!(INITIAL_MAX_DATA, self.initial_max_data, 0u64);

        // 0x05: initial_max_stream_data_bidi_local (default 0)
        encode_varint_param!(
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
            0u64
        );

        // 0x06: initial_max_stream_data_bidi_remote (default 0)
        encode_varint_param!(
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
            0u64
        );

        // 0x07: initial_max_stream_data_uni (default 0)
        encode_varint_param!(
            INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
            0u64
        );

        // 0x08: initial_max_streams_bidi (default 0)
        encode_varint_param!(
            INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
            0u64
        );

        // 0x09: initial_max_streams_uni (default 0)
        encode_varint_param!(INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni, 0u64);

        // 0x0a: ack_delay_exponent (default 3)
        encode_varint_param!(
            ACK_DELAY_EXPONENT,
            self.ack_delay_exponent,
            DEFAULT_ACK_DELAY_EXPONENT
        );

        // 0x0b: max_ack_delay (default 25)
        encode_varint_param!(
            MAX_ACK_DELAY,
            self.max_ack_delay_ms,
            DEFAULT_MAX_ACK_DELAY_MS
        );

        // 0x0c: disable_active_migration (presence = true, length = 0)
        if self.disable_active_migration {
            pos += encode_varint(DISABLE_ACTIVE_MIGRATION, &mut buf[pos..]);
            pos += encode_varint(0u64, &mut buf[pos..]);
        }

        // 0x0e: active_connection_id_limit (default 2)
        encode_varint_param!(
            ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
            DEFAULT_ACTIVE_CONNECTION_ID_LIMIT
        );

        // 0x0f: initial_source_connection_id
        if let Some(ref cid) = self.initial_source_connection_id {
            let cid_bytes = cid.as_bytes();
            pos += encode_varint(INITIAL_SOURCE_CONNECTION_ID, &mut buf[pos..]);
            pos += encode_varint(cid_bytes.len() as u64, &mut buf[pos..]);
            buf[pos..pos + cid_bytes.len()].copy_from_slice(cid_bytes);
            pos += cid_bytes.len();
        }

        // 0x10: retry_source_connection_id
        if let Some(ref cid) = self.retry_source_connection_id {
            let cid_bytes = cid.as_bytes();
            pos += encode_varint(RETRY_SOURCE_CONNECTION_ID, &mut buf[pos..]);
            pos += encode_varint(cid_bytes.len() as u64, &mut buf[pos..]);
            buf[pos..pos + cid_bytes.len()].copy_from_slice(cid_bytes);
            pos += cid_bytes.len();
        }

        pos
    }

    /// Decode transport parameters from wire format.
    ///
    /// Unknown parameter IDs are skipped (forward compatibility).
    /// Returns `TransportError::TRANSPORT_PARAMETER_ERROR` on malformed data.
    pub fn decode(buf: &[u8]) -> Result<Self, TransportError> {
        let mut params = TransportParams::default();
        let mut pos = 0;

        while pos < buf.len() {
            // Decode parameter type
            let (id, id_len) =
                decode_varint(&buf[pos..]).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
            pos += id_len;

            // Decode parameter length
            let (param_len, len_len) =
                decode_varint(&buf[pos..]).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
            pos += len_len;

            let param_len = param_len as usize;

            // Bounds check: make sure the value bytes are present
            if pos + param_len > buf.len() {
                return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
            }

            let value = &buf[pos..pos + param_len];
            pos += param_len;

            match id {
                ORIGINAL_DESTINATION_CONNECTION_ID => {
                    if param_len > 20 {
                        return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
                    }
                    params.original_destination_connection_id =
                        Some(ConnectionId::from_slice(value));
                }
                MAX_IDLE_TIMEOUT => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.max_idle_timeout_ms = val;
                }
                STATELESS_RESET_TOKEN => {
                    if param_len != 16 {
                        return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
                    }
                    let mut token = [0u8; 16];
                    token.copy_from_slice(value);
                    params.stateless_reset_token = Some(token);
                }
                MAX_UDP_PAYLOAD_SIZE => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.max_udp_payload_size = val;
                }
                INITIAL_MAX_DATA => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.initial_max_data = val;
                }
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.initial_max_stream_data_bidi_local = val;
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.initial_max_stream_data_bidi_remote = val;
                }
                INITIAL_MAX_STREAM_DATA_UNI => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.initial_max_stream_data_uni = val;
                }
                INITIAL_MAX_STREAMS_BIDI => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.initial_max_streams_bidi = val;
                }
                INITIAL_MAX_STREAMS_UNI => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.initial_max_streams_uni = val;
                }
                ACK_DELAY_EXPONENT => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.ack_delay_exponent = val;
                }
                MAX_ACK_DELAY => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.max_ack_delay_ms = val;
                }
                DISABLE_ACTIVE_MIGRATION => {
                    // Presence encodes true; length must be 0
                    if param_len != 0 {
                        return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
                    }
                    params.disable_active_migration = true;
                }
                ACTIVE_CONNECTION_ID_LIMIT => {
                    let (val, _) =
                        decode_varint(value).ok_or(TransportError::TRANSPORT_PARAMETER_ERROR)?;
                    params.active_connection_id_limit = val;
                }
                INITIAL_SOURCE_CONNECTION_ID => {
                    if param_len > 20 {
                        return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
                    }
                    params.initial_source_connection_id = Some(ConnectionId::from_slice(value));
                }
                RETRY_SOURCE_CONNECTION_ID => {
                    if param_len > 20 {
                        return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
                    }
                    params.retry_source_connection_id = Some(ConnectionId::from_slice(value));
                }
                _ => {
                    // Unknown parameter: skip for forward compatibility (RFC 9000 §7.4.2)
                }
            }
        }

        // Validate constraints per RFC 9000
        if params.ack_delay_exponent > 20 {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }
        if params.max_ack_delay_ms > 16384 {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }
        if params.max_udp_payload_size < 1200 {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }
        if params.active_connection_id_limit < 2 {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }

        Ok(params)
    }
}
