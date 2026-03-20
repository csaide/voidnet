/// QUIC transport error codes (RFC 9000 §20)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError(pub(crate) u64);

impl TransportError {
    pub const NO_ERROR: Self = Self(0x00);
    pub const INTERNAL_ERROR: Self = Self(0x01);
    pub const CONNECTION_REFUSED: Self = Self(0x02);
    pub const FLOW_CONTROL_ERROR: Self = Self(0x03);
    pub const STREAM_LIMIT_ERROR: Self = Self(0x04);
    pub const STREAM_STATE_ERROR: Self = Self(0x05);
    pub const FINAL_SIZE_ERROR: Self = Self(0x06);
    pub const FRAME_ENCODING_ERROR: Self = Self(0x07);
    pub const TRANSPORT_PARAMETER_ERROR: Self = Self(0x08);
    pub const CONNECTION_ID_LIMIT_ERROR: Self = Self(0x09);
    pub const PROTOCOL_VIOLATION: Self = Self(0x0a);
    pub const INVALID_TOKEN: Self = Self(0x0b);
    pub const APPLICATION_ERROR: Self = Self(0x0c);
    pub const CRYPTO_BUFFER_EXCEEDED: Self = Self(0x0d);
    pub const KEY_UPDATE_ERROR: Self = Self(0x0e);
    pub const AEAD_LIMIT_REACHED: Self = Self(0x0f);
    pub const NO_VIABLE_PATH: Self = Self(0x10);

    /// Map TLS alert to QUIC transport error (RFC 9001 §4.8).
    /// All TLS alerts are fatal in QUIC.
    pub fn from_tls_alert(alert: u8) -> Self {
        Self(0x0100 + alert as u64)
    }

    pub fn code(&self) -> u64 {
        self.0
    }

    pub fn is_crypto_error(&self) -> bool {
        self.0 >= 0x0100 && self.0 <= 0x01ff
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_crypto_error() {
            let alert = self.0 - 0x0100;
            return write!(f, "CRYPTO_ERROR(TLS alert 0x{:02x})", alert);
        }
        let name = match self.0 {
            0x00 => "NO_ERROR",
            0x01 => "INTERNAL_ERROR",
            0x02 => "CONNECTION_REFUSED",
            0x03 => "FLOW_CONTROL_ERROR",
            0x04 => "STREAM_LIMIT_ERROR",
            0x05 => "STREAM_STATE_ERROR",
            0x06 => "FINAL_SIZE_ERROR",
            0x07 => "FRAME_ENCODING_ERROR",
            0x08 => "TRANSPORT_PARAMETER_ERROR",
            0x09 => "CONNECTION_ID_LIMIT_ERROR",
            0x0a => "PROTOCOL_VIOLATION",
            0x0b => "INVALID_TOKEN",
            0x0c => "APPLICATION_ERROR",
            0x0d => "CRYPTO_BUFFER_EXCEEDED",
            0x0e => "KEY_UPDATE_ERROR",
            0x0f => "AEAD_LIMIT_REACHED",
            0x10 => "NO_VIABLE_PATH",
            _ => return write!(f, "UNKNOWN_ERROR(0x{:x})", self.0),
        };
        write!(f, "{}", name)
    }
}
