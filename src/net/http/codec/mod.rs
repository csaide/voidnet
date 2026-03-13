pub(crate) mod v0_9;

use crate::net::http::{
    error::ParseError,
    request::{Request, Version},
};

/// Result of attempting to decode an HTTP request from a byte buffer.
#[derive(Debug)]
pub enum DecodeResult {
    /// A complete request was parsed.
    Complete(Request),
    /// Not enough data yet — need more bytes.
    Incomplete,
    /// The input is malformed.
    Error(ParseError),
}

/// Outcome of a decode attempt: the result plus how many bytes were consumed.
#[derive(Debug)]
pub struct DecodeOutcome {
    pub result: DecodeResult,
    pub consumed: usize,
}

/// HTTP codec trait — interprets bytes as HTTP structures.
///
/// The `&mut self` receiver is intentional: HTTP/0.9 is stateless, but
/// future codecs (HTTP/2 HPACK) will need mutable state.
pub(crate) trait Codec {
    /// Attempt to decode a request from `buf`.
    ///
    /// `buf_offset` is the absolute position of `buf[0]` in the ReadBuffer,
    /// used to compute absolute offsets for the Request's path fields.
    fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome;

    /// Returns the HTTP version this codec handles.
    fn version(&self) -> Version;
}

/// Enum dispatch for HTTP codecs. Avoids dyn trait overhead.
pub(crate) enum HttpCodec {
    Http09(v0_9::Http09Codec),
}

impl HttpCodec {
    pub fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome {
        match self {
            HttpCodec::Http09(c) => c.decode(buf, buf_offset),
        }
    }

    pub fn version(&self) -> Version {
        match self {
            HttpCodec::Http09(c) => c.version(),
        }
    }
}
