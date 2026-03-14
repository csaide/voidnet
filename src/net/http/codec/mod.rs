pub(crate) mod parse;
pub(crate) mod v0_9;
pub(crate) mod v1_0;
pub(crate) mod v1_1;

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
    /// Initial state: version not yet determined. Peeks at the first line.
    Detecting,
    Http09(v0_9::Http09Codec),
    Http10(v1_0::Http10Codec),
    Http11(v1_1::Http11Codec),
}

impl HttpCodec {
    pub fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome {
        match self {
            HttpCodec::Detecting => {
                match parse::detect_version(buf) {
                    None => DecodeOutcome {
                        result: DecodeResult::Incomplete,
                        consumed: 0,
                    },
                    Some(Err(e)) => DecodeOutcome {
                        result: DecodeResult::Error(e),
                        consumed: 0,
                    },
                    Some(Ok(version)) => {
                        // Transition to the appropriate codec and re-decode.
                        *self = match version {
                            Version::Http09 => HttpCodec::Http09(v0_9::Http09Codec::new()),
                            Version::Http10 => HttpCodec::Http10(v1_0::Http10Codec::new()),
                            Version::Http11 => HttpCodec::Http11(v1_1::Http11Codec::new()),
                        };
                        self.decode(buf, buf_offset)
                    }
                }
            }
            HttpCodec::Http09(c) => c.decode(buf, buf_offset),
            HttpCodec::Http10(c) => c.decode(buf, buf_offset),
            HttpCodec::Http11(c) => c.decode(buf, buf_offset),
        }
    }

    pub fn version(&self) -> Version {
        match self {
            HttpCodec::Detecting => Version::Http09,
            HttpCodec::Http09(c) => c.version(),
            HttpCodec::Http10(c) => c.version(),
            HttpCodec::Http11(c) => c.version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecting_codec_http11() {
        let mut codec = HttpCodec::Detecting;
        let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.version, Version::Http11);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn detecting_codec_http10() {
        let mut codec = HttpCodec::Detecting;
        let buf = b"GET /index.html HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.version, Version::Http10);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn detecting_codec_http09() {
        let mut codec = HttpCodec::Detecting;
        let buf = b"GET /index.html\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.version, Version::Http09);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn detecting_codec_incomplete() {
        let mut codec = HttpCodec::Detecting;
        // No newline yet — can't detect version.
        let buf = b"GET /index.html HTTP/1.1";
        let outcome = codec.decode(buf, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
        assert_eq!(outcome.consumed, 0);
    }
}
