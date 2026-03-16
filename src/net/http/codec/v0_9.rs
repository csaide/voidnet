use super::parse::ConnectionDirective;
use crate::net::http::{
    error::ParseError,
    request::{BodyFraming, Method, Request, Version},
};

use super::{Codec, DecodeOutcome, DecodeResult};

/// HTTP/0.9 codec.
///
/// Parses the simple HTTP/0.9 request format: `GET <path>\r\n`
/// (also accepts bare `\n` for historical compatibility).
///
/// Responses have no status line or headers — just raw body bytes.
pub struct Http09Codec;

impl Http09Codec {
    pub fn new() -> Self {
        Self
    }
}

impl Codec for Http09Codec {
    fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome {
        // Find the end of the request line (\n or \r\n)
        let newline_pos = match memchr_newline(buf) {
            Some(pos) => pos,
            None => {
                return DecodeOutcome {
                    result: DecodeResult::Incomplete,
                    consumed: 0,
                };
            }
        };

        // Determine the line content (strip \r\n or \n)
        let line_end = if newline_pos > 0 && buf[newline_pos - 1] == b'\r' {
            newline_pos - 1
        } else {
            newline_pos
        };

        let line = &buf[..line_end];
        let consumed = newline_pos + 1; // consume through the \n

        // Empty line
        if line.is_empty() {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::InvalidRequestLine),
                consumed,
            };
        }

        // Find the space separating method from path
        let space_pos = match memchr(b' ', line) {
            Some(pos) => pos,
            None => {
                // No space — could be just "GET" with no path
                return DecodeOutcome {
                    result: DecodeResult::Error(ParseError::InvalidRequestLine),
                    consumed,
                };
            }
        };

        let method_bytes = &line[..space_pos];
        let path = &line[space_pos + 1..];

        // Validate method
        if method_bytes != b"GET" {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::UnsupportedMethod),
                consumed,
            };
        }

        // Path must not be empty
        if path.is_empty() {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::InvalidRequestLine),
                consumed,
            };
        }

        // Compute absolute offsets into the ReadBuffer
        let path_start = buf_offset + space_pos + 1;
        let path_end = buf_offset + line_end;

        DecodeOutcome {
            result: DecodeResult::Complete(Request::new(
                Method::Get,
                path_start,
                path_end,
                Version::Http09,
                Vec::new(),
                BodyFraming::None,
                false,
                ConnectionDirective::None,
            )),
            consumed,
        }
    }

    fn version(&self) -> Version {
        Version::Http09
    }
}

use super::parse::memchr_newline;
use memchr::memchr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_get() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /index.html\r\n";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 17);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.method, Method::Get);
                assert_eq!(req.path_from_buf(buf), b"/index.html");
                assert_eq!(req.version, Version::Http09);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_bare_newline() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /path\n";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 10);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.path_from_buf(buf), b"/path");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_root_path() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /\r\n";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 7);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.path_from_buf(buf), b"/");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_incomplete() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /index";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
    }

    #[test]
    fn decode_empty() {
        let mut codec = Http09Codec::new();
        let buf = b"";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
    }

    #[test]
    fn decode_unsupported_method() {
        let mut codec = Http09Codec::new();
        let buf = b"POST /data\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::UnsupportedMethod) => {}
            other => panic!("expected UnsupportedMethod, got {other:?}"),
        }
    }

    #[test]
    fn decode_missing_path() {
        let mut codec = Http09Codec::new();
        let buf = b"GET\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::InvalidRequestLine) => {}
            other => panic!("expected InvalidRequestLine, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_line() {
        let mut codec = Http09Codec::new();
        let buf = b"\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::InvalidRequestLine) => {}
            other => panic!("expected InvalidRequestLine, got {other:?}"),
        }
    }

    #[test]
    fn decode_with_offset() {
        let mut codec = Http09Codec::new();
        // Simulate buffer where unconsumed starts at offset 10
        let buf = b"GET /test\r\n";
        let outcome = codec.decode(buf, 10);
        assert_eq!(outcome.consumed, 11);
        match outcome.result {
            DecodeResult::Complete(req) => {
                // path offsets should be absolute (buf_offset + local position)
                assert_eq!(req.path_start(), 14); // 10 + 4
                assert_eq!(req.path_end(), 19); // 10 + 9
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_path_with_query_string() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /search?q=hello&lang=en\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.method, Method::Get);
                assert_eq!(req.path_from_buf(buf), b"/search?q=hello&lang=en");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_path_with_fragment() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /page#section\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.path_from_buf(buf), b"/page#section");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_path_with_encoded_chars() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /path%20with%20spaces\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.path_from_buf(buf), b"/path%20with%20spaces");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_path_after_space() {
        let mut codec = Http09Codec::new();
        let buf = b"GET \r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::InvalidRequestLine) => {}
            other => panic!("expected InvalidRequestLine for empty path, got {other:?}"),
        }
    }

    #[test]
    fn version_returns_http09() {
        let codec = Http09Codec::new();
        assert_eq!(codec.version(), Version::Http09);
    }
}
