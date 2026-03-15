use super::{Codec, DecodeOutcome, DecodeResult, parse};
use crate::net::http::request::{BodyFraming, Request, Version};

/// HTTP/1.0 codec.
///
/// Parses full HTTP/1.0 requests: request line + headers + optional body.
/// Uses the shared parsing layer in `parse.rs`.
pub struct Http10Codec;

impl Http10Codec {
    pub fn new() -> Self {
        Self
    }
}

impl Codec for Http10Codec {
    fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome {
        // Step 1: Parse the request line.
        let req_line = match parse::parse_request_line(buf, buf_offset) {
            None => {
                return DecodeOutcome {
                    result: DecodeResult::Incomplete,
                    consumed: 0,
                };
            }
            Some(Err(e)) => {
                return DecodeOutcome {
                    result: DecodeResult::Error(e),
                    consumed: 0,
                };
            }
            Some(Ok(rl)) => rl,
        };

        // Step 2: Parse headers from the buffer immediately after the request line.
        // parse_headers takes only the sub-buffer; offsets are LOCAL (0-based into header_buf).
        let header_buf = &buf[req_line.consumed..];
        let (local_headers, headers_consumed) = match parse::parse_headers(header_buf) {
            None => {
                return DecodeOutcome {
                    result: DecodeResult::Incomplete,
                    consumed: 0,
                };
            }
            Some(Err(e)) => {
                return DecodeOutcome {
                    result: DecodeResult::Error(e),
                    consumed: 0,
                };
            }
            Some(Ok((headers, consumed))) => (headers, consumed),
        };

        // Step 3: Determine body framing via Content-Length (local headers + local buf).
        let body_framing = match parse::find_content_length(&local_headers, header_buf) {
            Err(e) => {
                return DecodeOutcome {
                    result: DecodeResult::Error(e),
                    consumed: 0,
                };
            }
            Ok(Some(len)) => BodyFraming::ContentLength(len),
            Ok(None) => BodyFraming::None,
        };

        // Step 4: Absolutize header offsets.
        let abs_base = buf_offset + req_line.consumed;
        let abs_headers = parse::absolutize_headers(&local_headers, abs_base);

        let consumed = req_line.consumed + headers_consumed;

        // Step 5: Detect connection directive.
        let connection_directive = parse::detect_connection_directive(&local_headers, header_buf);

        DecodeOutcome {
            result: DecodeResult::Complete(Request::new(
                req_line.method,
                req_line.path_start,
                req_line.path_end,
                Version::Http10,
                abs_headers,
                body_framing,
                false,
                connection_directive,
            )),
            consumed,
        }
    }

    fn version(&self) -> Version {
        Version::Http10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http::error::ParseError;
    use crate::net::http::request::{BodyFraming, Method, Version};

    #[test]
    fn decode_simple_get() {
        let mut codec = Http10Codec::new();
        let buf = b"GET /index.html HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.method, Method::Get);
                assert_eq!(req.version, Version::Http10);
                assert_eq!(req.path_from_buf(buf), b"/index.html");
                assert_eq!(req.body_framing, BodyFraming::None);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_post_with_content_length() {
        let mut codec = Http10Codec::new();
        let buf = b"POST /submit HTTP/1.0\r\nContent-Length: 13\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.method, Method::Post);
                assert_eq!(req.body_framing, BodyFraming::ContentLength(13));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_incomplete_request_line() {
        let mut codec = Http10Codec::new();
        let buf = b"GET /index.html HTTP/1.0";
        let outcome = codec.decode(buf, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
        assert_eq!(outcome.consumed, 0);
    }

    #[test]
    fn decode_incomplete_headers() {
        let mut codec = Http10Codec::new();
        let buf = b"GET /index.html HTTP/1.0\r\nHost: example.com\r\n";
        let outcome = codec.decode(buf, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
        assert_eq!(outcome.consumed, 0);
    }

    #[test]
    fn decode_with_offset() {
        let mut codec = Http10Codec::new();
        // Simulate the request starting at absolute offset 100.
        // The header block needs a proper \r\n\r\n terminator after the request line.
        let buf = b"GET /hello HTTP/1.0\r\nHost: x.com\r\n\r\n";
        let outcome = codec.decode(buf, 100);
        match outcome.result {
            DecodeResult::Complete(req) => {
                // "GET " is 4 bytes, so path_start = 100 + 4 = 104
                assert_eq!(req.path_start(), 104);
                // "/hello" is 6 bytes, so path_end = 104 + 6 = 110
                assert_eq!(req.path_end(), 110);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_invalid_content_length() {
        let mut codec = Http10Codec::new();
        let buf = b"POST /data HTTP/1.0\r\nContent-Length: abc\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::InvalidContentLength) => {}
            other => panic!("expected InvalidContentLength error, got {other:?}"),
        }
    }

    #[test]
    fn version_returns_http10() {
        let codec = Http10Codec::new();
        assert_eq!(codec.version(), Version::Http10);
    }
}
