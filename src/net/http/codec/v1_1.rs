use super::{Codec, DecodeOutcome, DecodeResult, parse};
use crate::net::http::{
    error::ParseError,
    request::{BodyFraming, Request, Version},
};

/// HTTP/1.1 codec.
///
/// Parses full HTTP/1.1 requests: request line + headers + optional body.
/// Enforces that the Host header is present (RFC 7230 §5.4).
/// Detects chunked transfer encoding (RFC 7230 §3.3.3) with priority over
/// Content-Length.
pub struct Http11Codec;

impl Http11Codec {
    pub fn new() -> Self {
        Self
    }
}

impl Codec for Http11Codec {
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

        // Step 3: HTTP/1.1 requires a Host header (RFC 7230 §5.4).
        if !parse::has_header(&local_headers, header_buf, b"host") {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::MissingHostHeader),
                consumed: 0,
            };
        }

        // Step 4: Check for Expect: 100-continue.
        let expect_continue = parse::header_value_for(&local_headers, header_buf, b"expect")
            .map(|v| v.eq_ignore_ascii_case(b"100-continue"))
            .unwrap_or(false);

        // Step 5: Determine body framing.
        // Chunked Transfer-Encoding takes priority over Content-Length (RFC 7230 §3.3.3).
        let body_framing = if let Some(te) =
            parse::header_value_for(&local_headers, header_buf, b"transfer-encoding")
        {
            if te.eq_ignore_ascii_case(b"chunked") {
                BodyFraming::Chunked
            } else {
                // Non-chunked TE — fall through to Content-Length check.
                match parse::find_content_length(&local_headers, header_buf) {
                    Err(e) => {
                        return DecodeOutcome {
                            result: DecodeResult::Error(e),
                            consumed: 0,
                        };
                    }
                    Ok(Some(len)) => BodyFraming::ContentLength(len),
                    Ok(None) => BodyFraming::None,
                }
            }
        } else {
            match parse::find_content_length(&local_headers, header_buf) {
                Err(e) => {
                    return DecodeOutcome {
                        result: DecodeResult::Error(e),
                        consumed: 0,
                    };
                }
                Ok(Some(len)) => BodyFraming::ContentLength(len),
                Ok(None) => BodyFraming::None,
            }
        };

        // Step 6: Detect connection directive.
        let connection_directive = parse::detect_connection_directive(&local_headers, header_buf);

        // Step 7: Absolutize header offsets.
        let abs_base = buf_offset + req_line.consumed;
        let abs_headers = parse::absolutize_headers(&local_headers, abs_base);

        let consumed = req_line.consumed + headers_consumed;

        DecodeOutcome {
            result: DecodeResult::Complete(Request::new(
                req_line.method,
                req_line.path_start,
                req_line.path_end,
                Version::Http11,
                abs_headers,
                body_framing,
                expect_continue,
                connection_directive,
            )),
            consumed,
        }
    }

    fn version(&self) -> Version {
        Version::Http11
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http::request::{BodyFraming, Method, Version};
    use parse::ConnectionDirective;

    #[test]
    fn decode_simple_get() {
        let mut codec = Http11Codec::new();
        let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.method, Method::Get);
                assert_eq!(req.version, Version::Http11);
                assert_eq!(req.path_from_buf(buf), b"/index.html");
                assert_eq!(req.body_framing, BodyFraming::None);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_missing_host_header() {
        let mut codec = Http11Codec::new();
        let buf = b"GET /index.html HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::MissingHostHeader) => {}
            other => panic!("expected MissingHostHeader error, got {other:?}"),
        }
    }

    #[test]
    fn decode_chunked_transfer_encoding() {
        let mut codec = Http11Codec::new();
        let buf =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.body_framing, BodyFraming::Chunked);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_content_length_body() {
        let mut codec = Http11Codec::new();
        let buf = b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.body_framing, BodyFraming::ContentLength(42));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_chunked_takes_priority_over_content_length() {
        let mut codec = Http11Codec::new();
        // Both Transfer-Encoding: chunked and Content-Length present — chunked wins (RFC 7230 §3.3.3).
        let buf = b"POST /data HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 100\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.body_framing, BodyFraming::Chunked);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_incomplete() {
        let mut codec = Http11Codec::new();
        // Missing the final \r\n\r\n terminator.
        let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
        let outcome = codec.decode(buf, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
        assert_eq!(outcome.consumed, 0);
    }

    #[test]
    fn version_returns_http11() {
        let codec = Http11Codec::new();
        assert_eq!(codec.version(), Version::Http11);
    }

    #[test]
    fn decode_connection_close_directive() {
        let mut codec = Http11Codec::new();
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.connection_directive, ConnectionDirective::Close);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_connection_keep_alive_directive() {
        let mut codec = Http11Codec::new();
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.connection_directive, ConnectionDirective::KeepAlive);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_expect_100_continue() {
        let mut codec = Http11Codec::new();
        let buf =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert!(req.expect_continue);
                assert_eq!(req.body_framing, BodyFraming::ContentLength(100));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_expect_not_set_when_absent() {
        let mut codec = Http11Codec::new();
        let buf = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert!(!req.expect_continue);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_multiple_headers_same_name() {
        let mut codec = Http11Codec::new();
        // Two X-Custom headers — both should be present in the parsed header list.
        let buf =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: first\r\nX-Custom: second\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                let custom_count = req
                    .headers
                    .iter()
                    .filter(|h| buf[h.name_start..h.name_end].eq_ignore_ascii_case(b"X-Custom"))
                    .count();
                assert_eq!(custom_count, 2);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_header_value() {
        let mut codec = Http11Codec::new();
        // X-Empty header with no value after the colon.
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Empty:\r\n\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Complete(req) => {
                // Find the X-Empty header and confirm its value span is empty.
                let empty_header = req
                    .headers
                    .iter()
                    .find(|h| buf[h.name_start..h.name_end].eq_ignore_ascii_case(b"X-Empty"));
                assert!(empty_header.is_some(), "X-Empty header not found");
                let h = empty_header.unwrap();
                assert_eq!(h.value_start, h.value_end, "expected empty value span");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }
}
