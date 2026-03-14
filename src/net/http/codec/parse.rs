use crate::net::http::{
    error::ParseError,
    request::{HeaderOffset, Method, Version},
};
use memchr::{memchr, memrchr, memmem};

// ── Private helpers ──────────────────────────────────────────────────────────

/// Case-insensitive byte-slice comparison.
#[inline]
fn bytes_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Find the position of the first `\n` byte in `buf`.
#[inline]
pub fn memchr_newline(buf: &[u8]) -> Option<usize> {
    memchr(b'\n', buf)
}

// ── Public types ─────────────────────────────────────────────────────────────

/// Parsed result of a request line.
#[derive(Debug, PartialEq, Eq)]
pub struct RequestLine {
    pub method: Method,
    /// Absolute offset of path start in the ReadBuffer.
    pub path_start: usize,
    /// Absolute offset of path end in the ReadBuffer.
    pub path_end: usize,
    pub version: Version,
    /// How many bytes of `buf` were consumed (including the terminating `\r\n`).
    pub consumed: usize,
}

/// How the `Connection` header directs keep-alive behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirective {
    KeepAlive,
    Close,
    None,
}

// ── parse_method ─────────────────────────────────────────────────────────────

/// Map an uppercase ASCII token to a [`Method`].
///
/// Only exact uppercase matches are accepted. Returns
/// [`ParseError::UnsupportedMethod`] for anything else.
pub(crate) fn parse_method(token: &[u8]) -> Result<Method, ParseError> {
    match token {
        b"GET" => Ok(Method::Get),
        b"HEAD" => Ok(Method::Head),
        b"POST" => Ok(Method::Post),
        b"PUT" => Ok(Method::Put),
        b"DELETE" => Ok(Method::Delete),
        b"OPTIONS" => Ok(Method::Options),
        b"TRACE" => Ok(Method::Trace),
        b"CONNECT" => Ok(Method::Connect),
        b"PATCH" => Ok(Method::Patch),
        _ => Err(ParseError::UnsupportedMethod),
    }
}

// ── parse_request_line ───────────────────────────────────────────────────────

/// Parse `METHOD /path HTTP/1.x\r\n` from `buf`.
///
/// Returns:
/// - `None`             — incomplete (no `\r\n` yet)
/// - `Some(Ok(…))`      — successfully parsed
/// - `Some(Err(…))`     — malformed line
///
/// `buf_offset` is the absolute position of `buf[0]` inside the connection's
/// ReadBuffer; it is added to all path offsets so that callers always receive
/// absolute offsets.
///
/// Uses `rposition` on the first-line slice for the second space so that paths
/// that themselves contain spaces are handled correctly.
pub fn parse_request_line(
    buf: &[u8],
    buf_offset: usize,
) -> Option<Result<RequestLine, ParseError>> {
    // Need a complete line first.
    let newline_pos = memchr_newline(buf)?;

    let line_end = if newline_pos > 0 && buf[newline_pos - 1] == b'\r' {
        newline_pos - 1
    } else {
        newline_pos
    };
    let consumed = newline_pos + 1;

    let line = &buf[..line_end];

    // Empty line
    if line.is_empty() {
        return Some(Err(ParseError::InvalidRequestLine));
    }

    // First space separates method from the rest.
    let first_space = match memchr(b' ', line) {
        Some(p) => p,
        None => return Some(Err(ParseError::InvalidRequestLine)),
    };

    let method_bytes = &line[..first_space];
    let method = match parse_method(method_bytes) {
        Ok(m) => m,
        Err(e) => return Some(Err(e)),
    };

    // Last space separates path from version token.
    let after_method = &line[first_space + 1..];
    let last_space = match memrchr(b' ', after_method) {
        Some(p) => p,
        None => return Some(Err(ParseError::InvalidRequestLine)),
    };

    let path_slice = &after_method[..last_space];
    let version_token = &after_method[last_space + 1..];

    // Path must not be empty.
    if path_slice.is_empty() {
        return Some(Err(ParseError::InvalidRequestLine));
    }

    let version = match version_token {
        b"HTTP/1.0" => Version::Http10,
        b"HTTP/1.1" => Version::Http11,
        other if other.starts_with(b"HTTP/") => return Some(Err(ParseError::UnsupportedVersion)),
        _ => return Some(Err(ParseError::InvalidRequestLine)),
    };

    // Compute absolute offsets: buf_offset + local position inside buf.
    // `path_slice` starts at buf[first_space + 1].
    let path_start = buf_offset + first_space + 1;
    let path_end = buf_offset + first_space + 1 + last_space;

    Some(Ok(RequestLine {
        method,
        path_start,
        path_end,
        version,
        consumed,
    }))
}

// ── parse_headers ─────────────────────────────────────────────────────────────

const MAX_HEADERS: usize = 64;

/// Parse the header block that starts at the beginning of `buf`.
///
/// Returns:
/// - `None`                     — incomplete (no `\r\n\r\n` terminator yet)
/// - `Some(Ok((headers, n)))`   — `n` bytes consumed, offsets are LOCAL (0-based into `buf`)
/// - `Some(Err(…))`             — malformed
///
/// Offsets are **local** (0-based into `buf`). Call [`absolutize_headers`] to
/// convert them to absolute ReadBuffer positions before storing in a
/// [`Request`].
pub fn parse_headers(
    buf: &[u8],
) -> Option<Result<(Vec<HeaderOffset>, usize), ParseError>> {
    // We need \r\n\r\n (or \n\n) to know we have a complete header block.
    let (terminator_pos, terminator_len) = find_header_terminator(buf)?;
    let consumed = terminator_pos + terminator_len;

    // The scan region includes everything up to (but not including) the
    // blank-line terminator.  Individual header lines each end with \r\n or
    // \n, which are present in this slice (the terminator starts at the
    // *second* \r\n pair, so the first \r\n of \r\n\r\n is part of the last
    // header line).
    //
    // Example layout for "Host: foo\r\nBar: baz\r\n\r\n":
    //   pos 0..9   -> "Host: foo"
    //   pos 9..11  -> "\r\n"          <- end of Host header line
    //   pos 11..19 -> "Bar: baz"
    //   pos 19..21 -> "\r\n"          <- end of Bar header line
    //   pos 21..25 -> "\r\n\r\n"      <- terminator  (terminator_pos = 21)
    //
    // So scan_buf = &buf[..21], which includes the \r\n at the end of each
    // header.
    let scan_buf = &buf[..terminator_pos];

    let mut headers = Vec::new();
    let mut pos = 0;

    while pos < scan_buf.len() {
        // Find the \n that ends this header line.
        let rel_nl = match memchr_newline(&scan_buf[pos..]) {
            Some(p) => p,
            // No \n found: the remaining bytes are the last header line with no
            // trailing \r\n (bare last line before the \r\n\r\n terminator).
            // We treat scan_buf[pos..] as a header line.
            None => {
                let line = &scan_buf[pos..];
                if line.is_empty() {
                    break;
                }
                if let Some(e) = parse_header_line(line, pos, &mut headers) {
                    return Some(Err(e));
                }
                break;
            }
        };

        let line_end_nl = pos + rel_nl; // position of \n in scan_buf
        // Strip optional preceding \r.
        let raw_line_end = if line_end_nl > pos && scan_buf[line_end_nl - 1] == b'\r' {
            line_end_nl - 1
        } else {
            line_end_nl
        };

        let line = &scan_buf[pos..raw_line_end];

        // Empty line: skip (shouldn't normally occur before the terminator).
        if line.is_empty() {
            pos = line_end_nl + 1;
            continue;
        }

        if let Some(e) = parse_header_line(line, pos, &mut headers) {
            return Some(Err(e));
        }

        pos = line_end_nl + 1;
    }

    Some(Ok((headers, consumed)))
}

/// Parse a single header line (without terminating `\r\n`) and push the
/// resulting [`HeaderOffset`] onto `headers`.
///
/// `line_start` is the offset of `line[0]` within the original `buf`.
///
/// Returns `Some(ParseError)` on error, `None` on success.
fn parse_header_line(
    line: &[u8],
    line_start: usize,
    headers: &mut Vec<HeaderOffset>,
) -> Option<ParseError> {
    let colon = match memchr(b':', line) {
        Some(c) => c,
        None => return Some(ParseError::InvalidHeader),
    };

    let name_start = line_start;
    let name_end = line_start + colon;

    // Skip the colon and any leading OWS from the value.
    let value_raw = &line[colon + 1..];
    let value_trimmed_start = value_raw
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(value_raw.len());
    let value_trimmed_end = value_raw
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map(|p| p + 1)
        .unwrap_or(0);

    let value_start = line_start + colon + 1 + value_trimmed_start;
    let value_end = line_start + colon + 1 + value_trimmed_end;

    if headers.len() >= MAX_HEADERS {
        return Some(ParseError::TooManyHeaders);
    }

    headers.push(HeaderOffset { name_start, name_end, value_start, value_end });
    None
}

/// Locate the blank-line terminator for the header block.
///
/// Looks for `\r\n\r\n` first; falls back to `\n\n`.
///
/// Returns `(start_of_terminator, terminator_byte_length)`.
fn find_header_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = memmem::find(buf, b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = memmem::find(buf, b"\n\n") {
        return Some((pos, 2));
    }
    None
}

// ── find_content_length ───────────────────────────────────────────────────────

/// Case-insensitive lookup for `Content-Length` in `headers`.
pub(crate) fn find_content_length(
    headers: &[HeaderOffset],
    buf: &[u8],
) -> Result<Option<usize>, ParseError> {
    match header_value_for(headers, buf, b"content-length") {
        None => Ok(None),
        Some(val) => {
            let s = core::str::from_utf8(val).map_err(|_| ParseError::InvalidContentLength)?;
            s.trim()
                .parse::<usize>()
                .map(Some)
                .map_err(|_| ParseError::InvalidContentLength)
        }
    }
}

// ── has_header ────────────────────────────────────────────────────────────────

/// Return `true` if any header in `headers` has the given name (case-insensitive).
pub(crate) fn has_header(headers: &[HeaderOffset], buf: &[u8], name: &[u8]) -> bool {
    headers.iter().any(|h| bytes_eq_ignore_case(&buf[h.name_start..h.name_end], name))
}

// ── header_value_for ─────────────────────────────────────────────────────────

/// Return the value bytes for the first header with the given name
/// (case-insensitive), or `None`.
pub(crate) fn header_value_for<'a>(
    headers: &[HeaderOffset],
    buf: &'a [u8],
    name: &[u8],
) -> Option<&'a [u8]> {
    headers.iter().find_map(|h| {
        if bytes_eq_ignore_case(&buf[h.name_start..h.name_end], name) {
            Some(&buf[h.value_start..h.value_end])
        } else {
            None
        }
    })
}

// ── detect_version ────────────────────────────────────────────────────────────

/// Non-consuming peek at the first request line to determine the HTTP version.
///
/// Returns:
/// - `None`             — incomplete (no newline yet)
/// - `Some(Ok(…))`      — detected version
/// - `Some(Err(…))`     — version token starts with `HTTP/` but is not
///   `HTTP/1.0` or `HTTP/1.1`
///
/// If no version token is present (HTTP/0.9 simple request), returns
/// `Some(Ok(Version::Http09))`.
pub(crate) fn detect_version(buf: &[u8]) -> Option<Result<Version, ParseError>> {
    let newline_pos = memchr_newline(buf)?;

    let line_end = if newline_pos > 0 && buf[newline_pos - 1] == b'\r' {
        newline_pos - 1
    } else {
        newline_pos
    };

    let line = &buf[..line_end];

    // Look for the last space on the line.
    match memrchr(b' ', line) {
        None => {
            // No space at all — HTTP/0.9 bare request (e.g. "GET /path").
            // (Actually HTTP/0.9 has one space between method and path, but no
            // version token.  We'll treat "no last-space-followed-by-HTTP" as 0.9.)
            Some(Ok(Version::Http09))
        }
        Some(last_space) => {
            let token = &line[last_space + 1..];
            match token {
                b"HTTP/1.0" => Some(Ok(Version::Http10)),
                b"HTTP/1.1" => Some(Ok(Version::Http11)),
                other if other.starts_with(b"HTTP/") => {
                    Some(Err(ParseError::UnsupportedVersion))
                }
                _ => {
                    // Token after last space is not an HTTP version string — treat
                    // the whole line as HTTP/0.9 (path might contain spaces).
                    Some(Ok(Version::Http09))
                }
            }
        }
    }
}

// ── absolutize_headers ────────────────────────────────────────────────────────

/// Add `base` to every offset field in each [`HeaderOffset`].
///
/// Used by codecs to convert local (parse-buffer-relative) offsets returned by
/// [`parse_headers`] into absolute ReadBuffer offsets before constructing a
/// [`Request`].
pub(crate) fn absolutize_headers(headers: &[HeaderOffset], base: usize) -> Vec<HeaderOffset> {
    headers
        .iter()
        .map(|h| HeaderOffset {
            name_start: h.name_start + base,
            name_end: h.name_end + base,
            value_start: h.value_start + base,
            value_end: h.value_end + base,
        })
        .collect()
}

// ── detect_connection_directive ───────────────────────────────────────────────

/// Inspect the `Connection` header and return the appropriate directive.
pub(crate) fn detect_connection_directive(
    headers: &[HeaderOffset],
    buf: &[u8],
) -> ConnectionDirective {
    match header_value_for(headers, buf, b"connection") {
        None => ConnectionDirective::None,
        Some(val) => {
            if bytes_eq_ignore_case(val, b"keep-alive") {
                ConnectionDirective::KeepAlive
            } else if bytes_eq_ignore_case(val, b"close") {
                ConnectionDirective::Close
            } else {
                ConnectionDirective::None
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_method ─────────────────────────────────────────────────────────

    #[test]
    fn parse_method_all() {
        assert_eq!(parse_method(b"GET"), Ok(Method::Get));
        assert_eq!(parse_method(b"HEAD"), Ok(Method::Head));
        assert_eq!(parse_method(b"POST"), Ok(Method::Post));
        assert_eq!(parse_method(b"PUT"), Ok(Method::Put));
        assert_eq!(parse_method(b"DELETE"), Ok(Method::Delete));
        assert_eq!(parse_method(b"OPTIONS"), Ok(Method::Options));
        assert_eq!(parse_method(b"TRACE"), Ok(Method::Trace));
        assert_eq!(parse_method(b"CONNECT"), Ok(Method::Connect));
        assert_eq!(parse_method(b"PATCH"), Ok(Method::Patch));
    }

    #[test]
    fn parse_method_unknown() {
        assert_eq!(parse_method(b"FROBBLE"), Err(ParseError::UnsupportedMethod));
        assert_eq!(parse_method(b""), Err(ParseError::UnsupportedMethod));
    }

    #[test]
    fn parse_method_lowercase_rejected() {
        assert_eq!(parse_method(b"get"), Err(ParseError::UnsupportedMethod));
        assert_eq!(parse_method(b"post"), Err(ParseError::UnsupportedMethod));
    }

    // ── parse_request_line ───────────────────────────────────────────────────

    #[test]
    fn parse_request_line_http11() {
        let buf = b"GET /index.html HTTP/1.1\r\n";
        let rl = parse_request_line(buf, 0).unwrap().unwrap();
        assert_eq!(rl.method, Method::Get);
        assert_eq!(&buf[rl.path_start..rl.path_end], b"/index.html");
        assert_eq!(rl.version, Version::Http11);
        assert_eq!(rl.consumed, buf.len());
    }

    #[test]
    fn parse_request_line_http10() {
        let buf = b"POST /data HTTP/1.0\r\n";
        let rl = parse_request_line(buf, 0).unwrap().unwrap();
        assert_eq!(rl.method, Method::Post);
        assert_eq!(&buf[rl.path_start..rl.path_end], b"/data");
        assert_eq!(rl.version, Version::Http10);
        assert_eq!(rl.consumed, buf.len());
    }

    #[test]
    fn parse_request_line_with_offset() {
        // Simulate the request line starting 20 bytes into the ReadBuffer.
        let buf = b"GET /hello HTTP/1.1\r\n";
        let rl = parse_request_line(buf, 20).unwrap().unwrap();
        // "GET " is 4 bytes, so path_start = 20 + 4 = 24
        assert_eq!(rl.path_start, 24);
        // "/hello" is 6 bytes, so path_end = 24 + 6 = 30
        assert_eq!(rl.path_end, 30);
    }

    #[test]
    fn parse_request_line_incomplete() {
        let buf = b"GET /index.html HTTP/1.1";
        assert!(parse_request_line(buf, 0).is_none());
    }

    #[test]
    fn parse_request_line_unsupported_version() {
        let buf = b"GET / HTTP/2.0\r\n";
        assert_eq!(
            parse_request_line(buf, 0).unwrap(),
            Err(ParseError::UnsupportedVersion)
        );
    }

    #[test]
    fn parse_request_line_missing_path() {
        // No second space → can't split path from version
        let buf = b"GET HTTP/1.1\r\n";
        let result = parse_request_line(buf, 0).unwrap();
        // "HTTP/1.1" becomes both the "path" and "version" via rposition, but
        // there's no second space after the first, so last_space = 0 inside
        // after_method → path is empty.
        assert!(result.is_err());
    }

    // ── parse_headers ────────────────────────────────────────────────────────

    #[test]
    fn parse_headers_simple() {
        let buf = b"Host: example.com\r\nContent-Length: 5\r\n\r\n";
        let (headers, consumed) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(consumed, buf.len());

        // Verify Host header name and value bytes.
        assert_eq!(&buf[headers[0].name_start..headers[0].name_end], b"Host");
        assert_eq!(&buf[headers[0].value_start..headers[0].value_end], b"example.com");
    }

    #[test]
    fn parse_headers_offsets_are_local() {
        // When called with a sub-buffer, offsets must be 0-based into that buffer.
        let buf = b"X-Foo: bar\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(headers[0].name_start, 0);
        assert_eq!(headers[0].name_end, 5);
        assert_eq!(&buf[headers[0].value_start..headers[0].value_end], b"bar");
    }

    #[test]
    fn parse_headers_empty() {
        // An empty header block: just \r\n\r\n
        let buf = b"\r\n\r\n";
        let (headers, consumed) = parse_headers(buf).unwrap().unwrap();
        assert!(headers.is_empty());
        assert_eq!(consumed, 4);
    }

    #[test]
    fn parse_headers_value_whitespace_trimmed() {
        let buf = b"X-Spaces:   hello world   \r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(&buf[headers[0].value_start..headers[0].value_end], b"hello world");
    }

    #[test]
    fn parse_headers_incomplete_no_terminator() {
        let buf = b"Host: example.com\r\n";
        assert!(parse_headers(buf).is_none());
    }

    #[test]
    fn parse_headers_incomplete_partial_line() {
        let buf = b"Host: ex";
        assert!(parse_headers(buf).is_none());
    }

    #[test]
    fn parse_headers_malformed_no_colon() {
        let buf = b"InvalidHeaderLine\r\n\r\n";
        assert_eq!(
            parse_headers(buf).unwrap(),
            Err(ParseError::InvalidHeader)
        );
    }

    #[test]
    fn parse_headers_too_many() {
        // Build 65 headers to exceed the limit.
        let mut buf = String::new();
        for i in 0..65 {
            buf.push_str(&format!("X-Header-{i}: value\r\n"));
        }
        buf.push_str("\r\n");
        assert_eq!(
            parse_headers(buf.as_bytes()).unwrap(),
            Err(ParseError::TooManyHeaders)
        );
    }

    // ── find_content_length ──────────────────────────────────────────────────

    #[test]
    fn find_content_length_present() {
        let buf = b"Content-Length: 42\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(find_content_length(&headers, buf), Ok(Some(42)));
    }

    #[test]
    fn find_content_length_absent() {
        let buf = b"Host: example.com\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(find_content_length(&headers, buf), Ok(None));
    }

    #[test]
    fn find_content_length_invalid() {
        let buf = b"Content-Length: abc\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(find_content_length(&headers, buf), Err(ParseError::InvalidContentLength));
    }

    #[test]
    fn find_content_length_case_insensitive() {
        let buf = b"content-length: 7\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(find_content_length(&headers, buf), Ok(Some(7)));
    }

    // ── has_header ───────────────────────────────────────────────────────────

    #[test]
    fn has_header_case_insensitive() {
        let buf = b"Host: example.com\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert!(has_header(&headers, buf, b"host"));
        assert!(has_header(&headers, buf, b"HOST"));
        assert!(has_header(&headers, buf, b"Host"));
        assert!(!has_header(&headers, buf, b"Content-Type"));
    }

    // ── header_value_for ─────────────────────────────────────────────────────

    #[test]
    fn header_value_for_returns_value() {
        let buf = b"X-Custom: hello\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(header_value_for(&headers, buf, b"x-custom"), Some(b"hello".as_ref()));
        assert_eq!(header_value_for(&headers, buf, b"X-CUSTOM"), Some(b"hello".as_ref()));
        assert_eq!(header_value_for(&headers, buf, b"missing"), None);
    }

    // ── detect_version ───────────────────────────────────────────────────────

    #[test]
    fn detect_version_http11() {
        assert_eq!(detect_version(b"GET / HTTP/1.1\r\n"), Some(Ok(Version::Http11)));
    }

    #[test]
    fn detect_version_http10() {
        assert_eq!(detect_version(b"GET / HTTP/1.0\r\n"), Some(Ok(Version::Http10)));
    }

    #[test]
    fn detect_version_http09() {
        // HTTP/0.9 simple request — no version token after the last space.
        assert_eq!(detect_version(b"GET /index.html\r\n"), Some(Ok(Version::Http09)));
    }

    #[test]
    fn detect_version_incomplete() {
        assert_eq!(detect_version(b"GET / HTTP/1.1"), None);
    }

    #[test]
    fn detect_version_unsupported() {
        assert_eq!(
            detect_version(b"GET / HTTP/2.0\r\n"),
            Some(Err(ParseError::UnsupportedVersion))
        );
    }

    // ── absolutize_headers ───────────────────────────────────────────────────

    #[test]
    fn absolutize_headers_adds_base_correctly() {
        let local = vec![HeaderOffset {
            name_start: 0,
            name_end: 4,
            value_start: 6,
            value_end: 11,
        }];
        let abs = absolutize_headers(&local, 100);
        assert_eq!(abs[0].name_start, 100);
        assert_eq!(abs[0].name_end, 104);
        assert_eq!(abs[0].value_start, 106);
        assert_eq!(abs[0].value_end, 111);
    }

    #[test]
    fn absolutize_headers_base_zero_is_identity() {
        let local = vec![HeaderOffset {
            name_start: 3,
            name_end: 7,
            value_start: 9,
            value_end: 14,
        }];
        let abs = absolutize_headers(&local, 0);
        assert_eq!(abs[0], local[0]);
    }

    // ── detect_connection_directive ──────────────────────────────────────────

    #[test]
    fn detect_connection_directive_keep_alive() {
        let buf = b"Connection: keep-alive\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(
            detect_connection_directive(&headers, buf),
            ConnectionDirective::KeepAlive
        );
    }

    #[test]
    fn detect_connection_directive_close() {
        let buf = b"Connection: close\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(
            detect_connection_directive(&headers, buf),
            ConnectionDirective::Close
        );
    }

    #[test]
    fn detect_connection_directive_absent() {
        let buf = b"Host: example.com\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(
            detect_connection_directive(&headers, buf),
            ConnectionDirective::None
        );
    }

    #[test]
    fn detect_connection_directive_unknown_value() {
        let buf = b"Connection: upgrade\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(
            detect_connection_directive(&headers, buf),
            ConnectionDirective::None
        );
    }

    #[test]
    fn detect_connection_directive_case_insensitive_value() {
        let buf = b"connection: Keep-Alive\r\n\r\n";
        let (headers, _) = parse_headers(buf).unwrap().unwrap();
        assert_eq!(
            detect_connection_directive(&headers, buf),
            ConnectionDirective::KeepAlive
        );
    }
}
