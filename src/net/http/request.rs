use std::fmt;

use crate::net::http::codec::parse::ConnectionDirective;

/// HTTP request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Trace,
    Connect,
    Patch,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
            Method::Head => write!(f, "HEAD"),
            Method::Post => write!(f, "POST"),
            Method::Put => write!(f, "PUT"),
            Method::Delete => write!(f, "DELETE"),
            Method::Options => write!(f, "OPTIONS"),
            Method::Trace => write!(f, "TRACE"),
            Method::Connect => write!(f, "CONNECT"),
            Method::Patch => write!(f, "PATCH"),
        }
    }
}

/// HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http09,
    Http10,
    Http11,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::Http09 => write!(f, "HTTP/0.9"),
            Version::Http10 => write!(f, "HTTP/1.0"),
            Version::Http11 => write!(f, "HTTP/1.1"),
        }
    }
}

/// Zero-copy header field offsets into the connection's read buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderOffset {
    pub name_start: usize,
    pub name_end: usize,
    pub value_start: usize,
    pub value_end: usize,
}

/// How the body length is determined for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
}

/// An HTTP request with offset-based zero-copy path and header access.
///
/// Path and header values are resolved via offset lookup into the
/// connection's read buffer.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    path_start: usize,
    path_end: usize,
    pub version: Version,
    pub headers: Vec<HeaderOffset>,
    pub body_framing: BodyFraming,
    pub(crate) expect_continue: bool,
    pub(crate) connection_directive: ConnectionDirective,
}

impl Request {
    /// Create a new request with the given method, path offsets, version,
    /// headers, and body framing.
    pub(crate) fn new(
        method: Method,
        path_start: usize,
        path_end: usize,
        version: Version,
        headers: Vec<HeaderOffset>,
        body_framing: BodyFraming,
        expect_continue: bool,
        connection_directive: ConnectionDirective,
    ) -> Self {
        Self {
            method,
            path_start,
            path_end,
            version,
            headers,
            body_framing,
            expect_continue,
            connection_directive,
        }
    }

    /// Resolve the request path from a byte buffer.
    ///
    /// The buffer must be the same buffer the offsets were parsed from
    /// (i.e., the connection's ReadBuffer). This is enforced by the
    /// `HttpConnection::request_path()` API in normal usage.
    #[allow(dead_code)]
    pub(crate) fn path_from_buf<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.path_start..self.path_end]
    }

    /// Returns the byte offset where the path starts in the read buffer.
    pub fn path_start(&self) -> usize {
        self.path_start
    }

    /// Returns the byte offset where the path ends in the read buffer.
    pub fn path_end(&self) -> usize {
        self.path_end
    }

    /// Look up a header value by name (case-insensitive).
    ///
    /// Returns the raw bytes of the header value if found, or `None`.
    /// The `buf` must be the same buffer the offsets were parsed from.
    pub fn header_value<'a>(&self, buf: &'a [u8], name: &str) -> Option<&'a [u8]> {
        for h in &self.headers {
            let header_name = &buf[h.name_start..h.name_end];
            if header_name.eq_ignore_ascii_case(name.as_bytes()) {
                return Some(&buf[h.value_start..h.value_end]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http::codec::parse::ConnectionDirective;

    #[test]
    fn method_display_all() {
        assert_eq!(format!("{}", Method::Get), "GET");
        assert_eq!(format!("{}", Method::Head), "HEAD");
        assert_eq!(format!("{}", Method::Post), "POST");
        assert_eq!(format!("{}", Method::Put), "PUT");
        assert_eq!(format!("{}", Method::Delete), "DELETE");
        assert_eq!(format!("{}", Method::Options), "OPTIONS");
        assert_eq!(format!("{}", Method::Trace), "TRACE");
        assert_eq!(format!("{}", Method::Connect), "CONNECT");
        assert_eq!(format!("{}", Method::Patch), "PATCH");
    }

    #[test]
    fn version_display_all() {
        assert_eq!(format!("{}", Version::Http09), "HTTP/0.9");
        assert_eq!(format!("{}", Version::Http10), "HTTP/1.0");
        assert_eq!(format!("{}", Version::Http11), "HTTP/1.1");
    }

    #[test]
    fn header_offset_is_copy() {
        let h = HeaderOffset {
            name_start: 0,
            name_end: 4,
            value_start: 6,
            value_end: 15,
        };
        let h2 = h; // Copy
        assert_eq!(h.name_start, h2.name_start);
        assert_eq!(h.value_end, h2.value_end);
    }

    #[test]
    fn body_framing_default_is_none() {
        let framing = BodyFraming::None;
        assert_eq!(framing, BodyFraming::None);
    }

    #[test]
    fn body_framing_content_length() {
        let framing = BodyFraming::ContentLength(1024);
        assert_eq!(framing, BodyFraming::ContentLength(1024));
    }

    #[test]
    fn body_framing_chunked() {
        let framing = BodyFraming::Chunked;
        assert_eq!(framing, BodyFraming::Chunked);
    }

    #[test]
    fn request_is_clone() {
        let req = Request::new(
            Method::Get,
            4,
            15,
            Version::Http09,
            Vec::new(),
            BodyFraming::None,
            false,
            ConnectionDirective::None,
        );
        let req2 = req.clone();
        assert_eq!(req.method, req2.method);
        assert_eq!(req.version, req2.version);
    }

    #[test]
    fn request_is_no_longer_copy_but_clone() {
        // Request cannot be Copy because it contains Vec<HeaderOffset>.
        // Verify clone works correctly.
        let req = Request::new(
            Method::Post,
            5,
            10,
            Version::Http11,
            vec![HeaderOffset {
                name_start: 0,
                name_end: 4,
                value_start: 6,
                value_end: 9,
            }],
            BodyFraming::ContentLength(42),
            false,
            ConnectionDirective::None,
        );
        let req2 = req.clone();
        assert_eq!(req2.method, Method::Post);
        assert_eq!(req2.version, Version::Http11);
        assert_eq!(req2.headers.len(), 1);
        assert_eq!(req2.body_framing, BodyFraming::ContentLength(42));
    }

    #[test]
    fn request_path_offsets() {
        let req = Request::new(
            Method::Get,
            4,
            15,
            Version::Http09,
            Vec::new(),
            BodyFraming::None,
            false,
            ConnectionDirective::None,
        );
        let buf = b"GET /index.html\r\n";
        assert_eq!(req.path_from_buf(buf), b"/index.html");
    }

    #[test]
    fn request_empty_path() {
        let req = Request::new(
            Method::Get,
            4,
            5,
            Version::Http09,
            Vec::new(),
            BodyFraming::None,
            false,
            ConnectionDirective::None,
        );
        let buf = b"GET /\n";
        assert_eq!(req.path_from_buf(buf), b"/");
    }

    #[test]
    fn request_header_value_lookup() {
        // Simulate buffer: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        //                   0123456789...
        // "Host" at 16..20, ": " skipped, "example.com" at 22..33
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let headers = vec![HeaderOffset {
            name_start: 16,
            name_end: 20,
            value_start: 22,
            value_end: 33,
        }];
        let req = Request::new(
            Method::Get,
            4,
            5,
            Version::Http11,
            headers,
            BodyFraming::None,
            false,
            ConnectionDirective::None,
        );
        assert_eq!(req.header_value(buf, "Host"), Some(b"example.com".as_ref()));
        assert_eq!(req.header_value(buf, "host"), Some(b"example.com".as_ref()));
        assert_eq!(req.header_value(buf, "HOST"), Some(b"example.com".as_ref()));
        assert_eq!(req.header_value(buf, "Content-Type"), None);
    }

    #[test]
    fn method_debug() {
        assert_eq!(format!("{:?}", Method::Get), "Get");
    }

    #[test]
    fn version_display() {
        assert_eq!(format!("{}", Version::Http09), "HTTP/0.9");
    }
}
