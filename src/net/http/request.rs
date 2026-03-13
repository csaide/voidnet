use std::fmt;

/// HTTP request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
        }
    }
}

/// HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http09,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::Http09 => write!(f, "HTTP/0.9"),
        }
    }
}

/// An HTTP request with offset-based zero-copy path access.
///
/// `Request` is `Copy` — no allocations, no lifetimes. Path is resolved
/// via offset lookup into the connection's read buffer.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub method: Method,
    path_start: usize,
    path_end: usize,
    pub version: Version,
}

impl Request {
    /// Create a new request with the given method, path offsets, and version.
    pub(crate) fn new(method: Method, path_start: usize, path_end: usize, version: Version) -> Self {
        Self {
            method,
            path_start,
            path_end,
            version,
        }
    }

    /// Resolve the request path from a byte buffer.
    ///
    /// The buffer must be the same buffer the offsets were parsed from
    /// (i.e., the connection's ReadBuffer). This is enforced by the
    /// `HttpConnection::request_path()` API in normal usage.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_copy() {
        let req = Request::new(Method::Get, 4, 15, Version::Http09);
        let req2 = req; // Copy
        assert_eq!(req.method, req2.method);
        assert_eq!(req.version, req2.version);
    }

    #[test]
    fn request_path_offsets() {
        let req = Request::new(Method::Get, 4, 15, Version::Http09);
        let buf = b"GET /index.html\r\n";
        assert_eq!(req.path_from_buf(buf), b"/index.html");
    }

    #[test]
    fn request_empty_path() {
        let req = Request::new(Method::Get, 4, 5, Version::Http09);
        let buf = b"GET /\n";
        assert_eq!(req.path_from_buf(buf), b"/");
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
