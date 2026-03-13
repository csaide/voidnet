use std::fmt;

use crate::net::{BindError, TcpError};

/// Errors returned by HTTP operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// Underlying TCP error (reset, timeout, not connected, etc.)
    Tcp(TcpError),
    /// Bind error from TcpListener (address in use, etc.)
    Bind(BindError),
    /// HTTP parse error from the codec
    Parse(ParseError),
    /// Connection closed
    Closed,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Tcp(e) => write!(f, "TCP error: {e}"),
            HttpError::Bind(e) => write!(f, "bind error: {e}"),
            HttpError::Parse(e) => write!(f, "HTTP parse error: {e}"),
            HttpError::Closed => write!(f, "connection closed"),
        }
    }
}

impl From<TcpError> for HttpError {
    fn from(e: TcpError) -> Self {
        HttpError::Tcp(e)
    }
}

impl From<BindError> for HttpError {
    fn from(e: BindError) -> Self {
        HttpError::Bind(e)
    }
}

impl From<ParseError> for HttpError {
    fn from(e: ParseError) -> Self {
        HttpError::Parse(e)
    }
}

/// HTTP parse errors from the codec layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Request line is malformed (invalid method, missing path, etc.)
    InvalidRequestLine,
    /// Request line exceeds buffer capacity
    RequestTooLarge,
    /// Unsupported HTTP method (for HTTP/0.9: anything other than GET)
    UnsupportedMethod,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidRequestLine => write!(f, "invalid request line"),
            ParseError::RequestTooLarge => write!(f, "request too large"),
            ParseError::UnsupportedMethod => write!(f, "unsupported method"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_display() {
        assert_eq!(
            format!("{}", ParseError::InvalidRequestLine),
            "invalid request line"
        );
        assert_eq!(
            format!("{}", ParseError::RequestTooLarge),
            "request too large"
        );
        assert_eq!(
            format!("{}", ParseError::UnsupportedMethod),
            "unsupported method"
        );
    }

    #[test]
    fn http_error_display() {
        let e = HttpError::Parse(ParseError::InvalidRequestLine);
        assert_eq!(format!("{e}"), "HTTP parse error: invalid request line");

        let e = HttpError::Closed;
        assert_eq!(format!("{e}"), "connection closed");
    }

    #[test]
    fn http_error_from_tcp_error() {
        let e: HttpError = TcpError::Reset.into();
        assert!(matches!(e, HttpError::Tcp(TcpError::Reset)));
    }

    #[test]
    fn http_error_from_bind_error() {
        let e: HttpError = BindError::AddressInUse.into();
        assert!(matches!(e, HttpError::Bind(BindError::AddressInUse)));
    }

    #[test]
    fn http_error_from_parse_error() {
        let e: HttpError = ParseError::UnsupportedMethod.into();
        assert!(matches!(e, HttpError::Parse(ParseError::UnsupportedMethod)));
    }
}
