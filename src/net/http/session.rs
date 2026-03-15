use crate::net::http::codec::parse::ConnectionDirective;
use crate::net::http::{
    HttpError,
    codec::{DecodeResult, HttpCodec, v0_9::Http09Codec},
    request::{Request, Version},
};

/// Connection-level state machine for HTTP request/response lifecycle.
///
/// Owns the codec and enforces request/response ordering.
pub(crate) struct Session {
    codec: HttpCodec,
    state: SessionState,
    connection_directive: ConnectionDirective,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum SessionState {
    /// Ready to decode the next request.
    AwaitingRequest,
    /// Request has been decoded, waiting for response to begin.
    RequestReady,
    /// Request body is being read.
    ReadingBody,
    /// Waiting to send 100 Continue.
    ExpectContinue,
    /// Response is being written.
    ResponseInProgress,
    /// A parse error occurred. Connection should close.
    Failed,
    /// Connection lifecycle is complete.
    Done,
    /// Response finished, connection kept alive, waiting for next request setup.
    AwaitingNext,
}

impl Session {
    /// Create a new session with the given codec.
    pub fn new(codec: HttpCodec) -> Self {
        Self {
            codec,
            state: SessionState::AwaitingRequest,
            connection_directive: ConnectionDirective::None,
        }
    }

    /// Create a new session with the default HTTP/0.9 codec.
    #[allow(dead_code)]
    pub fn http09() -> Self {
        Self::new(HttpCodec::Http09(Http09Codec::new()))
    }

    /// Create a new session in version-detecting mode.
    ///
    /// The codec will peek at the first request line to determine the HTTP
    /// version and transition to the appropriate codec automatically.
    pub fn detecting() -> Self {
        Self::new(HttpCodec::Detecting)
    }

    /// Try to decode a request from the buffer.
    ///
    /// `buf` is the unconsumed bytes from the ReadBuffer.
    /// `buf_offset` is the absolute position of buf[0] in the ReadBuffer.
    ///
    /// Returns `Ok(Some((request, consumed)))` on success,
    /// `Ok(None)` if more data is needed, or `Err` on parse error
    /// (which transitions the session to Failed/Done).
    pub fn try_decode_request(
        &mut self,
        buf: &[u8],
        buf_offset: usize,
    ) -> Result<Option<(Request, usize)>, HttpError> {
        debug_assert!(
            self.state == SessionState::AwaitingRequest,
            "try_decode_request called in state {:?}",
            self.state
        );

        let outcome = self.codec.decode(buf, buf_offset);
        match outcome.result {
            DecodeResult::Complete(req) => {
                self.state = SessionState::RequestReady;
                self.connection_directive = req.connection_directive;
                Ok(Some((req, outcome.consumed)))
            }
            DecodeResult::Incomplete => Ok(None),
            DecodeResult::Error(e) => {
                self.state = SessionState::Failed;
                Err(HttpError::Parse(e))
            }
        }
    }

    /// Mark that the response has started.
    pub fn begin_response(&mut self) {
        debug_assert!(
            self.state == SessionState::RequestReady || self.state == SessionState::ReadingBody,
            "begin_response called in state {:?}",
            self.state
        );
        self.state = SessionState::ResponseInProgress;
    }

    /// Mark that the response is finished.
    ///
    /// Returns `true` if the connection should stay alive (keep-alive).
    pub fn finish_response(&mut self) -> bool {
        debug_assert_eq!(self.state, SessionState::ResponseInProgress);

        let keep_alive = match self.codec.version() {
            Version::Http09 => false,
            Version::Http10 => self.connection_directive == ConnectionDirective::KeepAlive,
            Version::Http11 => self.connection_directive != ConnectionDirective::Close,
        };

        if keep_alive {
            self.state = SessionState::AwaitingNext;
        } else {
            self.state = SessionState::Done;
        }

        keep_alive
    }

    /// Transition from AwaitingNext to AwaitingRequest for the next request
    /// on a keep-alive connection.
    pub fn prepare_next_request(&mut self) {
        debug_assert_eq!(self.state, SessionState::AwaitingNext);
        self.connection_directive = ConnectionDirective::None;
        self.state = SessionState::AwaitingRequest;
    }

    /// Whether the session is done (connection should close).
    pub fn is_done(&self) -> bool {
        matches!(self.state, SessionState::Done | SessionState::Failed)
    }

    /// Returns the HTTP version of this session's codec.
    pub fn version(&self) -> Version {
        self.codec.version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http::{Method, Version};

    fn new_session() -> Session {
        Session::new(HttpCodec::Http09(Http09Codec::new()))
    }

    #[test]
    fn initial_state_is_awaiting_request() {
        let session = new_session();
        assert!(!session.is_done());
    }

    #[test]
    fn decode_complete_request() {
        let mut session = new_session();
        let buf = b"GET /test\r\n";
        let result = session.try_decode_request(buf, 0).unwrap();
        assert!(result.is_some());
        let (req, consumed) = result.unwrap();
        assert_eq!(req.method, Method::Get);
        assert_eq!(consumed, 11);
    }

    #[test]
    fn decode_incomplete_returns_none() {
        let mut session = new_session();
        let buf = b"GET /test";
        let result = session.try_decode_request(buf, 0).unwrap();
        assert!(result.is_none());
        assert!(!session.is_done());
    }

    #[test]
    fn decode_error_transitions_to_done() {
        let mut session = new_session();
        let buf = b"POST /test\r\n";
        let result = session.try_decode_request(buf, 0);
        assert!(result.is_err());
        assert!(session.is_done());
    }

    #[test]
    fn response_lifecycle() {
        let mut session = new_session();
        let buf = b"GET /\r\n";
        session.try_decode_request(buf, 0).unwrap();

        session.begin_response();
        assert!(!session.is_done());

        let keep_alive = session.finish_response();
        assert!(!keep_alive); // HTTP/0.9 never keeps alive
        assert!(session.is_done());
    }

    #[test]
    fn version_delegates_to_codec() {
        let session = new_session();
        assert_eq!(session.version(), Version::Http09);
    }

    #[test]
    fn session_http10_close_by_default() {
        let mut session = Session::new(HttpCodec::Http10(
            crate::net::http::codec::v1_0::Http10Codec::new(),
        ));
        let buf = b"GET /test HTTP/1.0\r\nHost: test\r\n\r\n";
        session.try_decode_request(buf, 0).unwrap();
        session.begin_response();
        let keep_alive = session.finish_response();
        assert!(!keep_alive);
        assert!(session.is_done());
    }

    #[test]
    fn session_http11_keep_alive_by_default() {
        let mut session = Session::new(HttpCodec::Http11(
            crate::net::http::codec::v1_1::Http11Codec::new(),
        ));
        let buf = b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n";
        let result = session.try_decode_request(buf, 0).unwrap();
        assert!(result.is_some());
        session.begin_response();
        let keep_alive = session.finish_response();
        assert!(keep_alive);
        assert!(!session.is_done());
    }

    #[test]
    fn session_http11_connection_close() {
        let mut session = Session::new(HttpCodec::Http11(
            crate::net::http::codec::v1_1::Http11Codec::new(),
        ));
        let buf = b"GET /test HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
        let result = session.try_decode_request(buf, 0).unwrap();
        assert!(result.is_some());
        session.begin_response();
        let keep_alive = session.finish_response();
        assert!(!keep_alive);
        assert!(session.is_done());
    }

    #[test]
    fn session_http10_keep_alive_header() {
        let mut session = Session::new(HttpCodec::Http10(
            crate::net::http::codec::v1_0::Http10Codec::new(),
        ));
        let buf = b"GET /test HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
        let result = session.try_decode_request(buf, 0).unwrap();
        assert!(result.is_some());
        session.begin_response();
        let keep_alive = session.finish_response();
        assert!(keep_alive);
        assert!(!session.is_done());
    }

    #[test]
    fn session_awaiting_next_to_awaiting_request() {
        let mut session = Session::new(HttpCodec::Http11(
            crate::net::http::codec::v1_1::Http11Codec::new(),
        ));
        let buf = b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n";
        session.try_decode_request(buf, 0).unwrap();
        session.begin_response();
        let keep_alive = session.finish_response();
        assert!(keep_alive);
        session.prepare_next_request();
        assert!(!session.is_done());
    }
}
