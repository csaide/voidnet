use crate::net::http::{
    HttpError,
    buffer::{ReadBuffer, WriteBuffer},
    error::ParseError,
    request::{Method, Request},
    response::ResponseWriter,
    session::Session,
};
use crate::net::socket::TcpStream;

const DEFAULT_BUF_CAPACITY: usize = 8192; // 8 KiB

/// An HTTP connection wrapping a TCP stream.
///
/// Owns the TcpStream, read/write buffers, and session state machine.
/// Provides the low-level stream API for processing HTTP requests.
pub struct HttpConnection {
    stream: TcpStream,
    pub(crate) read_buf: ReadBuffer,
    write_buf: WriteBuffer,
    pub(crate) session: Session,
}

impl HttpConnection {
    /// Create a new HttpConnection wrapping the given TcpStream.
    pub(crate) fn new(stream: TcpStream, session: Session) -> Self {
        Self {
            stream,
            read_buf: ReadBuffer::new(DEFAULT_BUF_CAPACITY),
            write_buf: WriteBuffer::new(DEFAULT_BUF_CAPACITY),
            session,
        }
    }

    /// Wait for the next HTTP request.
    ///
    /// Returns `Ok(Some(request))` when a request is ready,
    /// `Ok(None)` when the connection is done (no more requests),
    /// or `Err` on parse/TCP errors.
    pub async fn next_request(&mut self) -> Result<Option<Request>, HttpError> {
        if self.session.is_done() {
            return Ok(None);
        }

        loop {
            // Try to decode from existing buffer data
            let buf = self.read_buf.unconsumed();
            let buf_offset = self.read_buf.start();
            match self.session.try_decode_request(buf, buf_offset)? {
                Some((req, consumed)) => {
                    self.read_buf.consume(consumed);
                    return Ok(Some(req));
                }
                None => {
                    // Need more data — compact if needed, then read
                    if self.read_buf.remaining_capacity() == 0 {
                        self.read_buf.compact();
                        if self.read_buf.remaining_capacity() == 0 {
                            // Buffer is genuinely full with unconsumed data — request too large
                            return Err(HttpError::Parse(ParseError::RequestTooLarge));
                        }
                    }

                    // Read from TcpStream into read buffer
                    let buf_slice = self.read_buf.writable_slice();
                    let n = self.stream.read(buf_slice).await.map_err(HttpError::Tcp)?;
                    if n == 0 {
                        // EOF — connection closed by remote
                        return Ok(None);
                    }
                    self.read_buf.advance_end(n);
                }
            }
        }
    }

    /// Begin writing a response for the current request.
    ///
    /// The returned `ResponseWriter` borrows the connection's write buffer
    /// and TcpStream. When dropped or finished, it transitions the session.
    pub fn respond(&mut self, req: &Request) -> ResponseWriter<'_> {
        let is_head = req.method == Method::Head;
        let version = self.session.version();
        ResponseWriter::new(
            &mut self.write_buf,
            &mut self.read_buf,
            &self.stream,
            &mut self.session,
            version,
            is_head,
            req.body_framing,
            req.expect_continue,
        )
    }

    /// Prepare for the next request on a keep-alive connection.
    pub(crate) fn prepare_next(&mut self) {
        self.read_buf.compact();
        self.session.prepare_next_request();
    }

    /// Resolve a request's path offsets against the read buffer.
    pub fn request_path(&self, req: &Request) -> &[u8] {
        self.read_buf.slice_at(req.path_start(), req.path_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http::codec::parse::ConnectionDirective;
    use crate::net::http::codec::{HttpCodec, v1_1::Http11Codec};
    use crate::net::http::request::BodyFraming;
    use crate::net::http::{Method, Version};

    use crate::net::handler::tcp::TcpHandler;
    use crate::net::handler::tcp::tcb::ConnectionId;
    use crate::net::socket::LocalQueue;
    use crate::net::wire::ip::{IpAddress, Ipv4Address};
    use std::cell::UnsafeCell;
    use std::rc::Rc;

    fn new_test_connection() -> HttpConnection {
        let handler = Rc::new(UnsafeCell::new(TcpHandler::new(false, false)));
        let conn_id = ConnectionId {
            local_addr: IpAddress::V4(Ipv4Address::unspecified()),
            local_port: 0,
            remote_addr: IpAddress::V4(Ipv4Address::unspecified()),
            remote_port: 0,
        };
        let event_queue = LocalQueue::new(16);
        let stream = TcpStream::from_accepted_for_test(0, conn_id, event_queue, handler);
        HttpConnection::new(stream, Session::http09())
    }

    fn new_test_connection_http11() -> HttpConnection {
        let handler = Rc::new(UnsafeCell::new(TcpHandler::new(false, false)));
        let conn_id = ConnectionId {
            local_addr: IpAddress::V4(Ipv4Address::unspecified()),
            local_port: 0,
            remote_addr: IpAddress::V4(Ipv4Address::unspecified()),
            remote_port: 0,
        };
        let event_queue = LocalQueue::new(16);
        let stream = TcpStream::from_accepted_for_test(0, conn_id, event_queue, handler);
        HttpConnection::new(stream, Session::new(HttpCodec::Http11(Http11Codec::new())))
    }

    #[test]
    fn request_path_resolution() {
        let mut conn = new_test_connection();
        // Simulate data in the read buffer
        conn.read_buf.append(b"GET /hello\r\n");
        let req = Request::new(
            Method::Get,
            4,
            10,
            Version::Http09,
            Vec::new(),
            BodyFraming::None,
            false,
            ConnectionDirective::None,
        );
        assert_eq!(conn.request_path(&req), b"/hello");
    }

    #[test]
    fn request_path_root() {
        let mut conn = new_test_connection();
        conn.read_buf.append(b"GET /\r\n");
        // path_start=4, path_end=5 => b"/"
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
        assert_eq!(conn.request_path(&req), b"/");
    }

    #[test]
    fn request_path_with_offset_after_consume() {
        let mut conn = new_test_connection();
        // Append a first request worth of bytes then consume it, leaving buffer
        // start > 0. The path offsets must be absolute (not relative to start).
        conn.read_buf.append(b"GET /first\r\n");
        conn.read_buf.consume(12); // consume "GET /first\r\n"
        conn.read_buf.append(b"GET /second\r\n");
        // "GET /second\r\n" starts at absolute offset 12 in the buffer.
        // path_start = 12+4 = 16, path_end = 16+7 = 23
        let req = Request::new(
            Method::Get,
            16,
            23,
            Version::Http09,
            Vec::new(),
            BodyFraming::None,
            false,
            ConnectionDirective::None,
        );
        assert_eq!(conn.request_path(&req), b"/second");
    }

    // --- Session state inspection via pub(crate) field ---

    #[test]
    fn initial_session_not_done() {
        let conn = new_test_connection();
        assert!(!conn.session.is_done());
    }

    #[test]
    fn initial_session_version_http09() {
        let conn = new_test_connection();
        assert_eq!(conn.session.version(), Version::Http09);
    }

    #[test]
    fn initial_session_version_http11() {
        let conn = new_test_connection_http11();
        assert_eq!(conn.session.version(), Version::Http11);
    }

    // --- ReadBuffer state after construction ---

    #[test]
    fn read_buf_initially_empty() {
        let conn = new_test_connection();
        assert_eq!(conn.read_buf.unconsumed().len(), 0);
    }

    #[test]
    fn read_buf_initial_remaining_capacity() {
        let conn = new_test_connection();
        // DEFAULT_BUF_CAPACITY is 8192
        assert_eq!(conn.read_buf.remaining_capacity(), 8192);
    }

    #[test]
    fn read_buf_start_initially_zero() {
        let conn = new_test_connection();
        assert_eq!(conn.read_buf.start(), 0);
    }

    #[test]
    fn read_buf_append_updates_state() {
        let mut conn = new_test_connection();
        let data = b"GET /test\r\n";
        let written = conn.read_buf.append(data);
        assert_eq!(written, data.len());
        assert_eq!(conn.read_buf.unconsumed(), data);
        assert_eq!(conn.read_buf.remaining_capacity(), 8192 - data.len());
    }

    // --- prepare_next() compacts buffer and resets session ---

    // --- Request decoding from pre-filled buffers ---

    #[test]
    fn decode_http11_get_from_prefilled_buffer() {
        let mut conn = new_test_connection_http11();
        let req_bytes = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        conn.read_buf.append(req_bytes);

        let buf = conn.read_buf.unconsumed();
        let offset = conn.read_buf.start();
        let result = conn.session.try_decode_request(buf, offset).unwrap();
        let (req, consumed) = result.unwrap();

        assert_eq!(req.method, Method::Get);
        assert_eq!(req.version, Version::Http11);
        assert_eq!(req.body_framing, BodyFraming::None);
        assert_eq!(consumed, req_bytes.len());
    }

    #[test]
    fn decode_http11_post_with_content_length() {
        let mut conn = new_test_connection_http11();
        let req_bytes = b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n";
        conn.read_buf.append(req_bytes);

        let buf = conn.read_buf.unconsumed();
        let offset = conn.read_buf.start();
        let result = conn.session.try_decode_request(buf, offset).unwrap();
        let (req, _consumed) = result.unwrap();

        assert_eq!(req.method, Method::Post);
        assert_eq!(req.body_framing, BodyFraming::ContentLength(5));
    }

    #[test]
    fn decode_http11_incomplete_returns_none() {
        let mut conn = new_test_connection_http11();
        // Missing final \r\n\r\n
        conn.read_buf
            .append(b"GET /hello HTTP/1.1\r\nHost: example.com\r\n");

        let buf = conn.read_buf.unconsumed();
        let offset = conn.read_buf.start();
        let result = conn.session.try_decode_request(buf, offset).unwrap();
        assert!(result.is_none(), "expected None for incomplete request");
    }

    #[test]
    fn decode_http11_path_resolution_after_decode() {
        let mut conn = new_test_connection_http11();
        let req_bytes = b"GET /test/path HTTP/1.1\r\nHost: localhost\r\n\r\n";
        conn.read_buf.append(req_bytes);

        let buf = conn.read_buf.unconsumed();
        let offset = conn.read_buf.start();
        let result = conn.session.try_decode_request(buf, offset).unwrap();
        let (req, _consumed) = result.unwrap();

        assert_eq!(conn.request_path(&req), b"/test/path");
    }

    #[test]
    fn decode_http11_missing_host_returns_error() {
        let mut conn = new_test_connection_http11();
        conn.read_buf
            .append(b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");

        let buf = conn.read_buf.unconsumed();
        let offset = conn.read_buf.start();
        let result = conn.session.try_decode_request(buf, offset);
        assert!(result.is_err(), "expected error for missing Host header");
    }

    #[test]
    fn prepare_next_compacts_buffer() {
        let mut conn = new_test_connection_http11();
        // Fill the buffer with a complete HTTP/1.1 request and decode it so the
        // session advances through the full lifecycle to AwaitingNext.
        let req_bytes = b"GET /keep HTTP/1.1\r\nHost: localhost\r\n\r\n";
        conn.read_buf.append(req_bytes);

        // Drive the session manually through the states using pub(crate) access.
        let buf = conn.read_buf.unconsumed();
        let offset = conn.read_buf.start();
        let result = conn.session.try_decode_request(buf, offset).unwrap();
        let (_req, consumed) = result.unwrap();
        conn.read_buf.consume(consumed);

        conn.session.begin_response();
        let keep_alive = conn.session.finish_response();
        assert!(keep_alive, "HTTP/1.1 should keep alive by default");

        // Buffer start is now > 0 after consuming the request bytes.
        assert!(conn.read_buf.start() > 0);

        // prepare_next() compacts the buffer and resets session to AwaitingRequest.
        conn.prepare_next();

        // After compact, start resets to 0.
        assert_eq!(conn.read_buf.start(), 0);
        // Session must be ready for the next request.
        assert!(!conn.session.is_done());
    }
}
