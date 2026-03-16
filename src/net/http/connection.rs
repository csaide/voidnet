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
}
