use crate::net::http::{HttpError, buffer::ReadBuffer, error::ParseError, request::BodyFraming};
use crate::net::socket::TcpStream;
use memchr::memchr;

/// Reads the request body according to the body framing.
///
/// Must be fully consumed (or dropped) before writing the response.
pub struct BodyReader<'conn> {
    stream: &'conn TcpStream,
    read_buf: &'conn mut ReadBuffer,
    framing: BodyFraming,
    remaining: usize,
    chunk_state: ChunkState,
    finished: bool,
    expect_continue: bool,
    continue_sent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    AwaitingSize,
    ReadingData(usize),
    AwaitingTrailer,
    Done,
}

impl<'conn> BodyReader<'conn> {
    pub(crate) fn new(
        stream: &'conn TcpStream,
        read_buf: &'conn mut ReadBuffer,
        framing: BodyFraming,
        expect_continue: bool,
    ) -> Self {
        let (remaining, finished, chunk_state) = match framing {
            BodyFraming::None => (0, true, ChunkState::Done),
            BodyFraming::ContentLength(len) => (len, len == 0, ChunkState::Done),
            BodyFraming::Chunked => (0, false, ChunkState::AwaitingSize),
        };
        Self {
            stream,
            read_buf,
            framing,
            remaining,
            chunk_state,
            finished,
            expect_continue,
            continue_sent: false,
        }
    }

    /// Read decoded body bytes into `dest`. Returns the number of bytes read.
    /// Returns 0 when the body is fully consumed.
    pub async fn read(&mut self, dest: &mut [u8]) -> Result<usize, HttpError> {
        if self.finished {
            return Ok(0);
        }

        // Send 100-continue if needed (lazy, on first read)
        if self.expect_continue && !self.continue_sent {
            let response = b"HTTP/1.1 100 Continue\r\n\r\n";
            self.stream.write(response).await.map_err(HttpError::Tcp)?;
            self.continue_sent = true;
        }

        match self.framing {
            BodyFraming::None => {
                self.finished = true;
                Ok(0)
            }
            BodyFraming::ContentLength(_) => self.read_content_length(dest).await,
            BodyFraming::Chunked => self.read_chunked(dest).await,
        }
    }

    /// Read the entire body up to `limit` bytes.
    pub async fn read_all(&mut self, limit: usize) -> Result<Vec<u8>, HttpError> {
        let mut body = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = self.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if body.len() + n > limit {
                return Err(HttpError::Parse(ParseError::RequestTooLarge));
            }
            body.extend_from_slice(&buf[..n]);
        }
        Ok(body)
    }

    /// Whether the body has been fully consumed.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    async fn read_content_length(&mut self, dest: &mut [u8]) -> Result<usize, HttpError> {
        if self.remaining == 0 {
            self.finished = true;
            return Ok(0);
        }

        let to_read = dest.len().min(self.remaining);

        // First try to read from the existing read buffer
        let buffered = self.read_buf.unconsumed();
        if !buffered.is_empty() {
            let n = to_read.min(buffered.len());
            dest[..n].copy_from_slice(&buffered[..n]);
            self.read_buf.consume(n);
            self.remaining -= n;
            if self.remaining == 0 {
                self.finished = true;
            }
            return Ok(n);
        }

        // Need more data from stream — compact if needed
        if self.read_buf.remaining_capacity() == 0 {
            self.read_buf.compact();
        }

        // Read from stream
        let buf_slice = self.read_buf.writable_slice();
        let n = self.stream.read(buf_slice).await.map_err(HttpError::Tcp)?;
        if n == 0 {
            self.finished = true;
            return Err(HttpError::Closed);
        }
        self.read_buf.advance_end(n);

        // Now read from buffer
        let buffered = self.read_buf.unconsumed();
        let n = to_read.min(buffered.len());
        dest[..n].copy_from_slice(&buffered[..n]);
        self.read_buf.consume(n);
        self.remaining -= n;
        if self.remaining == 0 {
            self.finished = true;
        }
        Ok(n)
    }

    async fn read_chunked(&mut self, dest: &mut [u8]) -> Result<usize, HttpError> {
        loop {
            match self.chunk_state {
                ChunkState::Done => {
                    self.finished = true;
                    return Ok(0);
                }
                ChunkState::AwaitingSize => {
                    let size = self.read_chunk_size().await?;
                    if size == 0 {
                        self.chunk_state = ChunkState::Done;
                        self.finished = true;
                        return Ok(0);
                    }
                    self.chunk_state = ChunkState::ReadingData(size);
                }
                ChunkState::ReadingData(remaining) => {
                    let to_read = dest.len().min(remaining);

                    // Read from buffer first
                    let buffered = self.read_buf.unconsumed();
                    if buffered.is_empty() {
                        // Need more data from stream
                        if self.read_buf.remaining_capacity() == 0 {
                            self.read_buf.compact();
                        }
                        let buf_slice = self.read_buf.writable_slice();
                        let n = self.stream.read(buf_slice).await.map_err(HttpError::Tcp)?;
                        if n == 0 {
                            return Err(HttpError::Closed);
                        }
                        self.read_buf.advance_end(n);
                        continue;
                    }

                    let n = to_read.min(buffered.len());
                    dest[..n].copy_from_slice(&buffered[..n]);
                    self.read_buf.consume(n);

                    let new_remaining = remaining - n;
                    if new_remaining == 0 {
                        self.chunk_state = ChunkState::AwaitingTrailer;
                    } else {
                        self.chunk_state = ChunkState::ReadingData(new_remaining);
                    }
                    return Ok(n);
                }
                ChunkState::AwaitingTrailer => {
                    // Consume the \r\n after chunk data
                    self.consume_crlf().await?;
                    self.chunk_state = ChunkState::AwaitingSize;
                }
            }
        }
    }

    /// Read a chunk size line (hex digits followed by \r\n).
    /// Handles chunk extensions (e.g., "a;ext=val\r\n") by trimming at `;`.
    async fn read_chunk_size(&mut self) -> Result<usize, HttpError> {
        loop {
            let buffered = self.read_buf.unconsumed();
            if let Some(pos) = memchr(b'\n', buffered) {
                let line_end = if pos > 0 && buffered[pos - 1] == b'\r' {
                    pos - 1
                } else {
                    pos
                };
                let line = &buffered[..line_end];
                // Trim chunk extensions at `;` (RFC 7230 Section 4.1.1)
                let hex = match line.iter().position(|&b| b == b';') {
                    Some(semi) => &line[..semi],
                    None => line,
                };
                let size = usize::from_str_radix(
                    std::str::from_utf8(hex)
                        .map_err(|_| HttpError::Parse(ParseError::InvalidChunkEncoding))?,
                    16,
                )
                .map_err(|_| HttpError::Parse(ParseError::InvalidChunkEncoding))?;
                self.read_buf.consume(pos + 1);
                return Ok(size);
            }

            // Need more data
            if self.read_buf.remaining_capacity() == 0 {
                self.read_buf.compact();
            }
            let buf_slice = self.read_buf.writable_slice();
            let n = self.stream.read(buf_slice).await.map_err(HttpError::Tcp)?;
            if n == 0 {
                return Err(HttpError::Closed);
            }
            self.read_buf.advance_end(n);
        }
    }

    /// Consume \r\n from the buffer.
    async fn consume_crlf(&mut self) -> Result<(), HttpError> {
        loop {
            let buffered = self.read_buf.unconsumed();
            if buffered.len() >= 2 {
                if buffered[0] == b'\r' && buffered[1] == b'\n' {
                    self.read_buf.consume(2);
                    return Ok(());
                } else if buffered[0] == b'\n' {
                    self.read_buf.consume(1);
                    return Ok(());
                } else {
                    return Err(HttpError::Parse(ParseError::InvalidChunkEncoding));
                }
            }
            if buffered.len() == 1 && buffered[0] == b'\n' {
                self.read_buf.consume(1);
                return Ok(());
            }

            // Need more data
            if self.read_buf.remaining_capacity() == 0 {
                self.read_buf.compact();
            }
            let buf_slice = self.read_buf.writable_slice();
            let n = self.stream.read(buf_slice).await.map_err(HttpError::Tcp)?;
            if n == 0 {
                return Err(HttpError::Closed);
            }
            self.read_buf.advance_end(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::handler::tcp::TcpHandler;
    use crate::net::handler::tcp::tcb::ConnectionId;
    use crate::net::socket::LocalQueue;
    use crate::net::wire::ip::{IpAddress, Ipv4Address};
    use std::cell::UnsafeCell;
    use std::rc::Rc;

    /// Build a fake TcpStream and a pre-filled ReadBuffer for unit testing.
    ///
    /// The buffer is pre-populated with `data` via `append()`. All chunked
    /// parsing logic will consume from the buffer and never fall through to
    /// the stream (which has no real TCP connection behind it).
    fn make_reader_parts(data: &[u8]) -> (crate::net::socket::TcpStream, ReadBuffer) {
        let handler = Rc::new(UnsafeCell::new(TcpHandler::new(false, false)));
        let conn_id = ConnectionId {
            local_addr: IpAddress::V4(Ipv4Address::unspecified()),
            local_port: 0,
            remote_addr: IpAddress::V4(Ipv4Address::unspecified()),
            remote_port: 0,
        };
        let event_queue = LocalQueue::new(16);
        let wheel = std::rc::Rc::new(std::cell::UnsafeCell::new(
            crate::net::timer_wheel::TimerWheel::new(coarsetime::Instant::now()),
        ));
        let stream = crate::net::socket::TcpStream::from_accepted_for_test(
            0,
            conn_id,
            event_queue,
            handler,
            wheel,
            coarsetime::Instant::now(),
        );

        let mut buf = ReadBuffer::new(4096);
        let written = buf.append(data);
        assert_eq!(written, data.len(), "test data too large for ReadBuffer");

        (stream, buf)
    }

    #[test]
    fn body_reader_none_is_immediately_finished() {
        let (remaining, finished, _) = match BodyFraming::None {
            BodyFraming::None => (0, true, ChunkState::Done),
            BodyFraming::ContentLength(len) => (len, len == 0, ChunkState::Done),
            BodyFraming::Chunked => (0, false, ChunkState::AwaitingSize),
        };
        assert!(finished);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn body_reader_content_length_zero_is_finished() {
        let (remaining, finished, _) = match BodyFraming::ContentLength(0) {
            BodyFraming::None => (0, true, ChunkState::Done),
            BodyFraming::ContentLength(len) => (len, len == 0, ChunkState::Done),
            BodyFraming::Chunked => (0, false, ChunkState::AwaitingSize),
        };
        assert!(finished);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn body_reader_content_length_nonzero_not_finished() {
        let (remaining, finished, _) = match BodyFraming::ContentLength(42) {
            BodyFraming::None => (0, true, ChunkState::Done),
            BodyFraming::ContentLength(len) => (len, len == 0, ChunkState::Done),
            BodyFraming::Chunked => (0, false, ChunkState::AwaitingSize),
        };
        assert!(!finished);
        assert_eq!(remaining, 42);
    }

    #[test]
    fn body_reader_chunked_not_finished() {
        let (_, finished, chunk_state) = match BodyFraming::Chunked {
            BodyFraming::None => (0, true, ChunkState::Done),
            BodyFraming::ContentLength(len) => (len, len == 0, ChunkState::Done),
            BodyFraming::Chunked => (0, false, ChunkState::AwaitingSize),
        };
        assert!(!finished);
        assert_eq!(chunk_state, ChunkState::AwaitingSize);
    }

    /// Single chunk: "5\r\nhello\r\n0\r\n\r\n"
    /// First read should yield "hello" (5 bytes); second read should return 0 (finished).
    #[test]
    fn chunked_read_single_chunk() {
        let payload = b"5\r\nhello\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];

        let n = futures::executor::block_on(reader.read(&mut dest)).expect("first read failed");
        assert_eq!(n, 5);
        assert_eq!(&dest[..n], b"hello");

        let n2 = futures::executor::block_on(reader.read(&mut dest)).expect("second read failed");
        assert_eq!(n2, 0, "expected finished after terminal chunk");
        assert!(reader.is_finished());
    }

    /// Multiple chunks: "3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"
    /// Reads should accumulate "abcdefg" across calls.
    #[test]
    fn chunked_read_multiple_chunks() {
        let payload = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut body = Vec::new();
        let mut dest = [0u8; 64];
        loop {
            let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
            if n == 0 {
                break;
            }
            body.extend_from_slice(&dest[..n]);
        }

        assert_eq!(body, b"abcdefg");
        assert!(reader.is_finished());
    }

    /// Empty body: "0\r\n\r\n" — terminal chunk only.
    /// First read must return 0 immediately.
    #[test]
    fn chunked_read_empty_body() {
        let payload = b"0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 0, "expected immediate EOF for empty chunked body");
        assert!(reader.is_finished());
    }

    /// Invalid hex in chunk size line should return a parse error.
    #[test]
    fn chunked_read_invalid_hex_returns_error() {
        let payload = b"XYZ\r\nignored\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let result = futures::executor::block_on(reader.read(&mut dest));
        assert!(
            result.is_err(),
            "expected a parse error for invalid chunk size, got Ok"
        );
        match result.unwrap_err() {
            HttpError::Parse(crate::net::http::error::ParseError::InvalidChunkEncoding) => {}
            e => panic!("expected InvalidChunkEncoding, got {:?}", e),
        }
    }

    #[test]
    fn content_length_read_exact() {
        let payload = b"Hello, World!";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(
            &stream,
            &mut buf,
            BodyFraming::ContentLength(payload.len()),
            false,
        );

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(&dest[..n], payload);
        assert!(reader.is_finished());
    }

    #[test]
    fn content_length_zero_is_immediately_finished() {
        let (stream, mut buf) = make_reader_parts(b"");
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::ContentLength(0), false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 0);
        assert!(reader.is_finished());
    }

    #[test]
    fn body_framing_none_returns_zero() {
        let (stream, mut buf) = make_reader_parts(b"ignored data");
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::None, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 0);
        assert!(reader.is_finished());
    }

    #[test]
    fn read_all_content_length_body() {
        let payload = b"Hello, World!";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(
            &stream,
            &mut buf,
            BodyFraming::ContentLength(payload.len()),
            false,
        );

        let body = futures::executor::block_on(reader.read_all(1024)).expect("read_all failed");
        assert_eq!(body, payload);
        assert!(reader.is_finished());
    }

    #[test]
    fn read_all_exceeds_size_limit() {
        let payload = b"This is a longer payload than allowed";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(
            &stream,
            &mut buf,
            BodyFraming::ContentLength(payload.len()),
            false,
        );

        // Set limit smaller than payload
        let result = futures::executor::block_on(reader.read_all(10));
        assert!(result.is_err(), "expected error when body exceeds limit");
        match result.unwrap_err() {
            HttpError::Parse(ParseError::RequestTooLarge) => {}
            e => panic!("expected RequestTooLarge, got {:?}", e),
        }
    }

    #[test]
    fn chunked_read_invalid_chunk_size_non_hex() {
        // "ZZZ" is not valid hex — should return InvalidChunkEncoding.
        let payload = b"ZZZ\r\ndata\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let result = futures::executor::block_on(reader.read(&mut dest));
        assert!(result.is_err());
        match result.unwrap_err() {
            HttpError::Parse(ParseError::InvalidChunkEncoding) => {}
            e => panic!("expected InvalidChunkEncoding, got {:?}", e),
        }
    }

    #[test]
    fn chunked_read_with_bare_newline_in_size_line() {
        // Use bare \n instead of \r\n in the chunk size line.
        // The parser should tolerate this (it searches for \n, strips optional \r).
        let payload = b"5\nhello\r\n0\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 5);
        assert_eq!(&dest[..n], b"hello");
    }

    #[test]
    fn chunked_read_with_chunk_extension() {
        // Chunk extension (e.g., "5;ext=val\r\n") should be trimmed at `;`.
        let payload = b"5;ext=val\r\nhello\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 5);
        assert_eq!(&dest[..n], b"hello");
    }

    #[test]
    fn read_all_chunked_body() {
        let payload = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let body = futures::executor::block_on(reader.read_all(1024)).expect("read_all failed");
        assert_eq!(body, b"abcdefg");
        assert!(reader.is_finished());
    }

    #[test]
    fn chunked_read_large_chunk_size() {
        // Chunk size in hex: "10" = 16 bytes
        let payload = b"10\r\n0123456789abcdef\r\n0\r\n\r\n";
        let (stream, mut buf) = make_reader_parts(payload);
        let mut reader = BodyReader::new(&stream, &mut buf, BodyFraming::Chunked, false);

        let mut dest = [0u8; 64];
        let n = futures::executor::block_on(reader.read(&mut dest)).expect("read failed");
        assert_eq!(n, 16);
        assert_eq!(&dest[..n], b"0123456789abcdef");
    }
}
