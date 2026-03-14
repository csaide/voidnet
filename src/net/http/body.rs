use crate::net::http::{HttpError, buffer::ReadBuffer, error::ParseError, request::BodyFraming};
use crate::net::socket::TcpStream;

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
            if let Some(pos) = buffered.iter().position(|&b| b == b'\n') {
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
}
