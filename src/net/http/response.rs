use crate::net::http::{HttpError, buffer::WriteBuffer, session::Session};
use crate::net::socket::TcpStream;

/// Writes HTTP response data to the client.
///
/// For HTTP/0.9, writes raw body bytes directly (no status line or headers).
/// Future HTTP versions will add `write_status()`, `write_header()`, etc.
pub struct ResponseWriter<'conn> {
    write_buf: &'conn mut WriteBuffer,
    stream: &'conn TcpStream,
    session: &'conn mut Session,
    finished: bool,
}

impl<'conn> ResponseWriter<'conn> {
    pub(crate) fn new(
        write_buf: &'conn mut WriteBuffer,
        stream: &'conn TcpStream,
        session: &'conn mut Session,
    ) -> Self {
        session.begin_response();
        Self {
            write_buf,
            stream,
            session,
            finished: false,
        }
    }

    /// Write body bytes to the response.
    ///
    /// For HTTP/0.9, this writes raw bytes. Data is buffered in the
    /// WriteBuffer and flushed to the TcpStream as needed.
    pub async fn write_body(&mut self, data: &[u8]) -> Result<usize, HttpError> {
        let mut total_written = 0;
        while total_written < data.len() {
            // Fill the write buffer
            let n = self.write_buf.write(&data[total_written..]);
            total_written += n;

            // If write buffer is full or we've written all data, flush
            if self.write_buf.remaining_capacity() == 0 || total_written == data.len() {
                self.flush().await?;
            }
        }
        Ok(total_written)
    }

    /// Signal that the response is complete. Flushes any remaining buffered data.
    pub async fn finish(mut self) -> Result<(), HttpError> {
        self.flush().await?;
        self.session.finish_response();
        self.finished = true;
        Ok(())
    }

    /// Flush the write buffer to the TcpStream.
    async fn flush(&mut self) -> Result<(), HttpError> {
        while !self.write_buf.is_empty() {
            let pending = self.write_buf.pending();
            let n = self.stream.write(pending).await.map_err(HttpError::Tcp)?;
            self.write_buf.advance(n);
        }
        Ok(())
    }
}

impl Drop for ResponseWriter<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // If the writer is dropped without finish(), still transition
            // the session so the connection can proceed or close.
            self.session.finish_response();
        }
    }
}
