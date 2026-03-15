use crate::net::http::{
    HttpError,
    body::BodyReader,
    buffer::{ReadBuffer, WriteBuffer},
    request::{BodyFraming, Version},
    session::Session,
};
use crate::net::socket::TcpStream;

/// Response state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ResponseState {
    /// Status and headers not yet sent.
    Headers,
    /// Headers flushed, writing body.
    Body,
    /// Response complete.
    Finished,
}

/// Writes HTTP response data to the client.
pub struct ResponseWriter<'conn> {
    write_buf: &'conn mut WriteBuffer,
    read_buf: &'conn mut ReadBuffer,
    stream: &'conn TcpStream,
    session: &'conn mut Session,
    finished: bool,
    version: Version,
    state: ResponseState,
    status_code: u16,
    status_reason: String,
    response_headers: Vec<(String, String)>,
    is_head: bool,
    chunked: bool,
    body_framing: BodyFraming,
    expect_continue: bool,
    body_taken: bool,
}

impl<'conn> ResponseWriter<'conn> {
    pub(crate) fn new(
        write_buf: &'conn mut WriteBuffer,
        read_buf: &'conn mut ReadBuffer,
        stream: &'conn TcpStream,
        session: &'conn mut Session,
        version: Version,
        is_head: bool,
        body_framing: BodyFraming,
        expect_continue: bool,
    ) -> Self {
        session.begin_response();
        Self {
            write_buf,
            read_buf,
            stream,
            session,
            finished: false,
            version,
            state: ResponseState::Headers,
            status_code: 200,
            status_reason: String::from("OK"),
            response_headers: Vec::new(),
            is_head,
            chunked: false,
            body_framing,
            expect_continue,
            body_taken: false,
        }
    }

    /// Set the response status code and reason phrase.
    /// Defaults to 200 OK if not called.
    /// No-op for HTTP/0.9.
    pub fn set_status(&mut self, code: u16, reason: &str) {
        if self.version == Version::Http09 {
            return;
        }
        self.status_code = code;
        self.status_reason = reason.to_string();
    }

    /// Add a response header. Can be called multiple times.
    /// No-op for HTTP/0.9.
    pub fn add_header(&mut self, name: &str, value: &str) {
        if self.version == Version::Http09 {
            return;
        }
        self.response_headers
            .push((name.to_string(), value.to_string()));
    }

    /// Access the request body reader. Must be called before write_body().
    /// Can only be called once per response. The returned BodyReader must be
    /// fully consumed and dropped before calling set_status/add_header/write_body.
    pub fn body(&mut self) -> BodyReader<'_> {
        debug_assert!(!self.body_taken, "body() called twice");
        debug_assert_eq!(
            self.state,
            ResponseState::Headers,
            "body() called after headers sent"
        );
        self.body_taken = true;
        BodyReader::new(
            self.stream,
            self.read_buf,
            self.body_framing,
            self.expect_continue,
        )
    }

    /// Write body bytes to the response.
    ///
    /// On first call for HTTP/1.x, flushes the status line and headers.
    /// For HEAD requests, body bytes are suppressed but headers are still sent.
    pub async fn write_body(&mut self, data: &[u8]) -> Result<usize, HttpError> {
        if self.state == ResponseState::Headers && self.version != Version::Http09 {
            self.flush_headers().await?;
        }

        // HEAD responses: suppress body but still "write" for Content-Length accounting
        if self.is_head {
            return Ok(data.len());
        }

        if self.chunked {
            // Write chunk header: hex size + \r\n
            let chunk_header = format!("{:x}\r\n", data.len());
            self.write_all(chunk_header.as_bytes()).await?;
            self.write_all(data).await?;
            self.write_all(b"\r\n").await?;
            Ok(data.len())
        } else {
            self.write_all(data).await
        }
    }

    /// Signal that the response is complete. Flushes any remaining buffered data.
    pub async fn finish(mut self) -> Result<(), HttpError> {
        if self.state == ResponseState::Headers && self.version != Version::Http09 {
            // Headers-only response (e.g., 204, 304)
            if !self
                .response_headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            {
                self.response_headers
                    .push(("Content-Length".to_string(), "0".to_string()));
            }
            self.flush_headers().await?;
        }

        if self.chunked {
            // Send final chunk: 0\r\n\r\n
            self.write_all(b"0\r\n\r\n").await?;
        }

        self.flush().await?;
        self.session.finish_response();
        self.finished = true;
        Ok(())
    }

    /// Flush headers to the wire. Called once on first write_body or finish.
    async fn flush_headers(&mut self) -> Result<(), HttpError> {
        debug_assert_eq!(self.state, ResponseState::Headers);

        let status_line = format_status_line(self.status_code, &self.status_reason, self.version);
        self.write_all(status_line.as_bytes()).await?;

        // Check if handler set Content-Length
        let has_content_length = self
            .response_headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));

        // If no Content-Length and HTTP/1.1, use chunked
        if !has_content_length && self.version == Version::Http11 {
            self.chunked = true;
            self.response_headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
        }

        let headers = std::mem::take(&mut self.response_headers);
        for (name, value) in &headers {
            let header = format_header(name, value);
            self.write_all(header.as_bytes()).await?;
        }
        self.response_headers = headers;

        // End of headers
        self.write_all(b"\r\n").await?;
        self.state = ResponseState::Body;
        Ok(())
    }

    /// Write all bytes to the write buffer, flushing as needed.
    async fn write_all(&mut self, data: &[u8]) -> Result<usize, HttpError> {
        let mut total_written = 0;
        while total_written < data.len() {
            let n = self.write_buf.write(&data[total_written..]);
            total_written += n;

            if self.write_buf.remaining_capacity() == 0 || total_written == data.len() {
                self.flush().await?;
            }
        }
        Ok(total_written)
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
            self.session.finish_response();
        }
    }
}

fn format_status_line(code: u16, reason: &str, version: Version) -> String {
    format!("{} {} {}\r\n", version, code, reason)
}

fn format_header(name: &str, value: &str) -> String {
    format!("{}: {}\r\n", name, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_state_initial() {
        let state = ResponseState::Headers;
        assert!(matches!(state, ResponseState::Headers));
    }

    #[test]
    fn format_status_line_http11() {
        let line = format_status_line(200, "OK", Version::Http11);
        assert_eq!(line, "HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn format_status_line_http10() {
        let line = format_status_line(404, "Not Found", Version::Http10);
        assert_eq!(line, "HTTP/1.0 404 Not Found\r\n");
    }

    #[test]
    fn format_header_line() {
        let line = format_header("Content-Type", "text/html");
        assert_eq!(line, "Content-Type: text/html\r\n");
    }
}
