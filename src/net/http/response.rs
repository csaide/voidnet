use std::borrow::Cow;

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

/// Max hex digits for a usize (2 per byte) plus `\r\n`.
const HEX_BUF_LEN: usize = std::mem::size_of::<usize>() * 2 + 2;

/// Format `n` as lowercase hex followed by `\r\n` into `buf`.
/// Returns the number of bytes written.
fn write_hex_usize(n: usize, buf: &mut [u8; HEX_BUF_LEN]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        buf[1] = b'\r';
        buf[2] = b'\n';
        return 3;
    }
    let mut pos = 0;
    let mut val = n;
    while val > 0 {
        let digit = (val & 0xf) as u8;
        buf[pos] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        pos += 1;
        val >>= 4;
    }
    buf[..pos].reverse();
    buf[pos] = b'\r';
    buf[pos + 1] = b'\n';
    pos + 2
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
    status_reason: Cow<'static, str>,
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
            status_reason: Cow::Borrowed("OK"),
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
        self.status_reason = match reason {
            "OK" => Cow::Borrowed("OK"),
            "Created" => Cow::Borrowed("Created"),
            "No Content" => Cow::Borrowed("No Content"),
            "Moved Permanently" => Cow::Borrowed("Moved Permanently"),
            "Found" => Cow::Borrowed("Found"),
            "Not Modified" => Cow::Borrowed("Not Modified"),
            "Bad Request" => Cow::Borrowed("Bad Request"),
            "Unauthorized" => Cow::Borrowed("Unauthorized"),
            "Forbidden" => Cow::Borrowed("Forbidden"),
            "Not Found" => Cow::Borrowed("Not Found"),
            "Method Not Allowed" => Cow::Borrowed("Method Not Allowed"),
            "Internal Server Error" => Cow::Borrowed("Internal Server Error"),
            "Service Unavailable" => Cow::Borrowed("Service Unavailable"),
            other => Cow::Owned(other.to_string()),
        };
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
            // Write chunk header: hex size + \r\n (stack-formatted, no alloc).
            let mut hex_buf = [0u8; HEX_BUF_LEN];
            let n = write_hex_usize(data.len(), &mut hex_buf);
            self.write_all(&hex_buf[..n]).await?;
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

        // Status line — direct writes, no String allocation.
        let version_bytes: &[u8] = match self.version {
            Version::Http10 => b"HTTP/1.0 ",
            Version::Http11 => b"HTTP/1.1 ",
            Version::Http09 => unreachable!(),
        };
        self.write_all(version_bytes).await?;
        let code = self.status_code;
        self.write_all(&[
            b'0' + (code / 100) as u8,
            b'0' + ((code / 10) % 10) as u8,
            b'0' + (code % 10) as u8,
        ])
        .await?;
        self.write_all(b" ").await?;
        // Temporarily take status_reason to avoid borrow conflict across await.
        let reason = std::mem::replace(&mut self.status_reason, Cow::Borrowed(""));
        self.write_all(reason.as_bytes()).await?;
        self.status_reason = reason;
        self.write_all(b"\r\n").await?;

        // Check if handler set Content-Length.
        let has_content_length = self
            .response_headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));

        // Headers — direct writes per header, no format_header() allocation.
        let headers = std::mem::take(&mut self.response_headers);
        for (name, value) in &headers {
            self.write_all(name.as_bytes()).await?;
            self.write_all(b": ").await?;
            self.write_all(value.as_bytes()).await?;
            self.write_all(b"\r\n").await?;
        }
        self.response_headers = headers;

        // Auto-inject Transfer-Encoding for HTTP/1.1 without Content-Length.
        // Written after user headers (RFC 9112 does not mandate header ordering).
        if !has_content_length && self.version == Version::Http11 {
            self.chunked = true;
            self.write_all(b"Transfer-Encoding: chunked\r\n").await?;
        }

        // End of headers.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_state_initial() {
        let state = ResponseState::Headers;
        assert!(matches!(state, ResponseState::Headers));
    }

    #[test]
    fn write_hex_zero() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(0, &mut buf);
        assert_eq!(&buf[..n], b"0\r\n");
    }

    #[test]
    fn write_hex_small() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(255, &mut buf);
        assert_eq!(&buf[..n], b"ff\r\n");
    }

    #[test]
    fn write_hex_large() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(0x1a2b3c, &mut buf);
        assert_eq!(&buf[..n], b"1a2b3c\r\n");
    }

    #[test]
    fn write_hex_one() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(1, &mut buf);
        assert_eq!(&buf[..n], b"1\r\n");
    }

    #[test]
    fn write_hex_sixteen() {
        let mut buf = [0u8; HEX_BUF_LEN];
        let n = write_hex_usize(16, &mut buf);
        assert_eq!(&buf[..n], b"10\r\n");
    }

    #[test]
    fn cow_status_common_phrase_is_borrowed() {
        let cow: Cow<'static, str> = match "OK" {
            "OK" => Cow::Borrowed("OK"),
            other => Cow::Owned(other.to_string()),
        };
        assert!(matches!(cow, Cow::Borrowed(_)));
    }

    #[test]
    fn cow_status_custom_phrase_is_owned() {
        let reason = "Custom Reason";
        let cow: Cow<'static, str> = match reason {
            "OK" => Cow::Borrowed("OK"),
            other => Cow::Owned(other.to_string()),
        };
        assert!(matches!(cow, Cow::Owned(_)));
        assert_eq!(&*cow, "Custom Reason");
    }
}
