# HTTP Layer Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement HTTP/0.9 request/response handling on top of VoidNet's TCP stack, with layered codec/session/connection architecture designed for HTTP/1.x and HTTP/2 extension.

**Architecture:** Three layers (codec → session → connection) with an HttpListener wrapping TcpListener. Request uses offset-based zero-copy design (no lifetime parameter). ReadBuffer/WriteBuffer provide terminal I/O buffering. HttpCodec uses enum dispatch (no dyn).

**Tech Stack:** Rust (edition 2024, 1.85+), VoidNet's existing TCP socket API (`TcpListener`, `TcpStream`), `LocalRuntime` async runtime.

**Constraints:**
- All work on `net-stack` branch only. Never merge.
- Run tests with plain `cargo test` (no `--features` or `--all-features`). Tests require root (configured via `.cargo/config.toml`).
- When committing, ask the user for the description and use their EXACT phrasing.

**Spec:** `docs/superpowers/specs/2026-03-12-http-layer-design.md`

---

## Chunk 1: Foundation Types (error, request, buffer)

### Task 1: Module scaffold + error types

**Files:**
- Create: `src/net/http/mod.rs`
- Create: `src/net/http/error.rs`
- Modify: `src/net/mod.rs` (add `pub mod http;`)

- [ ] **Step 1: Write tests for error types**

In `src/net/http/error.rs`, add tests at the bottom:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib net::http::error`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement error types**

Create `src/net/http/error.rs`:

```rust
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
```

Create `src/net/http/mod.rs`:

```rust
mod error;

pub use error::{HttpError, ParseError};
```

Modify `src/net/mod.rs` — add `pub mod http;` after `pub mod handler;`:

```rust
pub mod handler;
pub mod http;
pub mod socket;
pub mod wire;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib net::http::error`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

Ask user for commit description. Stage: `src/net/http/mod.rs`, `src/net/http/error.rs`, `src/net/mod.rs`.

---

### Task 2: Request types (Method, Version, Request)

**Files:**
- Create: `src/net/http/request.rs`
- Modify: `src/net/http/mod.rs` (add module + re-exports)

- [ ] **Step 1: Write tests for request types**

In `src/net/http/request.rs`, add tests at the bottom:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib net::http::request`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement request types**

Create `src/net/http/request.rs`:

```rust
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
```

Update `src/net/http/mod.rs`:

```rust
mod error;
mod request;

pub use error::{HttpError, ParseError};
pub use request::{Method, Request, Version};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib net::http::request`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

Ask user for commit description. Stage: `src/net/http/request.rs`, `src/net/http/mod.rs`.

---

### Task 3: ReadBuffer

**Files:**
- Create: `src/net/http/buffer.rs`
- Modify: `src/net/http/mod.rs` (add module)

- [ ] **Step 1: Write tests for ReadBuffer**

In `src/net/http/buffer.rs`, add tests at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_is_empty() {
        let buf = ReadBuffer::new(1024);
        assert_eq!(buf.unconsumed().len(), 0);
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    #[should_panic(expected = "must be a power of two")]
    fn non_power_of_two_panics() {
        ReadBuffer::new(1000);
    }

    #[test]
    fn append_and_read() {
        let mut buf = ReadBuffer::new(1024);
        let n = buf.append(b"GET /index.html\r\n");
        assert_eq!(n, 17);
        assert_eq!(buf.unconsumed(), b"GET /index.html\r\n");
    }

    #[test]
    fn consume_advances_start() {
        let mut buf = ReadBuffer::new(1024);
        buf.append(b"GET /index.html\r\n");
        buf.consume(4);
        assert_eq!(buf.unconsumed(), b"/index.html\r\n");
    }

    #[test]
    fn compact_shifts_data() {
        let mut buf = ReadBuffer::new(16);
        buf.append(b"12345678"); // fill half
        buf.consume(8); // consume all — start is now at 8
        buf.append(b"abcdefgh"); // fill remaining 8 bytes
        // start=8, end=16, no room to append more
        assert_eq!(buf.remaining_capacity(), 0);
        buf.compact();
        // after compact, data shifted to front
        assert_eq!(buf.unconsumed(), b"abcdefgh");
        assert_eq!(buf.remaining_capacity(), 8);
    }

    #[test]
    fn append_respects_capacity() {
        let mut buf = ReadBuffer::new(8);
        let n = buf.append(b"1234567890"); // 10 bytes into 8-byte buffer
        assert_eq!(n, 8);
        assert_eq!(buf.unconsumed(), b"12345678");
    }

    #[test]
    fn slice_at_returns_correct_range() {
        let mut buf = ReadBuffer::new(1024);
        buf.append(b"GET /path HTTP/1.1\r\n");
        assert_eq!(buf.slice_at(4, 9), b"/path");
    }

    #[test]
    fn consume_then_slice_at_uses_absolute_offsets() {
        let mut buf = ReadBuffer::new(1024);
        buf.append(b"GET /path\n");
        // slice_at uses offsets relative to buffer start (position 0),
        // not relative to unconsumed start
        assert_eq!(buf.slice_at(4, 9), b"/path");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib net::http::buffer`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement ReadBuffer**

Create `src/net/http/buffer.rs`:

```rust
/// Fixed-capacity read buffer for HTTP parsing.
///
/// Tracks unconsumed data via `start` and `end` positions. Parsers operate
/// on `unconsumed()` which returns a zero-copy `&[u8]` slice. The codec
/// stores offsets into this buffer; `slice_at()` resolves those offsets.
///
/// Capacity must be a power of two.
pub struct ReadBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl ReadBuffer {
    /// Create a new ReadBuffer with the given capacity.
    /// Capacity must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "ReadBuffer capacity must be a power of two"
        );
        Self {
            buf: vec![0u8; capacity],
            start: 0,
            end: 0,
        }
    }

    /// Returns a slice of the unconsumed data in the buffer.
    #[inline]
    pub fn unconsumed(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Returns a slice at the given absolute offsets into the buffer.
    ///
    /// These offsets are absolute positions in the buffer (not relative
    /// to `start`). Used by `Request` to resolve path offsets.
    #[inline]
    pub fn slice_at(&self, from: usize, to: usize) -> &[u8] {
        &self.buf[from..to]
    }

    /// Mark `n` bytes as consumed, advancing the start position.
    #[inline]
    pub fn consume(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.end);
    }

    /// Returns the number of bytes that can still be appended.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.end
    }

    /// Append bytes from a slice into the buffer. Returns the number
    /// of bytes actually written (may be less than `data.len()` if
    /// the buffer is nearly full).
    pub fn append(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.remaining_capacity());
        if to_write == 0 {
            return 0;
        }
        self.buf[self.end..self.end + to_write].copy_from_slice(&data[..to_write]);
        self.end += to_write;
        to_write
    }

    /// Shift unconsumed data to the front of the buffer, reclaiming
    /// space from consumed bytes.
    ///
    /// Only call when no outstanding offset-based reads are in progress
    /// (i.e., between request/response cycles).
    pub fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let len = self.end - self.start;
        self.buf.copy_within(self.start..self.end, 0);
        self.start = 0;
        self.end = len;
    }

    /// Returns the current start position (offset of first unconsumed byte).
    /// Used by the codec to compute absolute offsets for parsed fields.
    #[inline]
    pub fn start(&self) -> usize {
        self.start
    }
}

/// Fixed-capacity write buffer for HTTP response output.
///
/// Accumulates response bytes before flushing to the TcpStream.
/// Capacity must be a power of two.
pub struct WriteBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl WriteBuffer {
    /// Create a new WriteBuffer with the given capacity.
    /// Capacity must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "WriteBuffer capacity must be a power of two"
        );
        Self {
            buf: vec![0u8; capacity],
            start: 0,
            end: 0,
        }
    }

    /// Append bytes to the write buffer. Returns the number of bytes written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.buf.len() - self.end);
        if to_write == 0 {
            return 0;
        }
        self.buf[self.end..self.end + to_write].copy_from_slice(&data[..to_write]);
        self.end += to_write;
        to_write
    }

    /// Returns the buffered data ready to be flushed.
    pub fn pending(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Mark `n` bytes as flushed.
    pub fn advance(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.end);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Returns true if there is no pending data.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns the number of bytes that can still be written.
    pub fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.end
    }
}

#[cfg(test)]
mod tests {
    // ... (tests from Step 1 go here)
}
```

Update `src/net/http/mod.rs` to add the module:

```rust
mod buffer;
mod error;
mod request;

pub use error::{HttpError, ParseError};
pub use request::{Method, Request, Version};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib net::http::buffer`
Expected: All 8 tests PASS.

- [ ] **Step 5: Add WriteBuffer tests**

Add to the `tests` module in `buffer.rs`:

```rust
    #[test]
    fn write_buffer_new() {
        let buf = WriteBuffer::new(1024);
        assert!(buf.is_empty());
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn write_buffer_write_and_pending() {
        let mut buf = WriteBuffer::new(1024);
        let n = buf.write(b"Hello, World!");
        assert_eq!(n, 13);
        assert_eq!(buf.pending(), b"Hello, World!");
        assert!(!buf.is_empty());
    }

    #[test]
    fn write_buffer_advance() {
        let mut buf = WriteBuffer::new(1024);
        buf.write(b"Hello, World!");
        buf.advance(5);
        assert_eq!(buf.pending(), b", World!");
    }

    #[test]
    fn write_buffer_advance_all_resets() {
        let mut buf = WriteBuffer::new(1024);
        buf.write(b"Hello");
        buf.advance(5);
        assert!(buf.is_empty());
        // After full advance, positions reset so we can write again
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn write_buffer_respects_capacity() {
        let mut buf = WriteBuffer::new(8);
        let n = buf.write(b"1234567890");
        assert_eq!(n, 8);
        assert_eq!(buf.pending(), b"12345678");
    }
```

- [ ] **Step 6: Run all buffer tests**

Run: `cargo test --lib net::http::buffer`
Expected: All 13 tests PASS.

- [ ] **Step 7: Commit**

Ask user for commit description. Stage: `src/net/http/buffer.rs`, `src/net/http/mod.rs`.

---

## Chunk 2: Codec + Session

### Task 4: Http09Codec

**Files:**
- Create: `src/net/http/codec/mod.rs`
- Create: `src/net/http/codec/v0_9.rs`
- Modify: `src/net/http/mod.rs` (add module)

- [ ] **Step 1: Write tests for Http09Codec**

In `src/net/http/codec/v0_9.rs`, add tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http::{Method, Version};
    use crate::net::http::error::ParseError;

    #[test]
    fn decode_simple_get() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /index.html\r\n";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 17);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.method, Method::Get);
                assert_eq!(req.path_from_buf(buf), b"/index.html");
                assert_eq!(req.version, Version::Http09);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_bare_newline() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /path\n";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 10);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.path_from_buf(buf), b"/path");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_root_path() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /\r\n";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 7);
        match outcome.result {
            DecodeResult::Complete(req) => {
                assert_eq!(req.path_from_buf(buf), b"/");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_incomplete() {
        let mut codec = Http09Codec::new();
        let buf = b"GET /index";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
    }

    #[test]
    fn decode_empty() {
        let mut codec = Http09Codec::new();
        let buf = b"";
        let outcome = codec.decode(buf, 0);
        assert_eq!(outcome.consumed, 0);
        assert!(matches!(outcome.result, DecodeResult::Incomplete));
    }

    #[test]
    fn decode_unsupported_method() {
        let mut codec = Http09Codec::new();
        let buf = b"POST /data\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::UnsupportedMethod) => {}
            other => panic!("expected UnsupportedMethod, got {other:?}"),
        }
    }

    #[test]
    fn decode_missing_path() {
        let mut codec = Http09Codec::new();
        let buf = b"GET\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::InvalidRequestLine) => {}
            other => panic!("expected InvalidRequestLine, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_line() {
        let mut codec = Http09Codec::new();
        let buf = b"\r\n";
        let outcome = codec.decode(buf, 0);
        match outcome.result {
            DecodeResult::Error(ParseError::InvalidRequestLine) => {}
            other => panic!("expected InvalidRequestLine, got {other:?}"),
        }
    }

    #[test]
    fn decode_with_offset() {
        let mut codec = Http09Codec::new();
        // Simulate buffer where unconsumed starts at offset 10
        let buf = b"GET /test\r\n";
        let outcome = codec.decode(buf, 10);
        assert_eq!(outcome.consumed, 11);
        match outcome.result {
            DecodeResult::Complete(req) => {
                // path offsets should be absolute (buf_offset + local position)
                assert_eq!(req.path_start(), 14); // 10 + 4
                assert_eq!(req.path_end(), 19);   // 10 + 9
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn version_returns_http09() {
        let codec = Http09Codec::new();
        assert_eq!(codec.version(), Version::Http09);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib net::http::codec`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement codec trait and Http09Codec**

Create `src/net/http/codec/mod.rs`:

```rust
pub(crate) mod v0_9;

use crate::net::http::{
    error::ParseError,
    request::{Request, Version},
};

/// Result of attempting to decode an HTTP request from a byte buffer.
#[derive(Debug)]
pub enum DecodeResult {
    /// A complete request was parsed.
    Complete(Request),
    /// Not enough data yet — need more bytes.
    Incomplete,
    /// The input is malformed.
    Error(ParseError),
}

/// Outcome of a decode attempt: the result plus how many bytes were consumed.
#[derive(Debug)]
pub struct DecodeOutcome {
    pub result: DecodeResult,
    pub consumed: usize,
}

/// HTTP codec trait — interprets bytes as HTTP structures.
///
/// The `&mut self` receiver is intentional: HTTP/0.9 is stateless, but
/// future codecs (HTTP/2 HPACK) will need mutable state.
pub(crate) trait Codec {
    /// Attempt to decode a request from `buf`.
    ///
    /// `buf_offset` is the absolute position of `buf[0]` in the ReadBuffer,
    /// used to compute absolute offsets for the Request's path fields.
    fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome;

    /// Returns the HTTP version this codec handles.
    fn version(&self) -> Version;
}

/// Enum dispatch for HTTP codecs. Avoids dyn trait overhead.
pub(crate) enum HttpCodec {
    Http09(v0_9::Http09Codec),
}

impl HttpCodec {
    pub fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome {
        match self {
            HttpCodec::Http09(c) => c.decode(buf, buf_offset),
        }
    }

    pub fn version(&self) -> Version {
        match self {
            HttpCodec::Http09(c) => c.version(),
        }
    }
}
```

Create `src/net/http/codec/v0_9.rs`:

```rust
use crate::net::http::{
    error::ParseError,
    request::{Method, Request, Version},
};

use super::{Codec, DecodeOutcome, DecodeResult};

/// HTTP/0.9 codec.
///
/// Parses the simple HTTP/0.9 request format: `GET <path>\r\n`
/// (also accepts bare `\n` for historical compatibility).
///
/// Responses have no status line or headers — just raw body bytes.
pub struct Http09Codec;

impl Http09Codec {
    pub fn new() -> Self {
        Self
    }
}

impl Codec for Http09Codec {
    fn decode(&mut self, buf: &[u8], buf_offset: usize) -> DecodeOutcome {
        // Find the end of the request line (\n or \r\n)
        let newline_pos = match memchr_newline(buf) {
            Some(pos) => pos,
            None => {
                return DecodeOutcome {
                    result: DecodeResult::Incomplete,
                    consumed: 0,
                };
            }
        };

        // Determine the line content (strip \r\n or \n)
        let line_end = if newline_pos > 0 && buf[newline_pos - 1] == b'\r' {
            newline_pos - 1
        } else {
            newline_pos
        };

        let line = &buf[..line_end];
        let consumed = newline_pos + 1; // consume through the \n

        // Empty line
        if line.is_empty() {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::InvalidRequestLine),
                consumed,
            };
        }

        // Find the space separating method from path
        let space_pos = match line.iter().position(|&b| b == b' ') {
            Some(pos) => pos,
            None => {
                // No space — could be just "GET" with no path
                return DecodeOutcome {
                    result: DecodeResult::Error(ParseError::InvalidRequestLine),
                    consumed,
                };
            }
        };

        let method_bytes = &line[..space_pos];
        let path = &line[space_pos + 1..];

        // Validate method
        if method_bytes != b"GET" {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::UnsupportedMethod),
                consumed,
            };
        }

        // Path must not be empty
        if path.is_empty() {
            return DecodeOutcome {
                result: DecodeResult::Error(ParseError::InvalidRequestLine),
                consumed,
            };
        }

        // Compute absolute offsets into the ReadBuffer
        let path_start = buf_offset + space_pos + 1;
        let path_end = buf_offset + line_end;

        DecodeOutcome {
            result: DecodeResult::Complete(Request::new(
                Method::Get,
                path_start,
                path_end,
                Version::Http09,
            )),
            consumed,
        }
    }

    fn version(&self) -> Version {
        Version::Http09
    }
}

/// Find the position of the first `\n` byte in `buf`.
#[inline]
fn memchr_newline(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == b'\n')
}
```

Update `src/net/http/mod.rs`:

```rust
mod buffer;
pub(crate) mod codec;
mod error;
mod request;

pub use error::{HttpError, ParseError};
pub use request::{Method, Request, Version};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib net::http::codec`
Expected: All 10 tests PASS.

- [ ] **Step 5: Commit**

Ask user for commit description. Stage: `src/net/http/codec/mod.rs`, `src/net/http/codec/v0_9.rs`, `src/net/http/mod.rs`.

---

### Task 5: Session state machine

**Files:**
- Create: `src/net/http/session.rs`
- Modify: `src/net/http/mod.rs` (add module)

- [ ] **Step 1: Write tests for Session**

In `src/net/http/session.rs`, add tests:

```rust
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib net::http::session`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement Session**

Create `src/net/http/session.rs`:

```rust
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    /// Ready to decode the next request.
    AwaitingRequest,
    /// Request has been decoded, waiting for response to begin.
    RequestReady,
    /// Response is being written.
    ResponseInProgress,
    /// A parse error occurred. Connection should close.
    Failed,
    /// Connection lifecycle is complete.
    Done,
}

impl Session {
    /// Create a new session with the given codec.
    pub fn new(codec: HttpCodec) -> Self {
        Self {
            codec,
            state: SessionState::AwaitingRequest,
        }
    }

    /// Create a new session with the default HTTP/0.9 codec.
    pub fn http09() -> Self {
        Self::new(HttpCodec::Http09(Http09Codec::new()))
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
        debug_assert_eq!(self.state, SessionState::AwaitingRequest);

        let outcome = self.codec.decode(buf, buf_offset);
        match outcome.result {
            DecodeResult::Complete(req) => {
                self.state = SessionState::RequestReady;
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
        debug_assert_eq!(self.state, SessionState::RequestReady);
        self.state = SessionState::ResponseInProgress;
    }

    /// Mark that the response is finished.
    ///
    /// Returns `true` if the connection should stay alive (keep-alive).
    /// For HTTP/0.9, always returns `false`.
    pub fn finish_response(&mut self) -> bool {
        debug_assert_eq!(self.state, SessionState::ResponseInProgress);

        match self.codec.version() {
            Version::Http09 => {
                self.state = SessionState::Done;
                false
            }
        }
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
```

Update `src/net/http/mod.rs`:

```rust
mod buffer;
pub(crate) mod codec;
mod error;
mod request;
pub(crate) mod session;

pub use error::{HttpError, ParseError};
pub use request::{Method, Request, Version};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib net::http::session`
Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

Ask user for commit description. Stage: `src/net/http/session.rs`, `src/net/http/mod.rs`.

---

## Chunk 3: Connection, Response, Listener, Handler

### Task 6: HttpConnection + ResponseWriter

**Files:**
- Create: `src/net/http/connection.rs`
- Create: `src/net/http/response.rs`
- Modify: `src/net/http/mod.rs` (add modules + re-exports)

- [ ] **Step 1: Write tests for HttpConnection (unit tests with mock data)**

In `src/net/http/connection.rs`, add tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_path_resolution() {
        let mut conn = HttpConnection::new_for_test();
        // Simulate data in the read buffer
        conn.read_buf.append(b"GET /hello\r\n");
        let req = Request::new(Method::Get, 4, 10, Version::Http09);
        assert_eq!(conn.request_path(&req), b"/hello");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib net::http::connection`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement ResponseWriter**

Create `src/net/http/response.rs`:

```rust
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
```

- [ ] **Step 4: Implement HttpConnection**

Create `src/net/http/connection.rs`:

```rust
use crate::net::http::{
    HttpError,
    buffer::{ReadBuffer, WriteBuffer},
    request::{Method, Request, Version},
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
    session: Session,
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
                            return Err(HttpError::Parse(crate::net::http::error::ParseError::RequestTooLarge));
                        }
                    }

                    // Read from TcpStream into read buffer
                    let buf_slice = self.read_buf_writable();
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
    pub fn respond(&mut self) -> ResponseWriter<'_> {
        ResponseWriter::new(&mut self.write_buf, &self.stream, &mut self.session)
    }

    /// Resolve a request's path offsets against the read buffer.
    pub fn request_path(&self, req: &Request) -> &[u8] {
        self.read_buf.slice_at(req.path_start(), req.path_end())
    }

    /// Get a mutable slice of the writable portion of the read buffer.
    fn read_buf_writable(&mut self) -> &mut [u8] {
        self.read_buf.writable_slice()
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        // For unit tests that don't need a real TcpStream.
        // We only test request_path resolution here.
        // Integration tests with real TCP connections go in tests/.
        use std::cell::{Cell, UnsafeCell};
        use std::rc::Rc;
        use crate::net::handler::tcp::TcpHandler;
        use crate::net::socket::LocalQueue;
        use crate::net::handler::tcp::tcb::{ConnectionId, TcpEvent};
        use crate::net::wire::ip::IpAddress;

        // This is a minimal mock — we only need the struct to exist
        // for request_path() testing. Don't call async methods.
        let handler = Rc::new(UnsafeCell::new(TcpHandler::new(false, false)));
        let conn_id = ConnectionId {
            local_addr: IpAddress::V4(crate::net::wire::ip::Ipv4Address::unspecified()),
            local_port: 0,
            remote_addr: IpAddress::V4(crate::net::wire::ip::Ipv4Address::unspecified()),
            remote_port: 0,
        };
        let event_queue = LocalQueue::new(16);
        let stream = TcpStream::from_accepted_for_test(conn_id, event_queue, handler);
        Self::new(stream, Session::http09())
    }
}
```

We need to add two methods to `ReadBuffer` — `writable_slice()` and `advance_end()`:

Add to `src/net/http/buffer.rs` in the `ReadBuffer` impl:

```rust
    /// Returns a mutable slice of the writable region (from end to capacity).
    /// Used by HttpConnection to pass to TcpStream::read().
    pub fn writable_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.end..]
    }

    /// Advance the end position after writing into writable_slice().
    pub fn advance_end(&mut self, n: usize) {
        self.end += n;
        debug_assert!(self.end <= self.buf.len());
    }
```

Update `src/net/http/mod.rs`:

```rust
mod buffer;
pub(crate) mod codec;
mod connection;
mod error;
mod request;
mod response;
pub(crate) mod session;

pub use connection::HttpConnection;
pub use error::{HttpError, ParseError};
pub use request::{Method, Request, Version};
pub use response::ResponseWriter;
```

**Note:** The `new_for_test()` constructor requires a `TcpStream` which needs `from_accepted_for_test`. We need to add a `#[cfg(test)]` constructor to TcpStream. Add to `src/net/socket/tcp.rs` inside the `impl TcpStream` block:

```rust
    #[cfg(test)]
    pub(crate) fn from_accepted_for_test(
        conn_id: ConnectionId,
        event_queue: LocalQueue<TcpEvent>,
        handler: Rc<UnsafeCell<TcpHandler>>,
    ) -> Self {
        Self {
            conn_id,
            event_queue,
            handler,
            cached_idx: Cell::new(0),
            closed: false,
            write_closed: false,
        }
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib net::http::connection`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

Ask user for commit description. Stage: `src/net/http/connection.rs`, `src/net/http/response.rs`, `src/net/http/buffer.rs`, `src/net/http/mod.rs`, `src/net/socket/tcp.rs`.

---

### Task 7: HttpListener + HttpHandler

**Files:**
- Create: `src/net/http/listener.rs`
- Create: `src/net/http/handler.rs`
- Modify: `src/net/http/mod.rs` (add modules + re-exports)

- [ ] **Step 1: Implement HttpHandler trait**

Create `src/net/http/handler.rs`:

```rust
use crate::net::http::{HttpError, Request, ResponseWriter};

/// Trait for handling HTTP requests.
///
/// Implement this trait and pass it to `HttpListener::serve()` for the
/// high-level server API. Each connection spawns a task that calls
/// `handle()` for every request.
///
/// `Clone` is required because each spawned task gets its own copy.
pub trait HttpHandler: Clone + 'static {
    /// Handle an HTTP request and write the response.
    fn handle(
        &self,
        req: Request,
        res: ResponseWriter<'_>,
    ) -> impl std::future::Future<Output = Result<(), HttpError>> + '_;
}
```

- [ ] **Step 2: Implement HttpListener**

Create `src/net/http/listener.rs`:

```rust
use crate::net::http::{
    HttpConnection, HttpError,
    handler::HttpHandler,
    session::Session,
};
use crate::net::socket::TcpListener;
use crate::net::wire::ip::IpAddress;
use crate::rt::task::spawn;

/// An HTTP listener that accepts incoming connections.
///
/// Wraps `TcpListener` and produces `HttpConnection` instances.
/// Must be created inside `LocalRuntime::run()`. Panics otherwise.
pub struct HttpListener {
    inner: TcpListener,
}

impl HttpListener {
    /// Create a new HTTP listener bound to the given address and port.
    ///
    /// Wraps `TcpListener::listen()` internally. Must be called inside
    /// `LocalRuntime::run()`. Panics otherwise.
    pub fn listen(addr: IpAddress, port: u16) -> Result<Self, HttpError> {
        let inner = TcpListener::listen(addr, port).map_err(HttpError::Bind)?;
        Ok(Self { inner })
    }

    /// Accept the next HTTP connection.
    ///
    /// Returns an `HttpConnection` wrapping the accepted TCP stream
    /// with a fresh HTTP/0.9 session.
    pub async fn accept(&self) -> Result<HttpConnection, HttpError> {
        let stream = self.inner.accept().await;
        Ok(HttpConnection::new(stream, Session::http09()))
    }

    /// Convenience method: accept loop + spawn a task per connection.
    ///
    /// Spawned tasks that return errors are silently dropped
    /// (the connection is closed by `TcpStream::drop()`).
    pub async fn serve<H: HttpHandler>(&self, handler: H) -> Result<(), HttpError> {
        loop {
            let mut conn = self.accept().await?;
            let handler = handler.clone();
            spawn(async move {
                loop {
                    match conn.next_request().await {
                        Ok(Some(req)) => {
                            let writer = conn.respond();
                            if handler.handle(req, writer).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            });
        }
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> IpAddress {
        self.inner.local_addr()
    }

    /// Returns the local port this listener is bound to.
    pub fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
}
```

- [ ] **Step 3: Update mod.rs with final re-exports**

Update `src/net/http/mod.rs`:

```rust
mod buffer;
pub(crate) mod codec;
mod connection;
mod error;
mod handler;
mod listener;
mod request;
mod response;
pub(crate) mod session;

pub use connection::HttpConnection;
pub use error::{HttpError, ParseError};
pub use handler::HttpHandler;
pub use listener::HttpListener;
pub use request::{Method, Request, Version};
pub use response::ResponseWriter;
```

- [ ] **Step 4: Verify full build compiles**

Run: `cargo build`
Expected: BUILD SUCCESS with no errors.

- [ ] **Step 5: Commit**

Ask user for commit description. Stage: `src/net/http/handler.rs`, `src/net/http/listener.rs`, `src/net/http/mod.rs`.

---

### Task 8: Verify all tests pass

- [ ] **Step 1: Run the full test suite**

Run: `cargo test`
Expected: All existing tests plus new HTTP tests PASS. No regressions.

- [ ] **Step 2: Fix any issues**

If any tests fail, fix the issues and re-run.

- [ ] **Step 3: Final commit if any fixes were needed**

Ask user for commit description if changes were made.
