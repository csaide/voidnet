# HTTP Layer Design — VoidNet

**Date:** 2026-03-12
**Branch:** net-stack
**Scope:** HTTP/0.9 groundwork with structural investment for HTTP/1.x, HTTP/2, HTTP/3

## Goals

- Add HTTP parsing and listener infrastructure to VoidNet's network stack
- Target use cases: reverse proxies, load balancers, CDN nodes
- Prioritize performance: zero-copy parsing, minimal allocations, streaming bodies
- HTTP/0.9 as first implementation; structure must accommodate HTTP/1.x, HTTP/2, HTTP/3 without rearchitecting

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Module location | `src/net/http/` (Option B) | HTTP stays within the networking domain but above transport. TLS, QUIC land naturally nearby. Tight coupling to TCP internals is a feature for performance. |
| Parsing approach | Zero-copy with offsets (Option A + offset-based Request) | Request stores byte offsets into the read buffer, resolved via `req.path(&conn)`. No lifetime parameter on Request, no borrow conflicts, no allocations. |
| Request lifecycle | Layered — stream API + handler trait (Option C) | Low-level stream API as foundation, high-level handler trait on top. Proxy/CDN use cases need stream-level control. |
| Body handling | Streaming reader (Option B) | No buffering. Body is an async reader pulling from TCP stream on demand. Backpressure propagates through TCP flow control. |
| Architecture | Layered codec/session/connection (Approach B) | Proven architecture. Each layer independently testable. Codec handles parsing, session handles lifecycle, connection handles I/O. |
| Buffer strategy | ReadBuffer as terminal buffer (Option 3) | One copy from TCP RingBuffer into ReadBuffer, everything after is zero-copy offset resolution. Simplest approach; optimization path to direct RingBuffer access is clear for later. |
| Codec dispatch | Enum dispatch, no dyn | `HttpCodec` enum with variant per version. No vtable overhead, compiler can inline. Trait exists as contract, enum is the runtime dispatch. |
| Self-borrow solution | Offset-based Request (Option 1) | Request stores offsets not slices — no lifetime ties to the connection. Resolving `req.path(&conn)` provides zero-copy access without blocking `conn.respond()`. Follows pattern used by httparse internally. |

## Architecture

Three layers, bottom-up:

```
  HttpListener / HttpHandler (user-facing)
           |
    HttpConnection (owns TcpStream + buffers + session, stream API)
           |
       Session (request/response lifecycle, drives codec)
           |
     HttpCodec (enum: Http09Codec, future Http1xCodec, Http2Codec)
           |
  ReadBuffer / WriteBuffer (zero-copy I/O buffering)
```

## Module Layout

```
src/net/http/
├── mod.rs             // Public re-exports
├── listener.rs        // HttpListener (wraps TcpListener)
├── connection.rs      // HttpConnection (owns TcpStream + buffers + session)
├── session.rs         // Session (lifecycle state machine, drives codec)
├── codec/
│   ├── mod.rs         // Codec trait + HttpCodec enum
│   └── v0_9.rs        // Http09Codec implementation
├── request.rs         // Request (offset-based, no lifetime parameter)
├── response.rs        // ResponseWriter (streaming body output)
├── handler.rs         // HttpHandler trait
├── error.rs           // HttpError (wraps TcpError + ParseError)
└── buffer.rs          // ReadBuffer / WriteBuffer
```

## Layer Details

### Error Types (`error.rs`)

```rust
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

pub enum ParseError {
    /// Request line is malformed (invalid method, missing path, etc.)
    InvalidRequestLine,
    /// Request line exceeds buffer capacity
    RequestTooLarge,
    /// Unsupported HTTP method (for HTTP/0.9: anything other than GET)
    UnsupportedMethod,
}
```

`HttpError` wraps `TcpError` from the existing stack and adds HTTP-specific variants. All public APIs return `Result<T, HttpError>`.

### Buffer Layer (`buffer.rs`)

**ReadBuffer:**
- Fixed-capacity, power-of-2 sized buffer (default 8 KiB — accommodates URI lengths up to ~8000 bytes, expandable via configuration)
- Tracks `start` (unconsumed) and `end` (written) positions
- `unconsumed() -> &[u8]` returns zero-copy slice for parsers
- `consume(n)` advances start position
- `compact()` shifts data to front when start passes halfway (amortized). Safe to call only when no outstanding offset-based reads are in progress — enforced by the session layer (compact happens only between request/response cycles, never while a Request's offsets are live)
- `read_from(stream) -> usize` fills from TcpStream
- This is the terminal buffer — one copy from TCP RingBuffer, all parsing resolves offsets into here

**WriteBuffer:**
- Same power-of-2 structure (default 8 KiB)
- `write(data)` appends bytes
- `flush_to(stream)` writes to TcpStream and advances read position

### Codec Layer (`codec/`)

Byte interpretation. The `&mut self` receiver is intentional — HTTP/0.9 is stateless, but future codecs (HTTP/2 HPACK) will need mutable state. Never allocates.

```rust
pub struct DecodeOutcome {
    pub result: DecodeResult,
    pub consumed: usize,
}

pub enum DecodeResult {
    Complete(Request),
    Incomplete,
    Error(ParseError),
}

pub trait Codec {
    fn decode(&mut self, buf: &[u8]) -> DecodeOutcome;
    fn encode_response_head(&mut self, buf: &mut WriteBuffer, response: &ResponseHead) -> Result<(), HttpError>;
    fn version(&self) -> Version;
}

pub enum HttpCodec {
    Http09(Http09Codec),
    // Http1x(Http1xCodec),  -- future
    // Http2(Http2Codec),    -- future
}
```

**Http09Codec:**
- `decode()`: scan for `\r\n` or bare `\n` (HTTP/0.9 historically uses bare `\n`; we accept both for robustness, matching the lenient approach used by most HTTP implementations). Extracts `GET <path>`. Method is always GET, no headers, no version string.
- `encode_response_head()`: no-op (HTTP/0.9 has no status line or headers).

### Session Layer (`session.rs`)

Connection-level state machine. Owns the codec, enforces request/response ordering.

```rust
pub struct Session {
    codec: HttpCodec,
    state: SessionState,
}

enum SessionState {
    AwaitingRequest,
    RequestReady,
    ResponseInProgress,
    Failed,
    Done,
}
```

The `Failed` state handles codec parse errors. For HTTP/0.9, a parse error transitions directly to `Done` (no way to send an error response). For future HTTP/1.x, `Failed` will allow sending a 400 response before closing.

**API:**
- `try_decode_request(buf) -> Result<Option<(Request, usize)>, HttpError>` — feed bytes to codec. Returns `Err` on parse errors (transitions to `Failed`).
- `begin_response()` — transition to ResponseInProgress
- `finish_response() -> bool` — returns whether connection stays alive
- `is_done() -> bool` — connection should close (includes `Failed` state)

**HTTP/0.9:** one request, one response, then Done. No keep-alive.

**Future HTTP/1.x:** session checks Connection headers, loops back to AwaitingRequest after response, handles pipelining.

**Future HTTP/2:** session manages per-stream state machines, stream table, flow control windows, HPACK state.

### Connection Layer (`connection.rs`)

User-facing stream API. Owns everything.

```rust
pub struct HttpConnection {
    stream: TcpStream,
    read_buf: ReadBuffer,
    write_buf: WriteBuffer,
    session: Session,
}

impl HttpConnection {
    pub async fn next_request(&mut self) -> Result<Option<Request>, HttpError>;
    pub fn respond(&mut self) -> ResponseWriter<'_>;
    pub fn request_path(&self, req: &Request) -> &[u8];
}
```

`next_request()` loop: check session done → read into ReadBuffer → try decode → if Incomplete read more → if Complete consume bytes and return Request (with offsets).

`request_path(&self, &Request)` resolves the path offsets against the ReadBuffer. Safe because the buffer is not compacted until `finish_response()`.

No self-borrowing conflict: `Request` has no lifetime parameter, so holding a `Request` while calling `conn.respond()` compiles without issue.

Must be called inside `LocalRuntime::run()` (inherits the runtime context requirement from `TcpListener::listen()`).

### Request & Response Types

**Request** (`request.rs`):

```rust
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub method: Method,
    path_start: usize,
    path_end: usize,
    pub version: Version,
    // future: header offsets, body position
}

impl Request {
    /// Resolve the request path against the connection's read buffer.
    pub fn path<'a>(&self, conn: &'a HttpConnection) -> &'a [u8] {
        conn.request_path(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    // Head, Post, Put, Delete, Options, Patch, Trace, Connect — added with HTTP/1.x
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http09,
    // Http10, Http11, Http2 — future
}
```

`Request` is `Copy` — no allocations, no lifetimes, trivially cheap to pass around. Path resolution is zero-copy via offset lookup into the ReadBuffer.

**ResponseWriter** (`response.rs`):

```rust
pub struct ResponseWriter<'conn> {
    write_buf: &'conn mut WriteBuffer,
    stream: &'conn mut TcpStream,
    session: &'conn mut Session,
}

impl ResponseWriter<'_> {
    /// Write body bytes. For HTTP/0.9 this writes raw bytes directly.
    pub async fn write_body(&mut self, data: &[u8]) -> Result<usize, HttpError>;

    /// Signal that the response is complete. Flushes the write buffer.
    pub async fn finish(self) -> Result<(), HttpError>;
}
```

For HTTP/0.9: `write_body()` writes raw bytes through the buffer to the stream. No status line, no headers. `finish()` flushes the buffer and tells the session the response is done.

When HTTP/1.x arrives, ResponseWriter gains `write_status()`, `write_header()`, `end_headers()` methods that must be called before `write_body()`, with the session enforcing ordering.

### Listener & Handler

```rust
pub struct HttpListener {
    inner: TcpListener,
}

impl HttpListener {
    /// Create a new HTTP listener.
    /// Must be called inside `LocalRuntime::run()`. Panics otherwise.
    /// Wraps `TcpListener::listen()` internally.
    pub fn listen(addr: IpAddress, port: u16) -> Result<Self, HttpError>;

    /// Accept the next connection, wrapping it as an HttpConnection.
    pub async fn accept(&self) -> Result<HttpConnection, HttpError>;

    /// Convenience: accept loop + spawn a task per connection using the handler.
    /// Spawned tasks that return errors are silently dropped (connection closed).
    pub async fn serve<H: HttpHandler>(&self, handler: H) -> Result<(), HttpError>;
}

pub trait HttpHandler: Clone + 'static {
    async fn handle(&self, req: Request, res: ResponseWriter<'_>) -> Result<(), HttpError>;
}
```

`listen()` wraps `TcpListener::listen()` — same naming convention as the existing TCP API. Must be called inside `LocalRuntime::run()` (inherits the runtime context requirement).

`serve()` loops `accept()`, spawns a task per connection via the runtime's `spawn()`. Spawned connection tasks that error are dropped silently (the connection is closed by `TcpStream::drop()`). This matches the pattern in the TCP echo server example.

## Public API Examples

**High-level (handler trait):**
```rust
runtime.run(exit, async {
    let listener = HttpListener::listen(addr, 80)?;
    listener.serve(MyHandler).await
});

#[derive(Clone)]
struct MyHandler;
impl HttpHandler for MyHandler {
    async fn handle(&self, req: Request, mut res: ResponseWriter<'_>) -> Result<(), HttpError> {
        res.write_body(b"Hello").await?;
        res.finish().await
    }
}
```

**Low-level (stream API):**
```rust
runtime.run(exit, async {
    let listener = HttpListener::listen(addr, 80)?;
    loop {
        let mut conn = listener.accept().await?;
        spawn(async move {
            while let Some(req) = conn.next_request().await? {
                let path = req.path(&conn);
                // Use path for routing decisions...
                let mut writer = conn.respond();
                writer.write_body(b"Hello").await?;
                writer.finish().await?;
            }
            Ok::<(), HttpError>(())
        });
    }
});
```

## Data Flow (HTTP/0.9 Request → Response)

```
1. Client sends: "GET /index.html\r\n"
2. NIC → UMEM Frame (DMA, zero-copy)
3. Frame → TCP RingBuffer (copy #1: TCP reassembly)
4. RingBuffer → ReadBuffer (copy #2: TcpStream::read)
5. Http09Codec::decode(ReadBuffer) → Request { method: Get, path_start: 4, path_end: 15 }
6. req.path(&conn) → &ReadBuffer[4..15] → b"/index.html" (zero-copy resolution)
7. User writes response body via ResponseWriter
8. ResponseWriter → WriteBuffer → TcpStream::write (copy into TCP send RingBuffer)
9. TCP segments → XDP Frame → NIC (zero-copy DMA)
```

## Future Extension Points

| Feature | Where it lands |
|---------|---------------|
| HTTP/1.x headers + keep-alive | New `Http1xCodec` variant, session gains keep-alive logic, Request gains header offset storage |
| Chunked transfer encoding | Codec handles framing, ResponseWriter gains chunked mode |
| HTTP/2 | New codec for frame parsing, session manages stream table + HPACK + flow control |
| TLS | `src/net/tls/` — wraps TcpStream, HttpConnection accepts either |
| HTTP/3 / QUIC | `src/net/quic/` as transport, new codec for HTTP/3 framing. HttpConnection will need transport abstraction (trait or enum) to support both TCP and QUIC streams. |
| Request body streaming | BodyReader type added to Request, pulls from ReadBuffer on demand |
| Proxy forwarding | Operates on stream API, reads from one connection's Request, writes to another's ResponseWriter |
| Zero-copy optimization | Replace ReadBuffer with direct RingBuffer access via new TcpStream API |
| Buffer sizing | ReadBuffer/WriteBuffer capacity configurable via HttpListener builder (default 8 KiB) |
