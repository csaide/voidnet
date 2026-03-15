# HTTP Response Zero-Format Optimization — VoidNet

**Date:** 2026-03-15
**Approach:** Direct buffer writes, eliminate format!() allocations
**Target:** Eliminate ~4.77% CPU overhead from per-response String allocations

## Goals

Remove per-response heap allocations from `ResponseWriter` in `src/net/http/response.rs`.
The perf profile shows:

- 2.27% `ResponseWriter::flush_headers` closure — `format_status_line()` + `format_header()`
- 1.30% `ResponseWriter::flush` closure
- 1.20% `ResponseWriter::write_all` closure

Combined: ~4.77% of CPU in the http-server workload.

A typical HTTP/1.1 response with 4 headers allocates ~12 Strings + 1 Vec per
request cycle. These are all avoidable.

## Non-Goals

- Changing the `add_header(&str, &str)` public API to accept `&'a str` references
  (would require lifetime changes to ResponseWriter — deferred)
- Eliminating the `Vec<(String, String)>` header storage (kept for simplicity)
- HTTP request parsing optimizations (Approach C, separate spec)

---

## 1. Replace `format_status_line()` with direct `write_all` calls

### Problem

```rust
fn format_status_line(code: u16, reason: &str, version: Version) -> String {
    format!("{} {} {}\r\n", version, code, reason)
}
```

Allocates a `String` via `format!()`, invokes the `Display` trait for `Version`
(which writes "HTTP/1.1" through the fmt machinery), then copies to `WriteBuffer`.

### Design

Delete `format_status_line()`. In `flush_headers`, write each component directly
via `self.write_all()`:

```rust
// Version as static byte slice — no Display trait, no fmt machinery
let version_bytes: &[u8] = match self.version {
    Version::Http10 => b"HTTP/1.0 ",
    Version::Http11 => b"HTTP/1.1 ",
    Version::Http09 => unreachable!(), // flush_headers is not called for 0.9
};
self.write_all(version_bytes).await?;

// Status code as 3 ASCII digits — no itoa, no format!
let code = self.status_code;
self.write_all(&[
    b'0' + (code / 100) as u8,
    b'0' + ((code / 10) % 10) as u8,
    b'0' + (code % 10) as u8,
]).await?;

self.write_all(b" ").await?;
self.write_all(self.status_reason.as_bytes()).await?;
self.write_all(b"\r\n").await?;
```

Each `write_all` is a `copy_from_slice` into `WriteBuffer` with auto-flush when
full. The overhead of 5 `write_all` calls vs 1 is negligible — each is a memcpy
+ capacity check. The real cost was in `format!()` → String alloc → copy → drop.

### Location

- `src/net/http/response.rs` — `flush_headers()` method, delete `format_status_line()` fn

---

## 2. Replace `format_header()` with direct `write_all` calls

### Problem

```rust
fn format_header(name: &str, value: &str) -> String {
    format!("{}: {}\r\n", name, value)
}
```

Called per header in the `flush_headers` loop. Allocates a String per header.

### Design

Delete `format_header()`. In the `flush_headers` loop, write components directly:

```rust
let headers = std::mem::take(&mut self.response_headers);
for (name, value) in &headers {
    self.write_all(name.as_bytes()).await?;
    self.write_all(b": ").await?;
    self.write_all(value.as_bytes()).await?;
    self.write_all(b"\r\n").await?;
}
self.response_headers = headers;
```

Same pattern as the status line — 4 `write_all` calls per header instead of 1,
but zero allocations.

### Location

- `src/net/http/response.rs` — `flush_headers()` loop, delete `format_header()` fn

---

## 3. Stack-format chunk hex size

### Problem

```rust
let chunk_header = format!("{:x}\r\n", data.len());
self.write_all(chunk_header.as_bytes()).await?;
```

Allocates a String for each chunked body write. Called once per `write_body()`
for chunked responses.

### Design

Write the hex size into a stack buffer:

```rust
// Buffer sized for max usize hex digits (2 per byte) + \r\n.
const HEX_BUF_LEN: usize = std::mem::size_of::<usize>() * 2 + 2;

fn write_hex_usize(n: usize, buf: &mut [u8; HEX_BUF_LEN]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        buf[1] = b'\r';
        buf[2] = b'\n';
        return 3;
    }
    // Format hex digits in reverse, then reverse them
    let mut pos = 0;
    let mut val = n;
    while val > 0 {
        let digit = (val & 0xf) as u8;
        buf[pos] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        pos += 1;
        val >>= 4;
    }
    buf[..pos].reverse();
    buf[pos] = b'\r';
    buf[pos + 1] = b'\n';
    pos + 2
}
```

Usage in `write_body()`:

```rust
if self.chunked {
    let mut hex_buf = [0u8; HEX_BUF_LEN];
    let n = write_hex_usize(data.len(), &mut hex_buf);
    self.write_all(&hex_buf[..n]).await?;
    self.write_all(data).await?;
    self.write_all(b"\r\n").await?;
    Ok(data.len())
}
```

### Location

- `src/net/http/response.rs` — `write_body()` method, new `write_hex_usize()` fn

---

## 4. Status reason as `Cow<'static, str>`

### Problem

```rust
status_reason: String,
// in new(): String::from("OK")  — allocates on every ResponseWriter creation
// in set_status(): reason.to_string()  — allocates on every set_status call
```

### Design

Change the field to `Cow<'static, str>`:

```rust
use std::borrow::Cow;

status_reason: Cow<'static, str>,

// in new():
status_reason: Cow::Borrowed("OK"),  // zero allocation

// in set_status():
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
```

Common reason phrases (covering ~95% of responses) use static borrows. Custom
phrases fall back to heap allocation.

### Location

- `src/net/http/response.rs` — `ResponseWriter` struct, `new()`, `set_status()`

---

## 5. Eliminate `.to_string()` in `finish()` Content-Length injection

### Problem

```rust
self.response_headers
    .push(("Content-Length".to_string(), "0".to_string()));
```

and in `flush_headers`:

```rust
self.response_headers
    .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
```

### Design

Use `String::from` with static-length known strings — actually these are
identical in cost. The real optimization: since we're writing headers directly
in `flush_headers`, we can write these auto-injected headers directly too,
without pushing them to the Vec:

```rust
// In flush_headers, after the header loop:
if self.chunked {
    self.write_all(b"Transfer-Encoding: chunked\r\n").await?;
}

// In finish, for headers-only responses:
if !has_content_length {
    self.write_all(b"Content-Length: 0\r\n").await?;
}
```

Wait — `finish()` calls `flush_headers()` after pushing to the Vec. The cleanest
approach: move the auto-injection into `flush_headers` directly so it writes
the fixed header as a single byte slice without going through the Vec at all.

Actually, looking at the flow more carefully:
- `flush_headers` checks `has_content_length`, and if false + HTTP/1.1, sets
  `self.chunked = true` and pushes Transfer-Encoding to the Vec
- `finish()` checks headers for Content-Length before calling `flush_headers`

The cleanest change: keep the `self.chunked = true` logic in `flush_headers`,
but write `Transfer-Encoding: chunked\r\n` directly instead of pushing to Vec.
Similarly, in `finish()`, write `Content-Length: 0\r\n` directly before calling
`flush_headers()` — but that's tricky since headers aren't flushed yet.

Simplest correct approach: in `flush_headers`, after writing all Vec headers,
write any auto-injected headers as byte literals:

```rust
// Note: Transfer-Encoding is written after user headers. This is a
// behavioral change from the current code which pushes it to the Vec
// before iteration. RFC 9112 does not mandate header ordering, so this
// is valid — but the order changes from "among user headers" to "after".
if !has_content_length && self.version == Version::Http11 {
    self.chunked = true;
    self.write_all(b"Transfer-Encoding: chunked\r\n").await?;
}
```

And in `finish()`, instead of pushing to Vec then calling `flush_headers`:

```rust
if !has_content_length {
    self.response_headers.push(("Content-Length".into(), "0".into()));
}
self.flush_headers().await?;
```

We can simplify to:

```rust
self.flush_headers_with_content_length_zero().await?;
```

But that's over-engineering. Keep the push for `finish()` — it's a cold path
(headers-only responses like 204/304 are rare). Focus the optimization on the
hot path in `flush_headers`.

### Location

- `src/net/http/response.rs` — `flush_headers()` for Transfer-Encoding

---

## 6. Update existing tests

The tests for `format_status_line` and `format_header` need updating since those
functions are deleted. Replace with tests for the new write behavior, testing
via `WriteBuffer` output.

### Location

- `src/net/http/response.rs` — `#[cfg(test)] mod tests`

---

## Implementation Order

1. **Cow status reason** — change field type, update `new()` and `set_status()`
2. **Delete `format_status_line`** — replace with direct writes in `flush_headers`
3. **Delete `format_header`** — replace with direct writes in `flush_headers` loop
4. **Write Transfer-Encoding directly** — skip Vec push for auto-injected header
5. **Stack-format chunk hex** — add `write_hex_usize`, update `write_body`
6. **Update tests** — adapt existing tests to new behavior
7. **Verify** — run full test suite

Steps 1-4 are sequential (all modify `flush_headers`). Step 5 is independent.

---

## File Summary

| File | Action |
|------|--------|
| `src/net/http/response.rs` | All changes — Cow, direct writes, hex helper, tests |

No new dependencies. Single file change.

---

## Future: Approach C (HTTP Request Parsing + Run Loop)

If further optimization is needed after A and B, the next targets are:
- `parse_request_line` at 6.33% — inline hints, flatten codec dispatch
- `LocalRuntime::run` at 5.18% — audit per-tick overhead
- `process_ipv6` / `process_segment` at 2.48% — inbound TCP path
