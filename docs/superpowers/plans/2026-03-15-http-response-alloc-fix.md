# HTTP Response Zero-Format Optimization — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate ~4.77% CPU overhead from per-response String allocations in `ResponseWriter`.

**Architecture:** Replace `format!()` calls with direct `write_all()` byte slice writes, use `Cow<'static, str>` for status reason, stack-format chunk hex size. Single file change — all modifications in `src/net/http/response.rs`.

**Tech Stack:** Rust, `std::borrow::Cow`

**Spec:** `docs/superpowers/specs/2026-03-15-http-response-alloc-fix-design.md`

---

### Task 1: Cow status reason + flush_headers rewrite + delete format helpers

**Files:**
- Modify: `src/net/http/response.rs`

- [ ] **Step 1: Add Cow import and change status_reason field type**

At the top of response.rs, add `std::borrow::Cow` to imports. Change the struct field and constructor:

In the imports section, add:
```rust
use std::borrow::Cow;
```

Change field `status_reason: String` to `status_reason: Cow<'static, str>`.

Change `new()` from `status_reason: String::from("OK")` to `status_reason: Cow::Borrowed("OK")`.

- [ ] **Step 2: Update set_status to use Cow with common phrase matching**

Replace the `set_status` method body. Change:

```rust
    pub fn set_status(&mut self, code: u16, reason: &str) {
        if self.version == Version::Http09 {
            return;
        }
        self.status_code = code;
        self.status_reason = reason.to_string();
    }
```

to:

```rust
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
```

- [ ] **Step 3: Rewrite flush_headers with direct writes and Transfer-Encoding bypass**

Replace the entire `flush_headers` method. Change:

```rust
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
```

to:

```rust
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
        // Zero-alloc for Cow::Borrowed (common case).
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
```

- [ ] **Step 4: Delete format_status_line and format_header helper functions**

Delete these two functions (currently at the bottom of the file, before `#[cfg(test)]`):

```rust
fn format_status_line(code: u16, reason: &str, version: Version) -> String {
    format!("{} {} {}\r\n", version, code, reason)
}

fn format_header(name: &str, value: &str) -> String {
    format!("{}: {}\r\n", name, value)
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check 2>&1 | head -20`

Expected: Clean compile. The tests will fail (they reference deleted functions) but check should pass.

- [ ] **Step 6: Commit**

```bash
git add src/net/http/response.rs
git commit -m "perf(net::http): Eliminate format!() allocs in flush_headers

- Replace format_status_line() with direct write_all() byte slices
- Replace format_header() with per-component write_all() calls
- Use Cow<'static, str> for status reason (zero-alloc for common phrases)
- Write Transfer-Encoding directly as byte literal, skip Vec push"
```

---

### Task 2: Stack-format chunk hex size

**Files:**
- Modify: `src/net/http/response.rs`

- [ ] **Step 1: Add write_hex_usize helper and HEX_BUF_LEN constant**

Add above the `impl<'conn> ResponseWriter<'conn>` block (after the struct definition, before the impl):

```rust
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
```

- [ ] **Step 2: Update write_body to use stack hex formatting**

Replace the chunked branch in `write_body`. Change:

```rust
        if self.chunked {
            // Write chunk header: hex size + \r\n
            let chunk_header = format!("{:x}\r\n", data.len());
            self.write_all(chunk_header.as_bytes()).await?;
            self.write_all(data).await?;
            self.write_all(b"\r\n").await?;
            Ok(data.len())
```

to:

```rust
        if self.chunked {
            // Write chunk header: hex size + \r\n (stack-formatted, no alloc).
            let mut hex_buf = [0u8; HEX_BUF_LEN];
            let n = write_hex_usize(data.len(), &mut hex_buf);
            self.write_all(&hex_buf[..n]).await?;
            self.write_all(data).await?;
            self.write_all(b"\r\n").await?;
            Ok(data.len())
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check 2>&1 | head -10`

Expected: Clean compile.

- [ ] **Step 4: Commit**

```bash
git add src/net/http/response.rs
git commit -m "perf(net::http): Stack-format chunk hex size in write_body

Replace format!(\"{:x}\\r\\n\", len) with write_hex_usize() that formats
into a [u8; HEX_BUF_LEN] stack buffer. Zero heap allocation per chunk."
```

---

### Task 3: Update tests + final verification

**Files:**
- Modify: `src/net/http/response.rs`

- [ ] **Step 1: Replace deleted-function tests with WriteBuffer-based tests**

Replace the entire `#[cfg(test)] mod tests` block. Change:

```rust
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
```

to:

```rust
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
```

- [ ] **Step 2: Run cargo check and tests**

Run: `cargo check 2>&1 | head -10 && cargo test --lib 2>&1 | tail -10`

Expected: Clean compile, all tests pass (including the new hex and cow tests).

- [ ] **Step 3: Run cargo fmt and clippy**

Run: `cargo fmt && cargo clippy 2>&1 | head -20`

Expected: No issues.

- [ ] **Step 4: Commit**

```bash
git add src/net/http/response.rs
git commit -m "test(net::http): Update response tests for zero-alloc rewrite

Replace format_status_line/format_header tests (deleted functions) with
write_hex_usize tests and Cow status reason verification."
```

---

### Task 4: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test --lib 2>&1 | tail -10`

Expected: All tests pass.

- [ ] **Step 2: Verify the changes**

Run: `git diff HEAD~3 --stat`

Expected: 1 file changed — `src/net/http/response.rs`.
