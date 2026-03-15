# SIMD Optimization Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Maximize packet throughput via NEON-accelerated checksums and SIMD-optimized HTTP byte scanning.

**Architecture:** Two independent changes: (1) hand-rolled NEON intrinsics for RFC 1071 checksum `sum_words_carry()` with scalar fallback, (2) `memchr` crate for all HTTP byte scanning. Both use `#[cfg(target_arch)]` dispatch, no feature flags.

**Tech Stack:** Rust 2024 edition, aarch64 NEON via `std::arch::aarch64`, `memchr` crate, `criterion` benchmarks.

**Spec:** `docs/superpowers/specs/2026-03-14-simd-optimization-design.md`

---

## Chunk 1: memchr Integration

### Task 1: Add `memchr` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add memchr to dependencies**

Add to the `[dependencies]` section in `Cargo.toml`:

```toml
memchr = { version = "2", default-features = false }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check`
Expected: success

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add memchr for SIMD-optimized byte scanning"
```

---

### Task 2: Replace byte scans in `parse.rs`

**Files:**
- Modify: `src/net/http/codec/parse.rs:1-14,19-21,104,117,248,285-291,362`

- [ ] **Step 1: Add memchr import**

At the top of `src/net/http/codec/parse.rs`, add:

```rust
use memchr::{memchr, memrchr, memmem};
```

- [ ] **Step 2: Replace `memchr_newline()`**

Replace the body of `memchr_newline()` (line 19-21):

```rust
pub(crate) fn memchr_newline(buf: &[u8]) -> Option<usize> {
    memchr(b'\n', buf)
}
```

- [ ] **Step 3: Replace `find_header_terminator()`**

Replace the body of `find_header_terminator()` (lines 284-292):

```rust
fn find_header_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = memmem::find(buf, b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = memmem::find(buf, b"\n\n") {
        return Some((pos, 2));
    }
    None
}
```

- [ ] **Step 4: Replace space/colon scans in `parse_request_line()`**

In `parse_request_line()`, replace the first space search (line 104):

```rust
let first_space = match memchr(b' ', line) {
```

Replace the last space search (line 117):

```rust
let last_space = match memrchr(b' ', after_method) {
```

- [ ] **Step 5: Replace colon scan in `parse_header_line()`**

In `parse_header_line()` (line 248):

```rust
let colon = match memchr(b':', line) {
```

- [ ] **Step 6: Replace rposition in `detect_version()`**

In `detect_version()` (line 362):

```rust
match memrchr(b' ', line) {
```

- [ ] **Step 7: Run tests to verify correctness**

Run: `cargo test`
Expected: all tests pass — behavior is identical

- [ ] **Step 8: Commit**

```bash
git add src/net/http/codec/parse.rs
git commit -m "perf(http): replace manual byte scans with memchr"
```

---

### Task 3: Replace byte scans in `body.rs` and `v0_9.rs`

**Files:**
- Modify: `src/net/http/body.rs:204`
- Modify: `src/net/http/codec/v0_9.rs:55`

- [ ] **Step 1: Replace newline scan in `body.rs`**

In `src/net/http/body.rs`, add import at top:

```rust
use memchr::memchr;
```

Replace the newline scan in `read_chunk_size()` (line 204):

```rust
if let Some(pos) = memchr(b'\n', buffered) {
```

- [ ] **Step 2: Replace space scan in `v0_9.rs`**

In `src/net/http/codec/v0_9.rs`, add import at top:

```rust
use memchr::memchr;
```

Replace the space scan (line 55):

```rust
let space_pos = match memchr(b' ', line) {
```

- [ ] **Step 3: Run tests to verify correctness**

Run: `cargo test`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add src/net/http/body.rs src/net/http/codec/v0_9.rs
git commit -m "perf(http): replace remaining manual byte scans with memchr"
```

---

### Task 4: HTTP parse benchmarks

**Files:**
- Create: `benches/http_parse.rs`
- Modify: `Cargo.toml` (add `[[bench]]` entry)

- [ ] **Step 1: Add bench entry to Cargo.toml**

Add at the end of `Cargo.toml`:

```toml
[[bench]]
name = "http_parse"
harness = false
```

- [ ] **Step 2: Write the benchmark**

Create `benches/http_parse.rs`:

```rust
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn make_request(header_count: usize) -> Vec<u8> {
    let mut buf = b"GET /index.html HTTP/1.1\r\n".to_vec();
    for i in 0..header_count {
        buf.extend_from_slice(format!("X-Header-{i}: value-{i}\r\n").as_bytes());
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

fn bench_find_terminator(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_header_terminator");
    for count in [2, 8, 32] {
        let buf = make_request(count);
        group.bench_with_input(
            BenchmarkId::new("headers", count),
            &buf,
            |b, buf| {
                b.iter(|| {
                    // Search for \r\n\r\n the same way the parser does
                    let _ = memchr::memmem::find(buf, b"\r\n\r\n");
                });
            },
        );
    }
    group.finish();
}

fn bench_memchr_newline(c: &mut Criterion) {
    let mut group = c.benchmark_group("memchr_newline");
    let buf = b"GET /index.html HTTP/1.1\r\n";
    group.bench_function("request_line", |b| {
        b.iter(|| {
            let _ = memchr::memchr(b'\n', buf);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_find_terminator, bench_memchr_newline);
criterion_main!(benches);
```

- [ ] **Step 3: Run the benchmark**

Run: `cargo bench --bench http_parse`
Expected: benchmark results printed

- [ ] **Step 4: Commit**

```bash
git add benches/http_parse.rs Cargo.toml
git commit -m "bench: add HTTP parse benchmarks for memchr scanning"
```

---

## Chunk 2: NEON Checksum

### Task 5: Create NEON `sum_words_carry` implementation

**Files:**
- Create: `src/net/checksum/neon.rs`
- Modify: `src/net/checksum/mod.rs`

- [ ] **Step 1: Add neon module to mod.rs**

In `src/net/checksum/mod.rs`, add after line 3 (`mod verify;`):

```rust
#[cfg(target_arch = "aarch64")]
mod neon;
```

- [ ] **Step 2: Write the NEON implementation**

Create `src/net/checksum/neon.rs`:

```rust
//! NEON-accelerated RFC 1071 internet checksum.
//!
//! On little-endian aarch64, network (big-endian) data loaded via `vld1q_u8`
//! and reinterpreted as u16 gives byte-swapped words. We use `vrev16q_u8` to
//! byte-reverse within each 16-bit element, producing proper big-endian u16
//! values that match the scalar path's intermediate representation exactly.
//! This is critical for `sum_words_carry` where partial sums are threaded
//! across fragments.

use std::arch::aarch64::*;

/// NEON-accelerated version of `sum_words_carry`.
///
/// Processes 32 bytes per iteration using 128-bit NEON vectors.
/// Falls back to scalar for the tail (< 32 bytes).
///
/// Produces the same intermediate `sum` values as the scalar path,
/// so partial sums can be safely mixed across fragments.
///
/// # Safety
///
/// Requires aarch64 NEON support (guaranteed on all AArch64 CPUs).
#[inline]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn sum_words_carry_neon(
    data: &[u8],
    mut sum: u64,
    pending: Option<u8>,
) -> (u64, Option<u8>) {
    let len = data.len();
    let mut i = 0;

    // Handle pending byte from previous fragment.
    if let Some(hi) = pending {
        if len > 0 {
            sum += ((hi as u64) << 8) | (data[0] as u64);
            i = 1;
        } else {
            return (sum, Some(hi));
        }
    }

    // NEON accumulator: 4x u64 lanes.
    // We accumulate u32 values (widened from u16) so u64 lanes
    // prevent overflow even for jumbo frames.
    let mut acc = unsafe { vdupq_n_u64(0) };

    while i + 31 < len {
        // Load 32 bytes as two 128-bit u8 vectors.
        let v0 = unsafe { vld1q_u8(data.as_ptr().add(i)) };
        let v1 = unsafe { vld1q_u8(data.as_ptr().add(i + 16)) };

        // Byte-reverse within each 16-bit element:
        //   [B0, B1, B2, B3, ...] → [B1, B0, B3, B2, ...]
        // On LE aarch64, reinterpreting [B1, B0] as u16 gives B0*256 + B1,
        // which is the big-endian u16 value — matching scalar exactly.
        let rev0 = unsafe { vrev16q_u8(v0) };
        let rev1 = unsafe { vrev16q_u8(v1) };

        // Reinterpret as u16 (now proper big-endian values).
        let words0 = unsafe { vreinterpretq_u16_u8(rev0) };
        let words1 = unsafe { vreinterpretq_u16_u8(rev1) };

        // Widen u16 → u32 via pairwise add-accumulate.
        let sum32_0 = unsafe { vpaddlq_u16(words0) };
        let sum32_1 = unsafe { vpaddlq_u16(words1) };

        // Widen u32 → u64 and accumulate.
        acc = unsafe { vpadalq_u32(acc, sum32_0) };
        acc = unsafe { vpadalq_u32(acc, sum32_1) };

        i += 32;
    }

    // Horizontal reduce: sum both u64 lanes into the scalar accumulator.
    sum += unsafe { vgetq_lane_u64(acc, 0) } + unsafe { vgetq_lane_u64(acc, 1) };

    // Scalar tail: handle remaining bytes (< 32).
    while i + 3 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        sum += ((data[i + 2] as u64) << 8) | (data[i + 3] as u64);
        i += 4;
    }

    if i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        return (sum, Some(data[i]));
    }

    (sum, None)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check`
Expected: success

- [ ] **Step 4: Commit**

```bash
git add src/net/checksum/neon.rs src/net/checksum/mod.rs
git commit -m "feat(checksum): add NEON-accelerated sum_words_carry"
```

---

### Task 6: Wire NEON dispatch into `sum_words_carry()`

**Files:**
- Modify: `src/net/checksum/common.rs:22-33`

- [ ] **Step 1: Add conditional dispatch**

In `src/net/checksum/common.rs`, replace the `sum_words_carry` function (lines 22-103) with a version that dispatches to NEON. Add the NEON dispatch at the top of the function body, after the `pending` handling block (after line 33):

Insert after the closing brace of the `if let Some(hi) = pending` block (line 33), before the `// Process 32 bytes` comment:

```rust
    // NEON fast path for large data on aarch64.
    #[cfg(target_arch = "aarch64")]
    {
        if len - i >= 32 {
            // Safety: aarch64 always has NEON.
            return unsafe { super::neon::sum_words_carry_neon(&data[i..], sum, None) };
        }
    }
```

Note: we pass `None` for pending because any pending byte was already consumed above. The remaining data from index `i` onward has no pending byte.

- [ ] **Step 2: Run all tests to verify NEON produces identical results**

Run: `cargo test`
Expected: all checksum tests pass — NEON path is now exercised on aarch64

- [ ] **Step 3: Commit**

```bash
git add src/net/checksum/common.rs
git commit -m "perf(checksum): dispatch to NEON sum_words_carry on aarch64"
```

---

### Task 7: Checksum benchmarks

**Files:**
- Create: `benches/checksum.rs`
- Modify: `Cargo.toml` (add `[[bench]]` entry)

- [ ] **Step 1: Add bench entry to Cargo.toml**

Add at the end of `Cargo.toml`:

```toml
[[bench]]
name = "checksum"
harness = false
```

- [ ] **Step 2: Write the benchmark**

Create `benches/checksum.rs`:

```rust
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use libvoid::net::checksum::{sum_words, sum_words_carry};

fn bench_sum_words(c: &mut Criterion) {
    let mut group = c.benchmark_group("sum_words");
    for size in [64, 256, 1500, 9000] {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("bytes", size),
            &data,
            |b, data| {
                b.iter(|| sum_words(data));
            },
        );
    }
    group.finish();
}

fn bench_sum_words_carry_odd_pending(c: &mut Criterion) {
    let mut group = c.benchmark_group("sum_words_carry_odd");
    let data: Vec<u8> = (0..1499).map(|i| (i & 0xFF) as u8).collect();
    group.bench_function("1499B_pending", |b| {
        b.iter(|| sum_words_carry(&data, 0, Some(0xAB)));
    });
    group.finish();
}

criterion_group!(benches, bench_sum_words, bench_sum_words_carry_odd_pending);
criterion_main!(benches);
```

- [ ] **Step 3: Expose checksum functions for benchmarks**

The functions are `pub(crate)` and the `checksum` module is `pub(crate)` in `src/net/mod.rs`. Benchmarks are external crates and need public access. Make these changes:

In `src/net/mod.rs`, change line 1:

```rust
#[doc(hidden)]
pub mod checksum;
```

In `src/net/checksum/mod.rs`, add public re-exports after the existing `pub(crate) use` blocks:

```rust
// Exposed for benchmarks only.
#[doc(hidden)]
pub use common::{sum_words, sum_words_carry};
```

Note: `src/net/mod.rs` is already `pub mod net;` in `src/lib.rs`, so this chain (`lib → net → checksum → sum_words`) makes the functions accessible as `libvoid::net::checksum::sum_words`.

- [ ] **Step 4: Run the benchmark**

Run: `cargo bench --bench checksum`
Expected: benchmark results printed

Follow-up: after initial results, experiment with lowering the dispatch threshold
in `common.rs` from 32 to 16 bytes and re-run benchmarks. For small UDP/ICMP
packets (16-31 bytes), one NEON iteration + scalar tail may still beat pure scalar.
Choose whichever threshold benchmarks faster and commit the winner.

- [ ] **Step 5: Commit**

```bash
git add benches/checksum.rs Cargo.toml src/net/checksum/mod.rs
git commit -m "bench: add checksum benchmarks for NEON vs scalar"
```
