# SIMD Optimization Design — VoidNet

**Date:** 2026-03-14
**Approach:** Crate-first + hand-rolled intrinsics where no crate exists
**Target:** aarch64 NEON first, architected for x86_64 AVX2/SSE2 later

## Goals

Maximize packet throughput by applying SIMD to the two hottest paths in the
stack: internet checksum computation (every packet) and HTTP byte scanning
(every HTTP request/response).

## Non-Goals

- Portable `std::simd` (unstable, not ready)
- SIMD for case-insensitive header compare (inputs too short)
- Abstraction layer over NEON/AVX2 (premature — validate the NEON path first)
- Feature flags for SIMD on/off (always-on via `#[cfg(target_arch)]`)

---

## 1. Checksum SIMD — NEON-accelerated `sum_words_carry()`

### Location

- New file: `src/net/checksum/neon.rs` (behind `#[cfg(target_arch = "aarch64")]`)
- Modified: `src/net/checksum/common.rs` — conditional dispatch
- Modified: `src/net/checksum/mod.rs` — add `mod neon`

### Design

The existing `sum_words_carry()` processes 32 bytes/iteration using 4x scalar
u64 reads with bitwise extraction. The NEON replacement:

1. **Load** 32 bytes per iteration via 2x `vld1q_u8` (128-bit loads)
2. **Byte-reverse** within each 16-bit element via `vrev16q_u8`, then
   reinterpret as u16 via `vreinterpretq_u16_u8`. On LE aarch64, this
   produces proper big-endian u16 values matching the scalar path exactly.
   This is critical for `sum_words_carry` where partial sums are threaded
   across fragments — intermediate values must be representation-compatible.
3. **Widen** u16 → u32 via `vpaddlq_u16`, then u32 → u64 via `vpadalq_u32`
4. **Horizontal reduce** after the loop by extracting both u64 lanes
5. **Scalar tail** handles remaining bytes (< 32) with existing code

**Dispatch threshold:** Start at 32 bytes (two NEON iterations minimum).
Benchmark a 16-byte threshold during implementation — for small UDP/ICMP
packets (16–31 bytes), one NEON iteration + scalar tail may still beat pure
scalar.

### Dispatch

```rust
// In common.rs — sum_words_carry():
#[cfg(target_arch = "aarch64")]
{
    if data.len() >= 32 {
        return neon::sum_words_carry_neon(data, sum, pending);
    }
}
// existing scalar code follows as fallback
```

### Correctness

All existing checksum tests validate the scalar path. The NEON path must
produce bit-identical results — same tests cover both paths on aarch64.

### x86_64 Future

Add `src/net/checksum/avx2.rs` with the same function signature. The dispatch
in `common.rs` gains one more `#[cfg]` arm. AVX2 can process 32 bytes via
`_mm256_maddubs_epi16` + `_mm256_madd_epi16` for the byte-pair → u16 → u32
widening.

---

## 2. HTTP Byte Scanning — `memchr` Crate

### Location

- Modified: `Cargo.toml` — add `memchr` dependency
- Modified: `src/net/http/codec/parse.rs` — replace manual scans
- Modified: `src/net/http/body.rs` — replace chunk newline scan
- Modified: `src/net/http/codec/v0_9.rs` — replace space scan in request line

### Replacements

| Current code | Replacement | Function |
|---|---|---|
| `buf.iter().position(\|&b\| b == b'\n')` | `memchr::memchr(b'\n', buf)` | `memchr_newline()` |
| `buf.windows(4).position(\|w\| w == b"\r\n\r\n")` | `memchr::memmem::find(buf, b"\r\n\r\n")` | `find_header_terminator()` |
| `buf.windows(2).position(\|w\| w == b"\n\n")` | `memchr::memmem::find(buf, b"\n\n")` | `find_header_terminator()` |
| `line.iter().position(\|&b\| b == b' ')` | `memchr::memchr(b' ', line)` | `parse_request_line()` |
| `line.iter().rposition(\|&b\| b == b' ')` | `memchr::memrchr(b' ', line)` | `parse_request_line()` |
| `line.iter().position(\|&b\| b == b':')` | `memchr::memchr(b':', line)` | `parse_header_line()` |
| `line.iter().rposition(\|&b\| b == b' ')` | `memchr::memrchr(b' ', line)` | `detect_version()` |
| `buffered.iter().position(\|&b\| b == b'\n')` | `memchr::memchr(b'\n', buffered)` | `body.rs:read_chunk_size()` |
| `line.iter().position(\|&b\| b == b' ')` | `memchr::memchr(b' ', line)` | `v0_9.rs` request parse |

### What stays scalar

- Whitespace trimming in `parse_header_line()` — operates on very short slices
  (header values after colon). SIMD overhead would exceed benefit.
- Chunk extension semicolon scan in `body.rs:read_chunk_size()` — operates on
  a single already-extracted line (typically < 10 bytes).

### Why `memchr`

- Zero dependencies, `no_std`-compatible
- Auto-selects NEON on aarch64, AVX2/SSE2 on x86_64
- Battle-tested (used by regex, ripgrep, serde, etc.)
- x86_64 SIMD comes free — no hand-rolling needed

---

## 3. What We're NOT Doing

### Case-insensitive compare (`bytes_eq_ignore_case`)

Header names are 4–20 bytes. SIMD setup cost exceeds scalar loop at these
sizes. Called at most 64 times per request. If this ever bottlenecks, perfect
hashing on header names is the right fix, not SIMD.

### Ring buffer operations

`copy_from_slice()` and `copy_within()` already compile to optimized memcpy/
memmove. No improvement possible.

### IPv6 address checks

`is_unspecified()` does 16 byte comparisons but is typically const-folded.
Not worth the complexity.

---

## 4. Benchmarks

New directory: `benches/`

### `benches/checksum.rs`

Criterion benchmarks comparing scalar vs NEON `sum_words_carry()`:
- 64B (minimum IP packet)
- 256B (typical small packet)
- 1500B (standard MTU)
- 9000B (jumbo frame)
- 1499B with `pending = Some(0xAB)` (odd-length cross-fragment edge case)

Note: `criterion` is already in `[dev-dependencies]`.

### `benches/http_parse.rs`

Criterion benchmarks for HTTP scanning:
- `find_header_terminator()` on 256B–4KB buffers
- `memchr_newline()` on typical request lines

### Cargo.toml additions

```toml
[[bench]]
name = "checksum"
harness = false

[[bench]]
name = "http_parse"
harness = false
```

---

## 5. File Summary

| File | Action |
|---|---|
| `Cargo.toml` | Add `memchr` dep, bench entries |
| `src/net/checksum/mod.rs` | Add `#[cfg] mod neon` |
| `src/net/checksum/neon.rs` | **New** — NEON checksum intrinsics |
| `src/net/checksum/common.rs` | Dispatch to NEON when available |
| `src/net/http/codec/parse.rs` | Replace manual scans with `memchr` |
| `src/net/http/body.rs` | Replace chunk newline scan with `memchr` |
| `src/net/http/codec/v0_9.rs` | Replace space scan with `memchr` |
| `benches/checksum.rs` | **New** — checksum benchmarks |
| `benches/http_parse.rs` | **New** — HTTP parse benchmarks |
