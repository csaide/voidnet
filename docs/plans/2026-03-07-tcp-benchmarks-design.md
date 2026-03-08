# TCP Per-Connection Benchmarks Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Measure per-connection TCP throughput and latency over a veth pair using criterion, and validate data integrity under sustained load.

**Architecture:** Two criterion benchmark files (`tcp_throughput`, `tcp_latency`), each using `iter_custom` to time only the data transfer phase. Each benchmark creates a `TestVethPair`, spawns two threads (server + client) with independent `LocalRuntime` instances, and coordinates via barriers and channels.

**Tech Stack:** criterion 0.8, `TestVethPair`, `LocalRuntime`, `TcpListener`/`TcpStream`

---

## Benchmarks

### 1. Throughput (`benches/tcp_throughput.rs`)

- Client sends 1 GB in 64 KB chunks over a single TCP connection
- Server reads into a 64 KB buffer, discards data, counts bytes
- Client calls `shutdown()` after sending; server reads until EOF
- Data integrity: client fills each chunk with `(byte_offset % 251) as u8`, server computes a running checksum, panics on mismatch
- Criterion config: 10 samples, 60s measurement time
- Reports: GB/s (criterion handles statistical analysis)

### 2. Latency (`benches/tcp_latency.rs`)

- Two parameter groups: 64 bytes and 1 KB payloads
- Server runs an echo loop (read N bytes, write N bytes back)
- Client sends a message, reads back full response, repeats 10,000 times per criterion sample
- Client verifies each response matches the sent payload
- Criterion config: 10 samples, 30s measurement time
- Reports: per-round-trip latency with min/avg/p50/p99/max (criterion built-in)

## Thread Coordination

- Each benchmark creates `TestVethPair` once per group (not per iteration)
- Server thread: `LocalRuntime::run()` with `Arc<AtomicBool>` exit flag
- Client thread: `LocalRuntime::run()` with the benchmark workload
- `std::sync::Barrier` ensures both runtimes are up before client connects
- After measurement, client signals server via exit flag

## Cargo.toml

```toml
[[bench]]
name = "tcp_throughput"
harness = false

[[bench]]
name = "tcp_latency"
harness = false
```

## Running

```bash
cargo bench --bench tcp_throughput
cargo bench --bench tcp_latency
```

Requires root (handled by `.cargo/config.toml` via `sudo -E`).

## Out of Scope

- Artificial loss injection (deferred)
- Comparison against kernel TCP
- Custom reporting dashboard
- Multi-connection benchmarks (deferred to connection management phase)
- `--json` output (criterion has its own HTML reports)
