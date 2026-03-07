# TCP Echo Examples — End-to-End Validation Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prove the TCP stack works end-to-end on real hardware by writing echo server and client examples.

**Architecture:** Two standalone examples (`tcp-echo-server.rs`, `tcp-echo-client.rs`) mirroring the existing UDP example pattern. No library code changes — pure validation of existing TCP implementation.

**Tech Stack:** Existing `libvoid` TCP socket API (`TcpListener`, `TcpStream`), `clap` for CLI args, `ctrlc` for signal handling.

---

## TCP Echo Server (`examples/tcp-echo-server.rs`)

**Args:**
- All `BaseArgs` (interface, queue, XDP options)
- `--local-addr` — listen address (default `[fc00:dead:cafe:1::1]:8080`)

**Behavior:**
1. Build `LocalRuntime` from args
2. Set up Ctrl-C exit flag
3. Inside `runtime.run()`:
   - `TcpListener::listen(addr, port)`
   - Loop: `let stream = listener.accept().await`
   - Per connection: read into buffer, echo back, track stats
   - On read returning 0 (EOF): log disconnect, accept next connection
4. Single-connection handling (no concurrent task spawning)

**Stats:** Reuse existing `Stats` struct — bytes echoed, periodic printing.

## TCP Echo Client (`examples/tcp-echo-client.rs`)

**Args:**
- All `BaseArgs` (interface, queue, XDP options)
- `--local-addr` — client bind address (default `[fc00:dead:cafe:1::2]:8080`)
- `--remote-addr` — server address (default `[fc00:dead:cafe:1::1]:8080`)
- `--message-size` — payload size in bytes (default 64)

**Behavior:**
1. Build `LocalRuntime` from args
2. Set up Ctrl-C exit flag
3. Inside `runtime.run()`:
   - `TcpStream::connect(local, local_port, remote, remote_port)?.await?`
   - Loop: write fixed-size payload → read echo → verify length → update stats
   - On Ctrl-C: stream drops, triggers graceful FIN close

**Payload:** Fixed-size buffer allocated once. No content verification — length check only.

**Stats:** Same `Stats` struct, tracking round-trips and bytes.

## What This Validates

**Exercised paths:**
- Full 3-way handshake (SYN → SYN-ACK → ACK)
- Bidirectional data transfer through ring buffers
- Flow control (send/receive windows)
- Congestion control (slow start ramp-up)
- RTT estimation under real latency
- Graceful teardown on drop (FIN/ACK exchange)
- Frame accounting (`debug_assert` in runtime loop)
- Checksum computation (or offload) on real NIC

**Not exercised (deferred):**
- Retransmission under packet loss
- Out-of-order reassembly
- Multiple concurrent connections
- Half-close, keep-alive, linger

## Scope

Two new files only:
- `examples/tcp-echo-server.rs`
- `examples/tcp-echo-client.rs`

No library code changes.
