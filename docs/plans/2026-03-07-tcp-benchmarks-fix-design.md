# TCP Benchmarks Fix Design

## Problem

Both `tcp_throughput.rs` and `tcp_latency.rs` benchmarks create and tear down the
full infrastructure (TestVethPair, LocalRuntime, TCP connection) on every criterion
iteration. The measured time is dominated by setup/teardown, not actual TCP
performance. These benchmarks produce meaningless numbers.

## Solution: Iteration Inside Async Future

Move the criterion iteration loop inside the async future passed to
`runtime.run()`. Create the veth pair once at benchmark group level. Each
`iter_custom` sample spawns threads and runtimes once, establishes one TCP
connection, then iterates over the actual measured work.

### Throughput

- `TestVethPair` created once, outside `bench_function`
- `AtomicU16` port counter avoids TIME_WAIT between samples
- Server: sink loop (read until EOF)
- Client async future: connect, then `for _ in 0..iters { send TRANSFER_SIZE }`
- Timing wraps only the send loop, not connection setup
- Remove integrity checking from throughput (CPU overhead pollutes measurement)
- Remove `WaitForFlag` — use exit flag from main thread after client joins

### Latency

- Same veth-outside, port-counter pattern
- Server: echo loop (read → write back)
- Client async future: connect, then `for _ in 0..iters { ROUND_TRIPS × (write → read) }`
- Return raw elapsed — criterion divides by `iters`, each iteration = ROUND_TRIPS round trips
- Keep echo integrity check (lightweight, validates correctness)
- Eliminate `run_latency_iteration()` entirely

### Thread Coordination

Both benchmarks use:
- `Barrier::new(2)` for server-ready synchronization
- `mpsc::channel` for elapsed time from client to main thread
- `Arc<AtomicBool>` exit flag for server shutdown (set after client joins)
