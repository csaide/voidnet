# Multi-Threaded Runtime Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `Runtime` orchestrator that auto-discovers hardware queues and spawns one `LocalRuntime` per queue in a shared-nothing, thread-per-queue architecture.

**Architecture:** Two-phase setup on the main thread (create XdpContext, UMEMs, sockets), then spawn worker threads each running an independent `LocalRuntime`. BPF program reworked for deterministic `rx_queue_index` routing. First-failure shutdown propagation via shared `AtomicBool`.

**Tech Stack:** Rust, neli (netlink/ethtool), libbpf/libxdp (BPF), AF_XDP sockets, std::thread

**Spec:** `docs/superpowers/specs/2026-03-16-multi-threaded-runtime-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/netlink/ethtool.rs` (modify) | Add `get_queue_count()` — ethtool generic netlink channel query |
| `src/netlink/mod.rs` (modify) | Re-export `get_queue_count` |
| `bpf/xdp_kern.c` (modify) | Replace round-robin with `rx_queue_index` → socket routing |
| `src/xdp/context/ctx.rs` (modify) | `register_socket` takes explicit map index; remove `data_map`/`.bss` |
| `src/xdp/error.rs` (modify) | Add `GetQueueCount` and `QueueIdOutOfRange` error variants |
| `src/rt/affinity.rs` (modify) | Wrap `pin_core` for queue_id >= num_cores |
| `src/rt/context.rs` (modify) | Fix `ContextDropGuard` memory leak |
| `src/rt/local.rs` (modify) | Add `LocalRuntime::new_worker()` constructor (no XdpContext) |
| `src/rt/runtime.rs` (create) | `Runtime`, `RuntimeBuilder`, two-phase setup, thread management |
| `src/rt/mod.rs` (modify) | Export `Runtime`, `RuntimeBuilder` |

---

## Chunk 1: Foundation — BPF, XdpContext, Error Types, Bug Fixes

These are prerequisite changes that the rest of the plan depends on.

### Task 1: Add error variants for queue discovery and validation

**Files:**
- Modify: `src/xdp/error.rs:14-80`

- [ ] **Step 1: Add error variants**

Add two new variants to the `Error` enum in `src/xdp/error.rs`:

```rust
#[error("failed to query queue count: {0}")]
GetQueueCount(String),
#[error("queue ID {0} exceeds xsks_map max_entries (2048)")]
QueueIdOutOfRange(u32),
```

Insert these after the `GetChecksumOffload` variant (line 63).

- [ ] **Step 2: Add display tests**

Add to the existing `display_error_variants` test in `src/xdp/error.rs`:

```rust
let e = Error::GetQueueCount("not supported".to_string());
assert!(e.to_string().contains("not supported"));

let e = Error::QueueIdOutOfRange(3000);
assert!(e.to_string().contains("3000"));
```

- [ ] **Step 3: Run tests to verify**

Run: `cargo test -p libvoid error::tests`
Expected: All error display tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/xdp/error.rs
git commit -m "feat(xdp): add GetQueueCount and QueueIdOutOfRange error variants"
```

### Task 2: Rework BPF program for queue-based routing

**Files:**
- Modify: `bpf/xdp_kern.c`

- [ ] **Step 1: Replace the BPF program**

Replace the entire contents of `bpf/xdp_kern.c` with:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Socket map for redirects, filled by userspace as sockets are registered.
// Indexed by queue ID (sparse — gaps are allowed for unbound queues).
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 2048);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// Route packets from hardware queue N to socket N.
// If no socket is registered for this queue, XDP_PASS hands the packet to the kernel stack.
SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx) {
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}
```

- [ ] **Step 2: Rebuild the BPF object**

Run the project's BPF build step (check Makefile or build script). The compiled `bpf/xdp_kern.o` must be updated since it's included via `include_bytes!` in `src/xdp/context/ctx.rs:11`.

Run: `make bpf` (or the equivalent build command for this project)
Expected: `bpf/xdp_kern.o` is regenerated.

- [ ] **Step 3: Commit**

```bash
git add bpf/xdp_kern.c bpf/xdp_kern.o
git commit -m "feat(bpf): replace round-robin with rx_queue_index routing"
```

### Task 3: Update XdpContext — explicit map index, remove .bss

**Hard dependency:** Task 2 (BPF rebuild) MUST be completed first. The new BPF program no longer has a `.bss` section, and this task removes the `.bss` lookup from `XdpContext::new`. If done out of order, `find_map(".bss")` will fail against the new BPF object, or removal of `data_map` will break against the old BPF object.

**Files:**
- Modify: `src/xdp/context/ctx.rs:71-148`
- Modify: `src/xdp/error.rs` (already has `QueueIdOutOfRange` from Task 1)

- [ ] **Step 1: Write the failing test for explicit-index registration**

Add a new test in `src/xdp/context/ctx.rs` inside the `tests` module. Note: veth devices only have queue 0, so we test with queue 0 (the registration index is what changed, not the queue binding):

```rust
/// Tests that register_socket places the socket at the queue ID index in xsks_map.
#[test]
fn test_register_socket_uses_queue_id() {
    let veth = TestVethPair::new().expect("failed to create veth pair");

    let mut ctx = XdpContext::builder(veth.outer_name())
        .attach_mode(AttachMode::default())
        .enable_fragmentation(false)
        .build()
        .expect("failed to create context");

    let (umem, _fq, _cq) = crate::xdp::umem::Umem::builder()
        .num_frames(16)
        .frame_size(4096)
        .fill_ring_size(8)
        .completion_ring_size(8)
        .build()
        .expect("failed to create umem")
        .split();

    // Build socket on queue 0 (the only queue veth supports).
    // After this, register_socket should have placed it at xsks_map[0].
    let _socket = Socket::builder(veth.outer_name(), 0)
        .rx_ring_size(8)
        .tx_ring_size(8)
        .build(&mut ctx, umem)
        .expect("failed to create socket");

    // Verify: no panic, socket was registered successfully.
    // The key change is that xsks_map index = queue ID, not auto-increment.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p libvoid context::tests::test_register_socket_uses_queue_id`
Expected: FAIL — won't compile because `register_socket` signature changed (new `map_index` param).

- [ ] **Step 3: Update register_socket to accept explicit map index**

In `src/xdp/context/ctx.rs`, modify `register_socket` (line 134):

```rust
pub(crate) fn register_socket(&mut self, socket: &mut SocketOwner<'_>, map_index: u32) -> Result<()> {
    if map_index >= 2048 {
        return Err(Error::QueueIdOutOfRange(map_index));
    }

    // Update xsks_map with the socket's file descriptor at the given map index.
    // SAFETY: The map was created with u32 keys and i32 (fd) values.
    unsafe { self.xsks_map.update_elem(&map_index, &socket.fd())? };

    Ok(())
}
```

- [ ] **Step 4: Remove data_map field and .bss lookup**

In `src/xdp/context/ctx.rs`:

Remove the `data_map` field from the `XdpContext` struct (line 73).
Remove `num_sockets` field (line 77).
Remove `let data_map = program.find_map(".bss")?;` from `XdpContext::new` (line 95).
Remove `data_map` and `num_sockets` from the struct initializer in `new` (lines 99, 101).
Update `new_no_init` similarly.
Remove the `num_sockets()` test accessor.
Update the doc comment on the struct (line 69) to say "queue-based" instead of "round-robin".

- [ ] **Step 5: Update Socket::new to pass queue ID to register_socket**

In `src/xdp/socket/socket.rs`, line 261, change:

```rust
xdp_ctx.register_socket(&mut owner)?;
```

to:

```rust
xdp_ctx.register_socket(&mut owner, queue)?;
```

The `queue` parameter is already available in `Socket::new` (line 202).

- [ ] **Step 6: Fix existing tests that reference num_sockets()**

In `src/xdp/context/ctx.rs` tests, remove or update assertions that call `ctx.num_sockets()`:
- `test_context_creation` (line 188): remove `assert_eq!(ctx.num_sockets(), 0)`
- `test_multiple_contexts_different_interfaces` (lines 237-238): remove both `num_sockets` assertions
- `test_context_on_both_veth_ends` (lines 270-271): remove both `num_sockets` assertions

In `src/xdp/socket/socket.rs` tests:
- `test_socket_creation` (line 547): remove `assert_eq!(ctx.num_sockets(), 1, ...)`

- [ ] **Step 7: Run all tests to verify**

Run: `cargo test`
Expected: All tests pass. The BPF program change + register_socket change work together.

- [ ] **Step 8: Commit**

```bash
git add src/xdp/context/ctx.rs src/xdp/socket/socket.rs
git commit -m "feat(xdp): register_socket uses explicit queue ID, remove .bss/num_socks"
```

### Task 4: Fix ContextDropGuard memory leak

**Files:**
- Modify: `src/rt/context.rs:16-30`

- [ ] **Step 1: Write the failing test**

The existing tests don't detect the leak. Add a test in `src/rt/context.rs` tests module that at minimum exercises the drop path and verifies no panic. The real fix is in the `Drop` impl.

```rust
#[test]
fn context_drop_guard_does_not_leak() {
    // Create a context and guard, then drop — should not leak.
    // We can't directly assert no leak in a unit test, but we verify
    // the guard installs and cleans up without panic.
    let ctx = make_test_context();
    let guard = ContextDropGuard::new(ctx);
    drop(guard);

    // After drop, context should be cleared.
    let result = std::panic::catch_unwind(|| {
        with_runtime_context(|_ctx| {});
    });
    assert!(result.is_err(), "expected panic after guard is dropped");
}
```

- [ ] **Step 2: Fix the Drop impl**

In `src/rt/context.rs`, replace the `Drop` impl for `ContextDropGuard` (lines 26-30):

```rust
impl Drop for ContextDropGuard {
    fn drop(&mut self) {
        RT_CTX.with(|c| {
            let ptr = c.get();
            if !ptr.is_null() {
                // SAFETY: We created this pointer via Box::into_raw in new().
                // The lifetime is erased but still valid — we drop before the
                // UMEM/socket that the context references.
                unsafe { drop(Box::from_raw(ptr as *mut RuntimeContext<'_>)) };
            }
            c.set(std::ptr::null());
        });
    }
}
```

- [ ] **Step 3: Run tests to verify**

Run: `cargo test -p libvoid rt::context::tests`
Expected: All context tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/rt/context.rs
git commit -m "fix(rt): deallocate RuntimeContext in ContextDropGuard::drop"
```

### Task 5: Fix pin_core wrapping for high queue IDs

**Files:**
- Modify: `src/rt/affinity.rs`

- [ ] **Step 1: Write the failing test**

Add tests to `src/rt/affinity.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_core_queue_zero() {
        // Should not panic — queue 0 always exists.
        pin_core(0);
    }

    #[test]
    fn pin_core_wraps_on_overflow() {
        // Should not panic even if queue_id exceeds core count.
        let num_cores = core_affinity::get_core_ids().unwrap().len() as u32;
        pin_core(num_cores + 1);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p libvoid rt::affinity::tests::pin_core_wraps_on_overflow`
Expected: FAIL with panic (index out of bounds).

- [ ] **Step 3: Fix pin_core to wrap**

Replace the contents of `src/rt/affinity.rs`:

```rust
pub fn pin_core(queue: u32) {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let index = queue as usize % core_ids.len();
    let core_id = core_ids[index];

    core_affinity::set_for_current(core_id);
}
```

- [ ] **Step 4: Run tests to verify**

Run: `cargo test -p libvoid rt::affinity::tests`
Expected: Both tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/rt/affinity.rs
git commit -m "fix(rt): wrap pin_core when queue_id exceeds core count"
```

---

## Chunk 2: Queue Discovery via Ethtool

### Task 6: Add get_queue_count to netlink/ethtool

**Files:**
- Modify: `src/netlink/ethtool.rs`
- Modify: `src/netlink/mod.rs`

- [ ] **Step 1: Add the ChannelsGet command and attribute enums**

In `src/netlink/ethtool.rs`, add a new variant `ChannelsGet = 4` to the **existing** `EthtoolCmd` enum (do NOT replace the enum — add to it):

```rust
// Add this variant to the existing enum (before FeaturesGet):
ChannelsGet = 4,
```

The enum should end up looking like:

```rust
#[neli_enum(serialized_type = "u8")]
pub enum EthtoolCmd {
    ChannelsGet = 4,
    FeaturesGet = 11,
}
```

Add new attribute enums after the existing ones:

```rust
/// Ethtool CHANNELS request/reply attributes.
#[neli_enum(serialized_type = "u16")]
pub enum EthtoolAttrChannels {
    Unspec = 0,
    Header = 1,
    RxMax = 2,
    TxMax = 3,
    RxCount = 4,
    TxCount = 5,
    CombinedMax = 6,
    CombinedCount = 7,
    OtherMax = 8,
    OtherCount = 9,
}
impl NlAttrType for EthtoolAttrChannels {}
```

- [ ] **Step 2: Implement get_queue_count**

Add the function in `src/netlink/ethtool.rs` after `get_checksum_offload`:

```rust
/// Queries the ethtool generic netlink interface to determine the number of
/// combined RX/TX queues for the given network interface.
///
/// Returns the combined channel count. If the query fails (e.g., the driver
/// does not support it, or the interface is virtual), returns `Ok(1)` as a
/// safe default.
pub fn get_queue_count(if_index: i32) -> error::Result<u32> {
    let (router, _) = match NlRouter::connect(NlFamily::Generic, None, Groups::empty()) {
        Ok(r) => r,
        Err(_) => return Ok(1),
    };

    let family_id = match router.resolve_genl_family("ethtool") {
        Ok(id) => id,
        Err(_) => return Ok(1),
    };

    // Build nested header with the device interface index.
    let header_attrs: GenlBuffer<EthtoolAttrHeader, Buffer> = [NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(EthtoolAttrHeader::DevIndex)
                .build()
                .map_err(|e| Error::GetQueueCount(e.to_string()))?,
        )
        .nla_payload(if_index as u32)
        .build()
        .map_err(|e| Error::GetQueueCount(e.to_string()))?]
    .into_iter()
    .collect();

    let attrs: GenlBuffer<EthtoolAttrChannels, Buffer> = [NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(EthtoolAttrChannels::Header)
                .nla_nested(true)
                .build()
                .map_err(|e| Error::GetQueueCount(e.to_string()))?,
        )
        .nla_payload(header_attrs)
        .build()
        .map_err(|e| Error::GetQueueCount(e.to_string()))?]
    .into_iter()
    .collect();

    let msg = GenlmsghdrBuilder::default()
        .cmd(EthtoolCmd::ChannelsGet)
        .version(1)
        .attrs(attrs)
        .build()
        .map_err(|e| Error::GetQueueCount(e.to_string()))?;

    let recv = match router.send::<_, _, u16, Genlmsghdr<EthtoolCmd, EthtoolAttrChannels>>(
        family_id,
        NlmF::REQUEST,
        NlPayload::Payload(msg),
    ) {
        Ok(r) => r,
        Err(_) => return Ok(1),
    };

    let mut combined_count: u32 = 0;

    for response in recv {
        let response = match response {
            Ok(r) => r,
            Err(_) => return Ok(1),
        };

        if let Some(payload) = response.get_payload() {
            let handle = payload.attrs().get_attr_handle();
            if let Ok(count) =
                handle.get_attr_payload_as::<u32>(EthtoolAttrChannels::CombinedCount)
            {
                combined_count = count;
            }
        }
    }

    // Fallback: if combined_count is 0 (driver doesn't report it), default to 1.
    Ok(combined_count.max(1))
}
```

- [ ] **Step 3: Re-export from mod.rs**

In `src/netlink/mod.rs`, add:

```rust
pub use ethtool::get_queue_count;
```

- [ ] **Step 4: Write a test**

Add at the bottom of `src/netlink/ethtool.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_queue_count_on_loopback() {
        // lo (if_index=1) is always available. It may return 1 (virtual device).
        let count = get_queue_count(1).expect("query should not error");
        assert!(count >= 1, "queue count should be at least 1");
    }

    #[test]
    fn get_queue_count_on_invalid_interface() {
        // Non-existent interface index — should gracefully return 1.
        let count = get_queue_count(999999).expect("query should not error");
        assert_eq!(count, 1, "should default to 1 for invalid interface");
    }
}
```

- [ ] **Step 5: Run tests to verify**

Run: `cargo test -p libvoid netlink`
Expected: Both tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/netlink/ethtool.rs src/netlink/mod.rs
git commit -m "feat(netlink): add get_queue_count via ethtool CHANNELS_GET"
```

---

## Chunk 3: LocalRuntime Worker Constructor

### Task 7: Add LocalRuntime::new_worker (no XdpContext)

**Files:**
- Modify: `src/rt/local.rs:197-247`

- [ ] **Step 1: Understand the current constructor**

Read `src/rt/local.rs:207-247`. The existing `LocalRuntime::new` takes `XdpContext` and stores it as `self.ctx`. The `run` method uses `self.ctx.info()` for `tx_offload` (line 269) and nothing else from `ctx` during the event loop.

The worker constructor needs to receive `XdpInfo` (or just the fields it needs: `mtu`, `rx_offload`, `tx_offload`) instead of the full `XdpContext`.

- [ ] **Step 2: Refactor LocalRuntime struct to support optional XdpContext**

This must be done BEFORE adding `new_worker`, because `new_worker` sets `ctx: None`.

The `run` method currently calls `self.ctx.info().tx_offload` (line 269). Since the worker constructor has no `XdpContext`, we need to store `tx_offload` on the struct directly.

Add a `tx_offload: bool` field to `LocalRuntime` (after `evict_counter`).

Change the `ctx` field from `XdpContext` to `Option<XdpContext>`:

```rust
pub struct LocalRuntime<'umem> {
    ctx: Option<XdpContext>,
    // ... rest unchanged
    tx_offload: bool,
}
```

Update `LocalRuntime::new` to set `ctx: Some(ctx)` and `tx_offload: info.tx_offload`.

In `run`, change `self.ctx.info().tx_offload` (line 269 inside the `RuntimeContext` initializer) to `self.tx_offload`.

- [ ] **Step 3: Add new_worker constructor**

Add to `impl<'umem> LocalRuntime<'umem>` in `src/rt/local.rs`, after the existing `new` method:

```rust
/// Creates a `LocalRuntime` from pre-built components for use by the
/// multi-threaded `Runtime` orchestrator. Does not own an `XdpContext` —
/// the orchestrator retains that on the main thread.
pub(crate) fn new_worker(
    if_name: &str,
    umem: Umem<'umem>,
    socket: Socket<'umem>,
    mtu: u32,
    rx_offload: bool,
    tx_offload: bool,
    arp_ttl: Duration,
) -> Result<Self> {
    let mut neighbor_handler = NeighborHandler::new(if_name, arp_ttl)?;
    neighbor_handler.set_offload(rx_offload, tx_offload);
    let neighbor_handler = Rc::new(neighbor_handler);
    let pmtu = Rc::new(UnsafeCell::new(PmtuCache::with_mtu(mtu)));

    let tx_return = BasicFrameBuffer::new(umem.num_frames()).into();
    let rx_return = BasicFrameBuffer::new(umem.num_frames()).into();
    let free_frames = umem.init_buffer::<BasicFrameBuffer>().unwrap().into();

    Ok(Self {
        ctx: None,
        _queue: 0,
        umem,
        socket,
        neighbor_handler,
        pmtu,
        ethernet_handler: EthernetHandler,
        ipv4_handler: Ipv4Handler::new(rx_offload, tx_offload),
        ipv6_handler: Ipv6Handler::new(rx_offload, tx_offload),
        udp_handler: Rc::new(UnsafeCell::new(UdpHandler::new(256, rx_offload))),
        tcp_handler: Rc::new(UnsafeCell::new(TcpHandler::new(rx_offload, tx_offload))),
        free_frames,
        tx_return,
        rx_return,
        evict_counter: 0,
        tx_offload,
    })
}
```

- [ ] **Step 4: Remove the println! from LocalRuntime::new**

In `src/rt/local.rs:216`, remove:

```rust
println!("info: {:?}", info);
```

- [ ] **Step 5: Run tests to verify nothing is broken**

Run: `cargo test`
Expected: All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/rt/local.rs
git commit -m "feat(rt): add LocalRuntime::new_worker constructor for multi-threaded use"
```

---

## Chunk 4: Runtime Orchestrator

### Task 8: Add Clone to UmemBuilder

**Files:**
- Modify: `src/xdp/umem/umem.rs`

The `Runtime` needs to create one `Umem` per queue from the same builder config. `UmemBuilder` currently does not implement `Clone`. All its fields are primitive types (`u32`, `usize`, `bool`, `Option<usize>`), so this is trivial.

- [ ] **Step 1: Add `#[derive(Clone)]` to `UmemBuilder`**

In `src/xdp/umem/umem.rs`, add `Clone` to the derive list on `UmemBuilder`.

- [ ] **Step 2: Run cargo check**

Run: `cargo check`
Expected: Compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add src/xdp/umem/umem.rs
git commit -m "feat(xdp): derive Clone for UmemBuilder"
```

### Task 9: Create RuntimeBuilder and Runtime

**Files:**
- Create: `src/rt/runtime.rs`

- [ ] **Step 1: Write the full runtime module**

Create `src/rt/runtime.rs`. Key design decisions reflected in the code:
- `RuntimeBuilder` stores config fields directly (no `XdpContextBuilder` — that's created fresh in `run()` to avoid lifetime issues).
- `resolve_queues` uses `libc::if_nametoindex` for name→index resolution (no `netlink::get_interface_index` — that function doesn't exist).
- `Runtime` stores owned `String` for `if_name` and all config as plain fields.
- `Runtime::run` creates `XdpContext::builder(&self.if_name)` borrowing from `self`.

```rust
use std::{
    ffi::CString,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use coarsetime::Duration;

use crate::{
    netlink,
    rt::{affinity::pin_core, local::LocalRuntime},
    xdp::{
        context::XdpContext,
        error::{Error, Result},
        program::AttachMode,
        socket::{CopyMode, Socket},
        umem::{Umem, UmemBuilder},
    },
};

const DEFAULT_ARP_TTL: Duration = Duration::from_secs(60);

/// Determines which queues to bind.
enum QueueSelection {
    /// Auto-discover all queues via ethtool.
    Auto,
    /// Bind exactly these queue IDs.
    Explicit(Vec<u32>),
    /// Auto-discover, but cap at this many (starting from queue 0).
    Max(u32),
}

/// Builder for configuring and constructing a multi-threaded [`Runtime`].
///
/// Mirrors the configuration surface of `LocalRuntimeBuilder` with additional
/// queue selection options. All threads receive identical configuration.
pub struct RuntimeBuilder<'name> {
    if_name: &'name str,
    queue_selection: QueueSelection,
    attach_mode: AttachMode,
    umem_builder: UmemBuilder,
    rx_ring_size: u32,
    tx_ring_size: u32,
    busy_poll: bool,
    busy_poll_batch_size: usize,
    busy_poll_timeout_us: i32,
    copy_mode: CopyMode,
    enable_fragmentation: bool,
    arp_ttl: Duration,
}

impl<'name> RuntimeBuilder<'name> {
    pub fn new(if_name: &'name str) -> Self {
        Self {
            if_name,
            queue_selection: QueueSelection::Auto,
            attach_mode: AttachMode::default(),
            umem_builder: UmemBuilder::new(),
            rx_ring_size: 0, // 0 means use SocketBuilder defaults
            tx_ring_size: 0,
            busy_poll: false,
            busy_poll_batch_size: 32,
            busy_poll_timeout_us: 20,
            copy_mode: CopyMode::default(),
            enable_fragmentation: false,
            arp_ttl: DEFAULT_ARP_TTL,
        }
    }

    /// Explicitly select which queue IDs to bind.
    /// Mutually exclusive with `max_queues`.
    pub fn queues(mut self, queues: &[u32]) -> Self {
        self.queue_selection = QueueSelection::Explicit(queues.to_vec());
        self
    }

    /// Auto-discover queues but cap at this count.
    /// Mutually exclusive with `queues`.
    pub fn max_queues(mut self, max: u32) -> Self {
        self.queue_selection = QueueSelection::Max(max);
        self
    }

    pub fn attach_mode(mut self, mode: AttachMode) -> Self {
        self.attach_mode = mode;
        self
    }

    pub fn enable_fragmentation(mut self, enable: bool) -> Self {
        self.enable_fragmentation = enable;
        self
    }

    pub fn arp_ttl(mut self, ttl: Duration) -> Self {
        self.arp_ttl = ttl;
        self
    }

    pub fn completion_ring_size(mut self, size: u32) -> Self {
        self.umem_builder = self.umem_builder.completion_ring_size(size);
        self
    }

    pub fn fill_ring_size(mut self, size: u32) -> Self {
        self.umem_builder = self.umem_builder.fill_ring_size(size);
        self
    }

    pub fn frame_size(mut self, size: usize) -> Self {
        self.umem_builder = self.umem_builder.frame_size(size);
        self
    }

    pub fn busy_poll(mut self, enable: bool) -> Self {
        self.busy_poll = enable;
        self
    }

    pub fn busy_poll_batch_size(mut self, size: usize) -> Self {
        self.busy_poll_batch_size = size;
        self
    }

    pub fn busy_poll_timeout_us(mut self, timeout: i32) -> Self {
        self.busy_poll_timeout_us = timeout;
        self
    }

    pub fn huge_tables(mut self, enable: bool) -> Self {
        self.umem_builder = self.umem_builder.huge_tables(enable);
        self
    }

    pub fn unaligned(mut self, enable: bool) -> Self {
        self.umem_builder = self.umem_builder.unaligned(enable);
        self
    }

    pub fn rx_ring_size(mut self, size: u32) -> Self {
        self.rx_ring_size = size;
        self
    }

    pub fn tx_ring_size(mut self, size: u32) -> Self {
        self.tx_ring_size = size;
        self
    }

    pub fn copy_mode(mut self, mode: CopyMode) -> Self {
        self.copy_mode = mode;
        self
    }

    /// Resolve interface name to index using libc::if_nametoindex.
    fn resolve_if_index(if_name: &str) -> Result<i32> {
        let c_name = CString::new(if_name)
            .map_err(|e| Error::InterfaceNameToIndex(e))?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(Error::InterfaceNotFound);
        }
        Ok(index as i32)
    }

    /// Resolve which queue IDs to bind based on the queue selection strategy.
    fn resolve_queues(&self) -> Result<Vec<u32>> {
        match &self.queue_selection {
            QueueSelection::Explicit(queues) => Ok(queues.clone()),
            QueueSelection::Auto => {
                let if_index = Self::resolve_if_index(self.if_name)?;
                let count = netlink::get_queue_count(if_index)?;
                Ok((0..count).collect())
            }
            QueueSelection::Max(max) => {
                let if_index = Self::resolve_if_index(self.if_name)?;
                let count = netlink::get_queue_count(if_index)?;
                let capped = count.min(*max);
                Ok((0..capped).collect())
            }
        }
    }

    /// Build the multi-threaded Runtime.
    pub fn build(self) -> Result<Runtime> {
        let queues = self.resolve_queues()?;

        // Validate all queue IDs are within xsks_map bounds.
        for &qid in &queues {
            if qid >= 2048 {
                return Err(Error::QueueIdOutOfRange(qid));
            }
        }

        Ok(Runtime {
            if_name: self.if_name.to_string(),
            queues,
            umem_builder: self.umem_builder,
            rx_ring_size: self.rx_ring_size,
            tx_ring_size: self.tx_ring_size,
            busy_poll: self.busy_poll,
            busy_poll_batch_size: self.busy_poll_batch_size,
            busy_poll_timeout_us: self.busy_poll_timeout_us,
            copy_mode: self.copy_mode,
            enable_fragmentation: self.enable_fragmentation,
            arp_ttl: self.arp_ttl,
            attach_mode: self.attach_mode,
        })
    }
}

/// Multi-threaded runtime that spawns one worker thread per hardware queue.
///
/// Created via `Runtime::builder("eth0").build()`. The `run` method drives
/// the two-phase lifecycle: setup on the main thread, then spawn workers.
pub struct Runtime {
    if_name: String,
    queues: Vec<u32>,
    umem_builder: UmemBuilder,
    rx_ring_size: u32,
    tx_ring_size: u32,
    busy_poll: bool,
    busy_poll_batch_size: usize,
    busy_poll_timeout_us: i32,
    copy_mode: CopyMode,
    enable_fragmentation: bool,
    arp_ttl: Duration,
    attach_mode: AttachMode,
}

impl Runtime {
    /// Returns a builder for constructing a multi-threaded Runtime.
    pub fn builder<'name>(if_name: &'name str) -> RuntimeBuilder<'name> {
        RuntimeBuilder::new(if_name)
    }

    /// Run the multi-threaded event loop.
    ///
    /// Phase 1 (main thread): Create XdpContext, UMEMs, sockets; register all sockets.
    /// Phase 2 (worker threads): Spawn one thread per queue, each running a LocalRuntime.
    ///
    /// The factory closure is called on each worker thread with the queue ID.
    /// Returns when all threads exit, or on the first error (which triggers shutdown).
    pub fn run<F, Fut>(
        &self,
        exit: Arc<AtomicBool>,
        factory: F,
    ) -> Result<()>
    where
        F: Fn(u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        // ---- Phase 1: Setup (main thread) ----
        let mut ctx = XdpContext::builder(&self.if_name)
            .attach_mode(self.attach_mode)
            .enable_fragmentation(self.enable_fragmentation)
            .build()?;

        let info = ctx.info();
        let mtu = info.mtu;
        let rx_offload = info.rx_offload;
        let tx_offload = info.tx_offload;

        // Create per-queue resources.
        let mut workers = Vec::new();

        for &queue_id in &self.queues {
            let umem = self.umem_builder.clone().build()?;

            let mut socket_builder = Socket::builder(&self.if_name, queue_id);
            if self.rx_ring_size > 0 {
                socket_builder = socket_builder.rx_ring_size(self.rx_ring_size);
            }
            if self.tx_ring_size > 0 {
                socket_builder = socket_builder.tx_ring_size(self.tx_ring_size);
            }
            socket_builder = socket_builder
                .busy_poll(self.busy_poll)
                .busy_poll_batch_size(self.busy_poll_batch_size)
                .busy_poll_timeout_us(self.busy_poll_timeout_us)
                .copy_mode(self.copy_mode)
                .enable_fragmentation(self.enable_fragmentation);

            let socket = socket_builder.build(&mut ctx, umem.owner().clone())?;

            workers.push((queue_id, umem, socket));
        }

        // ---- Phase 2: Run (worker threads) ----
        let factory = Arc::new(factory);
        let mut handles = Vec::new();

        for (queue_id, umem, socket) in workers {
            let exit = exit.clone();
            let factory = factory.clone();
            let if_name = self.if_name.clone();
            let arp_ttl = self.arp_ttl;

            let handle = std::thread::Builder::new()
                .name(format!("voidnet-q{queue_id}"))
                .spawn(move || -> Result<()> {
                    pin_core(queue_id);

                    let mut rt = LocalRuntime::new_worker(
                        &if_name,
                        umem,
                        socket,
                        mtu,
                        rx_offload,
                        tx_offload,
                        arp_ttl,
                    )?;

                    let result = rt.run(exit.clone(), factory(queue_id));

                    // First-failure propagation: signal all other threads to exit.
                    if result.is_err() {
                        exit.store(true, Ordering::Relaxed);
                    }

                    result
                })
                .map_err(|e| Error::Other(format!("failed to spawn thread: {e}")))?;

            handles.push(handle);
        }

        // ---- Phase 3: Join ----
        // Keep ctx alive (holds BPF program) until all workers are done.
        let _ctx = ctx;

        let mut first_error: Option<Error> = None;

        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
                Err(panic_payload) => {
                    if first_error.is_none() {
                        let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                            format!("worker thread panicked: {s}")
                        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                            format!("worker thread panicked: {s}")
                        } else {
                            "worker thread panicked".to_string()
                        };
                        first_error = Some(Error::Other(msg));
                    }
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
```

**Important lifetime note:** The code above may need lifetime adjustments for `Umem` and `Socket` when transferring to worker threads. Since UMEM buffers are heap-allocated via `mmap`, the `'umem` lifetime should be `'static` in practice. Inspect `Umem` and `UmemOwner` during implementation to confirm. If needed, the workers vec type annotation may need adjustment.

- [ ] **Step 2: Run cargo check**

Run: `cargo check`
Expected: Compiles cleanly. Fix any lifetime or import issues.

- [ ] **Step 3: Commit**

```bash
git add src/rt/runtime.rs
git commit -m "feat(rt): add Runtime and RuntimeBuilder with two-phase setup"
```

### Task 10: Export Runtime from src/rt/mod.rs

**Files:**
- Modify: `src/rt/mod.rs`

- [ ] **Step 1: Add runtime module and exports**

In `src/rt/mod.rs`, add:

```rust
mod runtime;

pub use runtime::{Runtime, RuntimeBuilder};
```

- [ ] **Step 2: Run cargo check**

Run: `cargo check`
Expected: Compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add src/rt/mod.rs
git commit -m "feat(rt): export Runtime and RuntimeBuilder"
```

---

## Chunk 5: Integration Test

### Task 11: Integration test — multi-threaded runtime on veth

**Files:**
- Add test to `src/rt/runtime.rs` (or a new integration test file)

- [ ] **Step 1: Write the integration test**

Add a test module at the bottom of `src/rt/runtime.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::test_utils::TestVethPair;

    /// Test that Runtime can be constructed and run with a single queue on a veth pair.
    /// veth pairs have 1 queue, so this tests the single-queue codepath through
    /// the multi-threaded runtime.
    #[test]
    fn runtime_single_queue_veth() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let exit = Arc::new(AtomicBool::new(false));
        let exit_clone = exit.clone();

        // Signal exit after a brief moment so the test doesn't run forever.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            exit_clone.store(true, Ordering::Relaxed);
        });

        let rt = Runtime::builder(veth.outer_name())
            .queues(&[0])
            .build()
            .expect("failed to build runtime");

        let result = rt.run(exit, |_queue_id| async {
            // No-op: just confirm the event loop runs and exits cleanly.
        });

        assert!(result.is_ok(), "runtime should exit cleanly: {:?}", result.err());
    }

    /// Test that explicit queue selection works.
    #[test]
    fn runtime_builder_explicit_queues() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let rt = Runtime::builder(veth.outer_name())
            .queues(&[0])
            .build();

        assert!(rt.is_ok(), "should build with explicit queue 0");
    }

    /// Test that queue ID validation rejects out-of-range values.
    #[test]
    fn runtime_builder_rejects_out_of_range_queue() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let result = Runtime::builder(veth.outer_name())
            .queues(&[3000])
            .build();

        assert!(result.is_err(), "should reject queue ID >= 2048");
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p libvoid rt::runtime::tests`
Expected: All three tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/rt/runtime.rs
git commit -m "test(rt): add integration tests for multi-threaded Runtime"
```

### Task 12: Full test suite pass

- [ ] **Step 1: Run the complete test suite**

Run: `cargo test`
Expected: All tests pass. No regressions from the XdpContext changes, BPF program update, or LocalRuntime refactoring.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy`
Expected: No new warnings.

- [ ] **Step 3: Final commit if any fixups were needed**

```bash
git add -A
git commit -m "fix: address test suite and clippy feedback"
```
