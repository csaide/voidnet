use std::{
    cell::{Cell, UnsafeCell},
    rc::Rc,
    task::Waker,
};

use crate::{
    net::{
        handler::{tcp::TcpHandler, udp::UdpHandler},
        timer_wheel::TimerWheel,
        {NeighborHandler, PmtuCache},
    },
    rt::task::TaskQueue,
    xdp::frame::SharedFrameBuffer,
};

pub struct ContextDropGuard;

impl ContextDropGuard {
    pub fn new<'umem>(ctx: RuntimeContext<'umem>) -> Self {
        let ctx = Box::into_raw(Box::new(ctx));
        RT_CTX.with(|c| c.set(ctx as *const ()));
        Self
    }
}

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

thread_local! {
    static RT_CTX: Cell<*const ()> = const { Cell::new(std::ptr::null()) };
}

/// Runtime context for the [`LocalRuntime`].
pub(crate) struct RuntimeContext<'umem> {
    /// Set of empty ready to go frame structs that can be used for building outbound packets.
    pub free_frames: SharedFrameBuffer<'umem>,
    /// Frames that are filled and ready to be sent to the network.
    pub tx_return: SharedFrameBuffer<'umem>,
    /// Frames that were read from the network and should be handed back to the kernel for re-use.
    pub rx_return: SharedFrameBuffer<'umem>,
    /// Path MTU cache for handling path MTU discovery.
    pub pmtu: Rc<UnsafeCell<PmtuCache>>,
    /// ARP/NDP neighbor handling for IPv4 and IPv6.
    pub neighbor_handler: Rc<NeighborHandler>,
    /// UDP handler is used to bind and send UDP packets, handling things like fragmentation and reassembly.
    pub udp_handler: Rc<UnsafeCell<UdpHandler<'umem>>>,
    /// TCP handler manages TCP connections and the TCP state machine.
    pub tcp_handler: Rc<UnsafeCell<TcpHandler>>,
    /// Timer wheel for TCP timers.
    pub wheel: Rc<UnsafeCell<TimerWheel>>,
    /// Base instant for converting coarsetime to wheel milliseconds.
    pub base_instant: coarsetime::Instant,
    /// TX checksum offload.
    pub tx_offload: bool,
    /// Task queue for spawned tasks.
    pub task_queue: UnsafeCell<TaskQueue>,
    /// Wakers for futures blocked on frame/buffer capacity.
    pub capacity_wakers: UnsafeCell<Vec<Waker>>,
}

/// Called by `UdpSocket::new()` to access the current runtime context.
///
/// # Safety
///
/// Sound because: the context pointer is only set during `LocalRuntime::run()`,
/// and all sockets must live within that closure's scope. The `'umem` lifetime
/// is recovered from the calling context.
///
/// # Panics
///
/// Panics if called outside of `LocalRuntime::run()`.
pub(crate) fn with_runtime_context<'umem, R>(f: impl FnOnce(&RuntimeContext<'umem>) -> R) -> R {
    RT_CTX.with(|c| {
        let ptr = c.get();
        assert!(
            !ptr.is_null(),
            "UdpSocket::new() called outside of LocalRuntime::run()"
        );
        let ctx = unsafe { &*(ptr as *const RuntimeContext<'umem>) };
        f(ctx)
    })
}

/// Register a waker to be called when frame capacity is freed.
///
/// Called by capacity-driven futures (SendTo, Echo, TcpWrite) when
/// they return Pending due to insufficient buffer space.
pub(crate) fn register_capacity_waker(waker: &Waker) {
    with_runtime_context(|ctx| {
        let wakers = unsafe { &mut *ctx.capacity_wakers.get() };
        wakers.push(waker.clone());
    });
}

#[cfg(test)]
mod tests {
    use std::{cell::UnsafeCell, rc::Rc};

    use coarsetime::Duration;

    use crate::{
        net::{
            NeighborHandler, PmtuCache,
            handler::{tcp::TcpHandler, udp::UdpHandler},
            timer_wheel::TimerWheel,
        },
        rt::task::TaskQueue,
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    /// Build a minimal `RuntimeContext` suitable for testing.
    fn make_test_context<'umem>() -> RuntimeContext<'umem> {
        let free_frames = BasicFrameBuffer::new(128).into();
        let tx_return = BasicFrameBuffer::new(128).into();
        let rx_return = BasicFrameBuffer::new(128).into();
        RuntimeContext {
            free_frames,
            tx_return,
            rx_return,
            pmtu: Rc::new(UnsafeCell::new(PmtuCache::new())),
            neighbor_handler: Rc::new(
                NeighborHandler::new("test0", Duration::from_secs(60)).unwrap(),
            ),
            udp_handler: Rc::new(UnsafeCell::new(UdpHandler::new(256, false))),
            tcp_handler: Rc::new(UnsafeCell::new(TcpHandler::new(false, false))),
            wheel: Rc::new(UnsafeCell::new(TimerWheel::new(coarsetime::Instant::now()))),
            base_instant: coarsetime::Instant::now(),
            tx_offload: false,
            task_queue: UnsafeCell::new(TaskQueue::new()),
            capacity_wakers: UnsafeCell::new(Vec::new()),
        }
    }

    #[test]
    #[should_panic]
    fn with_runtime_context_panics_outside_runtime() {
        with_runtime_context(|_ctx| {});
    }

    #[test]
    fn context_drop_guard_installs_and_clears_context() {
        // Before the guard: accessing context must panic.
        let result = std::panic::catch_unwind(|| {
            with_runtime_context(|_ctx| {});
        });
        assert!(result.is_err(), "expected panic before guard is installed");

        // Inside the guard: with_runtime_context succeeds.
        {
            let ctx = make_test_context();
            let _guard = ContextDropGuard::new(ctx);
            // Should not panic.
            with_runtime_context(|ctx| {
                // Sanity check: tx_offload is the value we set.
                assert!(!ctx.tx_offload);
            });
        }

        // After the guard is dropped: context pointer is cleared again.
        let result = std::panic::catch_unwind(|| {
            with_runtime_context(|_ctx| {});
        });
        assert!(result.is_err(), "expected panic after guard is dropped");
    }

    #[test]
    fn context_drop_guard_does_not_leak() {
        let ctx = make_test_context();
        let guard = ContextDropGuard::new(ctx);
        drop(guard);

        let result = std::panic::catch_unwind(|| {
            with_runtime_context(|_ctx| {});
        });
        assert!(result.is_err(), "expected panic after guard is dropped");
    }
}
