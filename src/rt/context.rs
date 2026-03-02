use std::cell::{Cell, UnsafeCell};
use std::rc::Rc;

use crate::net::handler::udp::UdpHandler;
use crate::net::{NeighborHandler, PmtuCache};
use crate::xdp::frame::SharedFrameBuffer;

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
    pub pmtu: Rc<PmtuCache>,
    /// ARP/NDP neighbor handling for IPv4 and IPv6.
    pub neighbor_handler: Rc<NeighborHandler>,
    /// UDP handler is used to bind and send UDP packets, handling things like fragmentation and reassembly.
    pub udp_handler: Rc<UnsafeCell<UdpHandler<'umem>>>,
    /// TX checksum offload.
    pub tx_offload: bool,
}

/// Set the runtime context for the current thread.
pub(crate) fn set_runtime_context<'umem>(ctx: &RuntimeContext<'umem>) {
    RT_CTX.with(|c| c.set(ctx as *const RuntimeContext<'umem> as *const ()));
}

/// Clear the runtime context for the current thread.
pub(crate) fn clear_runtime_context() {
    RT_CTX.with(|c| c.set(std::ptr::null()));
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
