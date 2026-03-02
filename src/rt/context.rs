use std::cell::{Cell, UnsafeCell};
use std::rc::Rc;

use crate::net::handler::udp::UdpHandler;
use crate::net::{NeighborHandler, PmtuCache};
use crate::xdp::frame::SharedFrameBuffer;

thread_local! {
    static RT_CTX: Cell<*const ()> = const { Cell::new(std::ptr::null()) };
}

pub(crate) struct RuntimeContext<'umem> {
    pub free_frames: SharedFrameBuffer<'umem>,
    pub tx_return: SharedFrameBuffer<'umem>,
    pub rx_return: SharedFrameBuffer<'umem>,
    pub pmtu: Rc<PmtuCache>,
    pub neighbor_handler: Rc<NeighborHandler>,
    pub udp_handler: Rc<UnsafeCell<UdpHandler<'umem>>>,
}

pub(crate) fn set_runtime_context<'umem>(ctx: &RuntimeContext<'umem>) {
    RT_CTX.with(|c| c.set(ctx as *const RuntimeContext<'umem> as *const ()));
}

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
