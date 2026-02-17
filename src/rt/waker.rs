use std::{
    ptr::null,
    task::{RawWaker, RawWakerVTable, Waker},
};

const fn raw_waker() -> RawWaker {
    RawWaker::new(null(), &NOOP_WAKER_VTABLE)
}

unsafe fn noop_clone(_data: *const ()) -> RawWaker {
    raw_waker()
}

unsafe fn noop(_data: *const ()) {}

const NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

/// Creates a new waker for the [LocalExecutor] executor.
///
/// This waker is a no-op waker that does nothing. This is be design as we are driven purely by epoll events, so we don't need to wake up the task.
///
/// [LocalExecutor]: crate::xdp::futures::local::LocalExecutor
pub(super) const fn waker() -> Waker {
    unsafe { Waker::from_raw(raw_waker()) }
}
