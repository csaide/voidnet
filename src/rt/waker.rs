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

/// Creates a no-op waker for the local executor.
///
/// The local runtime is driven by packet arrival, not waker
/// notifications, so wake calls are intentionally ignored.
pub(crate) const fn waker() -> Waker {
    unsafe { Waker::from_raw(raw_waker()) }
}
