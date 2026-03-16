use std::{
    cell::Cell,
    rc::Rc,
    task::{RawWaker, RawWakerVTable, Waker},
};

/// Flag-based waker for the main future.
///
/// When woken, sets an internal flag that the event loop checks
/// before polling the main future. Initialized to `true` so the
/// main future gets its first poll immediately.
#[derive(Clone)]
pub(crate) struct MainWaker {
    woken: Rc<Cell<bool>>,
}

impl MainWaker {
    pub fn new() -> Self {
        Self {
            woken: Rc::new(Cell::new(true)),
        }
    }

    /// Check whether the waker has been triggered and reset the flag.
    #[inline(always)]
    pub fn take_woken(&self) -> bool {
        let was_woken = self.woken.get();
        self.woken.set(false);
        was_woken
    }

    /// Manually set the woken flag (used by event loop for capacity-driven wakes).
    #[inline(always)]
    pub fn set_woken(&self) {
        self.woken.set(true);
    }

    /// Build a `std::task::Waker` that sets this flag when woken.
    pub fn waker(&self) -> Waker {
        let data = Rc::into_raw(self.woken.clone()) as *const ();
        let raw = RawWaker::new(data, &MAIN_WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}

unsafe fn clone_main_waker(data: *const ()) -> RawWaker {
    let rc = unsafe { Rc::from_raw(data as *const Cell<bool>) };
    let cloned = rc.clone();
    std::mem::forget(rc);
    let ptr = Rc::into_raw(cloned) as *const ();
    RawWaker::new(ptr, &MAIN_WAKER_VTABLE)
}

unsafe fn wake_main(data: *const ()) {
    let rc = unsafe { Rc::from_raw(data as *const Cell<bool>) };
    rc.set(true);
}

unsafe fn wake_main_by_ref(data: *const ()) {
    let rc = unsafe { Rc::from_raw(data as *const Cell<bool>) };
    rc.set(true);
    std::mem::forget(rc);
}

unsafe fn drop_main_waker(data: *const ()) {
    drop(unsafe { Rc::from_raw(data as *const Cell<bool>) });
}

const MAIN_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_main_waker,
    wake_main,
    wake_main_by_ref,
    drop_main_waker,
);

// ---- No-op waker for TaskQueue's top-level FuturesUnordered poll ----

const fn noop_raw_waker() -> RawWaker {
    RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)
}

unsafe fn noop_clone(_data: *const ()) -> RawWaker {
    noop_raw_waker()
}

unsafe fn noop(_data: *const ()) {}

const NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

/// No-op waker used for the TaskQueue's top-level FuturesUnordered poll.
///
/// FuturesUnordered manages its own per-task wakers internally. The top-level
/// waker would signal "at least one task is ready to poll" — but we poll the
/// task queue every iteration anyway, so we don't need this notification.
pub(crate) const fn task_queue_waker() -> Waker {
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_woken() {
        let mw = MainWaker::new();
        assert!(mw.take_woken());
        assert!(!mw.take_woken());
    }

    #[test]
    fn waker_sets_flag() {
        let mw = MainWaker::new();
        mw.take_woken();
        let waker = mw.waker();
        waker.wake_by_ref();
        assert!(mw.take_woken());
    }

    #[test]
    fn set_woken_manual() {
        let mw = MainWaker::new();
        mw.take_woken();
        mw.set_woken();
        assert!(mw.take_woken());
    }

    #[test]
    fn waker_clone_works() {
        let mw = MainWaker::new();
        mw.take_woken();
        let waker = mw.waker();
        let cloned = waker.clone();
        drop(waker);
        cloned.wake();
        assert!(mw.take_woken());
    }

    #[test]
    fn wake_consumes_waker() {
        let mw = MainWaker::new();
        mw.take_woken();
        let waker = mw.waker();
        waker.wake();
        assert!(mw.take_woken());
    }

    #[test]
    fn wake_by_ref_does_not_consume() {
        let mw = MainWaker::new();
        mw.take_woken();
        let waker = mw.waker();
        waker.wake_by_ref();
        assert!(mw.take_woken());
        drop(waker);
    }

    #[test]
    fn drop_waker_does_not_panic() {
        let mw = MainWaker::new();
        let waker = mw.waker();
        drop(waker);
        mw.set_woken();
        assert!(mw.take_woken());
    }

    #[test]
    fn multiple_wakers_from_same_main() {
        let mw = MainWaker::new();
        mw.take_woken();
        let w1 = mw.waker();
        let w2 = mw.waker();
        w1.wake_by_ref();
        assert!(mw.take_woken());
        w2.wake();
        assert!(mw.take_woken());
    }

    #[test]
    fn noop_waker_does_not_panic() {
        let waker = task_queue_waker();
        waker.wake_by_ref();
        let cloned = waker.clone();
        cloned.wake();
    }

    #[test]
    fn task_queue_waker_clone_roundtrip() {
        let waker = task_queue_waker();
        let cloned = waker.clone();
        drop(waker);
        cloned.wake_by_ref();
        drop(cloned);
    }
}
