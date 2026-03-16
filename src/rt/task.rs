use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::rt::context::with_runtime_context;

/// Type-erased task future.
type Task = Pin<Box<dyn Future<Output = ()>>>;

/// Collection of spawned tasks with a staging buffer for newly spawned tasks.
pub(crate) struct TaskQueue {
    tasks: FuturesUnordered<Task>,
    staging: VecDeque<Task>,
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            tasks: FuturesUnordered::new(),
            staging: VecDeque::new(),
        }
    }

    /// Add a task to the staging buffer.
    pub fn push(&mut self, task: Task) {
        self.staging.push_back(task);
    }

    /// Drain staging into FuturesUnordered, then poll all woken tasks.
    pub fn poll(&mut self, cx: &mut Context<'_>) {
        while let Some(task) = self.staging.pop_front() {
            self.tasks.push(task);
        }
        while let Poll::Ready(Some(())) = self.tasks.poll_next_unpin(cx) {
            continue;
        }
    }
}

/// Handle to a spawned task. Implements `Future<Output = T>`.
///
/// Awaiting the handle returns the task's result when it completes.
/// Dropping the handle does NOT cancel the task — the task continues
/// running but its return value is discarded.
pub struct JoinHandle<T> {
    result: Rc<UnsafeCell<Option<T>>>,
    waker: Rc<UnsafeCell<Option<Waker>>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        // SAFETY: single-threaded, no concurrent access.
        let slot = unsafe { &mut *self.result.get() };
        match slot.take() {
            Some(value) => Poll::Ready(value),
            None => {
                unsafe { *self.waker.get() = Some(cx.waker().clone()) };
                Poll::Pending
            }
        }
    }
}

/// Spawn a future as a task on the local runtime.
///
/// Returns a [`JoinHandle`] that can be awaited to get the task's return value.
///
/// # Panics
///
/// Panics if called outside of `LocalRuntime::run()`.
pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    let result_slot: Rc<UnsafeCell<Option<T>>> = Rc::new(UnsafeCell::new(None));
    let waker_slot: Rc<UnsafeCell<Option<Waker>>> = Rc::new(UnsafeCell::new(None));

    let slot = result_slot.clone();
    let wake = waker_slot.clone();

    let task: Task = Box::pin(async move {
        let value = future.await;
        // SAFETY: single-threaded, no concurrent access.
        unsafe { *slot.get() = Some(value) };
        // Wake the parent task awaiting the JoinHandle.
        let waker = unsafe { &mut *wake.get() };
        if let Some(w) = waker.take() {
            w.wake();
        }
    });

    with_runtime_context(|ctx| {
        // SAFETY: single-threaded, no concurrent access.
        let tq = unsafe { &mut *ctx.task_queue.get() };
        tq.push(task);
    });

    JoinHandle {
        result: result_slot,
        waker: waker_slot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_queue_new_does_not_panic() {
        let _tq = TaskQueue::new();
    }

    #[test]
    fn task_queue_push_stages_task() {
        let mut tq = TaskQueue::new();
        // Staging is empty initially.
        assert!(tq.staging.is_empty());

        // Push a no-op future into the staging buffer.
        let task: Task = Box::pin(async {});
        tq.push(task);

        // One item staged.
        assert_eq!(tq.staging.len(), 1);
    }

    #[test]
    fn task_queue_push_multiple_stages_all() {
        let mut tq = TaskQueue::new();
        for _ in 0..5 {
            tq.push(Box::pin(async {}));
        }
        assert_eq!(tq.staging.len(), 5);
    }

    // poll() is not tested here because it requires a std::task::Context (waker),
    // which in turn requires either a real async executor or a manually constructed
    // RawWaker.  Building one safely is non-trivial and duplicates executor
    // infrastructure that doesn't exist in this crate's test helpers.
}
