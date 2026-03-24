use std::{
    cell::UnsafeCell,
    collections::{VecDeque, vec_deque::Drain},
    fmt,
    ops::RangeBounds,
    rc::Rc,
    sync::Arc,
    task::Waker,
};

use crossbeam_queue::ArrayQueue;

/// A fixed-capacity, lock-free shared queue.
///
/// Cloning shares the same underlying buffer (via `Arc`), allowing
/// a producer and consumer to communicate without mutexes or per-item
/// allocations. When the buffer is full, [`push`](Self::push) evicts
/// the oldest entry and returns it to the caller.
pub struct SharedQueue<T> {
    inner: Arc<ArrayQueue<T>>,
}

impl<T> SharedQueue<T> {
    /// Create a new shared queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(ArrayQueue::new(capacity)),
        }
    }

    /// Push an item. Returns the evicted oldest item if the queue was full.
    pub fn push(&self, item: T) -> Option<T> {
        self.inner.force_push(item)
    }

    /// Pop an item. Returns the oldest item if the queue was not empty.
    pub fn pop(&self) -> Option<T> {
        self.inner.pop()
    }

    /// Returns the number of items in the queue.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the capacity of the queue.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl<T> Clone for SharedQueue<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> fmt::Debug for SharedQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedQueue")
            .field("len", &self.inner.len())
            .field("capacity", &self.inner.capacity())
            .finish()
    }
}

/// A fixed-capacity, single-threaded shared queue.
///
/// Cloning shares the same underlying buffer (via `Rc`), allowing
/// a producer and consumer to communicate without atomic operations.
/// When the buffer is full, [`push`](Self::push) evicts the oldest
/// entry and returns it to the caller — matching `SharedQueue` semantics.
pub struct LocalQueue<T> {
    inner: Rc<UnsafeCell<VecDeque<T>>>,
    waker: Rc<UnsafeCell<Option<Waker>>>,
    capacity: usize,
}

impl<T> LocalQueue<T> {
    /// Create a new local queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Rc::new(UnsafeCell::new(VecDeque::with_capacity(capacity))),
            waker: Rc::new(UnsafeCell::new(None)),
            capacity,
        }
    }

    /// Push an item. Returns the evicted oldest item if the queue was full.
    #[inline(always)]
    pub fn push(&self, item: T) -> Option<T> {
        let q = unsafe { &mut *self.inner.get() };
        let evicted = if q.len() >= self.capacity {
            q.pop_front()
        } else {
            None
        };
        q.push_back(item);
        let waker_slot = unsafe { &mut *self.waker.get() };
        if let Some(waker) = waker_slot.take() {
            waker.wake();
        }
        evicted
    }

    /// Wake the registered waker (if any) without pushing an item.
    pub fn wake(&self) {
        let waker_slot = unsafe { &mut *self.waker.get() };
        if let Some(waker) = waker_slot.take() {
            waker.wake();
        }
    }

    /// Register a waker to be called when data is pushed to this queue.
    /// Only one waker is stored — re-registering replaces the previous.
    #[inline(always)]
    pub fn register_waker(&self, waker: &Waker) {
        let slot = unsafe { &mut *self.waker.get() };
        match slot {
            &mut Some(ref existing) if existing.will_wake(waker) => {}
            _ => {
                *slot = Some(waker.clone());
            }
        }
    }

    /// Pop an item. Returns the oldest item if the queue was not empty.
    #[inline(always)]
    pub fn pop(&self) -> Option<T> {
        unsafe { &mut *self.inner.get() }.pop_front()
    }

    /// Drain a range of items. Returns an iterator over the drained items.
    #[inline(always)]
    pub fn drain<R: RangeBounds<usize>>(&self, range: R) -> Drain<'_, T> {
        unsafe { &mut *self.inner.get() }.drain(range)
    }

    /// Returns the number of items in the queue.
    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { &*self.inner.get() }.len()
    }

    /// Returns true if the queue is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        unsafe { &*self.inner.get() }.is_empty()
    }

    /// Returns the capacity of the queue.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T> Clone for LocalQueue<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            waker: Rc::clone(&self.waker),
            capacity: self.capacity,
        }
    }
}

impl<T> fmt::Debug for LocalQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalQueue")
            .field("len", &self.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_pop() {
        let q = SharedQueue::new(8);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), 8);

        assert!(q.push(1).is_none());
        assert!(q.push(2).is_none());
        assert_eq!(q.len(), 2);
        assert!(!q.is_empty());

        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
        assert!(q.is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let q1 = SharedQueue::new(8);
        let q2 = q1.clone();

        q1.push(42);
        assert_eq!(q2.pop(), Some(42));

        q2.push(99);
        assert_eq!(q1.pop(), Some(99));
    }

    #[test]
    fn overwrites_oldest_when_full() {
        let q = SharedQueue::new(3);

        assert!(q.push(1).is_none());
        assert!(q.push(2).is_none());
        assert!(q.push(3).is_none());
        assert_eq!(q.len(), 3);

        // Queue is full — pushing evicts oldest (1).
        assert_eq!(q.push(4), Some(1));
        assert_eq!(q.len(), 3);

        // Evicts 2.
        assert_eq!(q.push(5), Some(2));
        assert_eq!(q.len(), 3);

        // Drain: should get 3, 4, 5.
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), Some(4));
        assert_eq!(q.pop(), Some(5));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn wraparound_correctness() {
        let q = SharedQueue::new(3);

        // Fill and drain to advance head.
        q.push(1);
        q.push(2);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));

        // Now push 3 items to fill, then overwrite.
        q.push(10);
        q.push(11);
        q.push(12);
        assert_eq!(q.len(), 3);

        assert_eq!(q.push(13), Some(10));
        assert_eq!(q.pop(), Some(11));
        assert_eq!(q.pop(), Some(12));
        assert_eq!(q.pop(), Some(13));
        assert!(q.is_empty());
    }

    #[test]
    fn local_push_and_pop() {
        let q = LocalQueue::new(8);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), 8);

        assert!(q.push(1).is_none());
        assert!(q.push(2).is_none());
        assert_eq!(q.len(), 2);
        assert!(!q.is_empty());

        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
        assert!(q.is_empty());
    }

    #[test]
    fn local_clone_shares_state() {
        let q1 = LocalQueue::new(8);
        let q2 = q1.clone();

        q1.push(42);
        assert_eq!(q2.pop(), Some(42));

        q2.push(99);
        assert_eq!(q1.pop(), Some(99));
    }

    #[test]
    fn local_overwrites_oldest_when_full() {
        let q = LocalQueue::new(3);

        assert!(q.push(1).is_none());
        assert!(q.push(2).is_none());
        assert!(q.push(3).is_none());
        assert_eq!(q.len(), 3);

        // Queue is full — pushing evicts oldest (1).
        assert_eq!(q.push(4), Some(1));
        assert_eq!(q.len(), 3);

        // Evicts 2.
        assert_eq!(q.push(5), Some(2));
        assert_eq!(q.len(), 3);

        // Drain: should get 3, 4, 5.
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), Some(4));
        assert_eq!(q.pop(), Some(5));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn local_queue_wakes_on_push() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::task::Wake;

        struct TestWaker {
            woken: AtomicBool,
        }
        impl Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.woken.store(true, Ordering::Relaxed);
            }
        }

        let q = LocalQueue::new(8);
        let test_waker = Arc::new(TestWaker {
            woken: AtomicBool::new(false),
        });
        let waker = Waker::from(test_waker.clone());
        q.register_waker(&waker);
        q.push(42);
        assert!(test_waker.woken.load(Ordering::Relaxed));
    }

    #[test]
    fn local_queue_waker_cleared_after_wake() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::task::Wake;

        struct TestWaker {
            woken: AtomicBool,
        }
        impl Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.woken.store(true, Ordering::Relaxed);
            }
        }

        let q = LocalQueue::new(8);
        let test_waker = Arc::new(TestWaker {
            woken: AtomicBool::new(false),
        });
        let waker = Waker::from(test_waker.clone());
        q.register_waker(&waker);
        q.push(1);
        assert!(test_waker.woken.load(Ordering::Relaxed));
        test_waker.woken.store(false, Ordering::Relaxed);
        q.push(2);
        assert!(!test_waker.woken.load(Ordering::Relaxed));
    }

    #[test]
    fn local_queue_drain_range() {
        let queue = LocalQueue::new(8);
        for i in 0..5u32 {
            queue.push(i);
        }
        let drained: Vec<_> = queue.drain(1..3).collect();
        assert_eq!(drained, vec![1, 2]);
        assert_eq!(queue.len(), 3);
        // Remaining items: 0, 3, 4
        assert_eq!(queue.pop(), Some(0));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), Some(4));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn local_queue_drain_full_range() {
        let queue = LocalQueue::new(4);
        for i in 0..4u32 {
            queue.push(i);
        }
        let drained: Vec<_> = queue.drain(..).collect();
        assert_eq!(drained, vec![0, 1, 2, 3]);
        assert!(queue.is_empty());
    }

    #[test]
    fn local_queue_drain_empty_range() {
        let queue = LocalQueue::new(8);
        for i in 0..5u32 {
            queue.push(i);
        }
        let drained: Vec<_> = queue.drain(2..2).collect();
        assert!(drained.is_empty());
        assert_eq!(queue.len(), 5);
    }

    #[test]
    fn local_wraparound_correctness() {
        let q = LocalQueue::new(3);

        // Fill and drain to advance head.
        q.push(1);
        q.push(2);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));

        // Now push 3 items to fill, then overwrite.
        q.push(10);
        q.push(11);
        q.push(12);
        assert_eq!(q.len(), 3);

        assert_eq!(q.push(13), Some(10));
        assert_eq!(q.pop(), Some(11));
        assert_eq!(q.pop(), Some(12));
        assert_eq!(q.pop(), Some(13));
        assert!(q.is_empty());
    }
}
