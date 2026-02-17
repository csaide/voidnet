use std::fmt;
use std::sync::Arc;

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
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(ArrayQueue::new(capacity)),
        }
    }

    /// Push an item. Returns the evicted oldest item if the queue was full.
    pub fn push(&self, item: T) -> Option<T> {
        self.inner.force_push(item)
    }

    pub fn pop(&self) -> Option<T> {
        self.inner.pop()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

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
}
