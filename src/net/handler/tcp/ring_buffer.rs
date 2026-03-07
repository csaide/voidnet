/// Fixed-capacity ring buffer for TCP send/receive data.
///
/// Capacity must be a power of two. Uses bitwise AND for index wrapping
/// instead of modulo for performance.
pub struct RingBuffer {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    len: usize,
    mask: usize,
}

impl RingBuffer {
    /// Create a new ring buffer. `capacity` must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "RingBuffer capacity must be a power of two"
        );
        Self {
            buf: vec![0u8; capacity],
            head: 0,
            tail: 0,
            len: 0,
            mask: capacity - 1,
        }
    }

    /// Number of bytes available to read.
    #[inline]
    pub fn available(&self) -> usize {
        self.len
    }

    /// Number of bytes available to write.
    #[inline]
    pub fn free_space(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Total capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ring_buffer() {
        let rb = RingBuffer::new(1024);
        assert_eq!(rb.capacity(), 1024);
        assert_eq!(rb.available(), 0);
        assert_eq!(rb.free_space(), 1024);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn non_power_of_two_panics() {
        RingBuffer::new(1000);
    }
}
