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

    /// Write bytes into the buffer at `tail`. Returns the number of bytes written.
    /// Writes as many bytes as fit; returns less than `data.len()` if buffer is nearly full.
    #[inline]
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.free_space());
        if to_write == 0 {
            return 0;
        }
        let tail = self.tail & self.mask;
        let first = to_write.min(self.buf.len() - tail);
        self.buf[tail..tail + first].copy_from_slice(&data[..first]);
        if first < to_write {
            self.buf[..to_write - first].copy_from_slice(&data[first..to_write]);
        }
        self.tail = self.tail.wrapping_add(to_write);
        self.len += to_write;
        to_write
    }

    /// Read bytes from the buffer starting at `head`. Returns the number of bytes read.
    /// Advances `head` by the number of bytes read.
    #[inline]
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.available());
        if to_read == 0 {
            return 0;
        }
        let head = self.head & self.mask;
        let first = to_read.min(self.buf.len() - head);
        buf[..first].copy_from_slice(&self.buf[head..head + first]);
        if first < to_read {
            buf[first..to_read].copy_from_slice(&self.buf[..to_read - first]);
        }
        self.head = self.head.wrapping_add(to_read);
        self.len -= to_read;
        to_read
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

    #[test]
    fn write_and_read() {
        let mut rb = RingBuffer::new(64);
        let data = b"hello world";
        let written = rb.write(data);
        assert_eq!(written, data.len());
        assert_eq!(rb.available(), data.len());
        assert_eq!(rb.free_space(), 64 - data.len());

        let mut buf = [0u8; 64];
        let read = rb.read(&mut buf);
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
        assert_eq!(rb.available(), 0);
        assert_eq!(rb.free_space(), 64);
    }

    #[test]
    fn write_wraps_around() {
        let mut rb = RingBuffer::new(16);
        rb.write(&[0xAA; 12]);
        let mut discard = [0u8; 12];
        rb.read(&mut discard);
        // head=12, tail=12. Write 8 bytes: 4 at end, 4 wrap to start.
        let written = rb.write(&[0xBB; 8]);
        assert_eq!(written, 8);
        assert_eq!(rb.available(), 8);

        let mut buf = [0u8; 8];
        let read = rb.read(&mut buf);
        assert_eq!(read, 8);
        assert_eq!(buf, [0xBB; 8]);
    }

    #[test]
    fn write_when_full_returns_zero() {
        let mut rb = RingBuffer::new(16);
        let written = rb.write(&[0xFF; 16]);
        assert_eq!(written, 16);
        let written = rb.write(&[0xAA; 1]);
        assert_eq!(written, 0);
    }

    #[test]
    fn partial_write_when_nearly_full() {
        let mut rb = RingBuffer::new(16);
        rb.write(&[0xFF; 12]);
        let written = rb.write(&[0xAA; 8]);
        assert_eq!(written, 4);
        assert_eq!(rb.available(), 16);
    }
}
