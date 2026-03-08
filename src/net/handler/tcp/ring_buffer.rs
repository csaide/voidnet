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

    /// Write bytes at an arbitrary offset from `head`. Does NOT advance `tail` or `len`.
    /// Used by the receive side for out-of-order segments — the caller is responsible
    /// for tracking which ranges are filled and advancing via `commit()` when contiguous.
    #[inline]
    pub fn write_at(&mut self, offset: usize, data: &[u8]) {
        let pos = (self.head.wrapping_add(offset)) & self.mask;
        let first = data.len().min(self.buf.len() - pos);
        self.buf[pos..pos + first].copy_from_slice(&data[..first]);
        if first < data.len() {
            self.buf[..data.len() - first].copy_from_slice(&data[first..]);
        }
    }

    /// Read bytes at an arbitrary offset from `head` without advancing `head`.
    /// Used by the send side for retransmission.
    #[inline]
    pub fn peek_at(&self, offset: usize, buf: &mut [u8]) {
        let len = buf.len();
        let pos = (self.head.wrapping_add(offset)) & self.mask;
        let first = len.min(self.buf.len() - pos);
        buf[..first].copy_from_slice(&self.buf[pos..pos + first]);
        if first < len {
            buf[first..].copy_from_slice(&self.buf[..len - first]);
        }
    }

    /// Return two slices covering `len` bytes starting at `offset` from `head`,
    /// without advancing `head`. The first slice covers data up to the end of
    /// the backing buffer; the second covers the wrap-around portion (empty if
    /// no wrap occurs).
    #[inline]
    pub fn peek_slices(&self, offset: usize, len: usize) -> (&[u8], &[u8]) {
        debug_assert!(offset + len <= self.len);
        let pos = (self.head.wrapping_add(offset)) & self.mask;
        let first = len.min(self.buf.len() - pos);
        if first >= len {
            (&self.buf[pos..pos + len], &[])
        } else {
            (&self.buf[pos..], &self.buf[..len - first])
        }
    }

    /// Advance `head` by `n` bytes, freeing space. Used when bytes are ACKed (send)
    /// or consumed by `TcpStream::read()` (receive).
    #[inline]
    pub fn advance(&mut self, n: usize) {
        debug_assert!(n <= self.len);
        self.head = self.head.wrapping_add(n);
        self.len -= n;
    }

    /// Advance `tail` and `len` to mark bytes as available for reading.
    /// Used by the receive side when contiguous data is confirmed.
    #[inline]
    pub fn commit(&mut self, n: usize) {
        debug_assert!(n <= self.free_space());
        self.tail = self.tail.wrapping_add(n);
        self.len += n;
    }

    /// Transfer up to `max_len` bytes from self (as source/read-side) to `dst`
    /// (as destination/write-side). Reads from self's head, writes to dst's tail.
    /// Returns the number of bytes transferred.
    /// Equivalent to read() + write() but avoids the intermediate buffer.
    #[inline]
    pub fn transfer(&mut self, dst: &mut RingBuffer, max_len: usize) -> usize {
        let available = self.available().min(max_len);
        let to_transfer = available.min(dst.free_space());
        if to_transfer == 0 {
            return 0;
        }
        // Get source slices (may wrap around).
        let (s1, s2) = self.peek_slices(0, to_transfer);
        // Write each slice to destination.
        let wrote1 = dst.write(s1);
        let wrote2 = if !s2.is_empty() { dst.write(s2) } else { 0 };
        let total = wrote1 + wrote2;
        // Advance source head.
        self.advance(total);
        total
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

    #[test]
    fn write_at_and_peek() {
        let mut rb = RingBuffer::new(64);
        // Write at offset 0.
        rb.write_at(0, b"AAAA");
        // Write at offset 8 (gap at 4..8).
        rb.write_at(8, b"CCCC");
        // Fill the gap.
        rb.write_at(4, b"BBBB");
        // write_at doesn't advance len/tail.
        assert_eq!(rb.available(), 0);
        // Commit all 12 bytes.
        rb.commit(12);
        assert_eq!(rb.available(), 12);
        // Read and verify.
        let mut buf = [0u8; 12];
        let read = rb.read(&mut buf);
        assert_eq!(read, 12);
        assert_eq!(&buf, b"AAAABBBBCCCC");
    }

    #[test]
    fn write_at_wraps() {
        let mut rb = RingBuffer::new(16);
        // Move head to position 12.
        rb.write(&[0xAA; 12]);
        let mut discard = [0u8; 12];
        rb.read(&mut discard);
        // head=12. write_at offset 2 from head = position 14. Writing 4 bytes wraps.
        rb.write_at(2, &[0xBB; 4]);
        // Verify by peeking.
        let mut buf = [0u8; 4];
        rb.peek_at(2, &mut buf);
        assert_eq!(buf, [0xBB; 4]);
    }

    #[test]
    fn peek_at_does_not_advance() {
        let mut rb = RingBuffer::new(64);
        rb.write(b"hello");
        let mut buf = [0u8; 5];
        rb.peek_at(0, &mut buf);
        assert_eq!(&buf, b"hello");
        assert_eq!(rb.available(), 5); // unchanged
        // Peek again at offset 2.
        let mut buf2 = [0u8; 3];
        rb.peek_at(2, &mut buf2);
        assert_eq!(&buf2, b"llo");
    }

    #[test]
    fn advance_frees_space() {
        let mut rb = RingBuffer::new(64);
        rb.write(b"hello world");
        rb.advance(5);
        assert_eq!(rb.available(), 6);
        assert_eq!(rb.free_space(), 64 - 6);
        let mut buf = [0u8; 6];
        rb.read(&mut buf);
        assert_eq!(&buf, b" world");
    }

    #[test]
    fn commit_makes_data_readable() {
        let mut rb = RingBuffer::new(64);
        // write_at without commit = no data available.
        rb.write_at(0, b"test");
        assert_eq!(rb.available(), 0);
        // After commit, data is readable.
        rb.commit(4);
        assert_eq!(rb.available(), 4);
        let mut buf = [0u8; 4];
        rb.read(&mut buf);
        assert_eq!(&buf, b"test");
    }

    #[test]
    fn peek_slices_no_wrap() {
        let mut rb = RingBuffer::new(64);
        rb.write(b"hello world");
        let (a, b) = rb.peek_slices(0, 5);
        assert_eq!(a, b"hello");
        assert!(b.is_empty());
        assert_eq!(rb.available(), 11); // unchanged
    }

    #[test]
    fn peek_slices_with_wrap() {
        let mut rb = RingBuffer::new(16);
        rb.write(&[0xAA; 12]);
        let mut discard = [0u8; 12];
        rb.read(&mut discard);
        // head=12. Write 8 bytes: 4 at end [12..16], 4 wrap [0..4].
        rb.write(&[0xBB; 8]);
        let (a, b) = rb.peek_slices(0, 8);
        assert_eq!(a, &[0xBB; 4]);
        assert_eq!(b, &[0xBB; 4]);
    }

    #[test]
    fn peek_slices_with_offset() {
        let mut rb = RingBuffer::new(64);
        rb.write(b"hello world");
        let (a, b) = rb.peek_slices(6, 5);
        assert_eq!(a, b"world");
        assert!(b.is_empty());
    }

    #[test]
    fn transfer_basic() {
        let mut src = RingBuffer::new(64);
        let mut dst = RingBuffer::new(64);
        src.write(b"hello");
        let n = src.transfer(&mut dst, 5);
        assert_eq!(n, 5);
        assert_eq!(src.available(), 0);
        assert_eq!(dst.available(), 5);
        let mut buf = [0u8; 5];
        dst.read(&mut buf);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn transfer_with_source_wrap() {
        let mut src = RingBuffer::new(16);
        let mut dst = RingBuffer::new(64);
        // Move head to position 12.
        src.write(&[0xAA; 12]);
        let mut discard = [0u8; 12];
        src.read(&mut discard);
        // head=12. Write 8 bytes: 4 at end [12..16], 4 wrap [0..4].
        src.write(&[0xBB; 8]);
        let n = src.transfer(&mut dst, 8);
        assert_eq!(n, 8);
        assert_eq!(src.available(), 0);
        assert_eq!(dst.available(), 8);
        let mut buf = [0u8; 8];
        dst.read(&mut buf);
        assert_eq!(buf, [0xBB; 8]);
    }

    #[test]
    fn transfer_partial_when_dst_nearly_full() {
        let mut src = RingBuffer::new(64);
        let mut dst = RingBuffer::new(16);
        // Fill dst with 12 bytes, leaving 4 free.
        dst.write(&[0xCC; 12]);
        src.write(b"hello world!");
        let n = src.transfer(&mut dst, 12);
        assert_eq!(n, 4);
        assert_eq!(src.available(), 8);
        assert_eq!(dst.available(), 16);
    }

    #[test]
    fn transfer_empty_source() {
        let mut src = RingBuffer::new(64);
        let mut dst = RingBuffer::new(64);
        let n = src.transfer(&mut dst, 100);
        assert_eq!(n, 0);
    }

    #[test]
    fn transfer_full_dst() {
        let mut src = RingBuffer::new(64);
        let mut dst = RingBuffer::new(16);
        dst.write(&[0xFF; 16]);
        src.write(b"hello");
        let n = src.transfer(&mut dst, 5);
        assert_eq!(n, 0);
    }
}
