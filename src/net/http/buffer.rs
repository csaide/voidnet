/// Fixed-capacity read buffer for HTTP parsing.
///
/// Tracks unconsumed data via `start` and `end` positions. Parsers operate
/// on `unconsumed()` which returns a zero-copy `&[u8]` slice. The codec
/// stores offsets into this buffer; `slice_at()` resolves those offsets.
///
/// Capacity must be a power of two.
pub struct ReadBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl ReadBuffer {
    /// Create a new ReadBuffer with the given capacity.
    /// Capacity must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "ReadBuffer capacity must be a power of two"
        );
        Self {
            buf: vec![0u8; capacity],
            start: 0,
            end: 0,
        }
    }

    /// Returns a slice of the unconsumed data in the buffer.
    #[inline]
    pub fn unconsumed(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Returns a slice at the given absolute offsets into the buffer.
    ///
    /// These offsets are absolute positions in the buffer (not relative
    /// to `start`). Used by `Request` to resolve path offsets.
    #[inline]
    pub fn slice_at(&self, from: usize, to: usize) -> &[u8] {
        &self.buf[from..to]
    }

    /// Mark `n` bytes as consumed, advancing the start position.
    #[inline]
    pub fn consume(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.end);
    }

    /// Returns the number of bytes that can still be appended.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.end
    }

    /// Append bytes from a slice into the buffer. Returns the number
    /// of bytes actually written (may be less than `data.len()` if
    /// the buffer is nearly full).
    pub fn append(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.remaining_capacity());
        if to_write == 0 {
            return 0;
        }
        self.buf[self.end..self.end + to_write].copy_from_slice(&data[..to_write]);
        self.end += to_write;
        to_write
    }

    /// Shift unconsumed data to the front of the buffer, reclaiming
    /// space from consumed bytes.
    ///
    /// Only call when no outstanding offset-based reads are in progress
    /// (i.e., between request/response cycles).
    pub fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let len = self.end - self.start;
        self.buf.copy_within(self.start..self.end, 0);
        self.start = 0;
        self.end = len;
    }

    /// Returns the current start position (offset of first unconsumed byte).
    /// Used by the codec to compute absolute offsets for parsed fields.
    #[inline]
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns a mutable slice of the writable region (from end to capacity).
    /// Used by HttpConnection to pass to TcpStream::read().
    pub fn writable_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.end..]
    }

    /// Advance the end position after writing into writable_slice().
    pub fn advance_end(&mut self, n: usize) {
        self.end += n;
        debug_assert!(self.end <= self.buf.len());
    }
}

/// Fixed-capacity write buffer for HTTP response output.
///
/// Accumulates response bytes before flushing to the TcpStream.
/// Capacity must be a power of two.
pub struct WriteBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl WriteBuffer {
    /// Create a new WriteBuffer with the given capacity.
    /// Capacity must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "WriteBuffer capacity must be a power of two"
        );
        Self {
            buf: vec![0u8; capacity],
            start: 0,
            end: 0,
        }
    }

    /// Append bytes to the write buffer. Returns the number of bytes written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.buf.len() - self.end);
        if to_write == 0 {
            return 0;
        }
        self.buf[self.end..self.end + to_write].copy_from_slice(&data[..to_write]);
        self.end += to_write;
        to_write
    }

    /// Returns the buffered data ready to be flushed.
    pub fn pending(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Mark `n` bytes as flushed.
    pub fn advance(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.end);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Returns true if there is no pending data.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns the number of bytes that can still be written.
    pub fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ReadBuffer tests

    #[test]
    fn new_buffer_is_empty() {
        let buf = ReadBuffer::new(1024);
        assert_eq!(buf.unconsumed().len(), 0);
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    #[should_panic(expected = "must be a power of two")]
    fn non_power_of_two_panics() {
        ReadBuffer::new(1000);
    }

    #[test]
    fn append_and_read() {
        let mut buf = ReadBuffer::new(1024);
        let n = buf.append(b"GET /index.html\r\n");
        assert_eq!(n, 17);
        assert_eq!(buf.unconsumed(), b"GET /index.html\r\n");
    }

    #[test]
    fn consume_advances_start() {
        let mut buf = ReadBuffer::new(1024);
        buf.append(b"GET /index.html\r\n");
        buf.consume(4);
        assert_eq!(buf.unconsumed(), b"/index.html\r\n");
    }

    #[test]
    fn compact_shifts_data() {
        let mut buf = ReadBuffer::new(16);
        buf.append(b"12345678"); // fill half
        buf.consume(8); // consume all — start is now at 8
        buf.append(b"abcdefgh"); // fill remaining 8 bytes
        // start=8, end=16, no room to append more
        assert_eq!(buf.remaining_capacity(), 0);
        buf.compact();
        // after compact, data shifted to front
        assert_eq!(buf.unconsumed(), b"abcdefgh");
        assert_eq!(buf.remaining_capacity(), 8);
    }

    #[test]
    fn append_respects_capacity() {
        let mut buf = ReadBuffer::new(8);
        let n = buf.append(b"1234567890"); // 10 bytes into 8-byte buffer
        assert_eq!(n, 8);
        assert_eq!(buf.unconsumed(), b"12345678");
    }

    #[test]
    fn slice_at_returns_correct_range() {
        let mut buf = ReadBuffer::new(1024);
        buf.append(b"GET /path HTTP/1.1\r\n");
        assert_eq!(buf.slice_at(4, 9), b"/path");
    }

    #[test]
    fn consume_then_slice_at_uses_absolute_offsets() {
        let mut buf = ReadBuffer::new(1024);
        buf.append(b"GET /path\n");
        // slice_at uses offsets relative to buffer start (position 0),
        // not relative to unconsumed start
        assert_eq!(buf.slice_at(4, 9), b"/path");
    }

    // WriteBuffer tests

    #[test]
    fn write_buffer_new() {
        let buf = WriteBuffer::new(1024);
        assert!(buf.is_empty());
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn write_buffer_write_and_pending() {
        let mut buf = WriteBuffer::new(1024);
        let n = buf.write(b"Hello, World!");
        assert_eq!(n, 13);
        assert_eq!(buf.pending(), b"Hello, World!");
        assert!(!buf.is_empty());
    }

    #[test]
    fn write_buffer_advance() {
        let mut buf = WriteBuffer::new(1024);
        buf.write(b"Hello, World!");
        buf.advance(5);
        assert_eq!(buf.pending(), b", World!");
    }

    #[test]
    fn write_buffer_advance_all_resets() {
        let mut buf = WriteBuffer::new(1024);
        buf.write(b"Hello");
        buf.advance(5);
        assert!(buf.is_empty());
        // After full advance, positions reset so we can write again
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn write_buffer_respects_capacity() {
        let mut buf = WriteBuffer::new(8);
        let n = buf.write(b"1234567890");
        assert_eq!(n, 8);
        assert_eq!(buf.pending(), b"12345678");
    }
}
