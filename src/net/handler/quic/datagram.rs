//! DATAGRAM extension queues (RFC 9221).
//!
//! Unreliable datagrams: no retransmission, no flow control, no ordering.
//! Uses a flat ring buffer to avoid per-datagram heap allocations.
//! Oldest datagrams are dropped when the send queue overflows.

const DEFAULT_CAPACITY: usize = 64;
/// Maximum single datagram payload (matches typical QUIC MTU).
const MAX_DATAGRAM_SIZE: usize = 1500;

/// Errors from datagram operations.
#[derive(Debug, PartialEq)]
pub enum DatagramError {
    /// Datagram exceeds the peer's max_datagram_frame_size.
    TooLarge,
    /// Peer did not advertise max_datagram_frame_size (extension not negotiated).
    NotNegotiated,
}

/// Fixed-size ring of datagrams backed by a flat byte buffer.
/// Each entry is stored as: [len: u16][data: len bytes].
/// No heap allocation per datagram.
struct DatagramRing {
    /// Flat byte storage for all datagram payloads.
    buf: Vec<u8>,
    /// Ring of (offset, length) into `buf`.
    entries: Vec<(u32, u16)>,
    head: usize,
    tail: usize,
    count: usize,
    /// Next write position in `buf`.
    write_pos: usize,
    capacity: usize,
}

impl DatagramRing {
    fn new(max_entries: usize) -> Self {
        // Pre-allocate enough for max_entries datagrams at max size.
        // In practice most datagrams are much smaller, so this is generous.
        let buf_size = max_entries * MAX_DATAGRAM_SIZE;
        Self {
            buf: vec![0u8; buf_size],
            entries: vec![(0, 0); max_entries],
            head: 0,
            tail: 0,
            count: 0,
            write_pos: 0,
            capacity: max_entries,
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn len(&self) -> usize {
        self.count
    }

    /// Push a datagram. If at capacity, drops the oldest entry first.
    fn push(&mut self, data: &[u8]) {
        let len = data.len();
        debug_assert!(len <= MAX_DATAGRAM_SIZE);

        // If at capacity, drop oldest
        if self.count >= self.capacity {
            self.pop_discard();
        }

        // Write data into flat buffer (wrap if needed)
        let buf_cap = self.buf.len();
        if self.write_pos + len <= buf_cap {
            self.buf[self.write_pos..self.write_pos + len].copy_from_slice(data);
        } else {
            // Wrap: write in two parts
            let first = buf_cap - self.write_pos;
            self.buf[self.write_pos..].copy_from_slice(&data[..first]);
            self.buf[..len - first].copy_from_slice(&data[first..]);
        }

        self.entries[self.tail] = (self.write_pos as u32, len as u16);
        self.tail = (self.tail + 1) % self.capacity;
        self.count += 1;
        self.write_pos = (self.write_pos + len) % buf_cap;
    }

    /// Pop the oldest datagram, copying it into `out`. Returns the slice written.
    fn pop<'a>(&mut self, out: &'a mut [u8]) -> Option<&'a [u8]> {
        if self.count == 0 {
            return None;
        }
        let (offset, len) = self.entries[self.head];
        let offset = offset as usize;
        let len = len as usize;
        self.head = (self.head + 1) % self.capacity;
        self.count -= 1;

        let buf_cap = self.buf.len();
        if offset + len <= buf_cap {
            out[..len].copy_from_slice(&self.buf[offset..offset + len]);
        } else {
            let first = buf_cap - offset;
            out[..first].copy_from_slice(&self.buf[offset..]);
            out[first..len].copy_from_slice(&self.buf[..len - first]);
        }
        Some(&out[..len])
    }

    /// Discard the oldest entry without copying.
    fn pop_discard(&mut self) {
        if self.count > 0 {
            self.head = (self.head + 1) % self.capacity;
            self.count -= 1;
        }
    }

    /// Peek at the oldest datagram data as two contiguous slices
    /// (handles ring buffer wrap). Returns (slice1, slice2, total_len).
    fn peek_front(&self) -> Option<(&[u8], &[u8])> {
        if self.count == 0 {
            return None;
        }
        let (offset, len) = self.entries[self.head];
        let offset = offset as usize;
        let len = len as usize;
        let buf_cap = self.buf.len();
        if offset + len <= buf_cap {
            Some((&self.buf[offset..offset + len], &[]))
        } else {
            let first = buf_cap - offset;
            Some((&self.buf[offset..], &self.buf[..len - first]))
        }
    }

    /// Remove the front entry (after peek_front + successful write).
    fn advance_front(&mut self) {
        if self.count > 0 {
            self.head = (self.head + 1) % self.capacity;
            self.count -= 1;
        }
    }
}

/// Send/receive queues for unreliable QUIC datagrams (RFC 9221).
pub struct DatagramQueue {
    send: DatagramRing,
    recv: DatagramRing,
    /// Peer's max_datagram_frame_size — controls whether we can send and max size.
    pub max_send_size: Option<u64>,
    /// Our max_datagram_frame_size — advertised to peer.
    pub max_recv_size: Option<u64>,
}

impl DatagramQueue {
    pub fn new() -> Self {
        Self {
            send: DatagramRing::new(DEFAULT_CAPACITY),
            recv: DatagramRing::new(DEFAULT_CAPACITY),
            max_send_size: None,
            max_recv_size: None,
        }
    }

    /// Queue a datagram for sending (zero-copy into ring buffer). Drops oldest if at capacity.
    pub fn queue_send(&mut self, data: &[u8]) -> Result<(), DatagramError> {
        let max = self.max_send_size.ok_or(DatagramError::NotNegotiated)?;
        if data.len() as u64 > max {
            return Err(DatagramError::TooLarge);
        }
        self.send.push(data);
        Ok(())
    }

    /// Peek at the next datagram to send (two slices for ring buffer wrap).
    /// Call `advance_send()` after successfully writing it.
    pub fn peek_send(&self) -> Option<(&[u8], &[u8])> {
        self.send.peek_front()
    }

    /// Advance past the front send datagram after it has been written.
    pub fn advance_send(&mut self) {
        self.send.advance_front();
    }

    /// Pop the next datagram to send, copying into the provided buffer.
    /// Returns the slice of `out` that was written to.
    pub fn pop_send<'a>(&mut self, out: &'a mut [u8]) -> Option<&'a [u8]> {
        self.send.pop(out)
    }

    /// Deliver a received datagram into the recv queue (zero-copy into ring buffer).
    pub fn deliver(&mut self, data: &[u8]) {
        if self.recv.len() < self.recv.capacity {
            self.recv.push(data);
        }
    }

    /// Pop the next received datagram, copying into the caller's buffer.
    pub fn pop_recv(&mut self) -> Option<Vec<u8>> {
        let mut tmp = [0u8; MAX_DATAGRAM_SIZE];
        let slice = self.recv.pop(&mut tmp)?;
        Some(slice.to_vec())
    }

    /// Check if there are datagrams waiting to be sent.
    pub fn has_pending_send(&self) -> bool {
        !self.send.is_empty()
    }
}
