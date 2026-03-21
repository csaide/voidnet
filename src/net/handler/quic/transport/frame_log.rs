use super::frame::StreamId;

/// Describes a frame that was sent, for retransmission on loss.
#[derive(Debug, Clone)]
pub enum SentFrame {
    Padding,
    Ping,
    Crypto {
        space: u8,
        offset: u64,
        len: usize,
    },
    Stream {
        id: StreamId,
        offset: u64,
        len: usize,
        fin: bool,
    },
    Ack {
        space: u8,
    },
    MaxData(u64),
    MaxStreamData(StreamId, u64),
    MaxStreams {
        bidi: u64,
        uni: u64,
    },
    NewConnectionId {
        sequence: u64,
    },
    RetireConnectionId {
        sequence: u64,
    },
    HandshakeDone,
    ResetStream {
        id: StreamId,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        id: StreamId,
        error_code: u64,
    },
}

/// Circular buffer of SentFrame entries. SentPacket stores (start, end) range indices.
pub struct FrameLog {
    entries: Vec<SentFrame>,
    capacity: u32,
    head: u32, // next write index (wraps via modulo)
}

impl FrameLog {
    pub fn new(capacity: u32) -> Self {
        Self {
            entries: Vec::with_capacity(capacity as usize),
            capacity,
            head: 0,
        }
    }

    /// Push a frame, return its index.
    pub fn push(&mut self, frame: SentFrame) -> u32 {
        let idx = self.head;
        let slot = (idx % self.capacity) as usize;
        if self.entries.len() <= slot {
            self.entries.push(frame);
        } else {
            self.entries[slot] = frame;
        }
        self.head = idx.wrapping_add(1);
        idx
    }

    /// Current head (next write position).
    pub fn head(&self) -> u32 {
        self.head
    }

    /// Get a frame by absolute index.
    pub fn get(&self, idx: u32) -> Option<&SentFrame> {
        // Check if idx is still in the window
        let oldest = self
            .head
            .wrapping_sub(self.capacity.min(self.entries.len() as u32));
        if idx.wrapping_sub(oldest) < self.capacity {
            self.entries.get((idx % self.capacity) as usize)
        } else {
            None // overwritten
        }
    }

    /// Iterate frames in a range [start, end).
    pub fn range(&self, start: u32, end: u32) -> impl Iterator<Item = &SentFrame> {
        let count = end.wrapping_sub(start) as usize;
        (0..count).filter_map(move |i| self.get(start.wrapping_add(i as u32)))
    }
}
