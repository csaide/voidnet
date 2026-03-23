use super::recv::StreamRingBuffer;

/// Send half of a QUIC stream
pub struct SendHalf {
    pub buffer: StreamRingBuffer,
    pub sent: u64,
    pub acked: u64,
    pub max_stream_data: u64,
    pub fin_sent: bool,
    pub blocked_at: Option<u64>,
    pub reset_requested: bool,
    pub reset_error_code: u64,
}

impl SendHalf {
    pub fn new(initial_max_stream_data: u64) -> Self {
        Self {
            buffer: StreamRingBuffer::new(8192),
            sent: 0,
            acked: 0,
            max_stream_data: initial_max_stream_data,
            fin_sent: false,
            blocked_at: None,
            reset_requested: false,
            reset_error_code: 0,
        }
    }

    pub fn can_send(&self) -> bool {
        self.sent < self.max_stream_data && !self.buffer.is_empty()
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        self.buffer.write(data)
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.sent = 0;
        self.acked = 0;
        self.fin_sent = false;
        self.blocked_at = None;
    }

    pub fn mark_reset(&mut self, error_code: u64) {
        self.reset_requested = true;
        self.reset_error_code = error_code;
    }

    pub fn final_size(&self) -> u64 {
        self.acked + self.buffer.len() as u64
    }
}
