use super::recv::RecvHalf;
use super::send::SendHalf;

/// Recycles stream half objects to avoid repeated allocation.
pub struct StreamPool {
    send_halves: Vec<SendHalf>,
    recv_halves: Vec<RecvHalf>,
    max_pooled: usize,
}

impl StreamPool {
    pub fn new(max_pooled: usize) -> Self {
        Self {
            send_halves: Vec::new(),
            recv_halves: Vec::new(),
            max_pooled,
        }
    }

    pub fn alloc_send(&mut self, max_stream_data: u64) -> SendHalf {
        self.send_halves
            .pop()
            .map(|mut s| {
                s.max_stream_data = max_stream_data;
                s
            })
            .unwrap_or_else(|| SendHalf::new(max_stream_data))
    }

    pub fn alloc_recv(&mut self, max_stream_data: u64) -> RecvHalf {
        self.recv_halves
            .pop()
            .map(|mut r| {
                r.max_stream_data = max_stream_data;
                r
            })
            .unwrap_or_else(|| RecvHalf::new(max_stream_data))
    }

    pub fn release_send(&mut self, mut half: SendHalf) {
        if self.send_halves.len() < self.max_pooled {
            half.reset();
            self.send_halves.push(half);
        }
    }

    pub fn release_recv(&mut self, mut half: RecvHalf) {
        if self.recv_halves.len() < self.max_pooled {
            half.reset();
            self.recv_halves.push(half);
        }
    }
}
