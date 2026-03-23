//! DATAGRAM extension queues (RFC 9221).
//!
//! Unreliable datagrams: no retransmission, no flow control, no ordering.
//! Oldest datagrams are dropped when the send queue overflows.

use std::collections::VecDeque;

const DEFAULT_CAPACITY: usize = 64;

/// Errors from datagram operations.
#[derive(Debug, PartialEq)]
pub enum DatagramError {
    /// Datagram exceeds the peer's max_datagram_frame_size.
    TooLarge,
    /// Peer did not advertise max_datagram_frame_size (extension not negotiated).
    NotNegotiated,
}

/// Send/receive queues for unreliable QUIC datagrams (RFC 9221).
pub struct DatagramQueue {
    pub(crate) send: VecDeque<Vec<u8>>,
    recv: VecDeque<Vec<u8>>,
    capacity: usize,
    /// Peer's max_datagram_frame_size — controls whether we can send and max size.
    pub max_send_size: Option<u64>,
    /// Our max_datagram_frame_size — advertised to peer.
    pub max_recv_size: Option<u64>,
}

impl DatagramQueue {
    pub fn new() -> Self {
        Self {
            send: VecDeque::new(),
            recv: VecDeque::new(),
            capacity: DEFAULT_CAPACITY,
            max_send_size: None,
            max_recv_size: None,
        }
    }

    /// Queue a datagram for sending. Drops oldest if at capacity.
    pub fn queue_send(&mut self, data: Vec<u8>) -> Result<(), DatagramError> {
        let max = self.max_send_size.ok_or(DatagramError::NotNegotiated)?;
        if data.len() as u64 > max {
            return Err(DatagramError::TooLarge);
        }
        if self.send.len() >= self.capacity {
            self.send.pop_front(); // drop oldest
        }
        self.send.push_back(data);
        Ok(())
    }

    /// Pop the next datagram to send.
    pub fn pop_send(&mut self) -> Option<Vec<u8>> {
        self.send.pop_front()
    }

    /// Deliver a received datagram into the recv queue.
    pub fn deliver(&mut self, data: Vec<u8>) {
        if self.recv.len() < self.capacity {
            self.recv.push_back(data);
        }
    }

    /// Pop the next received datagram.
    pub fn pop_recv(&mut self) -> Option<Vec<u8>> {
        self.recv.pop_front()
    }

    /// Check if there are datagrams waiting to be sent.
    pub fn has_pending_send(&self) -> bool {
        !self.send.is_empty()
    }
}
