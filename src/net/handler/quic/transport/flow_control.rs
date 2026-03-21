//! Connection-level flow control (RFC 9000 §4).
//!
//! Tracks both sending and receiving sides of the connection-level flow control
//! window.  Stream-level flow control is handled separately.

/// Connection-level flow control state (RFC 9000 §4).
pub struct FlowControl {
    // --- Sending side ---
    /// Peer's MAX_DATA limit (how much we are allowed to send in total).
    max_data_send: u64,
    /// Total data sent so far.
    data_sent: u64,
    /// The limit value at which we last emitted a DATA_BLOCKED notification.
    blocked_at: Option<u64>,

    // --- Receiving side ---
    /// Our advertised MAX_DATA limit (communicated to the peer via MAX_DATA frames).
    max_data_recv: u64,
    /// Total data received so far.
    data_received: u64,
    /// Total data consumed by the application (used for auto-tuning the window).
    data_consumed: u64,
}

impl FlowControl {
    pub fn new(initial_max_data_send: u64, initial_max_data_recv: u64) -> Self {
        FlowControl {
            max_data_send: initial_max_data_send,
            data_sent: 0,
            blocked_at: None,
            max_data_recv: initial_max_data_recv,
            data_received: 0,
            data_consumed: 0,
        }
    }

    // -------------------------------------------------------------------------
    // Sending side
    // -------------------------------------------------------------------------

    /// Returns true if we may send `bytes` more data without violating the
    /// peer's MAX_DATA limit.
    #[inline]
    pub fn can_send(&self, bytes: u64) -> bool {
        self.data_sent + bytes <= self.max_data_send
    }

    /// Account for `bytes` having been sent.
    #[inline]
    pub fn on_data_sent(&mut self, bytes: u64) {
        self.data_sent += bytes;
    }

    /// Update (or raise) the peer's MAX_DATA limit.
    ///
    /// Clears any pending DATA_BLOCKED notification since we are unblocked.
    pub fn update_max_data_send(&mut self, max: u64) {
        self.max_data_send = self.max_data_send.max(max);
        self.blocked_at = None;
    }

    /// Returns the limit value if we should emit a DATA_BLOCKED frame now
    /// (i.e., we are at the send limit and haven't notified at this limit yet).
    pub fn send_blocked(&mut self) -> Option<u64> {
        if self.data_sent >= self.max_data_send && self.blocked_at != Some(self.max_data_send) {
            self.blocked_at = Some(self.max_data_send);
            Some(self.max_data_send)
        } else {
            None
        }
    }

    // -------------------------------------------------------------------------
    // Receiving side
    // -------------------------------------------------------------------------

    /// Account for `bytes` having been received.
    ///
    /// Returns `Err(())` if the cumulative received data exceeds our advertised
    /// limit, which should be treated as a `FLOW_CONTROL_ERROR`.
    #[inline]
    pub fn on_data_received(&mut self, bytes: u64) -> Result<(), ()> {
        self.data_received += bytes;
        if self.data_received > self.max_data_recv {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Record that the application has consumed `bytes` from the receive buffer.
    pub fn on_data_consumed(&mut self, bytes: u64) {
        self.data_consumed += bytes;
    }

    /// Returns the new MAX_DATA value to advertise if auto-tuning suggests we
    /// should send a MAX_DATA frame.
    ///
    /// Triggers when consumed > max/2 (simple threshold heuristic).  The new
    /// limit is `data_consumed + max_data_recv` to keep the window roughly
    /// constant.
    pub fn should_send_max_data(&self) -> Option<u64> {
        if self.data_consumed > self.max_data_recv / 2 {
            Some(self.data_consumed + self.max_data_recv)
        } else {
            None
        }
    }

    /// Commit a new receive limit (call after sending a MAX_DATA frame with the
    /// value returned by `should_send_max_data`).
    pub fn commit_max_data(&mut self, new_max: u64) {
        self.max_data_recv = new_max;
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    pub fn max_data_send(&self) -> u64 {
        self.max_data_send
    }

    pub fn data_sent(&self) -> u64 {
        self.data_sent
    }

    pub fn max_data_recv(&self) -> u64 {
        self.max_data_recv
    }

    pub fn data_received(&self) -> u64 {
        self.data_received
    }

    /// Account for the final size of a terminated stream (RFC 9000 §4.5).
    ///
    /// A RESET_STREAM frame declares a `final_size`; those bytes count against
    /// flow control even if the data itself was never delivered to the
    /// application.  Call this instead of (or in addition to) `on_data_received`
    /// when processing RESET_STREAM.
    pub fn on_stream_final_size(&mut self, final_size: u64) {
        // Ensure data_received accounts for the final_size.  We only move
        // data_received forward — never back — since it is a cumulative counter.
        if final_size > self.data_received {
            self.data_received = final_size;
        }
    }
}
