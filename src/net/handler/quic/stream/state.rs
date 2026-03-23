/// RFC 9000 §3.1 — Sending stream states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    Ready,      // created, no data sent
    Send,       // actively sending
    DataSent,   // all data sent (FIN queued), awaiting ACKs
    DataRecvd,  // all data ACKed — terminal
    ResetSent,  // RESET_STREAM sent, awaiting ACK
    ResetRecvd, // RESET_STREAM ACKed — terminal
}

/// RFC 9000 §3.2 — Receiving stream states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    Recv,       // accepting data, final size unknown
    SizeKnown,  // got FIN, know total size, may still have gaps
    DataRecvd,  // all data received contiguously — ready for app
    DataRead,   // application consumed all data — terminal
    ResetRecvd, // got RESET_STREAM — terminal
}

/// Combined stream state for bidi, send-only, or recv-only streams
#[derive(Debug)]
pub enum StreamState {
    Bidi { send: SendState, recv: RecvState },
    SendOnly { send: SendState },
    RecvOnly { recv: RecvState },
}

impl SendState {
    /// Check if a transition is valid and perform it.
    /// Returns Err with a description if the transition is invalid.
    pub fn transition(&mut self, to: SendState) -> Result<(), &'static str> {
        let valid = match (*self, to) {
            (SendState::Ready, SendState::Send) => true,
            (SendState::Ready, SendState::DataSent) => true, // empty stream with FIN
            (SendState::Ready, SendState::ResetSent) => true,
            (SendState::Send, SendState::DataSent) => true,
            (SendState::Send, SendState::ResetSent) => true,
            (SendState::DataSent, SendState::DataRecvd) => true,
            (SendState::DataSent, SendState::ResetSent) => true,
            (SendState::ResetSent, SendState::ResetRecvd) => true,
            _ => false,
        };
        if valid {
            *self = to;
            Ok(())
        } else {
            Err("invalid send state transition")
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, SendState::DataRecvd | SendState::ResetRecvd)
    }

    pub fn can_send_data(&self) -> bool {
        matches!(self, SendState::Ready | SendState::Send)
    }
}

impl RecvState {
    pub fn transition(&mut self, to: RecvState) -> Result<(), &'static str> {
        let valid = matches!(
            (*self, to),
            (RecvState::Recv, RecvState::SizeKnown)
                | (RecvState::Recv, RecvState::ResetRecvd)
                | (RecvState::SizeKnown, RecvState::DataRecvd)
                | (RecvState::SizeKnown, RecvState::ResetRecvd)
                | (RecvState::DataRecvd, RecvState::DataRead)
        );
        if valid {
            *self = to;
            Ok(())
        } else {
            Err("invalid recv state transition")
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, RecvState::DataRead | RecvState::ResetRecvd)
    }

    pub fn can_receive_data(&self) -> bool {
        matches!(self, RecvState::Recv | RecvState::SizeKnown)
    }
}

impl StreamState {
    pub fn new_bidi() -> Self {
        StreamState::Bidi {
            send: SendState::Ready,
            recv: RecvState::Recv,
        }
    }

    pub fn new_send_only() -> Self {
        StreamState::SendOnly {
            send: SendState::Ready,
        }
    }

    pub fn new_recv_only() -> Self {
        StreamState::RecvOnly {
            recv: RecvState::Recv,
        }
    }

    pub fn send_state(&self) -> Option<&SendState> {
        match self {
            StreamState::Bidi { send, .. } => Some(send),
            StreamState::SendOnly { send } => Some(send),
            StreamState::RecvOnly { .. } => None,
        }
    }

    pub fn recv_state(&self) -> Option<&RecvState> {
        match self {
            StreamState::Bidi { recv, .. } => Some(recv),
            StreamState::RecvOnly { recv } => Some(recv),
            StreamState::SendOnly { .. } => None,
        }
    }

    pub fn send_state_mut(&mut self) -> Option<&mut SendState> {
        match self {
            StreamState::Bidi { send, .. } => Some(send),
            StreamState::SendOnly { send } => Some(send),
            StreamState::RecvOnly { .. } => None,
        }
    }

    pub fn recv_state_mut(&mut self) -> Option<&mut RecvState> {
        match self {
            StreamState::Bidi { recv, .. } => Some(recv),
            StreamState::RecvOnly { recv } => Some(recv),
            StreamState::SendOnly { .. } => None,
        }
    }

    /// Both halves are terminal (or don't exist)
    pub fn is_terminal(&self) -> bool {
        match self {
            StreamState::Bidi { send, recv } => send.is_terminal() && recv.is_terminal(),
            StreamState::SendOnly { send } => send.is_terminal(),
            StreamState::RecvOnly { recv } => recv.is_terminal(),
        }
    }
}
