/// TCP connection state per RFC 9293.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// Returns `true` for states where the connection is synchronized
    /// (Established through TimeWait).
    #[inline]
    pub fn is_synchronized(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait
        )
    }

    /// Returns `true` when the remote side has sent a FIN.
    #[inline]
    pub fn is_remote_closed(self) -> bool {
        matches!(
            self,
            TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::TimeWait
                | TcpState::Closing
                | TcpState::Closed
        )
    }
}
