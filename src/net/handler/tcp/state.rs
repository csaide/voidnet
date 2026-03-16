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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_synchronized() {
        let synchronized = [
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::CloseWait,
            TcpState::Closing,
            TcpState::LastAck,
            TcpState::TimeWait,
        ];
        let not_synchronized = [
            TcpState::Closed,
            TcpState::Listen,
            TcpState::SynSent,
            TcpState::SynReceived,
        ];
        for state in synchronized {
            assert!(
                state.is_synchronized(),
                "{:?} should be synchronized",
                state
            );
        }
        for state in not_synchronized {
            assert!(
                !state.is_synchronized(),
                "{:?} should not be synchronized",
                state
            );
        }
    }

    #[test]
    fn is_remote_closed() {
        let remote_closed = [
            TcpState::CloseWait,
            TcpState::LastAck,
            TcpState::TimeWait,
            TcpState::Closing,
            TcpState::Closed,
        ];
        let not_remote_closed = [
            TcpState::Listen,
            TcpState::SynSent,
            TcpState::SynReceived,
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::FinWait2,
        ];
        for state in remote_closed {
            assert!(
                state.is_remote_closed(),
                "{:?} should be remote_closed",
                state
            );
        }
        for state in not_remote_closed {
            assert!(
                !state.is_remote_closed(),
                "{:?} should not be remote_closed",
                state
            );
        }
    }
}
