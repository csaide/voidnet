use crate::net::timer_wheel::{TimerHandle, TimerId};

/// The six distinct timer kinds associated with a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpTimerKind {
    Retransmit = 0,
    DelayedAck = 1,
    Persist = 2,
    KeepAlive = 3,
    TimeWait = 4,
    Linger = 5,
}

impl From<u8> for TcpTimerKind {
    fn from(value: u8) -> Self {
        match value {
            0 => TcpTimerKind::Retransmit,
            1 => TcpTimerKind::DelayedAck,
            2 => TcpTimerKind::Persist,
            3 => TcpTimerKind::KeepAlive,
            4 => TcpTimerKind::TimeWait,
            5 => TcpTimerKind::Linger,
            v => panic!("invalid TcpTimerKind discriminant: {v}"),
        }
    }
}

/// Pack a connection key and timer kind into a [`TimerId`].
///
/// The low 8 bits hold the `kind` discriminant; bits 8 and above hold `key`.
pub fn tcp_timer_id(key: usize, kind: TcpTimerKind) -> TimerId {
    TimerId((key as u64) << 8 | kind as u64)
}

/// Unpack a [`TimerId`] previously created by [`tcp_timer_id`].
pub fn unpack_tcp_timer_id(id: TimerId) -> (usize, TcpTimerKind) {
    let kind = TcpTimerKind::from(id.0 as u8);
    let key = (id.0 >> 8) as usize;
    (key, kind)
}

/// Stores one optional [`TimerHandle`] per [`TcpTimerKind`].
pub struct TcpTimerHandles {
    pub handles: [Option<TimerHandle>; 6],
}

impl TcpTimerHandles {
    /// Create a new handle store with all slots empty.
    pub fn new() -> Self {
        Self { handles: [None; 6] }
    }

    /// Return the handle for `kind`, if one is armed.
    pub fn get(&self, kind: TcpTimerKind) -> Option<TimerHandle> {
        self.handles[kind as usize]
    }

    /// Store `handle` for `kind`.
    pub fn set(&mut self, kind: TcpTimerKind, handle: TimerHandle) {
        self.handles[kind as usize] = Some(handle);
    }

    /// Clear the handle for `kind`.
    pub fn clear(&mut self, kind: TcpTimerKind) {
        self.handles[kind as usize] = None;
    }

    /// Return `true` if a handle is currently stored for `kind`.
    pub fn is_armed(&self, kind: TcpTimerKind) -> bool {
        self.handles[kind as usize].is_some()
    }

    /// Cancel the timer for `kind` on `wheel` (if armed), then arm a new one
    /// at `deadline_ms` with the given `key`. Stores the new handle.
    pub fn arm(
        &mut self,
        kind: TcpTimerKind,
        key: usize,
        deadline: coarsetime::Instant,
        wheel: &mut crate::net::timer_wheel::TimerWheel,
    ) {
        if let Some(old) = self.get(kind) {
            wheel.cancel(old);
        }
        let handle = wheel.arm(tcp_timer_id(key, kind), deadline);
        self.set(kind, handle);
    }

    /// Cancel the timer for `kind` on `wheel` (if armed), then clear the handle.
    pub fn cancel_timer(
        &mut self,
        kind: TcpTimerKind,
        wheel: &mut crate::net::timer_wheel::TimerWheel,
    ) {
        if let Some(old) = self.get(kind) {
            wheel.cancel(old);
            self.clear(kind);
        }
    }

    /// Cancel all armed timers on `wheel` and clear all handles.
    pub fn cancel_all(&mut self, wheel: &mut crate::net::timer_wheel::TimerWheel) {
        for slot in self.handles.iter_mut() {
            if let Some(h) = slot.take() {
                wheel.cancel(h);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let key = 12345usize;
        let kind = TcpTimerKind::Retransmit;
        let id = tcp_timer_id(key, kind);
        let (got_key, got_kind) = unpack_tcp_timer_id(id);
        assert_eq!(got_key, key);
        assert_eq!(got_kind, kind);
    }

    #[test]
    fn pack_unpack_all_kinds() {
        let key = 999usize;
        let all_kinds = [
            TcpTimerKind::Retransmit,
            TcpTimerKind::DelayedAck,
            TcpTimerKind::Persist,
            TcpTimerKind::KeepAlive,
            TcpTimerKind::TimeWait,
            TcpTimerKind::Linger,
        ];
        for kind in all_kinds {
            let id = tcp_timer_id(key, kind);
            let (got_key, got_kind) = unpack_tcp_timer_id(id);
            assert_eq!(got_key, key, "key mismatch for {kind:?}");
            assert_eq!(got_kind, kind, "kind mismatch for {kind:?}");
        }
    }

    #[test]
    fn tcp_timer_handles_default_all_none() {
        let handles = TcpTimerHandles::new();
        let all_kinds = [
            TcpTimerKind::Retransmit,
            TcpTimerKind::DelayedAck,
            TcpTimerKind::Persist,
            TcpTimerKind::KeepAlive,
            TcpTimerKind::TimeWait,
            TcpTimerKind::Linger,
        ];
        for kind in all_kinds {
            assert!(
                handles.get(kind).is_none(),
                "{kind:?} should be None initially"
            );
        }
    }

    #[test]
    fn set_and_get_handle() {
        let mut handles = TcpTimerHandles::new();
        let handle = TimerHandle::from_raw(42);
        handles.set(TcpTimerKind::KeepAlive, handle);
        assert_eq!(handles.get(TcpTimerKind::KeepAlive), Some(handle));
    }

    #[test]
    fn clear_handle() {
        let mut handles = TcpTimerHandles::new();
        let handle = TimerHandle::from_raw(7);
        handles.set(TcpTimerKind::TimeWait, handle);
        handles.clear(TcpTimerKind::TimeWait);
        assert!(!handles.is_armed(TcpTimerKind::TimeWait));
    }

    #[test]
    fn is_armed_returns_false_when_not_set() {
        let handles = TcpTimerHandles::new();
        let all_kinds = [
            TcpTimerKind::Retransmit,
            TcpTimerKind::DelayedAck,
            TcpTimerKind::Persist,
            TcpTimerKind::KeepAlive,
            TcpTimerKind::TimeWait,
            TcpTimerKind::Linger,
        ];
        for kind in all_kinds {
            assert!(!handles.is_armed(kind), "{kind:?} should not be armed");
        }
    }
}
