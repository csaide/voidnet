use crate::net::timer_wheel::{TimerHandle, TimerId};

/// The eight distinct timer kinds associated with a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QuicTimerKind {
    LossDetection = 0,
    Idle = 1,
    Ack = 2,
    Handshake = 3,
    Draining = 4,
    KeyDiscard = 5,
    PathValidation = 6,
    PmtuProbe = 7,
}

impl From<u8> for QuicTimerKind {
    fn from(value: u8) -> Self {
        match value {
            0 => QuicTimerKind::LossDetection,
            1 => QuicTimerKind::Idle,
            2 => QuicTimerKind::Ack,
            3 => QuicTimerKind::Handshake,
            4 => QuicTimerKind::Draining,
            5 => QuicTimerKind::KeyDiscard,
            6 => QuicTimerKind::PathValidation,
            7 => QuicTimerKind::PmtuProbe,
            v => panic!("invalid QuicTimerKind discriminant: {v}"),
        }
    }
}

/// Pack a connection key and timer kind into a [`TimerId`].
///
/// The low 8 bits hold the `kind` discriminant; bits 8..62 hold `key`;
/// bit 63 is set to distinguish QUIC timers from TCP timers in the
/// shared [`TimerWheel`].
pub fn quic_timer_id(key: usize, kind: QuicTimerKind) -> TimerId {
    TimerId((1u64 << 63) | (key as u64) << 8 | kind as u64)
}

/// Unpack a [`TimerId`] previously created by [`quic_timer_id`].
pub fn unpack_quic_timer_id(id: TimerId) -> (usize, QuicTimerKind) {
    let kind = QuicTimerKind::from((id.0 & 0xFF) as u8);
    let key = ((id.0 & !(1u64 << 63)) >> 8) as usize;
    (key, kind)
}

/// Returns `true` if `id` was created by [`quic_timer_id`] (bit 63 set).
pub fn is_quic_timer(id: TimerId) -> bool {
    id.0 & (1u64 << 63) != 0
}

/// Stores one optional [`TimerHandle`] per [`QuicTimerKind`].
pub struct QuicTimerHandles {
    pub handles: [Option<TimerHandle>; 8],
}

impl QuicTimerHandles {
    /// Create a new handle store with all slots empty.
    pub fn new() -> Self {
        Self { handles: [None; 8] }
    }

    /// Return the handle for `kind`, if one is armed.
    pub fn get(&self, kind: QuicTimerKind) -> Option<TimerHandle> {
        self.handles[kind as usize]
    }

    /// Store `handle` for `kind`.
    pub fn set(&mut self, kind: QuicTimerKind, handle: TimerHandle) {
        self.handles[kind as usize] = Some(handle);
    }

    /// Clear the handle for `kind`.
    pub fn clear(&mut self, kind: QuicTimerKind) {
        self.handles[kind as usize] = None;
    }

    /// Return `true` if a handle is currently stored for `kind`.
    pub fn is_armed(&self, kind: QuicTimerKind) -> bool {
        self.handles[kind as usize].is_some()
    }

    /// Cancel the timer for `kind` on `wheel` (if armed), then arm a new one
    /// at `deadline` with the given `key`. Stores the new handle.
    pub fn arm(
        &mut self,
        kind: QuicTimerKind,
        key: usize,
        deadline: coarsetime::Instant,
        wheel: &mut crate::net::timer_wheel::TimerWheel,
    ) {
        if let Some(old) = self.get(kind) {
            wheel.cancel(old);
        }
        let handle = wheel.arm(quic_timer_id(key, kind), deadline);
        self.set(kind, handle);
    }

    /// Cancel the timer for `kind` on `wheel` (if armed), then clear the handle.
    pub fn cancel_timer(
        &mut self,
        kind: QuicTimerKind,
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
