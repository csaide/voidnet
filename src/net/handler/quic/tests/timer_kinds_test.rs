use crate::net::handler::quic::timer_kinds::{
    QuicTimerHandles, QuicTimerKind, quic_timer_id, unpack_quic_timer_id,
};
use crate::net::timer_wheel::TimerHandle;

const ALL_KINDS: [QuicTimerKind; 8] = [
    QuicTimerKind::LossDetection,
    QuicTimerKind::Idle,
    QuicTimerKind::Ack,
    QuicTimerKind::Handshake,
    QuicTimerKind::Draining,
    QuicTimerKind::KeyDiscard,
    QuicTimerKind::PathValidation,
    QuicTimerKind::PmtuProbe,
];

#[test]
fn timer_id_roundtrip() {
    let key = 12345usize;
    for kind in ALL_KINDS {
        let id = quic_timer_id(key, kind);
        let (got_key, got_kind) = unpack_quic_timer_id(id);
        assert_eq!(got_key, key, "key mismatch for {kind:?}");
        assert_eq!(got_kind, kind, "kind mismatch for {kind:?}");
    }
}

#[test]
fn timer_id_large_key() {
    let key = 1_000_000usize;
    for kind in ALL_KINDS {
        let id = quic_timer_id(key, kind);
        let (got_key, got_kind) = unpack_quic_timer_id(id);
        assert_eq!(got_key, key, "key mismatch for {kind:?} with large key");
        assert_eq!(got_kind, kind, "kind mismatch for {kind:?} with large key");
    }
}

#[test]
fn timer_handles_initially_none() {
    let handles = QuicTimerHandles::new();
    for kind in ALL_KINDS {
        assert!(
            handles.get(kind).is_none(),
            "{kind:?} should be None initially"
        );
    }
}

#[test]
fn timer_handles_set_get_clear() {
    let mut handles = QuicTimerHandles::new();
    let handle = TimerHandle::from_raw(42);

    handles.set(QuicTimerKind::LossDetection, handle);
    assert_eq!(
        handles.get(QuicTimerKind::LossDetection),
        Some(handle),
        "handle should be set"
    );

    handles.clear(QuicTimerKind::LossDetection);
    assert!(
        handles.get(QuicTimerKind::LossDetection).is_none(),
        "handle should be cleared"
    );

    // Verify other slots unaffected
    let handle2 = TimerHandle::from_raw(99);
    handles.set(QuicTimerKind::Idle, handle2);
    assert_eq!(handles.get(QuicTimerKind::Idle), Some(handle2));
    assert!(handles.get(QuicTimerKind::LossDetection).is_none());
}
