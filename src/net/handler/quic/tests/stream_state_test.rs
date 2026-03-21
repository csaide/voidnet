use crate::net::handler::quic::stream::state::{RecvState, SendState, StreamState};

// --- Send state: valid transitions ---

#[test]
fn send_ready_to_send() {
    let mut s = SendState::Ready;
    assert!(s.transition(SendState::Send).is_ok());
    assert_eq!(s, SendState::Send);
}

#[test]
fn send_ready_to_data_sent() {
    let mut s = SendState::Ready;
    assert!(s.transition(SendState::DataSent).is_ok());
    assert_eq!(s, SendState::DataSent);
}

#[test]
fn send_ready_to_reset_sent() {
    let mut s = SendState::Ready;
    assert!(s.transition(SendState::ResetSent).is_ok());
    assert_eq!(s, SendState::ResetSent);
}

#[test]
fn send_send_to_data_sent() {
    let mut s = SendState::Send;
    assert!(s.transition(SendState::DataSent).is_ok());
    assert_eq!(s, SendState::DataSent);
}

#[test]
fn send_send_to_reset_sent() {
    let mut s = SendState::Send;
    assert!(s.transition(SendState::ResetSent).is_ok());
    assert_eq!(s, SendState::ResetSent);
}

#[test]
fn send_data_sent_to_data_recvd() {
    let mut s = SendState::DataSent;
    assert!(s.transition(SendState::DataRecvd).is_ok());
    assert_eq!(s, SendState::DataRecvd);
}

#[test]
fn send_data_sent_to_reset_sent() {
    let mut s = SendState::DataSent;
    assert!(s.transition(SendState::ResetSent).is_ok());
    assert_eq!(s, SendState::ResetSent);
}

#[test]
fn send_reset_sent_to_reset_recvd() {
    let mut s = SendState::ResetSent;
    assert!(s.transition(SendState::ResetRecvd).is_ok());
    assert_eq!(s, SendState::ResetRecvd);
}

// --- Send state: invalid transitions ---

#[test]
fn send_data_recvd_is_terminal() {
    let mut s = SendState::DataRecvd;
    assert!(s.transition(SendState::Send).is_err());
    assert!(s.transition(SendState::Ready).is_err());
    assert!(s.transition(SendState::ResetSent).is_err());
    assert_eq!(s, SendState::DataRecvd, "state must not change on error");
}

#[test]
fn send_reset_recvd_is_terminal() {
    let mut s = SendState::ResetRecvd;
    assert!(s.transition(SendState::Send).is_err());
    assert!(s.transition(SendState::DataSent).is_err());
    assert_eq!(s, SendState::ResetRecvd, "state must not change on error");
}

#[test]
fn send_send_to_ready_invalid() {
    let mut s = SendState::Send;
    assert!(s.transition(SendState::Ready).is_err());
    assert_eq!(s, SendState::Send);
}

// --- Recv state: valid transitions ---

#[test]
fn recv_recv_to_size_known() {
    let mut r = RecvState::Recv;
    assert!(r.transition(RecvState::SizeKnown).is_ok());
    assert_eq!(r, RecvState::SizeKnown);
}

#[test]
fn recv_recv_to_reset_recvd() {
    let mut r = RecvState::Recv;
    assert!(r.transition(RecvState::ResetRecvd).is_ok());
    assert_eq!(r, RecvState::ResetRecvd);
}

#[test]
fn recv_size_known_to_data_recvd() {
    let mut r = RecvState::SizeKnown;
    assert!(r.transition(RecvState::DataRecvd).is_ok());
    assert_eq!(r, RecvState::DataRecvd);
}

#[test]
fn recv_size_known_to_reset_recvd() {
    let mut r = RecvState::SizeKnown;
    assert!(r.transition(RecvState::ResetRecvd).is_ok());
    assert_eq!(r, RecvState::ResetRecvd);
}

#[test]
fn recv_data_recvd_to_data_read() {
    let mut r = RecvState::DataRecvd;
    assert!(r.transition(RecvState::DataRead).is_ok());
    assert_eq!(r, RecvState::DataRead);
}

// --- Recv state: invalid transitions ---

#[test]
fn recv_data_read_is_terminal() {
    let mut r = RecvState::DataRead;
    assert!(r.transition(RecvState::Recv).is_err());
    assert!(r.transition(RecvState::SizeKnown).is_err());
    assert!(r.transition(RecvState::DataRecvd).is_err());
    assert_eq!(r, RecvState::DataRead, "state must not change on error");
}

#[test]
fn recv_reset_recvd_is_terminal() {
    let mut r = RecvState::ResetRecvd;
    assert!(r.transition(RecvState::Recv).is_err());
    assert!(r.transition(RecvState::DataRead).is_err());
    assert_eq!(r, RecvState::ResetRecvd, "state must not change on error");
}

#[test]
fn recv_recv_to_data_recvd_invalid() {
    let mut r = RecvState::Recv;
    // Must go through SizeKnown first
    assert!(r.transition(RecvState::DataRecvd).is_err());
    assert_eq!(r, RecvState::Recv);
}

// --- StreamState ---

#[test]
fn bidi_stream_both_halves() {
    let s = StreamState::new_bidi();
    assert_eq!(s.send_state(), Some(&SendState::Ready));
    assert_eq!(s.recv_state(), Some(&RecvState::Recv));
}

#[test]
fn send_only_no_recv() {
    let s = StreamState::new_send_only();
    assert!(s.send_state().is_some());
    assert!(s.recv_state().is_none());
}

#[test]
fn recv_only_no_send() {
    let s = StreamState::new_recv_only();
    assert!(s.send_state().is_none());
    assert!(s.recv_state().is_some());
}

#[test]
fn bidi_terminal_when_both_done() {
    let mut s = StreamState::new_bidi();
    assert!(!s.is_terminal());

    // Drive send to terminal
    s.send_state_mut()
        .unwrap()
        .transition(SendState::DataSent)
        .unwrap();
    s.send_state_mut()
        .unwrap()
        .transition(SendState::DataRecvd)
        .unwrap();
    assert!(!s.is_terminal(), "recv half still open");

    // Drive recv to terminal
    s.recv_state_mut()
        .unwrap()
        .transition(RecvState::SizeKnown)
        .unwrap();
    s.recv_state_mut()
        .unwrap()
        .transition(RecvState::DataRecvd)
        .unwrap();
    s.recv_state_mut()
        .unwrap()
        .transition(RecvState::DataRead)
        .unwrap();
    assert!(s.is_terminal());
}

// --- Helper checks ---

#[test]
fn can_send_data_check() {
    assert!(SendState::Ready.can_send_data());
    assert!(SendState::Send.can_send_data());
    assert!(!SendState::DataSent.can_send_data());
    assert!(!SendState::DataRecvd.can_send_data());
    assert!(!SendState::ResetSent.can_send_data());
    assert!(!SendState::ResetRecvd.can_send_data());
}

#[test]
fn can_receive_data_check() {
    assert!(RecvState::Recv.can_receive_data());
    assert!(RecvState::SizeKnown.can_receive_data());
    assert!(!RecvState::DataRecvd.can_receive_data());
    assert!(!RecvState::DataRead.can_receive_data());
    assert!(!RecvState::ResetRecvd.can_receive_data());
}
