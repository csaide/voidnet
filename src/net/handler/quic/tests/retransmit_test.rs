use crate::net::handler::quic::transport::frame::StreamId;
use crate::net::handler::quic::transport::frame_log::{FrameLog, SentFrame};
use crate::net::handler::quic::transport::retransmit::build_retransmit_queue;

#[test]
fn empty_loss_produces_empty_queue() {
    let log = FrameLog::new(64);
    let queue = build_retransmit_queue(&log, &[]);
    assert!(queue.is_empty());
}

#[test]
fn lost_crypto_queued() {
    let mut log = FrameLog::new(64);
    let start = log.head();
    log.push(SentFrame::Crypto {
        space: 0,
        offset: 0,
        len: 100,
    });
    let end = log.head();
    let queue = build_retransmit_queue(&log, &[(start, end)]);
    assert_eq!(queue.crypto.len(), 1);
    assert_eq!(queue.crypto[0], (0, 0, 100));
}

#[test]
fn lost_stream_queued() {
    let mut log = FrameLog::new(64);
    let start = log.head();
    log.push(SentFrame::Stream {
        id: StreamId(4),
        offset: 0,
        len: 500,
        fin: false,
    });
    let end = log.head();
    let queue = build_retransmit_queue(&log, &[(start, end)]);
    assert_eq!(queue.streams.len(), 1);
}

#[test]
fn ack_and_ping_not_retransmitted() {
    let mut log = FrameLog::new(64);
    let start = log.head();
    log.push(SentFrame::Ack { space: 0 });
    log.push(SentFrame::Ping);
    log.push(SentFrame::Padding);
    let end = log.head();
    let queue = build_retransmit_queue(&log, &[(start, end)]);
    assert!(queue.is_empty());
}

#[test]
fn max_data_deduplicates() {
    let mut log = FrameLog::new(64);
    let start = log.head();
    log.push(SentFrame::MaxData(1000));
    log.push(SentFrame::MaxData(2000));
    let end = log.head();
    let queue = build_retransmit_queue(&log, &[(start, end)]);
    assert!(queue.max_data); // just a flag, current value used on re-send
}

#[test]
fn handshake_done_retransmitted() {
    let mut log = FrameLog::new(64);
    let start = log.head();
    log.push(SentFrame::HandshakeDone);
    let end = log.head();
    let queue = build_retransmit_queue(&log, &[(start, end)]);
    assert!(queue.handshake_done);
}

#[test]
fn multiple_lost_packets() {
    let mut log = FrameLog::new(64);
    let s1 = log.head();
    log.push(SentFrame::Crypto {
        space: 0,
        offset: 0,
        len: 50,
    });
    let e1 = log.head();
    let s2 = log.head();
    log.push(SentFrame::Stream {
        id: StreamId(0),
        offset: 0,
        len: 100,
        fin: true,
    });
    let e2 = log.head();
    let queue = build_retransmit_queue(&log, &[(s1, e1), (s2, e2)]);
    assert_eq!(queue.crypto.len(), 1);
    assert_eq!(queue.streams.len(), 1);
}
