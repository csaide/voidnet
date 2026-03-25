use crate::net::handler::quic::transport::frame_log::{FrameLog, SentFrame};
use crate::net::handler::quic::transport::packet_builder::PacketBuilder;

#[test]
fn frame_log_push_and_get() {
    let mut log = FrameLog::new(8);
    let idx = log.push(SentFrame::Ping);
    assert!(log.get(idx).is_some());
}

#[test]
fn frame_log_wraps() {
    let mut log = FrameLog::new(4);
    for _i in 0..10 {
        log.push(SentFrame::Ping);
    }
    // Old entries overwritten
    assert!(log.get(0).is_none()); // overwritten
    assert!(log.get(9).is_some()); // latest still there
}

#[test]
fn frame_log_range() {
    let mut log = FrameLog::new(16);
    let start = log.head();
    log.push(SentFrame::Ping);
    log.push(SentFrame::HandshakeDone);
    let end = log.head();
    let frames: Vec<_> = log.range(start, end).collect();
    assert_eq!(frames.len(), 2);
}

#[test]
fn packet_builder_long_header_initial() {
    let mut buf = vec![0u8; 1400];
    let log = FrameLog::new(64);
    let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
    let scid = [9, 10, 11, 12];

    let builder =
        PacketBuilder::begin_long(&mut buf, 0x00, 0x00000001, &dcid, &scid, 0, 0, &log, &[])
            .unwrap();

    assert!(builder.remaining() > 0);
    assert!(buf[0] & 0x80 != 0); // long header
}

#[test]
fn packet_builder_short_header() {
    let mut buf = vec![0u8; 1400];
    let log = FrameLog::new(64);
    let dcid = [1, 2, 3, 4];

    let builder = PacketBuilder::begin_short(&mut buf, &dcid, 42, 40, false, &log).unwrap();

    assert!(builder.remaining() > 0);
    assert!(buf[0] & 0x80 == 0); // short header
}

#[test]
fn packet_builder_write_crypto_and_finish() {
    let mut buf = vec![0u8; 1400];
    let mut log = FrameLog::new(64);
    let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
    let scid: [u8; 0] = [];

    let mut builder =
        PacketBuilder::begin_long(&mut buf, 0x00, 0x00000001, &dcid, &scid, 0, 0, &log, &[])
            .unwrap();

    let crypto_data = b"ClientHello data here";
    let written = builder.write_crypto(0, crypto_data, 0, &mut log);
    assert_eq!(written, crypto_data.len());

    let (start, end) = builder.frame_range(&log);
    assert_eq!(end - start, 1); // one frame logged

    let total = builder.finish();
    assert!(total > 0);
}

#[test]
fn packet_builder_pad_to_1200() {
    let mut buf = vec![0u8; 1400];
    let mut log = FrameLog::new(64);
    let dcid = [1, 2, 3, 4, 5, 6, 7, 8];

    let mut builder =
        PacketBuilder::begin_long(&mut buf, 0x00, 0x00000001, &dcid, &[], 0, 0, &log, &[]).unwrap();

    builder.write_crypto(0, b"hello", 0, &mut log);
    builder.pad_to(1200);
    let total = builder.finish();
    assert!(total >= 1200);
}
