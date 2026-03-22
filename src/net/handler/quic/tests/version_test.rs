use crate::net::handler::quic::transport::version::{
    QUIC_VERSION_1, build_version_negotiation, is_reserved_version, is_supported_version,
    should_process_version_negotiation,
};

#[test]
fn is_supported_version_v1() {
    assert!(is_supported_version(QUIC_VERSION_1));
}

#[test]
fn is_supported_version_unknown() {
    assert!(!is_supported_version(0xdeadbeef));
}

#[test]
fn is_reserved_version_pattern() {
    assert!(is_reserved_version(0x1a2a3a4a));
}

#[test]
fn build_vn_packet() {
    let dcid = [0x01, 0x02, 0x03, 0x04];
    let scid = [0xaa, 0xbb];
    let supported = [QUIC_VERSION_1];

    let expected_len = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 4;
    let mut buf = vec![0u8; expected_len];
    let written = build_version_negotiation(&mut buf, &dcid, &scid, &supported);

    // total bytes written
    assert_eq!(written, expected_len);

    // first byte: long header form (bit 7 must be set, bits 0-6 randomized)
    assert!(buf[0] & 0x80 != 0, "bit 7 (long header form) must be set");

    // bytes 1-4: version = 0
    assert_eq!(&buf[1..5], &0u32.to_be_bytes());

    // byte 5: dcid_len
    assert_eq!(buf[5], dcid.len() as u8);

    // dcid bytes
    let dcid_start = 6;
    assert_eq!(&buf[dcid_start..dcid_start + dcid.len()], &dcid);

    // scid_len
    let scid_len_pos = dcid_start + dcid.len();
    assert_eq!(buf[scid_len_pos], scid.len() as u8);

    // scid bytes
    let scid_start = scid_len_pos + 1;
    assert_eq!(&buf[scid_start..scid_start + scid.len()], &scid);

    // supported versions
    let versions_start = scid_start + scid.len();
    assert_eq!(
        &buf[versions_start..versions_start + 4],
        &QUIC_VERSION_1.to_be_bytes()
    );
}

#[test]
fn discard_vn_after_processing() {
    // should_process returns false when we've already processed a packet
    assert!(!should_process_version_negotiation(true));
    // should_process returns true when we haven't processed any packet yet
    assert!(should_process_version_negotiation(false));
}
