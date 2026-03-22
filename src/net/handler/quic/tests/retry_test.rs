use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::crypto::retry::{
    compute_retry_integrity_tag, verify_retry_integrity_tag,
};
use crate::net::handler::quic::token::RetryToken;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use coarsetime::{Duration, Instant};

#[test]
fn retry_tag_deterministic() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08]; // fake retry header
    let tag1 = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);
    let tag2 = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);
    assert_eq!(tag1, tag2);
}

#[test]
fn retry_tag_verify_roundtrip() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08];
    let tag = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);

    let mut packet_with_tag = packet.to_vec();
    packet_with_tag.extend_from_slice(&tag);

    assert!(verify_retry_integrity_tag(
        &odcid,
        &packet_with_tag,
        0x00000001
    ));
}

#[test]
fn retry_tag_tampered_fails() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08];
    let tag = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);

    let mut packet_with_tag = packet.to_vec();
    packet_with_tag.extend_from_slice(&tag);
    packet_with_tag[0] ^= 0x01; // tamper

    assert!(!verify_retry_integrity_tag(
        &odcid,
        &packet_with_tag,
        0x00000001
    ));
}

#[test]
fn retry_tag_wrong_odcid_fails() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08];
    let tag = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);

    let mut packet_with_tag = packet.to_vec();
    packet_with_tag.extend_from_slice(&tag);

    let wrong_odcid = [0x00; 8];
    assert!(!verify_retry_integrity_tag(
        &wrong_odcid,
        &packet_with_tag,
        0x00000001
    ));
}

#[test]
fn retry_token_expiry() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433);
    let cid = ConnectionId::from_slice(&[1, 2, 3, 4]);
    let now = Instant::now();
    let token = RetryToken::new(cid, addr, now);
    assert!(!token.is_expired(now, Duration::from_secs(30)));
    // Can't easily test expiry without sleeping, so just verify the logic
    let future = now + Duration::from_secs(31);
    assert!(token.is_expired(future, Duration::from_secs(30)));
}
