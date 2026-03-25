use crate::net::handler::quic::connection::Side;
use crate::net::handler::quic::connection_id::{CidSet, ConnectionId};
use crate::net::handler::quic::transport::params::{PreferredAddress, TransportParams};

#[test]
fn preferred_address_encode_decode_round_trip() {
    let pa = PreferredAddress {
        ipv4_address: [192, 168, 1, 100],
        ipv4_port: 4433,
        ipv6_address: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ],
        ipv6_port: 4434,
        connection_id: ConnectionId::from_slice(&[0xde, 0xad, 0xbe, 0xef]),
        stateless_reset_token: [0xaa; 16],
    };

    let params = TransportParams {
        preferred_address: Some(pa),
        original_destination_connection_id: Some(ConnectionId::from_slice(&[0x01])),
        ..Default::default()
    };

    let mut buf = [0u8; 512];
    let len = params.encode(&mut buf);
    assert!(len > 0);

    let decoded = TransportParams::decode(&buf[..len]).expect("decode should succeed");
    let decoded_pa = decoded
        .preferred_address
        .as_ref()
        .expect("preferred_address should be Some");
    assert_eq!(decoded_pa.ipv4_address, [192, 168, 1, 100]);
    assert_eq!(decoded_pa.ipv4_port, 4433);
    assert_eq!(
        decoded_pa.ipv6_address,
        [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01
        ]
    );
    assert_eq!(decoded_pa.ipv6_port, 4434);
    assert_eq!(
        decoded_pa.connection_id,
        ConnectionId::from_slice(&[0xde, 0xad, 0xbe, 0xef])
    );
    assert_eq!(decoded_pa.stateless_reset_token, [0xaa; 16]);
}

#[test]
fn preferred_address_different_cid_lengths() {
    // Test with zero-length CID
    let pa_empty = PreferredAddress {
        ipv4_address: [10, 0, 0, 1],
        ipv4_port: 443,
        ipv6_address: [0; 16],
        ipv6_port: 0,
        connection_id: ConnectionId::empty(),
        stateless_reset_token: [0xbb; 16],
    };

    let params = TransportParams {
        preferred_address: Some(pa_empty),
        original_destination_connection_id: Some(ConnectionId::from_slice(&[0x01])),
        ..Default::default()
    };

    let mut buf = [0u8; 512];
    let len = params.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..len]).expect("decode empty CID");
    let dp = decoded.preferred_address.as_ref().unwrap();
    assert!(dp.connection_id.is_empty());
    assert_eq!(dp.ipv4_address, [10, 0, 0, 1]);
    assert_eq!(dp.ipv4_port, 443);

    // Test with maximum-length CID (20 bytes)
    let pa_max = PreferredAddress {
        ipv4_address: [172, 16, 0, 1],
        ipv4_port: 8443,
        ipv6_address: [0xff; 16],
        ipv6_port: 9443,
        connection_id: ConnectionId::from_slice(&[0x01; 20]),
        stateless_reset_token: [0xcc; 16],
    };

    let params2 = TransportParams {
        preferred_address: Some(pa_max),
        original_destination_connection_id: Some(ConnectionId::from_slice(&[0x01])),
        ..Default::default()
    };

    let mut buf2 = [0u8; 512];
    let len2 = params2.encode(&mut buf2);
    let decoded2 = TransportParams::decode(&buf2[..len2]).expect("decode max CID");
    let dp2 = decoded2.preferred_address.as_ref().unwrap();
    assert_eq!(dp2.connection_id.len(), 20);
    assert_eq!(dp2.connection_id, ConnectionId::from_slice(&[0x01; 20]));
    assert_eq!(dp2.ipv6_address, [0xff; 16]);
    assert_eq!(dp2.ipv6_port, 9443);
}

#[test]
fn preferred_address_cid_sequence_number_1() {
    // Verify CID from preferred_address gets registered with sequence number 1 (RFC 9000 §5.1.1)
    let pa_cid = ConnectionId::from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    let mut scid_set = CidSet::new();
    // Sequence 0 is the initial CID
    scid_set.push_with_seq(ConnectionId::from_slice(&[0x01, 0x02]), 0);

    // Simulate what processor does: register preferred_address CID with seq 1
    assert!(scid_set.push_with_seq(pa_cid, 1));
    assert_eq!(scid_set.len(), 2);
    assert!(scid_set.contains(&pa_cid));

    // Verify we can look up by sequence number 1
    let removed = scid_set.remove_by_seq(1);
    assert_eq!(removed, Some(pa_cid));
    assert_eq!(scid_set.len(), 1);
}

#[test]
fn preferred_address_with_disable_active_migration() {
    // RFC 9000 §9.6: Client STILL processes preferred_address even when
    // disable_active_migration is set by the server.
    let pa = PreferredAddress {
        ipv4_address: [10, 0, 0, 1],
        ipv4_port: 4433,
        ipv6_address: [0; 16],
        ipv6_port: 0,
        connection_id: ConnectionId::from_slice(&[0xab, 0xcd]),
        stateless_reset_token: [0x11; 16],
    };

    let params = TransportParams {
        preferred_address: Some(pa),
        disable_active_migration: true,
        original_destination_connection_id: Some(ConnectionId::from_slice(&[0x01])),
        ..Default::default()
    };

    // Server-side validation should pass — preferred_address with disable_active_migration is valid
    assert!(params.validate_for_side(Side::Server).is_ok());

    // Simulate client-side processing: preferred_address should still be processed
    let pa_ref = params.preferred_address.as_ref().unwrap();
    let mut scid_set = CidSet::new();
    scid_set.push_with_seq(ConnectionId::from_slice(&[0x01]), 0);

    // Client registers the CID regardless of disable_active_migration
    assert!(scid_set.push_with_seq(pa_ref.connection_id, 1));
    assert!(scid_set.contains(&ConnectionId::from_slice(&[0xab, 0xcd])));
}

#[test]
fn preferred_address_client_must_not_send() {
    let pa = PreferredAddress {
        ipv4_address: [127, 0, 0, 1],
        ipv4_port: 4433,
        ipv6_address: [0; 16],
        ipv6_port: 0,
        connection_id: ConnectionId::from_slice(&[0x01, 0x02]),
        stateless_reset_token: [0; 16],
    };

    let params = TransportParams {
        preferred_address: Some(pa),
        ..Default::default()
    };

    // preferred_address is server-only; client MUST NOT send it (RFC 9000 §18.2)
    assert!(params.validate_for_side(Side::Client).is_err());
}
