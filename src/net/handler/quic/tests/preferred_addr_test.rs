use crate::net::handler::quic::connection_id::ConnectionId;
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

    let mut params = TransportParams::default();
    params.preferred_address = Some(pa);
    // Server-only param requires original_destination_connection_id for validation
    params.original_destination_connection_id = Some(ConnectionId::from_slice(&[0x01]));

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

    let mut params = TransportParams::default();
    params.preferred_address = Some(pa_empty);
    params.original_destination_connection_id = Some(ConnectionId::from_slice(&[0x01]));

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

    let mut params2 = TransportParams::default();
    params2.preferred_address = Some(pa_max);
    params2.original_destination_connection_id = Some(ConnectionId::from_slice(&[0x01]));

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
fn preferred_address_client_must_not_send() {
    use crate::net::handler::quic::connection::Side;

    let pa = PreferredAddress {
        ipv4_address: [127, 0, 0, 1],
        ipv4_port: 4433,
        ipv6_address: [0; 16],
        ipv6_port: 0,
        connection_id: ConnectionId::from_slice(&[0x01, 0x02]),
        stateless_reset_token: [0; 16],
    };

    let mut params = TransportParams::default();
    params.preferred_address = Some(pa);

    // preferred_address is server-only; client MUST NOT send it
    assert!(params.validate_for_side(Side::Client).is_err());
}
