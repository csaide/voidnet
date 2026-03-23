use crate::net::handler::quic::transport::params::{TransportParams, VersionInformation};
use crate::net::handler::quic::transport::version::{
    QUIC_VERSION_1, QUIC_VERSION_2, rustls_quic_version,
};

#[test]
fn version_info_encode_decode_roundtrip() {
    let mut params = TransportParams::default();
    params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_1,
        other_versions: vec![QUIC_VERSION_1, QUIC_VERSION_2],
    });

    let mut buf = [0u8; 512];
    let written = params.encode(&mut buf);
    assert!(written > 0);

    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");
    let vi = decoded
        .version_information
        .expect("version_information should be present");
    assert_eq!(vi.chosen_version, QUIC_VERSION_1);
    assert_eq!(vi.other_versions, vec![QUIC_VERSION_1, QUIC_VERSION_2]);
}

#[test]
fn version_info_encode_decode_single_version() {
    let mut params = TransportParams::default();
    params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_2,
        other_versions: vec![QUIC_VERSION_2],
    });

    let mut buf = [0u8; 512];
    let written = params.encode(&mut buf);

    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");
    let vi = decoded
        .version_information
        .expect("version_information should be present");
    assert_eq!(vi.chosen_version, QUIC_VERSION_2);
    assert_eq!(vi.other_versions, vec![QUIC_VERSION_2]);
}

#[test]
fn version_info_none_not_encoded() {
    let params = TransportParams::default();
    assert!(params.version_information.is_none());

    let mut buf = [0u8; 512];
    let written = params.encode(&mut buf);

    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");
    assert!(decoded.version_information.is_none());
}

#[test]
fn validate_version_info_peer_chosen_not_in_our_list() {
    let mut params = TransportParams::default();
    params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_2,
        other_versions: vec![QUIC_VERSION_1, QUIC_VERSION_2],
    });

    // We only support v1, but peer chose v2
    let result = params.validate_version_info(QUIC_VERSION_1, &[QUIC_VERSION_1]);
    assert!(
        result.is_err(),
        "should fail: peer's chosen_version not in our list"
    );
}

#[test]
fn validate_version_info_our_version_not_in_peer_list() {
    let mut params = TransportParams::default();
    params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_1,
        other_versions: vec![QUIC_VERSION_2], // peer only lists v2
    });

    // We're using v1, peer lists v1 as chosen but only v2 in other_versions
    let result = params.validate_version_info(QUIC_VERSION_1, &[QUIC_VERSION_1, QUIC_VERSION_2]);
    assert!(
        result.is_err(),
        "should fail: our version not in peer's list"
    );
}

#[test]
fn validate_version_info_valid() {
    let mut params = TransportParams::default();
    params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_1,
        other_versions: vec![QUIC_VERSION_1, QUIC_VERSION_2],
    });

    let result = params.validate_version_info(QUIC_VERSION_1, &[QUIC_VERSION_1, QUIC_VERSION_2]);
    assert!(result.is_ok());
}

#[test]
fn version_info_decode_bad_length() {
    // Manually encode a version_information param with length not divisible by 4
    use crate::net::handler::quic::transport::varint::encode_varint;

    let mut buf = [0u8; 64];
    let mut pos = 0;
    pos += encode_varint(0x11, &mut buf[pos..]); // VERSION_INFORMATION
    pos += encode_varint(5, &mut buf[pos..]); // length=5 (not multiple of 4)
    buf[pos..pos + 5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01, 0xFF]);
    pos += 5;

    let result = TransportParams::decode(&buf[..pos]);
    assert!(result.is_err(), "should fail on length not divisible by 4");
}

// --- Task 13b tests ---

#[test]
fn compat_vn_both_support_v1_and_v2() {
    // Both sides advertise v1+v2 in version_information, connection uses v1 (default).
    // Verify version_information is exchanged correctly and validation passes.
    let mut client_params = TransportParams::default();
    client_params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_1,
        other_versions: vec![QUIC_VERSION_1, QUIC_VERSION_2],
    });

    let mut server_params = TransportParams::default();
    server_params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_1,
        other_versions: vec![QUIC_VERSION_1, QUIC_VERSION_2],
    });

    let our_available = [QUIC_VERSION_1, QUIC_VERSION_2];
    let current_version = QUIC_VERSION_1;

    // Client validates server's version_information
    assert!(
        server_params
            .validate_version_info(current_version, &our_available)
            .is_ok()
    );

    // Server validates client's version_information
    assert!(
        client_params
            .validate_version_info(current_version, &our_available)
            .is_ok()
    );

    // Encode/decode round-trip preserves version_information
    let mut buf = [0u8; 512];
    let written = client_params.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..written]).unwrap();
    let vi = decoded.version_information.unwrap();
    assert_eq!(vi.chosen_version, QUIC_VERSION_1);
    assert_eq!(vi.other_versions, vec![QUIC_VERSION_1, QUIC_VERSION_2]);
}

#[test]
fn rustls_quic_version_v1() {
    let v = rustls_quic_version(QUIC_VERSION_1);
    assert!(matches!(v, rustls::quic::Version::V1));
}

#[test]
fn rustls_quic_version_v2() {
    let v = rustls_quic_version(QUIC_VERSION_2);
    assert!(matches!(v, rustls::quic::Version::V2));
}

#[test]
fn rustls_quic_version_unknown_defaults_to_v1() {
    let v = rustls_quic_version(0xdeadbeef);
    assert!(matches!(v, rustls::quic::Version::V1));
}

#[test]
fn negotiated_version_field_defaults_to_none() {
    use crate::net::handler::quic::connection::{QuicConnectionState, Side};
    use crate::net::handler::quic::connection_id::ConnectionId;
    use crate::net::handler::quic::transport::params::TransportParams;

    let conn = QuicConnectionState::new(
        ConnectionId::empty(),
        Side::Server,
        TransportParams::default(),
        1200,
        coarsetime::Instant::now(),
    );
    assert!(conn.negotiated_version.is_none());
}
