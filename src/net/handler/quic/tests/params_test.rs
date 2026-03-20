use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::transport::params::TransportParams;

#[test]
fn transport_params_defaults() {
    let p = TransportParams::default();
    assert_eq!(p.max_idle_timeout_ms, 0);
    assert_eq!(p.max_udp_payload_size, 65527);
    assert_eq!(p.active_connection_id_limit, 2);
    assert_eq!(p.initial_max_data, 0);
    assert_eq!(p.initial_max_stream_data_bidi_local, 0);
    assert_eq!(p.initial_max_stream_data_bidi_remote, 0);
    assert_eq!(p.initial_max_stream_data_uni, 0);
    assert_eq!(p.initial_max_streams_bidi, 0);
    assert_eq!(p.initial_max_streams_uni, 0);
    assert_eq!(p.max_ack_delay_ms, 25);
    assert_eq!(p.ack_delay_exponent, 3);
    assert!(!p.disable_active_migration);
    assert!(p.original_destination_connection_id.is_none());
    assert!(p.initial_source_connection_id.is_none());
    assert!(p.retry_source_connection_id.is_none());
    assert!(p.stateless_reset_token.is_none());
}

#[test]
fn transport_params_encode_decode_roundtrip() {
    let mut orig = TransportParams::default();
    orig.max_idle_timeout_ms = 30000;
    orig.max_udp_payload_size = 1452;
    orig.initial_max_data = 1_048_576;
    orig.initial_max_stream_data_bidi_local = 262_144;
    orig.initial_max_stream_data_bidi_remote = 131_072;
    orig.initial_max_stream_data_uni = 65_536;
    orig.initial_max_streams_bidi = 100;
    orig.initial_max_streams_uni = 50;
    orig.max_ack_delay_ms = 20;
    orig.ack_delay_exponent = 2;
    orig.active_connection_id_limit = 4;

    let mut buf = [0u8; 512];
    let written = orig.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");

    assert_eq!(decoded.max_idle_timeout_ms, orig.max_idle_timeout_ms);
    assert_eq!(decoded.max_udp_payload_size, orig.max_udp_payload_size);
    assert_eq!(decoded.initial_max_data, orig.initial_max_data);
    assert_eq!(
        decoded.initial_max_stream_data_bidi_local,
        orig.initial_max_stream_data_bidi_local
    );
    assert_eq!(
        decoded.initial_max_stream_data_bidi_remote,
        orig.initial_max_stream_data_bidi_remote
    );
    assert_eq!(
        decoded.initial_max_stream_data_uni,
        orig.initial_max_stream_data_uni
    );
    assert_eq!(
        decoded.initial_max_streams_bidi,
        orig.initial_max_streams_bidi
    );
    assert_eq!(
        decoded.initial_max_streams_uni,
        orig.initial_max_streams_uni
    );
    assert_eq!(decoded.max_ack_delay_ms, orig.max_ack_delay_ms);
    assert_eq!(decoded.ack_delay_exponent, orig.ack_delay_exponent);
    assert_eq!(
        decoded.active_connection_id_limit,
        orig.active_connection_id_limit
    );
}

#[test]
fn transport_params_cid_roundtrip() {
    let mut orig = TransportParams::default();
    orig.original_destination_connection_id =
        Some(ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]));
    orig.initial_source_connection_id =
        Some(ConnectionId::from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]));
    orig.retry_source_connection_id = Some(ConnectionId::from_slice(&[0x10, 0x20]));

    let mut buf = [0u8; 256];
    let written = orig.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");

    let orig_dcid = orig.original_destination_connection_id.unwrap();
    let decoded_dcid = decoded.original_destination_connection_id.unwrap();
    assert_eq!(orig_dcid.as_bytes(), decoded_dcid.as_bytes());

    let orig_scid = orig.initial_source_connection_id.unwrap();
    let decoded_scid = decoded.initial_source_connection_id.unwrap();
    assert_eq!(orig_scid.as_bytes(), decoded_scid.as_bytes());

    let orig_rcid = orig.retry_source_connection_id.unwrap();
    let decoded_rcid = decoded.retry_source_connection_id.unwrap();
    assert_eq!(orig_rcid.as_bytes(), decoded_rcid.as_bytes());
}

#[test]
fn transport_params_stateless_reset_token() {
    let mut orig = TransportParams::default();
    let token: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    orig.stateless_reset_token = Some(token);

    let mut buf = [0u8; 256];
    let written = orig.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");

    let decoded_token = decoded
        .stateless_reset_token
        .expect("token should be present");
    assert_eq!(decoded_token, token);
}

#[test]
fn transport_params_disable_migration() {
    let mut orig = TransportParams::default();
    orig.disable_active_migration = true;

    let mut buf = [0u8; 256];
    let written = orig.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..written]).expect("decode should succeed");

    assert!(decoded.disable_active_migration);

    // Also test false is not encoded (defaults stay false)
    let default_params = TransportParams::default();
    let mut buf2 = [0u8; 256];
    let written2 = default_params.encode(&mut buf2);
    let decoded2 = TransportParams::decode(&buf2[..written2]).expect("decode should succeed");
    assert!(!decoded2.disable_active_migration);
}

#[test]
fn transport_params_unknown_id_skipped() {
    // Craft bytes with a known param (max_idle_timeout = 5000, id=0x01)
    // then an unknown param id=0x20 with value 0x42,
    // then another known param (initial_max_data = 100, id=0x04)
    // varint encoding: small values are 1 byte with high bits 00
    let mut buf = Vec::new();

    // max_idle_timeout (0x01), length=varint_len(5000)=2, value=5000
    // 5000 as varint: 5000 > 63, 5000 > 16383? No. So 2 bytes: 0x40 | (5000>>8), 5000&0xff
    // 5000 = 0x1388, so (0x40 | 0x13)=0x53, 0x88
    buf.push(0x01); // id = 1 (1-byte varint)
    buf.push(0x02); // length = 2 (1-byte varint)
    buf.push(0x53); // varint 5000 high byte
    buf.push(0x88); // varint 5000 low byte

    // Unknown id = 0x20 (32 decimal), length=1, value=0x42
    buf.push(0x20); // id = 32 (1-byte varint)
    buf.push(0x01); // length = 1
    buf.push(0x42); // value

    // initial_max_data (0x04), length=1, value=50
    // 50 fits in a 1-byte QUIC varint (max 63, top 2 bits = 00)
    buf.push(0x04); // id = 4 (1-byte varint)
    buf.push(0x01); // length = 1
    buf.push(50); // value = 50 (fits in 1-byte varint, top bits 00)

    let decoded = TransportParams::decode(&buf).expect("unknown ID should be skipped");
    assert_eq!(decoded.max_idle_timeout_ms, 5000);
    assert_eq!(decoded.initial_max_data, 50);
}

#[test]
fn transport_params_empty() {
    let decoded = TransportParams::decode(&[]).expect("empty buffer should give defaults");
    // All fields should be at their RFC defaults
    assert_eq!(decoded.max_idle_timeout_ms, 0);
    assert_eq!(decoded.max_udp_payload_size, 65527);
    assert_eq!(decoded.active_connection_id_limit, 2);
    assert_eq!(decoded.max_ack_delay_ms, 25);
    assert_eq!(decoded.ack_delay_exponent, 3);
    assert!(!decoded.disable_active_migration);
}
