use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
use crate::net::handler::quic::crypto::keys::DirectionalKey;
use crate::net::handler::quic::crypto::packet_protection::{
    decrypt_payload, protect_packet, unprotect_header,
};

#[test]
fn derive_initial_keys_succeeds() {
    // RFC 9001 Appendix A test DCID
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_keys, server_keys) = derive_initial_keys(&dcid, rustls::Side::Client);
    // If we got here without panic, keys were derived successfully.
    // The PacketKey and HeaderProtectionKey trait objects are valid.

    // Verify we can call tag_len() on the packet keys (proves they're real)
    assert!(client_keys.packet.tag_len() > 0);
    assert!(server_keys.packet.tag_len() > 0);
}

#[test]
fn derive_initial_keys_empty_dcid() {
    let (client_keys, _server_keys) = derive_initial_keys(&[], rustls::Side::Client);
    assert!(client_keys.packet.tag_len() > 0);
}

#[test]
fn derive_initial_keys_encrypt_decrypt_roundtrip() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_keys, _server_keys) = derive_initial_keys(&dcid, rustls::Side::Client);

    // Client encrypts, server decrypts
    let packet_number = 0u64;
    let header = [0xc0, 0x00, 0x00, 0x01]; // fake header bytes
    let mut payload = b"hello quic".to_vec();

    // Encrypt with client key
    let tag = client_keys
        .packet
        .encrypt_in_place(packet_number, &header, &mut payload)
        .unwrap();
    payload.extend_from_slice(tag.as_ref());

    // Decrypt with server key (server's "remote" = client's direction)
    // We need server-side keys for this
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let server_keys_obj = rustls::quic::Keys::initial(
        rustls::quic::Version::V1,
        suite,
        suite.quic.unwrap(),
        &dcid,
        rustls::Side::Server,
    );
    // server_keys_obj.remote = client direction (what we encrypted with)
    let decrypted = server_keys_obj
        .remote
        .packet
        .decrypt_in_place(packet_number, &header, &mut payload)
        .unwrap();
    assert_eq!(decrypted, b"hello quic");
}

#[test]
fn key_pair_from_initial_keys() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client, server) = derive_initial_keys(&dcid, rustls::Side::Client);
    let client_key = DirectionalKey::from_rustls(client);
    let server_key = DirectionalKey::from_rustls(server);
    assert!(client_key.packet_key.tag_len() > 0);
    assert!(server_key.packet_key.tag_len() > 0);
}

#[test]
fn protect_unprotect_roundtrip() {
    // Derive keys: client encrypts, server decrypts.
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_dk, _server_dk) = derive_initial_keys(&dcid, rustls::Side::Client);
    let client_key = DirectionalKey::from_rustls(client_dk);

    // Get matching server decrypt key (server.remote = client direction).
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let server_keys_obj = rustls::quic::Keys::initial(
        rustls::quic::Version::V1,
        suite,
        suite.quic.unwrap(),
        &dcid,
        rustls::Side::Server,
    );
    let server_key = DirectionalKey::from_rustls(server_keys_obj.remote);

    // Build a minimal QUIC Initial packet (long header):
    // first_byte(1) | version(4) | dcid_len(1) | dcid(8) | scid_len(1) | token_len_varint(1) | length_varint(2) | pn(1) | payload
    let plaintext = b"hello quic packet";
    let tag_len = client_key.packet_key.tag_len();

    // pn_offset: after first_byte(1) + version(4) + dcid_len(1) + dcid(8) + scid_len(1) + token_len(1) + length(2) = 18
    let pn_offset: usize = 18;
    let pn_length: usize = 1;
    let packet_number: u64 = 0;

    // Total packet length: header(pn_offset) + pn(pn_length) + payload + tag
    let total_len = pn_offset + pn_length + plaintext.len() + tag_len;
    let mut packet = vec![0u8; total_len];

    // Set first byte: long header (0x80 set), Initial packet type = 0xC0
    packet[0] = 0xC0;
    // version = QUIC v1: 0x00000001
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = 0x00;
    packet[4] = 0x01;
    // dcid_len = 8
    packet[5] = 0x08;
    // dcid bytes (positions 6..14)
    packet[6..14].copy_from_slice(&dcid);
    // scid_len = 0
    packet[14] = 0x00;
    // token_len varint = 0
    packet[15] = 0x00;
    // length varint (2-byte: 0x40 | high, low) = pn_length + plaintext.len() + tag_len
    let payload_and_tag_len = pn_length + plaintext.len() + tag_len;
    // Use 2-byte varint encoding: set high bit of first byte
    packet[16] = 0x40 | ((payload_and_tag_len >> 8) as u8);
    packet[17] = (payload_and_tag_len & 0xFF) as u8;
    // pn (1 byte) at offset 18
    packet[pn_offset] = 0x00;
    // payload at pn_offset + pn_length
    packet[pn_offset + pn_length..pn_offset + pn_length + plaintext.len()]
        .copy_from_slice(plaintext);
    // tag area is zeroed (will be filled by encrypt)

    // Protect (encrypt + header protection)
    let protected_len = protect_packet(
        &client_key,
        &mut packet,
        pn_offset,
        pn_length,
        packet_number,
    )
    .unwrap();
    assert_eq!(protected_len, total_len);

    // Unprotect header: remove header protection and decode PN
    let (decoded_pn, decoded_pn_len, payload_offset) =
        unprotect_header(&server_key, &mut packet, pn_offset).unwrap();
    assert_eq!(decoded_pn, packet_number);
    assert_eq!(decoded_pn_len, pn_length);
    assert_eq!(payload_offset, pn_offset + pn_length);

    // Decrypt payload
    let header = packet[..payload_offset].to_vec();
    let plaintext_len = decrypt_payload(
        &server_key,
        decoded_pn,
        &header,
        &mut packet[payload_offset..],
    )
    .unwrap();
    assert_eq!(
        &packet[payload_offset..payload_offset + plaintext_len],
        plaintext
    );
}
