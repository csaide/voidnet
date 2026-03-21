use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;

#[test]
fn derive_initial_keys_succeeds() {
    // RFC 9001 Appendix A test DCID
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_keys, server_keys) = derive_initial_keys(&dcid);
    // If we got here without panic, keys were derived successfully.
    // The PacketKey and HeaderProtectionKey trait objects are valid.

    // Verify we can call tag_len() on the packet keys (proves they're real)
    assert!(client_keys.packet.tag_len() > 0);
    assert!(server_keys.packet.tag_len() > 0);
}

#[test]
fn derive_initial_keys_empty_dcid() {
    let (client_keys, _server_keys) = derive_initial_keys(&[]);
    assert!(client_keys.packet.tag_len() > 0);
}

#[test]
fn derive_initial_keys_encrypt_decrypt_roundtrip() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_keys, _server_keys) = derive_initial_keys(&dcid);

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
