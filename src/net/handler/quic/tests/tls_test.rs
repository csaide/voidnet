use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};

use crate::net::handler::quic::crypto::tls::CryptoState;
use crate::net::handler::quic::transport::params::TransportParams;

/// A cert verifier that accepts everything (test only).
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn make_test_cert() -> (
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (
        vec![cert_der],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )
}

fn make_client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn make_server_config() -> Arc<ServerConfig> {
    let (certs, key) = make_test_cert();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = 0;
    Arc::new(config)
}

fn encode_test_transport_params() -> Vec<u8> {
    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };
    let mut buf = [0u8; 256];
    let len = params.encode(&mut buf);
    buf[..len].to_vec()
}

#[test]
fn crypto_state_new_client_produces_initial_data() {
    let client_config = make_client_config();
    let params = encode_test_transport_params();

    let (_state, initial_data) = CryptoState::new_client(
        client_config,
        "localhost",
        &params,
        rustls::quic::Version::V1,
    )
    .unwrap();

    // Client should produce a ClientHello
    assert!(
        !initial_data.is_empty(),
        "client should produce initial CRYPTO data (ClientHello)"
    );
}

#[test]
fn crypto_state_new_server_succeeds() {
    let server_config = make_server_config();
    let params = encode_test_transport_params();

    let _state =
        CryptoState::new_server(server_config, &params, rustls::quic::Version::V1).unwrap();
    // Just verify construction succeeds
}

#[test]
fn client_server_handshake() {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let client_params = encode_test_transport_params();
    let server_params = encode_test_transport_params();

    // Step 1: Create client, get initial ClientHello
    let (mut client, client_hello) = CryptoState::new_client(
        client_config,
        "localhost",
        &client_params,
        rustls::quic::Version::V1,
    )
    .unwrap();
    assert!(!client_hello.is_empty());

    // Step 2: Create server, feed ClientHello
    let mut server =
        CryptoState::new_server(server_config, &server_params, rustls::quic::Version::V1).unwrap();
    let server_output = server.process_crypto_data(&client_hello).unwrap();

    // Server should produce response crypto data (ServerHello + encrypted extensions + etc.)
    assert!(
        !server_output.crypto_data.is_empty(),
        "server should produce response CRYPTO data"
    );
    // Server should have handshake keys after processing ClientHello
    assert!(
        server_output.handshake_keys.is_some(),
        "server should derive handshake keys"
    );

    // Step 3: Feed server response to client
    let client_output = client
        .process_crypto_data(&server_output.crypto_data)
        .unwrap();

    // Client should get handshake keys
    assert!(
        client_output.handshake_keys.is_some(),
        "client should derive handshake keys"
    );

    // Client may also have response data (Finished message)
    // and may have 1-RTT keys at this point
    if !client_output.handshake_complete {
        // If not complete yet, there should be more data to exchange
        assert!(
            !client_output.crypto_data.is_empty(),
            "client should produce more CRYPTO data if not complete"
        );

        // Step 4: Feed client's response to server
        let server_output2 = server
            .process_crypto_data(&client_output.crypto_data)
            .unwrap();

        // After this round, at least one side should have 1-RTT keys
        // The server might already be complete or need one more round
        if !server_output2.crypto_data.is_empty() {
            let client_output2 = client
                .process_crypto_data(&server_output2.crypto_data)
                .unwrap();
            assert!(
                client_output2.handshake_complete || client_output.handshake_complete,
                "handshake should complete within a few rounds"
            );
        }
    }

    // Verify transport parameters are accessible from at least one side
    // (they become available after the handshake progresses sufficiently)
    let server_peer_params = server.peer_transport_parameters();
    let client_peer_params = client.peer_transport_parameters();
    // At least one side should have peer params by now
    assert!(
        server_peer_params.is_some() || client_peer_params.is_some(),
        "peer transport parameters should be available after handshake"
    );
}

#[test]
fn handshake_produces_one_rtt_keys() {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let client_params = encode_test_transport_params();
    let server_params = encode_test_transport_params();

    let (mut client, client_hello) = CryptoState::new_client(
        client_config,
        "localhost",
        &client_params,
        rustls::quic::Version::V1,
    )
    .unwrap();
    let mut server =
        CryptoState::new_server(server_config, &server_params, rustls::quic::Version::V1).unwrap();

    // Drive the handshake to completion by exchanging data in a loop
    let mut got_client_1rtt = false;
    let mut got_server_1rtt = false;

    // Round 1: ClientHello -> Server
    let server_out = server.process_crypto_data(&client_hello).unwrap();
    if server_out.one_rtt_keys.is_some() {
        got_server_1rtt = true;
    }

    // Exchange up to 5 rounds (TLS 1.3 should complete in 1-2)
    let mut data_for_client = server_out.crypto_data;
    for _ in 0..5 {
        if data_for_client.is_empty() && got_client_1rtt && got_server_1rtt {
            break;
        }

        if !data_for_client.is_empty() {
            let client_out = client.process_crypto_data(&data_for_client).unwrap();
            if client_out.one_rtt_keys.is_some() {
                got_client_1rtt = true;
            }
            if client_out.handshake_complete {
                got_client_1rtt = true;
            }

            if !client_out.crypto_data.is_empty() {
                let srv_out = server.process_crypto_data(&client_out.crypto_data).unwrap();
                if srv_out.one_rtt_keys.is_some() {
                    got_server_1rtt = true;
                }
                if srv_out.handshake_complete {
                    got_server_1rtt = true;
                }
                data_for_client = srv_out.crypto_data;
            } else {
                data_for_client = vec![];
            }
        } else {
            break;
        }
    }

    assert!(got_client_1rtt, "client must obtain 1-RTT keys");
    assert!(got_server_1rtt, "server must obtain 1-RTT keys");
}
