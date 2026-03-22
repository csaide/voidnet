use rustls::Side;
use rustls::quic::{DirectionalKeys, Keys, Version};

/// Derive Initial keys for a QUIC connection.
/// Returns (local_keys, remote_keys) as rustls DirectionalKeys.
/// These are deterministic — derived from the client's initial DCID.
/// Accepts a version parameter for v1/v2 key derivation.
pub fn derive_initial_keys(
    client_dcid: &[u8],
    side: Side,
    version: Version,
) -> (DirectionalKeys, DirectionalKeys) {
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;

    let keys = Keys::initial(version, suite, suite.quic.unwrap(), client_dcid, side);

    // local = our encryption key, remote = our decryption key
    (keys.local, keys.remote)
}
