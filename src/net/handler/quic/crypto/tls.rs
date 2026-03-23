//! Rustls TLS 1.3 integration for QUIC.
//!
//! Wraps `rustls::quic::{ClientConnection, ServerConnection}` behind a unified
//! `CryptoState` enum so the rest of the QUIC stack only interacts with a
//! single type for driving the handshake forward.

use rustls::pki_types::ServerName;
use rustls::quic::{self, KeyChange, Version};
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

use super::keys::{DirectionalKey, KeyPair};
use crate::net::handler::quic::error::TransportError;

/// Output from processing CRYPTO frame data.
pub struct CryptoOutput {
    /// Per-space CRYPTO data to send: [Initial, Handshake, 1-RTT].
    /// Data is split at key change boundaries so each space gets the
    /// correct portion of the TLS handshake.
    pub crypto_data: [Vec<u8>; 3],
    /// New handshake-level keys, if the handshake progressed to that point.
    pub handshake_keys: Option<KeyPair>,
    /// New 1-RTT application keys, if the handshake completed.
    pub one_rtt_keys: Option<KeyPair>,
    /// Whether the handshake is complete (1-RTT keys available).
    pub handshake_complete: bool,
    /// Next key update secrets (for key rotation support).
    pub next_secrets: Option<rustls::quic::Secrets>,
}

/// Wraps a rustls QUIC connection for TLS 1.3 handshake management.
pub enum CryptoState {
    Client(quic::ClientConnection),
    Server(quic::ServerConnection),
}

impl CryptoState {
    /// Create client-side crypto state.
    ///
    /// Returns the state and the initial CRYPTO data (ClientHello) to send.
    pub fn new_client(
        config: Arc<ClientConfig>,
        server_name: &str,
        transport_params: &[u8],
        version: Version,
    ) -> Result<(Self, Vec<u8>), TransportError> {
        let sni: ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| TransportError::INTERNAL_ERROR)?;
        let conn = quic::ClientConnection::new(config, version, sni, transport_params.to_vec())
            .map_err(|_| TransportError::INTERNAL_ERROR)?;

        let mut state = CryptoState::Client(conn);
        // Get initial ClientHello CRYPTO data
        let mut initial_data = Vec::new();
        state.write_hs(&mut initial_data);

        Ok((state, initial_data))
    }

    /// Create server-side crypto state.
    pub fn new_server(
        config: Arc<ServerConfig>,
        transport_params: &[u8],
        version: Version,
    ) -> Result<Self, TransportError> {
        let conn = quic::ServerConnection::new(config, version, transport_params.to_vec())
            .map_err(|_| TransportError::INTERNAL_ERROR)?;

        Ok(CryptoState::Server(conn))
    }

    /// Feed received CRYPTO frame data from peer.
    ///
    /// Returns crypto data to send back and any new keys derived during this
    /// step of the handshake.
    /// Process received CRYPTO data from the peer.
    ///
    /// `current_space` is the encryption level at which output data should
    /// start. Key changes advance the level (0→1→2). For the initial
    /// ClientHello processing, pass 0. For later calls where higher keys
    /// already exist, pass the appropriate level (e.g. 2 if 1-RTT keys
    /// are installed).
    pub fn process_crypto_data(
        &mut self,
        data: &[u8],
        current_space: usize,
    ) -> Result<CryptoOutput, TransportError> {
        self.read_hs(data)?;

        let mut buf = Vec::new();
        let mut current_space = current_space;
        let mut output = CryptoOutput {
            crypto_data: [Vec::new(), Vec::new(), Vec::new()],
            handshake_keys: None,
            one_rtt_keys: None,
            handshake_complete: false,
            next_secrets: None,
        };

        loop {
            let before = buf.len();
            let key_change = self.write_hs(&mut buf);
            // Data written in this call belongs to current_space
            if buf.len() > before {
                output.crypto_data[current_space].extend_from_slice(&buf[before..]);
            }
            match key_change {
                Some(KeyChange::Handshake { keys }) => {
                    output.handshake_keys = Some(KeyPair {
                        local: DirectionalKey::from_rustls(keys.local),
                        remote: DirectionalKey::from_rustls(keys.remote),
                    });
                    current_space = 1; // subsequent data goes to Handshake
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    output.one_rtt_keys = Some(KeyPair {
                        local: DirectionalKey::from_rustls(keys.local),
                        remote: DirectionalKey::from_rustls(keys.remote),
                    });
                    output.handshake_complete = true;
                    output.next_secrets = Some(next);
                    current_space = 2; // subsequent data goes to 1-RTT
                }
                None => break,
            }
        }

        Ok(output)
    }

    /// Get 0-RTT keys if available (client presented a valid session ticket).
    /// Returns a single DirectionalKeys — 0-RTT is unidirectional (client-to-server).
    pub fn zero_rtt_keys(&self) -> Option<rustls::quic::DirectionalKeys> {
        match self {
            CryptoState::Client(c) => c.zero_rtt_keys(),
            CryptoState::Server(c) => c.zero_rtt_keys(),
        }
    }

    /// Get peer's transport parameters (available after the handshake progresses).
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        match self {
            CryptoState::Client(c) => c.quic_transport_parameters(),
            CryptoState::Server(c) => c.quic_transport_parameters(),
        }
    }

    /// Return the negotiated cipher suite, if available.
    pub fn negotiated_cipher_suite(&self) -> Option<rustls::CipherSuite> {
        match self {
            CryptoState::Client(c) => c.negotiated_cipher_suite().map(|s| s.suite()),
            CryptoState::Server(c) => c.negotiated_cipher_suite().map(|s| s.suite()),
        }
    }

    /// Get TLS alert code if any error occurred.
    pub fn alert(&self) -> Option<u8> {
        let alert = match self {
            CryptoState::Client(c) => c.alert(),
            CryptoState::Server(c) => c.alert(),
        };
        alert.map(|a| u8::from(a))
    }

    // ── private helpers ──────────────────────────────────────────────

    fn read_hs(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let result = match self {
            CryptoState::Client(c) => c.read_hs(data),
            CryptoState::Server(c) => c.read_hs(data),
        };
        result.map_err(|_| {
            // If rustls reports an alert, map it to the QUIC crypto error range.
            let alert = self.alert();
            if let Some(code) = alert {
                TransportError::from_tls_alert(code)
            } else {
                TransportError::INTERNAL_ERROR
            }
        })
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        match self {
            CryptoState::Client(c) => c.write_hs(buf),
            CryptoState::Server(c) => c.write_hs(buf),
        }
    }
}
