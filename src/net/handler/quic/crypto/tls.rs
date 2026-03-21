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
    /// CRYPTO data to send to peer (may be empty).
    pub crypto_data: Vec<u8>,
    /// New handshake-level keys, if the handshake progressed to that point.
    pub handshake_keys: Option<KeyPair>,
    /// New 1-RTT application keys, if the handshake completed.
    pub one_rtt_keys: Option<KeyPair>,
    /// Whether the handshake is complete (1-RTT keys available).
    pub handshake_complete: bool,
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
    ) -> Result<(Self, Vec<u8>), TransportError> {
        let sni: ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| TransportError::INTERNAL_ERROR)?;
        let conn = quic::ClientConnection::new(config, Version::V1, sni, transport_params.to_vec())
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
    ) -> Result<Self, TransportError> {
        let conn = quic::ServerConnection::new(config, Version::V1, transport_params.to_vec())
            .map_err(|_| TransportError::INTERNAL_ERROR)?;

        Ok(CryptoState::Server(conn))
    }

    /// Feed received CRYPTO frame data from peer.
    ///
    /// Returns crypto data to send back and any new keys derived during this
    /// step of the handshake.
    pub fn process_crypto_data(&mut self, data: &[u8]) -> Result<CryptoOutput, TransportError> {
        // Feed data to rustls
        self.read_hs(data)?;

        // Get response crypto data and any key changes.
        // rustls may produce multiple key changes in a single step (e.g.
        // server emits Handshake keys then 1-RTT keys), so we loop until
        // write_hs returns None.
        let mut crypto_data = Vec::new();
        let mut output = CryptoOutput {
            crypto_data: Vec::new(),
            handshake_keys: None,
            one_rtt_keys: None,
            handshake_complete: false,
        };

        loop {
            let key_change = self.write_hs(&mut crypto_data);
            match key_change {
                Some(KeyChange::Handshake { keys }) => {
                    output.handshake_keys = Some(KeyPair {
                        local: DirectionalKey::from_rustls(keys.local),
                        remote: DirectionalKey::from_rustls(keys.remote),
                    });
                }
                Some(KeyChange::OneRtt { keys, next: _ }) => {
                    output.one_rtt_keys = Some(KeyPair {
                        local: DirectionalKey::from_rustls(keys.local),
                        remote: DirectionalKey::from_rustls(keys.remote),
                    });
                    output.handshake_complete = true;
                    // TODO: store `next` Secrets for key updates (Task 25)
                }
                None => break,
            }
        }

        output.crypto_data = crypto_data;
        Ok(output)
    }

    /// Get peer's transport parameters (available after the handshake progresses).
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        match self {
            CryptoState::Client(c) => c.quic_transport_parameters(),
            CryptoState::Server(c) => c.quic_transport_parameters(),
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
        result.map_err(|_e| {
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
