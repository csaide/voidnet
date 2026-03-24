use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rustls_pemfile::certs;

use libvoid::{
    net::{
        socket::QuicConnection,
        wire::{ethernet::MacAddress, ip::SocketAddr},
    },
    rt::LocalRuntime,
};

mod common;
use common::BaseArgs;

/// A no-op TLS certificate verifier for development/testing with self-signed certs.
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
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

/// Parse a MAC address in the form "aa:bb:cc:dd:ee:ff".
fn parse_mac(s: &str) -> Result<MacAddress, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("expected 6 colon-separated hex bytes, got: {}", s));
    }
    let mut octets = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = u8::from_str_radix(part, 16)
            .map_err(|e| format!("invalid hex byte '{}': {}", part, e))?;
    }
    Ok(MacAddress::new(octets))
}

#[derive(Parser)]
#[command(author, version, about = "QUIC echo client")]
struct Args {
    #[command(flatten)]
    base: BaseArgs,

    /// Local address and port to bind (e.g. [fc00:dead:cafe:1::2]:4434)
    #[arg(long, default_value = "[fc00:dead:cafe:1::2]:4434")]
    local_addr: SocketAddr,

    /// Remote server address and port (e.g. [fc00:dead:cafe:1::1]:4433)
    #[arg(long, default_value = "[fc00:dead:cafe:1::1]:4433")]
    remote_addr: SocketAddr,

    /// TLS server name for SNI and certificate verification
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Size of the message payload to send (bytes)
    #[arg(long, default_value = "64")]
    message_size: usize,

    /// Path to a CA certificate PEM file. If omitted, certificate verification is skipped (dev mode).
    #[arg(long)]
    ca_cert: Option<String>,

    /// MAC address of the local interface (e.g. aa:bb:cc:dd:ee:ff)
    #[arg(long, value_parser = parse_mac)]
    local_mac: MacAddress,

    /// MAC address of the remote gateway/next-hop (e.g. aa:bb:cc:dd:ee:ff)
    #[arg(long, value_parser = parse_mac)]
    remote_mac: MacAddress,
}

impl Deref for Args {
    type Target = BaseArgs;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

fn make_insecure_client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"hq-interop".to_vec(), b"h3".to_vec()];
    Arc::new(config)
}

fn load_client_config_with_ca(ca_cert_path: &str) -> Arc<ClientConfig> {
    let ca_pem = std::fs::read(ca_cert_path)
        .unwrap_or_else(|e| panic!("Failed to read CA certificate '{}': {}", ca_cert_path, e));

    let ca_certs: Vec<CertificateDer<'static>> = certs(&mut &ca_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse CA certificate PEM");
    assert!(
        !ca_certs.is_empty(),
        "No CA certificates found in {}",
        ca_cert_path
    );

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .expect("Failed to add CA certificate to root store");
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"hq-interop".to_vec(), b"h3".to_vec()];
    Arc::new(config)
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    let tls_config = match &args.ca_cert {
        Some(ca_path) => {
            println!("Loading CA certificate from {}", ca_path);
            load_client_config_with_ca(ca_path)
        }
        None => {
            println!("No --ca-cert provided, skipping certificate verification (dev mode)");
            make_insecure_client_config()
        }
    };

    let mut runtime = LocalRuntime::builder(&args.if_name, args.queue)
        .arp_ttl(Duration::from_secs(1200))
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .copy_mode(args.copy_mode)
        .build()
        .expect("Failed to create runtime");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let local_addr = args.local_addr;
    let remote_addr = args.remote_addr;
    let server_name = args.server_name.clone();
    let local_mac = args.local_mac;
    let remote_mac = args.remote_mac;
    let message_size = args.message_size;

    runtime
        .run(exit, async move {
            println!(
                "Connecting from {} to {} (server_name={})...",
                local_addr, remote_addr, server_name
            );

            let conn = QuicConnection::connect(
                local_addr.ip,
                local_addr.port,
                local_mac,
                remote_addr.ip,
                remote_addr.port,
                remote_mac,
                &server_name,
                tls_config,
            )
            .expect("Failed to initiate QUIC connection")
            .await
            .expect("QUIC handshake failed");

            println!(
                "Connected to {:?}:{}",
                conn.remote_addr(),
                conn.remote_port().unwrap_or(0)
            );

            let stream = conn
                .open_bidi_stream()
                .expect("Failed to open bidirectional stream");

            println!("Opened stream {}", stream.id().0);

            let payload = vec![0xABu8; message_size];
            let mut read_buf = vec![0u8; message_size];

            // Send the message
            match stream.write(&payload).await {
                Ok(n) => println!("Sent {} bytes", n),
                Err(e) => {
                    println!("Write error: {:?}", e);
                    return;
                }
            }

            // Read the echo response (may arrive in multiple reads)
            let mut total_read = 0;
            while total_read < message_size {
                let n = match stream.read(&mut read_buf[total_read..]).await {
                    Ok(0) => {
                        println!("Server closed stream before full echo was received");
                        return;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        println!("Read error: {:?}", e);
                        return;
                    }
                };
                total_read += n;
            }

            println!("Received {} bytes echo", total_read);

            // Verify the response matches what was sent
            if read_buf == payload {
                println!("Echo verified: response matches sent payload.");
            } else {
                println!("Echo MISMATCH: response does not match sent payload!");
            }

            // Graceful stream shutdown
            stream.finish();
            println!("Stream finished.");
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
