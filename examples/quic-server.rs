use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use libvoid::rt::LocalRuntime;
use libvoid::{
    net::{
        socket::{QuicListener, QuicStream},
        wire::ip::SocketAddr,
    },
    rt::spawn,
};

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about = "QUIC echo server")]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:4433")]
    local_addr: SocketAddr,
    #[arg(
        long,
        help = "Path to PEM certificate file (generates self-signed if omitted)"
    )]
    cert: Option<String>,
    #[arg(
        long,
        help = "Path to PEM private key file (generates self-signed if omitted)"
    )]
    key: Option<String>,
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

fn make_self_signed_config() -> Arc<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate self-signed certificate");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("Failed to build TLS config");
    config.alpn_protocols = vec![b"hq-interop".to_vec(), b"h3".to_vec()];
    config.max_early_data_size = u32::MAX;
    Arc::new(config)
}

fn load_config_from_files(cert_path: &str, key_path: &str) -> Arc<ServerConfig> {
    let cert_pem = std::fs::read(cert_path)
        .unwrap_or_else(|e| panic!("Failed to read certificate file '{}': {}", cert_path, e));
    let key_pem = std::fs::read(key_path)
        .unwrap_or_else(|e| panic!("Failed to read key file '{}': {}", key_path, e));

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse certificate PEM");
    assert!(!certs.is_empty(), "No certificates found in {}", cert_path);

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("Failed to parse key PEM")
        .unwrap_or_else(|| panic!("No private key found in {}", key_path));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build TLS config");
    config.alpn_protocols = vec![b"hq-interop".to_vec(), b"h3".to_vec()];
    config.max_early_data_size = u32::MAX;
    Arc::new(config)
}

async fn handle_stream(stream: QuicStream) {
    let mut stats = Stats::new_with_id_and_packets_per_print(stream.id().0 as usize, 1_000_000);
    let mut buf = [0u8; 65535];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break, // FIN
            Ok(n) => match stream.write(&buf[..n]).await {
                Ok(_) => {
                    stats.update(n, false);
                    stats.maybe_print();
                }
                Err(e) => {
                    println!("Stream {} write error: {:?}", stream.id().0, e);
                    break;
                }
            },
            Err(e) => {
                println!("Stream {} read error: {:?}", stream.id().0, e);
                break;
            }
        }
    }

    stream.finish();
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    let tls_config = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => {
            println!("Loading certificate from {} and key from {}", cert, key);
            load_config_from_files(cert, key)
        }
        (None, None) => {
            println!("No --cert/--key provided, using self-signed certificate");
            make_self_signed_config()
        }
        _ => {
            eprintln!("Error: --cert and --key must both be specified or both omitted");
            std::process::exit(1);
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

    runtime
        .run(exit, async move {
            let params = libvoid::net::handler::quic::TransportParams {
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_stream_data_uni: 1_000_000,
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 100,
                max_idle_timeout_ms: 30_000,
                ..Default::default()
            };
            let listener = QuicListener::listen_with_config(
                args.local_addr.ip,
                args.local_addr.port,
                tls_config,
                params,
            )
            .expect("Failed to listen");
            println!("QUIC echo server listening on {}", args.local_addr);

            loop {
                let conn = listener.accept().await;
                println!(
                    "Accepted QUIC connection from {:?}:{:?}",
                    conn.remote_addr(),
                    conn.remote_port()
                );

                spawn(async move {
                    loop {
                        match conn.accept_stream().await {
                            Ok(s) => {
                                println!("New stream {}", s.id().0);
                                spawn(handle_stream(s));
                            }
                            Err(e) => {
                                println!("Connection closed: {:?}", e);
                                break;
                            }
                        }
                    }
                });
            }
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
