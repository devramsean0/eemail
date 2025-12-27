use core::panic;

use log::{debug, error, info};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio::{net::TcpListener, task};
use tokio_rustls::TlsAcceptor;

use crate::message_handler::handle_smtp;
use rustls_pemfile::{certs, private_key};

mod message_handler;

pub async fn start_smtp(config: eemail_component_configurator::Configuration) {
    let transfer = task::spawn(listen(
        PortConfiguration {
            auth_enabled: false,
            filtering_enabled: true,
            implicit_tls: false,
            port: 2525,
        },
        config.clone(),
    ));

    let submission = task::spawn(listen(
        PortConfiguration {
            auth_enabled: true,
            filtering_enabled: false,
            implicit_tls: false,
            port: 5870,
        },
        config.clone(),
    ));

    tokio::select! {
        transfer_result = transfer => {
            match transfer_result {
                Ok(Ok(_)) => info!("Transfer listener finished normally"),
                Ok(Err(e)) => error!("Transfer listener failed: {}", e),
                Err(e) => error!("Transfer task panicked: {}", e),
            }
        }
        submission_result = submission => {
            match submission_result {
                Ok(Ok(_)) => info!("Submission listener finished normally"),
                Ok(Err(e)) => error!("Submission listener failed: {}", e),
                Err(e) => error!("Submission task panicked: {}", e),
            }
        }
    }
}

// Fn that will bind to the ports and do the initial worker handoff
async fn listen(
    config: PortConfiguration,
    service_config: eemail_component_configurator::Configuration,
) -> anyhow::Result<()> {
    // Do a sanity check on startup that the email path is set
    match std::env::var("EMAIL_PATH") {
        Ok(_) => {}
        Err(_) => {
            error!("EMAIL_PATH environment variable not set, maybe check the docs?");
            return Ok(());
        }
    };

    let cert_path: String = std::env::var("CERT_PATH").unwrap();
    let key_path: String = std::env::var("KEY_PATH").unwrap();

    let tls_cfg = load_rustls_config(cert_path.as_str(), key_path.as_str()).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    debug!("Registering Listener for {}", config.port);
    let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;
    info!(
        "SMTP: Listening on port {} (Auth Enabled? {}, Filtering Enabled? {}, TLS By Default? {})",
        config.port, config.auth_enabled, config.filtering_enabled, config.implicit_tls
    );

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                info!("New connection from {} on port {}", addr, config.port);
                // Spawn handler thread
                if let Err(e) =
                    handle_smtp(socket, config, tls_acceptor.clone(), service_config.clone()).await
                {
                    error!("Error processing connection from {}", e);
                }
                info!("Quit Connection from {}", addr);
            }
            Err(e) => {
                error!("Failed to accept connection on port {}: {}", config.port, e);
            }
        }
    }
}

// We need to support smtp on several ports with different configurations (25, 587)
#[derive(Clone, Copy)]
struct PortConfiguration {
    auth_enabled: bool,
    filtering_enabled: bool,
    implicit_tls: bool,
    port: u16,
}
async fn load_rustls_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    let certfile = File::open(cert_path)?;
    let mut reader = BufReader::new(certfile);

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut reader)
        .map(|c| c.map(|der| der.into_owned()))
        .collect::<Result<_, _>>()?;

    if cert_chain.is_empty() {
        error!("No Certificate's loaded");
        panic!();
    }

    let key_file = File::open(key_path)?;
    let mut reader = BufReader::new(key_file);

    let key: PrivateKeyDer<'static> =
        private_key(&mut reader)?.ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    cfg.alpn_protocols.clear();
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(512);

    Ok(cfg)
}
