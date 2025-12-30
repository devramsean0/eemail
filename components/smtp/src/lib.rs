use core::panic;

use log::{debug, error, info};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, private_key};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio::{fs, net::TcpListener, task};
use tokio_rustls::TlsAcceptor;

use eemail_lib_shared::SMTPPortConfiguration;

pub async fn start_smtp(config: eemail_component_configurator::Configuration) {
    let transfer = task::spawn(listen(
        SMTPPortConfiguration {
            auth_enabled: false,
            filtering_enabled: true,
            implicit_tls: false,
            port: 2525,
        },
        config.clone(),
    ));

    let submission = task::spawn(listen(
        SMTPPortConfiguration {
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
    config: SMTPPortConfiguration,
    service_config: eemail_component_configurator::Configuration,
) -> anyhow::Result<()> {
    // Do a sanity check on startup that the email path is set
    let email_path = match std::env::var("EMAIL_PATH") {
        Ok(path) => path,
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
                match eemail_lib_protocols_smtp_server::handle_smtp(
                    socket,
                    config,
                    tls_acceptor.clone(),
                    service_config.clone(),
                )
                .await
                {
                    Ok(mail) => {
                        let from_account = service_config
                            .accounts
                            .iter()
                            .find(|&x| x.clone().get_all_addresses().contains(&mail.from));

                        let local_recipients: Vec<String> = mail
                            .to
                            .iter()
                            .filter(|recipient| {
                                service_config.accounts.iter().any(|account| {
                                    account.clone().get_all_addresses().contains(recipient)
                                })
                            })
                            .cloned()
                            .collect();

                        debug!("Local Recipients {:#?}", local_recipients);

                        if from_account.is_some() && config.auth_enabled {
                            // If from_account exists & auth is enabled, we can assume it is from an account on this server
                            let base = format!(
                                "{}/{}/Sent",
                                email_path,
                                from_account.unwrap().clone().get_primary_address(),
                            );
                            fs::create_dir_all(base.clone()).await?;
                            fs::write(format!("{}/{}.eml", base, mail.id), mail.data.clone())
                                .await?;
                        }

                        for recipient in local_recipients {
                            let recipient = service_config
                                .clone()
                                .get_user_from_alias(&recipient)
                                .unwrap()
                                .get_primary_address();
                            let base = format!("{}/{}/Inbox", email_path, recipient);
                            fs::create_dir_all(base.clone()).await?;
                            fs::write(format!("{}/{}.eml", base, mail.id), mail.data.clone())
                                .await?;
                        }
                    }
                    Err(e) => {
                        error!("Error processing connection from {}", e);
                    }
                }
                info!("Quit Connection from {}", addr);
            }
            Err(e) => {
                error!("Failed to accept connection on port {}: {}", config.port, e);
            }
        }
    }
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
