use core::panic;

use log::{debug, error, info};
use tokio::{net::TcpListener, task};

use crate::message_handler::handle_smtp;

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
                if let Err(e) = handle_smtp(socket, config, service_config.clone()).await {
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
