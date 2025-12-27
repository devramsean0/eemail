use log::{error, info};

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    dotenv::dotenv().ok();

    info!("Starting Server");
    let config =
        match eemail_component_configurator::Configuration::parse_from_file("./config.toml") {
            Ok(config) => {
                info!("Loaded config file");
                config
            }
            Err(_) => {
                error!("Config file not loaded, continuing with defaults");
                return;
            }
        };

    let smtp_handle = tokio::task::spawn(async move {
        if config.enable_smtp.unwrap() {
            info!("SMTP Enabled");

            eemail_component_smtp::start_smtp(config).await;
        }
    });
    match smtp_handle.await {
        Ok(_) => info!("SMTP component stopped"),
        Err(e) => error!("SMTP component failed: {}", e),
    }
}
