use eemail_lib_shared::SMTPPortConfiguration;
use log::debug;
use tokio::io::{AsyncWriteExt, BufReader};

use crate::{Mail, SmtpStream};

pub async fn handle(
    mail: &Mail,
    config: &SMTPPortConfiguration,
    buffer: &mut BufReader<SmtpStream>,
) -> anyhow::Result<()> {
    let mut extension_strs: Vec<String> = vec![
        "250-Localhost".to_string(),
        "250-PIPELINING".to_string(),
        format!("250-Size {}", 10 * 1024 * 1024),
    ];

    // Only offer STARTTLS if TLS hasn't been established yet
    if !mail.has_tlsd {
        extension_strs.push("250-STARTTLS".to_string());
    }

    // Only offer AUTH if enabled, TLS is active
    if config.auth_enabled && mail.has_tlsd {
        extension_strs.push("250-AUTH PLAIN".to_string());
    }

    // The last one in the array needs to be "250 " not "250-"
    if let Some(last) = extension_strs.last_mut() {
        *last = last.replacen("250-", "250 ", 1);
    }

    debug!("Sending EHLO Response {:#?}", extension_strs);
    let mut joined_extensions = extension_strs.join("\r\n");
    joined_extensions.push_str("\r\n");
    buffer
        .get_mut()
        .write_all(joined_extensions.as_bytes())
        .await?;

    Ok(())
}
