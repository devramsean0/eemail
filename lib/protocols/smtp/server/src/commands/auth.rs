use base64::prelude::*;
use log::{debug, error, warn};
use tokio::io::{AsyncWriteExt, BufReader};
use yescrypt::{PasswordHash, PasswordVerifier, Yescrypt};

use crate::{Mail, SmtpStream, message_formatter};

pub async fn handle(
    mail: &mut Mail,
    service_config: &eemail_component_configurator::Configuration,
    buffer: &mut BufReader<SmtpStream>,
    cmd: Vec<String>,
) -> anyhow::Result<()> {
    // According to RFC 4954 if authentication has already completed, or we are in the mail transaction we need to reject it
    if mail.in_mail || mail.has_authed {
        buffer
            .get_mut()
            .write_all(&message_formatter(
                "503 Authentication already completed or already in mail",
            ))
            .await?;
        return Ok(());
    }

    debug!("RAW Auth Command: {:#?}", cmd);

    if let Some(auth_type) = cmd.get(1) {
        match auth_type.as_str() {
            "PLAIN" => {
                if let Some(base64) = cmd.get(2) {
                    let decoded = BASE64_STANDARD.decode(base64.as_str())?;
                    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();

                    if parts.len() != 3 {
                        warn!(
                            "Invalid PLAIN auth format: expected 3 parts, got {}",
                            parts.len()
                        );
                        buffer
                            .get_mut()
                            .write_all(&message_formatter("535 Authentication failed"))
                            .await?;
                    }

                    let username = String::from_utf8_lossy(parts[1]).to_string();
                    let password = String::from_utf8_lossy(parts[2]).to_string();

                    if let Some(user) = service_config.clone().get_user_from_alias(&username) {
                        if let Some(src) = user.hashed_password {
                            match PasswordHash::new(&src) {
                                Ok(parsed_hash) => {
                                    match Yescrypt
                                        .verify_password(password.as_bytes(), &parsed_hash)
                                    {
                                        Ok(_) => {
                                            debug!("Authentication Success!");
                                            buffer
                                                .get_mut()
                                                .write_all(&message_formatter(
                                                    "235 Authentication Successfull",
                                                ))
                                                .await?;
                                        }
                                        Err(_) => {
                                            debug!(
                                                "Password verification failed for user: {username}"
                                            );
                                            buffer
                                                .get_mut()
                                                .write_all(&message_formatter(
                                                    "535 Authentication failed",
                                                ))
                                                .await?;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to parse password hash for user {username}: {e}"
                                    );
                                    buffer
                                        .get_mut()
                                        .write_all(&message_formatter("535 Authentication failed"))
                                        .await?;
                                }
                            }
                        } else {
                            debug!("User doesn't have a password: {username}");
                            buffer
                                .get_mut()
                                .write_all(&message_formatter("535 Authentication failed"))
                                .await?;
                        }
                    } else {
                        debug!("User not found for email: {username}");
                        buffer
                            .get_mut()
                            .write_all(&message_formatter("535 Authentication failed"))
                            .await?;
                    }
                } else {
                    buffer
                        .get_mut()
                        .write_all(&message_formatter("535 Authentication failed"))
                        .await?;
                }
            }

            _ => {
                buffer
                    .get_mut()
                    .write_all(&message_formatter(
                        "504 Authentication mechanism not supported",
                    ))
                    .await?;
            }
        }
    } else {
        buffer
            .get_mut()
            .write_all(&message_formatter("501 Syntax error in parameters"))
            .await?;
    }
    Ok(())
}
