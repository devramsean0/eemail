use base64::prelude::*;
use log::{debug, error, warn};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use uuid::Uuid;
use yescrypt::{PasswordHash, PasswordVerifier, Yescrypt, yescrypt};

use crate::PortConfiguration;

#[derive(Default)]
struct Mail {
    from: String,
    to: Vec<String>,
    data: String,

    // Boolean checks
    sending_data: bool,
    in_mail: bool,
    has_authed: bool,
}

pub async fn handle_smtp(
    stream: TcpStream,
    config: PortConfiguration,
    service_config: eemail_component_configurator::Configuration,
) -> anyhow::Result<()> {
    let email_path = std::env::var("EMAIL_PATH")?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    writer
        .write_all(&message_formatter("220 Server Ready"))
        .await?;
    debug!("Sent Ready");

    let mut mail = Mail::default();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }

        let cmd: Vec<String> = line
            .trim_end()
            .split_whitespace()
            .map(str::to_string)
            .collect();

        if !mail.sending_data {
            if let Some(first) = cmd.get(0) {
                if let Some(second) = cmd.get(1) {
                    debug!("Received Command: {} with data: {}", first, second);
                } else {
                    debug!("Received Command: {}", first)
                }
                match first.as_str() {
                    "EHLO" => {
                        let mut extension_strs: Vec<String> = vec![
                            "250-Localhost".to_string(),
                            "250-PIPELINING".to_string(),
                            format!("250-Size {}", 10 * 1024 * 1024),
                        ];

                        if config.auth_enabled {
                            extension_strs.push("250-AUTH PLAIN".to_string());
                        }

                        // The last one in the array needs to be "250 " not "250-"
                        if let Some(last) = extension_strs.last_mut() {
                            *last = last.replacen("250-", "250 ", 1);
                        }

                        debug!("Sending EHLO Response {:#?}", extension_strs);
                        let mut joined_extensions = extension_strs.join("\r\n");
                        joined_extensions.push_str("\r\n");
                        writer.write_all(joined_extensions.as_bytes()).await?;
                    }
                    "AUTH" => {
                        // According to RFC 4954 if authentication has already completed, or we are in the mail transaction we need to reject it
                        if mail.in_mail || mail.has_authed {
                            writer
                                .write_all(&message_formatter(
                                    "503 Authentication already completed or already in mail",
                                ))
                                .await?;
                            continue;
                        }

                        debug!("RAW Auth Command: {:#?}", cmd);

                        if let Some(auth_type) = cmd.get(1) {
                            match auth_type.as_str() {
                                "PLAIN" => {
                                    if let Some(base64) = cmd.get(2) {
                                        let decoded = BASE64_STANDARD.decode(base64.as_str())?;
                                        let parts: Vec<&[u8]> =
                                            decoded.split(|&b| b == 0).collect();
                                        if parts.len() == 3 {
                                            let username =
                                                String::from_utf8_lossy(parts[1]).to_string();
                                            let password =
                                                String::from_utf8_lossy(parts[2]).to_string();

                                            if let Some(user) = service_config
                                                .clone()
                                                .get_user_from_alias(&username)
                                            {
                                                if let Some(src) = user.hashed_password {
                                                    match PasswordHash::new(&src) {
                                                        Ok(parsed_hash) => {
                                                            match Yescrypt.verify_password(
                                                                password.as_bytes(),
                                                                &parsed_hash,
                                                            ) {
                                                                Ok(_) => {
                                                                    debug!(
                                                                        "Authentication Success!"
                                                                    );
                                                                    mail.has_authed = true;
                                                                    writer
                                                                        .write_all(&message_formatter(
                                                                            "235 Authentication Successfull",
                                                                        ))
                                                                        .await?;
                                                                }
                                                                Err(_) => {
                                                                    debug!(
                                                                        "Password verification failed for user: {username}"
                                                                    );
                                                                    writer
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
                                                            writer
                                                                .write_all(&message_formatter(
                                                                    "535 Authentication failed",
                                                                ))
                                                                .await?;
                                                        }
                                                    }
                                                } else {
                                                    debug!(
                                                        "User doesn't have a password: {username}"
                                                    );
                                                    writer
                                                        .write_all(&message_formatter(
                                                            "535 Authentication failed",
                                                        ))
                                                        .await?;
                                                }
                                            } else {
                                                debug!("User not found for email: {username}");
                                                writer
                                                    .write_all(&message_formatter(
                                                        "535 Authentication failed",
                                                    ))
                                                    .await?;
                                            }
                                        } else {
                                            warn!(
                                                "Invalid PLAIN auth format: expected 3 parts, got {}",
                                                parts.len()
                                            );
                                            writer
                                                .write_all(&message_formatter(
                                                    "535 Authentication failed",
                                                ))
                                                .await?;
                                        }
                                    } else {
                                        writer
                                            .write_all(&message_formatter(
                                                "535 Authentication failed",
                                            ))
                                            .await?;
                                    }
                                }

                                _ => {
                                    writer
                                        .write_all(&message_formatter(
                                            "504 Authentication mechanism not supported",
                                        ))
                                        .await?;
                                }
                            }
                        } else {
                            writer
                                .write_all(&message_formatter("501 Syntax error in parameters"))
                                .await?;
                        }
                    }
                    "MAIL" => {
                        mail.in_mail = true;
                        if let Some(second) = cmd.get(1) {
                            // Carefully strip out the FROM header, this caters to Thunderbirds specific behaviour so some leeway is allowed
                            let second = second
                                .strip_prefix("FROM:")
                                .unwrap_or_else(|| second)
                                .to_string();
                            let second = second
                                .strip_prefix("<")
                                .unwrap_or_else(|| &second)
                                .strip_suffix(">")
                                .unwrap_or_else(|| &second)
                                .to_string();

                            debug!("Stripped FROM header to {}", second);

                            writer.write_all(&message_formatter("250 OK")).await?;

                            mail.from = second;
                            debug!("Responded to MAIL FROM");
                        }
                    }
                    "RCPT" => {
                        if let Some(second) = cmd.get(1) {
                            // Carefully strip out the FROM header, this caters to Thunderbirds specific behaviour so some leeway is allowed
                            let second = second
                                .strip_prefix("TO:")
                                .unwrap_or_else(|| second)
                                .to_string();
                            let second = second
                                .strip_prefix("<")
                                .unwrap_or_else(|| &second)
                                .strip_suffix(">")
                                .unwrap_or_else(|| &second)
                                .to_string();

                            debug!("Stripped TO header to {}", second);
                            mail.to.push(second);
                            writer.write_all(&message_formatter("250 OK")).await?;
                            debug!("Responded to RCPT TO");
                        }
                    }
                    "DATA" => {
                        // Validations
                        if mail.from.is_empty() || mail.to.is_empty() {
                            writer
                                .write_all(&message_formatter("503 Bad Sequence of commands"))
                                .await?;
                        }
                        mail.sending_data = true;
                        writer
                            .write_all(&message_formatter("354 End data with <CR><LF>.<CR><LF>"))
                            .await?;
                    }
                    "QUIT" => {
                        writer.write_all(&message_formatter("221 Bye")).await?;
                        writer.shutdown().await?;
                        break;
                    }
                    _ => {
                        warn!("Unrecognised Command {}", first);
                        writer
                            .write_all(&message_formatter("502 Command not implemented"))
                            .await?;
                    }
                }
            } else {
                error!("Failed to split command (string: {:?}", cmd);
                continue;
            }
        } else {
            if let Some(first) = cmd.get(0) {
                if first == "." {
                    mail.sending_data = false;
                    debug!("Finished Receving Data from connection");
                    writer
                        .write_all(&message_formatter("250 Message accepted"))
                        .await?;
                } else {
                    mail.data.push_str(line.replace("\r\n", "\n").as_str());
                }
            }
        }
    }
    debug!("FROM: {}", mail.from);
    debug!("TO: {:#?}", mail.to);
    debug!("DATA: {}", mail.data);

    let uuid = Uuid::now_v7().as_urn().to_string().replace("urn:uuid:", ""); // maybe I should explore v5 uuid's using the message body as the data, not sure
    debug!("Given message ID: {uuid}");

    let from_account = service_config
        .accounts
        .iter()
        .find(|&x| x.clone().get_all_addresses().contains(&mail.from));

    let local_recipients: Vec<String> = mail
        .to
        .iter()
        .filter(|recipient| {
            service_config
                .accounts
                .iter()
                .any(|account| account.clone().get_all_addresses().contains(recipient))
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
        fs::write(format!("{}/{}.eml", base, uuid), mail.data.clone()).await?;
    }

    for recipient in local_recipients {
        let recipient = service_config
            .clone()
            .get_user_from_alias(&recipient)
            .unwrap()
            .get_primary_address();
        let base = format!("{}/{}/Inbox", email_path, recipient);
        fs::create_dir_all(base.clone()).await?;
        fs::write(format!("{}/{}.eml", base, uuid), mail.data.clone()).await?;
    }
    Ok(())
}

fn message_formatter(string: &'static str) -> Vec<u8> {
    let formatted = format!("{}\r\n", string);
    debug!("Sending Message {formatted}");
    formatted.into_bytes()
}
