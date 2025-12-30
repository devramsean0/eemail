use log::debug;
use tokio::io::{AsyncWriteExt, BufReader};

use crate::{Mail, SmtpStream, message_formatter};

pub async fn handle(
    mail: &mut Mail,
    buffer: &mut BufReader<SmtpStream>,
    cmd: Vec<String>,
) -> anyhow::Result<()> {
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
        buffer
            .get_mut()
            .write_all(&message_formatter("250 OK"))
            .await?;
        debug!("Responded to RCPT TO");
    }
    Ok(())
}
