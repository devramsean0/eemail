use tokio::io::{AsyncWriteExt, BufReader};

use crate::{Mail, SmtpStream, message_formatter};

pub async fn handle(mail: &mut Mail, buffer: &mut BufReader<SmtpStream>) -> anyhow::Result<()> {
    // Validations
    if mail.from.is_empty() || mail.to.is_empty() {
        buffer
            .get_mut()
            .write_all(&message_formatter("503 Bad Sequence of commands"))
            .await?;
    }
    mail.sending_data = true;
    buffer
        .get_mut()
        .write_all(&message_formatter("354 End data with <CR><LF>.<CR><LF>"))
        .await?;
    Ok(())
}
