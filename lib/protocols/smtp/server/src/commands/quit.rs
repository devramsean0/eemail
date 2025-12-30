use tokio::io::{AsyncWriteExt, BufReader};

use crate::{SmtpStream, message_formatter};

pub async fn handle(buffer: &mut BufReader<SmtpStream>) -> anyhow::Result<()> {
    buffer
        .get_mut()
        .write_all(&message_formatter("221 Bye"))
        .await?;
    buffer.get_mut().shutdown().await?;
    Ok(())
}
