use tokio::io::{AsyncWriteExt, BufReader};
use tokio_rustls::TlsAcceptor;

use crate::{Mail, SmtpStream, message_formatter};

pub async fn handle(
    mail: &mut Mail,
    buffer: &mut BufReader<SmtpStream>,
    acceptor: &TlsAcceptor,
) -> anyhow::Result<()> {
    if mail.has_tlsd {
        buffer
            .get_mut()
            .write_all(&message_formatter("454 TLS Already Active"))
            .await?;
        return Ok(());
    }

    buffer
        .get_mut()
        .write_all(&message_formatter("220 Ready to start TLS"))
        .await?;
    buffer.get_mut().flush().await?;

    mail.has_tlsd = true;

    let old_buffer: BufReader<SmtpStream> = unsafe { std::ptr::read(buffer as *const _) };

    let inner_stream = old_buffer.into_inner();
    let plain_stream = match inner_stream {
        SmtpStream::Plain(s) => s,
        SmtpStream::Tls(_) => unreachable!("Already checked has_tlsd"),
    };

    let tls_stream = acceptor.accept(plain_stream).await?;
    let upgraded_stream = SmtpStream::Tls(tls_stream);

    // Write the new buffer back
    unsafe {
        std::ptr::write(buffer as *mut _, BufReader::new(upgraded_stream));
    }

    Ok(())
}
