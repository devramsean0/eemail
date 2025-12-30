use log::{debug, error, warn};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use eemail_lib_shared::SMTPPortConfiguration;

mod commands;

enum SmtpStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for SmtpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            SmtpStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            SmtpStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SmtpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            SmtpStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            SmtpStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            SmtpStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            SmtpStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            SmtpStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            SmtpStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Default)]
pub struct Mail {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub data: String,

    // Boolean checks
    sending_data: bool,
    in_mail: bool,
    has_authed: bool,
    has_tlsd: bool,
}

pub async fn handle_smtp(
    stream: TcpStream,
    config: SMTPPortConfiguration,
    acceptor: TlsAcceptor,
    service_config: eemail_component_configurator::Configuration,
) -> anyhow::Result<Mail> {
    let mut stream = SmtpStream::Plain(stream);
    let mut line = String::new();

    stream
        .write_all(&message_formatter("220 Server Ready"))
        .await?;
    debug!("Sent Ready");

    let mut mail = Mail::default();
    let mut reader = BufReader::new(stream);

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }

        if !mail.sending_data {
            let cmd: Vec<String> = line
                .trim_end()
                .split_whitespace()
                .map(str::to_string)
                .collect();
            if let Some(first) = cmd.get(0) {
                if let Some(second) = cmd.get(1) {
                    debug!("Received Command: {} with data: {}", first, second);
                } else {
                    debug!("Received Command: {}", first)
                }
                match first.as_str() {
                    "EHLO" => commands::ehlo::handle(&mail, &config, &mut reader).await?,
                    "AUTH" => {
                        commands::auth::handle(&mut mail, &service_config, &mut reader, cmd).await?
                    }
                    "MAIL" => commands::mail::handle(&mut mail, &mut reader, cmd).await?,
                    "RCPT" => commands::rcpt::handle(&mut mail, &mut reader, cmd).await?,
                    "DATA" => commands::data::handle(&mut mail, &mut reader).await?,
                    "QUIT" => commands::quit::handle(&mut reader).await?,
                    "STARTTLS" => {
                        commands::starttls::handle(&mut mail, &mut reader, &acceptor).await?
                    }
                    _ => {
                        warn!("Unrecognised Command {}", first);
                        reader
                            .get_mut()
                            .write_all(&message_formatter("502 Command not implemented"))
                            .await?;
                    }
                }
            } else {
                error!("Failed to split command (string: {:?}", cmd);
                continue;
            }
        } else {
            // We're receiving DATA - check if it's the end marker
            if line.trim_end() == "." {
                mail.sending_data = false;
                debug!("Finished Receving Data from connection");
                reader
                    .get_mut()
                    .write_all(&message_formatter("250 Message accepted"))
                    .await?;
            } else {
                mail.data.push_str(line.replace("\r\n", "\n").as_str());
            }
        }
    }
    debug!("FROM: {}", mail.from);
    debug!("TO: {:#?}", mail.to);
    debug!("DATA: {}", mail.data);

    mail.id = Uuid::now_v7().as_urn().to_string().replace("urn:uuid:", ""); // maybe I should explore v5 uuid's using the message body as the data, not sure
    debug!("Given message ID: {}", mail.id);

    Ok(mail)
}

fn message_formatter(string: &'static str) -> Vec<u8> {
    let formatted = format!("{}\r\n", string);
    debug!("Sending Message {formatted}");
    formatted.into_bytes()
}
