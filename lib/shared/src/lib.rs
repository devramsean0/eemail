#[derive(Clone, Copy)]
pub struct SMTPPortConfiguration {
    pub auth_enabled: bool,
    pub filtering_enabled: bool,
    pub implicit_tls: bool,
    pub port: u16,
}
