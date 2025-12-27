# eemail
An Opinionated (and WIP) single binary Email Server.

## TODO List
### MVP
- [x] Config File (TOML)
- [ ] SMTP
    - [x] Core (EHLO/General commands)
    - [ ] RFC 1870 (Size)
    - [ ] RFC 3207 (Starttls)
    - [x] RFC 4954 (Auth)
    - [ ] RFC 2034 (Enhanced Status Codes)
- [ ] IMAP

### V1
- [ ] SMTP
    - [ ] RFC 2920 (Pipelining)
    - [ ] RFC 6152 (8BITMINE)
    - [ ] RFC 3461 (DSN - Delivery Status Notifications)
- [ ] POP3
- [ ] Webmail
- [ ] DMARK/DKIM
- [ ] Admin UI

## Development
You need rust installed! (or just use nix and then run `nix develop`). Then run `cargo run` simples
