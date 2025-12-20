use std::{fs, io};

use log::debug;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
struct Configuration {
    enable_smtp: Option<bool>,
    enable_imap: Option<bool>,
    enable_pop3: Option<bool>,
    enable_filtering: Option<bool>,

    fqdn: String,
    sending_fqdn: String,
    domains: Vec<String>,

    accounts: Vec<Account>,
}

#[derive(Deserialize, Debug, Clone)]
struct Account {
    domain: String,
    user: String,
    aliases: Option<Vec<String>>,
}

impl Configuration {
    pub fn parse_from_file(path: &'static str) -> anyhow::Result<Self> {
        debug!("Starting Configuration Load from file");
        let file = fs::read_to_string(path)?;
        return Ok(toml::from_str::<Self>(file.as_str())?);
    }

    pub fn parse_from_string(string: String) -> anyhow::Result<Self> {
        debug!("Starting Configuration Load from string");
        return Ok(toml::from_str::<Self>(string.as_str())?);
    }

    pub fn get_accounts(self) -> Vec<Account> {
        self.accounts.clone()
    }
}

impl Account {
    pub fn get_all_addresses(self) -> Vec<String> {
        let mut aliases: Vec<String> = match self.aliases {
            Some(aliases) => aliases,
            None => Vec::new(),
        };

        let primary = format!("{}@{}", self.user, self.domain);
        aliases.push(primary);

        aliases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> String {
        // Define a quick and dirty config for our tests
        r#"
        fqdn = "mail.example.com"
        sending_fqdn = "example.com"

        domains = ["example.com", "example.net"]

        enable_smtp = true
        enable_pop3 = false

        [[accounts]]
        domain = "example.com"
        user = "example"
        aliases = ["hi@example.com", "example@example.net"]

        [[accounts]]
        domain = "example.com"
        user = "test"
        "#
        .to_string()
    }

    #[test]
    fn config_parses_from_string() {
        Configuration::parse_from_string(config()).unwrap();
    }

    #[test]
    fn config_parses_from_file() {
        // Actually get the correct file
        let mut path = "./tests/config.toml";
        if !fs::exists(path).unwrap() {
            path = "../../tests/config.toml"
        }

        Configuration::parse_from_file(path).unwrap();
    }

    #[test]
    fn config_parses_accounts() {
        let config = Configuration::parse_from_string(config()).unwrap();
        assert_eq!(config.get_accounts().len(), 2);
    }

    #[test]
    fn config_parses_all_account_addresses() {
        let config = Configuration::parse_from_string(config()).unwrap();
        assert_eq!(config.clone().get_accounts().len(), 2);

        assert_eq!(
            config.get_accounts()[0].clone().get_all_addresses(),
            [
                "hi@example.com",
                "example@example.net",
                "example@example.com",
            ]
        )
    }
}
