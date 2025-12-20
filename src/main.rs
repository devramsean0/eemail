fn main() {
    println!(
        "{:#?}",
        eemail_component_configurator::Configuration::parse_from_file("./config.toml")
            .unwrap()
            .accounts
    )
}
