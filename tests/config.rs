use certhoover::ServiceConfig;

#[test]
fn test_service_config_deserialization() {
    // Case 1: Field present
    let toml = r#"
        enable_systemd_notify = true
        batch_size = 100
        max_batch_age_secs = 30
        logging_level = "info"
    "#;
    let config: ServiceConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.enable_systemd_notify, Some(true));
    assert_eq!(config.enable_systemd_notify.unwrap_or(false), true);
    assert_eq!(config.batch_size, 100);
    assert_eq!(config.max_batch_age_secs, 30);
    assert_eq!(config.logging_level, "info");

    // Case 2: Field omitted
    let toml = r#"
        batch_size = 50
        max_batch_age_secs = 10
        logging_level = "debug"
    "#;
    let config: ServiceConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.enable_systemd_notify, None);
    assert_eq!(config.enable_systemd_notify.unwrap_or(false), false);
    assert_eq!(config.batch_size, 50);
    assert_eq!(config.max_batch_age_secs, 10);
    assert_eq!(config.logging_level, "debug");
}
