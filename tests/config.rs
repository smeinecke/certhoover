use certhoover::ServiceConfig;

#[test]
fn test_service_config_deserialization() {
    let toml = r#"
        enable_systemd_notify = true
        batch_size = 100
        max_batch_age_secs = 30
        logging_level = "info"
    "#;
    let config: ServiceConfig = toml::from_str(toml).unwrap();
    assert!(config.enable_systemd_notify.unwrap());
    assert_eq!(config.batch_size, 100);
    assert_eq!(config.max_batch_age_secs, 30);
    assert_eq!(config.logging_level, "info");
}
