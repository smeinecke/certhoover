use certhoover::ServiceConfig;

#[test]
fn test_service_config_deserialization() {
    let toml = r#"
        liveness_path = "/tmp/liveness"
        batch_size = 100
        max_batch_age_secs = 30
        logging_level = "info"
    "#;
    let config: ServiceConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.liveness_path, "/tmp/liveness");
    assert_eq!(config.batch_size, 100);
    assert_eq!(config.max_batch_age_secs, 30);
    assert_eq!(config.logging_level, "info");
}
