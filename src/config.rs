use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CertstreamConfig {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ClickhouseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub enable_systemd_notify: bool,
    pub batch_size: usize,
    pub max_batch_age_secs: u64,
    pub logging_level: String,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub certstream: CertstreamConfig,
    pub clickhouse: ClickhouseConfig,
    pub service: ServiceConfig,
}

impl AppConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, config::ConfigError> {
        let builder = config::Config::builder().add_source(config::File::from(path.as_ref()));
        builder.build()?.try_deserialize()
    }
}
