use anyhow::{Context, Result};
use certhoover::config::AppConfig;
use certhoover::reformat_cert_fields;
use certhoover::CertificateRow;
use clickhouse::Client;
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use publicsuffix::List;
use std::time::Duration;
// systemd notification is only used if enabled in config
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[tokio::main]
async fn main() -> Result<()> {
    // Allow config path override via CERTHOOVER_CONFIG env var
    let config_path =
        std::env::var("CERTHOOVER_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = AppConfig::from_file(&config_path)
        .with_context(|| format!("Failed to load config from '{}':", config_path))?;

    // Set RUST_LOG from config if not already set
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", &config.service.logging_level);
    }
    env_logger::init();

    let (ws_sender, ws_receiver) = tokio::sync::mpsc::channel(100);
    let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(100);

    let batch_size = config.service.batch_size;
    let max_batch_age = Duration::from_secs(config.service.max_batch_age_secs);

    let certstream_url = config.certstream.url.clone();
    let clickhouse_cfg = config.clickhouse;
    let mut ch_client = Client::default()
        .with_url(format!(
            "http://{}:{}",
            clickhouse_cfg.host, clickhouse_cfg.port
        ))
        .with_database(clickhouse_cfg.database);
    if !clickhouse_cfg.user.is_empty() {
        ch_client = ch_client.with_user(clickhouse_cfg.user);
    }
    if !clickhouse_cfg.password.is_empty() {
        ch_client = ch_client.with_password(clickhouse_cfg.password);
    }

    let ws_sender_clone = ws_sender.clone();
    let websocket_task = tokio::spawn(async move {
        read_websocket(&certstream_url, ws_sender_clone).await;
    });

    let batcher_task = tokio::spawn(async move {
        batch_records(ws_receiver, batch_sender, batch_size, max_batch_age).await;
    });

    let enable_systemd_notify = config.service.enable_systemd_notify.unwrap_or(false);
    let debug_log_first_batch_record = config.service.debug_log_first_batch_record;
    insert_records(
        ch_client,
        batch_receiver,
        enable_systemd_notify,
        debug_log_first_batch_record,
    )
    .await
    .with_context(|| "Failed to insert records into ClickHouse")?;

    websocket_task.await.context("Websocket task failed")?;
    batcher_task.await.context("Batcher task failed")?;
    Ok(())
}

async fn maybe_create_table(client: &Client) -> anyhow::Result<()> {
    let create_table_query = r#"
CREATE TABLE IF NOT EXISTS certs
(
    `timestamp` DateTime DEFAULT now() CODEC(DoubleDelta, LZ4),
    `cert_index` UInt64 CODEC(T64, ZSTD(1)),
    `cert_link` String CODEC(ZSTD(3)),
    `domain` String CODEC(ZSTD(3)),
    `hostnames` String CODEC(ZSTD(3)),
    `tld` LowCardinality(String),
    `root_domain` LowCardinality(String),
    `fingerprint` String,
    `not_after` UInt64 CODEC(T64, ZSTD(1)),
    `not_before` UInt64 CODEC(T64, ZSTD(1)),
    `serial_number` String,
    `c` LowCardinality(String),
    `cn` String CODEC(ZSTD(3)),
    `l` LowCardinality(String),
    `o` LowCardinality(String),
    `ou` LowCardinality(String),
    `st` LowCardinality(String),
    `aggregated` String CODEC(ZSTD(3)),
    `email_address` String CODEC(ZSTD(3)),
    `authority_info_access` String CODEC(ZSTD(3)),
    `authority_key_identifier` String CODEC(ZSTD(3)),
    `basic_constraints` LowCardinality(String),
    `certificate_policies` String CODEC(ZSTD(3)),
    `ctl_signed_certificate_timestamp` String CODEC(ZSTD(3)),
    `extended_key_usage` LowCardinality(String),
    `key_usage` LowCardinality(String),
    `subject_alt_name` String CODEC(ZSTD(3)),
    `subject_key_identifier` String CODEC(ZSTD(3)),
    `signature_algorithm` LowCardinality(String),
    `domain_rev` String MATERIALIZED reverse(domain)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (domain, not_before, cert_index)
SETTINGS index_granularity = 8192"#;

    client.query(create_table_query).execute().await?;
    Ok(())
}

async fn insert_records(
    client: Client,
    mut batch_receiver: tokio::sync::mpsc::Receiver<Vec<TransparencyRecord>>,
    enable_systemd_notify: bool,
    debug_log_first_batch_record: bool,
) -> Result<()> {
    // Process batch of records for insertion.
    let list = List::default();
    maybe_create_table(&client).await?;

    while let Some(batch) = batch_receiver.recv().await {
        if debug_log_first_batch_record {
            if let Some(first) = batch.first() {
                info!("First record in batch: {:?}", first);
            } else {
                info!("Batch is empty, no first record to log.");
            }
        }

        let mut inserter = client.insert::<CertificateRow>("certs").await?;
        let mut inserted = 0;
        for record in &batch {
            match &record.data {
                Some(data) => {
                    let row_struct = reformat_cert_fields(data, &list);
                    if let Err(e) = inserter.write(&row_struct).await {
                        warn!("Failed to queue row: {:?}", e);
                        continue;
                    }
                    inserted += 1;
                }
                None => {
                    warn!("Record missing data field: {:?}", record);
                }
            }
        }
        if let Err(e) = inserter.end().await {
            anyhow::bail!("Failed to insert block: {}", e);
        }
        info!(
            "Written batch of {} records, expanded to {} rows",
            batch.len(),
            inserted
        );
        // Notify systemd watchdog after each batch if enabled
        if enable_systemd_notify {
            #[cfg(unix)]
            {
                let _ = systemd::daemon::notify(false, std::iter::once(&("WATCHDOG", "1")));
            }
        }
    }
    Ok(())
}

async fn batch_records(
    mut ws_read_channel: tokio::sync::mpsc::Receiver<String>,
    batch_queue: tokio::sync::mpsc::Sender<Vec<TransparencyRecord>>,
    batch_size: usize,
    max_batch_age: Duration,
) {
    let mut message_buffer: Vec<TransparencyRecord> = Vec::new();
    let mut last_batch_time = tokio::time::Instant::now();

    while let Some(message) = ws_read_channel.recv().await {
        let record: TransparencyRecord = match serde_json::from_str(&message) {
            Ok(rec) => rec,
            Err(e) => {
                warn!("Failed to parse JSON: {e}");
                continue;
            }
        };
        message_buffer.push(record);

        if message_buffer.len() >= batch_size || last_batch_time.elapsed() >= max_batch_age {
            info!("Batching up {} records", message_buffer.len());
            if batch_queue.send(message_buffer).await.is_err() {
                warn!("Batch queue send failed in batch_records");
                break;
            }
            message_buffer = Vec::new();
            last_batch_time = tokio::time::Instant::now();
        }
    }
}

async fn read_websocket(url: &str, ws_write_channel: tokio::sync::mpsc::Sender<String>) {
    loop {
        let ws_stream = match connect_async(url).await {
            Ok((stream, _)) => stream,
            Err(e) => {
                warn!("Error connecting to websocket: {:?}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let (mut write, mut read) = ws_stream.split();
        let mut error_count: u16 = 0;
        let max_errors = 5;
        let ping_interval = Duration::from_secs(5);
        let mut _last_ping_sent = tokio::time::Instant::now();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Allow other tasks to run, avoid busy loop
                }
                _ = tokio::time::sleep(ping_interval) => {
                    info!("Sending ping");
                    if let Err(e) = write.send(Message::Ping(vec![])).await {
                        warn!("Error sending ping: {:?}", e);
                    }
                    _last_ping_sent = tokio::time::Instant::now();
                }
                msg = read.next() => {
                    match msg {
                        Some(Ok(msg)) => match msg {
                            Message::Text(text) => {
                                if ws_write_channel.send(text).await.is_err() {
                                    warn!("Websocket channel closed");
                                    break;
                                }
                            }
                            Message::Close(_) => {
                                info!("Connection closed");
                                break;
                            }
                            Message::Ping(_) => {
                                info!("Received ping");
                                if let Err(e) = write.send(Message::Pong(vec![])).await {
                                    warn!("Error sending pong: {:?}", e);
                                }
                            }
                            Message::Pong(_) => {
                                info!("Received pong");
                            }
                            _ => {
                                info!("Ignoring message: {:?}", msg);
                            }
                        },
                        Some(Err(e)) => {
                            error_count += 1;
                            warn!(
                                "[{}/{}] Error reading message: {:?}",
                                error_count, max_errors, e
                            );
                            if error_count >= max_errors {
                                warn!("Too many errors, closing connection");
                                break;
                            }
                        }
                        None => {
                            warn!("Websocket stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

// Types and batch_records moved to lib.rs
use certhoover::TransparencyRecord;
