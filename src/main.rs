use anyhow::{Context, Result};
use certhoover::config::AppConfig;
use certhoover::reformat_cert_fields;
use clickhouse_rs::{row, types::Block, ClientHandle, Pool};
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
    let clickhouse_conn_str = match (
        clickhouse_cfg.user.as_str(),
        clickhouse_cfg.password.as_str(),
    ) {
        (user, password) if !user.is_empty() && !password.is_empty() => format!(
            "tcp://{user}:{password}@{}:{}/{}",
            clickhouse_cfg.host, clickhouse_cfg.port, clickhouse_cfg.database
        ),
        (user, _) if !user.is_empty() => format!(
            "tcp://{user}@{}:{}/{}",
            clickhouse_cfg.host, clickhouse_cfg.port, clickhouse_cfg.database
        ),
        _ => format!(
            "tcp://{}:{}/{}",
            clickhouse_cfg.host, clickhouse_cfg.port, clickhouse_cfg.database
        ),
    };

    let ws_sender_clone = ws_sender.clone();
    let websocket_task = tokio::spawn(async move {
        read_websocket(&certstream_url, ws_sender_clone).await;
    });

    let batcher_task = tokio::spawn(async move {
        batch_records(ws_receiver, batch_sender, batch_size, max_batch_age).await;
    });

    let enable_systemd_notify = config.service.enable_systemd_notify;
    insert_records(clickhouse_conn_str, batch_receiver, enable_systemd_notify)
        .await
        .with_context(|| "Failed to insert records into ClickHouse")?;

    websocket_task.await.context("Websocket task failed")?;
    batcher_task.await.context("Batcher task failed")?;
    Ok(())
}

async fn maybe_create_table(client: &mut ClientHandle) -> anyhow::Result<()> {
    let create_table_query = r#"
CREATE TABLE IF NOT EXISTS certs
(
    `timestamp` DateTime DEFAULT now(),
    `cert_index` UInt64,
    `cert_link` String,
    `domain` String,
    `hostnames` String,
    `tld` String,
    `root_domain` String,
    `fingerprint` String,
    `not_after` UInt64,
    `not_before` UInt64,
    `serial_number` String,
    `c` String,
    `cn` String,
    `l` String,
    `o` String,
    `ou` String,
    `st` String,
    `aggregated` String,
    `email_address` String,
    `authority_info_access` String,
    `authority_key_identifier` String,
    `basic_constraints` String,
    `certificate_policies` String,
    `ctl_signed_certificate_timestamp` String,
    `extended_key_usage` String,
    `key_usage` String,
    `subject_alt_name` String,
    `subject_key_identifier` String,
    `signature_algorithm` String
)
ENGINE = MergeTree
ORDER BY (cert_index, domain, timestamp)"#;

    client.execute(create_table_query).await?;
    Ok(())
}

async fn insert_records(
    connection_string: String,
    mut batch_receiver: tokio::sync::mpsc::Receiver<Vec<TransparencyRecord>>,
    enable_systemd_notify: bool,
) -> Result<()> {
    // Process batch of records for insertion.
    let list = List::default();
    let pool = Pool::new(connection_string.clone());
    let mut client = pool.get_handle().await?;
    maybe_create_table(&mut client).await?;

    while let Some(batch) = batch_receiver.recv().await {
        // Update liveness file

        let mut block = Block::with_capacity(batch.len());
        let mut inserted = 0;
        for record in &batch {
            match &record.data {
                Some(data) => {
                    let row_struct = reformat_cert_fields(data, &list);
                    let row = row! {
                        "cert_index" => row_struct.cert_index,
                        "cert_link" => row_struct.cert_link,
                        "fingerprint" => row_struct.fingerprint,
                        "not_after" => row_struct.not_after,
                        "not_before" => row_struct.not_before,
                        "serial_number" => row_struct.serial_number,
                        "c" => row_struct.c,
                        "cn" => row_struct.cn,
                        "l" => row_struct.l,
                        "o" => row_struct.o,
                        "ou" => row_struct.ou,
                        "st" => row_struct.st,
                        "aggregated" => row_struct.aggregated,
                        "email_address" => row_struct.email_address,
                        "domain" => row_struct.domain,
                        "hostnames" => row_struct.hostnames,
                        "tld" => row_struct.tld,
                        "root_domain" => row_struct.root_domain,
                        "authority_info_access" => row_struct.authority_info_access,
                        "authority_key_identifier" => row_struct.authority_key_identifier,
                        "basic_constraints" => row_struct.basic_constraints,
                        "certificate_policies" => row_struct.certificate_policies,
                        "ctl_signed_certificate_timestamp" => row_struct.ctl_signed_certificate_timestamp,
                        "extended_key_usage" => row_struct.extended_key_usage,
                        "key_usage" => row_struct.key_usage,
                        "subject_alt_name" => row_struct.subject_alt_name,
                        "subject_key_identifier" => row_struct.subject_key_identifier,
                        "signature_algorithm" => row_struct.signature_algorithm
                    };
                    if let Err(e) = block.push(row) {
                        warn!("Failed to push row to block: {:?}", e);
                    }
                    inserted += 1;
                }
                None => {
                    warn!("Record missing data field: {:?}", record);
                }
            }
        }
        if let Err(e) = client.insert("certs", block).await {
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
