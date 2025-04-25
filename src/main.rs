mod config;

use anyhow::{Context, Result};
use clickhouse_rs::{row, types::Block, ClientHandle, Pool};
use config as config_mod;
use config_mod::AppConfig;
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use publicsuffix::{List, Psl};
use std::path::PathBuf;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn parse_subject_aggregated(aggregated: &str) -> std::collections::HashMap<&str, String> {
    let mut map = std::collections::HashMap::new();
    for part in aggregated.split('/') {
        if let Some((key, value)) = part.split_once('=') {
            map.insert(key, value.to_string());
        }
    }
    map
}

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

    let liveness_path = std::path::PathBuf::from(&config.service.liveness_path);
    insert_records(clickhouse_conn_str, batch_receiver, liveness_path)
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

fn touch_file(path: &PathBuf) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    Ok(())
}

async fn insert_records(
    connection_string: String,
    mut batch_receiver: tokio::sync::mpsc::Receiver<Vec<TransparencyRecord>>,
    liveness_path: PathBuf,
) -> Result<()> {
    // Process batch of records for insertion.

    let list = List::default();
    let pool = Pool::new(connection_string.clone());
    let mut client = pool.get_handle().await?;
    maybe_create_table(&mut client).await?;

    while let Some(batch) = batch_receiver.recv().await {
        // Update liveness file
        let _ = touch_file(&liveness_path);
        let mut block = Block::with_capacity(batch.len());
        let mut inserted = 0;
        for record in &batch {
            match &record.data {
                Some(data) => {
                    let agg_map = data
                        .leaf_cert
                        .subject
                        .aggregated
                        .as_ref()
                        .map(|agg| parse_subject_aggregated(agg));

                    let get_field = |key: &str, orig: &Option<String>| {
                        orig.clone()
                            .or_else(|| agg_map.as_ref().and_then(|m| m.get(key).cloned()))
                    };

                    let domain = data
                        .leaf_cert
                        .all_domains
                        .first()
                        .cloned()
                        .or_else(|| get_field("CN", &data.leaf_cert.subject.cn))
                        .unwrap_or_default();

                    let mut hostnames_set = std::collections::HashSet::new();
                    // Extract from subject_alt_name
                    if let Some(san) = data.leaf_cert.extensions.subject_alt_name.as_ref() {
                        for entry in san.split(',') {
                            let entry = entry.trim();
                            if let Some(host) = entry.strip_prefix("DNS:") {
                                hostnames_set.insert(host.to_string());
                            }
                        }
                    }

                    hostnames_set.insert(domain.clone());
                    let mut hostnames: Vec<String> = hostnames_set.into_iter().collect();
                    hostnames.sort();
                    let hostnames_json = serde_json::to_string(&hostnames).unwrap();

                    let domain = domain
                        .strip_prefix("*.")
                        .map_or(domain.clone(), |s| s.to_string());

                    let tld = match list.suffix(domain.as_bytes()) {
                        Some(s) => std::str::from_utf8(s.as_bytes()).unwrap_or("").to_string(),
                        None => "".to_string(),
                    };
                    let root_domain = match list.domain(domain.as_bytes()) {
                        Some(d) => std::str::from_utf8(d.as_bytes()).unwrap_or("").to_string(),
                        None => "".to_string(),
                    };

                    if let Err(e) = block.push(row!{
                        "cert_index" => data.cert_index,
                        "cert_link" => data.cert_link.clone(),
                        "fingerprint" => data.leaf_cert.fingerprint.clone(),
                        "not_after" => data.leaf_cert.not_after,
                        "not_before" => data.leaf_cert.not_before,
                        "serial_number" => data.leaf_cert.serial_number.clone(),
                        "c" => get_field("C", &data.leaf_cert.subject.c).unwrap_or_default(),
                        "cn" => get_field("CN", &data.leaf_cert.subject.cn).unwrap_or_default(),
                        "l" => get_field("L", &data.leaf_cert.subject.l).unwrap_or_default(),
                        "o" => get_field("O", &data.leaf_cert.subject.o).unwrap_or_default(),
                        "ou" => get_field("OU", &data.leaf_cert.subject.ou).unwrap_or_default(),
                        "st" => get_field("ST", &data.leaf_cert.subject.st).unwrap_or_default(),
                        "aggregated" => data.leaf_cert.subject.aggregated.clone().unwrap_or_default(),
                        "email_address" => data.leaf_cert.subject.email_address.clone().unwrap_or_default(),
                        "domain" => domain,
                        "hostnames" => hostnames_json,
                        "tld" => tld,
                        "root_domain" => root_domain,
                        "authority_info_access" => data.leaf_cert.extensions.authority_info_access.clone().unwrap_or_default(),
                        "authority_key_identifier" => data.leaf_cert.extensions.authority_key_identifier.clone().unwrap_or_default(),
                        "basic_constraints" => data.leaf_cert.extensions.basic_constraints.clone().unwrap_or_default(),
                        "certificate_policies" => data.leaf_cert.extensions.certificate_policies.clone().unwrap_or_default(),
                        "ctl_signed_certificate_timestamp" => data.leaf_cert.extensions.ctl_signed_certificate_timestamp.clone().unwrap_or_default(),
                        "extended_key_usage" => data.leaf_cert.extensions.extended_key_usage.clone().unwrap_or_default(),
                        "key_usage" => data.leaf_cert.extensions.key_usage.clone().unwrap_or_default(),
                        "subject_alt_name" => data.leaf_cert.extensions.subject_alt_name.clone().unwrap_or_default(),
                        "subject_key_identifier" => data.leaf_cert.extensions.subject_key_identifier.clone().unwrap_or_default(),
                        "signature_algorithm" => data.leaf_cert.signature_algorithm.clone().unwrap_or_default(),
                    }) {
                        warn!("Failed to add row to block: {e:?} (record: {:?})", record);
                        continue;
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
