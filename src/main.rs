use anyhow::{Context, Result};
use certhoover::batch_records;
use certhoover::config::AppConfig;
use certhoover::reformat_cert_fields;
use certhoover::CertificateRow;
use clickhouse::Client;
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use md5::{Digest, Md5};
use publicsuffix::List;
use std::collections::HashSet;
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

    // Larger buffer absorbs bursts: if the batcher falls behind, the ws task
    // stalls here instead of backpressuring TCP until certstream-server drops.
    let (ws_sender, ws_receiver) = tokio::sync::mpsc::channel(1000);
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

async fn insert_rows(client: &Client, rows: &[CertificateRow]) -> Result<()> {
    let mut inserter = client.insert::<CertificateRow>("certs").await?;
    for row in rows {
        inserter.write(row).await?;
    }
    inserter.end().await?;
    Ok(())
}

// dedup_key collapses precert/leaf pairs and multi-log copies of the same
// cert: serial_number is unique per issuing key (authority_key_identifier),
// and issuer guards CAs that log entries without AKI data. md5 is used
// because ClickHouse, Rust and Go all produce identical digests - the
// seen_certs seed was built with MD5(concat(serial,'|',aki,'|',issuer)).
fn dedup_key(row: &CertificateRow) -> String {
    format!(
        "{:x}",
        Md5::digest(format!(
            "{}|{}|{}",
            row.serial_number, row.authority_key_identifier, row.issuer
        ))
    )
}

// Chunk size for the h IN (...) lookup - each unhex('<64 hex>') literal is
// ~74 bytes, so 3000 keys (~220KiB) stays under ClickHouse's default
// max_query_size (256KiB).
const DEDUP_CHUNK: usize = 3000;

// filter_seen drops rows whose dedup key is already in certstream.seen_certs.
// Returns the rows to insert plus their keys; on query failure it warns and
// passes everything through (a rare dupe beats a dropped cert).

async fn filter_seen(
    client: &Client,
    rows: Vec<(CertificateRow, String)>,
) -> Vec<(CertificateRow, String)> {
    if rows.is_empty() {
        return rows;
    }
    let mut known: HashSet<String> = HashSet::new();
    let keys: Vec<&str> = rows.iter().map(|(_, k)| k.as_str()).collect();
    for chunk in keys.chunks(DEDUP_CHUNK) {
        let list = chunk
            .iter()
            .map(|k| format!("unhex('{k}')"))
            .collect::<Vec<_>>()
            .join(",");
        let res = client
            .query(&format!(
                "SELECT lower(hex(h)) FROM seen_certs WHERE h IN ({list})"
            ))
            .fetch_all::<String>()
            .await;
        match res {
            Ok(found) => known.extend(found),
            Err(e) => {
                warn!("seen_certs lookup failed, inserting unfiltered: {e}");
                return rows;
            }
        }
    }
    rows.into_iter()
        .filter(|(_, k)| !known.contains(k))
        .collect()
}

async fn record_seen(client: &Client, keys: &[String]) {
    for chunk in keys.chunks(DEDUP_CHUNK) {
        let list = chunk
            .iter()
            .map(|k| format!("unhex('{k}')"))
            .collect::<Vec<_>>()
            .join(",");
        let q = format!("INSERT INTO seen_certs SELECT arrayJoin([{list}])");
        if let Err(e) = client.query(&q).execute().await {
            warn!("seen_certs insert failed: {e}");
        }
    }
}

async fn insert_records(
    client: Client,
    mut batch_receiver: tokio::sync::mpsc::Receiver<Vec<TransparencyRecord>>,
    enable_systemd_notify: bool,
    debug_log_first_batch_record: bool,
) -> Result<()> {
    // Process batch of records for insertion.
    // List::default() is an EMPTY list (wildcard rule only) - suffix()
    // would return the last label and domain() the last two labels,
    // breaking tld/root_domain for every multi-label public suffix
    // (github.io, pages.dev, co.uk, s3-*.amazonaws.com...). A current
    // snapshot of publicsuffix.org's list is vendored into the binary.
    let list = List::from_bytes(include_bytes!("../public_suffix_list.dat"))
        .expect("embedded public_suffix_list.dat must parse");
    maybe_create_table(&client).await?;

    // Ping the watchdog on an independent cadence - a slow ClickHouse call
    // (big dedup lookup, contended insert) must not starve liveness pings.
    if enable_systemd_notify {
        #[cfg(unix)]
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(25));
            loop {
                tick.tick().await;
                let _ = systemd::daemon::notify(false, std::iter::once(&("WATCHDOG", "1")));
            }
        });
    }

    while let Some(batch) = batch_receiver.recv().await {
        if debug_log_first_batch_record {
            if let Some(first) = batch.first() {
                info!("First record in batch: {:?}", first);
            } else {
                info!("Batch is empty, no first record to log.");
            }
        }

        // Local dedup first: the same cert lands in several logs within
        // seconds, so copies frequently share one batch. The HashSet keeps
        // the first (row, key) per dedup key.
        let mut local: HashSet<String> = HashSet::new();
        let mut rows: Vec<(CertificateRow, String)> = Vec::with_capacity(batch.len());
        for record in &batch {
            match &record.data {
                Some(data) => {
                    let row = reformat_cert_fields(data, &list);
                    let key = dedup_key(&row);
                    if local.insert(key.clone()) {
                        rows.push((row, key));
                    }
                }
                None => warn!("Record missing data field: {:?}", record),
            }
        }

        // Then drop certs already stored (seen in earlier batches/logs) -
        // survivors get their keys recorded so later copies are skipped.
        let rows = filter_seen(&client, rows).await;
        let keys: Vec<String> = rows.iter().map(|(_, k)| k.clone()).collect();
        let rows: Vec<CertificateRow> = rows.into_iter().map(|(r, _)| r).collect();

        // A batch consisting only of data-less records has nothing to insert.
        if rows.is_empty() {
            continue;
        }

        const MAX_ATTEMPTS: u32 = 5;
        let mut attempt: u32 = 0;
        loop {
            match insert_rows(&client, &rows).await {
                Ok(()) => break,
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS {
                        anyhow::bail!("Failed to insert block after {MAX_ATTEMPTS} attempts: {e}");
                    }
                    warn!("Insert attempt {attempt}/{MAX_ATTEMPTS} failed: {e}; retrying");
                    tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                }
            }
        }
        record_seen(&client, &keys).await;
        info!(
            "Written batch of {} records, expanded to {} rows ({} already seen)",
            batch.len(),
            rows.len(),
            local.len() - rows.len()
        );
    }
    Ok(())
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
        let mut ping_ticker = tokio::time::interval(Duration::from_secs(5));
        ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ping_ticker.tick() => {
                    info!("Sending ping");
                    if let Err(e) = write.send(Message::Ping(vec![])).await {
                        warn!("Error sending ping: {:?}", e);
                    }
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
