mod config;

use clickhouse_rs::{row, types::Block, ClientHandle, Pool};
use config as config_mod;
use config_mod::AppConfig;
use log::{info, warn};
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use tungstenite::{connect, Message};

#[tokio::main]
async fn main() {
    // This whole thing is a bit of a monstrosity, for several reasons:
    //
    // * There's a hodge-podge of thread-based and async code here... the two main Clickhouse libraries I found are
    //   both async, the websocket library /can/ be async, but I don't know enough about async in rust to know whether
    //   it's performant enough -- there can be quite a few messages coming in from the websocket.
    // * I don't really know how to write idiomatic rust (yet).

    // Allow config path override via CERTHOOVER_CONFIG env var
    let config_path =
        std::env::var("CERTHOOVER_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = AppConfig::from_file(&config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config from '{}': {e}", config_path);
        std::process::exit(1);
    });

    // Set RUST_LOG from config if not already set
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", &config.service.logging_level);
    }
    env_logger::init();

    let (ws_sender, ws_receiver) = std::sync::mpsc::channel();
    let (batch_sender, batch_receiver) = std::sync::mpsc::channel();

    let batch_size = config.service.batch_size;
    let max_batch_age = Duration::from_secs(config.service.max_batch_age_secs);

    let certstream_url = config.certstream.url.clone();
    let clickhouse_cfg = config.clickhouse;
    let clickhouse_conn_str = format!(
        "tcp://{}:{}?database={}&user={}&password={}",
        clickhouse_cfg.host,
        clickhouse_cfg.port,
        clickhouse_cfg.database,
        clickhouse_cfg.user,
        clickhouse_cfg.password
    );

    // This could be a coroutine instead of a thread.
    let websocket_reader = std::thread::spawn(move || {
        read_websocket(&certstream_url, ws_sender);
    });

    let batcher = std::thread::spawn(move || {
        batch_records(ws_receiver, batch_sender, batch_size, max_batch_age);
    });

    // Inserter is async, so we don't need a thread but do need to await it.
    // Use liveness_path from config file for systemd liveness file
    let liveness_path = std::path::PathBuf::from(&config.service.liveness_path);
    insert_records(clickhouse_conn_str, batch_receiver, liveness_path)
        .await
        .unwrap();

    websocket_reader.join().unwrap();
    batcher.join().unwrap();
}

async fn maybe_create_table(client: &mut ClientHandle) {
    let create_table_query = r#"
CREATE TABLE IF NOT EXISTS certs
(
    `timestamp` DateTime DEFAULT now(),
    `cert_index` UInt64,
    `cert_link` String,
    `domain` String,
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

    client.execute(create_table_query).await.unwrap();
}

fn touch_file(path: &PathBuf) {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
}

async fn insert_records(
    connection_string: String,
    batch_receiver: std::sync::mpsc::Receiver<Vec<TransparencyRecord>>,
    liveness_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    // Process batch of records for insertion.
    // Rather than deal with nested fields in the JSON, we flatten the data into a single row per domain.
    // This is pretty inefficient, but it's a simple way to get the data into Clickhouse, and the data is probably
    // very compressible...?

    let pool = Pool::new(connection_string);

    let mut client = pool.get_handle().await?;

    maybe_create_table(&mut client).await;

    loop {
        // Update liveness file
        touch_file(&liveness_path);

        let batch = match batch_receiver.recv() {
            Ok(b) => b,
            Err(e) => {
                warn!("Batch channel closed in insert_records: {e}");
                break Ok(());
            }
        };

        let mut block = Block::new();
        let mut inserted: u64 = 0;

        for record in batch.iter() {
            match &record.data {
                Some(data) => {
                    // TODO: Can we avoid cloning here, and take ownership of the data?
                    // Note: this is a bit of a mess, but none of the two Clickhouse libraries I found seem to support
                    //       nested fields. We might be able to do some stuff with serdes to have it flatten the data
                    //       for us, but I'm not sure how to do that yet...
                    for domain in data.leaf_cert.all_domains.iter() {
                        block.push(row!{
                                "cert_index" => data.cert_index,
                                "cert_link" => data.cert_link.clone(),
                                "fingerprint" => data.leaf_cert.fingerprint.clone(),
                                "not_after" => data.leaf_cert.not_after,
                                "not_before" => data.leaf_cert.not_before,
                                "serial_number" => data.leaf_cert.serial_number.clone(),
                                "c" => data.leaf_cert.subject.c.clone().unwrap_or_default(),
                                "cn" => data.leaf_cert.subject.cn.clone().unwrap_or_default(),
                                "l" => data.leaf_cert.subject.l.clone().unwrap_or_default(),
                                "o" => data.leaf_cert.subject.o.clone().unwrap_or_default(),
                                "ou" => data.leaf_cert.subject.ou.clone().unwrap_or_default(),
                                "st" => data.leaf_cert.subject.st.clone().unwrap_or_default(),
                                "aggregated" => data.leaf_cert.subject.aggregated.clone().unwrap_or_default(),
                                "email_address" => data.leaf_cert.subject.email_address.clone().unwrap_or_default(),
                                "domain" => domain.clone(),
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
                            })?;
                        inserted += 1;
                    }
                }
                None => {
                    warn!("Record missing data field: {:?}", record);
                }
            }
        }
        client.insert("certs", block).await.unwrap();

        info!(
            "Written batch of {} records, expanded to {} rows",
            batch.len(),
            inserted
        );
    }
}

fn batch_records(
    ws_read_channel: std::sync::mpsc::Receiver<String>,
    batch_queue: std::sync::mpsc::Sender<Vec<TransparencyRecord>>,
    batch_size: usize,
    max_batch_age: Duration,
) {
    // Pull from the websocket queue, batch up records, and shove them into the batch queue
    // for insertion into Clickhouse.

    let mut message_buffer: Vec<TransparencyRecord> = Vec::new();
    let mut last_batch_time = std::time::Instant::now();

    loop {
        let message = match ws_read_channel.recv() {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Websocket channel closed in batch_records: {e}");
                break;
            }
        };
        let record: TransparencyRecord = serde_json::from_str(&message).unwrap();

        message_buffer.push(record);

        if message_buffer.len() >= batch_size || last_batch_time.elapsed() >= max_batch_age {
            info!("Batching up {} records", message_buffer.len());
            if let Err(e) = batch_queue.send(message_buffer) {
                warn!("Batch queue send failed in batch_records: {e}");
                break;
            }
            message_buffer = Vec::new();
            last_batch_time = std::time::Instant::now();
        }
    }
}

fn read_websocket(url: &str, ws_write_channel: std::sync::mpsc::Sender<String>) {
    loop {
        let (mut socket, _) = match connect(url) {
            Ok(result) => result,
            Err(e) => {
                warn!("Error connecting to websocket: {:?}", e);
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let mut error_count: u16 = 0;
        let max_errors = 5;

        let ping_interval = Duration::from_secs(5);
        let mut last_ping_sent = std::time::Instant::now();

        loop {
            // This isn't entirely ideal, given socket.read() is blocking so we're not guaranteed to meet the ping
            // interval, but the WS is busy enough that this doesn't matter in practice.

            if last_ping_sent.elapsed() >= ping_interval {
                info!("Sending ping");
                socket
                    .send(Message::Ping(vec![]))
                    .expect("Error sending ping");
                last_ping_sent = std::time::Instant::now();
            }

            match socket.read() {
                Ok(msg) => match msg {
                    Message::Text(text) => {
                        ws_write_channel.send(text).unwrap(); //todo: handle error
                    }
                    Message::Close(_) => {
                        info!("Connection closed");
                        break;
                    }
                    Message::Ping(_) => {
                        info!("Received ping");
                        socket
                            .send(Message::Pong(vec![]))
                            .expect("Error sending pong");
                    }
                    Message::Pong(_) => {
                        info!("Received pong");
                    }
                    _ => {
                        info!("Ignoring message: {:?}", msg);
                    }
                },
                Err(e) => {
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
            }
            socket.flush().unwrap();
        }
    }
}

// Types and batch_records moved to lib.rs
use certhoover::TransparencyRecord;
