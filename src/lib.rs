pub mod config;
pub use crate::config::ServiceConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyRecordData {
    pub cert_index: u64,
    pub cert_link: String,
    pub leaf_cert: LeafCert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyRecord {
    pub data: Option<TransparencyRecordData>,
    pub message_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafCert {
    pub all_domains: Vec<String>,
    pub fingerprint: String,
    pub not_after: u64,
    pub not_before: u64,
    pub serial_number: String,
    pub subject: Subject,
    pub extensions: Extensions,
    pub signature_algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub c: Option<String>,
    pub cn: Option<String>,
    pub l: Option<String>,
    pub o: Option<String>,
    pub ou: Option<String>,
    pub st: Option<String>,
    pub aggregated: Option<String>,
    #[serde(alias = "emailAddress")]
    pub email_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extensions {
    #[serde(alias = "authorityInfoAccess")]
    pub authority_info_access: Option<String>,
    #[serde(alias = "authorityKeyIdentifier")]
    pub authority_key_identifier: Option<String>,
    #[serde(alias = "basicConstraints")]
    pub basic_constraints: Option<String>,
    #[serde(alias = "certificatePolicies")]
    pub certificate_policies: Option<String>,
    #[serde(alias = "ctlSignedCertificateTimestamp")]
    pub ctl_signed_certificate_timestamp: Option<String>,
    #[serde(alias = "extendedKeyUsage")]
    pub extended_key_usage: Option<String>,
    #[serde(alias = "keyUsage")]
    pub key_usage: Option<String>,
    #[serde(alias = "subjectAltName")]
    pub subject_alt_name: Option<String>,
    #[serde(alias = "subjectKeyIdentifier")]
    pub subject_key_identifier: Option<String>,
}

pub fn batch_records(
    ws_read_channel: std::sync::mpsc::Receiver<String>,
    batch_queue: std::sync::mpsc::Sender<Vec<TransparencyRecord>>,
    batch_size: usize,
    max_batch_age: Duration,
) {
    let mut message_buffer: Vec<TransparencyRecord> = Vec::new();
    let mut last_batch_time = std::time::Instant::now();
    loop {
        let timeout = max_batch_age
            .checked_sub(last_batch_time.elapsed())
            .unwrap_or(std::time::Duration::from_secs(0));
        let message = ws_read_channel.recv_timeout(timeout);
        match message {
            Ok(msg) => {
                let record: TransparencyRecord = serde_json::from_str(&msg).unwrap();
                message_buffer.push(record);
                if message_buffer.len() >= batch_size {
                    log::info!("Batching up {} records", message_buffer.len());
                    if let Err(e) = batch_queue.send(message_buffer) {
                        log::warn!("Batch queue send failed in batch_records: {e}");
                        break;
                    }
                    message_buffer = Vec::new();
                    last_batch_time = std::time::Instant::now();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Time to flush the batch due to age
                if !message_buffer.is_empty() {
                    log::info!("Batching up {} records (timeout)", message_buffer.len());
                    if let Err(e) = batch_queue.send(message_buffer) {
                        log::warn!("Batch queue send failed in batch_records: {e}");
                        break;
                    }
                    message_buffer = Vec::new();
                }
                last_batch_time = std::time::Instant::now();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                log::warn!("Websocket channel closed in batch_records");
                break;
            }
        }
    }
}
