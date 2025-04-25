pub mod config;
pub use crate::config::ServiceConfig;
use publicsuffix::Psl;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CertificateRow {
    pub cert_index: u64,
    pub cert_link: String,
    pub fingerprint: String,
    pub not_after: u64,
    pub not_before: u64,
    pub serial_number: String,
    pub c: String,
    pub cn: String,
    pub l: String,
    pub o: String,
    pub ou: String,
    pub st: String,
    pub aggregated: String,
    pub email_address: String,
    pub domain: String,
    pub hostnames: String,
    pub tld: String,
    pub root_domain: String,
    pub authority_info_access: String,
    pub authority_key_identifier: String,
    pub basic_constraints: String,
    pub certificate_policies: String,
    pub ctl_signed_certificate_timestamp: String,
    pub extended_key_usage: String,
    pub key_usage: String,
    pub subject_alt_name: String,
    pub subject_key_identifier: String,
    pub signature_algorithm: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

pub fn parse_subject_aggregated(aggregated: &str) -> std::collections::HashMap<&str, String> {
    let mut map = std::collections::HashMap::new();
    for part in aggregated.split('/') {
        if let Some((key, value)) = part.split_once('=') {
            map.insert(key, value.to_string());
        }
    }
    map
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

pub fn reformat_cert_fields(
    data: &TransparencyRecordData,
    list: &publicsuffix::List,
) -> CertificateRow {
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

    let cn = get_field("CN", &data.leaf_cert.subject.cn);
    let subject_alt_name = &data.leaf_cert.extensions.subject_alt_name;

    // Find domain
    let all_domains = &data.leaf_cert.all_domains;
    let domain = all_domains
        .first()
        .cloned()
        .or_else(|| cn.clone())
        .unwrap_or_default();

    let mut hostnames_set = std::collections::HashSet::new();
    // Extract from subject_alt_name
    if let Some(san) = subject_alt_name.as_ref() {
        for entry in san.split(',') {
            let entry = entry.trim();
            if let Some(host) = entry.strip_prefix("DNS:") {
                hostnames_set.insert(host.to_string());
            } else if let Some(ip) = entry.strip_prefix("IP Address:") {
                hostnames_set.insert(ip.to_string());
            }
        }
    }
    // Add all domains (including IPs) from all_domains
    for d in all_domains {
        hostnames_set.insert(d.clone());
    }
    // Add CN if present and not already in set
    if let Some(cn_val) = cn.clone() {
        if !cn_val.is_empty() {
            hostnames_set.insert(cn_val);
        }
    }
    let mut hostnames: Vec<String> = hostnames_set.into_iter().collect();
    hostnames.sort();
    let hostnames_json = serde_json::to_string(&hostnames).unwrap();

    let domain = domain
        .strip_prefix("*.")
        .map_or(domain.clone(), |s| s.to_string());

    // Only set tld/root_domain if there is at least one non-IP hostname
    let any_non_ip = hostnames.iter().any(|h| !is_ip(h));

    let (tld, root_domain) = if any_non_ip {
        let tld = match list.suffix(domain.as_bytes()) {
            Some(s) => std::str::from_utf8(s.as_bytes()).unwrap_or("").to_string(),
            None => "".to_string(),
        };
        let root_domain = match list.domain(domain.as_bytes()) {
            Some(d) => std::str::from_utf8(d.as_bytes()).unwrap_or("").to_string(),
            None => "".to_string(),
        };
        (tld, root_domain)
    } else {
        ("".to_string(), "".to_string())
    };

    CertificateRow {
        cert_index: data.cert_index,
        cert_link: data.cert_link.clone(),
        fingerprint: data.leaf_cert.fingerprint.clone(),
        not_after: data.leaf_cert.not_after,
        not_before: data.leaf_cert.not_before,
        serial_number: data.leaf_cert.serial_number.clone(),
        c: get_field("C", &data.leaf_cert.subject.c).unwrap_or_default(),
        cn: get_field("CN", &data.leaf_cert.subject.cn).unwrap_or_default(),
        l: get_field("L", &data.leaf_cert.subject.l).unwrap_or_default(),
        o: get_field("O", &data.leaf_cert.subject.o).unwrap_or_default(),
        ou: get_field("OU", &data.leaf_cert.subject.ou).unwrap_or_default(),
        st: get_field("ST", &data.leaf_cert.subject.st).unwrap_or_default(),
        aggregated: data
            .leaf_cert
            .subject
            .aggregated
            .clone()
            .unwrap_or_default(),
        email_address: get_field("emailAddress", &data.leaf_cert.subject.email_address)
            .unwrap_or_default(),
        domain,
        hostnames: hostnames_json,
        tld,
        root_domain,
        authority_info_access: data
            .leaf_cert
            .extensions
            .authority_info_access
            .clone()
            .unwrap_or_default(),
        authority_key_identifier: data
            .leaf_cert
            .extensions
            .authority_key_identifier
            .clone()
            .unwrap_or_default(),
        basic_constraints: data
            .leaf_cert
            .extensions
            .basic_constraints
            .clone()
            .unwrap_or_default(),
        certificate_policies: data
            .leaf_cert
            .extensions
            .certificate_policies
            .clone()
            .unwrap_or_default(),
        ctl_signed_certificate_timestamp: data
            .leaf_cert
            .extensions
            .ctl_signed_certificate_timestamp
            .clone()
            .unwrap_or_default(),
        extended_key_usage: data
            .leaf_cert
            .extensions
            .extended_key_usage
            .clone()
            .unwrap_or_default(),
        key_usage: data
            .leaf_cert
            .extensions
            .key_usage
            .clone()
            .unwrap_or_default(),
        subject_alt_name: data
            .leaf_cert
            .extensions
            .subject_alt_name
            .clone()
            .unwrap_or_default(),
        subject_key_identifier: data
            .leaf_cert
            .extensions
            .subject_key_identifier
            .clone()
            .unwrap_or_default(),
        signature_algorithm: data
            .leaf_cert
            .signature_algorithm
            .clone()
            .unwrap_or_default(),
    }
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
