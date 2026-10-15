use certhoover::{batch_records, TransparencyRecord};
use std::time::Duration;

#[test]
fn test_transparency_record_missing_optional_fields() {
    let json = r#"{
        "data": null,
        "message_type": "certificate_update"
    }"#;
    let rec: certhoover::TransparencyRecord = serde_json::from_str(json).unwrap();
    assert_eq!(rec.message_type, "certificate_update");
    assert!(rec.data.is_none());
}

#[test]
fn test_transparency_record_extra_fields() {
    let json = r#"{
        "data": null,
        "message_type": "certificate_update",
        "extra_field": "should be ignored"
    }"#;
    let rec: certhoover::TransparencyRecord = serde_json::from_str(json).unwrap();
    assert_eq!(rec.message_type, "certificate_update");
}

#[tokio::test]
async fn test_batch_records_multiple_batches() {
    let (ws_sender, ws_receiver) = tokio::sync::mpsc::channel(10);
    let (batch_sender, mut batch_receiver) = tokio::sync::mpsc::channel(10);
    tokio::spawn(batch_records(
        ws_receiver,
        batch_sender,
        2,
        Duration::from_secs(60),
    ));
    for i in 0..4 {
        let msg = serde_json::to_string(&certhoover::TransparencyRecord {
            data: None,
            message_type: format!("test{}", i),
        })
        .unwrap();
        ws_sender.send(msg).await.unwrap();
    }
    let batch1 = tokio::time::timeout(Duration::from_secs(1), batch_receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let batch2 = tokio::time::timeout(Duration::from_secs(1), batch_receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch1.len(), 2);
    assert_eq!(batch2.len(), 2);
}

#[test]
fn test_subject_serde_roundtrip() {
    let subject = certhoover::Subject {
        c: Some("DE".to_string()),
        cn: Some("foo.com".to_string()),
        l: None,
        o: None,
        ou: None,
        st: None,
        aggregated: None,
        email_address: Some("admin@foo.com".to_string()),
    };
    let json = serde_json::to_string(&subject).unwrap();
    let parsed: certhoover::Subject = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.c, subject.c);
    assert_eq!(parsed.email_address, subject.email_address);
}

#[tokio::test]
async fn test_batch_records_empty_input() {
    let (_ws_sender, ws_receiver) = tokio::sync::mpsc::channel::<String>(10);
    let (batch_sender, mut batch_receiver) = tokio::sync::mpsc::channel(10);
    tokio::spawn(batch_records(
        ws_receiver,
        batch_sender,
        2,
        Duration::from_millis(100),
    ));
    // No messages sent
    let result = tokio::time::timeout(Duration::from_millis(200), batch_receiver.recv()).await;
    assert!(result.is_err()); // Should timeout
}

#[test]
fn test_transparency_record_json_parsing() {
    let json = r#"{
        "data": {
            "cert_index": 123,
            "cert_link": "https://crt.sh/?id=123",
            "leaf_cert": {
                "all_domains": ["example.com", "www.example.com"],
                "fingerprint": "ABCDEF",
                "not_after": 1234567890,
                "not_before": 1234560000,
                "serial_number": "01A2B3C4",
                "subject": {
                    "c": "US",
                    "cn": "example.com",
                    "l": "Somewhere",
                    "o": "Example Org",
                    "ou": null,
                    "st": "CA",
                    "aggregated": null,
                    "emailAddress": "admin@example.com"
                },
                "extensions": {
                    "authorityInfoAccess": null,
                    "authorityKeyIdentifier": null,
                    "basicConstraints": null,
                    "certificatePolicies": null,
                    "ctlSignedCertificateTimestamp": null,
                    "extendedKeyUsage": null,
                    "keyUsage": null,
                    "subjectAltName": null,
                    "subjectKeyIdentifier": null
                },
                "signature_algorithm": "sha256RSA"
            }
        },
        "message_type": "certificate_update"
    }"#;
    use certhoover::reformat_cert_fields;
    use publicsuffix::List;
    let rec: TransparencyRecord = serde_json::from_str(json).unwrap();
    assert_eq!(rec.message_type, "certificate_update");
    let data = rec.data.expect("data should be Some");
    let list = List::default();
    let row = reformat_cert_fields(&data, &list);
    assert_eq!(row.cert_index, 123);
    assert_eq!(row.domain, "example.com");
    assert_eq!(row.email_address, "admin@example.com");
    assert_eq!(row.fingerprint, "ABCDEF");
    assert_eq!(row.signature_algorithm, "sha256RSA");
}

#[test]
fn test_transparency_record_invalid_json() {
    let bad_json = "{ this is not valid json }";
    let result: Result<certhoover::TransparencyRecord, _> = serde_json::from_str(bad_json);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_batch_records_max_batch_age() {
    let (ws_sender, ws_receiver) = tokio::sync::mpsc::channel(10);
    let (batch_sender, mut batch_receiver) = tokio::sync::mpsc::channel(10);
    // batch_size large enough that only the age timer can flush
    tokio::spawn(batch_records(
        ws_receiver,
        batch_sender,
        10,
        Duration::from_millis(50),
    ));
    let msg = serde_json::to_string(&certhoover::TransparencyRecord {
        data: None,
        message_type: "timeout_test".to_string(),
    })
    .unwrap();
    ws_sender.send(msg).await.unwrap();
    let batch = tokio::time::timeout(Duration::from_secs(2), batch_receiver.recv())
        .await
        .expect("Batch not received in time")
        .expect("Channel closed");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].message_type, "timeout_test");
}

#[tokio::test]
async fn test_batch_records_flushes_on_channel_close() {
    let (ws_sender, ws_receiver) = tokio::sync::mpsc::channel(10);
    let (batch_sender, mut batch_receiver) = tokio::sync::mpsc::channel(10);
    tokio::spawn(batch_records(
        ws_receiver,
        batch_sender,
        10,
        Duration::from_secs(60),
    ));
    let msg = serde_json::to_string(&certhoover::TransparencyRecord {
        data: None,
        message_type: "final_msg".to_string(),
    })
    .unwrap();
    ws_sender.send(msg).await.unwrap();
    drop(ws_sender); // close input: pending buffer must still be flushed
    let batch = tokio::time::timeout(Duration::from_secs(2), batch_receiver.recv())
        .await
        .expect("Batch not received in time")
        .expect("Channel closed");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].message_type, "final_msg");
}

#[test]
fn test_transparency_recorddata_serde_roundtrip() {
    let original = certhoover::TransparencyRecordData {
        cert_index: 42,
        cert_link: "https://crt.sh/?id=42".to_string(),
        leaf_cert: certhoover::LeafCert {
            all_domains: vec!["foo.com".to_string()],
            fingerprint: "FINGERPRINT".to_string(),
            not_after: 1234,
            not_before: 5678,
            serial_number: "SN".to_string(),
            subject: certhoover::Subject {
                c: Some("DE".to_string()),
                cn: Some("foo.com".to_string()),
                l: None,
                o: None,
                ou: None,
                st: None,
                aggregated: None,
                email_address: Some("admin@foo.com".to_string()),
            },
            extensions: certhoover::Extensions {
                authority_info_access: None,
                authority_key_identifier: None,
                basic_constraints: None,
                certificate_policies: None,
                ctl_signed_certificate_timestamp: None,
                extended_key_usage: None,
                key_usage: None,
                subject_alt_name: None,
                subject_key_identifier: None,
            },
            signature_algorithm: Some("sha256RSA".to_string()),
        },
    };
    let json = serde_json::to_string(&original).unwrap();
    let parsed: certhoover::TransparencyRecordData = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.cert_index, original.cert_index);
    assert_eq!(parsed.leaf_cert.all_domains, original.leaf_cert.all_domains);
    assert_eq!(
        parsed.leaf_cert.subject.email_address,
        original.leaf_cert.subject.email_address
    );
}
#[tokio::test]
async fn test_batch_records_batches_correctly() {
    let (ws_sender, ws_receiver) = tokio::sync::mpsc::channel(10);
    let (batch_sender, mut batch_receiver) = tokio::sync::mpsc::channel(10);
    tokio::spawn(batch_records(
        ws_receiver,
        batch_sender,
        2,
        Duration::from_secs(60),
    ));
    let msg1 = serde_json::to_string(&TransparencyRecord {
        data: None,
        message_type: "test1".to_string(),
    })
    .unwrap();
    let msg2 = serde_json::to_string(&TransparencyRecord {
        data: None,
        message_type: "test2".to_string(),
    })
    .unwrap();
    ws_sender.send(msg1).await.unwrap();
    ws_sender.send(msg2).await.unwrap();
    let batch = tokio::time::timeout(Duration::from_secs(2), batch_receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].message_type, "test1");
    assert_eq!(batch[1].message_type, "test2");
}
