use certhoover::{batch_records, TransparencyRecord};
use std::sync::mpsc;
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

#[test]
fn test_batch_records_multiple_batches() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    let (ws_sender, ws_receiver) = mpsc::channel();
    let (batch_sender, batch_receiver) = mpsc::channel();
    let batch_size = 2;
    let max_batch_age = Duration::from_secs(60);
    thread::spawn(move || {
        certhoover::batch_records(ws_receiver, batch_sender, batch_size, max_batch_age);
    });
    for i in 0..4 {
        let msg = serde_json::to_string(&certhoover::TransparencyRecord {
            data: None,
            message_type: format!("test{}", i),
        })
        .unwrap();
        ws_sender.send(msg).unwrap();
    }
    let batch1 = batch_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    let batch2 = batch_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
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

#[test]
fn test_batch_records_empty_input() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    let (_ws_sender, ws_receiver) = mpsc::channel::<String>();
    let (batch_sender, batch_receiver) = mpsc::channel();
    let batch_size = 2;
    let max_batch_age = Duration::from_millis(100);
    thread::spawn(move || {
        certhoover::batch_records(ws_receiver, batch_sender, batch_size, max_batch_age);
    });
    // No messages sent
    let result = batch_receiver.recv_timeout(Duration::from_millis(200));
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
    let rec: TransparencyRecord = serde_json::from_str(json).unwrap();
    assert_eq!(rec.message_type, "certificate_update");
    let data = rec.data.expect("data should be Some");
    assert_eq!(data.cert_index, 123);
    assert_eq!(data.leaf_cert.all_domains[0], "example.com");
    assert_eq!(
        data.leaf_cert.subject.email_address.as_deref(),
        Some("admin@example.com")
    );
}

#[test]
fn test_transparency_record_invalid_json() {
    let bad_json = "{ this is not valid json }";
    let result: Result<certhoover::TransparencyRecord, _> = serde_json::from_str(bad_json);
    assert!(result.is_err());
}

#[test]
fn test_batch_records_max_batch_age() {
    use std::thread;
    use std::time::Duration;
    let (ws_sender, ws_receiver) = std::sync::mpsc::channel();
    let (batch_sender, batch_receiver) = std::sync::mpsc::channel();
    let batch_size = 10; // Large, so we hit timeout first
    let max_batch_age = Duration::from_millis(50);
    thread::spawn(move || {
        certhoover::batch_records(ws_receiver, batch_sender, batch_size, max_batch_age);
    });
    // Give the batch_records thread a moment to start
    thread::sleep(Duration::from_millis(10));
    let msg = serde_json::to_string(&certhoover::TransparencyRecord {
        data: None,
        message_type: "timeout_test".to_string(),
    })
    .unwrap();
    ws_sender.send(msg).unwrap();
    let batch = batch_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("Batch not received in time");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].message_type, "timeout_test");
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
#[test]
fn test_batch_records_batches_correctly() {
    let (ws_sender, ws_receiver) = mpsc::channel();
    let (batch_sender, batch_receiver) = mpsc::channel();
    let batch_size = 2;
    let max_batch_age = Duration::from_secs(60);
    std::thread::spawn(move || {
        batch_records(ws_receiver, batch_sender, batch_size, max_batch_age);
    });
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
    ws_sender.send(msg1).unwrap();
    ws_sender.send(msg2).unwrap();
    let batch = batch_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].message_type, "test1");
    assert_eq!(batch[1].message_type, "test2");
}
