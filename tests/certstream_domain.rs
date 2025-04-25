use certhoover::{reformat_cert_fields, TransparencyRecordData};
use publicsuffix::List;

#[test]
fn test_domain_extraction_from_all_domains_and_cn() {
    // Case 1: all_domains present

    let json = r#"{
        "data": {
            "cert_index": 1,
            "cert_link": "https://example.com",
            "leaf_cert": {
                "all_domains": ["foo.example.com", "bar.example.com"],
                "fingerprint": "abc",
                "not_after": 0,
                "not_before": 0,
                "serial_number": "123",
                "subject": {
                    "c": null, "cn": null, "l": null, "o": null, "ou": null, "st": null, "aggregated": null, "emailAddress": null
                },
                "extensions": {
                    "authorityInfoAccess": null, "authorityKeyIdentifier": null, "basicConstraints": null, "certificatePolicies": null, "ctlSignedCertificateTimestamp": null, "extendedKeyUsage": null, "keyUsage": null, "subjectAltName": null, "subjectKeyIdentifier": null
                },
                "signature_algorithm": null
            }
        },
        "message_type": "certificate_update"
    }"#;

    let rec: certhoover::TransparencyRecord = serde_json::from_str(json).unwrap();
    let data = rec.data.unwrap();
    let list = List::default();
    let row = reformat_cert_fields(&data, &list);
    assert_eq!(row.domain, "foo.example.com");

    // Case 2: all_domains empty, cn present
    let json = r#"{
        "data": {
            "cert_index": 2,
            "cert_link": "https://example.com",
            "leaf_cert": {
                "all_domains": [],
                "fingerprint": "abc",
                "not_after": 0,
                "not_before": 0,
                "serial_number": "123",
                "subject": {
                    "c": null, "cn": "baz.example.com", "l": null, "o": null, "ou": null, "st": null, "aggregated": null, "emailAddress": null
                },
                "extensions": {
                    "authorityInfoAccess": null, "authorityKeyIdentifier": null, "basicConstraints": null, "certificatePolicies": null, "ctlSignedCertificateTimestamp": null, "extendedKeyUsage": null, "keyUsage": null, "subjectAltName": null, "subjectKeyIdentifier": null
                },
                "signature_algorithm": null
            }
        },
        "message_type": "certificate_update"
    }"#;
    let rec: certhoover::TransparencyRecord = serde_json::from_str(json).unwrap();
    let data = rec.data.unwrap();
    let row = reformat_cert_fields(&data, &list);
    assert_eq!(row.domain, "baz.example.com");
}

#[test]
fn test_reformat_cert_fields_basic() {
    let data = TransparencyRecordData {
        cert_index: 42,
        cert_link: "https://crt.sh/?id=42".to_string(),
        leaf_cert: certhoover::LeafCert {
            all_domains: vec!["foo.com".to_string(), "bar.com".to_string()],
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
            extensions: certhoover::Extensions::default(),
            signature_algorithm: Some("sha256RSA".to_string()),
        },
    };
    let list = List::default();
    let row = reformat_cert_fields(&data, &list);
    assert_eq!(row.domain, "foo.com");
    assert_eq!(row.cert_index, 42);
    assert_eq!(row.fingerprint, "FINGERPRINT");
    assert_eq!(row.email_address, "admin@foo.com");
    assert_eq!(row.signature_algorithm, "sha256RSA");
}
