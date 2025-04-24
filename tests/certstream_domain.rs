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
    let domain = data
        .leaf_cert
        .all_domains
        .first()
        .cloned()
        .or_else(|| data.leaf_cert.subject.cn.clone())
        .unwrap_or_default();
    assert_eq!(domain, "foo.example.com");

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
    let domain = data
        .leaf_cert
        .all_domains
        .first()
        .cloned()
        .or_else(|| data.leaf_cert.subject.cn.clone())
        .unwrap_or_default();
    assert_eq!(domain, "baz.example.com");
}
