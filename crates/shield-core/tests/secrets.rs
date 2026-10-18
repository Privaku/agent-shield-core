use shield_core::secrets::{detect, redact, shannon_entropy, SecretKind};

/// PEM armour built from parts so the tree does not store a key header verbatim.
fn pem(kind: &str) -> String {
    format!("-----BEGIN {kind}-----")
}

fn assert_detector(kind: SecretKind, positives: &[String], negatives: &[String]) {
    assert!(positives.len() >= 3);
    assert!(negatives.len() >= 3);
    for value in positives {
        assert!(
            detect(value).iter().any(|found| found.kind == kind),
            "{kind} missed synthetic value {value:?}"
        );
    }
    for value in negatives {
        assert!(
            detect(value).iter().all(|found| found.kind != kind),
            "{kind} incorrectly matched {value:?}"
        );
    }
}

#[test]
fn detects_aws_access_key_ids() {
    assert_detector(
        SecretKind::AwsAccessKeyId,
        &[
            "AKIAIOSFODNN7EXAMPLE".into(),
            "ASIAIOSFODNN7EXAMPLE".into(),
            "AKIA1234567890ABCDEF".into(),
        ],
        &[
            "akiaiosfodnn7example".into(),
            "AKIA1234567890ABCDE".into(),
            "ABCDIOSFODNN7EXAMPLE".into(),
        ],
    );
}

#[test]
fn detects_private_key_pem_headers() {
    assert_detector(
        SecretKind::PemPrivateKey,
        &[
            pem("PRIVATE KEY"),
            pem("RSA PRIVATE KEY"),
            pem("OPENSSH PRIVATE KEY"),
        ],
        &[
            pem("PUBLIC KEY"),
            pem("CERTIFICATE"),
            format!("-----BEGIN {}----", "PRIVATE KEY"),
        ],
    );
}

#[test]
fn detects_github_tokens() {
    assert_detector(
        SecretKind::GitHubToken,
        &[
            format!("ghp_{}", "A1b2".repeat(9)),
            format!("gho_{}", "C3d4".repeat(9)),
            format!("github_pat_{}", "Ab1_".repeat(9)),
        ],
        &[
            format!("ghp_{}", "a".repeat(35)),
            format!("gitlab_{}", "a".repeat(40)),
            "github_pat_short".into(),
        ],
    );
}

#[test]
fn detects_sk_style_api_keys() {
    assert_detector(
        SecretKind::SkApiKey,
        &[
            format!("sk-{}", "Ab1_".repeat(7)),
            format!("sk-proj-{}", "Cd2_".repeat(7)),
            format!("sk-ant-api03-{}", "Ef3_".repeat(7)),
        ],
        &[
            "pk-example_not_a_secret_key".into(),
            "sk-too-short".into(),
            format!("SK-{}", "a".repeat(24)),
        ],
    );
}

#[test]
fn detects_slack_tokens() {
    assert_detector(
        SecretKind::SlackToken,
        &[
            "xoxb-1234567890-ABCDEFGHIJ".into(),
            "xoxp-ABCDEFGHIJKL-1234567890".into(),
            "xoxa-12345ABCDE-67890FGHIJ".into(),
        ],
        &[
            "xoxz-1234567890-ABCDEFGHIJ".into(),
            "xoxb-short".into(),
            "xoxb_1234567890_ABCDEFGHIJ".into(),
        ],
    );
}

#[test]
fn detects_stripe_live_keys() {
    assert_detector(
        SecretKind::StripeLiveKey,
        &[
            format!("sk_live_{}", "Ab1".repeat(8)),
            format!("sk_live_{}", "Cd2".repeat(8)),
            format!("sk_live_{}", "Ef3".repeat(8)),
        ],
        &[
            format!("pk_live_{}", "a".repeat(24)),
            format!("sk_test_{}", "a".repeat(24)),
            "sk_live_short".into(),
        ],
    );
}

#[test]
fn detects_google_api_keys() {
    assert_detector(
        SecretKind::GoogleApiKey,
        &[
            format!("AIza{}", "Ab1_2".repeat(7)),
            format!("AIza{}", "Cd3-4".repeat(7)),
            format!("AIza{}", "Ef5_6".repeat(7)),
        ],
        &[
            format!("AIza{}", "a".repeat(34)),
            format!("AIza{}", "a".repeat(36)),
            format!("BIza{}", "a".repeat(35)),
        ],
    );
}

#[test]
fn detects_json_web_tokens() {
    assert_detector(
        SecretKind::Jwt,
        &[
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOP".into(),
            "eyJ0eXAiOiJKV1QifQ.eyJpc3MiOiJleGFtcGxlIn0.QRSTUVWXYZabcdef".into(),
            "eyJraWQiOiIxMjM0NSJ9.eyJhdWQiOiJsb2NhbCJ9.ghijklmnopqrstuv".into(),
        ],
        &[
            "not.a.jwt".into(),
            "eyJsho.eyJsho.sig".into(),
            "abc.def.ghi0123456789".into(),
        ],
    );
}

#[test]
fn detects_generic_high_entropy_tokens() {
    let positives = [
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_string(),
        "abcdefghijklmnopqrstuvwxyz0123456789_-ABCD".to_string(),
        "MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNU".to_string(),
    ];
    for value in &positives {
        assert!(shannon_entropy(value) >= 4.0, "{value}");
    }
    assert_detector(
        SecretKind::HighEntropyToken,
        &positives,
        &[
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "abcabcabcabcabcabcabcabcabcabcabcabc".into(),
            "0123456789ABCDEFGHIJKLMNOPQRSTU".into(),
        ],
    );
}

#[test]
fn redacts_multiple_kinds_without_changing_safe_text() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let pem = pem("PRIVATE KEY");
    let text = format!("before {aws} middle {pem} after");
    let redacted = redact(&text);

    assert_eq!(
        redacted,
        "before [REDACTED:aws_access_key_id] middle [REDACTED:pem_private_key] after"
    );
    assert!(!redacted.contains(aws));
    assert!(!redacted.contains(&pem));
    assert_eq!(redact("ordinary source text"), "ordinary source text");
}

#[test]
fn does_not_redact_file_paths_or_dmg_names() {
    let dmg = "file_read ~/Downloads/Agent-Shield-0.1.0-rc.1-unsigned.dmg";
    assert_eq!(redact(dmg), dmg);
    let uuid_path = "/Users/x/bc-85bcc50c-970d-58a1-8fea-d1f081d4dc41/file.dmg";
    assert_eq!(redact(uuid_path), uuid_path);
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let mixed = format!("curl {aws} > ~/Downloads/Agent-Shield-0.1.0-rc.1-unsigned.dmg");
    let redacted = redact(&mixed);
    assert!(
        redacted.contains("[REDACTED:aws_access_key_id]"),
        "{redacted}"
    );
    assert!(
        redacted.contains("Agent-Shield-0.1.0-rc.1-unsigned.dmg"),
        "{redacted}"
    );
}

#[test]
fn shaped_detector_wins_over_generic_entropy() {
    let google = format!("AIza{}", "Ab1_2".repeat(7));
    let matches = detect(&google);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].kind, SecretKind::GoogleApiKey);
}
