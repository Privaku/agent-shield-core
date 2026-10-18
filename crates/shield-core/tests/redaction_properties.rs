use proptest::prelude::*;
use shield_core::secrets::redact;

fn secret_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Z0-9]{16}".prop_map(|tail| format!("AKIA{tail}")),
        "[A-Za-z0-9]{36}".prop_map(|tail| format!("ghp_{tail}")),
        "[A-Za-z0-9_-]{24,48}".prop_map(|tail| format!("sk-{tail}")),
        "[A-Za-z0-9-]{16,40}".prop_map(|tail| format!("xoxb-{tail}")),
        "[A-Za-z0-9]{20,40}".prop_map(|tail| format!("sk_live_{tail}")),
        "[A-Za-z0-9_-]{35}".prop_map(|tail| format!("AIza{tail}")),
        (
            "[A-Za-z0-9_-]{8,20}",
            "[A-Za-z0-9_-]{8,20}",
            "[A-Za-z0-9_-]{8,24}"
        )
            .prop_map(|(header, payload, signature)| {
                format!("eyJ{header}.eyJ{payload}.{signature}")
            }),
        Just(format!("-----BEGIN {}-----", "PRIVATE KEY")),
        Just(format!("-----BEGIN {}-----", "OPENSSH PRIVATE KEY")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn redaction_never_leaks_generated_secret(
        secret in secret_strategy(),
        prefix in "[a-z .,]{0,40}",
        suffix in "[a-z .,]{0,40}",
    ) {
        let input = format!("{prefix} {secret} {suffix}");
        let redacted = redact(&input);
        prop_assert!(
            !redacted.contains(&secret),
            "secret remained after redaction: {redacted:?}"
        );
        prop_assert!(redacted.contains("[REDACTED:"));
    }

    #[test]
    fn redaction_removes_every_repeated_occurrence(secret in secret_strategy()) {
        let input = format!("{secret}:{secret}:{secret}");
        let redacted = redact(&input);
        prop_assert!(!redacted.contains(&secret));
        prop_assert_eq!(redacted.matches("[REDACTED:").count(), 3);
    }
}
