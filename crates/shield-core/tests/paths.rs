use std::fs;

use shield_core::paths::{PathContext, PathMatcher, SensitivePathCatalog};
use tempfile::tempdir;

#[test]
fn expands_home_spellings_and_resolves_dot_segments() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let cwd = temp.path().join("work/project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    let context = PathContext::new(&home, &cwd);

    let expected_key = fs::canonicalize(&home)
        .unwrap_or(home.clone())
        .join(".ssh/id_rsa");
    for input in [
        "~/.ssh/../.ssh/id_rsa",
        "$HOME/.ssh/id_rsa",
        "${HOME}/.ssh/id_rsa",
    ] {
        assert_eq!(context.normalize(input).unwrap(), expected_key);
    }
    assert_eq!(
        context.normalize("../shared/./file").unwrap(),
        fs::canonicalize(temp.path())
            .unwrap_or_else(|_| temp.path().to_path_buf())
            .join("work/shared/file")
    );
}

#[test]
fn expands_injected_named_user_home() {
    let temp = tempdir().unwrap();
    let alice = temp.path().join("users/alice");
    fs::create_dir_all(&alice).unwrap();
    let context =
        PathContext::new(temp.path().join("home"), temp.path()).with_user_home("alice", &alice);
    assert_eq!(
        context.normalize("~alice/.ssh/id_ed25519").unwrap(),
        fs::canonicalize(&alice)
            .unwrap_or(alice.clone())
            .join(".ssh/id_ed25519")
    );
}

#[test]
fn glob_matching_honours_exclusions() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    let context = PathContext::new(&home, temp.path());
    let matcher = PathMatcher::new(
        &context,
        ["~/.ssh/id_*", "~/.ssh/*.pem"],
        ["~/.ssh/*.pub"],
        false,
    )
    .unwrap();

    assert!(matcher.is_match(&context, "~/.ssh/../.ssh/id_rsa").unwrap());
    assert!(!matcher.is_match(&context, "~/.ssh/id_rsa.pub").unwrap());
}

#[test]
fn glob_matches_tilde_ssh_key_when_home_directory_does_not_exist_yet() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("missing-home");
    let context = PathContext::new(&home, temp.path());
    let matcher =
        PathMatcher::new(&context, ["~/.ssh/id_*"], std::iter::empty::<&str>(), false).unwrap();
    assert!(
        matcher.is_match(&context, "~/.ssh/id_rsa").unwrap(),
        "HOME {} should still match ~/.ssh/id_rsa before the directory exists",
        home.display()
    );
}

#[cfg(unix)]
#[test]
fn glob_matches_when_home_path_goes_through_a_symlink() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let real_home = temp.path().join("real-home");
    fs::create_dir_all(real_home.join(".ssh")).unwrap();
    fs::write(real_home.join(".ssh/id_rsa"), "synthetic key").unwrap();
    let alias_home = temp.path().join("alias-home");
    symlink(&real_home, &alias_home).unwrap();

    let context = PathContext::new(&alias_home, temp.path());
    let matcher =
        PathMatcher::new(&context, ["~/.ssh/id_*"], std::iter::empty::<&str>(), false).unwrap();
    assert!(
        matcher.is_match(&context, "~/.ssh/id_rsa").unwrap(),
        "lexical HOME {} vs canonical {}",
        alias_home.display(),
        std::fs::canonicalize(&alias_home).unwrap().display()
    );
}

#[cfg(unix)]
#[test]
fn existing_symlink_is_canonicalized_before_matching() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let ssh = home.join(".ssh");
    let work = temp.path().join("work");
    fs::create_dir_all(&ssh).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::write(ssh.join("id_rsa"), "synthetic key").unwrap();
    symlink(&ssh, work.join("keys")).unwrap();

    let context = PathContext::new(&home, &work);
    let matcher =
        PathMatcher::new(&context, ["~/.ssh/id_*"], std::iter::empty::<&str>(), false).unwrap();
    assert!(matcher.is_match(&context, "keys/id_rsa").unwrap());
}

#[test]
fn optional_case_insensitive_matching_models_macos() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("Users/example");
    let context = PathContext::new(&home, temp.path());
    let sensitive = "~/.ssh/id_*";

    let exact = PathMatcher::new(&context, [sensitive], std::iter::empty::<&str>(), false).unwrap();
    let insensitive =
        PathMatcher::new(&context, [sensitive], std::iter::empty::<&str>(), true).unwrap();

    assert!(!exact.is_match(&context, "~/.SSH/ID_RSA").unwrap());
    assert!(insensitive.is_match(&context, "~/.SSH/ID_RSA").unwrap());
}

#[test]
fn embedded_catalog_covers_secret_families_and_dotenv_exceptions() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let work = temp.path().join("project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&work).unwrap();
    let context = PathContext::new(&home, &work);
    let catalog = SensitivePathCatalog::embedded()
        .unwrap()
        .compile(&context, false)
        .unwrap();

    let cases = [
        ("$HOME/.ssh/id_ed25519", "secrets.ssh_private_key"),
        ("~/.aws/credentials", "secrets.cloud_credentials"),
        ("~/.config/gh/hosts.yml", "secrets.package_tokens"),
        (
            "~/Library/Application Support/Google/Chrome/Default/Login Data",
            "secrets.browser_data",
        ),
        (
            "~/Library/LaunchAgents/com.example.plist",
            "persist.autostart",
        ),
        (
            "/Library/LaunchServices/com.example.helper",
            "persist.autostart",
        ),
        ("~/.config/privaku/agent-shield/policy.yaml", "self.tamper"),
        (
            "~/Library/Logs/Privaku/agent-shield/audit.jsonl",
            "self.tamper",
        ),
        ("~/.cursor/hooks.json", "self.tamper"),
        ("~/.privaku/shims/curl", "self.tamper"),
        (".agent-shield.yaml", "self.tamper"),
        (".env.production", "secrets.dotenv"),
    ];
    for (path, expected) in cases {
        let matches = catalog.matching(&context, path).unwrap();
        assert!(
            matches.iter().any(|family| family.id == expected),
            "{path} did not match {expected}"
        );
    }

    for public in [".env.example", ".env.sample", ".env.template"] {
        assert!(!catalog.is_sensitive(&context, public).unwrap(), "{public}");
    }
    for public in ["~/.ssh/id_rsa.pub", "~/.ssh/known_hosts", "~/.ssh/config"] {
        assert!(!catalog.is_sensitive(&context, public).unwrap(), "{public}");
    }
}

#[cfg(unix)]
#[test]
fn embedded_catalog_matches_symlink_into_ssh_directory() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let ssh = home.join(".ssh");
    let work = temp.path().join("work");
    fs::create_dir_all(&ssh).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::write(ssh.join("id_ed25519"), "synthetic key").unwrap();
    symlink(&ssh, work.join("linked-keys")).unwrap();

    let context = PathContext::new(&home, &work);
    let catalog = SensitivePathCatalog::embedded()
        .unwrap()
        .compile(&context, false)
        .unwrap();
    assert!(catalog
        .matching(&context, "linked-keys/id_ed25519")
        .unwrap()
        .iter()
        .any(|family| family.id == "secrets.ssh_private_key"));
}
