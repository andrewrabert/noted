use std::path::Path;

use noted_cli::config::{EnvFile, Environment, credential_store_config};
use noted_client::credentials::SecretStorage;

#[test]
fn the_env_file_flag_is_found_before_the_subcommand() {
    let found = noted_cli::env_file_arg(["noted", "--env-file", "/etc/x.env", "read", "a.md"]);
    assert_eq!(found.as_deref(), Some(Path::new("/etc/x.env")));
}

#[test]
fn the_env_file_flag_is_found_after_the_subcommand() {
    let found = noted_cli::env_file_arg(["noted", "read", "a.md", "--env-file", "/etc/x.env"]);
    assert_eq!(found.as_deref(), Some(Path::new("/etc/x.env")));
}

#[test]
fn an_argv_the_real_parse_rejects_still_yields_the_env_file() {
    let found = noted_cli::env_file_arg([
        "noted",
        "--env-file",
        "/etc/x.env",
        "read",
        "--no-such-flag",
    ]);
    assert_eq!(found.as_deref(), Some(Path::new("/etc/x.env")));
}

#[test]
fn a_help_request_yields_no_env_file() {
    assert_eq!(noted_cli::env_file_arg(["noted", "--help"]), None);
}

#[test]
fn an_explicit_hosts_file_forces_plaintext_storage() {
    let cfg = credential_store_config(
        Some(Path::new("/tmp/hosts.json")),
        Some(Path::new("/home/u/.config")),
    )
    .unwrap();
    assert_eq!(cfg.hosts_path, Path::new("/tmp/hosts.json"));
    assert!(matches!(cfg.storage, SecretStorage::Plaintext));
}

#[test]
fn an_empty_hosts_file_falls_back_to_the_config_dir() {
    let cfg =
        credential_store_config(Some(Path::new("")), Some(Path::new("/home/u/.config"))).unwrap();
    assert_eq!(
        cfg.hosts_path,
        Path::new("/home/u/.config/noted/hosts.json")
    );
    assert!(matches!(cfg.storage, SecretStorage::Auto));
}

#[test]
fn a_hosts_file_with_no_config_dir_and_no_override_is_rejected() {
    assert!(credential_store_config(None, None).is_err());
}

#[test]
fn an_explicit_env_file_overrides_the_config_dir_default() {
    let file = EnvFile::resolve(
        Some(Path::new("/etc/noted.env")),
        None,
        Some(Path::new("/home/u/.config")),
    )
    .unwrap();
    assert_eq!(file.path(), Path::new("/etc/noted.env"));
}

#[test]
fn an_empty_env_file_var_falls_back_to_the_config_dir() {
    let file = EnvFile::resolve(
        Some(Path::new("")),
        None,
        Some(Path::new("/home/u/.config")),
    )
    .unwrap();
    assert_eq!(file.path(), Path::new("/home/u/.config/noted.env"));
}

#[test]
fn no_config_dir_and_no_override_means_no_env_file() {
    assert!(EnvFile::resolve(None, None, None).is_none());
}

#[test]
fn a_notedenv_in_the_start_dir_is_discovered() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=repo\n").unwrap();
    let file =
        EnvFile::resolve(None, Some(root.path()), Some(Path::new("/home/u/.config"))).unwrap();
    assert_eq!(file.path(), root.path().join(".notedenv"));
}

#[test]
fn a_notedenv_above_the_start_dir_is_discovered() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=repo\n").unwrap();
    let nested = root.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let file = EnvFile::resolve(None, Some(&nested), None).unwrap();
    assert_eq!(file.path(), root.path().join(".notedenv"));
}

#[test]
fn the_nearest_notedenv_wins() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=outer\n").unwrap();
    let nested = root.path().join("inner");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join(".notedenv"), "NOTED_SOURCE=inner\n").unwrap();
    let file = EnvFile::resolve(None, Some(&nested), None).unwrap();
    assert_eq!(file.path(), nested.join(".notedenv"));
}

#[test]
fn an_explicit_env_file_suppresses_discovery() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=repo\n").unwrap();
    let file =
        EnvFile::resolve(Some(Path::new("/etc/noted.env")), Some(root.path()), None).unwrap();
    assert_eq!(file.path(), Path::new("/etc/noted.env"));
}

#[test]
fn no_notedenv_falls_back_to_the_config_dir() {
    let root = tempfile::tempdir().unwrap();
    let file =
        EnvFile::resolve(None, Some(root.path()), Some(Path::new("/home/u/.config"))).unwrap();
    assert_eq!(file.path(), Path::new("/home/u/.config/noted.env"));
}

#[test]
fn a_malformed_env_file_is_rejected() {
    let file = EnvFile::resolve(Some(Path::new("/etc/noted.env")), None, None).unwrap();
    let err = file
        .parse("ALPHA=/notes\nthis is not a binding\n")
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("/etc/noted.env"), "{message}");
    assert!(message.contains("this is not a binding"), "{message}");
}

#[test]
fn an_env_file_yields_its_bindings_in_file_order() {
    let file = EnvFile::resolve(Some(Path::new("/etc/noted.env")), None, None).unwrap();
    let bindings = file
        .parse("# a comment\nALPHA=/notes\n\nBETA=cli\n")
        .unwrap();
    assert_eq!(
        bindings,
        vec![
            ("ALPHA".to_string(), "/notes".to_string()),
            ("BETA".to_string(), "cli".to_string()),
        ]
    );
}

#[test]
fn visual_is_preferred_over_editor_and_empties_are_dropped() {
    let preference = Environment {
        visual: Some("vim".into()),
        editor: Some("nano".into()),
        ..Environment::default()
    }
    .editor_preference();
    assert_eq!(
        preference.commands(),
        ["vim".to_string(), "nano".to_string()]
    );

    let preference = Environment {
        visual: Some(String::new()),
        editor: Some("nano".into()),
        ..Environment::default()
    }
    .editor_preference();
    assert_eq!(preference.commands(), ["nano".to_string()]);
}
