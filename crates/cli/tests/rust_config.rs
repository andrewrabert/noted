use std::path::Path;

use noted_cli::config::{EnvFile, credential_store_config};
use noted_cli::settings::Variable;
use noted_client::credentials::SecretStorage;

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

fn paths(files: &[EnvFile]) -> Vec<&Path> {
    files.iter().map(EnvFile::path).collect()
}

#[test]
fn an_explicit_env_file_layers_over_the_global() {
    let files = EnvFile::stack(
        Some(Path::new("/etc/noted.env")),
        None,
        Some(Path::new("/home/u/.config")),
    );
    assert_eq!(
        paths(&files),
        [
            Path::new("/etc/noted.env"),
            Path::new("/home/u/.config/noted.env")
        ]
    );
}

#[test]
fn an_empty_env_file_var_is_unset() {
    let files = EnvFile::stack(
        Some(Path::new("")),
        None,
        Some(Path::new("/home/u/.config")),
    );
    assert_eq!(paths(&files), [Path::new("/home/u/.config/noted.env")]);
}

#[test]
fn no_config_dir_and_no_override_means_no_env_file() {
    assert!(EnvFile::stack(None, None, None).is_empty());
}

#[test]
fn a_notedenv_in_the_start_dir_layers_over_the_global() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=repo\n").unwrap();
    let files = EnvFile::stack(None, Some(root.path()), Some(Path::new("/home/u/.config")));
    assert_eq!(
        paths(&files),
        [
            root.path().join(".notedenv").as_path(),
            Path::new("/home/u/.config/noted.env")
        ]
    );
}

#[test]
fn a_notedenv_above_the_start_dir_is_discovered() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=repo\n").unwrap();
    let nested = root.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let files = EnvFile::stack(None, Some(&nested), None);
    assert_eq!(paths(&files), [root.path().join(".notedenv").as_path()]);
}

#[test]
fn the_nearest_notedenv_wins() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=outer\n").unwrap();
    let nested = root.path().join("inner");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join(".notedenv"), "NOTED_SOURCE=inner\n").unwrap();
    let files = EnvFile::stack(None, Some(&nested), None);
    assert_eq!(paths(&files), [nested.join(".notedenv").as_path()]);
}

#[test]
fn an_explicit_env_file_suppresses_discovery() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".notedenv"), "NOTED_SOURCE=repo\n").unwrap();
    let files = EnvFile::stack(Some(Path::new("/etc/noted.env")), Some(root.path()), None);
    assert_eq!(paths(&files), [Path::new("/etc/noted.env")]);
}

#[test]
fn no_notedenv_leaves_the_global_alone() {
    let root = tempfile::tempdir().unwrap();
    let files = EnvFile::stack(None, Some(root.path()), Some(Path::new("/home/u/.config")));
    assert_eq!(paths(&files), [Path::new("/home/u/.config/noted.env")]);
}

#[test]
fn a_near_file_that_is_the_global_appears_once() {
    let files = EnvFile::stack(
        Some(Path::new("/home/u/.config/noted.env")),
        None,
        Some(Path::new("/home/u/.config")),
    );
    assert_eq!(paths(&files), [Path::new("/home/u/.config/noted.env")]);
}

#[test]
fn an_absent_env_file_yields_an_empty_layer() {
    let root = tempfile::tempdir().unwrap();
    let file = EnvFile::stack(Some(&root.path().join("nothing.env")), None, None).remove(0);
    let layer = file.layer().unwrap();
    assert!(layer.get(Variable::Source).is_none());
}

#[test]
fn an_env_file_yields_its_bindings_as_a_layer() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("noted.env");
    std::fs::write(&path, "# a comment\nNOTED_SOURCE=repo\n\nALPHA=/notes\n").unwrap();
    let file = EnvFile::stack(Some(&path), None, None).remove(0);
    let layer = file.layer().unwrap();
    assert_eq!(layer.get(Variable::Source), Some("repo"));
    assert_eq!(layer.origin().to_string(), path.display().to_string());
}

#[test]
fn a_malformed_env_file_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("noted.env");
    std::fs::write(&path, "NOTED_DIR=/notes\nthis is not a binding\n").unwrap();
    let file = EnvFile::stack(Some(&path), None, None).remove(0);
    let message = file.layer().unwrap_err().to_string();
    assert!(message.contains(&path.display().to_string()), "{message}");
    assert!(message.contains("this is not a binding"), "{message}");
}
