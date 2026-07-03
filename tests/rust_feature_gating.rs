use std::process::{Command, Output};

fn probe(features: &[&str]) -> Output {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let tmp = tempfile::tempdir().unwrap();

    let dep = if features.is_empty() {
        format!("noted = {{ path = {manifest:?} }}")
    } else {
        let feats = features
            .iter()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("noted = {{ path = {manifest:?}, features = [{feats}] }}")
    };
    // The empty `[workspace]` keeps this probe out of any surrounding workspace,
    // so its feature selection is exactly what we ask for.
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{dep}\n\n[workspace]\n"
        ),
    )
    .unwrap();
    std::fs::create_dir(tmp.path().join("src")).unwrap();
    std::fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() {\n    \
         let _ = noted::credentials::CredentialStore::open_plaintext_at(\
         std::path::PathBuf::from(\"x\"));\n}\n",
    )
    .unwrap();

    Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--manifest-path"])
        .arg(tmp.path().join("Cargo.toml"))
        .env(
            "CARGO_TARGET_DIR",
            format!("{manifest}/target/feature_gating_probe"),
        )
        .output()
        .expect("run cargo build for the probe crate")
}

#[test]
fn test_util_seam_is_gated_behind_the_feature() {
    let without = probe(&[]);
    assert!(
        !without.status.success(),
        "a default-feature consumer must NOT be able to call `open_plaintext_at`\n{}",
        String::from_utf8_lossy(&without.stderr)
    );

    let with = probe(&["test-util"]);
    assert!(
        with.status.success(),
        "a `test-util` consumer must be able to call `open_plaintext_at`\n{}",
        String::from_utf8_lossy(&with.stderr)
    );
}
