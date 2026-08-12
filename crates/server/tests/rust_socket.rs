#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};

use noted::authorization::Bearer;
use noted::tools::ReadArgs;
use noted::{Backend, BackendArgs, PolicyFragment, ToolCall};
use noted_server::http::build_app;
use noted_server::socket::{bind_unix_socket, lock_path, staging_dir, staging_socket};

async fn serve(dir: &tempfile::TempDir) -> (PathBuf, String) {
    let svc = common::auth_service(dir);
    let token = common::mint_key(&svc, "test", PolicyFragment::default());
    let sock = dir.path().join("noted.sock");
    let (listener, guard) = bind_unix_socket(&sock, None).unwrap();
    let app = build_app(common::backend(dir), Some(svc), None);
    tokio::spawn(async move {
        let _guard = guard;
        let _ = axum::serve(listener, app).await;
    });
    (sock, token)
}

fn dialing(sock: &Path, token: &str) -> Backend {
    Backend::new(BackendArgs {
        endpoint: Some(format!("unix://{}", sock.display()).parse().unwrap()),
        token: Some(Bearer::new(token)),
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn tools_round_trip_over_a_unix_socket() {
    let dir = common::fixture_dir();
    let (sock, token) = serve(&dir).await;
    let backend = dialing(&sock, &token);
    let call = ToolCall::new(ReadArgs::new(common::rp("Inbox.md"))).unwrap();
    let out = backend
        .with_authority(None)
        .unwrap()
        .invoke(&call)
        .await
        .unwrap();
    assert!(out.render().contains("follow up with Dana"));
}

#[tokio::test]
async fn an_unknown_bearer_is_refused_over_the_socket() {
    let dir = common::fixture_dir();
    let (sock, _token) = serve(&dir).await;
    let backend = dialing(&sock, "not-a-token");
    let call = ToolCall::new(ReadArgs::new(common::rp("Inbox.md"))).unwrap();
    let err = backend
        .with_authority(None)
        .unwrap()
        .invoke(&call)
        .await
        .unwrap_err();
    assert!(err.is_rejection(), "{err}");
}

#[tokio::test]
async fn a_socket_left_by_an_unclean_stop_is_taken_over() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let dead = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    drop(dead);
    std::fs::write(lock_path(&sock), b"").unwrap();

    let (_listener, _guard) = bind_unix_socket(&sock, None).unwrap();
    assert!(sock.exists());
}

#[tokio::test]
async fn a_bind_at_a_live_socket_is_refused_and_the_owner_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let owner = bind_unix_socket(&sock, None).unwrap();

    let err = bind_unix_socket(&sock, None).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert!(err.message().contains("server already running"), "{err}");
    assert!(err.message().contains(&sock.display().to_string()), "{err}");
    assert!(sock.exists());
    assert!(owner.1.lock_path().exists());
    drop(owner);
}

#[tokio::test]
async fn a_bind_leaves_no_staging_directory_behind() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let _bound = bind_unix_socket(&sock, None).unwrap();
    assert!(!staging_dir(&sock).exists());
}

#[tokio::test]
async fn a_staging_path_occupied_by_a_regular_file_is_refused_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    std::fs::write(staging_dir(&sock), b"payload").unwrap();

    let err = bind_unix_socket(&sock, None).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert_eq!(std::fs::read(staging_dir(&sock)).unwrap(), b"payload");
    assert!(!sock.exists());
}

#[tokio::test]
async fn a_staged_entry_that_is_not_a_socket_is_refused_and_kept() {
    use std::os::unix::fs::DirBuilderExt;
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(staging_dir(&sock))
        .unwrap();
    std::fs::write(staging_socket(&sock), b"payload").unwrap();

    let err = bind_unix_socket(&sock, None).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert_eq!(std::fs::read(staging_socket(&sock)).unwrap(), b"payload");
    assert!(!sock.exists());
}

#[tokio::test]
async fn a_reused_staging_directory_is_tightened() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    std::fs::DirBuilder::new()
        .mode(0o777)
        .create(staging_dir(&sock))
        .unwrap();
    std::fs::set_permissions(staging_dir(&sock), std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::write(staging_socket(&sock), b"payload").unwrap();

    bind_unix_socket(&sock, None).unwrap_err();
    let mode = std::fs::metadata(staging_dir(&sock))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[tokio::test]
async fn a_socket_left_in_the_staging_directory_is_replaced() {
    use std::os::unix::fs::DirBuilderExt;
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(staging_dir(&sock))
        .unwrap();
    let stale = std::os::unix::net::UnixListener::bind(staging_socket(&sock)).unwrap();
    drop(stale);

    let (_listener, _guard) = bind_unix_socket(&sock, None).unwrap();
    assert!(sock.exists());
    assert!(!staging_dir(&sock).exists());
}

#[tokio::test]
async fn a_path_too_long_to_stage_is_rejected_by_its_own_name() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("n".repeat(200));

    let err = bind_unix_socket(&sock, None).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert!(err.message().contains(&sock.display().to_string()), "{err}");
    assert!(
        !err.message()
            .contains(&staging_socket(&sock).display().to_string()),
        "{err}"
    );
}

#[tokio::test]
async fn a_lock_path_that_is_not_a_regular_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    std::fs::write(lock_path(&sock), b"").unwrap();
    let bound = bind_unix_socket(&sock, None).unwrap();
    assert!(sock.exists());
    drop(bound);

    let other = dir.path().join("other.sock");
    std::fs::create_dir(lock_path(&other)).unwrap();
    let err = bind_unix_socket(&other, None).unwrap_err();
    assert!(err.message().contains("lock file"), "{err}");
    assert!(lock_path(&other).is_dir());
    assert!(!other.exists());
}

#[tokio::test]
async fn a_clean_drop_unlinks_the_socket_and_its_lock() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let bound = bind_unix_socket(&sock, None).unwrap();
    assert!(sock.exists());
    drop(bound);
    assert!(!sock.exists());
    assert!(!lock_path(&sock).exists());
}

#[tokio::test]
async fn an_occupied_path_refuses_to_bind_and_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("occupied");
    std::fs::write(&path, b"payload").unwrap();

    let err = bind_unix_socket(&path, None).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    assert!(!lock_path(&path).exists());
}

#[tokio::test]
async fn a_mode_is_applied_to_the_bound_socket() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let _bound = bind_unix_socket(&sock, Some(0o600)).unwrap();
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn no_mode_leaves_the_socket_at_umask_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.sock");
    let listener = std::os::unix::net::UnixListener::bind(&plain).unwrap();
    let expected = std::fs::metadata(&plain).unwrap().permissions().mode();
    drop(listener);

    let sock = dir.path().join("noted.sock");
    let _bound = bind_unix_socket(&sock, None).unwrap();
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, expected & 0o777);
}
