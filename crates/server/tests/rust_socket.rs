#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};

use noted::tools::ReadArgs;
use noted::{Backend, BackendArgs, Bearer, Endpoint, PolicyFragment, ToolCall, Transport};
use noted_server::serve::{Bind, HttpConfig, ServedConfig, serve_http};
use noted_server::socket::{
    SocketBind, SocketEnv, bind_unix_socket, lock_path, socket_base_dir, socket_root, staging_dir,
    staging_socket, write_endpoint_line,
};

fn env_at(runtime_dir: Option<&Path>, tmpdir: Option<&Path>) -> SocketEnv {
    SocketEnv {
        runtime_dir: runtime_dir.map(Path::to_path_buf),
        tmpdir: tmpdir.map(Path::to_path_buf),
    }
}

async fn serve(dir: &tempfile::TempDir) -> (PathBuf, String) {
    let svc = common::auth_service(dir);
    let token = common::mint_key(&svc, PolicyFragment::default());
    let sock = dir.path().join("noted.sock");
    let (listener, guard) = bind_unix_socket(&sock, None).unwrap();
    let app = common::origin_app(common::root(dir), &svc).await;
    tokio::spawn(async move {
        let _guard = guard;
        let _ = axum::serve(listener, app).await;
    });
    (sock, token)
}

fn dialing(sock: &Path, token: &str) -> Backend {
    Backend::new(BackendArgs::Remote {
        endpoint: format!("unix://{}", sock.display()).parse().unwrap(),
        bearer: Some(Bearer::new(token)),
        transport: Transport::Real,
    })
    .unwrap()
}

#[tokio::test]
async fn a_bound_unix_listener_endpoint_names_the_absolute_placed_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("noted.sock");
    let upstream: Endpoint = "http://upstream.test/internal".parse().unwrap();

    let error = serve_http(HttpConfig {
        served: ServedConfig::Relay {
            endpoint: upstream,
            bearer: Some(Bearer::new("carried-verbatim")),
            policy: noted::PolicyArgs {
                policy: Some("not json".to_string()),
                ..noted::PolicyArgs::default()
            },
            transport: Transport::Router(axum::Router::new()),
        },
        bind: Bind::Socket(SocketBind::Explicit(socket.clone())),
        public_url: None,
        authentication: None,
        admin_socket: None,
    })
    .await
    .unwrap_err();

    assert!(socket.is_absolute());
    assert!(
        error
            .to_string()
            .starts_with(&format!("unix://{}: ", socket.display())),
        "{error}"
    );
}

#[tokio::test]
async fn tools_round_trip_over_a_unix_socket() {
    let dir = common::fixture_dir();
    let (sock, token) = serve(&dir).await;
    let backend = dialing(&sock, &token);
    let call = ToolCall::new(ReadArgs::new(common::rp("Inbox.md"))).unwrap();
    let out = backend.invoke(&call).await.unwrap();
    assert!(out.render().contains("follow up with Dana"));
}

#[tokio::test]
async fn an_unknown_bearer_is_refused_over_the_socket() {
    let dir = common::fixture_dir();
    let (sock, _token) = serve(&dir).await;
    let backend = dialing(&sock, "not-a-token");
    let call = ToolCall::new(ReadArgs::new(common::rp("Inbox.md"))).unwrap();
    let err = backend.invoke(&call).await.unwrap_err();
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

#[tokio::test]
async fn a_picked_socket_lands_under_the_runtime_dir() {
    let dir = tempfile::tempdir().unwrap();
    let spec = SocketBind::Picked(env_at(Some(dir.path()), None));
    let (_listener, guard) = spec.bind().unwrap();
    assert_eq!(guard.path().parent().unwrap(), dir.path().join("noted"));
    assert!(guard.path().exists());
}

#[tokio::test]
async fn a_picked_name_is_eight_lowercase_alphanumerics_and_dot_sock() {
    let dir = tempfile::tempdir().unwrap();
    let spec = SocketBind::Picked(env_at(Some(dir.path()), None));
    let (_listener, guard) = spec.bind().unwrap();
    let name = guard.path().file_name().unwrap().to_str().unwrap();
    let stem = name.strip_suffix(".sock").unwrap();
    assert_eq!(stem.len(), 8, "{name}");
    assert!(
        stem.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "{name}"
    );
}

#[tokio::test]
async fn a_picked_socket_is_bound_at_0600_and_unlinked_with_its_lock() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let spec = SocketBind::Picked(env_at(Some(dir.path()), None));
    let (listener, guard) = spec.bind().unwrap();
    let path = guard.path().to_path_buf();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let lock = guard.lock_path().to_path_buf();
    drop(guard);
    drop(listener);
    assert!(!path.exists());
    assert!(!lock.exists());
    assert!(dir.path().join("noted").is_dir());
}

#[tokio::test]
async fn a_second_pick_under_one_base_directory_lands_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let spec = SocketBind::Picked(env_at(Some(dir.path()), None));
    let (_a, first) = spec.bind().unwrap();
    let (_b, second) = spec.bind().unwrap();
    assert_ne!(first.path(), second.path());
}

#[tokio::test]
async fn an_unusable_runtime_dir_falls_back_to_the_tmpdir() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("gone");
    let tmp = dir.path().join("tmp");
    std::fs::create_dir(&tmp).unwrap();
    assert_eq!(
        socket_root(&env_at(Some(&missing), Some(&tmp))).unwrap(),
        tmp
    );
    assert_eq!(
        socket_root(&env_at(Some(Path::new("")), Some(&tmp))).unwrap(),
        tmp
    );
    assert_eq!(
        socket_root(&env_at(Some(Path::new("relative")), Some(&tmp))).unwrap(),
        tmp
    );
}

#[tokio::test]
async fn an_empty_environment_falls_back_to_slash_tmp() {
    assert_eq!(
        socket_root(&SocketEnv::default()).unwrap(),
        Path::new("/tmp")
    );
}

#[tokio::test]
async fn a_root_holding_a_newline_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("a\nb");
    std::fs::create_dir(&root).unwrap();
    let err = socket_root(&env_at(Some(&root), None)).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert!(err.message().contains("newline"), "{err}");
}

#[tokio::test]
async fn a_created_base_directory_is_exactly_0700_and_reusable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let env = env_at(Some(dir.path()), None);

    let base = socket_base_dir(&env).unwrap();
    let mode = std::fs::metadata(&base).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    assert_eq!(socket_base_dir(&env).unwrap(), base);
}

#[tokio::test]
async fn a_base_directory_at_the_wrong_mode_is_refused_and_kept() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("noted");
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o770)).unwrap();

    let err = socket_base_dir(&env_at(Some(dir.path()), None)).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert!(err.message().contains(&base.display().to_string()), "{err}");
    let mode = std::fs::metadata(&base).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o770);
}

#[tokio::test]
async fn a_base_directory_that_is_not_a_directory_is_refused_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("noted");
    std::fs::write(&base, b"payload").unwrap();

    let err = socket_base_dir(&env_at(Some(dir.path()), None)).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert_eq!(std::fs::read(&base).unwrap(), b"payload");
}

#[tokio::test]
async fn a_base_directory_under_a_root_that_denies_mkdir_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();

    let err = socket_base_dir(&env_at(Some(&root), None)).unwrap_err();
    assert!(
        err.message()
            .contains(&root.join("noted").display().to_string()),
        "{err}"
    );
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!root.join("noted").exists());
}

#[test]
fn a_relative_endpoint_line_is_rejected_without_writing() {
    let mut out = Vec::new();
    let error = write_endpoint_line(&mut out, Path::new("relative.sock")).unwrap_err();

    assert!(error.is_rejection());
    assert!(out.is_empty());
}

#[tokio::test]
async fn an_endpoint_line_is_the_scheme_the_path_and_a_newline() {
    let mut out = Vec::new();
    write_endpoint_line(&mut out, Path::new("/run/noted/x.sock")).unwrap();
    assert_eq!(out, b"unix:///run/noted/x.sock\n");
}

#[tokio::test]
async fn an_endpoint_line_carries_a_non_utf8_path_verbatim() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let path = PathBuf::from(OsStr::from_bytes(b"/tmp/\xff.sock"));
    let mut out = Vec::new();
    write_endpoint_line(&mut out, &path).unwrap();
    assert_eq!(out, b"unix:///tmp/\xff.sock\n");
}
