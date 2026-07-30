mod common;

use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noted")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn out(o: Output) -> Run {
    Run {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn run(dir: &tempfile::TempDir, set_dir: bool, extra: &[(&str, &str)], args: &[&str]) -> Run {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("NOTED_ENV_FILE", "/dev/null");
    if set_dir {
        cmd.env("NOTED_DIR", common::notes_root(dir));
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    out(cmd.output().unwrap())
}

fn fixture() -> tempfile::TempDir {
    common::fixture_dir()
}

#[test]
fn read() {
    let d = fixture();
    let r = run(&d, true, &[], &["read", "Inbox.md"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("# Inbox"));
}

#[test]
fn write_then_read() {
    let d = fixture();
    assert_eq!(
        run(&d, true, &[], &["write", "new.md", "fresh content"]).code,
        0
    );
    assert!(
        run(&d, true, &[], &["read", "new.md"])
            .stdout
            .contains("fresh content")
    );
}

#[test]
fn search_content() {
    let d = fixture();
    let r = run(&d, true, &[], &["search", "XYZZY", "--mode", "line"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("projects/ideas.md"));
}

#[test]
fn search_path() {
    let d = fixture();
    let r = run(&d, true, &[], &["search", "contacts", "--mode", "path"]);
    assert_eq!(r.stdout.trim(), "people/contacts.md");
}

#[test]
fn search_no_results_is_silent_nonzero() {
    let d = fixture();
    let r = run(
        &d,
        true,
        &[],
        &["search", "NoSuchStringAnywhere", "--mode", "line"],
    );
    assert_eq!(r.code, 1);
    assert_eq!(r.stdout, "");
    assert_eq!(r.stderr, "");
}

#[test]
fn edit() {
    let d = fixture();
    assert_eq!(
        run(&d, true, &[], &["edit", "Inbox.md", "budget", "runway"]).code,
        0
    );
    assert!(
        run(&d, true, &[], &["read", "Inbox.md"])
            .stdout
            .contains("runway")
    );
}

#[test]
fn move_note() {
    let d = fixture();
    assert_eq!(
        run(&d, true, &[], &["move", "Inbox.md", "Inbox2.md"]).code,
        0
    );
    assert_eq!(run(&d, true, &[], &["read", "Inbox2.md"]).code, 0);
    assert_ne!(run(&d, true, &[], &["read", "Inbox.md"]).code, 0);
}

#[test]
fn delete_recoverable() {
    let d = fixture();
    let r = run(&d, true, &[], &["delete", "Inbox.md"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("deleted") && r.stdout.contains("Inbox.md"));
    assert!(!r.stdout.contains("trash"));
    assert_ne!(run(&d, true, &[], &["read", "Inbox.md"]).code, 0);
}

#[test]
fn log_writes_entry() {
    let d = fixture();
    let r = run(
        &d,
        true,
        &[],
        &["log", "did a thing\n-- claude-code · sess"],
    );
    assert_eq!(r.code, 0);
    assert!(r.stdout.starts_with("logged Log/"));
}

#[test]
fn read_missing_exits_nonzero_with_error() {
    let d = fixture();
    let r = run(&d, true, &[], &["read", "does-not-exist.md"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.starts_with("error:"));
}

#[test]
fn path_escape_rejected() {
    let d = fixture();
    let r = run(&d, true, &[], &["read", "../../etc/passwd"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("escapes notes root"));
}

#[test]
fn write_under_log_rejected() {
    let d = fixture();
    let r = run(&d, true, &[], &["write", "Log/2026/07/hack.md", "nope"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("immutable"));
}

#[test]
fn missing_notes_dir_errors() {
    let d = fixture();
    let r = run(&d, false, &[], &["read", "Inbox.md"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("NOTED_DIR"));
}

#[test]
fn env_file_supplies_dir() {
    let d = fixture();
    let env_file = d.path().join("nt.env");
    std::fs::write(
        &env_file,
        format!("NOTED_DIR={}\n", common::notes_root(&d).display()),
    )
    .unwrap();
    let r = run(
        &d,
        false,
        &[("NOTED_ENV_FILE", env_file.to_str().unwrap())],
        &["read", "Inbox.md"],
    );
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("# Inbox"));
}

#[test]
fn env_overrides_env_file() {
    let d = fixture();
    let empty = d.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let env_file = d.path().join("nt.env");
    std::fs::write(&env_file, format!("NOTED_DIR={}\n", empty.display())).unwrap();
    let r = run(
        &d,
        true,
        &[("NOTED_ENV_FILE", env_file.to_str().unwrap())],
        &["read", "Inbox.md"],
    );
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("# Inbox"));
}

#[test]
fn task_get_empty_says_no_tasks() {
    let d = fixture();
    let r = run(&d, true, &[], &["task", "get"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout.trim(), "no tasks");
}

#[test]
fn task_create_and_get() {
    let d = fixture();
    assert_eq!(
        run(
            &d,
            true,
            &[],
            &["task", "create", "do a thing", "--group", "dev"]
        )
        .code,
        0
    );
    let r = run(&d, true, &[], &["task", "get", "dev"]);
    assert!(r.stdout.contains("dev/task_0001") && r.stdout.contains("do a thing"));
}

#[test]
fn remote_url_drives_a_live_serve() {
    let d = fixture();
    let port = pick_port();
    let mut server = Command::new(bin())
        .args([
            "server",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("NOTED_ENV_FILE", "/dev/null")
        .env("NOTED_DIR", common::notes_root(&d))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port(port);

    // no NOTED_DIR on the client: the read must go over HTTP
    let mut cmd = Command::new(bin());
    cmd.args(["read", "Inbox.md"]);
    cmd.env_clear();
    cmd.env("NOTED_ENV_FILE", "/dev/null");
    cmd.env("NOTED_URL", format!("http://127.0.0.1:{port}"));
    let r = out(cmd.output().unwrap());
    let _ = server.kill();
    let _ = server.wait();
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("# Inbox"));
}

fn write_file(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, content).unwrap();
    p.to_str().unwrap().to_string()
}

fn script(dir: &tempfile::TempDir, name: &str, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.path().join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_str().unwrap().to_string()
}

#[test]
fn open_overwrites_buffer_and_saves() {
    let d = fixture();
    let src = write_file(&d, "new.txt", "rewritten body");
    let r = run(
        &d,
        true,
        &[("EDITOR", &format!("cp {src}"))],
        &["open", "Inbox.md"],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("wrote Inbox.md"));
    assert!(!r.stderr.contains("preserved at"));
    assert!(
        run(&d, true, &[], &["read", "Inbox.md"])
            .stdout
            .contains("rewritten body")
    );
}

#[test]
fn open_creates_missing_note() {
    let d = fixture();
    let src = write_file(&d, "new.txt", "brand new");
    let r = run(
        &d,
        true,
        &[("EDITOR", &format!("cp {src}"))],
        &["open", "created.md"],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        run(&d, true, &[], &["read", "created.md"])
            .stdout
            .contains("brand new")
    );
}

#[test]
fn open_unchanged_buffer_writes_nothing() {
    let d = fixture();
    let r = run(&d, true, &[("EDITOR", "true")], &["open", "Inbox.md"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "unchanged");
    assert!(!r.stderr.contains("preserved at"));
}

#[test]
fn open_editor_failure_leaves_note_untouched() {
    let d = fixture();
    let before = run(&d, true, &[], &["read", "Inbox.md"]).stdout;
    let r = run(&d, true, &[("EDITOR", "false")], &["open", "Inbox.md"]);
    assert_ne!(r.code, 0);
    assert!(!r.stderr.contains("preserved at"));
    assert_eq!(run(&d, true, &[], &["read", "Inbox.md"]).stdout, before);
}

#[test]
fn open_requires_an_editor() {
    let d = fixture();
    let empty_path = d.path().to_str().unwrap();
    let r = run(&d, true, &[("PATH", empty_path)], &["open", "Inbox.md"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("no editor"));
}

#[test]
fn open_visual_wins_over_editor() {
    let d = fixture();
    let good = write_file(&d, "good.txt", "from visual");
    let bad = write_file(&d, "bad.txt", "from editor");
    let r = run(
        &d,
        true,
        &[
            ("VISUAL", &format!("cp {good}")),
            ("EDITOR", &format!("cp {bad}")),
        ],
        &["open", "Inbox.md"],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        run(&d, true, &[], &["read", "Inbox.md"])
            .stdout
            .contains("from visual")
    );
}

#[test]
fn open_conflict_preserves_edits_and_aborts() {
    let d = fixture();
    let note = common::notes_root(&d).join("Inbox.md");
    let ed = script(
        &d,
        "clobber.sh",
        "printf 'concurrent write' > \"$NOTE_PATH\"\nprintf 'my careful edits' > \"$1\"",
    );
    let r = run(
        &d,
        true,
        &[("EDITOR", &ed), ("NOTE_PATH", note.to_str().unwrap())],
        &["open", "Inbox.md"],
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("preserved at"), "stderr: {}", r.stderr);
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "concurrent write");
    let rescue = r
        .stderr
        .lines()
        .find_map(|l| l.strip_prefix("your edits are preserved at "))
        .expect("rescue path in stderr")
        .trim();
    let saved = std::fs::read_dir(rescue)
        .unwrap()
        .filter_map(|e| e.ok())
        .find_map(|e| std::fs::read_to_string(e.path()).ok())
        .unwrap();
    assert_eq!(saved, "my careful edits");
}

#[test]
fn open_force_overwrites_concurrent_change() {
    let d = fixture();
    let note = common::notes_root(&d).join("Inbox.md");
    let ed = script(
        &d,
        "clobber.sh",
        "printf 'concurrent write' > \"$NOTE_PATH\"\nprintf 'forced edits' > \"$1\"",
    );
    let r = run(
        &d,
        true,
        &[("EDITOR", &ed), ("NOTE_PATH", note.to_str().unwrap())],
        &["open", "-f", "Inbox.md"],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(!r.stderr.contains("preserved at"));
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "forced edits");
}

#[test]
fn open_log_refusal_preserves_edits() {
    let d = fixture();
    let src = write_file(&d, "new.txt", "cannot land");
    let r = run(
        &d,
        true,
        &[("EDITOR", &format!("cp {src}"))],
        &["open", "Log/2026/07/hack.md"],
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("immutable"));
    assert!(r.stderr.contains("preserved at"), "stderr: {}", r.stderr);
}

fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("server did not start on port {port}");
}

#[test]
fn offline_bootstrap_users_and_keys() {
    use std::process::Stdio;
    let d = fixture();
    let db = d.path().join("auth.redb");
    let env = [("NOTED_AUTH_DB", db.to_str().unwrap())];

    // `user add` always prompts for a password — pipe one in
    let mut cmd = Command::new(bin());
    cmd.args(["server", "user", "add", "alice"]);
    cmd.env_clear();
    cmd.env("NOTED_ENV_FILE", "/dev/null");
    cmd.env("NOTED_AUTH_DB", db.to_str().unwrap());
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"hunter2\n").unwrap();
    let r = out(child.wait_with_output().unwrap());
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);

    let mut cmd = Command::new(bin());
    cmd.args(["server", "user", "add", "alice"]);
    cmd.env_clear();
    cmd.env("NOTED_ENV_FILE", "/dev/null");
    cmd.env("NOTED_AUTH_DB", db.to_str().unwrap());
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"pw\n").unwrap();
    let r = out(child.wait_with_output().unwrap());
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("already exists"));

    let r = run(
        &d,
        false,
        &env,
        &[
            "server",
            "key",
            "create",
            "backup",
            "--tools",
            "SearchNotes,ReadNote",
            "--path",
            "Log",
        ],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let secret = r.stdout.trim().to_string();
    assert!(secret.starts_with("noted_key_"), "stdout: {}", r.stdout);
    assert!(r.stderr.contains("shown exactly once"));

    let list = run(&d, false, &env, &["server", "key", "list", "backup"]);
    assert_eq!(list.code, 0, "stderr: {}", list.stderr);
    assert!(list.stdout.contains("backup") && list.stdout.contains("active"));
    assert!(list.stdout.contains("cred_"));

    let mut cmd = Command::new(bin());
    cmd.args(["server", "key", "revoke"]);
    cmd.env_clear();
    cmd.env("NOTED_ENV_FILE", "/dev/null");
    cmd.env("NOTED_AUTH_DB", db.to_str().unwrap());
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{secret}\n").as_bytes())
        .unwrap();
    let r = out(child.wait_with_output().unwrap());
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("revoked 1"));

    let list = run(&d, false, &env, &["server", "key", "list", "backup"]);
    assert!(list.stdout.contains("revoked"));
}

#[test]
fn key_revoke_without_target_on_a_tty_is_an_error() {
    use std::process::Stdio;
    let d = fixture();
    let db = d.path().join("auth.redb");
    let mut cmd = Command::new(bin());
    cmd.args(["server", "key", "revoke"]);
    cmd.env_clear();
    cmd.env("NOTED_ENV_FILE", "/dev/null");
    cmd.env("NOTED_AUTH_DB", db.to_str().unwrap());
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    drop(child.stdin.take());
    let r = out(child.wait_with_output().unwrap());
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("no secret on stdin"),
        "stderr: {}",
        r.stderr
    );
}

#[test]
fn bootstrap_key_then_authenticated_live_serve() {
    let d = fixture();
    let db = d.path().join("auth.redb");
    let env = [("NOTED_AUTH_DB", db.to_str().unwrap())];
    let r = run(&d, false, &env, &["server", "key", "create", "boot"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let secret = r.stdout.trim().to_string();
    assert!(secret.starts_with("noted_key_"));

    let port = pick_port();
    let mut server = Command::new(bin())
        .args([
            "server",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--auth-db",
            db.to_str().unwrap(),
        ])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("NOTED_ENV_FILE", "/dev/null")
        .env("NOTED_DIR", common::notes_root(&d))
        .spawn()
        .unwrap();
    wait_for_port(port);

    let drive = |token: Option<&str>| {
        let mut cmd = Command::new(bin());
        cmd.args(["read", "Inbox.md"]);
        cmd.env_clear();
        cmd.env("NOTED_ENV_FILE", "/dev/null");
        cmd.env("NOTED_URL", format!("http://127.0.0.1:{port}"));
        if let Some(t) = token {
            cmd.env("NOTED_TOKEN", t);
        }
        out(cmd.output().unwrap())
    };
    let ok = drive(Some(&secret));
    let denied = drive(None);
    let _ = server.kill();
    let _ = server.wait();
    assert_eq!(ok.code, 0, "stderr: {}", ok.stderr);
    assert!(ok.stdout.contains("# Inbox"));
    assert_ne!(denied.code, 0);
}

#[test]
#[cfg(unix)]
fn admin_socket_without_auth_db_is_rejected() {
    let d = fixture();
    let sock = d.path().join("admin.sock");
    let r = run(
        &d,
        true,
        &[],
        &[
            "server",
            "http",
            "--port",
            "0",
            "--admin-socket",
            sock.to_str().unwrap(),
        ],
    );
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("--admin-socket requires --auth-db"),
        "stderr: {}",
        r.stderr
    );
}

#[test]
fn public_url_without_auth_db_is_rejected() {
    let d = fixture();
    let r = run(
        &d,
        true,
        &[],
        &[
            "server",
            "http",
            "--port",
            "0",
            "--public-url",
            "https://notes.example",
        ],
    );
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("--public-url requires --auth-db"),
        "stderr: {}",
        r.stderr
    );
}

#[test]
fn admin_without_a_transport_is_rejected() {
    let d = fixture();
    let r = run(&d, false, &[], &["server", "key", "list"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("--auth-db"), "stderr: {}", r.stderr);
}
