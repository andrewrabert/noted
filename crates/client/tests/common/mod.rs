#![allow(dead_code)]

use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;

use axum::Router;
use noted::store::NotedDir;
use noted::types::{Source, Ttl};
use noted::{NotedRoot, PolicyFragment};
use noted_auth::authority::{Mint, Minter, OriginAuthority, Verified};
use noted_auth::types::Label;
use noted_auth::{AuthService, AuthState, Db};
use noted_server::http::{Served, build_app};

pub fn copy_tree(src: &StdPath, dst: &StdPath) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

pub fn fixture_dir() -> tempfile::TempDir {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/notes");
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("notes");
    copy_tree(&src, &dst);
    tmp
}

pub fn notes_root(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("notes")
}

pub fn root(dir: &tempfile::TempDir) -> NotedRoot {
    NotedRoot::open(NotedDir::new(notes_root(dir)), Some(Source::new("test")))
        .unwrap()
        .with_authority(&[PolicyFragment::default()])
        .unwrap()
}

pub fn auth_service(dir: &tempfile::TempDir) -> Arc<AuthService> {
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    Arc::new(AuthService::new(db, Ttl::from_secs(30 * 24 * 3600)))
}

pub fn mint_key(svc: &Arc<AuthService>, label: &str, policy: PolicyFragment) -> String {
    let minter = OriginAuthority::new(svc.clone());
    let ask = Mint {
        policy,
        ttl: svc.default_ttl(),
        session: None,
        label: Some(Label::new(label).unwrap()),
    };
    minter
        .mint(&Verified::anonymous(), &ask)
        .unwrap()
        .macaroon
        .expose()
        .to_string()
}

pub fn open_app(dir: &tempfile::TempDir) -> Router {
    build_app(Served::Origin(root(dir)), AuthState::open())
}

pub fn origin_app(dir: &tempfile::TempDir, svc: &Arc<AuthService>) -> Router {
    build_app(
        Served::Origin(root(dir)),
        AuthState::origin(svc.clone(), None),
    )
}
