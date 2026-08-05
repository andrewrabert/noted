use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;

fn main() {
    for path in [
        "../ui-wasm/src",
        "../ui-wasm/Cargo.toml",
        "../ui-wasm/Cargo.lock",
        "../picker/src",
        "../picker/Cargo.toml",
        "../core/src",
        "../core/Cargo.toml",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    inline(&compile_ui(), &out_dir);
}

fn compile_ui() -> PathBuf {
    let mut cmd = Command::new(std::env::var_os("CARGO").expect("CARGO"));
    cmd.args([
        "build",
        "--release",
        "--manifest-path",
        "../ui-wasm/Cargo.toml",
        "--target",
        "wasm32-unknown-unknown",
    ]);
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_MAKEFLAGS",
        "RUSTC",
        "RUSTC_LINKER",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
    ] {
        cmd.env_remove(var);
    }
    for (var, _) in std::env::vars_os() {
        let leaks_target = var
            .to_str()
            .is_some_and(|var| var.starts_with("CARGO_CFG_") || matches!(var, "TARGET" | "HOST"));
        if leaks_target {
            cmd.env_remove(var);
        }
    }
    let status = cmd.status().expect("run cargo for crates/ui-wasm");
    assert!(
        status.success(),
        "building crates/ui-wasm for wasm32-unknown-unknown failed; \
         if the target is missing, run: rustup target add wasm32-unknown-unknown"
    );
    PathBuf::from("../ui-wasm/target/wasm32-unknown-unknown/release/noted-ui-wasm.wasm")
}

fn inline(wasm: &Path, out_dir: &Path) {
    let mut output = wasm_bindgen_cli_support::Bindgen::new()
        .input_path(wasm)
        .web(true)
        .expect("wasm-bindgen: web target")
        .typescript(false)
        .out_name("noted_ui")
        .generate_output()
        .expect("wasm-bindgen: generate");
    let snippets: usize = output.snippets().values().map(Vec::len).sum();
    assert!(
        snippets == 0 && output.local_modules().is_empty(),
        "the UI pulled in a JS snippet; the served bundle is one file"
    );
    let module = base64::engine::general_purpose::STANDARD.encode(output.wasm_mut().emit_wasm());
    let glue = format!("{}\nexport const WASM = \"{module}\";\n", output.js());
    std::fs::write(out_dir.join("noted_ui.js"), glue).expect("write noted_ui.js");
}
