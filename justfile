[private]
list:
    @just --list

# Build the crates
build:
    @cargo build --manifest-path {{justfile_directory()}}/Cargo.toml

# Cross-compile the release binary for Termux/Android (arm64) via `cross`
build-android:
    #!/usr/bin/env sh
    set -eu
    cd "{{justfile_directory()}}"
    tools="$PWD/target/tools"
    cross="$tools/bin/cross"
    if [ ! -x "$cross" ]; then
        cargo install cross --locked --root "$tools"
    fi
    if [ -z "${CROSS_CONTAINER_ENGINE:-}" ] && command -v podman >/dev/null 2>&1; then
        export CROSS_CONTAINER_ENGINE=podman
    fi
    "$cross" build --release --target aarch64-linux-android
    echo "binary: $PWD/target/aarch64-linux-android/release/noted"

# Run the workspace, one package, or one exact library test
test package="" test_name="":
    #!/usr/bin/env sh
    set -eu
    if [ -z '{{package}}' ]; then
        cargo test --manifest-path {{justfile_directory()}}/Cargo.toml --workspace
    elif [ -z '{{test_name}}' ]; then
        cargo test --manifest-path {{justfile_directory()}}/Cargo.toml -p '{{package}}'
    else
        cargo test --manifest-path {{justfile_directory()}}/Cargo.toml -p '{{package}}' --lib '{{test_name}}' -- --exact --include-ignored
    fi

# Build the release binary and install it to ~/.local/bin/noted
install:
    #!/usr/bin/env sh
    set -eu
    cargo build --release --manifest-path {{justfile_directory()}}/Cargo.toml
    install -D -m 755 {{justfile_directory()}}/target/release/noted "$HOME/.local/bin/noted"

# Format the sources
fmt:
    @cargo fmt --all --manifest-path {{justfile_directory()}}/Cargo.toml
    @cargo fmt --all --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml

# Verify formatting without writing
fmt-check:
    @cargo fmt --all --manifest-path {{justfile_directory()}}/Cargo.toml --check
    @cargo fmt --all --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml --check

# Lint with clippy (warnings are errors)
lint:
    @cargo clippy --manifest-path {{justfile_directory()}}/Cargo.toml --workspace --all-targets -- -D warnings
    @cargo clippy --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml --target wasm32-unknown-unknown --all-targets -- -D warnings

# Run all static checks + tests
check: fmt-check lint test

# List outdated dependencies
outdated:
    @cargo outdated --manifest-path {{justfile_directory()}}/Cargo.toml --workspace --root-deps-only

# Install the git pre-commit hook
install-hooks:
    @uvx pre-commit install

# Run all pre-commit hooks against the whole repo
precommit:
    @uvx pre-commit run --all-files

# Run the noted CLI (NOTED_DIR must be set), e.g. `just run search foo`
[positional-arguments]
run *args:
    @cargo run --manifest-path {{justfile_directory()}}/Cargo.toml --quiet -- "$@"
