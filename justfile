[private]
list:
    @just --list

# Build the crate
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

# Run the test suite
test:
    @cargo test --manifest-path {{justfile_directory()}}/Cargo.toml

# Build the release binary and install it to ~/.local/bin/noted
install:
    #!/usr/bin/env sh
    set -eu
    cargo build --release --manifest-path {{justfile_directory()}}/Cargo.toml
    install -D -m 755 {{justfile_directory()}}/target/release/noted "$HOME/.local/bin/noted"

# Format the sources
fmt:
    @cargo fmt --manifest-path {{justfile_directory()}}/Cargo.toml

# Verify formatting without writing
fmt-check:
    @cargo fmt --manifest-path {{justfile_directory()}}/Cargo.toml --check

# Lint with clippy (warnings are errors)
lint:
    @cargo clippy --manifest-path {{justfile_directory()}}/Cargo.toml --all-targets -- -D warnings

# Run all static checks + tests
check: fmt-check lint test

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
