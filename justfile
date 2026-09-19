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
    # ui-wasm is excluded from the workspace, so it gets its own manifest.
    if [ -z '{{package}}' ]; then
        cargo test --manifest-path {{justfile_directory()}}/Cargo.toml --workspace
        cargo test --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml
    elif [ '{{package}}' = noted-ui-wasm ]; then
        if [ -z '{{test_name}}' ]; then
            cargo test --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml
        else
            cargo test --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml --lib '{{test_name}}' -- --exact --include-ignored
        fi
    elif [ -z '{{test_name}}' ]; then
        cargo test --manifest-path {{justfile_directory()}}/Cargo.toml -p '{{package}}'
    else
        cargo test --manifest-path {{justfile_directory()}}/Cargo.toml -p '{{package}}' --lib '{{test_name}}' -- --exact --include-ignored
    fi

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

# Update dependencies
[positional-arguments]
update *args:
    @cargo update --manifest-path {{justfile_directory()}}/Cargo.toml "$@"
    @cargo update --manifest-path {{justfile_directory()}}/crates/ui-wasm/Cargo.toml "$@"

# Install the git pre-commit hook
install-hooks:
    @prek install

# Run all pre-commit hooks against the whole repo
precommit:
    @prek run --all-files

# Run the noted CLI (NOTED_DIR must be set), e.g. `just run search foo`
[positional-arguments]
run *args:
    @cargo run --manifest-path {{justfile_directory()}}/Cargo.toml --quiet -- "$@"
