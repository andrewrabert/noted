# CLAUDE.md

## General guidelines
- HARD CONSTRAINT: Never defer change of pre-existing code for any reason or scope.
- Always prefer using an available `just` recipe when one exists.
- Always consider the entire codebase for all tasks regardless of scope or goal
- Always prefer rewriting the entire or large parts codebase to improve even the narrowest of changes
- Always make change with zero concern or acknowledgement of backwards-compatibility
- Always fix code when identified regardless
- All note domain behavior must be invariant with a single truth

## Review guidelines

- Prioritize correctness, path safety, tool-schema stability, then clarity.
- Embrace wide rewrites for the betterment of even the smallest scoped changes
- Flag code that breaks the guidelines below.
- Flag a new or renamed tool missing from the `README.md` command listing.
- Flag a new or changed `NOTED_*` variable missing from the `README.md` config table.
- Flag a renamed or removed field in a tool's arg schema. Added fields are fine.
- Flag a changed default in a tool's arg schema.
- Flag changed behavior with no test, where a crate's `tests/` can cover it.

## Style guidelines

- Avoid violating clippy under `-D warnings`.
- `Result<T, NotedError>` → `crate::error::Result<T>` (`noted::error::Result<T>` in `crates/cli`).
- `NotedError::Variant(m)` → the matching constructor in `crates/core/src/error.rs`.
- A bare `String` holding a domain value → its newtype from `crates/core/src/newtype.rs`.
- Tool names are PascalCase.
- The args struct for tool `Foo` is `FooArgs`.
- A new test file is `tests/rust_<area>.rs`; CLI tests live in `crates/cli/tests/`.
- A new test helper goes in that crate's `tests/common/mod.rs`.

## Core code guidelines
- Constraint: All I/O must be non-blocking. One exception: a one-shot listener bind at server startup, and its guard's unlink at shutdown.
- Constraint: All files are atomically written

- Non-negotiable:
  - A new tool is one `<Verb>Args` struct in `crates/core/src/tools.rs`, one `run_tool` arm, and one `NotedRoot` method.
  - Do not add a clap subcommand, an rmcp entry, or an axum route for a tool.
  - `std::fs::` outside `crates/core/src/store.rs` → a `Store` method.
  - An absolute path outside `Store` → a `RelPath`.
  - A path reached from anywhere but `NotedRoot` → a method on `NotedRoot`.
  - A `String` or `&str` holding a path → `RelPath`, `TaskRef`, or `GroupPath`.
  - No `TokenScope` or scope check inside a `run_tool` arm.

- Avoid, unless absolutely necessary:
  - `std::fs::write` → `util::atomic_write()`.
  - A write that must not clobber → `util::atomic_create()`.
  - `unwrap()` / `expect()` outside `tests/`. Permitted after a `strip_prefix` you just joined.
  - Blocking I/O in an `async fn`.
  - A subprocess in `tests/`. No `assert_cmd`, no `Command::new`.
