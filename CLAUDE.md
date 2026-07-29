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
- Flag changed behavior with no test, where `tests/` can cover it.

## Style guidelines

- Avoid violating clippy under `-D warnings`.
- `Result<T, NotedError>` → `crate::error::Result<T>`.
- `NotedError::Variant(m)` → the matching constructor in `error.rs`.
- A bare `String` holding a domain value → its newtype from `newtype.rs`.
- Tool names are PascalCase.
- The args struct for tool `Foo` is `FooArgs`.
- A new test file is `tests/rust_<area>.rs`.
- A new test helper goes in `tests/common/mod.rs`.

## Core code guidelines
- Constraint: All I/O must be non-blocking
- Constraint: All files are atomically written

- Non-negotiable:
  - A new tool is one `<Verb>Args` struct in `tools.rs` plus one `run_tool` arm.
  - Do not add a clap subcommand, an rmcp entry, or an axum route for a tool.
  - `std::fs::` in `notes.rs` or `tasks.rs` → a path from `get_path()`.
  - No `TokenScope` or scope check inside a `run_tool` arm.

- Avoid, unless absolutely necessary:
  - `std::fs::write` → `util::atomic_write()`.
  - A write that must not clobber → `util::atomic_create()`.
  - `unwrap()` / `expect()` outside `tests/`. Permitted after a `strip_prefix` you just joined.
  - Blocking I/O in an `async fn`.
  - A subprocess in `tests/`. No `assert_cmd`, no `Command::new`.
