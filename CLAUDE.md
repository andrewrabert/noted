# CLAUDE.md

## Review guidelines

- Prioritize correctness, path/scope safety, stability of the public tool schemas, then clarity.
- Flag code that breaks the style or core guidelines below, and suggest the fix.
- Flag a new or renamed tool that is not reflected in the `README.md` command listing.
- Flag a new or changed `NOTED_*` variable that is not reflected in the `README.md` config table.
- Flag renamed fields, removed fields, or changed defaults in a tool's arg schema. This is
  silent breakage for MCP and HTTP callers and is not allowed. Additive fields are fine.
- Flag missing test coverage for changed behavior, as long as the suites in `tests/` can cover it.

## Style guidelines

- Formatting is `cargo fmt` defaults; there is no `rustfmt.toml`. Avoid violating clippy under
  `-D warnings`.
- Return `crate::error::Result<T>` — the `thiserror` alias for `Result<T, NotedError>`.
- Build errors with the constructors in `error.rs` (`rejected`, `not_found`, `forbidden`,
  `conflict`, `unavailable`, `io_error`, `json_error`, `yaml_error`, `db_error`, `http_error`),
  not `NotedError` variant literals. The variant selects the HTTP status, so pick it by meaning.
- Wrap string domain values in a newtype via the `str_newtype!` / `str_surface!` macros in
  `newtype.rs` — `RelPath`, `Timestamp`, `Source`, `LogBody`, `HttpUrl`. Do not pass a bare
  `String` where one of these exists.
- Tool names are PascalCase (`WriteNote`); their args structs are `<Verb>Args` and derive
  `Args, Serialize, Deserialize, JsonSchema`.

## Core code guidelines

- Non-negotiable:
  - Every tool is exactly one args struct in `tools.rs` plus one `run_tool` arm. The CLI, MCP,
    and axum surfaces generate from it — never hand-wire a subcommand, entry, or route.
  - A tool does what its name says or it does not ship. No state a surface can create but not
    read, list, or undo.
  - All filesystem access goes through `Notes`/`Tasks` path resolution. `get_path()` is what
    rejects root escapes, dot-components, and ignored paths.
  - No bearer secret is stored in plaintext. The DB holds sha256 digests; passwords use scrypt.
  - Do not put an auth or scope check inside a tool body. Scope is enforced once at each
    surface's dispatch via `TokenScope::allows()` plus a `confined(scope.folders_for(name))`
    view of `Notes`/`Tasks`.
  - Do not widen a credential during attenuation; macaroon caveats are monotonic.
  - Macaroon verification fails closed at every step, including on any unrecognized caveat.

- Avoid, unless absolutely necessary:
  - non-atomic writes. Use `util::atomic_write()`, or `util::atomic_create()` where the write
    must not clobber, as in task numbering.
  - `unwrap()` / `expect()` outside tests. Permitted immediately after establishing the
    invariant yourself, e.g. `strip_prefix` on a path you just joined.
  - blocking I/O inside an `async fn`. The `Notes` and `Tasks` cores are sync by design; search
    is the async surface.

- Write tests for anything the suites in `tests/` can cover. Suites are `tests/rust_<area>.rs`
  with shared helpers in `tests/common/mod.rs`, and they run fully in-process: cores driven
  directly, HTTP through the axum `Router` via tower `oneshot`, CLI verbs through the `Backend`
  seam. No subprocesses.
