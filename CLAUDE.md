# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`noted` is a CLI, an MCP server, AND an HTTP API over the same set of file operations
on a tree of `.md` notes. It is a single Rust [Cargo](https://doc.rust-lang.org/cargo/)
crate (`Cargo.toml`, `rust-version = 1.90`, edition 2021) laid out with its sources under
the conventional `src/` (`src/lib.rs`, `src/main.rs`), producing a `noted`
binary. The async runtime is [tokio](https://tokio.rs/); the CLI is
[clap](https://docs.rs/clap/); the HTTP surface is [axum](https://docs.rs/axum/); the MCP
surface is [rmcp](https://docs.rs/rmcp/) (the official Rust MCP SDK); the self-hosted
OAuth server is [oxide-auth](https://docs.rs/oxide-auth/). Serialization is
serde/serde_json/serde_yaml; schemas are derived by schemars.

This repo is the canonical home for `notes`; work happens here.

## Running

```sh
NOTED_DIR=/path/to/notes cargo run -- <subcommand> [args]              # CLI (local notes)
NOTED_DIR=/path/to/notes cargo run -- server mcp                        # MCP over stdio (local)
NOTED_DIR=/path/to/notes cargo run -- server http --auth-db auth.redb   # HTTP: REST + MCP at /mcp
NOTED_URL=http://host:8000 cargo run -- <subcommand>                   # CLI driving a remote server
```

(Once installed with `cargo install --path .`, drop the `cargo run --` and call `noted`
directly.) Everything server-related is under one `server` parent: `server mcp` serves MCP
over **stdio** only (JSON-RPC on stdin/stdout, for a local client; no HTTP transport);
`server http` runs the **HTTP** surface (axum): the REST/JSON tool API (`/tool/{Name}`),
plus the MCP Streamable-HTTP app mounted at `/mcp`, over one port under one auth. `server
user` and `server key` administer the auth DB. Config has `NOTED_*` env vars: `NOTED_HOST`,
`NOTED_PORT` (CLI flags override).

Auth is **on exactly when `--auth-db`/`NOTED_AUTH_DB` is set** — a single redb file (keep it
outside `NOTED_DIR`) holding the whole auth authority: **users** (a thing that logs in —
username + scrypt password hash, always both), **API keys** (a labeled, scoped, expiring
bearer that is a principal complete in itself), OAuth tokens, DCR clients, and macaroon
state. There is no auth file and no static token flag. Every credential rides one wire
contract — `Authorization: Bearer <secret>` with **type-prefixed secrets** (`noted_acc_`
access token, `noted_ref_` refresh token, `noted_key_` API key, `noted_mac_` macaroon); the
resolver dispatches on the prefix to exactly one verifier (`credentials` is keyed by the
secret's sha256, so the hot path is one primary-key read) and an unknown/missing prefix is
an immediate fail-closed 401. No plaintext bearer secret is ever at rest. A no-auth process
(stdio `mcp`, or anonymous `http`) can be scoped by `--tools`/`--path`/`--rules`, the same
rule grammar used everywhere.

A principal's **scope** is either unrestricted (the default — narrowing is opt-in) or an
explicit grant list. A **grant** is one (tools × paths) rule; `user grant`/`key grant`
append one (simple flags: `--tools A,B` and `--path <prefix>`, each at most once, or
`--rules <JSON>` — a `[{"tools": [...], "paths": [...]}]` array, the same `RuleSpec` shape
the macaroon `policy` caveat carries), `ungrant N` removes by number, and `grant --all`
deliberately restores unrestricted. **Unrestricted is a distinct mode, not an empty list**:
ungranting the last grant leaves no access. Scope is resolved from the DB at request time,
so edits hit outstanding credentials immediately — no re-issuance. Key names are **labels**
(duplicates allowed — a group handle; `key revoke --label claude` sweeps every live match,
`--id cred_…` hits one, and a secret piped to `key revoke` on stdin resolves by hash);
usernames are unique. `key create` is a **two-phase mint**: the record persists `pending`,
the secret prints exactly once, then it finalizes `active` — a crash can never leave a live
credential no operator can see or revoke (stale `pending` rows sweep at server start).

**Live administration** runs through the **admin unix socket**
(`--admin-socket`/`NOTED_ADMIN_SOCKET`, created mode 0600 — OS permissions are the
authentication). The socket is forced by redb: the server holds the file's exclusive lock,
so while it is up it is the only possible writer and must broker mutations. The CLI's
`user`/`key` verbs connect to the socket when the server runs (changes apply immediately)
and open the DB directly when it doesn't (bootstrap / stopped server); the lock itself
arbitrates, failing closed. Wire contract: line-delimited JSON, `{"ok": …}` or
`{"error": {"kind": "rejected"|"unavailable", …}}`; domain errors keep the session open,
a malformed line closes it. Both transports call the identical `AuthService` methods.

For the **claude.ai** remote-connector UI (and the `noted auth login` CLI flow), `noted`
hosts its own OAuth 2.1 authorization server, enabled when `--public-url`/`NOTED_PUBLIC_URL`
is also set (`oauth.rs`). It's real OAuth — DCR + PKCE + a username/password login form
validated against the DB's users (read per attempt: enumeration-safe dummy-verify for
unknown names, per-(user,ip) rate limit). Access tokens are **hardcoded to 1h** (refresh
rotation makes the value invisible; the short life matters because that bearer sits in
claude.ai's infrastructure); every durable credential the server issues — rotating refresh
tokens, API keys, root macaroons — defaults to `--default-ttl`/`NOTED_DEFAULT_TTL` (humane
durations like `30d`; mint verbs override per credential with `--ttl`). Validation is
DB-only (the `DbIssuer` mints prefixed pairs as `credentials` rows), so it survives a
restart by construction. Terminate TLS at a reverse proxy in front.

**Macaroon delegation — the primary scoping mechanism.** Principals run unrestricted; the
credential handed to an agent is a short-lived, task-prefixed child macaroon minted offline
(`noted auth mint`, default 1h, `--session` tags a run for wholesale revocation). Users
**and API keys** are both macaroon parents (`POST /macaroon/root` accepts any live bearer —
there is zero harm in a credential reducing its own access): a child is an HMAC caveat
chain the client narrows (`policy`/`before`/`id`/`session` caveats) but can't widen; the
server verifies the chain and evaluates the pinned caveat vocabulary, returning
`effective = ∩ policy caveats ∩ owner's current scope` — so shrinking or revoking the
parent shrinks/kills the child live. Revocation is layered (`POST /macaroon/revoke`):
expiry (stateless) → per-child `id`/`session` deny-list (self-expiring) → `min_epoch` bump
(all-current) → parent removal (all). See `oauth/macaroon.rs`.

The CLI itself can drive a remote `noted server http` instead of local files: set
`--url`/`NOTED_URL` and every tool subcommand is shipped to the server over HTTP instead of
run against the local `NOTED_DIR`. The bearer comes from `--token`/`NOTED_TOKEN`, else from a
stored login: `noted auth login/logout/status/mint/revoke` manage credentials via the
backend-agnostic `CredentialStore` (`credentials.rs`) — the **secret** in the OS keyring, a
**non-secret pointer** in `~/.config/noted/hosts.yaml`; `build_backend` auto-fills and
refreshes the stored access token. The client OAuth flow lives in `authclient.rs`.

`NOTED_DIR` (required for local use) is the notes root. `NOTED_SOURCE` (optional) sets the
log `source` metadata; the `-s/--source` flag overrides it. Every `NOTED_*` var can
also be set in a dotenv file at `NOTED_ENV_FILE` (default `~/.config/noted.env`),
loaded via dotenvy; the process environment overrides the file. `NOTED_LOG_LEVEL` /
`NOTED_LOG_FILE` configure tracing.

Tests live in `tests/` (a shared fixture note-tree plus per-area suites) and run under
`cargo test`. They are **fully in-process — no subprocesses**: the domain cores are driven
directly, the HTTP surface (REST + the `/mcp` rmcp mount) is driven through the axum
`Router` via tower's `oneshot` (the analogue of an in-memory ASGI transport), and the CLI
verbs are driven through the `Backend` seam. `tests/common/mod.rs` holds the shared
helpers (`fixture_dir()` copies `tests/fixtures/notes/` into a fresh tempdir per test,
`cores()` builds `(Notes, Tasks)`, `post_json`/`post_mcp` drive the router). Common tasks
run through [just](https://github.com/casey/just):

```sh
just test        # cargo test
just lint        # cargo clippy --all-targets -- -D warnings
just fmt-check   # cargo fmt --check
just check       # fmt-check + lint + test
just run ...     # run the noted CLI (NOTED_DIR must be set)
```

A `.pre-commit-config.yaml` gates commits on `cargo fmt --check` + `cargo clippy` (plus
file hygiene): the commit fails on any lint or format error. Run `just install-hooks` once
per clone to enable it (`just precommit` runs every hook against the whole tree).

## Architecture

The design goal is a **single source of truth for tool definitions**: each tool is one
typed args struct, and all three surfaces (CLI + MCP + HTTP) are generated from it. When
adding or changing a tool, you touch one struct + its `run_tool` arm and every surface
follows. The domain-core operations (`Notes`/`Tasks`) are synchronous file I/O; search is
async (in-process via the `grep` crate on a `spawn_blocking` pool). The CLI edge drives
everything through a small tokio runtime.

- **`config.rs`** — cross-cutting settings: the `NOTED_*` env layer + `env_file_path()`
  dotenv (dotenvy), `resolve_root`/`resolve_source`, home expansion, and `setup_logging`
  (tracing). Knows about neither domain core.
- **`error.rs`** — the error type `NotedError` with `Rejected` (definitive,
  caller-actionable refusal → HTTP 400 / MCP error) and `Unavailable` (couldn't complete:
  I/O failure, backend unreachable, 5xx → HTTP 503). `rejected()`/`unavailable()`
  constructors; `Result<T>` alias.
- **`util.rs`** — primitives: `atomic_write`/`atomic_create` (temp file + `persist`,
  `persist_noclobber` for collision-safe task numbering), `walk_builder`/`walk_files` (the
  shared recursive file walk, used by both search and path listing), `IgnoreFilter` (the
  **single** `.ignore`/`.gitignore` matcher — see the ignore invariant), `normalize`
  (lexical path clean), `slice_lines` (1-based paging window), `random_token`.
- **`notes.rs`** — the note-tree domain core. `Notes` owns all path safety and tree
  semantics (trash, immutable log, meta sidecars), plus the search it drives. File I/O
  (read/write/move_note/delete/create_log) is synchronous; `grep`/`match_path` are async
  (they call `search.rs`). A `confine` (allowed folders, or None) restricts a scoped
  token: `confined(folders)` returns a cheap re-scoped `Notes` over the same root, and
  enforcement rides the existing chokepoints — `guard_confine` in the file resolvers (Log/
  exempt) and `filter_confine` on search results — so no per-tool code.
- **`search.rs`** — search **in-process** via the `grep` crate (the library ripgrep is
  built on) and `ignore`'s `WalkBuilder` — **no external `rg` binary**. `ripgrep()` walks
  contents with context; `match_paths()` filters relative path strings; both build one
  matcher from `MatchOpts` (fixed-strings, case mode, word-boundary, multiline) so path
  and content matching behave identically. `WalkOpts` (glob include/exclude via
  `OverrideBuilder`, file-type via `TypesBuilder`; `walk_search`) filters the hidden-
  skipping walk. An invalid pattern/glob/type is a `Rejected`.
- **`tasks.rs`** — the second domain core: `Tasks`, a group-organized task tracker. Each
  task is one `.md` note with YAML frontmatter (`task`, `state`, `created_at`,
  `updated_at`) plus a markdown body, stored under `NOTED_DIR/Tasks/` **inside** the note
  tree (so tasks are searchable). Tasks live in **groups** — arbitrarily nested,
  auto-created subdirectories — addressed by their Tasks-relative path minus `.md` (e.g.
  `dev/noted/task_0001`); there is no global id. The filename is noted-assigned: `create`
  puts the next per-folder `task_NNNN` in the chosen group (a hand-named `.md` file
  coexists and is a valid task, it just doesn't affect numbering). Group and task names
  must match `^[A-Za-z][A-Za-z0-9_-]*$`. `state` is one of
  `created|started|blocked|completed|rejected|invalid` (`completed`/`rejected`/`invalid`
  are terminal, hidden from the default read); every state except `created`/`started`
  requires a non-empty body. Owns `resolve` (segment validation + escape safety),
  `create`/`query`/`update`/`move_task`, and the `reconcile` frontmatter schema check
  applied on every task write. Like `Notes`, it takes a `confine` and a
  `confined(folders)`. `parse_front_matter` is the shared frontmatter splitter.
- **`tools.rs`** — the tool surface. One typed args struct per tool
  (`SearchArgs`/`ReadArgs`/… + task args), `#[derive(Deserialize, JsonSchema)]`, is the
  single source of truth for both the MCP input schema (schemars, `schema_of()`) and
  argument parsing (serde). `run_tool(name, args, notes, tasks)` dispatches one call to
  the domain cores. `tool_defs()` is the catalogue (name + verbatim docstring description
  + schema); `is_tool(name)` is the registry-membership predicate and `allowed_tools(scope)`
  the scope-narrowed subset (tools whose name any of the scope's rules grant). A field
  marked `#[schemars(skip)]` (e.g. `LogArgs.source`) is CLI-only: hidden from the MCP
  schema while still deserializable from the CLI/HTTP payload.
- **`scope.rs`** — the scope model: a `TokenScope` is a `Vec<Rule>`, each `Rule` an
  optional `tools` set over an optional `paths` set (`None` = unrestricted). `allows(tool)`
  and `folders_for(tool)` drive tool-narrowing and per-tool confinement;
  `TokenScope::full()` is unrestricted. `intersect()` (used by macaroon verification to
  clamp a child to `child ∩ parent`) and `compile_rules()` (a `RuleSpec` list → scope — the
  one rule-JSON schema shared by `--rules`, stored grants, and the macaroon `policy`
  caveat; `deny_unknown_fields`, tool names validated against the registry, paths
  normalized) live here too. `StoredScope` is a principal's persisted form:
  `Unrestricted` (a distinct mode) or `Grants(Vec<RuleSpec>)` — an empty grant list
  compiles to a zero-rule scope, which denies everything (narrowing never fails open).
- **`password.rs`** — scrypt hash/verify via the standard PHC string
  (`$scrypt$ln=…,r=…,p=…$salt$hash`), using the `scrypt` crate's `password-hash`
  integration; hashes exist only inside the auth DB. `verify_dummy` equalizes the
  unknown-username timing.
- **`mcp.rs`** — the rmcp surface. Implements `rmcp::ServerHandler` (`list_tools`/
  `call_tool`): `list_tools` returns `tool_defs()` narrowed by the request's scope;
  `call_tool` resolves the request's `CallScope` (from the request extensions set by the
  HTTP middleware, else the context's `process_scope`), refuses a non-registered tool
  (`is_tool`) or one outside `allows`, confines the cores per-tool
  (`scope.folders_for(name)`), `await`s `run_tool`, and maps a `NotedError`/validation
  failure to the MCP error envelope (`isError` with a visible `error: …` message; genuine
  bugs are masked). `context(notes, tasks)` builds the `McpContext`; set `process_scope` for
  the `--tools`/`--paths` case.
- **`http.rs`** — the axum surface. `build_app(ctx, auth, oauth)` builds one `Router`:
  **one typed POST route per tool** at `/tool/{Name}` (serde-validated body → `run_tool`,
  mapping `Rejected`→400 / `Unavailable`→503 / bad body→422); the rmcp Streamable-HTTP
  service mounted at `/mcp`; and **one** bearer-check middleware on *every* route that
  resolves the caller's `CallScope` onto the request extensions. `resolve` dispatches on
  the secret's prefix to exactly one verifier — `noted_acc_`/`noted_key_` →
  `AuthService::resolve_bearer` (one sha256 primary-key read), `noted_mac_` →
  `macaroon::verify`; a refresh prefix, an unknown prefix, or no bearer is a fail-closed
  401 — and a no-auth process falls back to the context's `process_scope`. The only
  route-specific logic is `is_public` (the OAuth discovery/login allowlist) and whether
  the 401 carries the RFC 9728 challenge. The `/macaroon/{root,revoke}` routes mount
  whenever auth is on; the OAuth discovery/`/login` routes mount with `--public-url`.
- **`oauth/service.rs`** — **the auth domain seam**: one `AuthService` owns all
  semantics — user/key CRUD (users always have a password; key names are non-unique
  labels, identity = `credential_id` = `cred_` + 10 base32 chars), grant edits
  (`ScopeEdit`), two-phase key mint (`pending` → `active`, `PENDING_WINDOW` sweep),
  `resolve_bearer` (prefix check → sha256 lookup → status/expiry → owner→scope; an orphan
  is deleted and refused), `resolve_scope` (kind-qualified owner `user:<name>` /
  `key:<credential_id>` → live scope, the macaroon clamp's source), the prefixed-secret
  constants + `split_prefix`, and the login-pair issuance the `DbIssuer` calls
  (`ACCESS_TTL = 3600`, hardcoded). Every adapter (HTTP resolver, OAuth provider, admin
  socket, CLI direct mode) calls these methods; none touches records directly.
- **`oauth/admin.rs`** — the admin transport: `AdminRequest`/`AdminResponse` (the enum IS
  the protocol) and **one** `apply()` dispatch used by both the unix-socket accept loop
  (`bind_socket` unlinks stale + chmods 0600; NDJSON; domain errors keep the session,
  malformed lines close it) and the CLI's direct-DB mode — the socket is transport, not a
  second implementation. `AdminClient` is the client half.
- **`oauth.rs`** — the self-hosted OAuth 2.1 authorization server (wired in with
  `--public-url`), built on `oxide-auth` so the SDK keeps the security-sensitive mechanics
  (PKCE S256, redirect/DCR validation, token-endpoint semantics) while the **`DbIssuer`**
  (implements `oxide_auth::Issuer` over `AuthService`) mints prefixed access/refresh pairs
  as durable `credentials` rows and recovers grants from them — validation is DB-only and
  survives a restart by construction; refresh rotation kills the old refresh token in the
  same transaction. `authorize()` parks the request and redirects to a username/password
  `/login` form (user read from the DB per attempt; scrypt verify off the event loop,
  dummy-verify for unknown users, per-(user,ip) rate limit); a successful login mints a
  code whose subject is the username. Holds **no** redb code — storage is `oauth/db.rs`
  (`oauth::Db`), the one place redb types appear: five tables, zero secondary indexes
  (`users`, `credentials` keyed by sha256(secret), `clients`, `mac_roots` keyed by the
  kind-qualified owner, `mac_revoked`), admin lookups scan (n is dozens; every index would
  be a sync invariant). `oauth/macaroon.rs` implements the delegation surface: per-owner
  root secret + `min_epoch`, root issuance (`noted_mac_`-prefixed wire form), the pinned
  caveat vocabulary + evaluator (crypto via the `macaroon` crate, policy evaluation ours),
  `attenuate` (shared with the client `auth mint`), and the `/macaroon/{root,revoke}`
  handlers behind the one `caller_owner` chokepoint (any live bearer — user token or API
  key — may mint/revoke its own children).
- **`serve.rs`** — the `http` and `mcp` (stdio) subcommand runners. `serve` builds the
  `Notes`/`Tasks`, opens the `AuthService` when `--auth-db` is set (startup sweep), the
  `OAuthProvider` when `--public-url` is too, spawns the admin socket when
  `--admin-socket` is, sets the process scope, assembles the axum `Router`, and runs a
  tokio + axum server; `mcp_stdio` runs the rmcp stdio transport over
  `serve_server(ctx, stdio())`.
- **`backend.rs`** — the CLI's invocation seam. `Backend` picks one peer: `Filesystem`
  (runs `run_tool` in-process against local `Notes`/`Tasks`) or `Http` (ships the
  serialized `ToolCall` to a remote `noted server http` via reqwest, keying off HTTP status: 2xx
  unwraps `{"ok":…}`, 4xx→`Rejected`, 5xx/transport→`Unavailable`). `invoke()` is async.
  A `Test` transport drives an in-process axum router for the CLI tests. `strip_cli_only`
  drops CLI-only fields (LogNote `source`) from the shipped payload.
- **`credentials.rs`** — the client credential store, backend-agnostic. `CredentialStore`
  exposes `open`/`get`/`set`/`remove`/`list` over a `Credential`; the **secret** (tokens +
  root macaroon) lives in the OS keyring (`keyring` crate) and the **non-secret pointer**
  (`user`, `client_id`) in `~/.config/noted/hosts.yaml`. A private `SecretBackend` trait
  (`Keyring`, `PlaintextFile`) is selected in `open` and never leaks into a signature;
  `NOTED_HOSTS_FILE` (tests) forces the plaintext backend.
- **`authclient.rs`** — the client OAuth flow: `login` runs discovery → DCR (loopback
  redirect) → PKCE → browser (`open` crate) → catch the code on a `tokio` loopback listener →
  code exchange; plus `refresh`, `fetch_root` (root macaroon), and `revoke`.
- **`cli.rs`** — the clap command tree and composition root. Each tool subcommand parses
  argv into a `ToolCall` shipped through the one `Backend` (local vs `NOTED_URL`); the
  `server` subtree (`http`/`mcp`/`user`/`key`) runs itself. `server user`
  (add/passwd/grant/ungrant/list/revoke/remove) and `server key`
  (create/grant/ungrant/list/revoke) share the `AdminTransport` pair (`--admin-socket`
  else `--auth-db` direct) and the `RuleFlags` grammar (`--tools`/`--path` at most once
  each, or `--rules <JSON>`; `parse_ttl` gives humane `--ttl`/`--default-ttl` durations);
  `key revoke` takes exactly one of `--label`/`--id`/a secret piped on stdin (hashed
  locally — plaintext never crosses the socket). The `auth` subtree
  (`login`/`logout`/`status`/`mint`/`revoke`) drives `authclient`/`CredentialStore`; `mint`
  attenuates the stored root macaroon **offline** via `oauth::macaroon::attenuate`, taking
  the same `RuleFlags` grammar compiled to one `policy` caveat (default 1h, `--session`
  tags a run). `build_backend` fills the remote bearer from `--token`/`NOTED_TOKEN` else
  the stored login (refreshing a lapsed access token). The async edge lives here:
  `run_dispatch` builds a small tokio runtime and `block_on`s `backend.invoke`, then
  renders (task listings get the human/`--json` render; everything else is passthrough).
  `main()` is the binary entry point (`src/main.rs` forwards to it).

## Invariants to preserve

- **Path safety**: `Notes::get_path()` (via `resolve_file`/`resolve_movable`) resolves
  every relative path and rejects any that escape the notes root. All file access goes
  through it.
- **Hidden and ignored paths are invalid everywhere**: `get_path()` rejects any path with a
  dot-prefixed (hidden) component *or* one excluded by an in-tree `.ignore`/`.gitignore`
  with a generic `invalid path` error — there is **no** `.trash`-specific code or message.
  Ignore filtering has **one source of truth**: `util::IgnoreFilter::is_ignored` (deepest-
  first per-directory gitignore match, bounded to the notes root; `.gitignore` honored even
  outside a git repo). Every surface consults that one predicate — the discovery walk drives
  it via `WalkBuilder::filter_entry` (the crate's own `.ignore`/`.git_ignore` matching is
  turned **off** in `util::walk_builder`, so there is no second engine), and the direct-
  access chokepoints (`get_path`, `Tasks::resolve`/`task_path`, task listing/numbering) call
  it directly. So `.trash`/`.git`/dotdirs and any ignored path are unreachable and
  unsearchable on every surface, and the walk and the resolvers can never disagree.
  `DeleteNote`'s internal move *into* `.trash/` bypasses `get_path`, so deletion still
  works.
- **Logs are immutable**: entries under `Log/` (and their `.md.meta` YAML sidecars)
  are write-once. `create_log()` writes them under `Log/YYYY/MM/` with an auto-generated
  timestamp name and system metadata; `guard_log()` blocks write/edit/move/delete on
  anything under `Log/`. The `.md.meta` sidecars carry no special search handling — they
  are ordinary searchable files (expected to fold into log front matter later).
- **Deletes are recoverable but one-way to the caller**: `DeleteNote` moves files into
  the hidden `.trash/` (uniquified), never unlinks — recoverable by an operator on disk,
  but with no surface path back (trash is unreachable like any hidden path).
- **Tasks are a managed subtree**: everything under `Tasks/` is owned by the task tools.
  `Notes::write` (so `WriteNote`/`EditNote`) refuses any path under `Tasks/`, and
  `Notes::move_note`/`delete` reject tasks too — the note tree no longer knows the task
  schema. Tasks are created by `CreateTask` (noted assigns the per-folder `task_NNNN.md`),
  advanced by `UpdateTask`, and relocated by `MoveTask` (change group → fresh number +
  bumped `updated_at`). Every mutation runs `reconcile`, the closed frontmatter schema:
  `task` required, `state` validated, `created_at` immutable, `updated_at` always stamped
  by our code, and blocked/terminal states require a non-empty body. Group/task names are
  validated (`^[A-Za-z][A-Za-z0-9_-]*$`) and paths can't escape `Tasks/`. A task or group
  reached through a **symlink** is ignored (never listed, read, or counted for numbering),
  so a planted symlink can't be used to reach files outside the tree. Tasks appear in
  normal search.
- **Scoped tokens enforce at the chokepoints, not per tool**: a `TokenScope` is a list of
  rules (each an optional `tools` set over an optional `paths` set). Tool restriction is one
  `scope.allows(name)` check at each surface's dispatch; path confinement rides
  `Notes`/`Tasks`'s existing guards (`guard_confine`/`filter_confine`, `Tasks::resolve`) via
  a per-request `confined(scope.folders_for(name))` view — so the allowed folder set is
  **per-tool** (a rule can grant note tools under `projects/` while granting task tools
  anywhere). The scope is resolved once by the HTTP middleware and read back by both
  surfaces; no tool code knows about auth. `Log/` stays writable for a confined credential
  (logs are shared, append-only). Every credential kind — browser token, API key,
  macaroon — resolves through the same owner→scope path at request time (fail-closed), so
  scope edits hit outstanding credentials immediately. Tool names in a rule are validated
  against the `TOOLS` registry, so a grant can't name a phantom tool.
- **A child credential never exceeds its parent**: macaroon attenuation is monotonic — the
  client can only *append* narrowing caveats (crypto), and the server clamps the result to
  the parent's **live** scope (`effective = ∩ policy caveats ∩ current owner scope`, the
  owner being a user or an API key), so shrinking or revoking the parent shrinks/kills the
  child. Verification is fail-closed at every step (bad signature, unknown/removed owner,
  expired `before`, revoked `id`/`session`, `epoch < min_epoch`, or **any unrecognized
  caveat** → reject). The `attenuate` builder and the verifier share one caveat-string
  vocabulary so mint and verify can't drift.
- **No plaintext bearer secret at rest, and every credential is accountable**: the DB
  stores sha256 digests (passwords: scrypt PHC strings); the fingerprint (prefix + head)
  is captured at mint, and the secret is printed exactly once. Every server-minted
  credential is a record with a public `credential-id` and a `pending → active → revoked`
  status — two-phase mint means a crash can never leave a live credential no operator can
  see or revoke. Prefix dispatch is fail-closed: an unprefixed or unknown-prefixed bearer
  touches no store.
- **Atomic writes**: all writes go through `atomic_write()` (temp file + `persist`); task
  auto-numbering uses `atomic_create()` (`persist_noclobber`) so a concurrent create never
  clobbers another.
- **Search** is in-process via the `grep` crate (`ripgrep()` for content, `match_paths()`
  for paths), sharing one `MatchOpts`-built matcher so path and content matching behave
  identically — no external `rg` binary is required. `SearchNotes` exposes `mode`
  (`any`/`line`/`file`/`path`), `fixed`, `glob`, and CLI/HTTP-only `case`/`word`/
  `multiline`/`type`; hidden paths are never walked.
- **Errors map, they don't crash**: `Rejected`/`Unavailable`/validation failures become
  transport envelopes, never unhandled panics. MCP: `call_tool` turns them into an
  `isError` result whose deliberate `error: …` message stays visible while any *other*
  failure is masked. HTTP: `http.rs` maps `Rejected`→400, `Unavailable`→503,
  validation→422. CLI: `main()` prints `NotedError` as `error: …` and exits non-zero.

Byte-compatibility with the prior Python implementation has been **retired** — it is
no longer a constraint. On-disk and wire formats are chosen for what is best in Rust:
task frontmatter and log sidecars use full local timestamps with a UTC offset (e.g.
`2026-07-05T00:13:10.415132-04:00`), password hashes use the standard scrypt PHC string,
and JSON output is plain `serde_json` pretty-printing. There is **no migration** of
pre-existing Python-era files; old task files keep their single-quoted `…Z` timestamps
until the next write re-stamps them (both forms parse fine). Do not re-introduce
compatibility shims.
