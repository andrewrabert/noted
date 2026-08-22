# noted

A tree of `.md` notes exposed three ways over one set of file operations:

- **CLI** — local files, or drive a remote server with `NOTED_URL`, over TCP or a Unix socket
- **HTTP API** — REST at `/tool/{Name}`, plus MCP (Streamable HTTP) at `/mcp`, under OAuth 2.1, over TCP or a Unix socket, with the web UI at `/`
- **MCP** — over stdio for a local client

A served process is an **origin** when it holds the notes directory, and a **relay**
when it holds a `NOTED_URL` instead: a relay carries every call through to its upstream
untouched, under a credential it minted from its own.

Features: regex search across the tree, timestamped log entries named by the instant they
were written, and a scoped task tracker.

The tree has one open region plus two reserved ones, and each gets its own search:
`SearchNotes` for ordinary notes, `SearchLog` for `Log/`, `SearchTasks` for `Tasks/`.

## Downloads

Development builds from the latest successful CI run on `main`:

### Android / Termux

Install the aarch64 package repository:

```sh
echo "deb [trusted=yes] https://andrewrabert.github.io/noted stable main" \
  > "$PREFIX/etc/apt/sources.list.d/noted.list"
pkg update
pkg install noted
```

The repository is currently unsigned; `[trusted=yes]` explicitly trusts its packages.
The [raw aarch64 build](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-aarch64-linux-android.zip)
is also available.

### Linux

- glibc: [x86_64](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-x86_64-unknown-linux-gnu.zip) · [aarch64](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-aarch64-unknown-linux-gnu.zip)
- musl: [x86_64](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-x86_64-unknown-linux-musl.zip) · [aarch64](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-aarch64-unknown-linux-musl.zip)

### macOS

- [Apple Silicon](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-aarch64-apple-darwin.zip)
- [Intel](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-x86_64-apple-darwin.zip)

### Windows

- [x64](https://nightly.link/andrewrabert/noted/workflows/ci/main/noted-x86_64-pc-windows-msvc.zip)

## Usage

```
noted <command>

  search  Find notes by regex
  read    Read a note by relative path
  write   Write a note, overwriting it
  edit    Revise a note via string-replace
  open    Open a note in $EDITOR; with no path, fuzzy-pick one, newest first
  move    Move or rename a note or folder
  delete  Move a note to .trash/ (recoverable)
  log     Log entries (create/get/search)
  task    Task tracker (create/get/update/move/search)
  auth    Log in to a remote server, mint agent credentials
  server  Run and manage the server (http/socket/mcp/user/key)
```

```sh
noted server socket                                      # pick a path, print its endpoint line
unix:///run/user/1000/noted/k3f9q2xd.sock                # the endpoint line, on stdout
noted server socket /run/noted/noted.sock                # or name the socket
noted --url unix:///run/noted/noted.sock read Inbox.md   # dial it
```

Tools, as the MCP and HTTP interfaces expose them:

| Tool | What it does |
| --- | --- |
| `SearchNotes` | Find notes by regex, outside `Log/` and `Tasks/` |
| `SearchLog` | Find log entries by regex, within a time range |
| `SearchTasks` | Find tasks by regex, within a group |
| `ReadNote` | Read a note's text by relative path |
| `WriteNote` | Write a note, overwriting it |
| `EditNote` | Revise a note via string-replace |
| `MoveNote` | Move or rename a note or folder |
| `DeleteNote` | Move a note to `.trash/` |
| `LogNote` | Append an immutable, timestamped entry |
| `GetLog` | List log entries newest first |
| `CreateTask` | Open a task under `Tasks/` |
| `GetTasks` | Read tasks as summary records |
| `UpdateTask` | Change a task's state, notes or title |
| `MoveTask` | Change a task's group |
| `AttachToTask` | Attach a file to a task, beside its markdown |

A task carrying attachments is a directory named exactly like its markdown file
(`task_0001.md/`), holding the markdown as `.task.md` alongside the attachments; its
path in every task tool is unchanged.

Every served process answers `GET /` with a self-contained WebAssembly UI — the whole
surface, over the same fifteen tools — embedded in the binary. The UI calls back to the
origin it was served from and carries no bearer of its own, so it reaches exactly what
that endpoint admits: put it behind a socket, or behind a relay that confines it.

## Configuration

Settings resolve in three layers, the nearer winning: command-line flags, the process
environment, then the dotenv file. The file is read as a layer of its own and never
enters the process environment.

`NOTED_DIR` and `NOTED_URL` are one setting spelled two ways. Setting both in one layer
is an error naming both spellings and the layer; setting either in a layer discards the
other from every layer below. Every other variable layers on its own.

Exactly one dotenv file loads, the first of:

1. The file `--env-file`/`NOTED_ENV_FILE` names.
2. The nearest `.notedenv`, searched from the working directory up to the
   filesystem root.
3. `~/.config/noted.env`.

A missing file is fine; one that cannot be read or parsed stops the process at
startup. The file cannot name itself: `NOTED_ENV_FILE` is read from the command
line and the process environment only. A relative `NOTED_DIR` resolves against
the working directory, so a committed `.notedenv` should use an absolute path.

Four variables read differently by what the process is:

| Variable | Origin | Relay | Local CLI | Remote CLI |
| --- | --- | --- | --- | --- |
| `NOTED_URL` | - | the upstream it dials | - | the server it drives |
| `NOTED_TOKEN` | - | the relay's own credential | - | the bearer it carries |
| `NOTED_POLICY` | the tree the origin serves | the confinement every proxied call carries | the tree the process sees | a `policy=` caveat on the bearer |
| `NOTED_SCOPE` | the same, as a scope alone | the same, as a scope alone | the same, as a scope alone | the same, as a scope alone |

| Variable             | Flag             | Default               | Description                                          |
| ---                  | ---              | ---                   | ---                                                  |
| `NOTED_DIR`          | `--dir`          | *(required locally)*  | Notes root directory; the other spelling of `NOTED_URL`. |
| `NOTED_ENV_FILE`     | `--env-file`     | *(discovered)*        | Dotenv file to load settings from; unset, the nearest `.notedenv` above the working directory, else `~/.config/noted.env`. |
| `NOTED_SOURCE`       | `-s`/`--source`  | -                     | `source` metadata recorded on log entries.           |
| `NOTED_POLICY`       | `--policy`       | *(everything)*        | A policy fragment as JSON, or `@<path>` to a file holding one; see the four-mode table. |
| `NOTED_SCOPE`        | `--scope`        | *(whole tree)*        | The scope the process is anchored at.                |
| `NOTED_URL`          | `--url`          | -                     | The server to reach instead of local files, and what makes a served process a relay: `http(s)://host[:port]` or `unix:///path.sock`. |
| `NOTED_TOKEN`        | `--token`        | *(stored login)*      | The credential carried upstream: a client's bearer, a relay's own. |
| `NOTED_HOST`         | `--host`         | `127.0.0.1`           | `server http` bind address.                          |
| `NOTED_PORT`         | `--port`         | `8000`                | `server http` bind port; `0` asks the operating system to allocate one. |
| `NOTED_AUTH_DB`      | `--auth-db`      | -                     | Auth database; setting it enables auth.              |
| `NOTED_ADMIN_SOCKET` | `--admin-socket` | -                     | Unix socket for live user/key admin (mode 0600).     |
| `NOTED_PUBLIC_URL`   | `--public-url`   | -                     | External `https` base URL; enables the OAuth server. |
| `NOTED_DEFAULT_TTL`  | `--default-ttl`  | `30d`                 | Default lifetime for issued credentials.             |
| `NOTED_LOG_LEVEL`    | `--log-level`    | `INFO`                | Tracing filter: a level, or `EnvFilter` directives.  |
| `NOTED_LOG_FILE`     | `--log-file`     | *(stderr)*            | Write logs to this file instead of stderr.           |
| `NOTED_HOSTS_FILE`   | `--hosts-file`   | `~/.config/noted/hosts.json` | Credential metadata path; setting it forces plaintext secret storage. |
| `VISUAL`             | -                | -                     | Editor `noted open` launches.                        |
| `EDITOR`             | -                | *(first known editor)* | Editor `noted open` launches when `VISUAL` is unset. |

## Auth

Setting `--auth-db`/`NOTED_AUTH_DB` enables auth. Keep the DB and admin socket outside
`NOTED_DIR` — a file under the notes root is reachable through the notes tools.

A macaroon is the only bearer a server accepts. `POST /token` returns one for a login,
`POST /macaroon/mint` returns one for an agent, and an API key is one with a long life
and its own token id.

Every credential a server hands out descends from the credential that server holds, so
the tree of them narrows downward and never widens. Revoking reaches only downward — a
relay withdraws only what it minted — and an open origin, holding no auth database,
honors no revocation at all.

- A **user** logs in with username + password (OAuth flow / claude.ai).
- An **API key** is a labeled, scoped, expiring macaroon. Labels are group handles
  (duplicates allowed); identity is the `token-id`.

Both carry a **policy**: a scope plus per-path read/write entries. Every policy flag
builds one fragment — `--scope` anchors it, `--in /path=read,write` names an entry, `--in
/=read` sets the access over the scope itself, and `--policy` takes the whole fragment as
JSON. An omitted `=<modes>` means both; an empty one denies. A fragment can only narrow
what the holder already has, and one that reaches further is refused rather than trimmed.

A fragment is written as JSON, and prints back the same way:

```json
{
  "scope": "dev/myproject",
  "access": { "read": true, "write": false },
  "paths": { "vendor": { "read": false, "write": false } }
}
```

`scope` is optional and omitting it means the whole tree. `access` is the access over
the scope itself, and `paths` is read from the scope. Both `access` and every `paths`
value take `read` and `write` as optional flags: an omitted flag keeps whatever the
enclosing policy already allows, so `{"write": false}` closes writing and leaves reading
as it was.

The scope is cumulative across the three regions: a scope of `/a/b/c` puts notes at
`a/b/c`, log entries at `Log/a/b/c`, and tasks at `Tasks/a/b/c`. A `paths` key is read
from the scope, except one at or under `Log` or `Tasks`, which names that region: under
scope `/dev`, `--in /Tasks=read` is `Tasks/dev` and `--in /Log=write` is `Log/dev`.

A user's policy is edited in place; a key's is fixed at its mint, so narrowing one means
minting another and revoking the old. Both can mint narrowed child credentials (see
[Delegation](#delegation)).

```sh
noted server user add myname                             # prompts for a password
noted server user passwd myname                          # change a password
noted server user policy ar --scope /dev --in /secrets=  # set the whole fragment
noted server user list                                   # every user, with its policy
noted server user revoke ar                              # withdraws ar's credentials, moves its epoch
noted server user remove ar                              # drops the user and everything under it
noted server key create claude --scope /dev/myproject    # prints the macaroon on stdout
noted server key create logger --in /= --in /Log=write --ttl 90d
noted server key list claude                             # label, token-id, fingerprint, expiry, policy
noted server key revoke --label claude                   # withdraws every live key of that label
noted server key revoke --id <token-id>                  # withdraws one
```

## Delegation

Hand an agent limited access by minting a short-lived credential from your stored login.
It can only narrow the login's scope, never widen it, and it tracks the parent: narrow or
revoke the login and every child narrows or dies with it.

A revocation reaches only what the server records having minted, and answers with the
names it withdrew — one that names nothing the server minted is an error.

```sh
noted auth login --url https://notes.example.com         # browser OAuth; stores the login
noted auth status                                        # who the stored login is, and until when
noted auth mint --ttl 1h --session claude:session123 --scope /dev/myproject --in /=read --in /Tasks=read,write
noted auth revoke <token-id>                             # withdraws one minted credential
noted auth revoke --session claude:session123            # withdraws every credential of that run
noted auth revoke --all                                  # withdraws every child and moves the epoch
noted auth logout                                        # drops the stored login
```

## Remote MCP for claude.ai

Run `server http` with `--auth-db` and `--public-url` (the external `https` URL clients
reach; terminate TLS at a reverse proxy). `noted` hosts the OAuth 2.1 server the connector
UI requires; sign in with a username/password from the auth DB.

## Development

Uses [just](https://github.com/casey/just):

```
build          Build the crates
build-android  Cross-compile the release binary for Termux/Android (arm64)
check          Run all static checks + tests
fmt            Format the sources
fmt-check      Verify formatting without writing
install        Build the release binary to ~/.local/bin/noted
install-hooks  Install the git pre-commit hook
lint           Lint with clippy (warnings are errors)
outdated       List outdated dependencies
precommit      Run all pre-commit hooks against the whole repo
test           Run the test suite
run *args      Run the noted CLI (NOTED_DIR must be set)
```

Building `noted` requires the wasm target:

```
rustup target add wasm32-unknown-unknown
```

`crates/ui-wasm` (the UI) is excluded from the workspace: `webgl` and `fira-sans` are
wasm-only iced features, and a member would drag winit/wgpu into every host
build. `crates/server`'s build script reaches it anyway — a nested `cargo` run
against its manifest, then wasm-bindgen as a library — and embeds the document,
the glue and the module into the binary. Nothing generated is committed and no
tool beyond the rustup target has to be installed, so a plain `cargo build`
produces a `noted` that serves the UI.
