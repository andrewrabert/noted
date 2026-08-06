# noted

A tree of `.md` notes exposed three ways over one set of file operations:

- **CLI** — local files, or drive a remote server with `NOTED_URL`, over TCP or a Unix socket
- **HTTP API** — REST at `/tool/{Name}`, plus MCP (Streamable HTTP) at `/mcp`, under OAuth 2.1, over TCP or a Unix socket
- **MCP** — over stdio for a local client

Features: regex search across the tree, timestamped log entries named by the instant they
were written, and a scoped task tracker.

The tree has one open region plus two reserved ones, and each gets its own search:
`SearchNotes` for ordinary notes, `SearchLog` for `Log/`, `SearchTasks` for `Tasks/`.

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
  web     Serve the web UI in a browser
  server  Run and manage the server (http/socket/mcp/user/key)
```

```sh
noted server socket /run/noted/noted.sock                # serve the HTTP app on a socket
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

`noted web` serves a self-contained WebAssembly UI — the whole surface, over the
same fifteen tools — on loopback and opens a browser at it. It honors `--dir` and
`--url` like the client commands, so the same UI drives local files or a remote
server, and it owns the credentials: the browser gets a session cookie, never a
bearer token.

## Configuration

Every `NOTED_*` var can also live in a dotenv file; the process environment wins.
CLI flags override both. Exactly one file loads, the first of:

1. The file `--env-file`/`NOTED_ENV_FILE` names.
2. The nearest `.notedenv`, searched from the working directory up to the
   filesystem root.
3. `~/.config/noted.env`.

A missing file is fine; one that cannot be read or parsed stops the process at
startup. The file cannot name itself: `NOTED_ENV_FILE` is read from the command
line and the process environment only. A relative `NOTED_DIR` resolves against
the working directory, so a committed `.notedenv` should use an absolute path.

| Variable             | Flag             | Default               | Description                                          |
| ---                  | ---              | ---                   | ---                                                  |
| `NOTED_DIR`          | `--dir`          | *(required locally)*  | Notes root directory.                                |
| `NOTED_ENV_FILE`     | `--env-file`     | *(discovered)*        | Dotenv file to load settings from; unset, the nearest `.notedenv` above the working directory, else `~/.config/noted.env`. |
| `NOTED_SOURCE`       | `-s`/`--source`  | -                     | `source` metadata recorded on log entries.           |
| `NOTED_POLICY`       | `--policy`       | *(everything)*        | A policy fragment as JSON, or `@<path>` to a file holding one. |
| `NOTED_SCOPE`        | `--scope`        | *(whole tree)*        | The scope the process is anchored at.                |
| `NOTED_URL`          | `--url`          | -                     | Drive a remote server instead of local files: `http(s)://host[:port]` or `unix:///path.sock`. |
| `NOTED_TOKEN`        | `--token`        | *(stored login)*      | Bearer for the remote server.                        |
| `NOTED_HOST`         | `--host`         | `127.0.0.1`           | `server http` bind address.                          |
| `NOTED_PORT`         | `--port`         | `8000`                | `server http` port.                                  |
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

- A **user** logs in with username + password (OAuth flow / claude.ai).
- An **API key** is a labeled, scoped, expiring bearer. Labels are group handles
  (duplicates allowed); identity is the `credential-id`.

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

Both can mint narrowed child credentials (see [Delegation](#delegation)).

```sh
noted server user add myname                             # prompts for a password
noted server key create claude --scope /dev/myproject    # scoped to one project
noted server key create logger --in /= --in /Log=write --ttl 90d
noted server key list claude                             # policy, fingerprint, expiry
noted server key revoke --label claude                   # sweep every live match
noted server user policy ar --scope /dev --in /secrets=  # set the whole fragment
noted server key policy claude --in /=read               # set a key's fragment
```

## Delegation

Hand an agent limited access by minting a short-lived credential from your stored login.
It can only narrow the login's scope, never widen it, and it tracks the parent: narrow or
revoke the login and every child narrows or dies with it.

```sh
noted auth login --url https://notes.example.com         # browser OAuth; stores tokens + root macaroon
noted auth mint --ttl 1h --session claude:session123 --scope /dev/myproject --in /=read --in /Tasks=read,write
noted auth revoke --session claude:session123            # kill that whole run
noted auth revoke --all                                  # kill every outstanding child
```

## Remote MCP for claude.ai

Run `server http` with `--auth-db` and `--public-url` (the external `https` URL clients
reach; terminate TLS at a reverse proxy). `noted` hosts the OAuth 2.1 server the connector
UI requires; sign in with a username/password from the auth DB.

## Development

Uses [just](https://github.com/casey/just):

```
build          Build the crates
check          Run all static checks + tests
fmt            Format the sources
fmt-check      Verify formatting without writing
install        Build the release binary to ~/.local/bin/noted
install-hooks  Install the git pre-commit hook
lint           Lint with clippy (warnings are errors)
test           Run the test suite
run *args      Run the noted CLI (NOTED_DIR must be set)
```

Building `noted` requires the wasm target:

```
rustup target add wasm32-unknown-unknown
```

`crates/web` (the UI) is excluded from the workspace: `webgl` and `fira-sans` are
wasm-only iced features, and a member would drag winit/wgpu into every host
build. `crates/web-host`'s build script reaches it anyway — a nested `cargo` run
against its manifest, then wasm-bindgen as a library — and embeds the document,
the glue and the module into the binary. Nothing generated is committed and no
tool beyond the rustup target has to be installed, so a plain `cargo build`
produces a `noted` that serves the UI.
