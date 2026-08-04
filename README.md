# noted

A tree of `.md` notes exposed three ways over one set of file operations:

- **CLI** — local files, or drive a remote server with `NOTED_URL`
- **HTTP API** — REST at `/tool/{Name}`, plus MCP (Streamable HTTP) at `/mcp`, under OAuth 2.1
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
  open    Open a note in $EDITOR; with no path, fuzzy-pick one
  move    Move or rename a note or folder
  delete  Move a note to .trash/ (recoverable)
  log     Log entries (create/get/search)
  task    Task tracker (create/get/update/move/search)
  auth    Log in to a remote server, mint agent credentials
  server  Run and manage the server (http/mcp/user/key)
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

## Configuration

Every `NOTED_*` var can also live in a dotenv file at `NOTED_ENV_FILE`; the process
environment wins. CLI flags override both.

| Variable             | Flag             | Default               | Description                                          |
| ---                  | ---              | ---                   | ---                                                  |
| `NOTED_DIR`          | -                | *(required locally)*  | Notes root directory.                                |
| `NOTED_ENV_FILE`     | -                | `~/.config/noted.env` | Dotenv file to load settings from.                   |
| `NOTED_SOURCE`       | `-s`/`--source`  | -                     | `source` metadata recorded on log entries.           |
| `NOTED_POLICY`       | `--policy`       | *(everything)*        | A policy fragment as JSON, or `@<path>` to a file holding one. |
| `NOTED_SCOPE`        | `--scope`        | *(whole tree)*        | The scope the process is anchored at.                |
| `NOTED_URL`          | `--url`          | -                     | Drive a remote server instead of local files.        |
| `NOTED_TOKEN`        | `--token`        | *(stored login)*      | Bearer for the remote server.                        |
| `NOTED_HOST`         | `--host`         | `127.0.0.1`           | `server http` bind address.                          |
| `NOTED_PORT`         | `--port`         | `8000`                | `server http` port.                                  |
| `NOTED_AUTH_DB`      | `--auth-db`      | -                     | Auth database; setting it enables auth.              |
| `NOTED_ADMIN_SOCKET` | `--admin-socket` | -                     | Unix socket for live user/key admin (mode 0600).     |
| `NOTED_PUBLIC_URL`   | `--public-url`   | -                     | External `https` base URL; enables the OAuth server. |
| `NOTED_DEFAULT_TTL`  | `--default-ttl`  | `30d`                 | Default lifetime for issued credentials.             |
| `NOTED_LOG_LEVEL`    | `--log-level`    | `INFO`                | Tracing log level.                                   |
| `NOTED_LOG_FILE`     | `--log-file`     | *(stderr)*            | Write logs to this file instead of stderr.           |
| `NOTED_HOSTS_FILE`   | -                | `~/.config/noted/hosts.yaml` | Credential metadata path; setting it forces plaintext secret storage. |

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
build          Build the crate
check          Run all static checks + tests
fmt            Format the sources
fmt-check      Verify formatting without writing
install        Build the release binary to ~/.local/bin/noted
install-hooks  Install the git pre-commit hook
lint           Lint with clippy (warnings are errors)
test           Run the test suite
run *args      Run the noted CLI (NOTED_DIR must be set)
```
