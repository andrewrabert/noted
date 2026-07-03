# noted

A tree of `.md` notes exposed three ways over one set of file operations:

- **CLI** — local files, or drive a remote server with `NOTED_URL`
- **HTTP API** — REST at `/tool/{Name}`, plus MCP (Streamable HTTP) at `/mcp`, under OAuth 2.1
- **MCP** — over stdio for a local client

Features: regex search across the tree, quick timestamped log entries, and a scoped task tracker.

## Usage

```
noted <command>

  search  Find notes by regex
  read    Read a note by relative path
  write   Write a note, overwriting it
  edit    Revise a note via string-replace
  move    Move or rename a note or folder
  delete  Move a note to .trash/ (recoverable)
  log     Append an immutable, timestamped log entry
  task    Task tracker (create/get/update/move)
  auth    Log in to a remote server, mint agent credentials
  server  Run and manage the server (http/mcp/user/key)
```

## Configuration

Every `NOTED_*` var can also live in a dotenv file at `NOTED_ENV_FILE`; the process
environment wins. CLI flags override both.

| Variable             | Flag             | Default               | Description                                          |
| ---                  | ---              | ---                   | ---                                                  |
| `NOTED_DIR`          | -                | *(required locally)*  | Notes root directory.                                |
| `NOTED_ENV_FILE`     | -                | `~/.config/noted.env` | Dotenv file to load settings from.                   |
| `NOTED_SOURCE`       | `-s`/`--source`  | -                     | `source` metadata recorded on log entries.           |
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

## Auth

Setting `--auth-db`/`NOTED_AUTH_DB` enables auth. Keep the DB and admin socket outside
`NOTED_DIR` — a file under the notes root is reachable through the notes tools.

- A **user** logs in with username + password (OAuth flow / claude.ai).
- An **API key** is a labeled, scoped, expiring bearer. Labels are group handles
  (duplicates allowed); identity is the `credential-id`.

Both can mint narrowed child credentials (see [Delegation](#delegation)).

```sh
noted server user add myname                             # prompts for a password
noted server key create claude --tools GetTasks,UpdateTask --path Tasks/dev/myproject
noted server key create logger --rules '[{"tools": ["LogNote"]}]' --ttl 90d
noted server key list claude                             # grants, fingerprint, expiry
noted server key revoke --label claude                   # sweep every live match
noted server user grant ar --all                         # back to unrestricted
```

## Delegation

Hand an agent limited access by minting a short-lived credential from your stored login.
It can only narrow the login's scope, never widen it, and it tracks the parent: narrow or
revoke the login and every child narrows or dies with it.

```sh
noted auth login --url https://notes.example.com         # browser OAuth; stores tokens + root macaroon
noted auth mint --ttl 1h --session claude:session123 --tools GetTasks,UpdateTask --path Tasks/dev/myproject
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
