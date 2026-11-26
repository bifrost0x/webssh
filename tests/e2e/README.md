# Browser end-to-end tests

The Playwright suite (`playwright.config.js`, specs in this directory) starts
one disposable backend and runs the specs against it. By default the backend
is the Python application, started through `run_app.py`. The specs do not
depend on how the backend is started, so another implementation can serve
the same suite.

```sh
npm run test:e2e                      # default: Python backend via run_app.py
npx playwright test --trace off       # same, without traces
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WEBSSH_E2E_SERVER_COMMAND` | `"$PYTHON" tests/e2e/run_app.py` | Shell command that starts the backend. Runs in the repository root. |
| `WEBSSH_E2E_PORT` | `4173` | Loopback port. Exported to the server command in every case. |
| `WEBSSH_E2E_SEED` | `tests/e2e/seed.json` | Fixture data the backend applies before it listens. |
| `WEBSSH_E2E_SERVER_TIMEOUT_MS` | `120000` | How long Playwright waits for `GET /login` to answer. |
| `PYTHON` | `python` (`.venv\Scripts\python.exe` on Windows) | Interpreter for the default command. |
| `WEBSSH_E2E_FAST_HASHING` | unset | `1` uses cheap password hashing for the seeded accounts (CI). |
| `WEBSSH_E2E_OUTPUT_DIR`, `WEBSSH_E2E_TIMING_FILE` | temp dir / `e2e-timing-full.json` | Playwright artifacts and the timing report. |

There is no base URL variable. Specs and `helpers.js` build
`http://127.0.0.1:<port>` and the WebAuthn origin `http://localhost:<port>`
themselves, so a backend must listen on loopback at `WEBSSH_E2E_PORT` and
answer for both host names.

## Backend contract

A backend started by `WEBSSH_E2E_SERVER_COMMAND` must:

1. Start with an empty, private data directory and separate scratch
   directories for backups and transfers. Nothing from a previous run may be
   reused.
2. Read the seed file and apply it completely before it accepts requests. A
   seed it cannot apply in full (unknown version, hook or entry) is a startup
   error, not a partial start.
3. Listen on `127.0.0.1:$WEBSSH_E2E_PORT` over plain HTTP and serve
   `GET /login` once it is ready.
4. Exit when Playwright stops it.

Seeding and test hooks are for this harness only. A production build must
not contain them, so another backend keeps them in a separate test build or
binary.

## Go backend

The Go server applies the seed in a separate test build (build tag `e2e`,
package `internal/e2eseed`); the release binary contains neither the
`e2e` command nor the hooks.

```sh
scripts/stage-webassets.sh
go build -tags e2e -o .test-run.tmp/webssh-e2e \
  -ldflags "-X github.com/bifrost0x/webssh/internal/buildinfo.version=3.4.0 -X github.com/bifrost0x/webssh/internal/buildinfo.revision=$(git rev-parse HEAD)" \
  ./cmd/webssh
WEBSSH_E2E_SERVER_COMMAND='.test-run.tmp/webssh-e2e e2e' node tests/e2e/m1/run-go-subset.js --with passkeys,e2e_hooks
```

Without the version in `-ldflags` the binary reports `dev`, and the
account menu spec, which expects a release version, fails.
`run-go-subset.js` runs the specs the Go preview has to pass
(`m1/go-subset.json`); every left-out test names the capability it needs.

`go run -tags e2e ./cmd/webssh e2e` works as well but compiles on every
start. The Go applier is stricter than `run_app.py`: unknown members, a
hook listed twice, references to another account's key or route and seed
variables that move the data directory (`DATA_DIR`, `BACKUP_TEMP_DIR`,
`TRANSFER_TEMP_DIR`) or set `WEBSSH_E2E_*` stop the start. Parts of the
seed that belong to capabilities the Go build does not contain yet are
logged and skipped.

## Seed file

`seed.json` describes the fixture data by meaning, not by storage format.
Each backend maps it onto its own data model. `run_app.py` is the Python
implementation and the reference for the exact semantics.

| Key | Meaning |
|---|---|
| `version` | Seed format version, currently `1`. |
| `environment` | Documented configuration variables for the backend. `{port}` stands for the port and `{data_dir}/name` for a file in the data directory. |
| `unset_environment` | Variables removed so that the related policies stay changeable at runtime (automation, registration). |
| `data_files` | Files written into the data directory before startup (plain file names only). |
| `admin_settings` | Admin policies applied before accounts are created: automation and registration enabled, raised username login limits. |
| `accounts` | Local accounts. `ref` is the name other entries use to point at the account. `mfa_enabled` marks the account as enrolled. |
| `account_settings` | Per-account settings stored for every account (intro tour already seen). |
| `external_identities` | GitHub and OIDC identities linked to an account. |
| `security_features` | Enabled TOTP and passkey features, attributed to an account. |
| `mfa_placeholders` | TOTP and passkey records that show an account as enrolled. They cannot authenticate. |
| `ssh_keys` | Keys generated fresh for every run (`generate: ed25519`). The seed holds no key material. |
| `jump_hosts`, `socks_proxies` | Saved routes. Without stored passwords. |
| `commands`, `command_sets` | User commands and command sets with fixed ids that profiles refer to. |
| `profiles` | Saved hosts per account, in display order. |
| `test_hooks` | Test-only behaviour the specs rely on, see below. |

References: `key`, `jump_host` and `socks_proxy` name the `ref` of an entry
in the same seed; the backend replaces them with the id it assigned.
`key_id`, `jump_host_id`, `socks_proxy_id`, `command_id` and
`command_set_id` are literal ids. Some deliberately point at nothing
(`missing-key`, `missing-jump-host`, `missing-socks-proxy`,
`missing-command`, `missing-command-set`) to exercise dangling references.
Profile ids are given explicitly; they equal the name in lower case with
spaces replaced by hyphens.

The configuration in `environment` exists to make the loopback fixture work:
`DEBUG` and `SESSION_COOKIE_SECURE=False` allow plain HTTP on loopback,
which production defaults correctly refuse. The raised rate limits let many
independent cases sign in to the same accounts. The SSH key list limit is
per user and minute; every sign-in and every visit of the file workspace
lists the keys, so a run of consecutive cases as `e2e_admin` (the theme
matrix visits the files view seven times per case) must stay below it, or
the workspace never reports its keys as loaded. All secrets in the seed are
fixed test values that are only valid for this harness.

## Test hooks

| Hook | Behaviour the specs expect |
|---|---|
| `automation_ssh_peer` | A loopback SSH server that accepts only a key seeded for the listed accounts, plus the profile `Automation fixture` in group `Automation lab` with a trusted host key. Command `wait` runs until cancelled, `fail` exits with 2, everything prints `fixture command completed`. |
| `outbound_ssh_guard` | Every outbound SSH connection fails with the given `error` text instead of reaching the network. |
| `socket_output_load` | Socket.IO event `e2e_output_load`: 20 synthetic terminal streams of 240 frames at 20 Hz each, then `e2e_output_load_done` with `counts`, `peak`, `elapsed_ms`, `aborted`. |
| `socket_workspace_restore` | Socket.IO event `e2e_workspace_restore` `{count}` (0–12): replaces the caller's fixture sessions with connected, restorable ones and returns their `session_ids`. |
| `socket_herdr_sessions` | Socket.IO events `e2e_herdr_sessions` `{profile_ids}` and `e2e_herdr_exec_count`: Herdr sessions for saved profiles with a recorded snapshot, and the number of commands executed on them. |

All hooks reject unauthenticated callers and only touch the caller's own
fixture state. `automation_fixture.py`, `output_load.py`,
`workspace_restore.py` and `herdr_fixture.py` are the Python versions.

## M1 acceptance specs

`tests/e2e/m1/` holds the acceptance journeys of the Go preview (M1). They
do not use the shared server or the seed: every spec file starts its own
backend on a data directory it prepared, so first start, `create-admin`
and the takeover of an existing `DATA_DIR` run as on a real installation.
The main configuration ignores the directory. The suite has its own
variables; `WEBSSH_E2E_SERVER_COMMAND` always means the seeded backend of
the main suite and is ignored here.

```sh
tests/lab/up.sh                                            # the journeys connect to the lab
npx playwright test -c tests/e2e/m1/playwright.config.js   # Python
go build -o .test-run.tmp/webssh ./cmd/webssh
WEBSSH_E2E_M1_SERVER_COMMAND='.test-run.tmp/webssh serve' \
WEBSSH_E2E_M1_ADMIN_COMMAND='.test-run.tmp/webssh' \
npx playwright test -c tests/e2e/m1/playwright.config.js   # Go
```

| Variable | Default | Purpose |
|---|---|---|
| `WEBSSH_E2E_M1_SERVER_COMMAND` | `"$PYTHON" tests/e2e/m1/python_backend.py serve` | Starts the server on an existing `DATA_DIR`. When set, the specs treat the backend as the Go server. |
| `WEBSSH_E2E_M1_ADMIN_COMMAND` | `"$PYTHON" tests/e2e/m1/python_backend.py cli` | Prefix for `create-admin --username <name> --password-file <file>`. Required when the server command is set. |
| `WEBSSH_LAB_INVENTORY` | `tests/lab/runtime/lab.json` | Inventory of the running lab. Without it the journeys fail instead of passing without a connection. |

Both commands run in the repository root with `DATA_DIR`, `HOST=127.0.0.1`,
`PORT` (also `WEBSSH_E2E_PORT`) and documented settings for the loopback
fixture (`backend.js`: plain-HTTP cookies, lab targets on 127.0.0.1,
passkeys on `http://localhost:<port>`, raised sign-in limits). The server
must serve `GET /login` and stop on SIGINT. `SECRET_KEY` is not passed;
like `entrypoint.sh`, the server reads or creates `DATA_DIR/secret_key`.

| Spec | Journey |
|---|---|
| `fresh-start` | `create-admin`, sign-in, TOTP activated and enrolled, sign-in with TOTP, saved host on `ssh-modern` with host-key prompt and shell round trip, reload resumes the session, close, second connection without prompt, key upload (step-up on Go), key connection through `ssh-bastion` to `ssh-inner` |
| `hosts` | saved host created, edited and deleted, each surviving a reload, without any connection |
| `passkey` | passkey registered with a virtual authenticator, then sign-in with it |
| `preview-areas` | every navigation area, asset manager, workspace tool and Settings section opens without page errors, unhandled rejections, 5xx other than the preview's 501 or a loading indicator older than 5 s; the preview notice on Go, none on Python |
| `migration` | the Python release writes a `DATA_DIR` through its interface (`python-data-dir.js`: TOTP, key, two hosts, accepted host key); the server under test starts on a copy; old password and TOTP sign in, hosts and key are there, the host key is trusted. On Go also the migration report and an unchanged legacy listing |

`node tests/e2e/m1/python-data-dir.js <empty dir>` writes the same fixture
for other checks and prints the synthetic account details as JSON.
