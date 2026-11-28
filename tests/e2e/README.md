# Browser end-to-end tests

The Playwright suite (`playwright.config.js`, specs in this directory) starts
one disposable backend and runs the specs against it. The backend is the Go
server built with the tag `e2e` (see [Go backend](#go-backend)). The specs do
not depend on how the backend is started; `WEBSSH_E2E_SERVER_COMMAND`
replaces it.

```sh
npm run test:e2e                      # every spec against the Go test backend
node tests/e2e/run-go-suite.js        # the specs of go-suite.json, with their exclusions
npx playwright test --trace off       # without traces
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WEBSSH_E2E_SERVER_COMMAND` | the Go test backend (`playwright.config.js`) | Shell command that starts the backend. Runs in the repository root. |
| `WEBSSH_E2E_PORT` | `4173` | Loopback port. Exported to the server command in every case. |
| `WEBSSH_E2E_SEED` | `tests/e2e/seed.json` | Fixture data the backend applies before it listens. |
| `WEBSSH_E2E_SERVER_TIMEOUT_MS` | `120000` | How long Playwright waits for `GET /login` to answer. |
| `WEBSSH_E2E_FAST_HASHING` | unset | `1` uses cheap password hashing for the seeded accounts (CI). |
| `WEBSSH_E2E_OUTPUT_DIR`, `WEBSSH_E2E_TIMING_FILE` | new directory under `.test-run.tmp/playwright/` (`test-results` in CI) / `e2e-timing-full.json` | Playwright artifacts and the timing report. |

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
WEBSSH_E2E_SERVER_COMMAND='.test-run.tmp/webssh-e2e e2e' node tests/e2e/run-go-suite.js --with passkeys,e2e_hooks
```

Setting `WEBSSH_E2E_SERVER_COMMAND` this way reuses one build across runs.
Without the version in `-ldflags` the binary reports `dev`, and the
account menu spec, which expects a release version, fails.
`run-go-suite.js` runs the specs the Go server has to pass
(`go-suite.json`). Every left-out test names its reason and the package
that unlocks it, the capability of the build it needs (`--with`), or the
decision that drops what it checks (`"decision": "ADR 0005"`, such as long
polling).
`--spec a.spec.js,b.spec.js` runs only those files of the plan (a file the
plan leaves out is an error). A run stopped by SIGINT or SIGTERM, for
example by `timeout`, stops Playwright and its backend, so the port is free
afterwards. `--workers N` runs the specs in parallel; specs marked `serial` change the
stored settings of a seed account (`e2e_admin`) that other specs read and
run afterwards on one worker. A package that builds an area adds its
specs to `go-suite.json` and removes the exclusions it unlocks.
A spec marked `"go_only": "<reason>"` checks behaviour that 3.3 did not
have (`overview-host-order`, `record-unique-names`).

`go run -tags e2e ./cmd/webssh e2e` works as well but compiles on every
start. The Go applier is strict: unknown members, a hook listed twice,
references to another account's key or route and seed variables that move the data directory (`DATA_DIR`, `BACKUP_TEMP_DIR`,
`TRANSFER_TEMP_DIR`) or set `WEBSSH_E2E_*` stop the start. Parts of the
seed that belong to capabilities the Go build does not contain yet are
logged and skipped.

## Seed file

`seed.json` describes the fixture data by meaning, not by storage format.
Each backend maps it onto its own data model; `internal/e2eseed` is the Go
implementation.

| Key | Meaning |
|---|---|
| `version` | Seed format version, currently `1`. |
| `environment` | Documented configuration variables for the backend. `{port}` stands for the port and `{data_dir}/name` for a file in the data directory. |
| `unset_environment` | Variables removed so that the related policies stay changeable at runtime (automation, registration). |
| `data_files` | Files written into the data directory before startup (plain file names only). |
| `admin_settings` | Admin policies applied before accounts are created: automation and registration enabled, raised username login limits. |
| `accounts` | Local accounts. `ref` is the name other entries use to point at the account. `mfa_enabled` marks the account as enrolled. `migrated` marks the account as taken over from 3.3 by the first-start migration: the Go server records the pending upgrade notice for it. |
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
| `socket_output_load` | Realtime event `e2e_output_load`: 20 synthetic terminal streams of 240 frames at 20 Hz each, then `e2e_output_load_done` with `counts`, `peak`, `elapsed_ms`, `aborted`. |
| `socket_workspace_restore` | Realtime event `e2e_workspace_restore` `{count}` (0–12): replaces the caller's fixture sessions with connected, restorable ones and returns their `session_ids`. |
| `socket_herdr_sessions` | Realtime events `e2e_herdr_sessions` `{profile_ids}` and `e2e_herdr_exec_count`: Herdr sessions for saved profiles with a recorded snapshot, and the number of commands executed on them. |

All hooks reject unauthenticated callers and only touch the caller's own
fixture state.

## M1 acceptance specs

`tests/e2e/m1/` holds the acceptance journeys of the first Go milestone (M1). They
do not use the shared server or the seed: every spec file starts its own
backend on a data directory it prepared, so first start, `create-admin`
and the takeover of an existing `DATA_DIR` run as on a real installation.
The main configuration ignores the directory. The suite has its own
variables; `WEBSSH_E2E_SERVER_COMMAND` always means the seeded backend of
the main suite and is ignored here.

```sh
tests/lab/up.sh                                            # the journeys connect to the lab
go build -o .test-run.tmp/webssh ./cmd/webssh
WEBSSH_E2E_M1_SERVER_COMMAND='.test-run.tmp/webssh serve' \
WEBSSH_E2E_M1_ADMIN_COMMAND='.test-run.tmp/webssh' \
npx playwright test -c tests/e2e/m1/playwright.config.js
```

| Variable | Default | Purpose |
|---|---|---|
| `WEBSSH_E2E_M1_SERVER_COMMAND` | – | Starts the server under test on an existing `DATA_DIR`, for example `.test-run.tmp/webssh serve`. |
| `WEBSSH_E2E_M1_ADMIN_COMMAND` | – | Prefix for `create-admin --username <name> --password-file <file>`, for example `.test-run.tmp/webssh`. Required with the server command. |
| `PYTHON`, `WEBSSH_PYTHON_ROOT` | – | Only for the `migration` journey: an interpreter with the 3.3 dependencies and a worktree of the 3.3 release, as in [Difference tests against 3.3](../../docs/wiki/Development-and-Testing.md#difference-tests-against-33). |
| `WEBSSH_LAB_INVENTORY` | `tests/lab/runtime/lab.json` | Inventory of the running lab. Without it the journeys fail instead of passing without a connection. |

Both commands run in the repository root with `DATA_DIR`, `HOST=127.0.0.1`,
`PORT` (also `WEBSSH_E2E_PORT`) and documented settings for the loopback
fixture (`backend.js`: plain-HTTP cookies, lab targets on 127.0.0.1,
passkeys on `http://localhost:<port>`, raised sign-in limits). The server
must serve `GET /login` and stop on SIGINT. `SECRET_KEY` is not passed;
as in the image, the server reads or creates `DATA_DIR/secret_key`.

| Spec | Journey |
|---|---|
| `fresh-start` | `create-admin`, sign-in, TOTP activated and enrolled, sign-in with TOTP, saved host on `ssh-modern` with host-key prompt and shell round trip, reload resumes the session, close, second connection without prompt, key upload (step-up), key connection through `ssh-bastion` to `ssh-inner` |
| `hosts` | saved host created, edited and deleted, each surviving a reload, without any connection |
| `passkey` | passkey registered with a virtual authenticator, then sign-in with it |
| `areas` | every navigation area, asset manager, workspace tool and Settings section opens without page errors, unhandled rejections, 5xx, a realtime event the server has no type for or a loading indicator older than 5 s; no preview notice |

`tests/e2e/m2/` holds acceptance journeys of M2 packages that need the
same disposable backend and the lab. It uses the M1 helpers and variables
and its own configuration, `-c tests/e2e/m2/playwright.config.js`.

| Spec | Journey |
|---|---|
| `ldap` | LDAP from a secret volume against `ldap1`: wrong directory password refused, sign-in with auto-provisioning, the administrator unlinks the identity with a new local password (step-up), local sign-in, a new link, local password refused and directory sign-in again |
| `tmux` | a saved host on `ssh-modern` with tmux and a startup command opens a tmux session; the server restarts; the page lists the persistent session, the user reattaches with the password, the shell state is that of before and the startup command ran once; closing the tab ends it |
| `saved-password` | saved passwords over HTTPS: a TLS proxy with a certificate made per run by `openssl` (`https-proxy.js`, trusted through `TRUSTED_PROXIES=1`) in front of the backend; "Save passwords" switched on, a saved host on `ssh-modern` with a new saved password connects without a typed password, as does Quick Connect with that saved password; a target changed after the page authorized it is refused with the interface's message; over plain HTTP the form says that saved passwords need HTTPS and a `ssh_connect` carrying the saved password and its token is refused without a session |
| `migration` | the 3.3 release writes a `DATA_DIR` through its interface (`python-data-dir.js`: TOTP, key, two hosts, accepted host key); the server under test starts on a copy; old password and TOTP sign in, hosts and key are there, the host key is trusted, the one-time upgrade notice appears at the first sign-in, the migration report and the legacy listing are unchanged |

`node tests/e2e/m1/python-data-dir.js <empty dir>` writes the same fixture
for other checks and prints the synthetic account details as JSON.
