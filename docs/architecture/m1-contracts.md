# M1 contracts

This document fixes the contracts between the Go packages built for the M1
preview: the realtime protocol, the principal, the error codes, the store
API and the interfaces where packages meet. It is the reference for the
packages that are built in parallel against it.

The [package map](go-package-map.md) says which package may import which.
The rules behind both are in
[ADR 0003](../adr/0003-package-structure-and-modularity.md) and
[ADR 0005](../adr/0005-native-websocket-realtime-transport.md).

## How contracts are fixed

- A contract is compiled code when a package of the first build wave
  consumes or provides it across a package boundary, or when two packages
  of a later wave meet on it. Those types and interfaces exist in the
  packages named below and are changed only by a contract change, which
  updates this document in the same commit.
- Concrete provider APIs that only later waves consume (configuration,
  keyring ring, session service, page data) are fixed here by signature.
  They become binding when the providing package is merged.
- Interfaces are declared by the consumer. They use only standard library
  types, foundation types and types of the provider's package when the
  consumer may import it. A provider satisfies them structurally and never
  imports the consumer.
- Test doubles live in packages whose name ends in `test`
  (`principaltest`, `protocoltest`, `storetest`). The architecture tests
  allow only test files to import them.
- The tables of error codes, message types and step-up actions below are
  checked against the code by `internal/architecture`.

## Principal

`internal/principal` says who acts.

```go
type Principal struct {
	UserID    int64
	SessionID string
	Username  string
	IsAdmin   bool
	Recovery  bool
}
func With(ctx context.Context, p Principal) context.Context
func From(ctx context.Context) (Principal, bool)
func Require(ctx context.Context) (Principal, error)                 // fails closed
func RequireAllowingRecovery(ctx context.Context) (Principal, error) // factor repair only
func RequireAdmin(ctx context.Context) (Principal, error)
```

- The transports validate the session and put the principal into the
  request context and into the context of every realtime handler.
  Capabilities read it with `Require`; they never parse cookies or tokens.
- `Require` returns `authentication_required` without a principal and
  `forbidden` for a recovery session. Only the factor-repair actions use
  `RequireAllowingRecovery`.
- Authorization uses `UserID`; `Username` is for display and audit.
- `principal.Revocation{SessionID, UserID, Reason}` announces an ended
  session. Reasons are stable strings (`logout`, `revoked_by_user`,
  `password_changed`, `factor_changed`, `account_locked`, `role_changed`,
  `expired`, `recovery_ended`).

## Errors

`internal/fault` is the one error model.

```go
type Error struct {
	Code       Code
	Message    string        // safe to show
	RetryAfter time.Duration // rate_limited, busy
	Err        error         // cause, for logs only
}
func New(code Code, message string) *Error
func Wrap(code Code, cause error, message string) *Error
func Status(err error) (httpStatus int, code Code, message string)
```

- A capability returns a `*fault.Error` (possibly wrapped) for every
  failure a user should see. An empty message uses the code's default text.
  `Message` never contains secrets, remote-supplied text, paths or
  internal identifiers.
- The transports map errors only through `fault.Status`. An unclassified
  error becomes `internal` with the default text; the transport logs the
  cause. No internal text reaches a client.
- HTTP JSON errors keep the shape the frontend expects:
  `{"success": false, "code": "<code>", "error": "<message>"}` with the
  status from the table. Realtime errors are the `err` member of a
  `result` message: `{"code", "message", "retry_after_ms"}`.
- Routes planned but not built in M1 answer
  `501 {"success": false, "code": "not_available_in_preview", "error": …}`.

### Error codes

| Code | HTTP status | Default message |
|---|---|---|
| `auth_banner_declined` | 400 | The login banner was declined. |
| `auth_failed` | 502 | Authentication failed. |
| `authentication_required` | 401 | Sign in to continue. |
| `backpressure` | 503 | The connection did not keep up. |
| `busy` | 409 | Another operation is in progress. |
| `channel_in_use` | 409 | The terminal channel is already in use. |
| `channel_rejected` | 502 | The host refused the session. |
| `conflict` | 409 | The change conflicts with the current state. |
| `connection_cancelled` | 400 | The connection was cancelled. |
| `csrf_expired` | 400 | The page has expired. Reload it and try again. |
| `forbidden` | 403 | You are not allowed to do this. |
| `host_key_changed` | 502 | The host key has changed. |
| `host_key_not_accepted` | 502 | The host key was not accepted. |
| `host_key_revoked` | 502 | The host key is revoked. |
| `interaction_required` | 502 | The host asks for input that cannot be answered here. |
| `internal` | 500 | An internal error occurred. |
| `invalid_request` | 400 | The request is invalid. |
| `invalid_value` | 400 | A value is not allowed. |
| `last_factor_required` | 409 | At least one second factor must remain. |
| `maintenance` | 503 | The server is in maintenance mode. |
| `mfa_restart` | 400 | The sign-in has expired. Start again. |
| `no_common_algorithm` | 502 | No common SSH algorithm. |
| `not_available_in_preview` | 501 | Not available in this preview yet. |
| `not_found` | 404 | Not found. |
| `precondition_failed` | 412 | The data has changed. Reload and try again. |
| `rate_limited` | 429 | Too many attempts. Try again later. |
| `ssh_input_backpressure` | 503 | The terminal is not accepting input right now. |
| `ssh_input_too_large` | 413 | The input is too large. |
| `ssh_protocol_error` | 502 | The SSH connection failed. |
| `step_up_failed` | 403 | The confirmation failed. |
| `step_up_required` | 403 | Confirm your identity to continue. |
| `storage_error` | 500 | The data could not be stored. |
| `target_blocked` | 403 | The network policy does not allow this target. |
| `timeout` | 504 | The connection timed out. |
| `too_large` | 413 | The request is too large. |
| `unavailable` | 503 | The service is unavailable. |
| `unknown_type` | 400 | Unknown message type. |
| `unreachable` | 502 | The host could not be reached. |
| `version_unsupported` | 400 | Reload the page to use the current version. |

The codes the Python release sends and the frontend matches on
(`step_up_required`, `rate_limited`, `csrf_expired`, `mfa_restart`,
`last_factor_required`, `host_key_changed`, `host_key_not_accepted`,
`auth_banner_declined`, `ssh_input_too_large`, `ssh_input_backpressure`,
`busy`, `maintenance`, `unavailable`, `storage_error`, `invalid_request`,
`invalid_value`, `not_found`) keep their spelling.

## Realtime protocol

`internal/realtime/protocol`, schema `webssh.v1`, WebSocket subprotocol
`webssh.v1`.

**Envelope.** Every text frame is `{"v":1,"t":<type>,"id":<id>,"p":<object>}`.
`id` is set by the client on requests that want a result and echoed in the
`result` message; server events carry no `id`. Types match
`[a-z0-9._-]{1,64}`, ids `[A-Za-z0-9:._-]{1,128}` (the request-id pattern of
the Python release).

**Strict decoding (condition K6).** `DecodeEnvelope` and `DecodePayload`
use `encoding/json/v2` and reject:

- unknown members, at the top level and in payloads;
- member names that differ in case from the declared name;
- duplicate member names at any depth, including inside `p`;
- trailing data after the value (whitespace is allowed);
- invalid UTF-8 and lone surrogates;
- a version other than 1, a payload that is not an object.

An invalid envelope closes the connection with 4002. An invalid payload is
answered with `invalid_request`. Payload types therefore declare every
member the frontend sends; a field the browser adds is a contract change.

**Result.** `{"v":1,"t":"result","id":<id>,"p":{"ok":true,"p":<object>}}` or
`{"ok":false,"err":{"code","message","retry_after_ms"}}`. Handlers return
`fault` errors; the dispatcher converts them with `protocol.WireError`.

**Binary frames.** Header of 14 bytes, big endian: `kind u8 | flags u8 |
ch u32 | seq u64 | data`. Kinds: 1 output (server to client), 2 input
(client to server, Go-Back-N by `seq`), 3 cumulative ack (no data, no
flags). Output flags: 1 reset, 2 replay. Input flag: 1 want ack, answered
with `terminal.input_ack`. Channels `1 … 2^31-1` are allocated by the
client.

**Close codes.** 4001 unsupported version, 4002 protocol violation, 4003
session ended or revoked, 4008 slow consumer, 4503 maintenance or
shutdown.

**Routes.** Capabilities export `Routes() []protocol.Route` from
`realtime.go`, built with
`protocol.Handle[Req, Resp](type, Spec, handler)`. `Spec` holds
`MaxPayload` (default 4 KiB), `Async`, `Timeout` (default 30 s), `Mutates`
and `RateKey`. The payload is decoded strictly and validated (`Validate()`
on the request type) before the handler runs; the handler's context
carries the principal.

**Peer.** `ID() uint64`, `Principal()`, `Context()`, `SendEvent(type,
payload)`, `SendBinary(frame)`. Sends never block. `Context()` ends when
the connection ends, at the latest when its session is revoked.

**Session revocation (condition K6, mandatory).** `internal/realtime`
declares

```go
type SessionValidator interface {
	Authenticate(ctx context.Context, token string) (principal.Principal, error)
	Check(ctx context.Context, p principal.Principal) error
}
type Revocations interface {
	Subscribe(fn func(principal.Revocation)) (cancel func())
}
```

`internal/session` provides both. The guarantees that make an immediate
revocation enforceable:

1. The session service publishes one `Revocation` per ended session,
   synchronously, after the change is committed and before the revoking
   call (logout, session list, password change, lock) returns.
2. The endpoint registers a connection under its session ID before it calls
   `Check` once more and sends `hello`. A revocation in between is either
   delivered to the registered connection or seen by `Check`.
3. On a revocation the endpoint cancels the context of every connection of
   the session at once and closes it with 4003. Running handlers end with
   their context; the terminal stops forwarding output of that connection.
4. Before every message whose `Spec` has `Mutates` set, the dispatcher
   calls `Check`; a failure closes with 4003 and the handler does not run.
5. The periodic re-check stays as a backstop for expiry; it is not the
   revocation path.

`Limiter.Allow(userID, key)` (from `internal/auth`) and
`Auditor.RealtimeCall(ctx, p, type, err)` (from `internal/audit`) are the
other edge interfaces.

**hello.** First message of every connection:
`{"user":{"username","is_admin"},"schema":1,"restorable":[SessionInfo…]}`.

### Message types

Payload types are in `payload_*.go` of `internal/realtime/protocol`.
"As today" means the payload of the Socket.IO event the compatibility shim
maps to, unchanged; the owning package declares it as a Go type with every
member the frontend sends.

| Type | Direction | Owner | Payload | Socket.IO today |
|---|---|---|---|---|
| `hello` | server | `internal/realtime` | `Hello` | `connected`, `ssh_session_restored` |
| `session.keepalive` | client | `internal/realtime` | `Empty` | `keep_alive` |
| `terminal.open` | client | `internal/terminal` | `TerminalOpen` → `TerminalOpened` | `ssh_connect` → `ssh_connected` / `ssh_error` |
| `terminal.cancel` | client | `internal/terminal` | `TerminalCancel` | `ssh_connect_cancel` |
| `terminal.discard_late` | client | `internal/terminal` | `SessionRef` | `ssh_discard_late_connection` |
| `terminal.attach` | client | `internal/terminal` | `TerminalAttach` → `TerminalAttached` | internal on reconnect and reload |
| `terminal.detach` | client | `internal/terminal` | `ChannelRef` | – (tab closed without ending the session) |
| `terminal.close` | client | `internal/terminal` | `SessionRef` | `ssh_disconnect` |
| `terminal.resize` | client | `internal/terminal` | `TerminalResize` | `ssh_resize` |
| `terminal.rename` | client | `internal/terminal` | `TerminalRename` | `save_session_name` |
| `terminal.closed` | server | `internal/terminal` | `TerminalClosed` | `ssh_disconnected` |
| `terminal.timeout_warning` | server | `internal/terminal` | `TerminalTimeoutWarning` | `session_timeout_warning` |
| `terminal.resync_required` | server | `internal/terminal` | `TerminalResync` | `ssh_output_resync_required` |
| `terminal.input_rejected` | server | `internal/terminal` | `TerminalInputRejected` | error ack of `ssh_input` |
| `terminal.input_ack` | server | `internal/terminal` | `TerminalInputAck` | ack of `ssh_input` |
| `prompt.host_key` | server | `internal/terminal` | `PromptHostKey` | `ssh_host_key` |
| `prompt.banner` | server | `internal/terminal` | `PromptBanner` | `ssh_auth_banner` |
| `prompt.closed` | server | `internal/terminal` | `PromptClosed` | `ssh_host_key_closed` |
| `prompt.answer` | client | `internal/terminal` | `PromptAnswer` | `ssh_host_key_decision`, `ssh_auth_banner_decision` |
| `hosts.profile.list` | client | `internal/hosts` | as today | `list_profiles` → `profiles_list` |
| `hosts.profile.save` | client | `internal/hosts` | as today | `save_profile` → `profile_saved` |
| `hosts.profile.delete` | client | `internal/hosts` | as today | `delete_profile` |
| `hosts.profile.organize` | client | `internal/hosts` | as today | `update_profile_organization` |
| `hosts.profile.move` | client | `internal/hosts` | as today | `move_profile` |
| `hosts.jump.list` | client | `internal/hosts` | as today | `list_jump_hosts` |
| `hosts.jump.save` | client | `internal/hosts` | as today | `save_jump_host` |
| `hosts.jump.delete` | client | `internal/hosts` | as today | `delete_jump_host` |
| `hosts.socks.list` | client | `internal/hosts` | as today | `list_socks_proxies` |
| `hosts.socks.save` | client | `internal/hosts` | as today | `save_socks_proxy` |
| `hosts.socks.delete` | client | `internal/hosts` | as today | `delete_socks_proxy` |
| `notes.get` | client | `internal/hostops` | `Empty` → `Note` | `get_notepad` → `notepad_data` |
| `notes.save` | client | `internal/hostops` | `NotesSave` → `Note` | `save_notepad` |
| `keys.list` | client | `internal/vault` | as today | `list_keys` → `keys_list` |
| `keys.upload` | client | `internal/vault` | as today, plus `step_up` and `passphrase` | `upload_key` |
| `keys.rename` | client | `internal/vault` | as today | `rename_key` |
| `keys.replace` | client | `internal/vault` | as today, plus `step_up` and `passphrase` | `replace_key` |
| `keys.delete` | client | `internal/vault` | as today, plus `step_up` | `delete_key` |
| `settings.theme.set` | client | `internal/settings` | `SettingsTheme` | `set_theme` |
| `settings.confirm_close.set` | client | `internal/settings` | `SettingsConfirmClose` | `set_confirm_session_close` |
| `settings.disconnect_action.set` | client | `internal/settings` | `SettingsDisconnectAction` | `set_disconnect_session_action` |

Push events of today (`profiles_list`, `profile_saved`, `keys_list`, …) are
produced by the shim from the result; the server sends none. All other
Socket.IO events are answered by the shim locally with
`not_available_in_preview`.

`SessionInfo` carries the fields of `ssh_connected` and
`ssh_session_restored` plus `last_seq`; empty strings stand for `null`
there and the shim converts them. Terminal sizes are clamped like the
Python release: rows 1–500 (default 24), cols 1–1000 (default 80). Notes
are limited to 100,000 characters (code points, not bytes).

## Step-up

`internal/auth/stepup` is the one step-up service. Every consumer declares

```go
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}
```

(compiled in `internal/ssh/hostkey`, `internal/vault`,
`internal/operations` and `internal/accounts`). A grant is bound to user,
session, action and target, valid for `STEP_UP_MAX_AGE_SECONDS` and
consumed once. Every failure is `step_up_required`.
`principaltest.StepUp` implements the same rules for tests.

### Step-up actions

| Action | Used by |
|---|---|
| `key.upload` | `internal/vault` |
| `key.replace` | `internal/vault` |
| `key.delete` | `internal/vault` |
| `host_key.delete` | `internal/ssh/hostkey` |
| `totp.enroll` | `internal/auth/totp` |
| `totp.delete` | `internal/auth/totp` |
| `passkey.enroll` | `internal/auth/webauthn` |
| `passkey.delete` | `internal/auth/webauthn` |
| `mfa.enable` | `internal/auth` |
| `mfa.disable` | `internal/auth` |
| `recovery.rotate` | `internal/auth` |
| `security_feature.update` | `internal/operations` |
| `user.create` | `internal/accounts` |

## Store

`internal/store` is the only writer of WebSSH's own database.

```go
func Open(ctx context.Context, path string, o Options) (*DB, error)
func (db *DB) Write(ctx context.Context, fn func(*Tx) error) error
func (db *DB) Read(ctx context.Context, fn func(*Tx) error) error
func (db *DB) Apply(ctx context.Context, owner string, ms []Migration) error
func (db *DB) ApplyAll(ctx context.Context, schemas ...Schema) error
func (db *DB) CloseForActivation(ctx context.Context) error
type Migration struct { Version int; SQL string }
type Schema struct { Owner string; Migrations []Migration }
```

- WAL, `foreign_keys = ON`, `trusted_schema = OFF`, `synchronous = FULL`,
  busy timeout. New files get mode 0600.
- `Write` transactions are serialized in the process and start with
  `BEGIN IMMEDIATE`; `Read` runs on read-only connections (`query_only`)
  with a consistent snapshot. The store commits or rolls back; callbacks
  return an error to roll back and never call `Read` or `Write`.
- Every capability has `schema.go` with `Schema()` returning its
  `store.Schema`. Owners are a closed list (`store.Owners`): `accounts`,
  `audit`, `auth`, `authlocal`, `hostkey`, `hostops`, `hosts`, `migrate`,
  `operations`, `session`, `settings`, `stepup`, `terminal`, `totp`,
  `vault`, `webauthn`. `store_` is reserved for the store.
- `Apply` runs each pending migration with its ledger entry in one
  transaction. It refuses an unknown owner, version gaps, an edited or
  removed applied migration (SHA-256 checksum) and any migration that
  creates, changes or drops a schema object outside `<owner>_`, including
  indexes and triggers on another owner's tables.
- A migration does not touch rows of other owners; review checks this,
  the store cannot.
- `CloseForActivation` checkpoints, switches to `journal_mode=DELETE` and
  closes, so only the database file remains.
- `storetest.Open(t, schemas...)` gives tests a real database in a
  temporary directory.

The first build wave (store package) adds crash tests of the activation,
`quick_check`, the re-evaluation of the SQLite driver for writing and any
tuning of the pragmas; the API above stays.

## Keyring

`internal/keyring` (ADR 0008). Compiled now: the closed purpose list
(`ssh_key`, `totp`, `session_token`, `csrf`, `step_up_grant`,
`webauthn_challenge`, `browser_scope`) and `AAD{Table, Column, Row}` with
its encoding `"webssh-aad-v1\x00" + purpose + "\x00" + table + "\x00" +
column + "\x00" + row` (every part non-empty, no NUL). Both are stored
formats and never change.

The ring, built in the first wave:

```go
func Open(secret, material []byte) (*Ring, error)
func (r *Ring) Seal(p Purpose, ad AAD, plain []byte) ([]byte, error)
func (r *Ring) Open(p Purpose, ad AAD, sealed []byte) ([]byte, error)
func (r *Ring) MAC(p Purpose, msg []byte) []byte
func (r *Ring) KeyID() string
func LoadOrCreateMaterial(dataDir string, legacyPresent bool) ([]byte, error)
```

## Session and sign-in

`internal/session` (second wave) provides `Issue(ctx, IssueRequest)
(Session, token string, error)`, `Revoke(ctx, id, reason)`,
`RevokeUser(ctx, userID, reason, except string)`, `List(ctx, userID)`, and
for the transports `Authenticate`, `Check` and `Subscribe` as above. A
token is a random value; only `keyring.MAC(SessionToken, token)` is
stored.

`internal/auth` declares the registries:

```go
type Provider interface {
	Name() string
	Authenticate(ctx context.Context, username, secret string) (userID int64, err error)
}
type Factor interface {
	Kind() string
	Enrolled(ctx context.Context, userID int64) (bool, error)
	Verify(ctx context.Context, userID int64, response jsontext.Value) error
}
```

`internal/auth/local` is a provider; `internal/auth/totp` and
`internal/auth/webauthn` are factors. A provider fails with `auth_failed`
for every wrong combination, with the same timing.

## SSH

`internal/ssh/client` declares what the dialer needs and the types its
callers use: `Target{Owner, Hop, Jumps, Proxy, Display}`,
`Hop{Host, Port, User, Auth, Legacy}`, `Auth{Password, KeyID}`,
`SOCKS{Host, Port}` and

```go
type KeySource interface { Signer(ctx, owner int64, keyID string) (ssh.Signer, error) }         // internal/vault
type HostKeys interface {                                                                       // internal/ssh/hostkey
	Known(ctx, owner int64, host string, port int, key ssh.PublicKey) (bool, error)
	Record(ctx, owner int64, host string, port int, key ssh.PublicKey) error
	Preferred(ctx, owner int64, host string, port int, allowed []string) ([]string, error)
}
type Interaction interface {                                                                    // internal/terminal
	HostKey(ctx, q HostKeyPrompt) (bool, error)
	Banner(ctx, q BannerPrompt) (bool, error)
}
type NetDialer interface { DialContext(ctx, role netpolicy.Role, network, addr string) (net.Conn, error) } // internal/netpolicy
type Shell interface { io.ReadWriteCloser; Resize(rows, cols int) error; Wait() error }
```

- `Known` returns `false, nil` for a host without trust (the user is
  asked) and an error with `host_key_changed` or `host_key_revoked` when
  trust exists but not for this key (refused, no prompt).
- A nil `Interaction` is unattended: unknown keys and banners are refused.
- `(*client.Dialer).OpenShell(ctx, t, ix, rows, cols) (Shell, error)` is the
  terminal's entry; closing the shell closes the whole connection. The
  terminal consumes it through `terminal.Shells`, so its tests use a fake
  shell.

`internal/terminal` declares `Profiles.Resolve(ctx, owner, profileID)
(client.Target, error)`, provided by `internal/hosts`. `client.Display`
carries the profile name and the startup features M1 does not run, so
neither package imports the other.

## Pages

`internal/httpapi` owns `PageData` with every variable of
`templates/*.html`. The page package of the first wave defines it and the
templates together; it is frozen when that package is merged and filled by
the composition root from consumer interfaces of the capabilities. Assets
are copied from `static/` to `internal/httpapi/webassets/` at build time
(ignored by Git, the build fails on an empty directory) and embedded; the
build tag `devfs` reads `static/` directly.

## Migration steps

`internal/migrate/legacy` declares `Step` (entity, version, `Read`,
`Write(ctx, *store.Tx, Sealer)`, `Verify(ctx, *store.Tx, Opener)`,
`Report`), `StepReport` and `Pending`. `Sealer` and `Opener` are satisfied
by `*keyring.Ring`. The migration record holds `coverage` (the steps with
their versions) and `pending` (entities kept in place with their phase and
count).

## End-to-end harness

The seed applier and the test-only hooks live in `internal/e2eseed`. Only
`cmd/webssh/e2e.go`, built with the tag `e2e`, imports it; the release
build of `cmd/webssh` must not depend on it (architecture test).
Test-only switches such as `WEBSSH_E2E_FAST_HASHING` are read only in that
file.

## Modules

`golang.org/x/crypto` may be imported by `internal/migrate/legacy`,
`internal/ssh/…`, `internal/vault` and `internal/auth/local`.
`github.com/coder/websocket` (tier B, ISC, chosen in K6) is added to the
allowlist with the importer `internal/realtime` in the same change that
first imports it: the architecture tests reject allowlist entries for
modules that are not required.
