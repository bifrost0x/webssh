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
	Message    string         // safe to show
	RetryAfter time.Duration  // rate_limited, busy
	Details    map[string]any // optional facts the page acts on, safe to show
	Err        error          // cause, for logs only
}
func New(code Code, message string) *Error
func Wrap(code Code, cause error, message string) *Error
func Status(err error) (httpStatus int, code Code, message string)
func DetailsOf(err error) map[string]any
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
  `result` message: `{"code", "message", "retry_after_ms", "details"}`.
- `details` is optional and an object. It carries what the Python release
  sent beside the error and the page acts on: `requires_confirmation` with
  `organization` (or `profile_id`, `profile_name`, `source_group` when the
  move asks for confirmation) for `hosts.profile.move`, `usages` (display
  strings) for the delete types, and `passphrase_required: true` for
  `keys.upload` and `keys.replace` when the key's passphrase is missing or
  wrong (code `invalid_value`). The shim copies its members into the acknowledgement; they
  never replace `success`, `code` or `error`. Like `Message`, details never
  hold secrets, remote-supplied text or paths, and an error outside the
  catalog sends none.
- Error text never becomes a message: `Error()` must not feed the message
  of `fault.New` or `fault.Wrap`, and transport files of capabilities
  (`http.go`, `http_*.go`, `realtime.go`) do not call it (architecture
  test). The one exception is `internal/realtime/protocol/route.go`, which
  sends the error of `Validate()`; every validator returns fixed texts of
  its own and never includes request values.
- Routes planned but not built in M1 answer
  `501 {"success": false, "code": "not_available_in_preview", "error": …}`.
- One answer leaves the catalog on purpose: a wrong password or code on
  the admin step-up routes is `403 {"code": "invalid_value"}`, because
  `admin.js` retries only on that pair; `internal/auth/stepup/http.go`
  writes it itself (`writeRejected`).

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
| `in_use` | 409 | The item is still in use. |
| `interaction_required` | 502 | The host asks for input that cannot be answered here. |
| `internal` | 500 | An internal error occurred. |
| `invalid_dismissed` | 400 | The acknowledgement list is invalid. |
| `invalid_layout` | 400 | The overview layout is invalid. |
| `invalid_request` | 400 | The request is invalid. |
| `invalid_value` | 400 | A value is not allowed. |
| `last_factor_required` | 409 | At least one second factor must remain. |
| `maintenance` | 503 | The server is in maintenance mode. |
| `mfa_restart` | 400 | The sign-in has expired. Start again. |
| `no_common_algorithm` | 502 | No common SSH algorithm. |
| `not_available_in_preview` | 501 | Not available in this preview yet. |
| `not_found` | 404 | Not found. |
| `precondition_failed` | 412 | The data has changed. Reload and try again. |
| `quota_exceeded` | 413 | Connection storage quota exceeded. |
| `rate_limited` | 429 | Too many attempts. Try again later. |
| `recovery_required` | 403 | Add a replacement factor or turn off MFA to continue. |
| `socks_auth_required` | 502 | The SOCKS5 proxy requires a username and password. |
| `socks_connection_refused` | 502 | The target refused the connection through the SOCKS5 proxy. |
| `socks_host_unreachable` | 502 | The SOCKS5 proxy cannot reach the target host. |
| `socks_network_unreachable` | 502 | The SOCKS5 proxy cannot reach the target network. |
| `socks_not_allowed` | 403 | The SOCKS5 proxy does not allow this connection. |
| `socks_protocol_error` | 502 | The SOCKS5 proxy sent an invalid response. |
| `socks_proxy_failure` | 502 | The SOCKS5 proxy reported a general failure. |
| `socks_proxy_unreachable` | 502 | The SOCKS5 proxy could not be reached. |
| `socks_timeout` | 504 | The SOCKS5 proxy did not respond in time. |
| `socks_ttl_expired` | 504 | The connection through the SOCKS5 proxy timed out. |
| `socks_unsupported` | 502 | The SOCKS5 proxy does not support this request. |
| `ssh_input_backpressure` | 503 | The terminal is not accepting input right now. |
| `ssh_input_too_large` | 413 | The input is too large. |
| `ssh_protocol_error` | 502 | The SSH connection failed. |
| `step_up_failed` | 403 | The confirmation failed. |
| `step_up_required` | 403 | Confirm your identity to continue. |
| `storage` | 500 | The overview settings could not be saved. |
| `storage_error` | 500 | The data could not be stored. |
| `tailscale_route_restricted` | 403 | This target is on the tailnet and requires Tailscale SSH. |
| `target_blocked` | 403 | The network policy does not allow this target. |
| `timeout` | 504 | The connection timed out. |
| `too_large` | 413 | The request is too large. |
| `unavailable` | 503 | The service is unavailable. |
| `unknown_type` | 400 | Unknown message type. |
| `unreachable` | 502 | The host could not be reached. |
| `validation_error` | 400 | The data is invalid. |
| `version_unsupported` | 400 | Reload the page to use the current version. |

The codes the Python release sends and the frontend matches on
(`step_up_required`, `rate_limited`, `csrf_expired`, `mfa_restart`,
`last_factor_required`, `host_key_changed`, `host_key_not_accepted`,
`auth_banner_declined`, `ssh_input_too_large`, `ssh_input_backpressure`,
`busy`, `maintenance`, `unavailable`, `storage_error`, `invalid_request`,
`invalid_value`, `not_found`, `recovery_required`,
`tailscale_route_restricted` and the `socks_*` codes) keep their spelling.
`recovery_required` is the refusal of a recovery session on every API
route outside factor repair, with the Python text; the frontend does not
match on it, its spelling is kept for scripts. The `hosts.*` types keep the codes
of the Python handlers: `in_use` (with `details.usages`),
`validation_error` and `quota_exceeded`. `PUT /api/overview/preferences`
keeps the codes of the Python route: `invalid_layout`,
`invalid_dismissed` and `storage`.

`tailscale_route_restricted` is every refusal by the tailnet rule of the
network policy (cause `netpolicy.ErrTailnetRestricted`); the page shows its
own hint and links admins to the setting. The `socks_*` codes are those of
`app/socks5_client.py`; their HTTP status is that of the general code the
failure had before (`unreachable`, `timeout`, `target_blocked`,
`auth_failed`). `socks_auth_rejected` and `socks_auth_failed` join the
catalog together with SOCKS5 username and password authentication, which
M1 does not offer.

## Realtime protocol

`internal/realtime/protocol`, schema `webssh.v1`, WebSocket subprotocol
`webssh.v1`.

**Endpoint.** `GET {APPLICATION_ROOT}/ws` (WebSocket upgrade, subprotocol
`webssh.v1`). `{APPLICATION_ROOT}/socket.io/` answers 410. The page derives
the URL from its application root; no other path is used.

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

Input sequences start at 1 per channel and attachment. The server accepts
input frame `s` only if `s` equals the next expected sequence `e`; any
other frame is dropped silently. When it refuses frame `e` (rate limit,
full queue), it sends exactly one
`terminal.input_rejected {ch, iseq: e, code, retry_after_ms}` and from
then on drops every frame until a frame with sequence `e` arrives; that
frame is evaluated afresh and may be refused again. An accepted frame with
the want-ack flag is answered with exactly one
`terminal.input_ack {ch, iseq}`, a refused one only with the rejection.
The client resends from `e` and ignores rejections until it has sent `e`
again.

The maximum data length of an input frame is `SSH_INPUT_MAX_BYTES`
(default 128 KiB, range as in the Python release). The page receives the
same value in `websshRuntimeLimits.sshInput.maxEventBytes`, and the
server's `DecodeFrame(…, maxData)` uses it; a larger frame closes the
connection with 4002.

**Close codes.**

| Close code | Meaning | Client |
|---|---|---|
| 1013 | connection limit reached; the reason starts with `connection_limit_user:` or `connection_limit_server:` and is readable text | `connect_error` with `data.code = connection_limit` and the reason, retry with backoff |
| 4001 | no common schema version; reason `supported: webssh.v1` | `socket_protocol_mismatch`, no retry |
| 4002 | malformed frame or envelope | retry with backoff |
| 4003 | session ended, revoked or never valid; the reason is the `principal.Reason` value, otherwise `session_ended` | `io server disconnect` or `connect_error` with `authentication_required`, no retry |
| 4008 | slow consumer | retry with backoff |
| 4503 | maintenance or shutdown | retry with backoff |

The 1013 refusal accepts the upgrade, echoes the offered subprotocol and
closes at once; at most `RejectSlots` such connections exist at a time,
beyond that the request gets HTTP 503 with `Retry-After`.

**What a browser can see.** A browser cannot read the status of a refused
upgrade, and it fails a handshake that does not echo an offered
subprotocol with 1006. In M1:

1. A refused origin (403), a missing, invalid or expired session cookie
   (401), a recovery session (403), shutdown (503) and the server-wide
   limit beyond `RejectSlots` (503) are answered before the upgrade; there
   are no unauthenticated upgrades. The page sees an ordinary failed
   connection and retries with backoff. After repeated failures the shim
   asks `GET {APPLICATION_ROOT}/api/realtime/status` (same origin,
   `Cache-Control: no-store`, changes nothing):
   - `401 {"success": false, "code": "authentication_required", "error",
     "authenticated": false, "recovery": false, "schema": 1,
     "subprotocols": ["webssh.v1"]}` without a valid session: the page goes
     to the sign-in at once;
   - `200 {"success": true, "authenticated": true, "recovery": <bool>,
     "schema": 1, "subprotocols": ["webssh.v1"]}` otherwise; a different
     `schema` or `recovery: true` makes the page reload.
   The shim side comes with D4.
2. 4001 is sent only after an upgrade with a common subprotocol, so a
   request without one reaches the page as 1006 and is retried like (1).
   The shim also treats an open connection without `webssh.v1` as 4001.
3. 4003 before or after `hello` ends reconnecting.

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
   For the reasons `logout`, `password_changed`, `factor_changed`,
   `account_locked` and `role_changed` the terminal (`Manager.Revoked`)
   also ends every terminal session and pending attempt of the account,
   as the Python release closed every socket and SSH connection of the
   account on logout; on `password_changed` this includes the tmux
   sessions once D6 runs them. The other reasons end only the connections
   of the session.
4. Before every message whose `Spec` has `Mutates` set, the dispatcher
   calls `Check`; a failure closes with 4003 and the handler does not run.
5. The periodic re-check stays as a backstop for expiry; it is not the
   revocation path.

`Limiter.Allow(userID, key)` (from `internal/auth`) and
`Auditor.RealtimeCall(ctx, p, type, err)` (from `internal/audit`) are the
other edge interfaces.

The server is wired by the composition root:

```go
func NewServer(cfg Config, deps Deps) (*Server, error)
func (s *Server) Mount(routes ...protocol.Route)
func (s *Server) HandleBinary(h BinaryHandler) // type BinaryHandler func(peer protocol.Peer, frame []byte) error
func (s *Server) SetRestorer(r Restorer)
func (s *Server) OnKeepalive(f func(protocol.Peer))
func (s *Server) OnClose(f func(protocol.Peer))
func (s *Server) Shutdown(ctx context.Context) error // closes with 4503
type Restorer interface {
	Restorable(ctx context.Context, p principal.Principal) ([]protocol.SessionInfo, error)
	Persistent(ctx context.Context, p principal.Principal) ([]protocol.SessionInfo, error)
}
```

`Restorer` is the source of `hello.restorable` and `hello.persistent`
(`internal/terminal`).
`session.keepalive` is registered by the endpoint itself; it calls the
`OnKeepalive` hooks (the terminal updates `last_activity`). `OnClose` runs
once per connection after it ended and all its handlers returned.
`HandleBinary` has one owner (the terminal) and runs on the read loop, as
do routes without `Async`. All registrations happen before the first
request; a later one panics.

**hello.** First message of every connection:
`{"user":{"username","is_admin"},"schema":1,"restorable":[SessionInfo…],"persistent":[SessionInfo…]}`.
`persistent` lists the account's detached persistent (tmux) sessions; the
shim sends one `persistent_session_available` per entry, with the fields
of the Python event, before `connected`.

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

`terminal.open` and `terminal.attach` bind channel `ch` before they
return. For `terminal.attach` the server sends every replay frame (flag
`replay`, the first one also `reset` when `full`) before the `result`;
their sequences are at most `result.seq`. Live output of the same session
may follow at any time after the binding, also before the `result`, always
with sequences above `result.seq` and in order. For `terminal.open`,
output may arrive before the `result`. `terminal.close` ends the session;
the server sends `terminal.closed` to every connection the session was
attached to, the requesting one included. After
`terminal.resync_required` the channel is unbound on the server;
`terminal.detach` for it is a no-op.

`terminal.open` carries the tmux fields of `ssh_connect` in its target
(`use_tmux`, `tmux_session_name`, at most 256 bytes) and `replacement_of`,
the session a reconnecting tab replaces. The shim sends them once the
terminal runs tmux sessions (D6).

`SessionRef` is `{session_id, request_id?}`. `terminal.discard_late`
discards a session only for the connection whose `terminal.open` created
it and only with that open's `request_id` (Python matched
`client_request_id`); otherwise it answers `not_found`. The shim maps
`client_request_id` to `request_id`. `terminal.close` ignores
`request_id`. A full session quota answers `busy`, as the Python release
did.

`terminal.cancel` answers `ok` when the attempt was cancelled, `not_found`
when no attempt with that `request_id` exists, and `conflict` when the
attempt already produced its session (the shim reports `cancelled: true`,
`reason: 'not_found'` and `reason: 'already_committed'`).

### Result forms

The payloads marked "as today" carry exactly the members the frontend
sends today (`profile-manager.js`, `jump-host-manager.js`,
`socks-proxy-manager.js`, `app.js`). C4 and C5 declare them as Go types in
`payload_hosts.go` and `payload_keys.go` and pin the member list with a
test. The result `p` is the success payload of the Python release without
`success`:

| Type | Request | Result `p` |
|---|---|---|
| `hosts.profile.list` | `Empty` | `{profiles: [Profile]}` |
| `hosts.profile.save` | `Profile` (every field the profile form sends; the client drops `tailscale_authorized`) | `{profile: Profile}` |
| `hosts.profile.delete` | `{profile_id}` | `{}` |
| `hosts.profile.organize` | `{profile_id, group?, favorite?}` | `{profile: Profile}` |
| `hosts.profile.move` | `{profile_id, target_group, target_index, expected_source_group, confirm_source_group_removal}` | `{requires_confirmation: false, organization: [{id, group, sort_order, updated_at?}]}` |
| `hosts.jump.list` | `Empty` | `{jump_hosts: [JumpHost]}` |
| `hosts.jump.save` | `{jump_host_id?, name, host, port, username, auth_type, key_id?}` | `{jump_host: JumpHost}` |
| `hosts.jump.delete` | `{jump_host_id}` | `{}` |
| `hosts.socks.list` | `Empty` | `{socks_proxies: [SOCKSProxy]}` |
| `hosts.socks.save` | `{socks_proxy_id?, name, host, port, username, auth_type, remote_dns}` | `{socks_proxy: SOCKSProxy}` |
| `hosts.socks.delete` | `{socks_proxy_id}` | `{}` |
| `keys.list` | `Empty` | `{keys: [KeySummary]}` |
| `keys.upload` | `{name, key_content, passphrase?, step_up?}` | `{key: KeySummary}` |
| `keys.rename` | `{key_id, name}` | `{key: KeySummary}` |
| `keys.replace` | `{key_id, key_content, passphrase?, step_up?}` | `{key: KeySummary}` |
| `keys.delete` | `{key_id, step_up?}` | `{}` |
| `settings.theme.set` | `SettingsTheme` | `{theme}` |
| `settings.confirm_close.set` | `SettingsConfirmClose` | `{enabled}` (stored value) |
| `settings.disconnect_action.set` | `SettingsDisconnectAction` | `{action}` (stored value) |

For deletes the shim adds the IDs of the request to the acknowledgement.
Failures the page acts on carry `err.details` (see Errors). The page
reads the move result from `organization`; a move that would empty its
source group fails with `details {requires_confirmation: true,
profile_id, profile_name, source_group}`.

The payload types are those of `payload_hosts.go` and `payload_keys.go`.
`keys.upload` and `keys.replace` accept up to `protocol.MaxKeyPayload`
(192 KiB: the key of at most 64 KiB, its passphrase and the step-up
grant); every other type keeps the default of 4 KiB. `hosts.*` failures
keep the Python codes (`in_use`, `validation_error`, `quota_exceeded`).

The shim's catalog entries may carry `answeredByPage(failure)`: a failure
the page answers itself (the step-up and passphrase questions of the key
dialog) is then not repeated as an `error` event. Every other failure of
an entry with `errorEvent` is sent as `error` with all members of the
rejection (`details`, `retry_after_ms`).

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
session, action and target, valid for a fixed 300 seconds as in the Python
release, and consumed once. `STEP_UP_MAX_AGE_SECONDS` (60–900) is only the
window of the shortcut: a session that authenticated with MFA or a passkey
within it gets a grant without a new proof. Every failure is
`step_up_required`. `principaltest.StepUp` implements the same rules for
tests.

Own-account actions (`totp.enroll`, `passkey.enroll`, `mfa.enable`,
`mfa.disable`, `recovery.rotate`, `key.upload`) take the user id as their
target when the request has none and refuse any other. `key.replace` and
`key.delete` take the `key_id`; the vault checks ownership before
`Consume`. Both URL families exist: the account family
`/api/account/step-up/…` (`security-ui.js`) and the admin family
`/api/step-up/…` (`admin.js`).

`*stepup.Service` takes its dependencies as consumer interfaces:
`Sessions.Assurance(ctx, p) (SessionAssurance{Level, StrongAt, Methods},
error)` (from `internal/session`), `Passwords{HasPassword,
VerifyPassword}` (from `internal/auth/local`, the same time for every
wrong password), `TOTP`, `Passkeys{Enrolled, AssertionOptions,
VerifyAssertion}` (D1; nil until then, so passkeys are never offered),
`auth.Accounts`, `auth.Gates`, `auth.Audit` and the per-action
`Targets[action]` checks (`totp.delete` → `(*totp.Service).OwnsTarget`;
D1 sets `passkey.delete`). It satisfies every `StepUp` interface above
structurally; the composition root (D4) asserts that at compile time,
because capabilities do not import each other.

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
func (db *DB) Close() error
func (db *DB) QuickCheck(ctx context.Context) error
func (db *DB) IntegrityCheck(ctx context.Context) error
func (db *DB) Path() string
func OpenReadOnly(ctx context.Context, path string, mode ReadOnlyMode) (*sql.DB, error)
type Options struct { BusyTimeout time.Duration; MaxReaders int }
type Migration struct { Version int; SQL string }
type Schema struct { Owner string; Migrations []Migration }
var ErrCorrupt, ErrNotRegular, ErrMigration error
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
  closes, so only the database file remains. `Close` does the same at
  shutdown and waits for a running write and running reads first; a
  stopped Go leaves only the database file.
- `QuickCheck` and `IntegrityCheck` run the SQLite checks and fail with
  `ErrCorrupt`. `Open` refuses a path that is not a regular file in a
  directory (`ErrNotRegular`); `Apply` fails with `ErrMigration` for an
  invalid migration. `OpenReadOnly` opens an existing database with
  `mode=ro`, `query_only` and `trusted_schema = OFF` and never creates it
  (migration reader).
- `storetest.Open(t, schemas...)` gives tests a real database in a
  temporary directory.

Crash tests of the activation and of a write cut off by SQLite, and the
driver version that rolls back such a write completely, are in place
(first wave).

## Keyring

`internal/keyring` (ADR 0008). Compiled now: the closed purpose list
(`ssh_key`, `totp`, `session_token`, `csrf`, `step_up_grant`,
`webauthn_challenge`, `browser_scope`, `feature_approval`) and `AAD{Table, Column, Row}` with
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
func (r *Ring) Verify(storedKeyID string) error
func (r *Ring) BrowserScope(userID int64, username, generation string) string
func NewRotation(from, to *Ring, legacyPurged bool) (*Rotation, error)
func (rt *Rotation) Reseal(p Purpose, ad AAD, sealed []byte) ([]byte, error)
func LoadOrCreateMaterial(dataDir string, legacyPresent bool) ([]byte, error)
func MoveMaterialToGo(dataDir string, r *Ring, storedKeyID string, record func() error) error
func MoveMaterialToState(dataDir string, r *Ring, storedKeyID string) (moved bool, err error)
const GoDirName, DatabaseName, LogsDirName, StateDirName, MaterialName
const MaterialSize = 32
const MinSealedSize = …
```

- Purposes per operation: `Seal` and `Open` take `ssh_key`, `totp` and
  `webauthn_challenge`; `MAC` takes `session_token`, `csrf`,
  `step_up_grant` and `feature_approval` (the five-minute impact approval
  of a security feature change, never stored); `browser_scope` is only the name of the derivation
  behind `BrowserScope` (the browser-local namespace, bit-identical to the
  Python release). `Seal` and `Open` fail with `ErrPurpose` for any other
  purpose; `MAC` with another purpose is a programming error and panics.
- Errors: `ErrSecret`, `ErrMaterialSize`, `ErrFormat`, `ErrWrongKey`,
  `ErrDecrypt`, `ErrKeyMismatch` (from `Verify`), `ErrPurpose`, `ErrAAD`,
  `ErrMaterialMissing`, `ErrMaterialConflict`, `ErrMaterialFile`,
  `ErrRotationLegacy`, `ErrRotationMaterial`, `ErrRotationSameKey`.
- `LoadOrCreateMaterial` never recreates missing material when data
  exists, and never removes material before a copy is verified.
  `MoveMaterialToGo` moves it from `logs/.webssh-go/` to `go/` after
  `webssh legacy purge`, crash-safe and idempotent; `record` notes
  "material in go/" in the database and must be idempotent too.
- `MoveMaterialToState` is the reverse move of condition F2: legacy data
  exists but the material lies only in `go/` (copied by hand, or a Python
  backup restored onto a new installation). It moves the material to
  `logs/.webssh-go/` crash-safe and reports whether it moved anything;
  nothing that could export decryptable material starts before it.
- The keyring stores neither the key ID nor that note: there is no owner
  `keyring`. Both are in `migrate_keyring(key_id, material_in_go)` of the
  migration record; on an installation that never had Python data the
  composition root writes the row at the first start with
  `legacy.RecordKeyID`.
- The file names have one exported source, the constants above in
  `internal/keyring`: `go/`, `go/webssh.db`, `logs/`, `logs/.webssh-go/`,
  `keyring-material`. No package spells them a second time.

## Configuration

`internal/config` (first wave) reads the documented environment variables
with the meaning they have in the Python release.

```go
type LookupFunc func(name string) (string, bool)
func ResolveDataDir(lookup LookupFunc) (string, error)
func ResolveSecretKey(dataDir string, lookup LookupFunc) (SecretResolution, []Warning, error)
func Load(lookup LookupFunc) (Config, []Warning, error)
func Bootstrap(lookup LookupFunc, prepare func(dataDir string) error) (Config, []Warning, error)
func (c Config) Explicit(name string) bool
```

- The order is `ResolveDataDir` → `platform.PrepareDataDir` →
  `ResolveSecretKey` → `Load`, as `Bootstrap` runs it; the composition
  root (D4) calls `Bootstrap` with `platform.PrepareDataDir` and does not
  reorder the steps.
- `Config` holds only the settings this preview acts on; every other
  documented variable is still validated like the Python release.
  `Explicit(name)` says a variable was set to a non-blank value.
- In the container the port stays 5000 (`serve --bind 0.0.0.0:5000`),
  whatever `HOST` and `PORT` say.
- Consumers that compare client addresses with `TRUSTED_PROXY_CIDRS` or
  `SSH_ALLOWED_INTERNAL_NETWORKS` normalize them with `Unmap()` first
  (C1).
- `netpolicy.Tailnet.InterfaceConfigured` is
  `cfg.Explicit("TAILSCALE_SSH_INTERFACE")`; D4 sets it when it builds
  the network policy.
- `BACKUP_TEMP_DIR` is registered as inert today; `Config` offers its
  resolved value with D4, which passes it to `legacy.Options.BackupTempDir`
  (restore-state probes of the migration).

## HTTP edge

`internal/httpapi` (second wave) is the HTTP edge in front of every route.

```go
func New(o Options) (*Handler, error) // Options{Config, Sessions, MAC, Assets, Renderer, ErrorPageData, Readiness, Logger}
func (h *Handler) Mux() *http.ServeMux
func (h *Handler) Finish() (filled []string, err error)
func (h *Handler) SessionCookie() SessionCookie // Set(w, token, expires), Clear(w), Name()
func ConfigureServer(srv *http.Server)
func CSRFToken(r *http.Request) string
func BrowserBinding(r *http.Request) string
func ClientAddr(r *http.Request) netip.Addr
func Origin(r *http.Request) (scheme, host string) // realtime.OriginPolicy.Self
func BasePath(r *http.Request) string
type SessionValidator interface {
	Authenticate(ctx context.Context, token string) (principal.Principal, error) // as in realtime
}
type Readiness struct { Maintenance, Stopping func() bool; Database Pinger; DataDir string }
```

- Pipeline: client address, security headers, admin gate (404 while
  `ADMIN_PANEL_ENABLED` is false), preview routes (501 before the body is
  read), per-request deadlines (none for `/ws`), body limit, session,
  access level, origin, CSRF, handler.
- Capabilities register on `Mux()` with patterns relative to
  `APPLICATION_ROOT`; wildcard names do not matter. A pattern outside the
  route catalog is refused at run time. `Finish()` runs at start; every
  catalog route without a handler then answers 501, so an unwired package
  stays closed.
- Access levels: `AccessPublic` (no session needed; a valid one is still
  put into the context, unsafe methods still need CSRF and same origin),
  `AccessUser`, `AccessRepair` (also a recovery session: factor repair,
  settings page, sign-out), `AccessAdmin`, `AccessUpgrade` (`/ws` checks
  origin and session itself), `AccessProbe` (`/health`, `/ready`, static
  files), `AccessPreview` (501).
- An API request without a valid session gets `401
  authentication_required` and the session cookie is cleared; a page
  request is redirected to the sign-in. A recovery session on other APIs
  gets `403 recovery_required`. A failure of the session store is `503
  unavailable`, never anonymous access.
- CSRF tokens are MACs (purpose `csrf`) bound to the browser binding
  cookie `<SESSION_COOKIE_NAME>_binding`; an unsafe request from another
  origin is `403`. A handler that issues or ends a session answers with a
  redirect or JSON, never with a form in the same response, because that
  form's token would belong to the old binding.
- Client address: forwarding headers count with `TRUSTED_PROXIES` (hops
  like Werkzeug's ProxyFix) only when the direct peer is in
  `TRUSTED_PROXY_CIDRS`, and every address the hop count skips must be in
  the CIDRs too; otherwise the first address outside is the client.
  Addresses are compared after `Unmap()`. Malformed forwarded values are
  ignored and logged once.
- `/health` and `/ready` keep the Python bodies and order
  (`maintenance`, `runtime`, `database`, `data_directory`).
- `GET /api/realtime/status` is the session status for the realtime
  client (see "What a browser can see").

Visible changes against the Python release: the binding cookie, 401
instead of a redirect for API requests without a session, 403 for a
cross-origin unsafe request, and `connect-src 'self'` in the CSP.

## Session and sign-in

`internal/session` (second wave):

```go
func New(db *store.DB, mac MAC, accounts Accounts, durations Durations) *Service
func (s *Service) Issue(ctx, IssueRequest) (Session, string, error)
func (s *Service) IssueTx(ctx, tx *store.Tx, IssueRequest) (Session, string, error)
func (s *Service) Authenticate(ctx, token string) (principal.Principal, error)
func (s *Service) Check(ctx, p principal.Principal) error
func (s *Service) Validate(ctx, token string) (Session, error)
func (s *Service) Lookup(ctx, id string) (Session, error)
func (s *Service) List(ctx, userID int64) ([]Session, error)
func (s *Service) Revoke(ctx, id string, reason principal.Reason) error
func (s *Service) RevokeUser(ctx, userID int64, reason principal.Reason, except string) (int, error)
func (s *Service) RevokeUserTx(ctx, tx, userID, reason, except) ([]principal.Revocation, error) // then Publish
func (s *Service) RevokeSessionsTx(ctx, tx, userID int64, ids []string, …) ([]principal.Revocation, error)
func (s *Service) RevokeAll(ctx, reason principal.Reason) (int, error) // revoke-all epoch
func (s *Service) Publish(revs []principal.Revocation)
func (s *Service) ClearRecovery(ctx, id, replacement string, mfaOff bool) (bool, error)
func (s *Service) Subscribe(fn func(principal.Revocation)) (cancel func())
func (s *Service) Sweep(ctx) (int, error)
type Accounts interface { Standing(ctx, userID int64) (Standing, error) }       // internal/accounts
type Durations interface { SessionMinutes(ctx, userID int64) (int, error) }     // internal/settings
```

A token is 32 random bytes; only `MAC(session_token,
"webssh-session-v1\0"+token)` is stored. A session is bound to the
account's `auth_generation` and to the installation's revoke-all epoch.
Revocations are published after the commit and before the revoking call
returns. HTTP: `GET /api/account/sessions`, `POST
/api/account/sessions/revoke`.

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

`internal/auth/local` is a provider (Argon2id, migrated bcrypt hashes
verify and are rehashed); `internal/auth/totp` and `internal/auth/webauthn`
are factors. A provider fails with `auth_failed` for every wrong
combination, with the same timing per hash kind.

`auth.Flow` runs `/login`, `/login/cancel`, `/register`, `/logout` and
`/change-password` (`Register(mux)`). Second factors finish a pending
sign-in through `PendingUser(r) (int64, error)`,
`CompletePending(w, r, userID, method, assurance) (continuation string,
error)` and `DiscardPending(r, flashes…)`; D4 renders flashes with
`TakeFlashes` and `AddFlash`. A pending sign-in is not a principal; it
lives in `auth_pending`, bound to the browser binding, five minutes, at
most five per user. Its consumer interfaces: `Passwords`, `Gates`,
`SignInSettings{RegistrationEnabled, LoginLimits}` (C6), `Auditor`
(`internal/audit`), `Pages` (D4 adapts `httpapi.Renderer`),
`SessionCookie` (`httpapi.SessionCookie`), `Binding`
(`httpapi.BrowserBinding`), `ClientAddr` (`httpapi.ClientAddr`).

The factor side of `internal/auth`, `internal/auth/totp` and
`internal/auth/stepup` declares:

- `auth.Accounts{MFARequired, SetMFARequired}` with `*store.Tx`, so a
  factor change and the flag commit together (`internal/accounts`);
- `auth.RecoverySessions.EndRecovery(ctx, tx, sessionID, replacement,
  basic)` (`internal/session`);
- `auth.PendingSignIn{Pending, Complete, Discard}`; D4 adapts
  `auth.Flow` to it (`Complete` returns the public continuation with
  `APPLICATION_ROOT`);
- `auth.Gates.Active(ctx, feature)` (`(*operations.Gates).Active`);
- `auth.Audit.Security(ctx, level, event, kv…)`; D4 adapts
  `*audit.Logger` (`Security` for info, `SecurityWarning` for warnings);
  without one it logs through slog;
- `auth.DurableFactor`, `auth.FactorRemover` per factor kind.

The sign-in forms and the factor routes share one `auth.Limiter`
(sliding window, bounded memory); the factor routes use it through
`auth.RuleLimiter` in `auth.FactorLimits{Limiter, Enabled, Login, Reauth,
ClientAddr}`. The realtime endpoint gets a second, separate instance
through `auth.Realtime`, so realtime traffic cannot use up the sign-in
budget.

The auth store has one owner `auth` with one ordered migration list in
`internal/auth/schema.go` (pending sign-ins, then recovery codes and
`auth_mfa_throttle`); a test in `internal/store` applies every production
schema together.

`internal/accounts` keeps `accounts_users` (with `managed_by`),
`accounts_id_floor` and `accounts_quarantine`, applies ADMIN_USERS variant
B (`Normalize` before serving) and offers `RaiseIDFloorTx` and
`SetMFARequiredTx` to D2 and C3. `internal/operations` keeps the feature
gates (`Status`, `All`, `Active`); its impact approval is a MAC of
purpose `feature_approval`, bound to feature, administrator, session and
state digest for five minutes.

D4 wires `Accounts.Normalize` before serving, `Sessions.Sweep`
periodically, and `audit.Open(DATA_DIR/logs, …)` with
`AUDIT_LOG_MAX_BYTES` and `audit_backup_count`.

## SSH

`internal/ssh/client` declares what the dialer needs and the types its
callers use: `Target{Owner, Hop, Jumps, Proxy, Display}`,
`Hop{Host, Port, User, Auth, Legacy}`, `Auth{Password, KeyID}`,
`SOCKS{Host, Port, RemoteDNS}` and

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
type Network interface {                                                                        // internal/netpolicy
	NetDialer
	DialRelay(ctx, role netpolicy.Role, network, addr string) (net.Conn, error)
	JumpDestination(ctx, host string, port int, relay bool) (string, error)
	SOCKSDestination(ctx, host string, port int, remoteDNS bool) (string, error)
}
type Shell interface { io.ReadWriteCloser; Resize(rows, cols int) error; Wait() error }
```

- `Known` returns `false, nil` for a host without trust (the user is
  asked) and an error with `host_key_changed` or `host_key_revoked` when
  trust exists but not for this key (refused, no prompt).
- A nil `Interaction` is unattended: unknown keys and banners are refused.
- `Network` is the network policy as the dialer uses it (ADR 0010, every
  hop separately); `*netpolicy.Policy` provides it and `Dialer.Net` is
  required. `DialRelay` connects to a jump host or SOCKS5 proxy under the
  tailnet relay rule. `JumpDestination` returns what a jump host is asked
  to reach; `relay` marks a further jump host, which passes the relay rule
  too. `SOCKSDestination` returns what a proxy is asked to reach; with
  `remoteDNS` a name may go to the proxy unresolved where
  `BLOCK_INTERNAL_SSH` and `SOCKS_REMOTE_DNS_ALLOWLIST` permit it.
- `SOCKS.RemoteDNS` is the proxy's `remote_dns` setting. The Python
  default is true; `internal/hosts` (C4) fills it from the stored proxy,
  because the zero value means local resolution.
- Refusals of the policy carry `target_blocked`, those of the tailnet rule
  `tailscale_route_restricted`; SOCKS5 failures carry their `socks_*`
  code. The remote text stays in the cause.
- `(*client.Dialer).OpenShell(ctx, t, ix, rows, cols) (Shell, error)` is the
  terminal's entry; closing the shell closes the whole connection. The
  terminal consumes it through `terminal.Shells`, so its tests use a fake
  shell.

`internal/terminal` declares `Profiles.Resolve(ctx, owner, profileID)
(client.Target, error)`, provided by `(*hosts.Service).Resolve`, and the
optional `SavedRoutes{JumpHost(ctx, owner, id) (client.Hop, error),
SOCKSProxy(ctx, owner, id) (client.SOCKS, error)}` for a connection typed
by hand that names a saved jump host or proxy (`jump_host_id`,
`socks_proxy_id` without `profile_id`); D4 adapts `internal/hosts` to it,
and without a provider such a connection answers
`not_available_in_preview`. `client.Display` carries the profile name and
the startup features M1 does not run, so neither package imports the
other. The terminal is wired with `terminal.New(FromConfig(cfg.Terminal),
Deps{Shells, Profiles, Routes, Log})`, `Mount(m.Routes()…)`,
`HandleBinary(m.HandleBinary)`, `SetRestorer(m)`,
`OnKeepalive(m.Keepalive)`, `OnClose(m.PeerClosed)` and
`sessions.Subscribe(m.Revoked)`; at shutdown the realtime server stops
first, then the terminal. Persistent tmux sessions (D6) need
`Deps{Connections, DB, TmuxEnabled}` and `Config.TmuxPrefix`;
`Deps.Audit` (`SecurityWarning`, from `*audit.Logger`) receives
`TMUX_SESSION_NOT_ENDED`, and `*terminal.Manager` is the
`hosts.PersistentSessions` of `internal/hosts`.

`internal/ssh/hostkey` declares
`Targets.SSHTargets(ctx, owner) ([]hostkey.Target, error)` for the
`/effective` and `/deletion-impact` views. `internal/hosts` may not import
`internal/ssh/hostkey`; it offers `(*hosts.Service).SSHTargets(ctx,
owner) ([]hosts.Endpoint, error)` with the same fields, and D4 adapts it. `(*hostkey.HTTP).Register(mux)` adds
its routes relative to `APPLICATION_ROOT`; the HTTP edge (C1) puts session,
CSRF and origin checks in front and the principal into the context.
Deleting a host key needs the step-up `host_key.delete`. Host keys are
stored per scope as whole files (`hostkey_files(scope, user_id, raw,
modified_us)`); the migration (D2) takes them over with
`hostkey.ImportFile(ctx, tx, scope, owner, raw, modified)`, which
validates like the Python release, stores the file byte for byte and stops
with an `*InvalidFileError` naming the line.

`internal/vault` is the one parser of private keys. It does not import
`internal/ssh/client` (package map) and parses with
`golang.org/x/crypto/ssh` itself; `internal/ssh/client` has no key parser
and receives ready signers through `KeySource`, which `*vault.Service`
provides (`Signer`). The vault also provides `hosts.Keys.HasKey(ctx,
owner, keyID) (bool, error)`: true for a stored key of that owner,
usable or not, so saved hosts and jump hosts can refer to it. New
uploads refuse RSA below 1024 bits and protected OpenSSH keys with more
than 128 bcrypt rounds; migrated keys are not refused for that
(migration specification 4.8). D2 imports keys with
`vault.ImportKey(ctx, tx, sealer, Imported{…})` in the order of
`keys.json` (column `seq`).

`internal/hosts` takes `Service{DB, Keys, Limits, Persistent}`. The
optional `PersistentSessions.UsingSOCKSProxy(ctx, owner, proxyID) (count,
labels, error)` (D6, from the terminal's tmux sessions) blocks deleting a
SOCKS5 proxy that a persistent session still needs; without a provider
nothing blocks. D2 imports with `hosts.Import(ctx, tx, owner, Legacy,
limits)` and `hostops.ImportNote`.

## Settings and overview

`internal/settings` owns application and user settings. Application
settings are rows of `settings_app(key, value, source, rule, updated_us)`
with `source` `admin`, `migrated` or `materialised`; user settings are
`settings_user(user_id, key, value)`. The settings derived from the
Python behaviour (migration specification, section 6) are written only by
`settings.MaterialisePolicies` with `source = 'materialised'`:
`permission.hosts.discovery` and `permission.hosts.reachability` (role
rights stay settings until the role model of B2/B3; `Granted(roles, role,
admin)` always grants admins), `ssh.legacy_algorithms` and
`origin.ignore_scheme`. The origin setting has no second copy elsewhere;
D4 applies it to `OriginPolicy.IgnoreScheme` and the origin check of the
HTTP edge only while `realtime.KeepLegacySchemeRule` still holds for the
current configuration, and otherwise reports once that it has no effect.

Consumer interfaces, adapted by D4:

- `settings.FeatureGates.FeatureActive(ctx, feature)` (from
  `(*operations.Gates).Active`);
- `settings.Scoper` (`*keyring.Ring`), `settings.Account{ID, Username,
  HistoryGeneration}` (from `accounts_users`; an empty generation fails
  the page closed), `settings.TourDeployment`;
- `hostops.Inventory.OverviewInventory(ctx, owner) (OverviewInventory,
  error)` from `internal/hosts` and `internal/vault`;
- `hostops.HostTrust.Trusted(ctx, owner, host, port) (bool, error)` from
  `internal/ssh/hostkey` (host canonicalised as `canonicalize_hostname`; an
  invalid host is `false, nil`).

`settings.New(db, Environment{Values, Explicit, Production,
AuditBackupCount})` is filled from `internal/config`. The page data takes
`settings.Page` values as typed Go values; `html/template` encodes the
JSON blocks as usual (no `template.JS`). Specs that compared the bytes of
Python's `json.dumps` are rewritten to check behaviour (D5).

## Pages

`internal/httpapi` owns `PageData` with every variable of
`templates/*.html`. The page package of the first wave defines it and the
templates together; it is frozen when that package is merged and filled by
the composition root from consumer interfaces of the capabilities. Assets
are copied from `static/` to `internal/httpapi/webassets/` at build time
(ignored by Git, the build fails on an empty directory) and embedded; the
build tag `devfs` reads `static/` directly. Every build and test of the Go
module therefore runs `scripts/stage-webassets.sh` first: the CI jobs, the
image build (`deploy/docker/Dockerfile` copies the same way) and every
worktree.

The workspace loads the realtime client where the Python page loads
`socket.io.min.js`, in this order: `js/realtime-emitter.js`,
`js/realtime-acks.js`, `js/realtime-wire.js`, `js/realtime-catalog.js`,
`js/realtime-terminal.js`, `js/realtime-shim.js`. A preview page adds
`css/preview-notice.css` in the head and `js/preview-notice.js` at the end;
the workspace loads `js/preview-notice-i18n.js` after `js/i18n.js` and
before it. The sign-in page has no `i18n.js`; the notice uses its built-in
texts there. `internal/httpapi` tests pin this order.

## Migration steps

`internal/migrate/legacy` declares `Step` (entity, version, `Read`,
`Write(ctx, *store.Tx, Sealer)`, `Verify(ctx, *store.Tx, Opener)`,
`Report`), `StepReport` and `Pending`. `Sealer` and `Opener` are satisfied
by `*keyring.Ring`. The migration record holds `coverage` (the steps with
their versions) and `pending` (entities kept in place with their phase and
count).

```go
type Options struct { DataDir, Secret, SecretSource, BackupTempDir, Release string; Registry *Registry; Origin OriginRule; Now func() time.Time }
func Start(ctx, Options) (*Startup, error)      // sections 5.1 and 5.2; holds the Go lock until Close
func DryRun(ctx, Options) (*Report, error)      // steps 2 to 9 into staging, no activation
func Replace(ctx, Options) (*Replaced, error)   // section 5.4
func NewSourceWatch(ctx, *store.DB, dataDir string) (*SourceWatch, error) // nil without a record
func (w *SourceWatch) Changed() (bool, error)   // section 5.7
func NewRegistry() *Registry                    // Add, KeepInPlace, Schemas, Covered, Uncovered
func RecordSchema() store.Schema                // owner migrate
func RecordKeyID(ctx, *store.DB, keyID string) error
func StoredKeyID(ctx, *store.DB) (string, error)
func ExtractBackup(b *Backup, dest string, limits BackupLimits, mode RestoreMode) (ExtractResult, error)
type StopError struct { State State; Code, Entity string; UserID int64; Record, Message string; Err error }
type StepError struct { UserID int64; Record string; Err error }
```

- The owner `migrate` has `migrate_record` and `migrate_keyring`; there
  is no table of derived settings. After every step has written, the
  framework calls `settings.MaterialisePolicies` in the same transaction
  with `Origin.KeepLegacyScheme` and lists what it wrote in
  `materialised_settings` of the report.
- `StepReport` gains flags, kept paths, warnings and user actions
  (`Flag`, `KeptPath`, `MaterialisedSetting`, `Warning`, `UserAction`);
  `Restored(mode, at)` marks a run on a restored Python backup.
- Stop codes are stable constants (`legacy_changed`, `go_data_missing`,
  `keyring_material`, `legacy_in_use`, `python_restore_unfinished`,
  `not_enough_space`, `secret_key_mismatch`, …); every message names the
  way out and never a secret value.
- The periodic re-check of 5.7 is `SourceWatch`; D4 calls `Changed` every
  60 seconds and treats an error as a change (maintenance, not ready,
  audit event).
- `internal/migrate/legacy/host_unix.go` and `host_windows.go` may use
  `syscall` (lock and free-space probes, architecture test); R2 reviews
  both. On Windows the Go lock is real; the SQLite and flock probes and
  the free-space check still only warn and must become real checks before
  the Windows release (decision C7, open).
- `--replace` moves to `internal/backup` once that exists (B8/B7).

## End-to-end harness

The seed applier and the test-only hooks live in `internal/e2eseed`. Only
`cmd/webssh/e2e.go`, built with the tag `e2e`, imports it; the release
build of `cmd/webssh` must not depend on it (architecture test).
Test-only switches such as `WEBSSH_E2E_FAST_HASHING` are read only in that
file.

The hook routes use the reserved type namespace `e2e.` (`e2e.output_load`,
`e2e.output_load_done`, `e2e.workspace_restore`). They are not in the v1
catalog; only the e2e build registers them, through the `routes` argument
of `Backend.Serve`, which the composition root passes to `Mount`. The shim
maps the Socket.IO events `e2e_output_load`, `e2e_output_load_done` and
`e2e_workspace_restore` to these types (added with the e2e wiring, D4); a
release server answers them with `unknown_type`. Playwright stops the backend with SIGINT
(`webServer.gracefulShutdown`), so it can remove its scratch tree.

The terminal's hooks (`e2eseed.Hooks{OutputFlow, FixtureSessions}`, both
`*terminal.Manager`) add the server event `e2e.output_stream {ch,
session_id}`: it binds a synthetic load stream on a channel at or above
2^31, which the client never allocates, to the session name `load-N`
before its first frame. The shim maps it to a channel with that
`session_id` and delivers and acknowledges its frames like
`ssh_output` (D4).

## Modules

`golang.org/x/crypto` may be imported by `internal/migrate/legacy`,
`internal/ssh/…`, `internal/vault` and `internal/auth/local`.
`github.com/coder/websocket` (tier B, ISC, chosen in K6) is added to the
allowlist with the importer `internal/realtime` in the same change that
first imports it: the architecture tests reject allowlist entries for
modules that are not required.
