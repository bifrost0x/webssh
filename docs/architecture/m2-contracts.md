# M2 contracts: data and files

This document fixes the contracts between the Go packages built for M2 in
the areas files, transfers, saved passwords, commands, remote commands,
quotas, cron and background jobs. It continues
[m1-contracts.md](m1-contracts.md); everything fixed there still holds.
External identity, operation (backup, restore, audit, feature switches),
the wiring files of `cmd/webssh`, the realtime catalog of the new areas
and the end-to-end harness are fixed in the second part of the M2
contracts.

The [package map](go-package-map.md) says which package may import which.

## How these contracts are fixed

The rules of [m1-contracts.md](m1-contracts.md#how-contracts-are-fixed)
apply unchanged:

- Types, consumer interfaces, constants and the shared pure rules (path
  model, decoding rule, fingerprint, source ids, script command) are
  compiled code in the packages named below. They change only by a
  contract change that updates this document in the same commit.
- Provider APIs that a later package builds are fixed here by signature.
  They become binding when the providing package is merged. There are no
  placeholder implementations.
- Interfaces are declared by the consumer and use standard library types,
  foundation types and types of packages the consumer may import. Where a
  provider cannot be imported, `cmd/webssh` adapts.
- Test doubles live in packages named `…test`: `internal/files/filestest`
  (an in-memory `files.Backend`) and `internal/vault/vaulttest` (the
  saved-password provider).
- The tables of error codes and step-up actions below are checked against
  the code by `internal/architecture`, together with those of every other
  `docs/architecture/m*-contracts*.md`. A name may appear in one document
  only.

Python behaviour that the contracts keep, fix or drop is named where it
matters; every visible change is listed at the end.

## Files

`internal/files` owns the workspace; `internal/files/sftp` and
`internal/files/smb` implement backends.

### Backend

Compiled in `internal/files/backend.go`. One `Backend` value is one open
source; paths are canonical and relative to the source root.

```go
type Backend interface {
	Capabilities() Capabilities
	Home(ctx) (string, error)
	OpenListing(ctx, path string) (Listing, error)
	Stat(ctx, path string, follow bool) (Entry, error)
	Open(ctx, path string, r Range) (Reader, error)
	Write(ctx, path string, src io.Reader, o WriteOptions) (WriteResult, error)
	Mkdir(ctx, path string) error
	Rename(ctx, from, to string) error
	Remove(ctx, path string, recursive bool, b Budget) error
	Walk(ctx, path string, b Budget, fn func(Entry) error) error
	Chmod(ctx, path string, perm fs.FileMode) error
	Close() error
}
type Listing interface { Next(ctx, max int) ([]Entry, bool, error); Close() error }
type Reader interface { io.ReadCloser; Entry() Entry }
type AccessProber interface { Access(ctx, path string) (Access, error) } // optional, SMB
```

- Every method honours the deadline of `ctx`. Backends set their own
  operation bounds (`SFTP_OPERATION_TIMEOUT`, `SMB_IO_IDLE_TIMEOUT_SECONDS`,
  the 10-second mutation bound of the Python release).
- Failures are `*fault.Error` with the codes of the table below; messages
  never carry remote text or paths.
- `Write` is the one write path: new files (`Exclusive`), uploads, editor
  saves (`ExpectedRevision`), host-to-host copies. It reads from `src`
  and installs the content as one replacement (temporary file in the same
  directory, then rename). `Size` and `MaxBytes` bound the stream; a short
  or long stream fails with `SOURCE_CHANGED` and leaves the target as it
  was. The new `WriteResult.Revision` is returned.
- `Strategy` is `atomic` (SFTP `posix-rename@openssh.com`, SMB handle
  rename) or `recoverable_swap` (SMB editor only, after the user's consent
  through the save challenge of the Python release). A source without a
  safe replace answers `ATOMIC_REPLACE_UNAVAILABLE` for transfers and
  `SMB_RECOVERABLE_REPLACE_REQUIRED` for an editor save on SMB. A lost
  reply after the final rename was sent is `SAVE_OUTCOME_UNKNOWN` (editor)
  or `OUTCOME_UNKNOWN` (other writes); the temporary file is then kept.
  `SMB_RECOVERY_REQUIRED` and a retained backup
  (`WarningRecoveryBackupRetained`) name their files in
  `RecoveryLeaves` / `details.recovery_leaves`.
- `Rename` never replaces. The Python service refused replacing renames
  too; the K1 rule for SMB (a lost reply is reconciled through the open
  file id, unknown stays `OUTCOME_UNKNOWN`) applies to `Rename` and to
  the final rename of `Write`. The K1 spike's upload deleted the handle's
  object after a lost rename reply; FS3 must reconcile first.
- `Remove` with `recursive` walks without following links, deletes
  children first and stops at the `Budget` (`LIMIT_EXCEEDED`); nothing is
  rolled back. SMB refuses a tree with a reparse point before it deletes
  anything (Python rule, kept).
- `Walk` is the tree read of folder downloads, host-to-host copies and
  permission jobs. Parents come before children; links are reported
  (`IsSymlink`) and not entered. Consumers refuse links where Python did.
- `Chmod` sets permission bits without following a link (SFTP
  `lsetstat@openssh.com`). It needs `CapChmod`, which SFTP sets only when
  the admin switch `sftp_chmod_enabled` is on and the server offers the
  extension; SMB never sets it. The mode read back must match
  (`MODE_MISMATCH`); an unverifiable result is `OUTCOME_UNKNOWN`.
- `Stat` with `follow` describes a link target; SMB refuses
  (`REPARSE_POINT_REJECTED`). `Open` refuses directories and links.
- `Entry.Mode` is the POSIX `st_mode` with type bits as the page shows it;
  SMB synthesises it (directory `0o040111`, file `0o100444` read-only or
  `0o100666`). `Owner` is numeric (uid, gid) and only for SFTP.

Check against the Python operations (`app/file_backend.py`,
`app/sftp_handler.py`, `app/smb_backend.py`) and the K1 matrix:

| Python operation | Backend |
|---|---|
| `open_directory_listing`, `read_page`, `close` | `OpenListing`, `Listing.Next`, `Listing.Close` |
| `stat`, `stat_or_raise`, `get_file_stat`, `check_exists(_or_raise)` | `Stat` (not found is `NOT_FOUND`) |
| `get_home_directory` | `Home` |
| `read_file_preview` (offset, tail), `read_binary_preview`, `read_file_for_edit`, `open_reader` | `Open` with `Range`, then `files.Decode` in `internal/files` |
| `write_file_text`, `open_atomic_writer`, `atomic_transfer_writer` | `Write` with `ExpectedRevision`, `Strategy`, `FollowSymlink` |
| `create_file` (exclusive, empty) | `Write` with `Exclusive` and an empty reader |
| `mkdir`, `create_directory`, `mkdir_no_follow` | `Mkdir` (one level, as Python) |
| `rename`, `rename_item`, `rename_verified` | `Rename` |
| `delete`, `delete_directory_recursive` | `Remove` |
| `iter_tree` | `Walk` |
| `get_permissions`, `set_permissions`, `permission_job_session` | `Stat` (`Mode`, `Owner`), `Chmod`; jobs in `internal/automation` |
| `inspect_directory_access` (SMB) | `AccessProber` |
| `probe_sftp_capability` | the SFTP backend when it opens (`Capabilities`) |
| `normalize_path` | `files.Clean` and the backend's own component rules |

### Capabilities and sources

`Capability` is a bit set whose names are the `capabilities[]` of the
source descriptor (`list`, `read`, `write`, `create-file`, `chmod`,
`mkdir`, `rename`, `delete`, `preview`, `edit`, `recursive`,
`remote-transfer`). `Capabilities` adds `Replace` (supported strategies),
`SymlinkTargets` (SFTP saves through a link), `CaseInsensitive` (SMB name
comparison) and `RootWritable` (false for an SMB share root).

A source id is `<kind>:<handle>` with kind `sftp-session` (the SFTP
subsystem of a terminal session), `sftp-quick` (Quick SFTP, also for a
saved host) or `smb-quick`, and a handle
`[A-Za-z0-9][A-Za-z0-9_-]{0,127}` (`files.ParseSourceID`,
`FormatSourceID`). Every id that does not resolve for the caller is
`SOURCE_UNAVAILABLE`, as in Python. `Descriptor` carries label, endpoint,
protocol, `Ephemeral` and `Security` for the page.

The source registry (FS1, signatures binding on merge):

```go
type Opener func(ctx context.Context, p principal.Principal, handle string) (Descriptor, Backend, error)
func NewRegistry(o RegistryOptions) *Registry
func (r *Registry) RegisterKind(kind SourceKind, open Opener)    // sftp-session: opened on first use
func (r *Registry) Add(p principal.Principal, kind SourceKind, d Descriptor, b Backend) (string, error)
func (r *Registry) Resolve(ctx, p principal.Principal, sourceID string, need Capability) (Backend, func(), error)
func (r *Registry) Close(p principal.Principal, sourceID string) error
func (r *Registry) Revoke(rev principal.Revocation)              // K6: subscribed to the revocation feed
func (r *Registry) LastConnectionClosed(userID int64)            // Python: quick sources close with the last socket
```

- A source is bound to the user and the browser session that opened it;
  `Resolve` checks both and the capability, and returns a release
  function that holds the source open (transfer holds of Python).
- A revocation closes every source of the session (of the user when the
  revocation has no session) before `Revoke` returns; held sources are
  closed when the hold ends, and every operation on them fails with
  `SOURCE_UNAVAILABLE` from then on.
- When the user's last realtime connection ends, quick and SMB sources
  close as in Python (deferred while a transfer holds them). Terminal
  sessions and their `sftp-session` sources stay.
- Quick sources reserve quota `quick_connection`; SMB sources expire after
  300 seconds without use (Python pool).
- cmd/webssh registers the `sftp-session` opener over an adapter of
  `internal/terminal` (the session's `*client.Conn`) and `internal/files/sftp`.

### Path model

Compiled in `internal/files/path.go`.

- `Clean(raw)` for reads and listings: absolute, single slashes, no `.`
  segment, no trailing slash. Refused: empty, relative, invalid UTF-8, a
  `..` segment anywhere (checked before cleaning), C0, DEL and C1
  characters, more than `MaxPathBytes` (4096). A backslash is an ordinary
  POSIX character here. The page resolves `.` to `Home` first.
- `CleanTarget(raw)` for mutations additionally refuses a leading `//`, a
  backslash and the root itself (Python mutation rules).
- `ValidName(name)` for new leaf names: 1 to 255 bytes, not `.`/`..`, no
  slash, backslash or control character, not only white space.
- `Join(dir, name)`, `Within(root, p, fold)` (subtree check; `fold` for
  SMB).
- Root binding: SFTP's root is the server's `/` (the whole file system
  the account can reach, as in Python); SMB's root is the share and its
  backend applies the component rules of `app/smb_paths.py` (128
  components, 255 characters each, no `<>:"/\|?*`, no trailing dot or
  space, no reserved device names) and refuses modifying the root.

### Decoding rule (D-23)

Compiled in `internal/files/decode.go`; preview and editor use it for both
backends.

- `Decode(raw) (text, encoding, binary)`: a NUL in the first 1024 bytes is
  binary; else strict UTF-8; else Latin-1, which accepts every byte. A
  byte order mark stays as U+FEFF. Equal to `decode_text` of
  `app/editor_text.py` (vectors written by that function in
  `internal/files/testdata/decode-vectors.json`).
- `DetectNewline(raw)`: `lf` without CRLF, `crlf` when every LF ends a
  CRLF, `mixed` otherwise; a lone CR is no line ending.
- `EditorText(text)` replaces CRLF by LF for the textarea. Saving maps back
  by the newline mode (for `mixed` with the per-line merge of
  `encode_editor_text`, bounded by 2,000,000 comparisons; FS1).
- `Revision(raw)` is the lower-case hex SHA-256 of all bytes; a save with
  another revision fails with `EDIT_CONFLICT`.
- The edit result keeps the Python fields: `content`, `size`, `encoding`,
  `newline`, `revision`, `original_bytes` (base64), `endpoint`. A
  character the encoding cannot store fails with
  `EDIT_ENCODING_UNSUPPORTED` with `details {character, line}`.
- Binary content in the editor is `FILE_BINARY`; content above
  `MAX_EDITOR_FILE_SIZE` (5 MiB) is `FILE_TOO_LARGE`. Python sent plain
  texts for both.

### Listing and cursors

- The page asks with `cursor` `0` for the first page; `internal/files`
  holds the open `Listing` as a snapshot and answers with `next_cursor`
  `v1.<snapshot>.<offset>.<mac>` as in Python. The snapshot id is random,
  the snapshot is held in memory and bound to user, session, realtime
  connection, source and path; the MAC is a per-process check value over
  these fields. A continuation that does not match
  exactly fails with `invalid_request`.
- Page size `REMOTE_LISTING_PAGE_SIZE` (500, 50 to 1000), at most
  `MAX_TRANSFER_MEMBERS` entries per listing (`LIMIT_EXCEEDED`), idle
  snapshot TTL `REMOTE_LISTING_SNAPSHOT_TTL_SECONDS` (60), at most 4
  snapshots per user and 8 in total (the user's oldest is evicted first).
  A cancel by cursor or request id closes the listing synchronously.
- Entries keep server order; only `.` and `..` are dropped.

### Limits

The file limits keep their names and defaults: `MAX_EDITOR_FILE_SIZE`
(5 MiB), `EDITOR_SAVE_BYTES_PER_MINUTE`, `MAX_PREVIEW_SIZE` (512000),
`MAX_PREVIEW_TAIL_LINES` (10000), `MAX_SUPPORTED_FILE_SIZE` (1 GiB),
`FILE_CONTROL_MAX_PATH_BYTES` (4096), `FILE_CONTROL_BYTES_PER_MINUTE`,
`REMOTE_FILENAME_MAX_BYTES`, `REMOTE_LISTING_MAX_METADATA_BYTES` (4 MiB),
`SFTP_MAX_PACKET_BYTES`, `SFTP_MAX_HANDLE_BYTES`, `SFTP_OPERATION_TIMEOUT`,
`SFTP_CHMOD_ENABLED`, `SMB_CONNECT_TIMEOUT_SECONDS`,
`SMB_IO_IDLE_TIMEOUT_SECONDS`, `SMB_ALLOWED_TARGETS`. `files.Budget`
defaults to 10000 members and depth 50.

### Realtime

The message types of the file area (`files.*`, `smb.*`, `transfer.*`)
with their `Spec` and the mapping to the Socket.IO events of the
Python release (`list_directory`,
`create_directory`, `rename_file`, `delete_item`, `prepare_transfer`,
`cancel_transfer`, `transfer_server_to_server`, `quick_connect`,
`file_source_disconnect`, …) are part of the realtime catalog in the
second part of the M2 contracts. Payloads keep the members of today;
failures carry the upper-case code as `code` (files) or `error_code`
(transfers) and the members `retryable`, `limit_kind`, `limit_bytes`,
`actual_bytes`, `revision`, `recovery_leaves`, `character`, `line`,
`save_challenge` in `details`.

## Transfers

`internal/transfer`, compiled in `internal/transfer/contract.go`.

- Routes as in Python: `GET /api/transfers/{token}/download`,
  `GET /api/transfers/{token}/folder-download`,
  `POST /api/transfers/{token}/upload` (raw body with `Content-Length`, at
  most `MAX_UPLOAD_SIZE`). A token is prepared over realtime and bound to
  user, browser session, source and direction; it is 43 characters of
  base64url (`NewToken`, `ValidToken`), valid for 300 seconds and used
  once. An unknown, used, expired or misdirected token answers 404
  without a body.
- `Direction`: `upload`, `download`, `server_to_server`. `State`:
  `pending`, `running`, `cancelling`, `cancelled`, `failed`, `completed`;
  a cancel answers the state or `unavailable`.
- `ConflictPolicy`: `error` or `replace` (atomic). A download allows only
  `error`.
- Limits (`DefaultLimits`): `MAX_UPLOAD_SIZE`, `MAX_DOWNLOAD_SIZE`
  (100 MiB each), `MAX_ZIP_DOWNLOAD_SIZE` (500 MiB, also host-to-host),
  `MAX_TRANSFER_MEMBERS` (10000), depth 50; a ZIP being built is capped by
  `QUOTA_TEMP_BYTES_PER_USER` and reserves `temp_bytes`.
- `Failure{Code, Message, LimitKind, LimitBytes, ActualBytes}` with
  `Retryable()`: `SHARE_UNAVAILABLE`, `TIMEOUT`, `SOURCE_UNAVAILABLE` and
  `SOURCE_CHANGED` are retryable (`app/transfer_errors.py`).
- A transfer belongs to the user and the browser session. Reconnecting
  the realtime connection keeps running HTTP transfers and cancels pending
  tokens and host-to-host copies of the closed connection, as in Python;
  ending the session or a revocation cancels everything of it.
- Host-to-host copies run on two `files.Backend` values, in every
  combination of SFTP and SMB, including one source to itself (same path
  refused). They reserve `background_job`, refuse links, check declared
  sizes and report `SOURCE_CHANGED` when fewer bytes arrive.

Consumer interfaces (compiled):

```go
type Sources interface { Resolve(ctx, p principal.Principal, sourceID string, need files.Capability) (files.Backend, func(), error) }
type Quotas interface { Reserve(ctx, kind string, userID, amount int64) (func(), error) }
type Events interface { Progress(userID int64, ev Progress); Finished(userID int64, ev Finished) }
```

Provider API for the admin page (TR1, signatures binding on merge; the
operations interface that consumes it is fixed in the second part):

```go
func (m *Manager) Active(limit int) (items []Active, total int) // no tokens, no paths
func (m *Manager) Cancel(ctx context.Context, transferID string) (State, error)
```

## Saved passwords and the legacy vault

`internal/vault`, compiled in `internal/vault/credential.go`.

- `Credential{ID, UserID, Name, Username, Version, UpdatedAt}`; the
  secret is sealed with `keyring.Credential` and the AAD
  `(vault_credentials, secret, <id>)`. Limits: 100 credentials, 1000
  assignments, name 128 bytes, username 256 bytes (may be empty), secret
  1 to 4096 bytes without NUL.
- Resources: saved host `<id>`, jump host `jump:<id>`, SOCKS proxy
  `socks:<id>`, SMB share `smb:<id>` (`ResourceID`, `ParseResourceID`).
- `Assignment{ResourceID, CredentialID, Fingerprint, Generation}`. The
  fingerprint of a `Target` is computed exactly as `profile_fingerprint`
  of `app/automation_store.py` (`Fingerprint`, vectors from Python in
  `internal/vault/testdata/fingerprint-vectors.json`); migrated
  assignments keep their stored fingerprint and generation (E32), and
  schedules keep their binding to version and generation (E15).
- `Status` as the page shows it: `ready`, `changed` (the target changed:
  the user reviews and assigns again, with step-up), `missing`,
  `disabled`. The M2 plan's `review_required` is `changed`.
- Saved passwords need HTTPS (`https_required`) and the feature switch
  (`credentials_disabled`), as in Python.

Provider API (VA1, signatures binding on merge):

```go
func New(o Options) (*Service, error)                // Options gains Resources and the credential limits
func (s *Service) Password(ctx context.Context, userID int64, resourceID string, t Target) ([]byte, error)
func (s *Service) ImportLegacy(ctx context.Context, p principal.Principal, passphrase []byte, grant string) (imported int, err error)
func (s *Service) Routes() []protocol.Route           // none in M2: the page uses HTTP
func (s *Service) HTTP() http.Handler                 // /credentials, /api/credentials/…
func ImportCredentialTx(ctx, tx *store.Tx, sealer Sealer, c ImportedCredential) error  // migration E32
func ImportLegacyVaultTx(ctx, tx *store.Tx, userID int64, document []byte, version int) error // E30
```

- `Password` returns the secret only when the resource has an
  assignment of the user and `Fingerprint(t)` equals it; otherwise
  `credential_missing` or `credential_target_changed`. `t` is the target
  the caller is about to connect to, so the check and the connection use
  the same record. The secret is a fresh copy; the caller clears it after
  use and never logs it. Consumers (the dialer adapter for hosts, jump
  hosts and SOCKS, `internal/files/smb`, `internal/automation`) declare
  their own interface; `cmd/webssh` adapts their target types to
  `vault.Target`. `vaulttest.Passwords` implements the same checks.
- `Resources` (consumer interface of the vault, compiled) returns the
  current `Target` of a resource; `cmd/webssh` provides it over
  `internal/hosts` and `internal/files/smb`.
- A credential that is assigned to a live resource cannot be deleted
  (`credential_in_use`); assignments of deleted resources are removed.
- Intents: every change is prepared as an intent (300 seconds, 8 per
  user, 4096 in total) bound to user, session and the digest of the
  mutation; preview and apply compare the frozen target
  (`preview_changed`). Replacing an assigned credential needs the
  confirmation of the old one (`replacement_confirmation_required`).
- Step-up: binding a saved secret (assign, import, authorize a one-off
  target) consumes a grant for `credentials.vault` with the intent token
  as target. After one grant, further bindings of the same session need
  none for 300 seconds (Python `BINDING_ASSURANCE_SECONDS`).
- Legacy vault (D-06): the file stays byte for byte in
  `vault_legacy_automation`; `ImportLegacy` decrypts it with the user's
  passphrase (scrypt N=131072, r=8, p=1, AES-GCM, AAD
  `webssh-automation-vault-v<version>:<user_id>:<incarnation>`, passphrase
  16 to 1024 characters and at most 1024 bytes), creates one credential
  per record named after the resource (else its id, else
  `Imported password`) with an empty username, assigns it where the
  resource exists and has no assignment, keeps the legacy fingerprint and
  is idempotent per document. A wrong passphrase is
  `vault_unlock_failed` and changes nothing. The routes
  `/api/automation/vault/*` and `/api/credentials/apply|lock` are dropped
  (D-06).

## Commands and command sets

`internal/commands`, compiled in `internal/commands/contract.go`.

- `Command{ID, Name, Command, Parameters, Description, Category, OS,
  System, CreatedAt}`; built-in templates come from
  `app/resources/commands/system_commands.json` (embedded in Go, 312
  entries `sys-NNN`), translated in the page.
- `Set{ID, Name, Description, UseSudo, Steps, Parameters, CreatedAt,
  UpdatedAt}` with steps `inline`, `library` (with `Override`) and `argv`
  (only in parameterised sets). Unknown stored members are kept.
- Limits in `contract.go` (`MaxCommands` 500, `MaxSets` 500,
  `MaxSetSteps` 64, parameters 1 to 20, argv steps 1 to 50, resolved text
  at most 4096 characters, …). Storage limits use `quota.WithinStorage`.
- `References` (consumer interface of commands, compiled) lists the
  profiles that refer to a set or a command; delete answers `in_use` with
  `details.usages` (at most 20 names). Host context references are
  checked when the host context is saved (`invalid_reference`), not on
  delete.

Provider API (CM1, signatures binding on merge), with standard types only
so that `internal/terminal`, `internal/hostops` and
`internal/automation` declare matching interfaces:

```go
func (l *Library) Resolve(ctx context.Context, userID int64, setID string, values map[string]string, sudo bool) (string, error)
func (l *Library) SetExists(ctx context.Context, userID int64, setID string) (bool, error)
```

- `Resolve` without values is the startup text of a non-parameterised set:
  library steps append their parameters, `sudo ` is prefixed per line
  (not for blank lines, comments or lines already starting with `sudo`),
  comment-only steps become `:`, steps are chained with ` && ` by the
  quote- and comment-aware rule of `app/command_set_manager.py`, and the
  result passes the startup normalisation (4096 characters, no NUL,
  LF). A parameterised set refuses an empty `values`
  ("Parameterized command sets require interactive launch after
  connecting").
- With values, every declared parameter and no other must be given (each
  at most 1024 characters, no control characters); placeholders are whole
  arguments, the program is single-quoted and the other arguments are
  shell-quoted as `shlex.quote` does, steps are joined with ` && `.
  Values are never stored. Differential tests against
  `app/command_parameters.py` are part of CM1.
- The terminal sends a startup set with Enter at connect (not on a tmux
  reattach); the launcher after connect inserts the text without Enter.

## Remote commands

`internal/ssh/remotecmd` stays the only way to run a non-interactive
command. M2 adds `Script(body, sudo) (Command, error)` (compiled):

- The script (1 to 8192 bytes of UTF-8 without NUL, line breaks allowed)
  travels on stdin; the command line is the fixed text
  `sh -c 'eval "$(cat)"'`, or `sudo -n -- sh -c 'eval "$(cat)"'` with
  sudo. The script runs with an exhausted stdin, as the Python release
  closed stdin after `sudo -n -- sh -c <script>`.
- No password is written to sudo: a step that needs one fails with a
  non-zero exit status, as in Python. The M2 plan's "sudo input" is not
  needed.
- The exit status is `Result.ExitStatus`; a channel without exit status
  is `client.ErrNoExitStatus` (Python `unknown`/`channel_lost`). Output
  bounds are `Command.MaxOutput` (stdout) and 4 KiB of stderr, which is
  what an automation step keeps (8 KiB per step, stderr at most half).
  Cleaning of ANSI sequences and redaction of passwords stay in
  `internal/automation`.

## Quotas

`internal/quota`, compiled in `internal/quota/contract.go`.

- Kinds as plain strings: `ssh_session`, `quick_connection`, `transfer`,
  `temp_bytes`, `background_job`, with global and per-user limits from
  `QUOTA_<KIND>_GLOBAL` and `QUOTA_<KIND>_PER_USER` (`DefaultLimits`).
  `Limit.Check` enforces positive limits, per-user at most global, and
  for `ssh_session`, `quick_connection` and `transfer` per-user below
  global.
- `WithinStorage(size, stored, limit)` is the shared rule of the storage
  limits: within the limit, or not growing a value already above it.

Provider API (RT1, signatures binding on merge); consumers declare
`Reserve` with the same standard types:

```go
func New(limits map[string]Limit) (*Policy, error)
func (p *Policy) Reserve(ctx context.Context, kind string, userID, amount int64) (release func(), err error)
func (p *Policy) Usage() map[string]Usage // for the admin page
```

- `Reserve` checks the per-user limit first, then the global one, under
  one lock, and fails with `busy` and the plain text of Python
  (`"transfer quota exceeded (per_user limit 2)"`). `release` is
  idempotent. An unknown kind is a programming error (`internal`).

## Cron

`internal/cron` (foundation, tier C). Provider API (RT1, signatures
binding on merge):

```go
func Parse(expr string) (Schedule, error)       // invalid_schedule
func LoadZone(name string) (*time.Location, error)
func (s Schedule) Next(after time.Time, loc *time.Location) (time.Time, error)
```

- Five fields (minute 0–59, hour 0–23, day 1–31, month 1–12, weekday 0–7
  with 7 as Sunday), characters `0-9 * / , -` only, parts `*`, `N`, `A-B`
  with optional `/S` (1 ≤ S ≤ span; `N/S` runs to the maximum). No names,
  no macros, no `L W # ?`. Expression and zone at most 128 bytes.
- Day rule: when the day or weekday field starts with `*`, both must
  match; otherwise either may (Vixie).
- `Next` scans local wall times after `after` for 5 years
  (`cron.Horizon`): a wall time in a spring-forward gap is skipped, in an
  autumn fold only the first occurrence runs. Vectors against
  `next_due` of `app/automation_cron.py` and fuzzing are part of RT1.

## Background jobs

`internal/jobs` (edge), compiled in `internal/jobs/contract.go`:
`Func`, `Spec{Every, Cron, Zone, Singleton, Concurrency, Timeout,
Defer}`, `State`, `Info`, `DefaultShutdownGrace` (5 s), `MaxShutdownGrace`
(30 s), `MaxPending` (64).

Provider API (RT1, signatures binding on merge):

```go
func New(o Options) *Registry
func (r *Registry) Register(name string, s Spec, fn Func) error // before Start; names unique
func (r *Registry) Start(ctx context.Context)
func (r *Registry) RunNow(ctx context.Context, name string) error // busy when MaxPending runs wait
func (r *Registry) Cancel(name string) error
func (r *Registry) List() []Info
func (r *Registry) Shutdown(ctx context.Context) error          // grace from RUNTIME_SHUTDOWN_GRACE_SECONDS
```

- One owner per job: the registry runs it, nothing else starts its
  goroutines. Capabilities expose job functions; `cmd/webssh` registers
  them (LDAP revalidation, platform detection, reachability, audit
  retention, automation scheduler, transfer and listing cleanup, SMB
  idle cleanup, backup cleanup).
- Shutdown stops new runs, cancels jobs without `Defer`, waits for the
  shutdown callbacks, then cancels the deferred jobs and waits up to the
  grace; the report names jobs that did not stop.

## Errors

### Error codes

The codes of the file, transfer, credential and schedule capabilities.
The upper-case codes keep the spelling of the Python release because the
file pages match on them; they live in `internal/fault/codes_data.go`
apart from the M1 catalog.

| Code | HTTP status | Default message |
|---|---|---|
| `PERMISSION_DENIED` | 403 | Permission denied for this file operation. |
| `CONFLICT` | 409 | A file or folder already exists at the destination. |
| `NOT_FOUND` | 404 | The requested file or folder was not found. |
| `TIMEOUT` | 504 | The file operation timed out. |
| `CANCELLED` | 409 | The operation was cancelled. |
| `SOURCE_UNAVAILABLE` | 404 | The file source is no longer available. Reconnect and try again. |
| `SOURCE_CHANGED` | 409 | The source changed during the operation. Try again. |
| `LIMIT_EXCEEDED` | 413 | The transfer exceeds the configured limit. |
| `ATOMIC_REPLACE_UNAVAILABLE` | 409 | Safe overwrite is unavailable for this destination. |
| `TRANSFER_UNAVAILABLE` | 500 | The transfer could not be completed. |
| `UNSUPPORTED_OPERATION` | 400 | This file source does not support the operation. |
| `METADATA_CHANGED` | 409 | The file changed. Reload and try again. |
| `OPERATION_FAILED` | 502 | The file operation failed. |
| `OUTCOME_UNKNOWN` | 502 | The outcome of the operation is unknown. Reload to check. |
| `MODE_MISMATCH` | 409 | The permissions were not applied as requested. |
| `EXPIRED` | 409 | The preview has expired. Start again. |
| `EDIT_CONFLICT` | 409 | The file changed since it was opened. |
| `EDIT_ENCODING_UNSUPPORTED` | 400 | The text cannot be saved in the file's encoding. |
| `EDIT_METADATA_UNSUPPORTED` | 409 | The file's owner or special permissions prevent a safe save. |
| `SAVE_OUTCOME_UNKNOWN` | 502 | The outcome of the save is unknown. Reload to check. |
| `FILE_TOO_LARGE` | 413 | The file is too large. |
| `FILE_BINARY` | 415 | Binary files cannot be shown as text. |
| `SMB_RECOVERABLE_REPLACE_REQUIRED` | 409 | Saving this file needs a recoverable replace. Confirm to continue. |
| `SMB_RECOVERABLE_REPLACE_FAILED` | 502 | The file could not be replaced; the original was restored. |
| `SMB_RECOVERY_REQUIRED` | 502 | The save outcome is uncertain. Check the recovery files. |
| `SHARE_UNAVAILABLE` | 404 | The SMB share is unavailable. |
| `AUTHENTICATION_REQUIRED` | 502 | The SMB server requires valid credentials. |
| `OPERATION_UNAVAILABLE` | 502 | The SMB server does not support this operation. |
| `IDENTITY_UNAVAILABLE` | 502 | SMB object identity is unavailable. |
| `REPARSE_POINT_REJECTED` | 403 | Reparse points are not supported. |
| `MUTATION_GUARD_REQUIRED` | 409 | SMB mutation safety check failed. |
| `CONNECT_CANCELLED` | 400 | The SMB connection was cancelled. |
| `CONNECTION_FAILED` | 502 | The SMB connection failed. |
| `QUOTA_EXCEEDED` | 409 | Too many SMB connections are open. |
| `RUNTIME_SHUTTING_DOWN` | 503 | The server is shutting down. |
| `TARGET_NOT_ALLOWED` | 403 | The SMB target is not allowed. |
| `ENCRYPTION_REQUIRED` | 502 | The SMB server does not offer the required encryption. |
| `DIALECT_REQUIRED` | 502 | The SMB server does not support SMB 3.1.1. |
| `https_required` | 403 | Saved passwords require HTTPS. |
| `credentials_disabled` | 403 | Saved passwords are turned off. |
| `invalid_intent` | 409 | The confirmation has expired. Start again. |
| `preview_changed` | 409 | The target changed. Review it and try again. |
| `credential_in_use` | 409 | The saved password is still assigned. |
| `vault_locked` | 423 | The saved password changed. Start again. |
| `invalid_targets` | 400 | The target is invalid. |
| `credential_target_changed` | 400 | The target changed since the password was assigned. |
| `credential_missing` | 400 | No saved password is assigned. |
| `credential_unreadable` | 400 | The saved password cannot be read. |
| `credential_unavailable` | 400 | The saved password is unavailable. |
| `storage_limit` | 400 | The storage limit is reached. |
| `replacement_confirmation_required` | 400 | Confirm the replacement of the assigned password. |
| `confirmation_required` | 400 | Confirm the target to continue. |
| `vault_missing` | 400 | There is no legacy vault to import. |
| `vault_unreadable` | 400 | The legacy vault cannot be read. |
| `vault_unlock_failed` | 400 | The passphrase is wrong. |
| `invalid_passphrase` | 400 | The passphrase is invalid. |
| `invalid_schedule` | 400 | The schedule is invalid. |

- The M2 plan's `outcome_unknown`, `stale_revision` and `source_closed`
  are `OUTCOME_UNKNOWN` / `SAVE_OUTCOME_UNKNOWN`, `EDIT_CONFLICT` and
  `SOURCE_UNAVAILABLE`: the Python codes with the same meaning, which the
  page already handles. `file_too_large` is `FILE_TOO_LARGE`; `smb_*` are
  the `SMB_*` codes and the SMB protocol codes of `app/smb_protocol.py`.
- Codes of the M1 catalog keep their meaning: runtime quotas answer
  `busy`, a referenced set `in_use`, invalid input `invalid_request` or
  `validation_error`, command storage `quota_exceeded` with the Python
  text.
- Messages are defaults; the capabilities may send the Python text of an
  operation (for example "No write permission for the destination." for
  an upload), never remote-supplied text.

## Step-up

### Step-up actions

| Action | Used by |
|---|---|
| `credentials.vault` | `internal/vault` |

The page asks for `credentials.vault` with the intent token as target
(`static/js/native-credentials.js`), and the intent carries the operation
and the digest of the mutation. One action therefore binds every
credential operation as narrowly as separate actions would, and the page
stays unchanged. The M2 plan's `credential.create|replace|rename|delete|
assign|authorize` and `vault.import_legacy` are not added (decision for
the main chat). The admin cancel of a transfer
(`operations.transfer.cancel`) belongs to the operations part.

## Keyring purposes

`keyring.Credential` (`credential`, seal) is added to the closed list for
saved passwords. It is a new stored format: renaming it later makes every
sealed password unreadable.

## Migration registry

The phases of the entities kept in place now follow the package map
(label only, no behaviour change): E26 and E27 (commands) and the rest of
E28 (directories and command set references, completed by HO3 and CM1)
are B6; E30 (legacy vault) and E32 (saved passwords) are B5.

## Modules

No module is added by these contracts. The entries are added by the
package that first imports the module, as in M1 (the architecture tests
reject entries for modules that are not required):

| Module | Tier | Importer | Package | Reason |
|---|---|---|---|---|
| `github.com/pkg/sftp` (with `github.com/kr/fs`) | B | `internal/files/sftp` | FS2 | K2; concurrent reads and writes, `posix-rename`, extensions. Paged directory reads and no-follow chmod (`lsetstat@openssh.com`) need its low-level request API or a small own request layer; FS2 decides and reports. |
| `github.com/hirochachacha/go-smb2/v2` as a shortened, pinned fork in `third_party/go-smb2` (`replace`), with `github.com/geoffgarside/ber` | B | `internal/files/smb` | SM0, FS3 | K1; QUIC, Kerberos and LZ4 removed; vulnerabilities tracked by hand. |
| `golang.org/x/oauth2` | A | `internal/auth/oidc`, `internal/auth/github` | ID2, ID3 | K7; only if the main chat keeps it (recommendation of the M2 plan: own code for code exchange and PKCE). |

## Deviations from the M2 plan

- `Backend.List(ctx, path, cursor, limit)` became `OpenListing` with
  `Listing.Next(ctx, max)`: Python pages over a live directory handle,
  and the cursor with its binding to user, connection and source belongs
  to `internal/files`, not to each backend.
- `Create` became `Write` with options; one write path covers create,
  upload, editor save and copy.
- Conflict strategies are `error` and `replace` only; Python has no skip,
  abort or "apply to the rest".
- Step-up for credentials stays one action, `credentials.vault` (see
  above).
- `remotecmd` needs no sudo input; `Script` covers automation and sets.

## Visible changes

- Preview of non-UTF-8 text on SFTP shows Latin-1 text instead of
  "binary" (D-23).
- Reading or listing a path with control characters is refused on SFTP
  too (Python refused them only for mutations); names that are not valid
  UTF-8 cannot be opened.
- The editor's "binary" and "too large" answers carry codes
  (`FILE_BINARY`, `FILE_TOO_LARGE`) beside the text.
