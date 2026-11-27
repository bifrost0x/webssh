# M2 contracts

This document fixes the contracts the packages of the M2 parity milestone
are built against. It extends [m1-contracts.md](m1-contracts.md); the rules
of "How contracts are fixed" there apply unchanged. The catalog tables
below (headings that start with "Error codes", "Message types" or
"Step-up actions") are joined with those of the M1 document and checked
against the code by `internal/architecture`.

The parts are written by two contract packages; each part has its own
top-level heading.

## Data and files (V2a)

This part fixes the contracts between the Go packages built for M2 in
the areas files, transfers, saved passwords, commands, remote commands,
quotas, cron and background jobs. External identity, operation (backup,
restore, audit, feature switches), the wiring files of `cmd/webssh`, the
realtime catalog of the new areas and the end-to-end harness are fixed in
the second part (V2b).

The [package map](go-package-map.md) says which package may import which.

### How these contracts are fixed

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

### Files

`internal/files` owns the workspace; `internal/files/sftp` and
`internal/files/smb` implement backends.

#### Backend

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
- `Stat` with `follow` describes a link target, with the canonical path
  of the final target in `Entry.Path` (SFTP `realpath`); SMB refuses
  (`REPARSE_POINT_REJECTED`). `Open` refuses directories and links.
- Links (decision of the main chat on the FS2 report): reads follow links
  as in Python (preview, editor load, image preview, downloads), so a file
  such as `sites-enabled/*` can still be shown, edited and downloaded.
  They do so through `files.OpenFollow` in the file layer, which resolves
  the link with `Stat(follow)` and opens the target; `Backend.Open` keeps
  refusing links. An editor save follows the link as Python did
  (`WriteOptions.FollowSymlink`, the link stays). Every other change
  (rename, delete, chmod, create, upload without the editor) never
  follows a link and acts on the link itself.
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

#### Capabilities and sources

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

#### Path model

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

#### Decoding rule (D-23)

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

#### Listing and cursors

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

#### Limits

The file limits keep their names and defaults: `MAX_EDITOR_FILE_SIZE`
(5 MiB), `EDITOR_SAVE_BYTES_PER_MINUTE`, `MAX_PREVIEW_SIZE` (512000),
`MAX_PREVIEW_TAIL_LINES` (10000), `MAX_SUPPORTED_FILE_SIZE` (1 GiB),
`FILE_CONTROL_MAX_PATH_BYTES` (4096), `FILE_CONTROL_BYTES_PER_MINUTE`,
`REMOTE_FILENAME_MAX_BYTES`, `REMOTE_LISTING_MAX_METADATA_BYTES` (4 MiB),
`SFTP_MAX_PACKET_BYTES`, `SFTP_MAX_HANDLE_BYTES`, `SFTP_OPERATION_TIMEOUT`,
`SFTP_CHMOD_ENABLED`, `SMB_CONNECT_TIMEOUT_SECONDS`,
`SMB_IO_IDLE_TIMEOUT_SECONDS`, `SMB_ALLOWED_TARGETS`. `files.Budget`
defaults to 10000 members and depth 50.

#### Realtime

The message types of the file area (`files.*`, `smb.*`, `transfer.*`)
with their `Spec` and the mapping to the Socket.IO events of the
Python release (`list_directory`,
`create_directory`, `rename_file`, `delete_item`, `prepare_transfer`,
`cancel_transfer`, `transfer_server_to_server`, `quick_connect`,
`file_source_disconnect`, …) are defined by the packages that own the
areas (FS1 for `files.*`, FS3 for `smb.*`, TR1 for `transfer.*`; see
"Realtime shim by area" in the second part). Payloads keep the members of today;
failures carry the upper-case code as `code` (files) or `error_code`
(transfers) and the members `retryable`, `limit_kind`, `limit_bytes`,
`actual_bytes`, `revision`, `recovery_leaves`, `character`, `line`,
`save_challenge` in `details`.

### Message types (files)

Defined by FS1. Payload types are in `payload_files.go` of
`internal/realtime/protocol`; the shim file `realtime-shim-files.js` maps
the Socket.IO events of today to them and turns results and failures into
the push events the pages listen for (`directory_listing`, `preview_data`
/ `preview_error`, `edit_data` / `edit_error`, `file_saved`, the generic
`error` with `operation`, `source_id`, `request_id` and `path`). Every
type runs asynchronously and charges the per-user byte budget of file
requests (`FILE_CONTROL_BYTES_PER_MINUTE`; the editor body
`EDITOR_SAVE_BYTES_PER_MINUTE`), which answers `rate_limited`. Types
marked "mutates" re-validate the browser session before they run.

| Type | Direction | Owner | Payload | Socket.IO today | Spec |
|---|---|---|---|---|---|
| `files.list` | client | `internal/files` | `FilesList` → `FilesListing` | `list_directory` → `directory_listing` | 60 s |
| `files.list.cancel` | client | `internal/files` | `FilesListCancel` → `Empty` | `cancel_directory_listing` (always succeeds) | 30 s |
| `files.home` | client | `internal/files` | `FileRef` → `FilesPath` | `get_home_directory` → `home_directory` | 30 s |
| `files.preview` | client | `internal/files` | `FilesPreview` → `FilesPreviewData` | `preview_file` → `preview_data` / `preview_error` | 60 s |
| `files.preview.image` | client | `internal/files` | `FilesImage` → `FilesImageData` | `download_file_binary` with `for_preview` → `file_download_ready_binary` | 60 s |
| `files.edit.open` | client | `internal/files` | `FilesEditOpen` → `FilesEditData` | `open_file_for_edit` → `edit_data` / `edit_error` | 60 s |
| `files.edit.save` | client | `internal/files` | `FilesEditSave` → `FilesSaved` | `save_file` → `file_saved` | mutates, 120 s, payload 6 × `MAX_EDITOR_FILE_SIZE` + 64 KiB |
| `files.mkdir` | client | `internal/files` | `FilesMkdir` → `FilesPath` | `create_directory` → `directory_created` | mutates, 60 s |
| `files.create` | client | `internal/files` | `FilesCreate` → `FilesCreated` | `create_file` → `file_created` | mutates, 60 s |
| `files.rename` | client | `internal/files` | `FilesRename` → `FilesRenamed` | `rename_file` → ack and `file_renamed` | mutates, 60 s |
| `files.delete` | client | `internal/files` | `FilesDelete` → `FilesPath` | `delete_item` → `item_deleted` | mutates, 300 s |
| `files.source.close` | client | `internal/files` | `FilesSourceClose` → `FilesSourceClosed` | `file_source_disconnect` → `file_source_disconnect_success` | mutates, 30 s |

The payload bound of the other types is 32 KiB. `check_exists` and
`get_file_stat` have no caller in the frontend and get no type (D-13).
The permission events (`get_file_permissions`, `set_file_permissions`,
`*_file_permissions_job`) belong to AU2; `probe_session_sftp`,
`request_session_directory` and `quick_*` to FS2.

### Transfers

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

### Saved passwords and the legacy vault

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

### Commands and command sets

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

### Remote commands

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

### Quotas

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

### Cron

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

### Background jobs

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

### Error codes (data and files)

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

### Step-up actions (data and files)

| Action | Used by |
|---|---|
| `credentials.vault` | `internal/vault` |

`credentials.vault` is in the audience of every signed-in account
(`internal/auth/stepup/audience.go`); the vault checks that the intent
belongs to the user and the session.

The page asks for `credentials.vault` with the intent token as target
(`static/js/native-credentials.js`), and the intent carries the operation
and the digest of the mutation. One action therefore binds every
credential operation as narrowly as separate actions would, and the page
stays unchanged. The M2 plan's `credential.create|replace|rename|delete|
assign|authorize` and `vault.import_legacy` are not added (decision for
the main chat). The admin cancel of a transfer
(`operations.transfer.cancel`) belongs to the operations part.

### Keyring purposes

`keyring.Credential` (`credential`, seal) is added to the closed list for
saved passwords. It is a new stored format: renaming it later makes every
sealed password unreadable.

### Migration registry

The phases of the entities kept in place now follow the package map
(label only, no behaviour change): E26 and E27 (commands) and the rest of
E28 (directories and command set references, completed by HO3 and CM1)
are B6; E30 (legacy vault) and E32 (saved passwords) are B5.

### Modules

No module is added by these contracts. The entries are added by the
package that first imports the module, as in M1 (the architecture tests
reject entries for modules that are not required):

| Module | Tier | Importer | Package | Reason |
|---|---|---|---|---|
| `github.com/pkg/sftp` (with `github.com/kr/fs`) | B | `internal/files/sftp` | FS2 | K2; concurrent reads and writes, `posix-rename`, extensions. Paged directory reads and no-follow chmod (`lsetstat@openssh.com`) need its low-level request API or a small own request layer; FS2 decides and reports. |
| `github.com/hirochachacha/go-smb2/v2` as a shortened, pinned fork in `third_party/go-smb2` (`replace`), with `github.com/geoffgarside/ber` | B | `internal/files/smb` | SM0, FS3 | K1; QUIC, Kerberos and LZ4 removed; vulnerabilities tracked by hand. |
| `golang.org/x/oauth2` | A | `internal/auth/oidc`, `internal/auth/github` | ID2, ID3 | K7; only if the main chat keeps it (recommendation of the M2 plan: own code for code exchange and PKCE). |

### Deviations from the M2 plan

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

### Visible changes

- Preview of non-UTF-8 text on SFTP shows Latin-1 text instead of
  "binary" (D-23).
- Reading or listing a path with control characters is refused on SFTP
  too (Python refused them only for mutations); names that are not valid
  UTF-8 cannot be opened.
- The editor's "binary" and "too large" answers carry codes
  (`FILE_BINARY`, `FILE_TOO_LARGE`) beside the text.

## Identity, operation, wiring and harness (V2b)

### External identity

`internal/auth` (file `external.go`, `flight.go`) defines the contract of
the external providers; the provider packages `internal/auth/ldap`,
`internal/auth/oidc` and `internal/auth/github` declare what they consume
in their `contract.go`.

- **Providers.** `auth.ProviderName` is `ldap`, `oidc` or `github`.
  LDAP is a `auth.Provider` (name and password, same timing for every
  refusal). OIDC and GitHub are `auth.ExternalProvider`:
  `Name()`, `Begin(ctx, Flight) (redirectURL, error)` and
  `Complete(ctx, Flight, Callback) (Identity, error)`. The registry of
  `internal/auth` holds them; `cmd/webssh/wire_<provider>.go` registers
  them. Every refusal is `auth_failed` without provider text; an
  unreachable provider is `unavailable`.
- **Flight.** One redirect in progress: provider, purpose (`login`,
  `link`, `step_up`, the values of the Python login state), state, nonce,
  PKCE verifier (`NewFlight`: 32, 32 and 64 random bytes as base64url, as
  `secrets.token_urlsafe`), user id, auth generation and session id for
  `link` and `step_up`, the step-up intent token (`Flight.Intent`), the
  administrator step-up action and target, the continuation.
  The flow of `internal/auth` stores it server-side, bound to the browser
  binding, consumes it once and drops it after `auth.FlightTTL` (five
  minutes). Providers keep no per-request state. `Flight.Accept(cb, now)`
  is the first check of every callback: state compared in constant time,
  not expired, no provider error, a code present. `ParseCallback` refuses
  a repeated or oversized parameter (fuzzed). `Flight.Challenge` is S256
  (RFC 7636 vector tested). `link` and `step_up` ask the provider to
  authenticate again (`prompt=login`; for OIDC step-up also `max_age=0`
  and `OIDC_STEP_UP_ACR_VALUES`).
- **Identity.** Provider, issuer (OIDC issuer, `LDAP_PROVIDER_ID`, empty
  for GitHub), subject (OIDC `sub`, numeric GitHub id, canonical LDAP
  unique attribute), username, display name, e-mail and its verification,
  the LDAP DN, assurance and amr methods. Accounts are found only by
  `(issuer, subject)`, never by name or e-mail.
- **Mapping to accounts.** `auth.IdentityLinks` (`Account`, `Provision`,
  `LinkTx`, `Unlink`, `List`) is implemented by each provider package over
  its own table. `(issuer, subject)` is unique; an account has at most one
  identity per LDAP provider and one GitHub identity. A second link is
  `conflict`, never a move. `Account` is `not_found` for an unlinked
  identity; the caller then provisions or refuses. `Provision` follows the
  provider's policy (`LDAP_AUTO_PROVISION`; GitHub `auto_provision` with the
  organisation allowlist, which production requires) and is `forbidden`
  otherwise; OIDC never provisions. Link, unlink and provision run after
  the consumer consumed the step-up grant.
- **Managed accounts.** `accounts.Manager` stays `""`, `ldap` or
  `github` (E01). An LDAP identity makes the account LDAP-managed; a
  GitHub identity only when it provisioned the account
  (`provisioned_by_github`). OIDC never manages an account, as in
  `models.py`; the M2 plan's `managed_by = oidc` is not taken over. A
  managed account has no local password and cannot change one. Unlinking
  an LDAP identity needs a new local password (`ldap.Accounts.ReleaseTx`).
  The provisioning call of `internal/accounts` is
  `ProvisionTx(ctx, tx, username, manager string) (userID int64, error)`;
  it is binding when ID4 merges it.
- **Bootstrap.** `webssh issue-factor-bootstrap` issues a one-time code,
  valid ten minutes, bound to the account and the action, stored only as
  its MAC (`keyring.FactorBootstrap`). It is the step-up method
  `bootstrap` (C-MFA-11, ID3).
- **Step-up methods** of the external providers keep the Python names:
  `ldap`, `oidc`, `github`, `bootstrap`. The redirect providers complete a
  step-up through `StepUpProofs.ProveExternal(ctx, p, intent, method,
  assurance) (grant, error)`, which `internal/auth/stepup` provides (ID2).
- **Revalidation.** `auth.Revalidator.Revalidate(ctx, userID)` re-checks an
  LDAP account against the directory every
  `LDAP_SESSION_REVALIDATION_SECONDS`, as a job and before a request whose
  last check is older. A refusal or an unreachable directory ends every
  session of the account with the reason `directory_refused` (fail
  closed). While the check runs, a request gets
  `503 ldap_validation_in_progress` with `Retry-After: 1`.
- **Callback paths (invariant I-03).** `auth.PathOIDCLogin`
  (`/oidc/login`), `auth.PathOIDCCallback` (`/oidc/callback`),
  `auth.PathGitHubLogin` (`/auth/github/login`),
  `auth.PathGitHubCallback` (`/auth/github/callback`) and
  `auth.PathLDAPLogin` (`POST /login/ldap`) never change; a test of
  `internal/httpapi` checks that they are in the route catalog. The stored
  GitHub `redirect_uri` is kept byte for byte.
- **Tables.** Owners `authldap`, `authoidc`, `authgithub`:
  `authldap_identities` (E03), `authldap_revalidation` (E37),
  `authoidc_identities` (E05), `authgithub_identities` (E04),
  `authgithub_config` (E06, client secret sealed with
  `keyring.GitHubClientSecret`). The migration specification uses these
  names.
- **Test doubles.** `internal/auth/authtest`: `Provider` (a redirect
  provider whose codes the test issues, one use each), `Links` (in-memory
  links with the uniqueness rules), `Revalidator`.

### Step-up actions (identity and operation)

The names are those the Python release checks (`step_up_required`) and
the frontend sends; every action belongs to exactly one audience in
`internal/auth/stepup/audience.go` (administrator, own account, or any
account with a checked target), which a test enforces.

| Action | Used by |
|---|---|
| `user.manage` | `internal/accounts` (target `<user id>:<action>`) |
| `user.mfa_reset` | `internal/accounts` |
| `recovery.reset` | `internal/accounts` |
| `ldap.link` | `internal/auth/ldap` |
| `ldap.unlink` | `internal/auth/ldap` (target `<user id>:<identity id>`) |
| `oidc.link` | `internal/auth/oidc` |
| `oidc.unlink` | `internal/auth/oidc` (target `<user id>:<identity id>`) |
| `oidc.self_link` | `internal/auth/oidc` (own account) |
| `github.config` | `internal/auth/github` (target `global`) |
| `github.link` | `internal/auth/github` (own account) |
| `github.unlink` | `internal/auth/github` (own account) |
| `settings.update` | `internal/settings` (target `global`) |
| `audit.retention` | `internal/audit` (target `global`) |
| `backup.create` | `internal/backup` (target `new`) |
| `backup.cancel` | `internal/backup` |
| `backup.download` | `internal/backup` |
| `backup.upload` | `internal/backup` (target `upload`) |
| `backup.restore_prepare` | `internal/backup` |
| `backup.restore` | `internal/backup` |
| `operations.session.disconnect` | `internal/operations` (target: session reference) |
| `operations.connection.disconnect` | `internal/operations` (target: connection reference) |
| `operations.transfer.cancel` | `internal/operations` |
| `host_key.global_add` | `internal/ssh/hostkey` (target `global`) |
| `host_key.global_delete` | `internal/ssh/hostkey` |
| `server.operation` | `internal/hostops` (target: operation intent) |

The M2 plan's working names (`user.lock`, `identity.link`,
`backup.restore` with `secret.rotate`, …) are replaced by these. Secret
rotation is a CLI command only and has no step-up action.

### Error codes (operation)

| Code | HTTP status | Default message |
|---|---|---|
| `action_unconfirmed` | 503 | The action could not be confirmed. |
| `deployment_locked` | 409 | The setting is controlled by the deployment configuration. |
| `out_of_range` | 400 | A value is out of range. |
| `ldap_validation_in_progress` | 503 | Directory session validation is in progress. |

`out_of_range` carries `setting`, `min` and `max` as details;
`deployment_locked` carries `setting` and `policy`. The operations routes
answer a connection, session or transfer that is gone with
`404 {"code": "unavailable"}` as the Python release does; like the admin
step-up's `invalid_value`, `internal/operations` writes that answer itself.

New revocation reason: `directory_refused` (terminals end, as for a lock).
New keyring purposes: `github_client_secret` (Seal), `factor_bootstrap`
and `backup_download` (MAC). New store owners: `authgithub`, `authldap`,
`authoidc`, `backup`.

### Operation

- **Backup format** stays `webssh-go-backup` version 1
  (`internal/backup/backup.go`). Online backups snapshot the live database
  through `backup.Snapshotter` (`internal/store`, `VACUUM INTO`), write the
  archive with mode 0600 into `BACKUP_TEMP_DIR`, and are downloaded once
  with a token stored as its MAC (`keyring.BackupDownload`) after the
  `backup.download` step-up. `--without-secret-key` leaves out
  `data/secret_key` and the keyring material (D-08).
- **Restore** reads Go archives strictly (D-30: no absolute paths, no
  `..`, no links or devices, every member in the manifest) within
  `backup.Limits` (the `BACKUP_MAX_*` values and defaults of the Python
  release). Python backups (`python-v1`, `python-v2`) go through
  `backup.LegacyRestorer.RestoreLegacy`, implemented in
  `internal/migrate/legacy` with the steps of the one-time migration and
  connected in `cmd/webssh/wire_backup.go`; `internal/backup` never imports
  it.
- **States.** Operations use the Python statuses (`pending`, `running`,
  `uploading`, `verifying`, `verified`, `ready`, `downloading`,
  `restoring`, `failed`); `Active()` marks those that cannot be cancelled.
  A restore has `preparing`, `in_progress`, `succeeded`, `failed`,
  `rollback_failed`; the blocking ones keep the server in maintenance after
  a restart until it is finished (table `backup_restore`). A legacy
  `restore-status.json` is only read by the migration (A10).
- **Maintenance.** `backup.Maintenance` (`Enter(ctx, reason) (leave,
  error)`, `Active()`), provided by `cmd/webssh`: `/ready` answers 503,
  every other route `503 maintenance`, realtime connections close with
  4503 and new ones are refused. Reasons `restore`, `rotation`,
  `legacy_source_changed`; only one at a time (`busy` otherwise); the
  last one ends only with a restart.
- **Audit.** `internal/audit/export.go`: `MaxExportScan` 50,000 lines,
  `ExportFilter{From, To, Level, Query}`, `ExportMeta{Scanned, Truncated}`
  with `Completeness()` for `X-WebSSH-Audit-Completeness`, `Record` with
  the raw line so Python lines are exported byte for byte. Retention is
  the rotation's `backup_count` (1 to 90) and needs no job (the plan's
  retention job is not needed).
- **Instance operations.** `internal/operations/runtime.go` declares the
  sources of the operations view: `Connections` (realtime), `Sessions`
  (terminal), `Transfers`, `Jobs`, `Quotas`. References are
  `operations.ConnectionRef(id)` = hex `sha256("admin-connection:"+id)`
  and `operations.SessionRef(id)` = hex `sha256("admin-ssh:"+id)`, tested
  against Python vectors. Raw ids never reach the browser.
- **Integration switches** (C-ASET-05) are the existing
  `settings.App.RuntimeFeature(name)` with `FeatureStatus{Enabled, Saved,
  Source}`; `Source` keeps the Python values `compose` (locked by an
  explicit environment value), `admin` and `default`, and changes answer
  `409 deployment_locked` for a locked switch.
- **Support report.** `operations.SupportRequest` with the areas
  `general`, `ssh`, `files`, `sign_in`, `automation` and the optional
  reference `SMB-` plus 12 upper-case hex digits; anything else is
  `invalid_request` ("Invalid report options"). The report lists the
  features and readiness failures of `SupportFeatures` and
  `SupportReadinessFailures` and never reads logs, targets or account data.
- **Test doubles.** `internal/backup/backuptest`: `Maintenance` and
  `Restorer`.

### Wiring per area

`cmd/webssh/wire_areas.go` lists the areas of M2 in a fixed order; each
has its own file `wire_<area>.go` with a function `<area>Area()
extension`, and the package that builds the area edits only that file.
The extension hooks are `schemas`, `prepare` (optional dependencies before
the capabilities are built), `wire` (HTTP routes on `sys.edge.Mux()` and
realtime types with `sys.realtime.Mount`), `background` (periodic work on
`sys.background`, ending with its context) and `migrate` (the migration
steps of the entities the area takes over, after those of the release).
The wire files also hold the compile-time checks that existing providers
satisfy the area's consumer interfaces.

| Area | Package |
|---|---|
| `ldap` | ID1 |
| `oidc` | ID2 |
| `github` | ID3 |
| `accounts` | ID4 |
| `sshext` | NW1 |
| `gateway` | NW2 |
| `jobs` | RT1 |
| `terminal` | TM1 |
| `serverops` | HO1 |
| `discovery` | HO2 |
| `hostcontext` | HO3 |
| `files` | FS1 |
| `sftp` | FS2 |
| `smb` | FS3 |
| `credentials` | VA1 |
| `transfers` | TR1 |
| `commands` | CM1 |
| `automation` | AU1 |
| `schedules` | AU2 |
| `backup` | OP1 |
| `rotation` | OP2 |
| `operations` | OP3 |
| `platform` | PF1 |

A test checks that the files and the list agree.

### Route catalog by area

The 501 catalog of `internal/httpapi` is split by area:
`routes_areas.go` lists the areas, and each `routes_<area>.go` holds
`<area>Built` (routes with their access level) and `<area>Preview` (routes
that still answer 501). A package moves each route it builds from the
preview list to the built list of its own file. The areas are `ldap`
(ID1), `oidc` (ID2), `github` (ID3), `accounts` (ID4), `retired` (FE1:
`POST /api/totp/disable`, without a caller after D-13), `backup` (OP1),
`operations` (OP3), `hostcontext` (HO3), `discovery` (HO2), `serverops`
(HO1), `credentials` (VA1), `automation` (AU1), `schedules` (AU2) and
`transfers` (TR1). The test against the Flask route table is unchanged:
every Python route is built or a preview route, never both.

### Realtime shim by area

The name table of the shim is split into `static/js/realtime-shim-<area>.js`
(`hosts`, `keys`, `settings`, `notes`, `files`, `smb`, `commands`,
`insights`, `terminal-tools`). Each file registers
`{requests, refresh, unavailable, features}` on `WebSSHRealtimeAreas`;
`realtime-catalog.js` joins them in that order, and an event in two areas,
or both built and answered as unavailable, stops the load. A package that
builds an area adds its `requests` and removes its `unavailable` replies
and feature patterns. Only the Go workspace loads the files, after
`realtime-wire.js` and before `realtime-catalog.js`; the Python templates
load none of them. The split changes no behaviour (JS tests compare the
joined table with the M1 table).

New message types of M2 (section 4.10 of the plan) are not fixed here.
Each area's types are defined by the package that owns the area, in a
contract commit of that package: the type with its `Spec` in the catalog
of `internal/realtime/protocol`, the mapping in the area's shim file, and
the rows in a table "### Message types (<area>)" of this document, which
`internal/architecture` joins with the M1 catalog. A type belongs to one
package only.

| Area | Owning package |
|---|---|
| `files` | FS1 |
| `smb` | FS3 |
| `transfer` | TR1 |
| `commands` | CM1 |
| `insights`, `inventory`, `herdr` | HO1 |
| `hostops.discovery` | HO2 |
| `gateway` (`prompt.interactive`) | NW2 |
| `credentials` (if it has socket events) | VA1 |

### Message types (gateway)

Defined by NW2 (`internal/realtime/protocol/payload_gateway.go`). The
shim maps them in `static/js/realtime-shim-terminal-tools.js`; server
events of an area are joined through the area's `events` table (see
`realtime-catalog.js`). `prompt.interactive` carries one
keyboard-interactive round of a connection attempt: of the SSH gateway
(target and the jump host in front of it) and of ordinary hosts whose
page answers prompts: there the dialer's own plan chooses the methods
and puts the rounds it cannot answer to the user through
`client.Challenger`, which `(*gateway.Attempt).Challenger` implements on
an attempt begun with `gateway=false` (`terminal.Variants.Interact`,
C-CONN-09). Its prompt is bound to the connection,
the user and the attempt's `request_id`, has its own `prompt_id`, the
server's echo flag per question and the seconds left (`expires_in`, at
most 120). Answers are one-shot; a second answer, a wrong count or more
than 16 KiB is refused with `not_found` or `invalid_request`.

| Type | Direction | Owner | Payload | Socket.IO today |
|---|---|---|---|---|
| `prompt.interactive` | server | `internal/ssh/gateway` | `PromptInteractive` | `ssh_gateway_challenge` (`challenge_id` = `prompt_id`) |
| `prompt.respond` | client | `internal/ssh/gateway` | `PromptRespond` | `ssh_gateway_answer` |
| `gateway.setup` | server | `internal/ssh/gateway` | `GatewaySetup` | `ssh_gateway_progress` |
| `gateway.output` | server | `internal/ssh/gateway` | `GatewayOutput` | `ssh_gateway_output` |
| `gateway.input` | client | `internal/ssh/gateway` | `GatewayInput` | `ssh_gateway_input` |
| `gateway.ack` | client | `internal/ssh/gateway` | `GatewayAck` | `ssh_gateway_ack` |

`terminal.open` gains the auth type `tailscale` and the member
`interactive` (`gateway_interaction` or `ssh_interaction` of today); a
gateway selector without it is refused as in the Python release. `ssh_gateway_quick_cancel` belongs
to Quick SFTP (FS2) and stays unavailable until FS2 builds it.

The dialer gains `client.Target.Variant` (`internal/ssh/client/variant.go`,
additive): `Auth` replaces the authentication plan of every hop (the
gateway strategy; with it the target needs no password or key), `Dial`
replaces the network policy for the target hop (Tailscale SSH, no jump
host and no proxy) and `Ready` runs on the authenticated target before the
connection is returned (the gateway's readiness probe).
`client.Display.Tailscale` marks a saved host with the auth type
`tailscale`. Host keys apply to every variant.

### Message types (smb)

Defined by FS3 (`internal/realtime/protocol/payload_smb.go`), mapped in
`static/js/realtime-shim-smb.js`. With `SMB_ENABLED` false no type is
mounted; the shim answers `unknown_type` with the code `SMB_DISABLED`
of today. Results are the success payloads of the Python release; the
shim pushes the events of today from them, and from a failure the error
event of today (the optional `failurePush` builders of an area entry in
`realtime-catalog.js`, additive).

| Type | Direction | Owner | Payload | Socket.IO today |
|---|---|---|---|---|
| `smb.share.list` | client | `internal/files/smb` | `Empty` → `SMBShares` | `list_smb_shares` (`smb_shares_list`, `smb_share_error`) |
| `smb.share.save` | client | `internal/files/smb` | `SMBShareSave` → `SMBShareSaved` | `save_smb_share` (`smb_share_saved`, `smb_shares_list`, `smb_share_error`) |
| `smb.share.delete` | client | `internal/files/smb` | `SMBShareDelete` → `SMBShareDeleted` | `delete_smb_share` (`smb_share_deleted`, `smb_shares_list`, `smb_share_error`) |
| `smb.connect` | client | `internal/files/smb` | `SMBConnect` → `SMBConnected` | `smb_quick_connect` (`smb_quick_connect_success`, `smb_quick_connect_error`) |
| `smb.connect.cancel` | client | `internal/files/smb` | `SMBConnectCancel` → `Empty` | `smb_quick_connect_cancel` |

- Specs: list `RateKey smb_share_list`; save and delete `Mutates`,
  `RateKey smb_share_mutation`; connect `Async`, `Mutates`, `RateKey
  smb_connect`, 24 KiB, timeout `SMB_CONNECT_TIMEOUT_SECONDS` plus twice
  `SMB_IO_IDLE_TIMEOUT_SECONDS` plus 5 s; cancel inline. The buckets take
  `SMB_SHARE_LIST_RATELIMIT`, `SMB_SHARE_MUTATION_RATELIMIT` and
  `SMB_CONNECT_RATELIMIT` (cmd/webssh `realtimeLimiter`).
- A connect failure carries `details.diagnostic_id` (`SMB-` and 12
  upper-case hex digits); the server log has the same id with the
  credential-free diagnostic (`diagnostic_phase`, `cause_type`,
  `nt_status`). Codes outside `_SMB_CONNECT_CODES` become
  `CONNECTION_FAILED`; saved-password codes pass unchanged. The shim maps
  `rate_limited`, `invalid_request`, `busy` and `unknown_type` to
  `RATE_LIMITED`, `INVALID_REQUEST`, `REQUEST_IN_PROGRESS` and
  `SMB_DISABLED`.
- Share validation failures are `validation_error` (`not_found` for an
  unknown id) with the Python text; requests decode strictly, so a
  member the page never sends (a password among them) is
  `invalid_request` instead of "Passwords cannot be saved".

Consumer interfaces of `internal/files/smb` (compiled):

```go
type Sources interface { Add(p principal.Principal, kind files.SourceKind, d files.Descriptor, b files.Backend) (string, error) }
type Passwords interface { ConnectionPassword(ctx, p principal.Principal, req CredentialRequest) ([]byte, error) }
type Network interface { Admit(ctx, role netpolicy.Role, host string, port int) (netpolicy.Admitted, error) }
```

`Sources` is the file source registry (FS1); `Passwords` adapts
`vault.Service.Password` (VA1) with the resource `smb:<id>` or a
confirmed target. `(*Service).ResourceTarget` gives the vault the
current target of a saved share. Store owner `smb` (table `smb_shares`:
one row per definition with the record as Python stored it, E22) is
added to `store.Owners`.

### End-to-end harness for M2

- `tests/e2e/go-suite.json` (formerly `tests/e2e/m1/go-subset.json`) lists
  the specs that must pass against Go; `tests/e2e/run-go-suite.js` runs
  them. Every excluded test has a `reason` and either the M2 package that
  unlocks it (`package`) or a capability of the build (`requires`); the
  runner refuses an entry without them.
- `serial: "e2e_admin"` marks specs that change stored settings of the
  shared seed account. With `--workers N` (N > 1) the other specs run in
  parallel and the marked ones afterwards on one worker.
- Seed parts the build skips are listed with their owner package in
  `internal/e2eseed/owners.go`; the package adds the applier with the
  entity and removes the row.
- Test hooks stay in the build tag `e2e` and the type namespace `e2e.`
  (M1 contracts, "End-to-end harness").
