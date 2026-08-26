# SFTP and SMB File Workspace and Transfers

The File Workspace uses SFTP over SSH and can optionally open temporary SMB
shares. SFTP can reuse active terminal sessions, open saved SSH hosts, or
create temporary SFTP-only connections.

## Sources and tabs

The source launcher offers:

- an active SSH session;
- a saved SSH profile;
- a new SFTP quick connection;
- an ephemeral SMB share when the administrator enables SMB.

Each side has independent source tabs and directory state. The workspace starts
with one file area and can switch to a side-by-side layout for remote-to-remote
work. A source already open on the opposite side is not silently duplicated.

SMB is opt-in and remains disabled with `SMB_ENABLED=false`. Enabling it
requires a non-empty `SMB_ALLOWED_TARGETS` list containing exact server
hostnames or IP addresses. The server field is resolved and checked against
that allowlist before a connection is opened. SMB always uses TCP 445 and
requires SMB 3.1.1, signing, encryption, and secure negotiation. The current
authentication mode is NTLM. Guest or null sessions, DFS, Kerberos,
administrative shares, reparse-point traversal, and automatic reconnect are
not supported.

The SMB dialog sends the password only for the requested temporary connection;
passwords and authentication secrets are never stored by WebSSH. Users may save
non-secret, per-user share definitions containing a display name, host, share,
domain, and username. Closing a source's final tab closes the connection after
any dependent transfer finishes. An application restart also removes all active
SMB sources.

For Active Directory or TrueNAS, enter a UPN-style username such as
`user@example.com` when the server requires the DNS realm. Use the separate
domain field only when the server expects the `DOMAIN\\user` form.

After authentication, WebSSH performs a non-mutating access inspection at the
share root. It separately records whether listing, file creation, directory
creation, and child deletion are granted, denied, or unknown. The workspace
shows confirmed write access, confirmed root read-only access, or unknown root
write access. This is evidence for the root only: ACLs on nested directories
can be more or less restrictive, so every operation still handles a remote
denial explicitly.

Connection failures show a sanitized reason in the SMB dialog. Failures that
reach the server-side connection job also include a reference in the form
`SMB-A1B2C3D4E5F6`; an operator can correlate it with `DATA_DIR/logs/app.log`
without exposing the backend exception text to the browser. The log record
separates target resolution, transport negotiation, security requirements,
session authentication, share access, and lifecycle handling, and can include
the exception class and SMB NT status when safely available.

Browser TLS and SMB encryption protect different links. TLS covers the browser
to WebSSH, while SMB encryption covers WebSSH to the share. The WebSSH process
must handle the submitted credentials and file contents, so deploy it on a
trusted host and allowlist only trusted SMB servers. This is not end-to-end
encryption between the browser and the share.

## Embedded active-session browser

In the single-terminal layout, an embedded SFTP browser follows the active SSH
session. Its state is separate from the standalone File Workspace, so switching
terminal sessions does not overwrite independent workspace tabs.

WebSSH probes SFTP availability for the selected session before showing the
embedded browser. Manual dismissal is retained for that session, and changing
viewport size keeps the mounted browser state instead of opening another
connection. Disconnecting the selected SSH session removes only its embedded
source; independent File Workspace tabs remain intact.

## File operations

Supported operations include:

- directory listing and navigation;
- create directory;
- rename;
- move files or folders between directories on the same source;
- delete;
- drag-and-drop file and folder upload;
- single and batch download;
- folder download as ZIP;
- server-to-server copy;
- existence and stat checks;
- image and syntax-highlighted text preview;
- log tail preview;
- inline text editing and save;
- selection and context-menu actions.

All operations authenticate the WebSSH user, resolve the opaque source ID
server-side, verify source ownership, and enforce the named capability before
touching SFTP or SMB.

## Transfer architecture

![WebSSH realtime session and bulk transfer lifecycle showing transfer records, single-use tokens, HTTP streams, and bounded jobs](https://github.com/bifrost0x/webssh/blob/main/docs/media/diagrams/session-and-transfer-lifecycle.png?raw=true)

The control record retains user and connection ownership while the body path
uses a short-lived token. This separation keeps large payloads away from the
Socket.IO terminal channel without weakening cancellation, quota, or lifecycle
tracking.

Large file bodies do not travel as base64 Socket.IO messages. Socket.IO creates
bounded control state and single-use user-bound transfer tokens. HTTP routes
stream upload, download, and folder archives.

The body routes are:

- `POST /api/transfers/<token>/upload` for streamed uploads;
- `GET /api/transfers/<token>/download` for streamed file downloads;
- `GET /api/transfers/<token>/folder-download` for bounded folder archives.

Server-to-server work runs as a bounded cancellable background job. The
transfer queue tracks progress, errors, cancellation, and conflict choices such
as skip or overwrite.

An SMB source maintains separate control and transfer sessions. Directory
navigation and metadata operations therefore remain available while a bulk
upload, download, or remote copy is using the transfer lane. Cancellation is
one idempotent request: the queue changes to **Cancelling** once and waits for
the authoritative terminal event instead of requiring repeated clicks.

HTTP responses, Socket.IO terminal events, notifications, and queue rows use
the same allowlisted transfer failure contract. The visible reason distinguishes
permission denial, an existing destination, a missing path, an unavailable
share or source, a timeout, a configured limit, cancellation, and unavailable
atomic replacement. Backend exception text, paths, and credentials are not
reflected to the browser.

When the browser or server knows the actual byte count, configured-limit
errors include the operation, actual size, and exact limit. Unknown or
untrusted sizes are never guessed.

Uploads and server-to-server copies start with a no-overwrite policy. If the
destination exists, the workspace asks whether to replace, skip, or cancel and
can apply that choice to the remaining batch. Replace uses a new authorized
transfer request and an atomic backend rename. If atomic replacement is not
available, the existing destination remains untouched and the queue explains
why the replacement was refused.

Queued and active transfers retain references to their source and destination
connections. Closing the last quick-connection tab defers disconnect until the
dependent transfer reaches a terminal state.

## Limits

| Variable | Default | Meaning |
|---|---:|---|
| `MAX_DOWNLOAD_SIZE` | 100 MiB | Maximum single file download |
| `MAX_ZIP_DOWNLOAD_SIZE` | 500 MiB | Maximum generated folder archive |
| `MAX_TRANSFER_MEMBERS` | 10,000 | Maximum traversed entries |
| `MAX_PREVIEW_SIZE` | 512,000 bytes | Maximum preview content in memory |
| `MAX_PREVIEW_TAIL_LINES` | 10,000 | Maximum requested tail lines |
| `MAX_SUPPORTED_FILE_SIZE` | 1 GiB | Maximum remote file size accepted by preview service |
| `MAX_EDITOR_FILE_SIZE` | 5 MiB | Maximum inline-edited file size |
| `SFTP_OPERATION_TIMEOUT` | 30 seconds | Timeout per SFTP channel operation |
| `TRANSFER_TEMP_DIR` | `DATA_DIR/tmp` | Private fallback archive directory |

Default transfer quotas are 8 records globally and 2 per user. Background jobs
default to 4 globally and 1 per user. Temporary-byte reservations default to
1 GiB globally and 512 MiB per user.

## Folder downloads

WebSSH prefers bounded streaming and uses private temporary storage only where
the archive path requires it. Size, member, timeout, ownership, and temporary
byte quotas apply. Symlinks and unsafe traversal are not followed as arbitrary
host filesystem paths.

## Preview and editor safety

Preview loads only bounded content. Tail mode limits requested line count. The
editor refuses files above its size cap and saves through the resolved, owned
file source.

Text saves carry the revision that was previewed and reject stale content.
Atomic replacement is the default. If an SMB account cannot provide it, the
editor asks for explicit consent before using a recoverable swap that keeps a
backup until the new file is in place. A failed rollback leaves named temporary
and backup artifacts in the error so an operator can recover the content; the
dirty editor buffer remains open.

Treat remote content as untrusted. Previewing or editing a file does not make
its commands safe to execute.

## Server-to-server copy

Open source and destination in the two file areas, select items, and start the
copy. The server reads from one SFTP or SMB source and writes to the other
without routing the entire payload through the browser. The same bounded engine
covers SFTP-to-SFTP, SFTP-to-SMB, SMB-to-SFTP, and SMB-to-SMB copies.

Both connections remain owned by the same WebSSH user, both count against
capacity, and cancellation is tied to the server-owned transfer record.
Existing targets are not overwritten without the conflict decision described
above.

For two folders on the same source, the workspace offers **Move** instead of a
copy. It uses the source's rename operation, refuses root, self, descendant,
and existing-destination moves, and never replaces an existing item. SMB path
relationship checks are case-insensitive.

## Connection lifecycle

- Active terminal-backed sources follow the SSH session lifetime.
- Quick sources use the bounded temporary connection pool.
- Closing a tab releases a quick connection only when no remaining tab or
  queued/active transfer references it.
- Disconnect events remove all matching stale workspace tabs while preserving
  unrelated tabs.

## Troubleshooting

### Source list is empty

Open an SSH session, create a saved profile, or choose a new SFTP quick
connection.

### Upload or download is rejected immediately

Check file-size, member, quota, rate, and token-expiry limits. Confirm the source
session is still connected.

### Transfer waits after closing a tab

This can be intentional. WebSSH retains the quick connection until queued or
active transfer references terminalize.

### Preview refuses a large file

Use a direct bounded download or tail mode. Preview and inline editing have
lower memory-oriented limits than raw transfer.

### Server-to-server copy fails

Verify both sides are connected, writable, and owned by the same WebSSH user.
Check background-job and transfer quotas plus the target conflict policy.

## Related pages

- [SSH Connections and Host Keys](SSH-Connections-and-Host-Keys)
- [Configuration Reference](Configuration-Reference)
- [Security Model and Hardening](Security-Model-and-Hardening)
