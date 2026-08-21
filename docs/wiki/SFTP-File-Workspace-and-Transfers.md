# SFTP File Workspace and Transfers

The File Workspace uses SFTP over SSH. It can reuse active terminal sessions,
open saved SSH hosts, or create temporary SFTP-only connections.

## Sources and tabs

The source launcher offers supported SFTP sources:

- an active SSH session;
- a saved SSH profile;
- a new SFTP quick connection.

Each side has independent source tabs and directory state. The workspace starts
with one file area and can switch to a side-by-side layout for remote-to-remote
work. A source already open on the opposite side is not silently duplicated.

The SMB action is disabled, labeled **Coming soon**, and is not a supported
connection source. It opens no SMB connection and generates no SMB network
activity.

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

All operations authenticate the WebSSH user and verify ownership of the SSH or
temporary connection.

## Transfer architecture

Large file bodies do not travel as base64 Socket.IO messages. Socket.IO creates
bounded control state and single-use user-bound transfer tokens. HTTP routes
stream upload, download, and folder archives.

Server-to-server work runs as a bounded cancellable background job. The
transfer queue tracks progress, errors, cancellation, and conflict choices such
as skip or overwrite.

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
editor refuses files above its size cap and saves through the existing owned
SFTP session.

Treat remote content as untrusted. Previewing or editing a file does not make
its commands safe to execute.

## Server-to-server copy

Open source and destination in the two file areas, select items, and start the
copy. The server reads from one SFTP connection and writes to the other without
routing the entire payload through the browser.

Both connections remain owned by the same WebSSH user, both count against
capacity, and cancellation is tied to the server-owned transfer record.

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
