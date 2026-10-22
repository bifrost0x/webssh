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

For Active Directory or TrueNAS, first try the DNS domain such as `example.com`
in the domain field with an account name such as `alice`. Alternatively, leave
the domain field empty and use a UPN such as `alice@example.com`. NetBIOS domain
names may not be accepted by every server.

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

### New files

Use **New file** in the pane toolbar, context menu, or mobile action sheet.
Enter a single filename in the displayed directory. Existing files, folders,
and links are never replaced by this action. SFTP requests initial permissions
of `0600`; SMB retains the server's normal inherited ACLs. Optionally open the
empty file in the editor after creation. A failed editor open does not delete
the created file.

### Unix permissions

Permissions are disabled by default. This is an instance-wide operator setting,
not a personal preference or an Admin-panel toggle. The file manager includes
an expandable **Enable chmod** help section while the instance setting is disabled.
After activation and a page reload, this setup hint disappears. Missing server
support or an SMB source does not make this instance-wide hint reappear.

For Docker Compose, remove the leading `#` from this existing optional line under
the `webssh` service's `environment` section in `docker-compose.yml`:

```yaml
      - SFTP_CHMOD_ENABLED=true
```

Apply the change with `docker compose up -d --force-recreate webssh`. When using
the production overlay, use the same `-f` files as your normal deployment;
alternatively uncomment `SFTP_CHMOD_ENABLED: "true"` in that overlay. A plain
`docker compose restart` does not apply changed container environment variables.
For source installations, set `SFTP_CHMOD_ENABLED=true` in the application
environment or `.env`, then restart the application. An explicit environment
variable takes precedence over `.env`.

After activation, users reload WebSSH, reconnect their SSH/SFTP source and open
a directory. No WebSSH administrator role is required for using the action;
the remote account must have permission to change the selected object's mode.
To disable it, comment out the Compose line (or set it to false) and recreate
the service again. The action disappears from toolbars and menus, while new-file
creation and editing remain available. Direct mutation requests are also denied.

The action appears for SFTP sources after a successful handshake advertises
`lsetstat@openssh.com` version 1. SMB has no Unix permission editor. Unsupported
servers fail closed; WebSSH does not fall back to ordinary path-based chmod,
shell commands, or sudo.

Select one regular file or directory and choose **Permissions**. Review the
freshly loaded owner/group/other rwx values, change the checkboxes or three-digit
octal value, then explicitly apply. For directories, execute means traversal.
Removing owner access can prevent you from accessing the item afterward.
Known symlinks, special files, and objects with setuid/setgid/sticky bits cannot
be edited. There is no recursive chmod, chown, or ACL editor.

You can also select up to **20** regular files and/or directories in one pane
and choose **Permissions** from its toolbar, context menu or mobile actions.
All selected targets are listed in the dialog. If their current modes differ,
enter an explicit common mode; otherwise the existing mode is shown. Applying
changes each selected object individually and never changes directory contents.
For mixed files and directories, choose execute/traversal bits deliberately.

WebSSH inspects every target before enabling Apply, then checks the original
signed metadata again at each write. Inspection tokens expire after **60 seconds**;
close and reopen the dialog if they expire. WebSSH does not silently accept a
replacement object by obtaining a new token. Requests run sequentially and stop
at the first error, conflict, disconnect or uncertain result. The dialog reports
each changed, unchanged, failed or unsent item. Completed changes remain; this is
not an atomic transaction and there is no automatic rollback. Closing the dialog
stops remaining requests; an already submitted request may still complete.
Refresh and inspect the remote state before another attempt.

No-follow applies to the final path component, not to every ancestor or to an
immutable file identity. Use trusted servers and appropriately restricted remote
accounts. Do not enable this feature for privileged accounts working in directories
that untrusted users can replace or modify without suitable server-side isolation.
Metadata checks detect observed changes; they are not an atomic compare-and-set.
Unix rwx values do not describe every ACL rule. Changing mode can affect POSIX ACL
masks; hardlinks share the same inode and therefore the same permissions.

### Saving and uncertain results

The editor's **Review changes** step separates the target endpoint and path,
removed and added lines, and final save actions. Red `−` lines show removed
text; green `+` lines show added text, with their respective line numbers.
Large comparisons remain bounded and explicitly show when shortened; expand
the full original/edited versions before saving in that case. **Back to editing**
keeps the draft, **Download original** preserves the opened file's exact bytes,
and **Save reviewed changes** saves only the reviewed version.

SFTP editor saves stage content in a privately and exclusively created file,
retain ordinary rwx permissions, and require atomic replacement. Known special
bits or an owner/group mismatch prevent replacement. SFTP v3 does not provide
general ACL preservation: inode replacement can lose extended ACLs. Use another
method when exact ACL preservation is required. If staging fails, a private
`.webssh-tmp-*` file may remain on the remote server; WebSSH avoids unsafe
path-based rollback when an object could have changed concurrently.

A lost mutation acknowledgement is shown as an unknown result. Refresh and
review the remote state before acting again. The editor keeps the draft and
blocks another save after an uncertain outcome; download the draft, explicitly
reopen the file, then compare. A matching delayed success can reconcile the
result. Successful creation or rename is not a promise of power-loss durability.

Supported operations include:

- directory listing and navigation;
- create directory;
- rename;
- move files or folders on the same source with the pane's **Move…** action and
  folder picker, or by dragging them onto a destination folder in the current
  File Workspace pane, the embedded active-session SFTP browser, or the other
  pane;
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

Downloads intentionally do not implement HTTP byte ranges. A request carrying
`Range` still receives the complete `200` response and `Accept-Ranges: none`.
The server opens the remote file once before creating the response, obtains the
security-relevant size from that same handle, and keeps that handle for the
whole stream. Renaming or replacing the pathname while a response is active
therefore cannot switch the stream to another object.

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

Preview, editor, download, archive, and server-to-server reads bind their byte
limits to the already-open remote object. SFTP obtains size and type through
handle `fstat`; SMB uses the SMB2 CREATE response and rejects directory or
reparse-point handles. Observed bytes remain capped as a second guard if a file
grows after it was opened. Path metadata is not reused to authorize bytes from
a later open.

For SFTP, the remote SSH account and server configuration define which paths
are reachable; WebSSH does not add a virtual allowed-folder boundary. Deploy
`internal-sftp` with a server-side chroot when a user must be confined to one
subtree. Handle binding prevents a later pathname swap, but it is not a
replacement for server-side filesystem confinement.

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

The **Move…** action is available in both the standalone File Workspace and the
embedded active-session SFTP browser. Its picker shows folders from the same
authorized source only and revalidates the original selection before sending
the correlated rename requests.

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

## Sync the Workspace file browser with the terminal

In **Workspaces → Files**, **Synchronize folders with terminal** is enabled by
default in the compact header above the file list. Temporary probe failures
retry silently without adding status messages. This applies to the active
session's embedded browser, not the separate File Manager. In
**Settings → Preferences → Terminal**, each user can change
**Synchronize folders with terminal by default**. The preference is stored in
the user account and applies when opening or reloading the workspace. The
Workspace checkbox still overrides sync per SSH session for the current page;
switching sessions preserves those overrides.

Enabling sync first opens the terminal's actual working directory in Files.
Subsequent terminal navigation (`cd`, `pushd`, aliases, or a nested shell) is
observed from the remote process state. Opening a folder, using Up/Home, or
entering an absolute path in the embedded browser sends a quoted `cd -- '…'`
to that session. Selecting or previewing a file does not execute it. The browser
then follows the observed directory, including the result of a failed `cd` or
symlink resolution. Sync-generated input never uses broadcast mode.

The current implementation supports Linux targets with readable `/proc`,
`readlink`, and a `ps` implementation supporting `--ppid`, `pid`, `ppid`, `tty`,
`tpgid`, and `comm`. For WebSSH-managed tmux sessions it resolves the active pane
in the active window of that session. Ambiguous PTYs, inaccessible processes,
non-Linux targets, and restricted SSH exec channels report sync as unavailable.
No shell startup files are modified and no remote agent is installed.

Files-to-terminal navigation additionally requires an empty detected shell
prompt, bracketed paste mode, and a supported
foreground shell (bash, zsh, fish, sh, dash, or ksh). Shells without prompt-mode
signaling can still be followed, but automatic `cd` waits for a reliably
detected prompt. Finish any partial command or return from an application to
the prompt, then open the folder again. Navigation that cannot be sent safely
is **not queued for later execution**. A blocked folder action now explains
why it could not proceed; turn off sync to browse Files independently.
For managed tmux sessions the outer terminal's alternate screen is expected;
the server separately rejects copy mode and alternate-screen applications
inside the active tmux pane. A confirmed directory change from a sync-generated
`cd` acknowledges that command even when tmux coalesces prompt-mode signals,
provided no user input or shell change occurred meanwhile. Unknown or replayed
prompts and unfinished manual input remain guarded.
On tmux servers exposing `bracket_paste_flag`, after a manual Enter or Ctrl+C,
a fresh probe can also confirm the prompt
once live terminal output advances to a new line. It must find a supported
foreground shell with bracketed paste enabled **inside the pane**. This avoids
depending on mode changes that tmux may omit from the outer terminal, and keeps
navigation blocked while a prompt hook is still running. New typing, an active
paste, or transcript replay invalidates this confirmation. After reconnecting
at an unknown prompt, finish or cancel the current input to establish a live
prompt before using Files-to-terminal navigation.
Older tmux servers without this optional flag still support directory following
and the existing live-prompt and sync-generated `cd` checks. They cannot use the
additional confirmation after manual input when tmux omits the prompt signal;
Files-to-terminal navigation remains guarded in that case.
These are conservative UI guards, not an atomic shell protocol: custom prompt
behavior and concurrent input from another SSH/tmux client cannot be fully
inferred. Paths containing control characters are intentionally rejected.

The directory is sampled about every 1.5 seconds while the opted-in Workspace
file panel is visible; folder clicks request a fresh sample. Hidden panels,
other application views, disconnected sessions, and disabled sync stop polling.
Unavailable targets retry with a longer delay. After identifier validation,
requests consume the per-user rate limit before the ownership lookup. Each
owned session allows one in-flight probe with bounded response size and a
timeout; probes use a separate SSH exec channel without interrupting PTY output.
There is no directory polling when sync is off.
