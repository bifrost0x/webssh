# Terminal and Persistent tmux Sessions

WebSSH uses xterm.js in the browser and Paramiko channels on the server. Socket.IO
carries terminal control and output events.

## Session workspace

The terminal supports:

- multiple session tabs;
- one-, two-, and four-pane layouts;
- floating terminal windows that move, resize, snap, minimize, and maximize;
- broadcast input across open sessions;
- a command palette with `Ctrl+K`;
- terminal search with `Ctrl+F`;
- tab switching with `Ctrl+1` through `Ctrl+9`;
- configurable scrollback from 50 to 10,000 lines;
- transcript download;
- recent connections;
- persistent session names;
- per-session notes;
- manual reconnect.

On macOS, use the platform's Command equivalents for copy and paste.

`Ctrl+C` copies selected text. With no selection, it sends the normal interrupt
character to the remote process.

When tmux mouse mode owns the selection, WebSSH accepts tmux's bounded OSC 52
clipboard request for that persistent session. A visible WebSSH notification
requires a fresh **Copy** click before the remote text reaches the browser
clipboard. Replayed output and ordinary non-tmux SSH sessions cannot request a
clipboard write. Browser clipboard permissions still apply.

Remote OSC 52 clipboard requests are limited to 128 KiB of decoded UTF-8 text.
Oversized OSC/DCS control strings are discarded by the terminal parser before
they can accumulate unbounded browser memory.

### Remote tmux clipboard configuration

WebSSH preserves the remote tmux configuration on both new connections and
reconnects. It does not change `set-clipboard` or `allow-passthrough` automatically.
Existing persistent sessions keep using the same tmux server and session names.

For tmux's own copy mode, `set-clipboard external` allows tmux to send clipboard
requests when the attached terminal supports them, while preventing applications
inside tmux from setting its clipboard buffers. Applications such as editors that
emit their own OSC 52 sequences may need additional operator configuration.

`set-clipboard` is a **server-wide** option, even when a command includes
`-t session`. If you deliberately want applications in every session on that
server to set clipboard contents, configure this on the remote host:

```tmux
set-option -s set-clipboard on
```

This also affects other sessions and attached native terminals using that tmux
server. WebSSH's Copy confirmation protects only the WebSSH browser, not those
other clients. Leave the existing policy unchanged if that broader effect is
unwanted.

`allow-passthrough` is needed only for applications using tmux's DCS passthrough
wrapper, not for ordinary tmux copy mode. On tmux versions supporting the option,
an operator who wants it across windows can explicitly configure:

```tmux
set-option -gw allow-passthrough on
```

This changes the default for existing and future windows on the server that
inherit it. Explicit window or pane overrides still take precedence; inspect and
configure those individually if needed. Using only `-t session` changes the
selected window, not all windows of that session. Passthrough also permits other
wrapped terminal sequences, so enable it only where intended.

These settings belong in the remote account's tmux configuration, or can be
applied to a running server without killing sessions. See the
[tmux clipboard guide](https://github.com/tmux/tmux/wiki/Clipboard) for terminal
capability checks and application-specific setup.

## Floating windows

Select the window button next to the **1**, **2**, and **4** layout buttons to
place each session in its own window on a desktop, the way a desktop operating
system arranges applications.

- Drag a window by its title bar. Drop it on the left or right edge to fill
  that half, on a corner to fill a quarter, or on the top edge to maximize it.
  A preview shows where the window will land.
- Resize from any edge or corner. The terminal refits while you drag and the
  remote shell learns the final size once you release.
- Use the title-bar buttons to minimize, maximize or restore, and close.
  Double-clicking the title bar also maximizes or restores the window.
- With the title bar focused, arrow keys move the window, `Alt`+arrow keys
  resize it, and `Enter` maximizes or restores it.
- The session tabs act as a taskbar: minimized sessions appear dimmed, and
  selecting a tab restores and focuses its window.
- **+** opens a new window with the connection launcher, and a new connection
  always opens in a window of its own instead of replacing the focused one.
- The tile and cascade buttons arrange every open window.

Closing a window ends its SSH session, exactly like closing its tab, including
the confirmation when **Ask before closing a session** is enabled. A
minimized session keeps running in the background.

Window placement is kept per session for the browser tab, so windows return to
the same place after a page reload or after switching to a split layout and
back. The browser remembers the window layout as a preference. Phones and
other narrow screens always use the single-pane layout and return to windows
when there is room again. At most 16 windows are open at once; further
sessions stay available from their tabs.

## Broadcast input

Broadcast mode sends the same input to every open SSH session. Treat it as a
high-impact operation:

- verify the visible target set;
- start with a harmless command;
- avoid interactive programs with divergent state;
- disable broadcast immediately after the intended action.

WebSSH does not interpret whether a command is safe for every target.

## Focused session workspace

The single-pane layout can place the active session's SFTP browser beside the
terminal and show Linux resource information alongside notes. On wide desktop
layouts, the SFTP companion can open for a single connected session; manual
dismissal is respected for that session.

The context area follows the selected session and keeps Notes, Commands, Files,
and supported diagnostics within reach. WebSSH probes each capability instead
of assuming that every SSH target is Linux or provides SFTP. Unsupported tools
stay unavailable while the core terminal remains usable. Switching sessions
or resizing the browser preserves the current context without reconnecting SSH.

### Commands for the active session

The Commands context searches the user's Commands and Command Sets, filters
entries by the detected operating system where applicable, and inserts one
reviewable line into the active terminal. It does not press Enter. The optional
`sudo` control prefixes the inserted command; WebSSH never stores or answers a
sudo password, so any required prompt remains visible in the terminal.

## Diagnostics

For supported Linux targets, WebSSH can request:

- CPU, memory, disk, load, and uptime;
- process and network-throughput counts;
- history and pressure charts;
- top CPU and memory processes;
- systemd service inventory;
- Docker container inventory.

Service action controls do not execute commands. They generate an allowlisted
`systemctl` command and copy it to the clipboard with visible confirmation. The
operator decides whether and where to run it.

Diagnostics are a convenience layer over the current SSH session, not a host
monitoring or privilege-escalation agent.

## Browser refresh and reconnect

![WebSSH realtime SSH session and bulk transfer paths with ownership and transport boundaries](https://github.com/bifrost0x/webssh/blob/main/docs/media/diagrams/session-and-transfer-lifecycle.png?raw=true)

Terminal control and output use authenticated Socket.IO events around an owned,
process-local SSH session. Bulk transfer bodies take the separate bounded HTTP
path shown below; they are not encoded into terminal events.

Each live output event is charged to per-browser, per-user, and process-wide
budgets until the browser acknowledges accepting it. At capacity, WebSSH stops
reading the Paramiko channel so SSH/TCP backpressure applies. A browser that
keeps an acknowledgement budget blocked for the configured timeout is
disconnected, while its underlying SSH or persistent tmux session stays
available for reconnect.

The browser can restore UI state for live sessions after refresh without
injecting terminal input. The underlying SSH transport remains process-local;
a WebSSH process restart closes a normal SSH session.

Manual reconnect behavior depends on authentication:

- stored-key and Tailscale sessions can reconnect directly when authorized;
- password sessions reopen a pre-filled connection form at the password field.

Passwords are not retained in the session object for reconnect.

## Persistent tmux sessions

tmux runs on the remote SSH host. It keeps the remote shell and commands alive
when the browser closes, the WebSSH transport disconnects, or WebSSH restarts.

Configuration:

```bash
TMUX_ENABLED=true
TMUX_DEFAULT=true
TMUX_SESSION_PREFIX=webssh
```

The base Compose file enables and preselects tmux. Source installations default
to disabled unless configured.

### Requirements

- tmux installed on the remote host;
- permission for the remote SSH user to create sessions;
- a usable shell environment;
- a stable prefix and remote username.

If tmux is unavailable, WebSSH falls back to a regular shell.

### Session identity

WebSSH creates or reattaches a remote tmux session using its configured prefix
and connection identity. Persistent display names can be retained across
browsers.

Disconnecting the WebSSH transport is different from killing the remote tmux
session. Use the deliberate kill action only when the remote workload should
end.

## Sharing a terminal

Select **Share** in the session tab bar to invite someone into the active
session with a link. Guests open the link in any browser; they need no WebSSH
account, and they never receive the target host, account name, password,
private keys, file sources, or any other workspace resource. They see the
terminal, the link name you choose, and your WebSSH username.

Each link has:

- **Access**: *View only* streams the terminal live. *Can type* also forwards
  the guest's keystrokes into the session. Use **Allow typing** on an active
  link to grant or withdraw input at any time.
- **Expiry**: 15 minutes to 24 hours (capped by
  `TERMINAL_SHARE_MAX_TTL_MINUTES`).
- **Viewers**: a per-link seat limit.
- **Ask me before anyone joins**: guests wait in a lobby, without seeing any
  output, until you select **Admit**.

The share dialog lists every guest with their connection state. You can remove
a guest or select **Stop sharing** at any time. A link also ends when it
expires, when the SSH session closes, and when you sign out or your access is
revoked. Links live only in server memory, so they never survive a restart.

The link token is kept in the URL fragment (after `#`), which browsers never
send to a server, so it does not appear in proxy or access logs. The server
stores only a hash for lookups. Guest keystrokes draw from the owner's SSH
input budget, and every link creation, join, approval, removal, and first use
of guest input is written to the security audit log.

### Inviting guests

Each active link offers **QR code**, which renders a scannable code in the
browser (no external service sees the link), and **Copy invite**, which copies
a ready-to-send message with the link name, the link, the access level, and
the time left. Browsers with a system share sheet also offer **Share…**.

### Chat and pointers

While a session is shared, **Chat** appears in the corner of the workspace.
Everyone admitted to any link of that session shares one conversation;
guests waiting for approval see neither past nor new messages. Late joiners
receive the most recent `TERMINAL_SHARE_CHAT_HISTORY` messages. Messages are
plain text, limited to 500 characters, rate limited per sender, never written
to disk or the audit log, and disappear when the session's last link ends.

Select the pointer button (in the chat panel for owners, or **Point** in the
guest toolbar), then click the terminal to highlight a character for everyone
else with your name. Pointers fade after a few seconds and address the live
screen, so they line up for every participant even when someone has scrolled.
Press `Esc` to leave pointer mode.

A guest that falls behind never slows your terminal: each guest has its own
bounded queue and is resynchronised from the session's replay buffer instead.
A guest that briefly loses its connection keeps its seat for
`TERMINAL_SHARE_VIEWER_GRACE_SECONDS` and resumes without a full redraw when
nothing was lost.

## Idle timeout

`SESSION_TIMEOUT` defaults to 1800 seconds and closes idle WebSSH SSH sessions.
This does not imply a 30-minute browser HTTP-session timeout. A remote tmux
session can survive and be reattached later.

## Capacity

Default SSH quota is 10 sessions globally and 5 per user. Each live terminal
reader occupies bounded runtime capacity. The defaults calculate enough
background workers for cleanup loops, every admitted SSH reader, and permitted
background jobs.

## Troubleshooting

### Terminal opens but stays blank

Check remote shell startup, banner or MFA interaction, channel logs, and browser
Socket.IO connectivity.

### Terminal disconnects behind a proxy

Verify WebSocket upgrade forwarding, proxy timeouts, CORS origin, and subfolder
prefix handling.

### Persistent session was not restored

Confirm tmux exists for the same remote user, the prefix did not change, and
the operator did not kill the tmux session. A regular shell cannot survive a
WebSSH restart.

### Diagnostics are empty

The remote system may not be Linux, commands may be missing, or the SSH user may
lack permission to inspect the requested data. Core terminal access remains
independent.

## Related pages

- [SFTP File Workspace and Transfers](SFTP-File-Workspace-and-Transfers)
- [Profiles, Jump Hosts and Commands](Profiles-Jump-Hosts-and-Commands)
- [Architecture and Runtime Lifecycle](Architecture-and-Runtime-Lifecycle)
