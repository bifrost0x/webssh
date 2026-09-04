# Terminal and Persistent tmux Sessions

WebSSH uses xterm.js in the browser and Paramiko channels on the server. Socket.IO
carries terminal control and output events.

## Session workspace

The terminal supports:

- multiple session tabs;
- one-, two-, and four-pane layouts;
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
clipboard update for that persistent session. Browser clipboard permissions
still apply.

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
