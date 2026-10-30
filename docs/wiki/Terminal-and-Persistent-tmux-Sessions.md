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

### Scrolling in persistent tmux sessions

When starting or reattaching a persistent session, WebSSH enables tmux's `mouse`
option for that exact session. With tmux's standard bindings, scrolling up enters
copy mode and reads the remote history; scrolling down returns towards the live
screen. Press `q` to leave copy mode. Mouse-aware applications keep receiving
their own mouse input. Custom tmux mouse bindings remain authoritative.

This changes no global or server options, `.tmux.conf`, history limits, or
clipboard policy. Reattaching preserves the existing shell process and history;
other clients attached to the same tmux session share its session-local mouse
setting. Other sessions are unchanged. Existing connections receive this setting
on their next connection or reattachment. To activate it immediately from the
current tmux session without disconnecting, run `tmux set-option mouse on`.

tmux now handles ordinary mouse selection in that session. Hold Shift while
dragging to use the browser terminal's selection instead. The remote tmux history
is separate from WebSSH's configurable local scrollback; its scrollbar does not
represent tmux's remote history. The remote tmux must support the session-local
`mouse` option.

When tmux mouse mode owns the selection, WebSSH accepts tmux's bounded OSC 52
clipboard request for that persistent session. A visible WebSSH notification
requires a fresh **Copy** click before the remote text reaches the browser
clipboard. Replayed output and ordinary non-tmux SSH sessions cannot request a
clipboard write. Browser clipboard permissions still apply.

Remote OSC 52 clipboard requests are limited to 128 KiB of decoded UTF-8 text.
Oversized OSC/DCS control strings are discarded by the terminal parser before
they can accumulate unbounded browser memory.

### Remote tmux clipboard configuration

WebSSH preserves the remote tmux clipboard configuration on both new connections and
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
TMUX_DEFAULT=false
TMUX_SESSION_PREFIX=webssh
```

The base Compose file makes tmux available without preselecting it. Users opt in
per connection or saved host. `TMUX_DEFAULT=true` explicitly preselects it for new
connections; saved host preferences remain unchanged. Source installations
disable tmux unless configured.

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


## Folder synchronization in an existing tmux shell

The existing **Synchronize folders with terminal** checkbox controls folder synchronization. No second toggle is required. Terminal-to-Files following remains available without shell integration; sending a directory change into tmux requires explicit Bash prompt detection.

1. Enable the checkbox and open **Set up Bash prompt detection** beneath it.
2. Copy the activation block. Finish or cancel any pending command, then paste and execute the complete block yourself at an empty Bash prompt in the intended pane. WebSSH never sends the setup block automatically.
3. Wait until WebSSH detects the helper, then press Enter at the empty prompt. The status changes to **Folder sync ready**.

The helper supports Bash 4.4 or newer with prompt expansion enabled and compatible tmux format arithmetic (tested with Bash 5.2 and tmux 3.4). It appends invisible hooks to the current shell's PS0, PS1 and PS2, preserving the original strings and leaving PROMPT_COMMAND unchanged. It writes only private options on that pane. It does not edit startup files, enable passthrough, restart shells, or change global/window options. Protected/exported prompt variables and repeated activation are rejected without replacing the prompt hooks.

Turning the checkbox off immediately stops synchronization. The helper remains in that shell until it exits, including across tmux detach/reattach. Reconnection requires a fresh empty Enter after detection; transcript output cannot unlock synchronization. Other shells remain usable, but automatic Files-to-terminal navigation is unavailable without this integration.

Open quotes, continuations, here-documents, running commands, copy mode and unfinished input keep navigation blocked. After input consumed by an interactive program (for example a normally completed `read`), multiline paste, or uncertain prompt counts, synchronization may remain paused. Finish or cancel the input, switch the existing checkbox off and on, wait for detection, and press Enter at the empty prompt. This conservative recovery avoids inserting commands into unfinished input. Prompt frameworks that later replace the hook-bearing prompt variables can also leave synchronization paused; WebSSH does not overwrite their configuration.

### Repeating the real tmux checks

Run `node tests/integration/tmux_sync.cjs` after installing the project Node dependencies and Playwright Chromium. On Linux it uses Python 3 and tmux; on Windows it uses Ubuntu under WSL. The test creates its own tmux server and synthetic shell configuration, checks actual xterm/controller behavior, and removes only those test resources. It verifies continuation blocking, repeated folder changes, Unicode/quoted paths, checkbox recovery, prompt/exit-status preservation, configuration hashes, pane identity and detach/reattach.
