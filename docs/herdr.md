# Herdr integration

[Herdr](https://github.com/herdrdev/herdr) is a terminal multiplexer that
reports the agents running in its panes. It runs on the remote host and keeps
those terminals alive in a background server. WebSSH can show the agents Herdr
reports and can open the Herdr client as the terminal session of a saved host.

The integration is **disabled by default**. An administrator must enable
**Settings → Administration → Integrations → Herdr** first. This global setting
applies to all WebSSH users and is saved in the existing application settings
store. Changing it requires the normal admin step-up verification. Reload open
workspaces after changing the setting.

Disabling stops every further status request, including requests from browser
tabs that still show the enabled UI, and new connections start a standard shell.
Saved host options are retained. Established sessions are not disconnected and
nothing is stopped on the remote host.

## Per-host opt-in

Herdr is used only for saved hosts with **Herdr on this host** enabled. Quick
connections and hosts without the option are never queried and never start
Herdr. Herdr must already be installed on the remote host; WebSSH does not
install, update or configure it.

## Agent overview

The **Agents** panel on the Overview board lists the agents of every opted-in
host that has a connected session of the current user. Each entry shows the
agent type, its label, the working directory and the status Herdr reports.
Selecting an entry opens the WebSSH session of that host. The classic overview
layout has no Agents panel.

The panel exists only while the integration is enabled. In the default board
layout it appears below **Needs attention**; a user who has saved their own
board arrangement keeps it unchanged and finds the panel at the end. Use
**Customize** to move or hide it.

- The status is a hint. Herdr derives it mostly from terminal output and can lag
  or be wrong, and any process on the remote account can report its own values.
  Open the session before acting on it.
- WebSSH runs `herdr api snapshot` on a separate channel of the existing SSH
  connection while the panel is visible. It opens no additional connection,
  stores no additional credentials and does not query hosts in the background.
- A request never starts a Herdr server. Without a running server the panel
  reports that Herdr is not running.
- Requests are bounded. The panel asks every 10 seconds and pauses while it or
  the browser tab is hidden. WebSSH waits at most 3 seconds for an answer and
  accepts at most 256 KiB and 64 agents. At most two requests per user and four
  per WebSSH process run at the same time. Herdr's own call has no deadline, so
  the command WebSSH runs ends it on the remote host after 5 seconds; the
  `sleep` of that guard can remain for up to 5 seconds after an answer. A host
  that timed out is not asked again for 30 seconds.
- The panel has its own states for a host where Herdr is not installed, is not
  running, speaks an unsupported protocol version or does not answer in time.
- The panel is read-only. It does not show terminal content or token counts and
  cannot send input, focus panes or change Herdr.
- Only the default Herdr session is read. Named sessions are not supported.

## Herdr session mode

A saved host with the Herdr option can select **Herdr** as its terminal session
instead of a standard shell or a persistent tmux session. WebSSH then starts the
Herdr client in the terminal. Herdr starts its server when none is running and
attaches to the default session otherwise, so reconnecting returns to the same
panes. If Herdr is not installed, WebSSH falls back to a standard shell.

- Herdr and tmux cannot be combined for one host, and the Herdr session mode
  cannot be combined with commands that run after connecting.
- Closing the WebSSH session detaches the client. The Herdr server and its
  agents keep running on the remote host; WebSSH never stops them.
- WebSSH does not reconnect a Herdr session by itself after the connection is
  lost. A manual reconnect attaches to Herdr again under the same rules as the
  first connection: the integration must still be enabled and the saved host
  must still select Herdr.
- Folder synchronization with the terminal is unavailable in a Herdr session.
- Remote clipboard requests (OSC 52) are accepted for persistent tmux sessions
  only, not for Herdr sessions. Hold Shift while dragging to select and copy
  with the browser terminal.
- Herdr's prefix key is `Ctrl+B` by default. A control bar above the terminal
  sends the prefix and one key for actions that are hard to type in a browser
  or on a phone: split, zoom, pane and tab switching, workspaces, sidebar,
  rename, help, settings, a plain `Ctrl+B` and closing a pane after a
  confirmation. The keyboard button in the session toolbar shows or hides the
  bar, and the choice is kept per browser. The command palette offers the
  toggle and the same actions while a Herdr session is active, also on phones. Each button sends only its fixed
  key sequence as terminal input.
- A right click in a Herdr session that uses the mouse opens Herdr's pane menu.
  Hold Shift for the browser's context menu.
- Broadcast input reaches a Herdr session like typed input and goes to the pane
  Herdr currently focuses. Review the recipients before sending.

## Security and compatibility boundaries

- Every command runs as the SSH user of the user's own connected session. The
  integration grants nothing that the user's shell on that host does not
  already allow.
- The commands WebSSH runs are fixed. No user input and nothing reported by the
  remote host becomes part of a command. WebSSH writes no files on the remote
  host and does not use the Herdr socket directly.
- The server decides for every request and every connection whether Herdr may
  be used, from the administrator setting and the user's own saved host. A flag
  sent by the browser is not sufficient, and a session of another user is never
  queried.
- Error output of Herdr is read only to classify the failure and is not sent
  to the browser.
- Everything Herdr reports is treated as untrusted text: it is bounded in size
  and count, stripped of control characters and rendered as text only.
- Herdr is located through the remote `PATH` followed by `$HOME/.local/bin`,
  `/usr/local/bin` and `/opt/homebrew/bin`, because the Herdr installer uses a
  directory that non-interactive SSH channels do not search.
- A running Herdr server contacts `herdr.dev` for agent manifest and update
  checks. This is Herdr's own behavior and also applies when WebSSH starts the
  server in session mode; the status request alone makes no network request.
  See the Herdr documentation for `manifest_check` to turn it off on the host.
- Existing hosts, settings and tmux sessions are unchanged. Exports carry the
  Herdr options only for hosts that have them enabled. A document with such a host cannot be imported by WebSSH
  versions without this integration; exports of other hosts are unchanged.
- Controlling agents from WebSSH, plugins, worktrees, layouts and browser
  notifications are not supported.

The reference implementation is tested against Herdr 0.9.5. Herdr's API is still
changing before its 1.0 release; WebSSH ignores unknown fields and reports an
incompatible Herdr version instead of guessing.
