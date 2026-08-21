# Profiles, Jump Hosts and Commands

Saved connection data is private to each WebSSH account. Profiles intentionally
exclude SSH and jump-host passwords.

## Saved profiles

A profile can store:

- display name;
- hostname, port, and remote username;
- selected stored key;
- selected jump host;
- tmux preference;
- Tailscale authorization mode when allowed;
- post-connect startup behavior;
- flat group and sort position;
- favorite state.

Password-dependent profiles open the connection form at the required field.
Profiles that need no password, such as a usable stored key or authorized
Tailscale mode, can launch directly from an empty pane.

## Favorites and groups

The connection manager provides:

- a Favorites section;
- named flat groups;
- an Ungrouped section;
- search by name, host, user, or group;
- collapsed group state in the browser;
- drag-and-drop ordering and movement between groups.

Groups are flat labels, not nested folders. Favorite profiles are promoted into
the Favorites section. Remove a profile from favorites before relying on normal
group ordering.

Moving the last profile out of a real group requires an explicit confirmation
because the empty group ceases to exist.

## Jump hosts

Jump hosts are saved separately so several target profiles can reuse one
bastion. Select the jump host while editing a profile.

Use least privilege on the bastion and target. The presence of a jump host does
not bypass target network policy, session ownership, or host-key verification.

For bastion-only DNS names that cannot resolve locally, configure an exact
`PROXY_JUMP_REMOTE_DNS_ALLOWLIST`. Do not use wildcards.

## Command library

The command library stores named commands and optional operating-system scope:

- Linux
- macOS
- BSD
- Windows

OS-aware filtering helps present relevant commands after the remote system is
detected. A stored command remains text; review it before sending it to a
terminal.

## Command sets

Command sets combine ordered steps. A step can reference a library command or
contain free text. Sets can be duplicated, reordered, assigned to profiles, and
launched for an active session.

Profiles use an explicit startup mode:

- `none`
- one library command
- one command set
- free-text startup commands

Existing legacy profile data is migrated additively into this model.

## Commands in an active session

The focused session workspace can search Commands and Command Sets for the
active terminal. Entries with an operating-system scope are filtered against
the detected target where possible. Selecting **Insert** writes one visible,
single-line command to the terminal but does not press Enter, leaving the final
review and execution to the operator.

The optional **Insert with sudo** control prefixes the inserted command without
changing the stored library entry. WebSSH does not store or answer a sudo
password; an interactive prompt remains in the terminal. Multiline entries are
not inserted through this active-session shortcut.

## Post-connect behavior

When a profile is assigned a post-connect action, WebSSH waits for the SSH
channel to become usable and then submits the selected command text or ordered
set. Use this only for commands that are safe to repeat after reconnect.

Avoid embedding secrets in commands, profile names, or parameters. Command text
may appear in terminal output or session transcripts depending on remote shell
behavior.

## Data integrity

Profiles, jump hosts, commands, command sets, and settings are JSON stores below
the owning user's data directory. Updates perform a complete load-modify-save
cycle under a logical storage lock and replace files atomically.

Corrupt JSON is reported as storage corruption instead of silently becoming an
empty store. Versioned migrations preserve existing installations and create
private backups before a migration write.

## Practical organization pattern

For a larger homelab, use flat groups based on operational context:

- `Production`
- `Lab`
- `Network`
- `Storage`
- `Clients`

Use favorites for the small set of hosts accessed every day. Put shared
bastions in Jump Hosts rather than duplicating their configuration.

## Troubleshooting

### Profile launch still asks for a password

The profile depends on a password for the target or jump host, or the selected
stored key is unavailable. Passwords are deliberately not persisted.

### A post-connect set did not run

Check the profile's startup mode, referenced command/set, remote shell state,
and whether the selected step requires interactive input.

### A group disappeared

Groups exist through profile labels. Moving the last profile out removes the
empty group after confirmation.

### A profile changed while dragging

The server verifies the expected source group before an atomic move. Reload and
retry when another browser changed the profile concurrently.

## Related pages

- [SSH Connections and Host Keys](SSH-Connections-and-Host-Keys)
- [Terminal and Persistent tmux Sessions](Terminal-and-Persistent-tmux-Sessions)
- [Data Storage and Persistence](Data-Storage-and-Persistence)
