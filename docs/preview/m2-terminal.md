# Terminal in the Go release (draft)

Draft for the documentation package of M2 (DOC1). It describes what the Go
terminal does differently from the Python release for startup commands,
persistent tmux sessions and the Herdr session mode, and what has not been
verified.

## Startup commands

The post-connect behaviour of a saved host or of Quick Connect (nothing,
free text, a command of the library with its parameters, a command set)
is sent with the connection request and checked by the server with the
rules of the Python release: at most 4096 characters, no NUL, line breaks
become Enter. It runs once after the connection is made, as the first
input of the session, and never when a persistent tmux session is
reattached. A command or a set is read from the user's own library at that
moment. Until the command library is part of the Go release, the modes
*command* and *command set* answer "not available in this preview"; free
text works.

## Persistent tmux sessions

Names, the reattach rules, the SOCKS5 route check and the end of a session
are those of the Python release. Gateway terminals keep the gateway digest
in the name; Tailscale SSH starts tmux with UTF-8.

| Change | Kind |
|---|---|
| Startup commands are queued as the first input before the shell's output is read; Python wrote them after the reader had started. | keep |
| A reattach without a display name keeps the stored one; Python dropped it. | fix |
| A new name is shortened so that it can always be reattached (190 characters); Python could create a longer name that a reattach refused. | fix |
| `has-session` and `kill-session` name the session exactly (`-t =name`). | fix |
| A connection that keeps sending more than 1024 terminal frames in a row that are dropped unread is closed (4002). | new |

## Herdr

The session mode runs Herdr as the program of a saved host when the
administrator switch and both options of the host grant it and the host has
Herdr; otherwise the login shell opens, as in Python. Nothing the browser
sends grants Herdr. The Herdr overview (agent list) comes with the server
operations package.

## Not verified

- The modes *command* and *command set* against the real library (they
  are tested against a fixed library that mirrors the Python one).
- The Herdr session mode against a real Herdr binary (the lab has none);
  the commands are compared byte for byte with `app/herdr.py`.
