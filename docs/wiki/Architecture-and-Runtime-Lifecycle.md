# Architecture and Runtime Lifecycle

WebSSH is a Flask application with authenticated HTTP and Socket.IO interfaces, Paramiko SSH/SFTP channels, SQLite persistence, and a bounded threaded runtime.

## Request and connection flow

```text
Browser
  |-- HTTPS/forms/API --------> Flask routes and blueprints
  |-- Socket.IO controls -----> authenticated socket events
  |-- streamed transfers -----> HTTP transfer routes
                                  |
                                  v
                         ownership and quota checks
                                  |
                     +------------+-------------+
                     |                          |
                 SSH manager              persistent storage
                     |                   SQLite + per-user files
              Paramiko channels
                     |
               SSH/SFTP servers
```

Bulk file content is streamed over HTTP. Socket.IO carries terminal traffic, control events, and bounded editor content rather than whole bulk-transfer payloads.

## Application entry points

- `start.py` creates the application through `create_app()` in `app/__init__.py`.
- Focused blueprints implement transfers, host keys, audit export, backup/restore, recovery codes, WebAuthn, OIDC, LDAP, and health/readiness.
- `app/socket_events.py` defines authenticated real-time contracts for terminal, SFTP, profiles, keys, commands, diagnostics, and transfers.
- `app/ssh_manager.py` owns process-local SSH state.
- `app/paramiko_channels.py` centralizes bounded Paramiko channel creation.

## One-worker contract

Production uses:

```bash
gunicorn --worker-class gthread --workers 1 --threads 64 \
  --bind 0.0.0.0:5000 start:app
```

Exactly one worker is supported. Live Paramiko objects, session coordination, and parts of resource admission are process-local. Multiple workers would create isolated views of live state and can violate ownership, quota, cleanup, and routing assumptions.

Redis-backed rate limiting externalizes counters only. It does not externalize SSH channels or turn the application into a multi-worker architecture.

## Socket admission and HTTP reserve

`app/socket_capacity.py` limits admitted sockets globally and per user. Capacity must leave at least four Gunicorn threads for ordinary HTTP work:

```text
GUNICORN_THREADS - MAX_SOCKET_CONNECTIONS >= 4
```

The default is 64 threads and 48 sockets, with at most eight sockets per user. Socket.IO uses native threading and simple-websocket; Eventlet, greenlets, and monkey patching are not part of the supported runtime.

## Background work

`app/runtime_lifecycle.py` owns a bounded `ThreadPoolExecutor`. Jobs have cancellation state, ownership, and explicit terminalization. LDAP cache cleanup, transfers, SSH/SFTP helper work, and other background tasks must share this bounded lifecycle instead of creating unlimited thread loops.

## SSH and SFTP lifecycle

SSH connections belong to an authenticated user and consume quotas. Paramiko channels are created through existing helpers with timeouts and cancellation. Quick SFTP connections used by the file workspace remain alive while queued or active transfers still reference them, then disconnect when ownership can safely end.

Persistent tmux metadata survives a browser disconnect, but the underlying remote tmux session lives on the SSH server. WebSSH's local connection objects do not survive a process restart.

## Graceful shutdown

On shutdown WebSSH:

1. closes admission for new runtime work;
2. signals cancellable jobs;
3. stops or terminalizes owned operations within the configured window;
4. closes SSH/SFTP and Socket.IO resources;
5. exits so the process supervisor can complete replacement or restart.

Readiness reports failure once the runtime is no longer accepting work. Keep the proxy/load-balancer drain period aligned with `RUNTIME_SHUTDOWN_GRACE_SECONDS`.

## Maintenance mode

Restore operations enter maintenance mode before replacing persistent state. `/health` stays a liveness check, while `/ready` fails so traffic can be drained. Restore then terminates the process intentionally to guarantee a clean application state after replacement.

## Frontend architecture

The frontend uses vanilla JavaScript and CSS without a build-time application framework. Browser libraries are pinned in `package.json`, vendored locally, and checked for integrity. Runtime CDN dependencies are intentionally absent so the frontend remains offline-capable and compatible with the Content Security Policy.
