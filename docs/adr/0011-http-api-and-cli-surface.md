# ADR 0011: Stable HTTP and CLI surface, internal API

## Status

Accepted

## Date

2026-11-26

## Context

The JSON routes under `/api/` and the realtime events of the Python release
are used only by its own frontend; they are not documented as a public
interface and no external clients are known. They contain three ways to
turn off a second factor, two step-up families with different rules, and
routes and events without any caller. Sensitive actions on SSH keys need no
step-up, unlike stored credentials and host keys.

Operators rely on other parts: page and callback URLs, health endpoints,
the client address behind a reverse proxy, and the documented CLI form
`/app/entrypoint.sh flask --app start:app <command>`, which they use in
emergencies such as a password reset or a restore.

## Decision

**Stable surface.** Page URLs and deep links, the OIDC and GitHub callback
URLs, `/health` and `/ready` stay unchanged; they are compatibility
invariants of ADR 0007.

**Internal API.** The JSON API and the realtime messages are internal and
designed anew for the Go release, together with the frontend. Routes and
events without a caller are not rebuilt; there is no transition period
with `410 Gone`. The migration notes list the removed routes.

**One step-up service.** `internal/auth/stepup` grants step-up per action
from an action catalog. A grant is bound to the user, the browser session
and the action, and expires after a short window. Every action on stored
secrets requires it, including uploading, replacing and deleting SSH keys.
The capability that owns an action checks the grant on the server, through
a small interface wired by `cmd/webssh`. There is one way to turn off a
second factor.

**Client address.** `TRUSTED_PROXIES` keeps its meaning as a hop count. The
additive variable `TRUSTED_PROXY_CIDRS` lists proxy networks; when it is
set, `X-Forwarded-For` is honoured only from those sources. A hop count
without CIDRs logs a clear warning at start.

**Realtime origin.** The origin rule for the WebSocket upgrade is part of
ADR 0005.

**CLI.** The administrator commands are subcommands of `webssh`. The image
keeps `/app/entrypoint.sh` as a link to the binary; invoked under that path
with the old argument form (`flask --app start:app <command> …`), it
accepts the same options and returns the same exit codes and messages, and
prints a notice that the form is deprecated. The old form is kept until the
next major release. CLI tests run against both forms.

**LDAP secret helper.** The documented `ldap-tools` service of
`docker-compose.ldap.yml` runs `python /app/deployment/ldap_secret_cli.py`
with `set-password`, `install-ca`, `status` or `remove`. The Go image has no
Python, so it provides the same kind of argv shim without any change to the
Compose file: `python` on the image's `PATH` is a link to the binary that
accepts exactly the argument vector `/app/deployment/ldap_secret_cli.py
<command> …` and maps it to `webssh ldap-secret <command> …`, with the same
options, files (`ldap_bind_password`, `ldap_ca.pem` under
`/run/webssh-auth`), modes, exit codes and messages, and a deprecation
notice. Any other argument vector is refused. The shim is kept for the same
period as the old CLI form.

## Alternatives considered

- **Rebuild every route.** Keeps the duplicate paths with inconsistent
  rules and a large amount of code without callers.
- **Answer removed routes with `410 Gone` for one release.** Protects only
  hypothetical scripts.
- **Drop the old CLI form at once.** Breaks documented emergency
  procedures at the moment operators need them.

## Consequences

- The package map has `internal/auth/stepup`; capabilities that own
  sensitive actions add them to the catalog in the pull request that adds
  the action.
- The reverse-proxy documentation describes `TRUSTED_PROXY_CIDRS` and the
  `Origin` header requirement.
- The migration notes list the new step-up for SSH keys, the removed routes
  and the deprecated CLI form, including the LDAP secret helper shim.
