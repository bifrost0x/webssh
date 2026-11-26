# ADR 0002: Parallel clean build with one-time migration on first start

## Status

Accepted

## Date

2026-11-26

## Context

The Go backend replaces the Python application (ADR 0001) and is designed
from WebSSH's capabilities, not from the Python code (ADR 0006). Running
both side by side behind a proxy would tie the Go design to Python's
session cookie, database schema and runtime until the very end, and every
intermediate state would need its own compatibility work.

Users who upgrade must not notice a break: everything they created must be
there and keep working.

## Decision

- The Go backend is built in full on the long-lived integration branch
  `go`, with its own data model. Every contribution reaches `go` as a pull
  request with the same protection rules and CI gates as `main`; history is
  never rewritten. There is no proxy to Python, no shared cookie, no
  shared database, no Unix socket between the two and no per-area switches.
- The Go release replaces the Python release in one step. Its first start on
  an existing `DATA_DIR` runs a one-time, automatic, verified migration of
  all user data (ADR 0007). Before the migration a backup is taken, and the
  legacy data is never modified, so returning to the last Python release
  stays possible.
- The external contracts listed in ADR 0007 stay stable: port, volumes,
  UID/GID, environment variables, URL paths, WebAuthn relying party,
  OAuth callback URLs and the ability to restore Python backups.
- `main` receives only security fixes, the last Python feature change and
  the hardened base image. `main` is merged into `go` regularly (no rebase).
- Every security fix on `main` is listed and becomes a test or a rule on
  `go` before the affected build phase counts as done.
- The Go code reaches `main` once, with the cut-over pull request for
  release v3.4.0, which continues the version numbering and removes Python,
  Gunicorn, Socket.IO and the `entrypoint.sh` script. The path
  `/app/entrypoint.sh` stays in the image as the `webssh` binary and accepts
  the documented `flask --app start:app …` commands until the next major
  release (see [ADR 0011](0011-http-api-and-cli-surface.md)).

## Alternatives considered

- **Strangler with Go as entry process and a proxy to Python.** Gradual
  delivery, but Go would have to validate Flask cookies, share the Python
  schema and coexist with Socket.IO until the end. It preserves the old
  structure for longest. Rejected.
- **Big-bang rewrite without migration.** Users would have to re-create
  their setup. Rejected by the no-break requirement.
- **Go reading the Python schema permanently.** Couples the data model to
  Python forever.

## Consequences

- The migration is the highest-risk component and gets its own tests
  against data produced by the real Python application, covering every
  entity.
- Feature work on Python stops; Python receives security fixes until the
  Go release and for three months after it on a maintenance branch.
- One release changes the runtime completely, so the release candidate is
  validated against real upgrade scenarios, including rollback to Python
  from the pre-migration backup.
- Long-lived branch risk: `go` is kept green in CI (the `Go` workflow and
  the Python gates while Python is still on the branch) and merged from
  `main` regularly.
