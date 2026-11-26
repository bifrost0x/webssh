# ADR 0005: Native WebSocket with a versioned message schema

## Status

Accepted

## Date

2026-11-26

## Context

Terminal traffic, file control and live status use Socket.IO today
(Flask-SocketIO with simple-websocket, plus `socket.io-client` in the
browser). Socket.IO adds its own framing, polling fallback and a server
library with no maintained Go equivalent. The connection limit of the
threaded Python runtime caps concurrent sessions.

The protocol between our frontend and our backend is internal: only our own
frontend speaks it (ADR 0006).

## Decision

- Go offers one native WebSocket endpoint (RFC 6455) in `internal/realtime`.
- Every message uses one envelope defined in `internal/realtime/protocol`:
  schema version, message type, optional correlation id and payload. A
  client announces the schema version on connect; an unsupported version is
  refused with a clear error instead of being guessed.
- Message types are registered per capability (terminal, files, status).
  Each type has a bounded payload size, and flow control and input budgets
  are part of the type's contract, not of the transport.
- Authentication happens on the HTTP upgrade: the session cookie
  (`SameSite`), an exact `Origin` allowlist check, which is the CSRF defence
  for WebSockets because browsers cannot add custom headers, and a
  revocation re-check while the connection is open.
- Origin rule: by default only the application's own origin is accepted,
  compared with scheme, host and port. `CORS_ORIGINS` is the allowlist for
  further origins. `ALLOW_CORS_WILDCARD` and `SOCKETIO_ALLOW_ANY_ORIGIN`
  keep their documented meaning and log a warning at start when enabled.
  An upgrade without an `Origin` header is refused. Reverse proxies must
  pass the header through; the reverse-proxy documentation says so.
- Bulk file content stays on HTTP.
- The frontend gets a thin transport layer; each area gets a small adapter
  from its current calls to the new message types. The Go release ships
  without Socket.IO on either side.

The WebSocket implementation (tier B library such as `coder/websocket`, or
an own tier C implementation) is chosen when the terminal is built in Go
(phase B3), based on the latency and throughput measurements of the
preparation phase.

## Alternatives considered

- **Keep Socket.IO with a Go server library.** The available libraries lag
  the protocol and would be a large tier B dependency for a feature we do not
  need (polling fallback).
- **Server-sent events plus HTTP POST.** No binary frames, a second channel
  for input, and higher terminal latency.
- **gRPC-Web or WebTransport.** Heavier stack, no benefit for a single
  browser client.

## Consequences

- The path `/socket.io/` disappears; reverse-proxy rules written for it
  must be adapted. This is listed in the migration notes.
- There is no long-polling fallback. Installations whose reverse proxy
  blocks WebSocket upgrades, and so ran Socket.IO on polling only, must
  enable them. This is a documented break.
- The frontend changes are part of the Go release and are tested with the
  same end-to-end suite as today.
- The schema version makes later changes explicit and testable.
