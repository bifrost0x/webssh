# ADR 0001: Go for the backend

## Status

Accepted

## Date

2026-11-26

## Context

The backend is a Python/Flask monolith. It needs 23 direct and about 50
locked Python packages plus system libraries (OpenLDAP, SASL, OpenSSL), and
the container image carries a full Debian userland with a steady stream of
unfixable scanner findings. The goals are fewer dependencies, a smaller and
harder image, single binaries for Linux, Windows and macOS, and full
feature parity with stronger security.

The real risks of WebSSH are logic errors in authentication, authorization
and session handling, not memory corruption in parsers of untrusted binary
formats.

## Decision

Rebuild the backend in Go as a parallel clean build (ADR 0002).

- HTTP, TLS, X.509 and the cryptography WebSSH needs are in the standard
  library. The target is five to seven direct modules.
- SSH client and server come from `golang.org/x/crypto/ssh`, maintained by
  the Go team and used in production by large SSH products.
- Builds for linux/amd64, linux/arm64, windows/amd64, darwin/amd64 and
  darwin/arm64 need no cgo and no per-target linker.
- Data races are found with `go test -race` in CI; parsers we write
  ourselves are fuzzed; `unsafe` is not used in our code.

## Alternatives considered

- **Rust.** Stronger memory and race safety, but a typical web stack pulls in
  100 to 300 crates, partly with C or assembly, and SQLite and TLS bring C
  toolchains to every target. The SSH, SFTP, LDAP and SMB libraries are
  smaller community projects. Rejected: it contradicts the dependency goal,
  and its type system does not prevent the authorization errors that matter
  here.
- **.NET AOT, JVM.** Heavy runtimes without better SSH or SMB libraries.
- **Node or Bun.** Large dependency trees, the problem we want to remove.
- **Zig.** No ecosystem for SSH, SMB, LDAP or WebAuthn.

## Consequences

- SMB support is weak in every candidate language. It is verified before the
  other capabilities are built and may require a maintained fork or an own
  implementation.
- Contributors need Go in addition to Python until the migration ends.
- Toolchain patch releases carry security fixes; `go.mod` follows the
  installed toolchain and CI runs `govulncheck`.
