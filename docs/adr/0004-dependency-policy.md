# ADR 0004: Dependency policy in tiers A, B and C

## Status

Accepted

## Date

2026-11-26

## Context

Each dependency is a supply-chain and maintenance commitment. The Python
backend needs about 50 locked packages and several system libraries. The Go
backend targets five to seven direct modules with few transitive ones.

## Decision

Every building block belongs to one tier.

| Tier | Rule | Examples |
|---|---|---|
| A: standard library and `golang.org/x` | use freely | `net/http`, `crypto/*` (including `crypto/hkdf` and AES-GCM for the keyring), `crypto/pbkdf2`, `encoding/json`, `html/template`, `embed`, `log/slog`, `time/tzdata`, `archive/zip`; `x/crypto/ssh`, `x/crypto/bcrypt`, `x/crypto/argon2`, `x/crypto/scrypt`, `x/sys` |
| B: small library with few transitive dependencies | only where writing it ourselves is riskier; needs a reason, an Apache-2.0 compatible license and a maintenance check | SQLite without cgo (`ncruces/go-sqlite3`), `pkg/sftp`, an SMB client, possibly a WebSocket library |
| C: own implementation | only for small, clearly specified protocols, and only with official test vectors and fuzzing | Fernet (to read legacy secrets during migration only), TOTP, cron, QR code, an LDAP subset, an OIDC client, possibly WebSocket |

Open: WebAuthn, own implementation or `go-webauthn`, is decided with the sign-in
design.

Decided building blocks: the keyring uses only the standard library
([ADR 0008](0008-keyring-for-secrets-at-rest.md)); password hashing uses
`x/crypto/argon2` and `x/crypto/bcrypt` ([ADR 0009](0009-password-hashing.md));
`x/crypto/scrypt` reads the legacy automation vault on import. All three are
packages of `golang.org/x/crypto`, which SSH needs anyway, so they add no
module. Rate limits live in the process; there is no Redis client.

**Allowlist.** `internal/architecture/allowed-modules.txt` lists every module
reachable from the module's non-test packages (all modules of the packages
that `go list -deps` reports for `./cmd/...` and `./internal/...` on the five
release platforms) and every direct requirement in `go.mod`, including
test-only ones. All packages are roots, so a package not yet wired into the
binary is checked as soon as it exists. Each entry
names the tier, the packages allowed to import the module directly and the
reason. The architecture tests fail on an unlisted module, a stale entry, or
an import from a package that is not allowed to use the module, so a SQLite
driver used outside `internal/store` fails automatically. Modules that only
appear in the module graph (`go list -m all`) and never reach a binary are
not listed: they need no license or maintenance review.

**Version.** The first Go release is v3.4.0 and continues the numbering.
Release builds set version and revision with `-ldflags -X` in
`internal/buildinfo`; the module path keeps no major-version suffix. The
output follows the Python format, for example `3.4.0 (abc1234)`.

**go.mod.** No `replace` directives (a fork is allowlisted under its own
path) and no `tool` directives. The `go` directive follows the installed
toolchain release.

**Tools stay out of the module.** staticcheck, govulncheck and gosec are
installed in CI with `go install <tool>@<exact version>`, verified by the Go
checksum database. They never enter `go.mod`, so their large dependency trees
do not reach the build list or the binary.

**CI gates.** `go vet`, staticcheck, govulncheck, gosec, `go fix -diff`,
`go test -race`, gofmt, the architecture tests, and Trivy for the image once
the binary ships in it.

## Alternatives considered

- **Free choice with review only.** Dependency creep is gradual and easy to
  miss in review.
- **`tool` directives for linters.** Reproducible, but puts hundreds of tool
  modules into `go.sum` and the module graph.
- **Vendoring.** Adds churn to every diff without a security gain over the
  checksum database.

## Consequences

- **SQLite CVEs are tracked by hand.** The SQLite engine reaches the build
  as Go code translated from C (`github.com/ncruces/go-sqlite3-wasm`).
  Its vulnerabilities are published at <https://sqlite.org/cves.html>, not
  in the Go vulnerability database, so `govulncheck` does not report them.
  The SQLite version (`SELECT sqlite_version()`) is checked against that
  list on every update of the driver modules and before every release; the
  release checklist names the check. Driver updates are pinned and reviewed
  by hand (v0.x API, single maintainer).

- Tier C code is security-critical and gets the strictest review: test
  vectors from the specification, fuzz targets, and round-trip tests against
  data produced by the Python application.
- Each new module needs an allowlist line in the same pull request.
- Dependabot reads its configuration from the default branch. A `gomod`
  entry with `target-branch: go` exists and takes effect once the
  configuration is on `main`. The Go workflow's action pins on `go` are not
  covered by the default `github-actions` entry. The tool versions in
  the Go workflow are updated by hand and belong on the release checklist.
