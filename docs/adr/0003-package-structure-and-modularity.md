# ADR 0003: Package structure and modularity rules

## Status

Accepted

## Date

2026-11-26

## Context

The Python backend grew into modules of up to several thousand lines with
cross-cutting imports. A change to one capability often touched many files.
The Go backend should keep every later change local: a new file backend,
sign-in provider or realtime event is a new package or file, not a change
across the tool.

## Decision

**Layout.** One Go module, `github.com/bifrost0x/webssh`.

- `cmd/webssh/` only wires: load configuration, construct packages, register
  implementations, dispatch subcommands. No product logic.
- `internal/<capability>/`: one package per product capability. Inside a
  package one file per responsibility: transport (`http.go`, `http_*.go`,
  `realtime.go`), logic (service), persistence (store), types. Tests sit next
  to the code.
- No `pkg/`: nothing is meant for external import.
- The packages, their kinds and allowed imports are listed in the
  [package map](../architecture/go-package-map.md).

**Kinds and import direction.**

| Kind | May import |
|---|---|
| entry (`cmd/…`) | every internal package |
| foundation | standard library, allowlisted modules, other foundation packages |
| capability | foundation, its own ancestors, capabilities listed in the map |
| edge | foundation, capability, edge packages listed in the map |

- Transport depends on logic, logic on persistence, never the reverse.
- Capabilities never import `internal/httpapi` or `internal/realtime`.
  They use `net/http`, `net/http/*` and `html/template`, directly or through
  a dependency, only in transport files: `http.go` and `http_*.go`, which
  also hold outbound HTTP clients (OIDC discovery and token exchange, GitHub
  API). The rule follows file names, so review checks that no logic hides
  in a transport file.
- Foundation packages use no HTTP, directly or through a dependency.
- `expvar`, `net/rpc` and `net/http/pprof` register global handlers; only
  `internal/httpapi` may use them.
- A parent package never imports its children; children implement the
  parent's interface and `cmd/webssh` registers them.
- No local processes: no package imports `os/exec`, directly or through a
  dependency, or refers to `os.StartProcess`, `syscall.ForkExec`,
  `syscall.Exec` and the process functions of `golang.org/x/sys`. WebSSH
  runs commands on remote hosts over SSH only (`internal/ssh/remotecmd`).
  An exception needs a listed reason in the architecture tests; the list is
  empty.
- `syscall` is imported only by files listed in the architecture tests. The
  only planned one is the netlink route lookup for Tailscale SSH
  (`internal/netpolicy/route_linux.go`); it is listed together with the
  file. Even there, process system calls (`SYS_EXECVE`, `SYS_EXECVEAT`,
  `SYS_FORK`, `SYS_VFORK`, `SYS_CLONE`, `SYS_CLONE3`) are rejected.
- Exception entries for files or packages that do not exist fail, so an
  exception is always reviewed together with its code.
- No cgo (`import "C"`) and no `unsafe` in our code (ADR 0001).
- Interfaces are declared by the consumer and are small. They exist only for
  at least two implementations or a real test seam. Interfaces of extension
  points use only standard library and foundation types.

**Extension points** get an interface and a registry in the consuming
package: file backends, sign-in providers, second factors, realtime message
types, background jobs and migration steps per entity.

**Size.** A production file has at most 400 lines; from 300 lines a split is
considered. Functions usually stay under 60 lines; this is checked in
review, not by a test. Exceptions to the file limit, such as tables
of official test vectors, are listed with a reason in
`internal/architecture/size-exceptions.txt`.

**Names.** No catch-all packages (`util`, `utils`, `common`, `helper`,
`helpers`, `misc`); shared code gets a package named after what it does. No
directories named `data`, `instance`, `secrets`, `build`, `dist`, `plans` or
`reviews`, because the repository's ignore and hygiene rules exclude them.

**Enforcement.** `go test ./internal/architecture` checks, in CI and locally:

- every package, commands under `cmd/` included, is in the package map, and
  the map matches the documented table;
- the direct imports of every non-test file, including files excluded by
  build tags, and the packages they pull in transitively (`go list -deps`
  for all five release platforms) follow the rules above;
- references to process-starting functions;
- file sizes against the limit and the exception list; stale exceptions fail;
- forbidden names;
- Go code exists only under `cmd/` and `internal/`, not in directories the
  go command ignores, and there is no nested module;
- the module allowlist (ADR 0004).

## Alternatives considered

- **Layered packages (`handlers/`, `services/`, `models/`).** Every feature
  then touches every layer package; it recreates the coupling we are
  removing.
- **Flat single package.** Simple at first, but no boundary is enforceable.
- **Linter configuration (depguard or similar).** Adds a tool dependency and
  cannot express ancestor and per-file rules without plugins. A Go test with
  the standard library is enough.

## Consequences

- Adding a package needs a reviewed entry in the package map and in its
  documentation; the tests fail otherwise.
- Cross-capability coupling is visible in one place and in review.
- Large protocol implementations (SMB, SFTP handling) must be split by
  responsibility from the start.
