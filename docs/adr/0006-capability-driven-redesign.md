# ADR 0006: Capability-driven redesign, not a port

## Status

Accepted

## Date

2026-11-26

## Context

The Python backend contains years of fixes, workarounds and structures that
grew with the product. Translating it module by module would carry all of
that into Go, including its mistakes. What has to survive is what users and
operators rely on, not how the code is organised.

## Decision

The Go backend implements WebSSH's capabilities as users experience them,
designed from scratch in Go. The Python code is a source of behaviour and
rules, never a template for structure.

**External contracts stay compatible:**

- stored data and its formats (database, files in `DATA_DIR`, encrypted
  secrets, backups); migration is allowed, loss is not;
- documented configuration and environment variables;
- security-relevant behaviour (authentication, authorization, session
  lifetime and revocation, rate limits, audit);
- everything users see and use: pages, workflows, documented URLs and
  commands.

**Internal structure may be redesigned:** packages, internal APIs, and the
protocol between our frontend and the backend. When that protocol changes,
the frontend gets a thin adapter per area.

**Every old rule is classified** before its capability is built. Rules are extracted
from the Python code and tests as testable statements, and each one gets one
class:

| Class | Meaning | Go side |
|---|---|---|
| keep | correct and needed | becomes a Go test and is implemented |
| fix | intent is right, behaviour is wrong or unsafe | the corrected rule becomes a test; the old behaviour is documented |
| drop | workaround for a Python or library limitation, or unreachable | not implemented; the reason is recorded |
| decide | changes what users see or a security property, or the right answer is unclear | the maintainer decides before the capability is implemented |

The classification is part of the capability's pull request.

**User-visible changes are declared.** Every pull request lists each change
in behaviour that users or operators can notice, with its class and the
migration note if one is needed. A change that is not listed is a bug.

## Alternatives considered

- **Faithful port.** Lower design effort, but preserves accidental
  complexity and makes the Go code as hard to change as the Python code.
- **Rewrite from the documentation only.** Loses rules that exist only in
  code and tests, including security hardening.

## Consequences

- Each capability needs rule extraction and classification before implementation;
  this is the main review artefact besides the code.
- End-to-end tests and data compatibility tests are the acceptance oracle,
  not line-by-line equivalence.
- The package map is derived from capabilities; its list of Python modules
  only ensures nothing is forgotten.
