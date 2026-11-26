# ADR 0009: Password hashing with Argon2id and transparent rehash

## Status

Accepted

## Date

2026-11-26

## Context

The Python release stores local passwords as bcrypt hashes. bcrypt only
uses the first 72 bytes of a password, so the Python release limits
passwords to 72 bytes. Existing hashes must stay verifiable after the
upgrade (ADR 0007).

## Decision

**New hashes use Argon2id** (`golang.org/x/crypto/argon2`, tier A). Each
hash is stored in the PHC string format with algorithm, version and
parameters, so every hash names how it was made. The parameters are set
during phase B2 from a measurement on the smallest supported hardware and
recorded with the measurement.

**Existing bcrypt hashes are migrated unchanged** and verified with
`golang.org/x/crypto/bcrypt`. After a successful sign-in with a bcrypt hash,
or with an Argon2id hash whose parameters are below the current ones, Go
hashes the password again with the current parameters and replaces the
stored hash in the same step. The user notices nothing. The rehash only
touches the Go database; the legacy data stays as it was.

**Length limit.** Passwords may be up to 1024 bytes; longer input is
refused before any hashing. A bcrypt hash can only match passwords of up to
72 bytes, as before.

**Resource limits.** The number of concurrent Argon2id computations is
bounded, so sign-in attempts cannot exhaust memory. Comparisons run in
constant time.

**Placement.** The hashing lives in `internal/auth/local`. Password reset
and administrator creation in the CLI use the same code.

## Alternatives considered

- **Keep bcrypt with the 72-byte limit.** Keeps a limitation of the old
  algorithm as a user-visible rule.
- **Rehash all hashes during migration.** Impossible without the
  passwords.
- **scrypt.** Comparable, but Argon2id is the current recommendation for
  password storage.

## Consequences

- Hashes in the database carry their algorithm; verification dispatches on
  it and rejects unknown identifiers.
- Tests cover bcrypt hashes produced by the Python release, the rehash on
  sign-in, the length limit and the concurrency bound.
