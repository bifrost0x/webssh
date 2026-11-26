# ADR 0008: Keyring for secrets at rest

## Status

Accepted

## Date

2026-11-26

## Context

The Python release protects stored secrets with several schemes derived
from `SECRET_KEY`: Fernet with PBKDF2 (600,000 rounds, static salt),
AES-GCM with HKDF, scrypt for the automation vault and itsdangerous for
cookies. PBKDF2 adds nothing for a high-entropy key, but costs hundreds of
milliseconds per decryption and serialises connection setup. Each scheme
has its own code, tests and failure modes.

The Go release has its own data model (ADR 0002) and migrates every secret
once (ADR 0007), so it is free to choose one scheme. Python finds its own
data unchanged on the way back, so the choice does not affect rollback.

## Decision

**One foundation package.** `internal/keyring` derives all keys from
`SECRET_KEY` and the keyring material, and encrypts every secret Go writes. It uses only the standard
library. `SECRET_KEY` and its resolution stay unchanged (ADR 0007).

**Keyring material.** Besides `SECRET_KEY`, the keyring uses 32 random
bytes that Go creates once, before it seals the first secret, in
`DATA_DIR/logs/.webssh-go/keyring-material` (mode 0600, directory 0700).
The reason is the way back to the unchanged Python release: Python 3.3.x
exports include `DATA_DIR/go/` and `secret_key`, but never anything under
`logs/`, and a Python restore never deletes or replaces `logs/`. A Python
export made after a way back therefore holds the Go database without the
means to decrypt its secrets, and no Python path removes the material. The
evidence and the rejected alternatives are in the migration specification,
section 2.2. Volume backups of `DATA_DIR` include the file; Go backups,
including the one `legacy purge` writes, include it whenever they include
`SECRET_KEY`.

The place under `logs/` is needed only while legacy data exists, because
only then can a Python export happen; the operations documentation marks
`logs/.webssh-go/` as "do not delete" for that time. After a successful
`webssh legacy purge` Go moves the material into `DATA_DIR/go/`: it writes
and fsyncs a copy, verifies it against the stored key identifier, renames it
into place, records the new location, and only then removes the copy under
`logs/`. At start a leftover state of this move is completed; two differing
copies stop Go. Installations without legacy data keep the material in
`go/` from the start.

Go never creates new material while a Go database exists. If the material
is missing or does not match the key identifier stored in the database, Go
does not start, changes nothing and names the ways out: restore the file,
migrate again from the legacy data with `webssh migrate --replace` while it
exists, or restore the Go backup that `webssh legacy purge` requires. In that
case `--replace` first moves the unreadable database and any non-matching
material aside unchanged, so no Go database exists when new material is
created.

**Derivation.** HKDF-SHA256 (`crypto/hkdf`) with `SECRET_KEY` as input key
material and the keyring material as salt, so neither alone yields a key.
One subkey per purpose.
The purpose and a format version are part of the HKDF info string, so keys
for credentials, SSH keys, MFA secrets, identity provider secrets and
cookie or token MACs are independent. Purposes are a closed list in the
package; a new purpose is a reviewed change.

**Encryption.** AES-256-GCM with random 96-bit nonces
(`crypto/cipher.NewGCMWithRandomNonce`). A ciphertext carries a format
version and a key identifier derived from the key, so a wrong `SECRET_KEY`
fails with a clear error instead of garbage. The associated data binds each
ciphertext to its purpose and record (table, row, column); a ciphertext
copied to another record does not decrypt. Per-key message counts stay far
below the GCM limit of 2^32 random nonces.

**No key stretching at runtime.** There is no PBKDF2 or scrypt in the
runtime path for keyring data.

**Rotation.** `rotate-secret-key` derives the keys from the new
`SECRET_KEY` and the unchanged material and re-encrypts every keyring record
in one database transaction. After it commits, only the new key is in use.
It is refused while legacy data exists, that is, until `webssh legacy purge`
has run, because the legacy data depends on the current `SECRET_KEY`
(ADR 0007).

**Legacy formats.** Python formats are read only by
`internal/migrate/legacy`, with `internal/fernet` as the tier C Fernet
implementation. The one runtime reader of a legacy format is the import of
the automation vault, which the user starts with their passphrase
(`internal/vault`, scrypt from `golang.org/x/crypto`).

**Exception: browser-local namespace.** The namespace of browser-local data
is the Python HMAC derivation, kept bit for bit (ADR 0007 invariant). The
keyring provides it as a named, separately tested derivation; it is not used
for anything else.

## Alternatives considered

- **Keep writing the Python formats.** Keeps five schemes and the PBKDF2
  latency, and carries Python's design into the new code.
- **XChaCha20-Poly1305 from `golang.org/x/crypto`.** Larger nonces, but
  AES-GCM with random nonces is sufficient for the volumes involved and
  needs no extra package.
- **A crypto library such as Tink.** A large dependency for a small,
  well-specified job.

## Consequences

- The migration decrypts each secret with the legacy scheme, encrypts it
  with the keyring and checks it by decrypting again (ADR 0007).
- Backups that include `SECRET_KEY` also include the keyring material and
  can be restored on a new host; backups without them need the same
  `SECRET_KEY` and material on the target.
- Losing the material without a backup of it makes the Go secrets
  unreadable; Go stops instead of starting with unreadable data. Before the
  purge, `migrate --replace` from the legacy data is still possible; after
  it, the material is in `go/` and in every Go backup that includes
  `SECRET_KEY`.
- The browser-local namespace keeps using `SECRET_KEY` alone, as Python
  does.
- `internal/keyring` gets known-answer tests for the derivation, tamper
  tests (changed ciphertext, nonce, associated data, key) and fuzzing of the
  decoder.
