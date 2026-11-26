# ADR 0007: Legacy data migration

## Status

Accepted

## Date

2026-11-26

## Context

The Go release has its own data model (ADR 0002). Existing installations
keep their state in `DATA_DIR`: the SQLite database, per-user JSON files,
SSH keys, encrypted credentials, MFA secrets and passkeys, host keys,
automation vault, settings and backups, protected with `SECRET_KEY` and the
formats of the Python libraries (Fernet, PBKDF2, bcrypt). All of it must be
present and working after the upgrade.

## Decision

**One package.** `internal/migrate/legacy` is the only code that knows the
Python schema and file layout. It reads legacy data and writes it through
the capabilities' own stores. It never imports Python-era structure into
other packages.

**Legacy formats only during migration.** Go reads Python formats (Fernet
with PBKDF2, the AES-GCM and HKDF variants, store document versions, vault
v1, backup v1 and v2, start-mode fields) only in the migration and in the
restore of Python backups, never at runtime. No read path writes as a side
effect. Unencrypted SSH keys found in `DATA_DIR` are encrypted during the
migration and recorded in the audit log; afterwards Go refuses unencrypted
key material. Imports that users trigger with their own files (old command
set exports, profile exchange files) and the import of the automation vault
are capabilities, not migration, and keep their readers.

**Target model.** All user data moves into the one SQLite database
(`internal/store`); there are no per-user JSON files. Every secret is
decrypted with the legacy scheme, encrypted with the keyring
([ADR 0008](0008-keyring-for-secrets-at-rest.md)) and checked by decrypting
it again. bcrypt hashes are copied unchanged and stay verifiable
([ADR 0009](0009-password-hashing.md)).

**Steps per entity.** The package holds a registry of migration steps, one
file per entity (users, password hashes, MFA secrets, passkeys, recovery
codes, external identities, hosts and profiles, SSH keys, host keys,
credentials, vault entries, command sets, automations and schedules,
settings, notes, tmux session names, audit data). Each step implements three operations: read the
legacy entity, write it to the new model, verify it. A build phase is done
only when the steps for its entities pass against the golden data set.

**Sequence on first start.** If `DATA_DIR` holds a Python installation and
no completed Go migration:

1. Detect the legacy schema version. Supported is everything the last
   Python release (3.3.x) can read, including its older database shapes,
   older store document versions and backups in format v1 and v2. Domain
   structures 3.3.x does not know (an unknown column in a migrated table, a
   newer store version) stop Go before anything is written. Objects SQLite
   or Python create themselves (`sqlite_sequence`, `sqlite_stat*`, indexes)
   and unrelated tables, triggers and views are tolerated and reported; the
   legacy database is opened read-only, so triggers never fire.
2. Refuse to run while the legacy database is in use by another process,
   for example a Python container on the same volume. Go probes the SQLite
   lock and the backup operation lock without writing to the legacy files,
   and stops on a hot journal. An idle Python process holds no SQLite lock,
   so the decisive guard is a second digest of the legacy source taken
   immediately before activation: if it differs from the digest taken in
   this step, Go stops.
3. Check free space: the new database must fit, with a margin. Otherwise
   stop before writing anything.
4. No copy of the legacy data is written; this replaces the earlier plan of
   a full backup before the migration (decided by the maintainer). The
   legacy data is the backup because Go never writes it: the database is
   opened read-only, every file with read-only flags, the legacy digest is
   compared before and after the migration with a stop on any difference,
   and a test proves the files unchanged for every scenario. An optional
   backup in the Go format can be added again at this step if needed.
5. Read the legacy data; it is never modified. Write the new database to a
   temporary file in the Go directory.
6. Run every step's verification: count per entity, decrypt every secret
   (compared in memory, never logged), verify password hashes, compute TOTP
   codes for a fixed time, check WebAuthn credential parameters and host key
   fingerprints, read back through the Go code paths, compare checksums.
7. Activate atomically: close the temporary database in rollback-journal
   mode so no WAL file belongs to it, fsync it, move stale `-wal`/`-shm`
   files of an earlier database aside, rename it to its final name, fsync
   the directory. A crash before the rename leaves the previous state, a
   crash after it a complete database. The migration record (migration version and
   digest of the legacy source) is stored inside the new database, so the
   database and its record appear together or not at all.
8. On any error Go removes the temporary files, leaves the legacy data
   untouched, names the failing entity without secret values and exits. The
   Python release still starts on the original data. Damaged data of a
   single user stops the whole migration: Go does not start, nothing is
   changed, and the report names the user and the file.

A report per entity type (migrated, skipped with reason, discarded with
reason) is logged and kept without secret values.

**Settings derived from behaviour.** Where Go has a safer default than the
Python release, a new installation gets the safer default. For an existing
installation the migration records the old behaviour as an explicit setting,
lists it in the report and shows administrators a notice; nothing changes
silently. Example: host discovery and the reachability check stay allowed
for the roles that have them today
([ADR 0010](0010-outbound-network-policy.md)). The target restriction of
the network policy needs no such setting: its default is unrestricted for
every installation, and `BLOCK_INTERNAL_SSH` keeps its meaning. Where an
old behaviour is an actual attack path and the installation demonstrably
does not rely on it, Go tightens it and the report says so.

**Entity decisions.**

| Entity | Handling |
|---|---|
| Global notepad and host context notes | one note model with a context (saved host or none); both sources are migrated, both entry points in the UI stay |
| Persistent tmux session names (`ssh_sessions`) | migrated; stored names are copied byte for byte, new names follow the same scheme (`TMUX_SESSION_PREFIX`, connection identity and a random part) |
| Automation vault (`automation-vault.json`, encrypted with the user's passphrase) | copied unchanged, marked "import pending"; verification checks structure only. The user imports it with the passphrase, as in Python; the UI shows a notice until then. The old vault write, apply and lock API is not rebuilt |
| Browser sessions, remember and known-device cookies | discarded, reported (see Sessions) |
| Pending enrolments, step-up grants, OAuth states, bootstrap codes | discarded; the report names open bootstrap codes and enrolments so administrators can issue them again |

**Idempotence and the way back.** The state of `DATA_DIR` is one of: no
migration, migrated, legacy source changed. A completed migration is not
run again. After a return to the Python release, users may change the
legacy data. On the next Go start, Go compares the current legacy digest
with the recorded one. If they differ, Go does not start and does not
migrate on its own; the message names `webssh migrate --replace`, which
backs up the Go database and runs the migration again. Changes made in Go
after the first upgrade are not visible to Python; the release notes state
this.

**Go files in `DATA_DIR`.** The Python release is not changed for the
upgrade, and old images stay in use. Go keeps every file of its own in
`DATA_DIR/go/`, which holds only regular files and directories, because
Python 3.3.x aborts a backup or restore on anything else. `logs/` and
`tmp/`, the only places Python never packs or touches, were rejected:
users and log-rotation tools empty them, and losing the Go database weighs
more. After a way back Python treats `go/` as ordinary data: its exports
include it, and its restore removes or replaces it. Go handles this without
a marker of its own (below). The legacy digest excludes `go/` and `logs/`,
and a Go restore of a Python backup never restores the `go/` members it may
contain.

A Python export made after a way back contains `go/` and `secret_key`.
It must not contain decryptable Go secrets: Python exports deliberately
never carry SSH keys or saved passwords. The Go keyring therefore also uses
material that Go keeps under `logs/.webssh-go/`, which Python never exports
and never deletes on restore ([ADR 0008](0008-keyring-for-secrets-at-rest.md)).
Next to it Go keeps a marker of the completed migration. If `go/` is missing
while the marker exists, for example after a Python restore of an archive
without it, Go stops and names `webssh migrate --replace` instead of
migrating again on its own (D-07); only without the marker is a missing
`go/` a first migration.

A Go database is valid when it passes an integrity check and the legacy
digest stored in its migration record equals the current one. There is no
other marker. After a way back, a Python restore changes the legacy data,
so Go stops with the `webssh migrate --replace` message; a restore that
removed `go/` stops the same way through the marker; a matching pair of
legacy data and Go database starts normally. While Go runs it re-checks the
legacy files periodically; if a Python process still writes them, Go
reports not ready and refuses changes until an administrator resolves it.

**Secret rotation.** `rotate-secret-key` is refused while legacy data
exists, that is, until `webssh legacy purge` has run, because the legacy
data, `--replace` and the restore of older Python backups depend on the
current secret. The message explains the reason and the way there.

**Removing legacy data.** Legacy data is removed only by
`webssh legacy purge`, and only after a successful migration. Because the
untouched legacy data is the backup until then, the command first writes a
Go backup including `SECRET_KEY` and the keyring material outside `go/`,
verifies it and aborts if that fails; only an explicit `--skip-backup`
skips this. Go never deletes legacy data on its own. In the state "legacy
data gone without a purge" the command only records the purge, after the
same backup. Before the first file is removed, the command records "purge
in progress" with the list of files in the Go database; after a crash Go
resumes and completes the purge at the next start instead of treating the
partly removed legacy data as changed, and refuses `--replace` and any new
migration until the purge is complete. After the purge it moves the keyring material from
`logs/.webssh-go/` into `go/` with a verified copy before it removes the
old one ([ADR 0008](0008-keyring-for-secrets-at-rest.md)); from then on a
Go-only installation keeps all its data in `go/`. The operations
documentation marks `logs/.webssh-go/` as "do not delete" while legacy data
exists. The migration notes recommend the purge once the way
back is no longer needed, and give the reason when unencrypted keys were
found.

**Backups.** Go writes its own backup format: an archive with a versioned
manifest, the SQLite database and a flag that says whether `SECRET_KEY` and
the keyring material are included. The key is included by default, as in Python;
`--without-secret-key` leaves it out, and backup files are written with mode
0600. A restore checks that the key matches before it activates anything.
Go backups reject non-canonical paths with a clear error. Go backups cannot
be restored by the Python release; the way back uses the unchanged legacy
data.

A backup created by the Python release (format v1 or v2) can be restored by
Go: `internal/backup` unpacks it and hands it to the same migration through
an interface that `cmd/webssh` wires to `internal/migrate/legacy`. The key
that decrypts it is chosen as in Python: the environment secret when set,
otherwise the archive's `secret_key`, otherwise the active key; secrets are
then sealed with the active keyring. Python
backups stay lenient: non-canonical paths are normalised as in Python, so
existing backups remain restorable.

**Sessions.** Browser sessions and known-device cookies are not migrated.
Users sign in once after the upgrade with their existing passwords,
second factors and passkeys. This was decided by the maintainer; it removes
the need to implement the Flask session cookie format. The known-device
cookie only relaxes the sign-in rate limit, so losing it costs no access.

**Configuration.** Go reads every documented environment variable with the
same result as the Python release. Where Python accepts an odd form (for
example `1_000` for an integer, or `" true"`, which Python reads as false),
Go gives the same result and logs a warning; it fails only where Python
fails. Secret placeholders are detected by the stricter of the two Python
rules, with a warning. Variables without meaning in Go (`GUNICORN_*`,
`RATELIMIT_STORAGE_URL`, budgets of the old output flow control that have
no per-connection equivalent) are accepted, ignored and logged with a
warning at start. Redis is not supported; rate-limit counters live in the
process and do not survive a restart.

**Compatibility invariants.** These must not change, because users,
browsers, identity providers or deployment files depend on them. Values are
not repeated here; the sources named are authoritative.

| Invariant | Source of truth | Reason |
|---|---|---|
| WebAuthn relying party ID and origin handling | Python configuration and stored credentials | passkeys are bound to the RP ID; a change locks users out |
| OIDC and GitHub callback URLs | routes of the Python release | registered at the identity provider |
| URL paths users may have bookmarked or linked (sign-in, workspace, file and terminal entry points, health and readiness) | routes of the Python release | links, reverse-proxy rules and monitoring |
| Subfolder deployment behaviour | `docs/wiki/Reverse-Proxy-and-Subfolder-Deployment.md` | reverse-proxy configurations |
| Port, volume paths, UID/GID | `Dockerfile`, `docker-compose*.yml` | deployment files and file ownership |
| Unraid template: user 99:100, appdata paths | `unraid/webssh.xml` | Unraid installations |
| Documented environment variables and their meaning | `docs/wiki/Configuration-Reference.md` | existing configuration |
| `SECRET_KEY` resolution, including the secret generated on first start and kept in the data directory | `entrypoint.sh` | decrypts all stored secrets |
| Restore of Python backups | backup format of the Python release | recovery after upgrade |
| Namespace of browser-local data (HMAC over `SECRET_KEY`, user id, user name and `created_at`) | Python derivation, compared bit for bit by the golden data test | history, favourites and layout in `localStorage` stay visible |
| bcrypt hashes of existing passwords | stored hashes | existing passwords keep working |
| CLI commands in the documented `/app/entrypoint.sh flask --app start:app …` form | `docs/wiki/` and `README.md` | emergency procedures such as password reset and restore ([ADR 0011](0011-http-api-and-cli-surface.md)) |
| LDAP secret helper (`python /app/deployment/ldap_secret_cli.py …`, files under `/run/webssh-auth`), kept by an argv shim ([ADR 0011](0011-http-api-and-cli-surface.md)) | `docker-compose.ldap.yml` | documented LDAP secret maintenance |
| Python 3.3.x keeps working on `DATA_DIR` after a Go run, with `go/` present | backup and restore code of the Python release | the way back |

Every pull request that touches one of these names it and shows the test
that keeps it stable.

## Alternatives considered

- **Migrating lazily on first access.** Leaves mixed state for an unbounded
  time and makes rollback unclear.
- **Converting in place.** Saves disk space but removes the way back.
- **Exporting from Python and importing into Go.** Requires a Python release
  step every user must run first.

## Consequences

- Each capability adds its migration steps to `internal/migrate/legacy` in
  the same pull request that adds the capability.
- A data set produced by the real Python application with synthetic secrets
  is the fixture for migration tests.
- `DATA_DIR` needs room for the new database during the upgrade; Go checks
  this before writing and the release notes state it.
- The release notes tell operators to stop and remove the Python container
  before the first Go start, and how to handle `go/` after a way back.
- The migration notes list every setting the migration recorded, the
  one-time sign-in, the discarded short-lived state, ignored variables and
  the Go backup format.
- The full entity table (old to new, conversion, verification, phase) is
  the migration specification, maintained with the project plan.
