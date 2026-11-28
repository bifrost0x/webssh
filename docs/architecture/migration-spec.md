# Legacy data migration specification

This document specifies how the Go release takes over an existing Python
installation: every entity users and administrators have created, the
sequence on first start, the failure behaviour, the way back and the tests
that prove it. It implements [ADR 0007](../adr/0007-legacy-data-migration.md)
and the maintainer decisions D-01 to D-30.

Scope and status: draft for G0. Go table and field names are proposals; the
owning package fixes them when it adds its migration step. Values such as
salts, iteration counts and limits are not repeated here; the sources named
are authoritative:

- golden data set: `tests/golden/fixture/manifest.json`
  (`entity_inventory`, `data_kinds`, `values`),
- the contract inventory of the Python release v3.3.1 (tables, crypto,
  schema mechanism, DATA_DIR layout, backup layout, stable contracts),
- package ownership: [go-package-map.md](go-package-map.md).

## 1. Principles

1. **Legacy data is only read, and is its own backup.** No byte, mode or
   modification time of a legacy file changes, in any state, including
   failures (invariant I-01 defines exactly what is checked). Go opens the
   legacy database read-only and every legacy file with read-only flags, and
   compares the source digest before and after the migration. Because the
   legacy data stays untouched, it is the backup: the Python release starts
   on it at any time until `webssh legacy purge`. A separate copy is not
   written (section 5.2, step 6).
2. **Nothing a user created is lost.** Every record of every entity in
   section 3 is migrated, or kept in place and reported with a reason. Silent
   loss is a defect. Limits and quotas that apply to new records never drop
   migrated ones; records above a current limit are migrated and reported.
3. **One package knows the legacy layout.** `internal/migrate/legacy` reads
   the Python schema and writes through each capability's store. Legacy
   formats (Fernet, PBKDF2 key derivation, HKDF contexts, Python JSON
   stores) are read only there (D-05).
4. **Secrets are re-encrypted.** Every secret the migration can decrypt is
   decrypted with the legacy derivation and written with the Go keyring
   derived from the same `SECRET_KEY` (D-04). Password hashes are copied
   unchanged and rehashed with Argon2id after the next successful sign-in
   (D-12). The automation vault cannot be decrypted without the user's
   passphrase and is carried over unchanged (D-06).
5. **Verification is functional.** A migration is complete only when every
   secret was decrypted and read back through the Go code path, and the
   functional checks of section 3 pass in memory.
6. **Fail closed, name the cause.** Any error stops before activation. The
   message names the entity type, the user id and the record id, never a
   secret value, plaintext, hash or token.
7. **Keep visible behaviour.** Where Python derives behaviour from data
   (defaults by account generation, implicit permissions),
   the migration writes the effective previous behaviour as explicit Go
   settings and reports each one (D-01).

## 2. Terms

| Term | Meaning |
|---|---|
| Legacy source | The Python state in `DATA_DIR`: `app.db`, `app_settings.json`, `secret_key`, `session_epoch`, `known_hosts`, `recovery-check.json`, `users/**`, `deleted_users/**`, legacy single-user paths (`profiles.json`, `keys/`, `commands/`). Runtime paths are not part of it: `logs/`, `tmp/`, `.access-revocations/`, `.ldap-revocation-fences/`, `.webssh-ready-*`. |
| Go directory | `DATA_DIR/go/` (mode 0700, section 2.1). It holds only regular files and directories: no symlinks, sockets or FIFOs, because Python 3.3.x aborts a backup or restore on such entries. |
| Go database | `<Go directory>/webssh.db`. Go runs it in WAL mode; before every activation and replacement it is closed in `journal_mode=DELETE` so that no `-wal` or `-shm` file is left beside it (5.2 step 10, 5.4). |
| Go-owned paths | The Go directory with the database, staging (`.migration-*/`), reports (`migration-report-*.json`), replaced databases (`replaced-<UTC>/`) and the lock file `webssh.lock`, plus the Go state directory `logs/.webssh-go/` with keyring material that `--replace` set aside (`logs/.webssh-go/replaced-<UTC>/`, 5.4). Go also writes the shared log files of E34 and, on a new installation only, `DATA_DIR/secret_key` (I-08); like the entrypoint it creates `DATA_DIR`, `logs/` and `keys/` with mode 0700. Nothing else. |
| Incarnation | Normative rule: `datetime.fromisoformat(text).isoformat()` applied to the stored `users.created_at` text, as SQLAlchemy 2.1.6 (pinned in `requirements.txt` of 3.3.x) returns it. Verified vectors: `2026-11-02 09:00:00.000000` → `2026-11-02T09:00:00`; `…09:00:00.250000+00:00` → `…T09:00:00.250000+00:00`; `2026-11-02` → `2026-11-02T00:00:00`; `2026-11-02 09:00` → `2026-11-02T09:00:00`; `2026-11-02T09:00:01.5` → `2026-11-02T09:00:01.500000`. |
| Source digest | SHA-256 over the canonical listing of the legacy source (section 5.3). |
| Go state directory | `DATA_DIR/logs/.webssh-go/` (mode 0700), only while legacy data exists: the keyring material file `keyring-material` (32 random bytes, mode 0600) and the marker `migrated` (database identity). After `legacy purge` the material lives in `go/keyring-material` and this directory is removed; installations without legacy data never have it. Section 2.2. |
| Classes | `keep`, `fix`, `drop`, `decided` as in [ADR 0006](../adr/0006-capability-driven-redesign.md). `decided` cites the maintainer decision. |
| Failure codes | **STOP**: abort, remove staging, exit non-zero, legacy untouched; Go does not start and the report names user and file. **FLAG**: migrate, mark the record, report it, show a notice where the UI has one. **KEEP-IN-PLACE**: not imported, left in the legacy path, reported. **DISCARD**: runtime state, not imported, counted in the report. |

### 2.1 Location of the Go directory and the way back

Go keeps all its own data in `DATA_DIR/go/`, on the persistent data volume
and next to the legacy data. Places that Python 3.3.x never packs or
touches exist only below `logs/` and `tmp/`
(`app/backup_manager.py:31`, `:36-39`, `:762-796`, `:923-932`); they were
rejected because users and log-rotation tools empty `logs/`, and `tmp/` is
the disposable transfer directory (`config.py:50-51`,
`app/sftp_handler.py:911-936`). Losing the Go database permanently weighs
more than the risk below.

Python 3.3.x is not changed for the upgrade. After a way back it treats
`go/` as ordinary persistent data:

- every Python export, backup, online backup and rotation snapshot includes
  `go/` (`app/backup_manager.py:330-347` walks all of `DATA_DIR` except the
  excluded top-level directories; `app/online_backup.py:84`,
  `app/secret_rotation.py:17`, `:433`);
- a Python restore deletes `go/` when the archive lacks it, or replaces it
  with the archive's copy (`app/backup_manager.py:905-960`, `extra_paths`);
- `_existing_persistent_files` and `_stage_source` abort on symlinks and
  non-regular files (`app/backup_manager.py:762-796`, `:330-347`), hence the
  rule that `go/` holds only regular files and directories. Go closes its
  database in `journal_mode=DELETE` at shutdown, so a file copy taken by
  Python while Go is stopped is a complete database.

### 2.2 Go secrets in Python exports after a way back

Requirement: a Python export made after a way back must not contain any Go
secret that can be decrypted, and no path may destroy Go data. Python is
frozen at 3.3.x, so its behaviour is a stable contract.

What a Python 3.3.x export contains and what a restore deletes:

- An export walks all of `DATA_DIR` (`app/backup_manager.py:312-360`,
  `_stage_source`) except the top-level directories `logs/`, `tmp/`,
  `.access-revocations/` and `.ldap-revocation-fences/` (`:31-39`,
  `:330-347`) and, for exports only, every path with a component `keys`,
  `deleted_users/`, `credentials.json*` and `automation-vault.json*`
  (`:299-310`, "Native exports never carry reusable remote authentication
  material"). It therefore includes `go/webssh.db` and `secret_key`. The
  online backup uses the same walk (`app/online_backup.py:80-92`), the
  rotation snapshot the same archive writer (`app/secret_rotation.py:17`,
  `:433`; `app/backup_manager.py:452-462`).
- A restore computes the persistent files of the target, skipping only
  `logs/` and `tmp/` (`app/backup_manager.py:762-796`), drops archive
  members under the excluded directories and, for exports, the credential
  paths (`:923-932`), and deletes every existing file that is not in the
  filtered manifest (`:946` `extra_paths`, `:813-855`
  `_restore_staged_files`, unlink at `:853`). An export restore therefore
  deletes existing `keys/` paths and `credentials.json` as well.

Options evaluated:

| Option | Export contains decryptable Go secrets? | Can a Python path destroy Go data? | Verdict |
|---|---|---|---|
| Keyring from `SECRET_KEY` only, Go database in `go/` | yes: `go/webssh.db` plus `secret_key` | an export restore without `go/` deletes the database | rejected (R1) |
| Go database below a path with a `keys` component (for example `go/keys/`) | no, excluded from exports | yes: an export restore deletes it as a credential path (`:923-932`, `:853`) | rejected |
| Go database under `logs/` | no | no | rejected by the maintainer: users and log rotation empty `logs/`, the database would be lost |
| Material outside `DATA_DIR` (`BACKUP_TEMP_DIR`) | no | no | rejected: `BACKUP_TEMP_DIR` defaults to `/tmp` (`config.py:388-391`) in older installations and is lost when the container is recreated |
| Second secret from the environment | no | no | rejected: every installation would need new configuration before the upgrade, which breaks the zero-configuration upgrade |
| **Keyring from `SECRET_KEY` and Go-generated material in `logs/.webssh-go/`** | **no**: `logs/` is never exported, so the export holds the database and `SECRET_KEY` but not the material | **no** for the material and the marker: a restore never deletes or replaces `logs/` (`:762-796`, `:923-932`); a removed database is detected (S1a) | **chosen** |

The chosen design ([ADR 0008](../adr/0008-keyring-for-secrets-at-rest.md)):

- The material needs the place under `logs/` only while legacy data
  exists, because only then can a Python export happen. A fresh
  installation without legacy data creates it in `go/keyring-material`.
  After a successful `legacy purge` Go moves it there (5.9) and removes
  `logs/.webssh-go/`. Go looks for the material in `go/` first, then in
  `logs/.webssh-go/`.
- On the first migration Go creates `logs/.webssh-go/keyring-material` with
  32 random bytes, mode 0600, and fsyncs it and the directory before any secret
  is sealed. The keyring derives every key from `SECRET_KEY` and this
  material together; the database stores the resulting key identifier.
- The file is regular, so Python's walks accept it. It sits in a hidden
  directory, so shell globs such as `logs/*` and log rotation patterns do
  not match it, and Python's log pruning (`app/audit_logger.py:71-82`) only
  removes `<log file>.<digits>`. Volume backups of `DATA_DIR`, which the
  documentation tells operators to take, include it. The operations
  documentation names `logs/.webssh-go/` explicitly as "do not delete" while
  legacy data exists.
- The Go database itself stays in `DATA_DIR/go/` (section 2.1). A Python
  export after a way back contains it with non-secret Go data (hosts,
  commands, notes), the same class of data Python exports already contain
  for Python's own stores, and sealed secrets it cannot decrypt.
- A Python export restore on the same host brings `go/` back together with
  the untouched material, which is the installation's own consistent data.
  On another host the material is absent, so the restored Go secrets stay
  unreadable, matching Python's rule that exports do not carry remote
  credentials.
- Go backups (D-03, D-08), including the backup `legacy purge` writes,
  include the material whenever they include `SECRET_KEY`; with
  `--without-secret-key` they include neither, and the restore needs both on
  the target.

**Loss of the material never loses data silently.** Go never creates new
material while a Go database exists. At every start Go checks the key
identifier against the database:

- material missing or not matching while the database holds sealed
  records: state S9, STOP. The message names the file, says that sealed SSH
  keys, saved passwords and second factors cannot be read without it, and
  lists the ways out: restore `logs/.webssh-go/keyring-material` from the
  volume backup; while the legacy data exists, `webssh migrate --replace`
  (migrates again from the Python data, Go changes are lost, the replaced
  database is kept as a Go backup); after `legacy purge`, restore the Go
  backup that `legacy purge` required (5.9), which contains the material.
- Nothing is deleted or overwritten in S9. A volume restore that brought
  back `go/` but not `logs/.webssh-go/` therefore stops with this message
  instead of starting with unreadable secrets.

The earlier advice to remove `go/` before a Python export is withdrawn: it
destroyed the Go database. An operator who does not want Go's non-secret
data in a Python export moves `go/` out of `DATA_DIR` for the export and
back afterwards.

## 3. Entity table

One row per entity type of `entity_inventory` (41 types, numbered E01 to
E41 in manifest order), followed by the items the inventory does not list
separately (A01 to A13). Phase is the build phase whose pull request adds the
step (ADR 0007: one file per entity in `internal/migrate/legacy`).

Common rules for every row:

- **Identifiers are preserved**: user ids, profile, key, jump host, SOCKS,
  SMB, credential, command, command set, runbook, schedule and run ids keep
  their values, because stored references, tmux names, schedule grants and
  browser namespaces use them. Surrogate keys of factor tables are kept too.
- **Timestamps** are converted from naive UTC text
  (`YYYY-MM-DD HH:MM:SS.ffffff`) to the Go representation without loss of
  precision; JSON timestamps are kept as their original strings where they
  enter a digest or fingerprint.
- **Unknown fields** that Python tolerates are kept per record in a
  `legacy_extra` JSON column and listed in the report. A document Python
  itself rejects (its validator fails, `schema_version` newer than
  `CURRENT_STORAGE_VERSIONS`) is STOP for the whole migration: Go does not
  start, nothing is changed, and the report names the user and the file.
  Python shows the same store as broken today, and silently skipping it
  would lose data. Decided by the maintainer; there is no option to skip a
  damaged user.
- **Older store versions** are lifted in memory with the rules of
  `app/storage_migrations.py` (section 3.5 of the inventory), never written
  back.

### 3.1 Accounts and sign-in (phase B2)

| # | Entity | Legacy source | Go target (draft) | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E01 | User account (admin, non-admin, locked, ADMIN_USERS, 72-byte password, legacy Unicode name, id reuse) | `users`: `id`, `username`, `created_at`, `last_login`, `is_admin`, `is_locked`, `auth_generation`, `mfa_enabled`, `settings_default_generation`, `mfa_failed_attempts`, `mfa_last_failed_at`, `mfa_step_up_failed_attempts`, `mfa_step_up_last_failed_at` | `internal/accounts`: `accounts_users(id, username, incarnation TEXT, history_generation TEXT, created_us, last_login_us, is_admin, is_locked, auth_generation, mfa_required, managed_by, legacy_extra)` with times as microseconds since the Unix epoch (UTC); `mfa_enabled` → `mfa_required`; `managed_by` (`''`, `ldap`, `github`) is derived from the LDAP and GitHub identities (E03, E04); `accounts_id_floor(value)` holds the id floor of 4.1, raised with `RaiseIDFloorTx` to the highest legacy and quarantined id. The backoff counters `mfa_failed_attempts`, `mfa_last_failed_at`, `mfa_step_up_*` go to `internal/auth`: `auth_mfa_throttle(user_id, scope, failures, last_failed_at)` with scope `login` or `step_up` (`auth.ImportThrottleTx`) | Missing additive columns take the defaults of `ensure_user_columns` (`settings_default_generation` 0 for old databases; when `is_admin` is absent only `MIN(id)` becomes admin). Python's start-up normalisation is applied in memory: `ensure_initial_admin`, then `sync_admin_users` (section 4.6). `incarnation` and `history_generation` are frozen at migration (section 4.2). Usernames are copied byte for byte, no normalisation. Backoff counters are kept in `auth_mfa_throttle`. Ids are kept; there is no `AUTOINCREMENT` (its `sqlite_sequence` table would break the owner prefix rule of the store), the floor table takes its role. | keep; ADMIN_USERS decided (K-11 variant B) | Count equal; every field equal after normalisation; admin set equal to the legacy set after Python's start-up rules; locked accounts are refused at sign-in with the Python wording; id sequence above every legacy and quarantined id (4.1). | STOP |
| E02 | Local password | `users.password_hash` (bcrypt `$2b$12$`) | `internal/auth/local`: `authlocal_passwords(user_id, algorithm='bcrypt', hash, updated_us)` (owner `authlocal`) | Copied unchanged. After a successful sign-in Go stores Argon2id and drops the bcrypt value in the Go store only (D-12). Inputs above 72 UTF-8 bytes are rejected for bcrypt hashes, as Python does (`password_matches`). Directory- and GitHub-managed accounts keep their random unknown hash. While bcrypt hashes remain, an unknown name answers with bcrypt timing and an account already rehashed to Argon2id answers faster; this is accepted and named in the upgrade notes. | decided (D-12) | Each fixture password verifies; the 72-byte password verifies; 73 bytes fails; wrong password fails; after the first Go sign-in the row holds Argon2id and the password still verifies; legacy `app.db` unchanged. | STOP if a hash is not parseable modular crypt |
| E03 | LDAP identity | `ldap_identities`: `provider`, `subject`, `directory_username`, `distinguished_name`, `created_at`, `last_verified_at` | `internal/auth/ldap`: `authldap_identities` with unique `(provider, subject)` and unique `user_id` | Verbatim. | keep | Count, uniqueness, binding: a sign-in with the lab directory (K7) resolves to the same user id. | STOP on uniqueness violation |
| E04 | GitHub identity | `github_identities`: `github_user_id`, `login`, `display_name`, `provisioned_by_github`, timestamps | `internal/auth/github`: `authgithub_identities` | Verbatim; `provisioned_by_github` keeps the managed-account rule. | keep | Count; managed flag; lab sign-in (K7) maps `github_user_id` to the same account. | STOP on uniqueness violation |
| E05 | OIDC identity | `oidc_identities`: `issuer`, `subject`, `created_at` | `internal/auth/oidc`: `authoidc_identities` unique `(issuer, subject)` | Verbatim. | keep | Count; lab sign-in with Dex (K7) maps to the same account. | STOP on uniqueness violation |
| E06 | GitHub sign-in configuration | `github_auth_configuration` (singleton): `enabled`, `client_id`, `encrypted_client_secret` (Fernet), `redirect_uri`, `auto_provision`, `allowed_orgs_json`, `generation`, `updated_by`, timestamps | `internal/auth/github`: `authgithub_config` with `client_secret` sealed by the keyring | Fernet decrypt with the legacy derivation (`data_kinds` `github_client_secret`), seal with the keyring, compare in memory. `redirect_uri` unchanged (invariant I-03). | keep | Decrypted value equals `values.github_client_secret`; reading back through `internal/auth/github` yields the same bytes. | STOP on decrypt failure |
| E07 | Security feature gate | `security_feature_states` (`passkey`, `totp`, `oidc`, `ldap`, `recovery`) | `internal/operations`: `operations_feature_gates(feature, enabled, updated_by, updated_at)` | Verbatim; absent rows stay absent (the environment ceiling still applies at run time). | keep | Effective state per feature equal for the fixture environment. | STOP on unknown feature name |
| E08 | TOTP authenticator | `totp_authenticators`: `encrypted_secret` (Fernet), `label`, `active`, `last_accepted_step`, timestamps | `internal/auth/totp`: `totp_authenticators(id, user_id, label, sealed_secret, active, last_accepted_step, created_at, activated_at, last_used_at)` (owner `totp`, times in microseconds) | Fernet decrypt (per-user derivation), seal with the keyring, store with `(*totp.Service).ImportTx`; the legacy id is kept. `last_accepted_step` kept (replay protection). | keep | Decrypted secret equals the manifest; the code for the manifest time verifies; the same step is rejected as a replay; a step at or below `last_accepted_step` is rejected. | STOP on decrypt failure |
| E09 | TOTP enrollment (unfinished) | `totp_enrollments` | none | Not imported. Counted per user in the report so the user can restart enrolment. | decided (D-02) | Report lists the count; no row in the Go database. | DISCARD |
| E10 | Passkey | `webauthn_credentials`: `credential_id` (raw), `public_key` (COSE), `sign_count`, `transports` (JSON), `name`, timestamps | `internal/auth/webauthn` (owner `webauthn`): `webauthn_credentials(id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at)` with the legacy id; written with `(*webauthn.Service).ImportTx`, read back with `webauthn.ImportedTx`; the COSE key is checked with `webauthn.ParseCOSEKey` (the migration has no parser of its own) | Verbatim bytes; COSE key parsed once to validate algorithm (ES256, RS256, EdDSA) and curve. User handle stays the ASCII decimal user id (I-02). | keep | Every assertion vector in `values.webauthn_vectors` verifies against the migrated record with the configured RP ID and origin; the counter rule holds (synced passkey with counter 0 accepted with 0; non-zero counter must increase); an assertion signed by a different key fails. | STOP on unparseable COSE key or unsupported algorithm |
| E11 | Recovery codes | `recovery_codes.code_hash` (SHA-256 with domain prefix) | `internal/auth`: `auth_recovery_codes(id, user_id, algorithm='sha256-webssh-v1', hash, created_at)` | Hash copied with `(*auth.Recovery).ImportTx`; the normalisation rule (upper case, whitespace removed) is part of the algorithm tag. Consumed codes are already deleted in Python. | keep | Each remaining manifest code is accepted once and then rejected; the consumed code is rejected. | STOP on hash length other than 32 bytes |
| E12 | Browser login (sessions, cookies) | `authentication_sessions`, cookies `session`, remember cookie, `<name>_device` | none | Not imported; every user signs in once. Count of live sessions per user in the report. | decided (D-02) | No Go session exists after migration; every manifest cookie is rejected by Go. | DISCARD |
| E13 | Transient auth state | `pending_authentications`, `step_up_grants`, `step_up_intents`, `factor_bootstrap_tokens`, `github_oauth_states`, `oidc_login_states`, `webauthn_challenges` | none | Not imported. Unexpired factor bootstrap codes are listed per user (username and action, no token) so admins can reissue them. | decided (D-02) | Report lists open bootstrap codes and step-up grants. | DISCARD |
| E14 | Runtime sessions | `socket_sessions`; `ssh_sessions` | `socket_sessions`: none. `ssh_sessions`: see A01 | `socket_sessions` discarded; persistent tmux rows migrate as A01. | decided (D-02, D-09) | Report counts discarded rows. | DISCARD |

### 3.2 Automation (phase B6)

| # | Entity | Legacy source | Go target (draft) | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E15 | Automation schedule (active, paused) | `automation_schedules`: `id`, `user_id`, `revision`, `enabled`, `cron`, `timezone`, `grant` (JSON), `next_at`, `last_status`, `claim_id`, `claimed_at` | `internal/automation`: `automation_schedules(id, user_id, revision, enabled, cron, timezone, next_at, last_status, approval)` where `approval` is the Go-native grant | The legacy grant is first validated with the legacy rules against the legacy state (`_validate_snapshot`: account tuple with the legacy session epoch, policy revision, profile fingerprints, key digests, credential generations). A valid grant becomes a valid Go approval bound to the Go equivalents (section 4.3); an invalid grant is migrated as "needs review" and fails exactly as it would in Python. A row with a stale claim gets Python's recovery: `enabled=false`, `last_status='unknown'`, claim cleared, revision + 1. Rows whose `grant.account[0]` differs from the current incarnation of that user id belong to a deleted account (4.1) and are KEEP-IN-PLACE. | keep | Count; field equality; the schedules of the base fixture were approved before its session epoch rotation, so Python rejects them (`preview_changed`) and they migrate as "needs review" (negative case); the schedule of `datadir-extended.tar` approved after the rotation (`schedule_after_rotation`, AU2-4) migrates with its approval and runs at its next slot without a new approval; the active schedule on a copy with the approval epoch runs against the lab sshd (K10); the paused one stays paused; a valid grant's key digests are rewritten to the public-key digests the Go run side binds with; a changed target after migration invalidates the approval; `next_at` produces the same next slot. | STOP on unparseable grant or cron; FLAG for invalid grant |
| E29 | Automation runbook | `users/user_N/automation.json` `{version: 1, runbooks: [...]}` | `internal/automation`: `automation_runbooks`, `automation_runbook_steps(position, name, command, timeout, sudo)` | Verbatim, order kept; deleted runbooks are not in the file. Runbooks above the current count limit are migrated and reported. | keep | Count; equality of steps (20-step Unicode runbook); digest of the runbook as the grant sees it is unchanged. | STOP |
| E30 | Automation vault (passphrase protected) | `users/user_N/automation-vault.json` version 1 or 2 | `internal/vault`: `vault_legacy_automation(user_id, document BLOB, version, imported_at NULL)` | Stored byte for byte. Only structure is checked: JSON keys, `kdf` value, base64 field lengths, version 1 or 2. No decryption (passphrase unknown). The UI shows "legacy vault not imported yet" until the user imports it with the passphrase; the import decrypts with the legacy AAD (user id and incarnation) and writes named credentials. | decided (D-06) | Structure check; with the manifest passphrase the import yields the three manifest passwords, including the 4096-byte one; a wrong passphrase fails without changing data. | STOP on malformed structure; FLAG when present (import pending) |
| E31 | Automation run history | `users/user_N/automation-runs.json` | `internal/automation`: `automation_runs`, one JSON document per run with the member order of the Python file and its size there (`py_size`), output and truncation flags verbatim (AU1-2: the golden runs have a non-canonical member order that the byte-equal export needs) | Verbatim. Runs with `queued` or `running` entries get Python's load-time rule: status `unknown`, reason `run_interrupted`. | keep | Count; failed fixture run with stdout and stderr equal byte for byte; export as JSON and CSV equal to the Python export for the same run. | STOP |

### 3.3 Settings (phase B1)

| # | Entity | Legacy source | Go target (draft) | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E16 | Admin settings | `DATA_DIR/app_settings.json` (schema 2): registration, automation and credentials flags with their opaque `*_revision` values, `automation_effective_observed`, `automation_enabled_from_environment`, runtime features, `audit_backup_count`, sign-in limits, `ssh_gateway_enabled`, `herdr_enabled`, `support_links_enabled`, `tailscale_ssh_restrict_tailnet_routes` | `internal/settings`: `settings_app(key, value, source, rule, updated_us)` with `source = 'migrated'` (`settings.ImportApp`) | Values and revision strings copied verbatim (revisions are part of schedule and credential bindings). `migrate_runtime_features` and `migrate_feature_policies` are applied in memory first. Absent keys stay absent so the Go default applies only where D-01 allows it (section 6). | keep | Effective value of every setting equal to Python's for the fixture environment, including the support-links edge case (`null` and `false`). | STOP |
| E25 | User settings | `users/user_N/settings.json` (schema 2): theme, overview layout and panels, dismissed items, start page, terminal appearance, `notepad`, `confirm_session_close`, `sync_terminal_directory`, `disconnect_session_action`, `authentication_session_duration_minutes`, `workspace_presets`, tour state, `recovery_reviewed_at` | `internal/settings`: `settings_user(user_id, key, value)` (`settings.ImportUser`); `notepad` to E28/A05, `workspace_presets` to A06; since step version 2 also `settings_notices(user_id, notice, acknowledged_us)`: the open notice `upgrade-3.4` for every account taken over (`settings.GrantNotice`) | Each key copied. Defaults that depend on `users.settings_default_generation` are written explicitly (section 6). | keep; materialised defaults decided (D-01) | Effective settings equal to `get_user_settings` for every fixture user, including users without a file; the notice `upgrade-3.4` is present and open for every account (`settings.VerifyNotice`). | STOP |

### 3.4 Host trust (phase B3)

| # | Entity | Legacy source | Go target (draft) | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E17 | Global host key | `DATA_DIR/known_hosts` | `internal/ssh/hostkey`: `hostkey_entries(scope='global', line_no, marker, hosts, key_type, key_blob, hashed)` | Every line kept in order, including hashed hosts (`|1|…`), `[host]:port`, `@revoked`, comments. `@cert-authority` lines are kept and FLAGged; Python ignores them with a warning. Parsed for verification, raw line stored for export. | keep | The trusted fixture key is accepted without a prompt; the `@revoked` key is rejected; fingerprints equal `values.host_keys`. | STOP for an invalid line: Python's parser (`app/host_key_store.py:679-722`) rejects the whole file, so the store is damaged user data |
| E24 | User host key | `users/user_N/known_hosts` | same table with `scope='user', user_id` | As E17. Deleted entries are absent in the file. | keep | Three recorded keys accepted without a prompt for that user only; another user gets the TOFU prompt. | STOP |

### 3.5 Session state that is not migrated (phase B2)

| # | Entity | Legacy source | Go target | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E18 | Session epoch | `DATA_DIR/session_epoch` | none | Read for E15 validation only. Go's revoke-all generation starts fresh. The file stays as is. | decided (D-02) | E15 grants validated with the legacy epoch. | STOP if the file is malformed (Python refuses to start too) |

### 3.6 Hosts and connections (phase B3, SMB B4)

| # | Entity | Legacy source | Go target (draft) | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E19 | SSH host profile | `users/user_N/profiles.json` (schema 0 to 3) | `internal/hosts`: `hosts_profiles` with one column per field of `_PROFILE_FIELDS` in `app/profile_manager.py` (3.3.x), including `herdr`, `use_herdr`, `role_override`, `authenticated_greeting`, `detection_state`, the identity facts and the `*_checked_at` timestamps, plus `legacy_extra` | Schema 0 to 3 lifted in memory (1 to 2 derives `startup_mode`; 2 to 3 drops `tailscale_authorized`). Names longer than the current limit keep their stored value (Python already shortened at write). Detected host facts kept. | keep | Count; field equality; the profile fingerprint (`automation_store.profile_fingerprint`) recomputed from the Go record equals the legacy one; SSH login with password, key, jump and SOCKS routes in the lab (K2/K10). | STOP |
| E20 | Jump host | `users/user_N/jump_hosts.json` | `internal/hosts`: `hosts_jump_hosts` | Verbatim (no passwords stored there). | keep | Count; key-authenticated jump route connects in the lab. | STOP on dangling `key_id` only if Python rejects it; otherwise FLAG |
| E21 | SOCKS proxy | `users/user_N/socks_proxies.json` | `internal/hosts`: `hosts_socks_proxies` | Verbatim, including `remote_dns`. | keep | Count; lab connection through the SOCKS container with and without authentication. | STOP |
| E22 | SMB share | `users/user_N/smb_shares.json` | `internal/files/smb`: `smb_shares` | Verbatim, empty domain preserved as empty. | keep | Count; field equality; listing a lab Samba share with an assigned credential (K1). | STOP |
| E23 | SSH private key | `users/user_N/keys/keys.json` and `<uuid>.pem` (Fernet token, or plaintext PEM in old installations) | `internal/vault`: `vault_ssh_keys(id, user_id, seq, name, key_type, public_key, fingerprint_sha256, private_key sealed, uploaded_at, state)`; `seq` keeps the order of `keys.json`, which is the list order | Fernet decrypt with the per-user derivation, or read plaintext; pending deletion entries reconciled with `keys.json` as the authority (as `_reconcile_pending_key_deletions`); parse; seal with the keyring through `vault.ImportKey(ctx, tx, sealer, Imported{…})`, called in the order of `keys.json`; it returns the public key of a usable key for the verification. A key id the AAD cannot carry (a NUL byte) is STOP. Plaintext keys are sealed, an audit event is written and the report recommends `webssh legacy purge` (D-05, D-07). Keys Go cannot load (passphrase-protected or DSA material from old releases) are migrated sealed with `state='unsupported'` (4.8). | keep; plaintext decided (D-05); DSA decided (plan section 9) | Public key and fingerprint equal `values.ssh_keys.stored[*].public_key_openssh`; RSA, ECDSA P-256/384/521 and Ed25519 in OpenSSH and PEM form authenticate against the lab sshd; the 128-character Unicode name is equal; the legacy plaintext key is sealed and usable; the key digest used by E15 equals the legacy digest. | STOP on decrypt failure or a `keys.json` entry without file; FLAG for unsupported |
| E26 | User command | `users/user_N/commands.json` (list, or legacy object `{"commands": [...]}`) | `internal/commands`: `commands_user` | Legacy object form lifted in memory. | keep | Count; Unicode command equal; deleted command absent. | STOP |
| E27 | Command set | `users/user_N/command_sets.json` | `internal/commands`: `commands_sets`, one row per set with the record as Python stored it; steps and parameters stay in the record, unknown members are kept (CM1-3) | Verbatim including argv form, `{{name}}` parameters and sudo flag. | keep | Count; resolved preview of the parameterised set equal to Python's; reference protection (profile and host context references) intact. | STOP |
| E28 | Host context | `users/user_N/host_context.json` `{version: 1, hosts: {profile_id: {notes, directories, command_sets, revision}}}` | `internal/hostops`: notes to `hostops_notes(user_id, profile_id, body, revision)` with `hostops.ImportNote` (D-11); directories and command set references to `hostops_host_context(user_id, profile_id, directories, command_set_ids, revision)` | Split per D-11 (section 4.5). Entries whose profile no longer exists are KEEP-IN-PLACE: Python never shows them and prunes them on the next write. | decided (D-11) | Notes, directories and references equal for the fixture profile; the revision counter continues (an edit with the old revision succeeds, a stale one conflicts). | STOP |
| E32 | Saved password (named credential) | `users/user_N/credentials.json` `{version: 1, credentials, assignments, imports}` | `internal/vault`: `vault_credentials(id, user_id, name, username, version, updated_at, secret sealed)`, `vault_credential_assignments(resource_id, credential_id, fingerprint, generation)` | AES-256-GCM decrypt with HKDF context `[label, user_id, incarnation, record_id]` (`data_kinds` `named_credential`), seal with the keyring. Assignments and their fingerprints kept; `version` and `generation` kept so E15 bindings stay valid. Empty username kept as empty. | keep | Each password equals `values.named_credential` and the 4096-byte Unicode value; the assigned password signs in to the lab sshd; an assignment whose profile changed after migration is refused. | STOP on authentication failure of GCM |

### 3.7 Accounts lifecycle, logs, deployment (phases B2, B7, B1)

| # | Entity | Legacy source | Go target | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| E33 | Deleted account data | `DATA_DIR/deleted_users/user_<id>_<hex32>/` | none (stays in place); `internal/accounts`: `accounts_quarantine(former_user_id, path, found_at)` index only | Not imported, never associated with a live account (section 4.1). Listed in the report. Removal stays a manual, documented administrator procedure or `webssh legacy purge`. | keep (in place) | Quarantined files are not readable through any Go path of the user who now holds the same id; the index lists the directory. | KEEP-IN-PLACE |
| E34 | Audit and app logs | `DATA_DIR/logs/app.log`, `security_audit.log` and rotated `.N` files | none; files stay | Go appends to the same paths in the same JSON line format and rotates with the same naming (invariant I-10). Old lines remain readable for audit export. | keep | Audit export over a mixed file (Python lines, then Go lines) returns both in order. | Not part of the migration; an unreadable log does not stop it |
| E35 | Legacy single-user stores | `DATA_DIR/profiles.json`, `DATA_DIR/keys/`, `DATA_DIR/commands/` | none | The current Python release does not read `profiles.json` or files in `keys/`; `commands/system_commands.json` is a read-only fallback for built-in commands, not user data. Presence and size are reported. | drop (not read by Python today) | Report lists the paths. | KEEP-IN-PLACE |
| E36 | Access revocation queue | `DATA_DIR/.access-revocations/<user_id>` | none | Every session is discarded (D-02), which completes every pending request. Pending requests are counted in the report. | decided (D-02) | Report count; no Go session for those users. | DISCARD |
| E37 | LDAP revocation fences | `DATA_DIR/.ldap-revocation-fences/<user_id>` | `accounts_users.auth_generation` and `authldap_revalidation` (internal/auth/ldap) | A fence marks an LDAP revalidation or invalidation whose outcome was not recorded before the process stopped (`app/ldap_session.py:43-68`, `:313-355`); Python denies access until a directory check succeeds. The migration raises `auth_generation` by one for that user and sets `ldap_revalidation_required`, so access is only regained through a successful directory check. The fence file stays in place. | keep | Fixture with a fence: the user has no session, the generation is raised, the next LDAP sign-in runs the directory check (K7). | FLAG |
| E38 | Transfer temp files | `TRANSFER_TEMP_DIR` (default `DATA_DIR/tmp`) | none | Ignored, as Python sweeps them at start. | drop | – | DISCARD |
| E39 | Backup operations | `BACKUP_TEMP_DIR/instance-<hash>/operation-*`, `snapshot-*`, `.webssh-restore-*` | none; files stay | Ignored, except: an existing `restore-status.json` in state `preparing`, `in_progress` or `rollback_failed` is STOP (A10), and `rollback.zip` and `*-pre-rotation-*.zip` stay restorable through 5.6. | keep (in place) | – | STOP for unfinished restore, otherwise none |
| E40 | Profile export file | download only, not in `DATA_DIR` | none | Import of exported files stays a capability of `internal/hosts` (D-05 exception for user uploads). | keep (import) | The fixture export, once produced by Python, imports into Go with the same preview. | – |
| E41 | Deployment configuration | environment, `.env`, Compose files | `internal/config` (not stored) | Not migrated; read at every start with the Python parser semantics (D-14). Settings derived from configuration and data follow section 6. | keep | Configuration differential test against `config.py` (B1). | – |

### 3.8 Items not listed separately in the fixture inventory

| # | Entity | Legacy source | Go target (draft) | Conversion | Class | Verification | On failure |
|---|---|---|---|---|---|---|---|
| A01 | Persistent tmux session and its display name | `ssh_sessions` rows with `is_persistent=1` and a `tmux_session_name`: `session_id`, `user_id`, `host`, `port`, `username`, `key_id`, `auth_type`, `display_name`, `jump_host_id`, `socks_proxy_id`, `via_socks`, `profile_id`, `via_jump`, `reconnect_route_known`, `created_at`, `last_activity` | `internal/terminal`: `terminal_persistent_sessions(...)` with the same fields and the legacy row id (`ssh_sessions.id`), `connected=false`; written with `terminal.ImportPersistentAt`, read back with `terminal.ImportedPersistentTx` through the `legacy.PersistentSessionStore` adapter of the composition root | Names are copied byte for byte; they contain a random part (`{prefix}_{user}_{host}_{port}_{uuid4.hex[:8]}`, `app/ssh_manager.py:640-647`; gateway `{prefix}_wg_{sha256[:16]}_{uuid4.hex}`, `app/ssh_gateway.py:25-30`) and cannot be re-derived. New names follow the same scheme. Non-persistent rows are discarded. Not applied when restoring a Python backup: Python's restore empties `ssh_sessions` (`app/restore_sanitizer.py:9-21`). | decided (D-09) | After migration the reconnect offer lists each row; reattaching in the lab finds the running tmux session (K2); a renamed session keeps its name. | STOP |
| A02 | Application secret | `DATA_DIR/secret_key` or `SECRET_KEY` | none (read only) | Resolved like `entrypoint.sh:37-87` (rules in I-08). Before any write the migration decrypts one existing secret to prove the key matches; with no encrypted data this check is skipped and reported. | keep (invariant I-08) | A wrong `SECRET_KEY` stops with "SECRET_KEY does not match the stored data" before anything is written. | STOP |
| A03 | Login devices | cookie `<SESSION_COOKIE_NAME>_device` | none | Not imported; known devices lose their rate-limit exemption once. | decided (D-02) | – | DISCARD |
| A04 | Connection history namespace (browser storage) | derived: HMAC over user id, username and incarnation (`app/browser_identity.py`) | `accounts_users.history_generation` | Frozen input (section 4.2), so the browser keeps its recent connections, scrollback setting, favourites and topology layout (D-10). | decided (D-10) | Scope computed by Go equals `values.users[*].connection_history_scope` bit for bit, also for an account with `created_at` NULL. | STOP |
| A05 | Global notepad | `settings.json` key `notepad` | `internal/hostops`: `hostops_notes(user_id, profile_id NULL, body, revision)` (`hostops.ImportNote`) | Merged into the one notes model with "no host" context (D-11). The UI entry point stays. Empty notepad creates no row. | decided (D-11) | Notepad text equal; host notes and the notepad stay separate in the UI. | STOP |
| A06 | Workspace presets | `settings.json` key `workspace_presets` | `internal/hosts`: `hosts_workspace_presets` | Verbatim, references to profiles kept. | keep | Applying a preset opens the same layout and hosts. | STOP |
| A07 | Recovery check notice | `DATA_DIR/recovery-check.json` | `internal/settings`: `settings_app` key `recovery_check` | Copied; the notice after a portable restore stays visible until reviewed. A malformed or oversized file is treated as absent, as Python does (`app/customer_workflows.py:70-81`), and noted in the report. | keep | Notice shown for a fixture with the file; no notice and a report entry for a malformed one. | FLAG for a malformed file |
| A08 | Key deletion staging and store copies | `keys/<prefix><hex>-<name>`, `*.<uuid4hex>.bak`, `.<name>.*.tmp` | none | Staging reconciled as part of E23; `.bak` and `.tmp` files are ignored and kept in place. | keep (in place) | Interrupted deletion fixture resolves as Python does. | – |
| A09 | ADMIN_USERS | configuration | derived at run time | Not stored; Go marks listed accounts as configuration-managed, refuses demotion with an explanation, refuses registration of listed but missing names (K-11 variant B). The report lists listed names without account. | decided (K-11 B) | `cfg_admin` is admin and marked; demotion refused; registering a listed missing name refused. | – |
| A10 | Restore state | `BACKUP_TEMP_DIR/instance-<hash>/restore-status.json` | none (the Go restore keeps its own state in the journal `go/restore-status.json`, read before the database it replaces is opened; OP1-3) | `preparing`, `in_progress`, `rollback_failed`: STOP with the message to finish or roll back the restore with the Python release. `succeeded`, `failed`: ignored. | keep | Fixture with each state. | STOP |
| A11 | Host favourites, groups, sort order | profile fields `favorite`, `group`, `sort_order` | part of E19 | – | keep | Order and grouping equal. | – |
| A12 | Command and set favourites, scrollback, topology layout | browser `localStorage` | none (browser) | Preserved by A04. | decided (D-10) | – | – |
| A13 | Discovery and reachability permission | implicit: every signed-in user | `internal/settings`: `settings_app` keys `permission.hosts.discovery` and `permission.hosts.reachability` until the role model exists (B2/B3) | Always written for existing installations (section 6); `HOST_DISCOVERY_ENABLED` stays the ceiling. | decided (D-18, D-27, D-29) | Existing non-admin users can still start discovery and reachability checks. | – |

## 4. Special cases

### 4.1 Reused user ids and `deleted_users/`

SQLite reuses the highest freed `INTEGER PRIMARY KEY`. The golden data set
contains this case: the account with id 12 was deleted, its directory moved
to `deleted_users/user_12_<hex>/`, and a later account received id 12 again.

- Quarantined directories are never imported and never mapped to the account
  that now holds the id. Their encrypted keys use the derivation
  `"{SECRET_KEY}:{user_id}"`; mapping them would let the new account decrypt
  the old account's keys.
- Schedules (`automation_schedules` has no foreign key) and any other record
  whose incarnation differs from the current account's incarnation are
  KEEP-IN-PLACE and reported.
- The Go id sequence starts above the maximum of the legacy user ids and of
  every id parsed from `deleted_users/user_<id>_*` and from `users/user_<id>`
  directories without an account. Go never reuses an id (`fix`: the Python
  reuse is an accident of SQLite, not a rule).
- An id parsed from a directory name above 2^31-1 is not one Python handed
  out. It does not raise the floor (that would leave no ids for new
  accounts, or overflow); the directory stays in place, a `deleted_users/`
  entry gets no quarantine index entry (reason `implausible_account_id`),
  and the report names the path.

### 4.2 `users.created_at` in cryptographic contexts

The incarnation enters the named-credential HKDF context and AAD, the
automation vault AAD, the schedule grant account tuple and the browser
history namespace. The migration therefore:

- stores `incarnation` by the normative rule of section 2, computed once
  from the database text; a stored offset stays in the string;
- stores `history_generation`: the incarnation, or, when `created_at` is
  NULL, the legacy bcrypt hash string, as `browser_identity.py` does. A later
  Argon2id rehash (D-12) does not change it; only a real password change
  does, which matches Python, where a password change also starts a fresh
  history;
- never recomputes these values from a reformatted timestamp. New Go
  accounts get an incarnation generated by Go at creation.

An account with `created_at` NULL cannot use named credentials or the vault
in Python (`isoformat()` of NULL fails). The migration keeps the account,
FLAGs it and reports that saved passwords and vault import are unavailable
for it, as today.

### 4.3 Schedule approvals

A Python grant binds to `[incarnation, auth_generation, session_epoch]`, the
automation policy revision, the profile fingerprints, the SHA-256 of each
decrypted key, and the credential generations. After the migration the
legacy epoch and file identities no longer exist, so the grant is
re-expressed:

1. Validate the legacy grant with the legacy rules against the legacy state.
2. If valid, write a Go approval bound to: user id, incarnation,
   `auth_generation`, the Go revoke-all generation at migration time, the
   migrated policy revision, the same profile fingerprints, the same key
   digests (SHA-256 of the key plaintext is format-independent) and the
   migrated credential `version`/`generation` values.
3. If invalid, write the approval with `stale=true`; the next due run fails
   with `needs_review` as it would in Python.

Behaviour stays equal: a global sign-out (Go revoke-all), a changed target,
key or password, a lock or a policy change invalidates the approval.

### 4.4 Automation vault (D-06)

The vault is encrypted with the user's passphrase (scrypt) and an AAD that
contains the user id and incarnation. The migration stores the document
unchanged, checks only its structure, and reports every user with a pending
import. The import in Go is the same user-triggered action as in Python and
uses the frozen incarnation (4.2). Version 1 documents (no `generation`,
AAD prefix `v1`) stay importable. The write API and lock route are not
rebuilt.

### 4.5 Notes (D-11)

One notes model owned by `internal/hostops` (table `hostops_notes`):

- `settings.json` `notepad` becomes the note with `profile_id NULL`;
- `host_context.json` `hosts[profile_id].notes` becomes the note for that
  profile, with the context's `revision` as the note revision;
- directories and command set references stay host context in
  `internal/hostops` with the same `revision`.

Both UI entry points stay. The notes live with the host context in
`internal/hostops`, as the package map assigns them; `hostops.ImportNote`
takes over both kinds, and an empty notepad creates no row.

### 4.6 ADMIN_USERS and start-up admin rules

The stored `is_admin` flag is the source of truth, as in Python, where
`sync_admin_users` only promotes and never demotes. The migration applies,
in memory and in this order, what Python's next start would apply:
`ensure_initial_admin` (oldest local user if no local admin exists), then
`sync_admin_users` (promote listed accounts that are not locked and not LDAP-
or GitHub-managed). Any promotion this causes is reported. At run time Go
implements variant B (A09).

### 4.7 Locked accounts

`is_locked` and the incremented `auth_generation` are migrated unchanged.
Locked accounts are refused at sign-in with the Python wording; their data
is migrated like every other account, so unlocking restores full access.
Schedules of locked accounts are migrated; Python's `_account` refuses them
while locked, and Go does the same.

### 4.8 Keys Go cannot use

The current Python release refuses passphrase-protected keys and PKCS#8 at
upload, so none should exist. Older releases may have stored such material
or DSA keys. For any key whose plaintext Go cannot parse without a
passphrase, or whose algorithm Go does not support (DSA, plan section 9):

- the plaintext is sealed with the keyring and kept (`state='unsupported'`),
  so a later release or an explicit re-upload can use it;
- profiles and jump hosts that reference it are listed in the report;
- connecting with it fails with a clear message naming the key, which is
  the same visible result as in Python for passphrase-protected keys and the
  documented break for DSA.

PKCS#8 without passphrase is parsed by Go (`x/crypto/ssh`) and becomes
usable; this is an additive change and is reported as such.

The upload rules of Go that Python did not have (RSA below 1024 bits, more
than 128 bcrypt rounds for a protected OpenSSH key) apply to new uploads
only. A migrated key is never refused for them: it is imported, and the
report and the key list mark it as weak. An RSA key below 1024 bits is the
one exception that cannot stay usable, because the Go standard library
refuses to sign with it; it is imported with `state='unsupported'` like the
keys above and listed with that reason.

### 4.9 Secret rotation while legacy data exists

`webssh rotate-secret-key` (and its shim form) is refused while a legacy
source exists, that is, until `webssh legacy purge` has run (state S4). The
legacy data is encrypted with the current secret: rotating would make the
way back, `migrate --replace` and the restore of Python backups without
`data/secret_key` fail, and rewriting `DATA_DIR/secret_key` would change the
source digest. The message explains this and names the way: confirm that the
way back is no longer needed, run `webssh legacy purge`, then rotate. In S5
(legacy data gone without a purge entry), `webssh legacy purge` only records
the entry, after the backup of 5.9, and rotation is allowed afterwards. Go
therefore never writes `secret_key` while a legacy source exists. Rotation
keeps the keyring material and re-seals every record under the new
`SECRET_KEY`.

## 5. Sequence

### 5.1 State machine

Validity rule, without any marker outside the Go database: a Go database is
valid when it opens, passes `PRAGMA quick_check`, holds a completed
migration record, and the source digest stored in that record equals the
current digest of the legacy source. A Go-native installation (no legacy
source, no record) is valid when it opens and passes the check.

| State | Detected by | Action |
|---|---|---|
| S0 fresh | no legacy source, no Go database | normal start |
| S1 legacy only | legacy source present (`app.db` with a `users` table), no Go database, no marker `logs/.webssh-go/migrated` | run the migration (5.2) |
| S1a Go data missing | legacy source present, no Go database, marker present | STOP: the message says that Go data existed and is missing (for example removed by a Python restore or a move), names the marker's database identity and date, and names `webssh migrate --replace` to migrate again from the legacy data (D-07). Nothing is written |
| S2 migrated | Go database valid by the rule above | normal start |
| S3 legacy changed | Go database with migration record, stored digest differs from the current one | do not start; exit non-zero with the message naming `webssh migrate --replace` and explaining that Go changes since the migration would be replaced (D-07) |
| S4 legacy purged | migration record with a purge entry, no legacy source | normal start |
| S5 legacy missing | migration record without purge entry, legacy source gone | normal start with a warning at every start: the way back to Python no longer exists; `webssh legacy purge` records the purge entry (5.9) |
| S6 interrupted | staging directory `<Go directory>/.migration-*` exists | remove the staging directory (Go-owned), then evaluate again |
| S7 unknown | without a valid Go database: partial legacy source (for example `users/` without `app.db`) or unknown schema; or a Go database that does not open or fails `quick_check` | STOP without writing; a damaged Go database is never replaced automatically |
| S10 purge in progress | the Go database holds a "purge in progress" entry (5.9) | resume the purge from its file list without evaluating the legacy source (never S3), then complete it; `migrate --replace`, `migrate --dry-run` and any new migration are refused with a message naming the interrupted purge until it is complete |
| S9 key material | Go database with sealed records, keyring material missing in both places (`go/keyring-material`, `logs/.webssh-go/keyring-material`), not matching the key identifier, or two differing copies | STOP without writing (section 2.2) |

With a valid Go database, a partial legacy source (for example `app.db`
deleted by hand) is a change of the legacy source: S3, with the hint that
`webssh legacy purge` is the supported way to remove legacy data.

The Go database and its migration record appear together (5.2 step 10), so
a Go database with a legacy source but without a completed record cannot be
the result of an interrupted activation; it is S7.

A legacy path counts as present only when it holds a file or a link:
empty directories are no legacy data, because the entrypoint and Go create
`logs/` and `keys/` on every start. An empty `keys/` beside a new
installation is therefore S0, beside a Go-native database S2, and beside a
migrated database whose legacy data is gone S5.

In S9 with a legacy source Go also tries `SECRET_KEY` on the legacy data
(A02). When that fails too, the secret is wrong rather than the material
lost: Go stops with "SECRET_KEY does not match" and does not offer
`--replace`.

A missing Go directory with a legacy source present is S1a when the marker
exists and S1 only when it does not (marker removed with an emptied `logs/`,
or never written). The marker is a hint, not a validity criterion; validity
is still decided by the digest. Python never removes it (section 2.2).

### 5.2 First start with a legacy source

1. **Acquire the Go lock.** An exclusive lock on a Go-owned lock file
   prevents two Go processes from migrating at once.
2. **Resolve `SECRET_KEY`** by the rules of I-08 (A02).
3. **Detect the legacy schema.** There is no schema version in `app.db`
   (inventory 3.5). Supported sources, decided by the maintainer:
   everything the last Python release (3.3.x) can read, including its older
   database shapes, every older store document version and backups in
   format v1 and v2. Data older than that is not a supported direct
   upgrade. Rules:
   - STOP for domain structures 3.3.x does not know: an unknown column in a
     table that is migrated (possible user data of a newer release), a JSON
     store with a newer `schema_version`, a backup with
     `data_schema_version` above 2.
   - Tolerated and reported (FLAG): objects SQLite or Python create
     themselves (`sqlite_sequence`, `sqlite_stat1` to `sqlite_stat4`,
     autoindexes), additional indexes, unknown tables without relation to
     the migrated tables (KEEP-IN-PLACE), triggers and views. The legacy
     database is opened read-only with `PRAGMA trusted_schema=OFF` (as
     `app/restore_database.py:11`), so triggers never fire and functions in
     views or generated columns are not executed; Python 3.3.x runs
     normally with them. A restore of a Python backup stays strict on
     triggers and views, as Python's restore is (`app/restore_database.py:9-24`).
   - The detected shape is recorded in the report.
4. **Refuse to run beside Python.**
   - A hot journal or WAL (`app.db-journal`, `app.db-wal` non-empty): STOP
     with the message to start and stop the Python release once so it
     recovers its own transaction. Go never rolls back a legacy journal.
   - Probe the SQLite lock of `app.db` without modifying it (read-only open
     and a lock probe that writes nothing; covered by a test that checks
     bytes and timestamps before and after). A held lock: STOP.
   - Probe `BACKUP_TEMP_DIR/instance-<hash>/operation.lock` with a
     non-blocking `flock`. Held: STOP.
   - `restore-status.json` in an unfinished state: STOP (A10).
   - These probes only catch a Python process in the middle of a
     transaction or a backup: SQLAlchemy holds no SQLite lock while idle.
     The decisive guard is the second digest comparison in step 9: the
     source digest is computed here and again immediately before
     activation; any difference is STOP. After activation, 5.7 watches the
     legacy source.
5. **Check free space** on the file system of the Go directory: three
   times the size of `app.db` plus the size of the per-user stores, plus
   64 MiB. Not enough: STOP before writing anything, naming the numbers.
6. **No copy of the legacy data.** Decided by the maintainer: the
   migration writes no separate pre-migration backup. The legacy data is
   the backup, because Go provably never writes it: the database is opened
   with `mode=ro`, every file with read-only flags, the digest is compared
   before (step 4) and after (step 9) with STOP on any difference, and
   invariant I-01 is tested for every scenario of section 8. This replaces
   the earlier plan of a full backup before the migration. The step keeps
   its number so that an optional backup can be added again without
   renumbering; if it is, it is written in the Go backup format into
   the Go directory, never as a Python archive and never to a volatile
   location, and its absence of space or a volatile target is a warning, not
   STOP.
7. **Migrate into staging.** If `logs/.webssh-go/keyring-material` does not
   exist, create it (section 2.2) and fsync it and its directory; if it
   exists, use it. Create `<Go directory>/.migration-<random>/`
   (0700) and the new database inside it. Run the steps of section 3 in
   dependency order: accounts, factors and identities, settings, keys and
   credentials, hosts and connections, host trust, commands, host context
   and notes, automation, terminal. Each capability writes through its own
   store; all writes happen in transactions on the staging database.
   Entities kept in per-user stores are read for every account before
   anything is written, then read, written and verified one account at a
   time, so that the memory the migration needs depends on the largest
   account's stores and not on all of them together.
8. **Verify** every step (section 3, column Verification): counts per entity
   and per user, field equality, every secret decrypted with the legacy
   derivation and read back through the Go path, compared in memory only;
   password hash checks against the golden vectors in tests and a parse
   check in production; TOTP codes for a fixed time; WebAuthn parameters;
   host key fingerprints; profile fingerprints and key digests for
   schedules; `PRAGMA integrity_check` and foreign key check on the staging
   database.
9. **Re-check the source digest.** Equal to step 4: continue. Different:
   STOP ("the legacy data changed during the migration; stop the Python
   release").
10. **Activate atomically**, in this order:
    1. write the migration record (format version, Go release, source
       digest, per-file listing, schema shape, report) in the same
       transaction as the last step;
    2. switch the staging database to `journal_mode=DELETE`, close it, and
       check that no `-wal`, `-shm` or `-journal` file is left beside it;
    3. fsync the database file;
    4. if any `webssh.db-wal`, `-shm` or `-journal` exists at the target
       (left by an earlier database), move it into `replaced-<UTC>/`;
    5. rename the staging database to `<Go directory>/webssh.db`;
    6. fsync the Go directory;
    7. write the marker `logs/.webssh-go/migrated` (database identity,
       time) atomically and fsync it;
    8. remove the staging directory.
    A crash before 5 leaves the previous state (S1 with leftover staging,
    S6); a crash after 5 leaves a complete, valid database (S2); a marker
    missing after a crash between 5 and 7 is written at the next start.
    There is no intermediate state. Material created in this run but not yet
    used by any database is kept; the next migration uses it.
11. **Write the report** file `<Go directory>/migration-report-<UTC>.json`
    (0600) and log a summary. A failure to write the file after activation
    is logged; the record in the database remains authoritative.

On any STOP: close all handles, remove the staging directory, log the
failure with entity, user id and file or record id, exit non-zero. Go does
not start and nothing is changed; the Python release starts on the legacy
data.

### 5.3 Source digest (D-07)

The digest covers every regular file of the legacy source (section 2):
for each, in byte order of the relative POSIX path, the line
`path NUL size NUL sha256(content) LF`; the digest is SHA-256 over all
lines. Directories, modes and timestamps are not included. Runtime paths,
`logs/` (Go appends to the shared log files) and `go/` are excluded, so a
Python backup or restore that carries `go/` along never changes the digest
by itself. `secret_key` is included; Go never
writes it while a legacy source exists (4.9). To keep the start-up cost low,
the record stores `(path, size, mtime_ns, inode, sha256)` and the start time
of the scan; Go rehashes files whose stat values differ, and always treats
new or removed files as a change. Two exceptions keep the fast path safe
(decided by the maintainer): `app.db` is always hashed in full, because
SQLite rewrites it in place with the same size; and any file modified less
than 2 seconds before the recorded scan started is hashed again whatever
its stat values (the racy-clean rule of git), because file systems set
mtime with a coarse clock. The second digest of a migration (5.2 step 9)
hashes every file.

Symlinks anywhere in the legacy source are STOP during migration, because
Python's stores reject them as well and following them could read outside
`DATA_DIR`. After activation, a symlink counts as a change.

### 5.4 `webssh migrate --replace`

Run with the service stopped, explicitly by an administrator:

1. Acquire the Go lock; refuse while Go serves. Refuse without a complete
   legacy source and for a damaged Go database (S7).
   Before anything is set aside, run every check of 5.2 steps 2 to 5 and the
   reading of the legacy data: a running Python, digest and links, free
   space (which includes the copy of the current database), `SECRET_KEY`
   against the legacy data and every step's read. A refusal leaves the
   current database and its material where they are.
2. Close the current Go database after switching it to
   `journal_mode=DELETE`, so that no `-wal` or `-shm` file belongs to it.
3. Write a Go-format backup of it (`internal/backup`, D-03) into the Go
   directory and verify it. Until `internal/backup` exists (M1), a verified
   byte copy of the cleanly closed database in `go/replaced-<UTC>/` takes its
   place.
4. Run 5.2 steps 2 to 9 against the current legacy source.
5. Activate with 5.2 step 10: stale side files are moved into
   `replaced-<UTC>/`, and the rename replaces the old database atomically.
   A crash before the rename leaves the old database (still S3, the command
   can be run again); after it, the new one (S2). The new record names the
   backup of the replaced database.
6. Rewrite the marker with the new database identity; print the backup
   path and the report.

The command is the only way out of S3, S1a and, before the purge, S9; it
also runs when no current database exists. It is refused while a purge is
in progress (S10).

**`--replace` in S9.** Without matching material the current database cannot
be read, so step 3 cannot produce a verified Go backup. In S9 the command
therefore replaces steps 2 and 3 by: move the current database and its side
files byte for byte into `go/replaced-<UTC>/`, and move any material file
that does not match it into `logs/.webssh-go/replaced-<UTC>/` (never
overwrite or delete one; a copy that matches the database stays in place).
Material never goes into `go/`: `go/` is part of every Python export next to
`secret_key`, and the export would then hold decryptable Go secrets (I-22).
A crash after the database was moved and before the new one is renamed into
place leaves no Go database with the marker present: S1a, resolved by
running the command again; the moved database stays in `go/replaced-<UTC>/`,
and the S1a message names it. From then
on no Go database exists, and the command continues like a first migration
(5.2 steps 2 to 10), which creates new material in `logs/.webssh-go/`. Go
thus never creates material while a Go database exists. The report names the
moved database and states that it is readable only with its original
material, which the operator may still find in a volume backup. `webssh migrate --dry-run` runs 5.2
steps 2 to 9 into staging and prints the report without activating; it is
meant for operators before the upgrade and for K10.

### 5.5 Migration report

JSON, UTF-8, mode 0600, also stored in the migration record. No secret
values, no plaintexts, no password, token or code hashes.

```json
{
  "format": "webssh-migration-report",
  "version": 1,
  "go_release": "v3.4.0",
  "started_at": "…Z",
  "finished_at": "…Z",
  "result": "completed | failed | dry-run",
  "source": {
    "data_dir": "/app/data",
    "digest": "sha256:…",
    "schema_shape": "python-3.x additive set …",
    "store_versions": {"profiles": [3], "settings": [2]},
    "secret_key_source": "file | environment"
  },
  "legacy_untouched": {"digest_before": "sha256:…", "digest_after": "sha256:…", "equal": true},
  "entities": [
    {"entity": "ssh_private_key", "read": 10, "migrated": 10,
     "flagged": [{"user_id": 1, "id": "…", "reason": "plaintext_sealed"}],
     "kept_in_place": [], "discarded": 0}
  ],
  "materialised_settings": [
    {"setting": "permission.hosts.discovery", "value": "granted to role user",
     "rule": "D-01/D-18/D-29", "evidence": "HOST_DISCOVERY_ENABLED effective"}
  ],
  "discarded_runtime_state": {
    "browser_sessions": {"users": 3, "rows": 4},
    "step_up_grants": 0,
    "unfinished_totp_enrolments": [{"user_id": 6}],
    "open_factor_bootstrap_codes": [{"user_id": 11, "username": "…", "action": "…"}],
    "access_revocation_requests": 0,
    "ldap_revocation_fences": 0
  },
  "pending_user_actions": [
    {"user_id": 3, "action": "import_legacy_automation_vault"}
  ],
  "kept_in_place": [
    {"path": "deleted_users/user_12_…", "reason": "deleted_account"}
  ],
  "warnings": [
    {"code": "admin_users_missing_account", "username": "…"},
    {"code": "plaintext_keys_remain_in_legacy_data", "count": 1,
     "recommendation": "webssh legacy purge"}
  ],
  "error": null
}
```

`error`, when set, holds `{entity, user_id, record_id, code, message}`. The
admin area shows the report once after the upgrade, with the materialised
settings, discarded bootstrap codes and pending vault imports first.

### 5.6 Restore of Python backups (D-03, D-30)

`internal/backup` recognises a Python archive by its manifest
(`format_version` 1 or 2, `producer` "webssh" for v2) and hands it to
`internal/migrate/legacy` through the restore interface (package map,
"Python backups"). Applies to downloaded exports, CLI backups, `rollback.zip`
and `*-pre-rotation-*.zip`.

1. Validate with exactly the reading rules of inventory 4.6 (members,
   manifest keys, sorted unique paths, sizes, hashes, compression ratio,
   no encryption bit, no symlink members, `app.db` present, no SQLite side
   files, `quick_check`, no triggers or views, `trusted_schema=OFF`).
   Non-canonical paths are normalised as Python does (D-30, tolerant for
   Python backups); Go archives stay strict.
2. Unpack into a private staging directory (0700) under the backup temp
   root, never into the live `DATA_DIR`.
3. Apply Python's restore semantics in memory: without
   `--recovery-snapshot`, ignore `keys/`, `credentials.json*`,
   `automation-vault.json*` and `deleted_users/` even if present; drop the
   runtime paths; increment `auth_generation` for every account (Python
   invalidates schedule approvals this way, and its documentation tells users
   to review and re-enable schedules after a restore); set the recovery check
   notice for exports.
4. The legacy decryption key follows Python: when `SECRET_KEY` is set in
   the environment, that key (Python restores the file, but the environment
   wins at the next start); otherwise the archive's `data/secret_key`;
   otherwise the active key. Secrets are re-sealed with the keyring of the
   active `SECRET_KEY`. A key that cannot decrypt a secret stops the restore
   before anything is activated (D-08). Persistent tmux sessions (A01) are
   not restored, because Python's restore empties `ssh_sessions`.
5. Run 5.2 steps 7 and 8 into a staging database, then activate through
   `internal/backup` with its own pre-restore Go backup and maintenance
   handling. A build that leaves an entity pending refuses the restore of
   an archive holding records of it (`restore_incomplete`): unlike a
   migration, a restore keeps no legacy data in place, so the records
   would be lost.
6. The live legacy source is not touched, so the migration record's digest
   stays valid; the restore is recorded separately.
7. Members under `data/go/` (a Python backup taken after a way back
   carries the Go directory along) are never restored, never opened and
   never executed; they are counted in the restore report. The restore
   report is the migration report of the archive; the activation keeps it
   as `<Go directory>/restore-report-<UTC>.json` (0600). Members under
   `data/logs/` are ignored as Python ignores them
   (`app/backup_manager.py:923-932`). A Python archive therefore cannot
   inject or roll back Go data through a Go restore.

Visible difference to Python, declared: without an environment secret,
Python makes the archive's secret the active key. Go keeps the active key
and re-seals, so a restore never changes `DATA_DIR/secret_key` and never
breaks the legacy data that the way back depends on.

### 5.7 Python beside Go after activation

The digest comparison of 5.2 covers the time until activation. A Python
container that keeps running on the same volume (a second Compose project,
a forgotten Unraid container) would let users write into both systems. Go
therefore re-checks the legacy source with the stat fast path of 5.3 every
60 seconds while it runs. On a change it:

- reports not ready on `/ready`,
- refuses new sign-ins and state-changing requests with a maintenance
  message; running terminal sessions continue,
- shows administrators the cause and writes an audit event,
- names the two ways out: stop the Python process and restart Go (S3 then
  requires `webssh migrate --replace`), or return to Python.

The upgrade documentation says to stop and remove the Python container
before starting Go.

### 5.8 Go data after a way back

With the behaviour of section 2.1, the validity rule of 5.1 covers every
case without a marker outside the Go database:

| After the way back | Result at the next Go start |
|---|---|
| Python ran, legacy data changed | S3: stop, `webssh migrate --replace` |
| Python restore from an archive without `go/` | `go/` removed, marker kept in `logs/`: S1a, STOP with `webssh migrate --replace` |
| Python restore from an archive with `go/` taken after the way back | legacy data and Go database come from the same moment; recorded digest equal: S2; otherwise S3 |
| Host-level restore of a matching pair | S2 |
| `go/` damaged (does not open, fails `quick_check`) | S7: stop, never replaced automatically |
| Volume restore with `go/` but without `logs/.webssh-go/` | S9: stop with the ways out of section 2.2 |
| Python export restored on another host | `go/` restored, material absent: S9 there |

Crash order is unchanged by the location: activation and `--replace` end
in the old or the new database (5.2 step 10, 5.4), and staging lives inside
`go/`, so a Python backup taken after a crash may contain a staging
directory, which Go removes as S6.

### 5.9 `webssh legacy purge`

Allowed only in S2, S5 or to finish S10. Before it removes anything, it writes a Go backup
(D-03) that includes `SECRET_KEY` and the keyring material, to the path
given with `--backup-to`, or by default next to `DATA_DIR` when its parent
is writable, otherwise `BACKUP_TEMP_DIR`; never into `go/`. It verifies the
backup by reading it back (manifest, hashes, database integrity, one sealed
record decrypted), prints its path, and aborts without removing anything if
any step fails. Only an explicit `--skip-backup` skips this.

The backup file is created with mode 0600 and is not encrypted, like the
backups of the Python release: it holds the database, `SECRET_KEY` and the
keyring material in plain form, so whoever can read it can read every
sealed secret. Keep it off the host, or at least out of any shared or
world-readable directory.

The purge is refused while the migration record lists a pending entity
with a count above zero (KEEP-IN-PLACE for a later release): removing it
would lose it. A pending entity with count 0 does not block. Every path of
the report's `kept_in_place` whose files the purge removes (directories of
accounts that no longer exist, `deleted_users/`, key files not listed in
`keys.json`, legacy single-user stores) is listed with its reason and file
count before the confirmation, and its files go into the verified backup
as `data/<path>`; `--skip-backup` is refused while there are any, because
Go has no copy of them. `secret_key` is never removed: it holds
`SECRET_KEY` for Go as well (I-08), and the backup carries a copy. Then:

1. write a "purge in progress" entry with the list of legacy files to remove
   (taken from the migration record; never `secret_key`, `logs/`, `go/` or files not in
   the record) and the backup path, in one committed and synced transaction
   (state S10);
2. remove the listed files one by one; a file that is already gone counts as
   removed; fsync each affected directory;
3. in one transaction, record the purge entry with the backup path and
   delete the in-progress entry; the state becomes S4.

A crash during step 2 leaves S10. At the next start Go resumes the removal
from the stored list instead of evaluating the partly removed legacy source,
so it never offers `--replace` on a partial legacy state. While S10 lasts,
`--replace`, `--dry-run` and every new migration are refused. The command
tells the operator to keep the backup off the host.

It then moves the keyring material into `go/`, in this order:

1. copy `logs/.webssh-go/keyring-material` to `go/.keyring-material.tmp`
   (mode 0600), fsync it;
2. read the copy back and check that it is byte-identical and yields the key
   identifier stored in the database;
3. rename it to `go/keyring-material`, fsync `go/`;
4. record "material in `go/`" in the database;
5. remove `logs/.webssh-go/keyring-material` and the marker, and fsync
   `logs/.webssh-go/`. Material that `--replace` set aside in
   `logs/.webssh-go/replaced-<UTC>/` is not removed: each such directory is
   moved byte for byte into `go/replaced-<UTC>/` beside the database it
   belongs to (allowed now, because no Python export exists any more),
   with the copy, read-back and fsync of steps 1 to 3. Only when
   `logs/.webssh-go/` is then empty is it removed and `logs/` synced; the
   purge never removes it with its contents.

At start, Go resolves the material as follows: a leftover
`go/.keyring-material.tmp` is removed; if both copies exist and are
identical, the copy under `logs/` is removed (completing step 5); if they
differ, S9; if only one exists, it is used when it matches the key
identifier. If the purge entry exists and the material is only under
`logs/`, the move (steps 1 to 5) is carried out at start, so after a purge
the material always ends up in `go/`. A crash at any point therefore leaves at least one verified
copy, and Go never deletes the only copy.

## 6. Settings derived from behaviour (D-01)

For an existing installation the migration writes the previous effective
behaviour as explicit Go settings and lists each in the report
(`materialised_settings`). New installations get the secure Go defaults.

The derived settings live in `internal/settings`, table `settings_app`,
with `source = 'materialised'` and the rule in `rule`; no row means the
secure Go default of a new installation. The migration framework writes
them through `settings.MaterialisePolicies` in the migration transaction,
after every step, and copies the returned list into the report; it keeps
no copy of its own.

| Setting | Written when | Value | Decision |
|---|---|---|---|
| `permission.hosts.discovery` | always for an existing installation; `HOST_DISCOVERY_ENABLED` stays the ceiling, so a later switch-on behaves as in Python | `{"user":true}` | D-18, D-29 |
| `permission.hosts.reachability` | always (every user could run the port check) | `{"user":true}`; the SSH banner requirement of D-27 applies and is listed as a visible change | D-27 |
| `ssh.legacy_algorithms` | always (paramiko offered ssh-rsa, SHA-1 key exchange and CBC ciphers to every host) | `true` | D-01, K2 |
| `origin.ignore_scheme` | only when `realtime.KeepLegacySchemeRule` holds for the configuration at migration time; it takes effect only while the rule still holds for the current configuration | `true` | D-01, D-20 (K6 A1) |
| `settings_user.confirm_session_close` | account with `settings_default_generation < 1` and no stored value | true | D-01 (preserves the Python default for old accounts) |
| `tailscale_ssh_restrict_tailnet_routes` | value stored in `app_settings.json` | copied (`settings.ImportApp`), not materialised | D-28 (when absent, Go enforces the restriction; stored profiles on `100.64.0.0/10` are listed as possibly affected) |
| `netpolicy.tailnet_follows_switch` | always for an existing installation (the Python release applied the tailnet rule only while `TAILSCALE_SSH_ENABLED` was true) | `true`: the rule keeps following the switch; while the tailnet interface exists and the switch is off the server warns the administrator at every start; new installations have the rule whenever this host is a tailnet node | D-01, D-28 |

The discovery and reachability rights stay settings until the role model
of B2/B3 exists; it then takes these values as its start values.

The network target policy needs no entry: per
[ADR 0010](../adr/0010-outbound-network-policy.md) its default is
unrestricted for new and existing installations alike, exactly as
`BLOCK_INTERNAL_SSH=false` today, and `BLOCK_INTERNAL_SSH=true` keeps its
documented meaning as the optional restriction. The migration records
nothing for it.

Configuration values that come from the environment (origins, proxies,
rate-limit storage) are not data and are handled by `internal/config`
(D-14, D-16, D-19, D-20).

## 7. Compatibility invariants

| # | Invariant | Source of truth | Test idea |
|---|---|---|---|
| I-01 | Legacy files unchanged by migration, failure, start, `--dry-run`, restore, `--replace`, run time | ADR 0007 | For every regular legacy file: content SHA-256, size, mode and `mtime_ns` before and after each scenario of section 8; for directories: existence and mode, except the 0700 mode the entrypoint also sets on `DATA_DIR`, `logs/` and `keys/`; atime is not checked |
| I-02 | WebAuthn RP ID, origin handling, user handle = ASCII decimal user id, credential id bytes | `config.py` WebAuthn block, `webauthn_credentials` | Golden assertion vectors verify after migration; discoverable sign-in resolves the user from the handle |
| I-03 | OIDC and GitHub callback URLs, stored `redirect_uri` | `app/oidc_routes.py`, `app/github_auth_service.py`, `github_auth_configuration` | Route table contains the paths; lab sign-in with Dex and the GitHub stub (K7) |
| I-04 | User ids and every stored entity id | `users.id`, per-user stores | Id sets equal per entity; tmux reconnect and schedule targets resolve |
| I-05 | Incarnation string and history namespace | `app/browser_identity.py`, `automation_store.incarnation`, SQLAlchemy 2.1.6 | Scope equal to `values.users[*].connection_history_scope`; the vectors of section 2 (zero microseconds, offset, date only, minutes only, `T` separator) and `created_at` NULL |
| I-06 | bcrypt verification semantics, 72-byte rule for bcrypt hashes | `app/models.py`, `app/auth.py` | Manifest passwords verify; 73-byte input fails on bcrypt; succeeds after a password change to Argon2id |
| I-07 | TOTP parameters and replay rule | `data_kinds` `totp_secret` | Manifest code at manifest time verifies; replay and earlier step rejected |
| I-08 | `SECRET_KEY` resolution including the generated `DATA_DIR/secret_key` | `entrypoint.sh:37-87`, `config.py:704-720` | Table test: environment value used unchanged; it counts as a placeholder when, lower-cased with all whitespace removed, it is empty or a known placeholder (`"change me"` too), and then the file wins; file content with every trailing LF removed and CR kept (`key\r\n` → `key\r`); empty file exports an empty key and start fails, no new key is generated; `/app/data/secret_key` beside a different `DATA_DIR`: start fails when the target is missing or differs byte for byte; `WEBSSH_SECRET_KEY_SOURCE` recorded |
| I-09 | Host trust: no new prompt for stored keys, revoked keys refused, hashed and port entries recognised | `app/host_key_store.py` | Lab connection to every fixture host key; `@revoked` refused |
| I-10 | Log paths and JSON line format | `app/audit_logger.py` | Go lines parse with the Python field set; mixed file exports correctly |
| I-11 | Stored tmux session names copied byte for byte; new names follow the same scheme (`TMUX_SESSION_PREFIX`, random part) | `app/ssh_manager.py:640-647`, `app/ssh_gateway.py:25-30` | Names byte-identical; new names match the scheme; reattach in the lab |
| I-12 | Python backups v1 and v2 restorable, export/snapshot distinction | inventory 4.6 | Restore of the three fixture archives plus a v1 archive; keys only with `--recovery-snapshot` |
| I-13 | Schedule semantics: cron, time zone, missed and overlap rules, invalidation triggers | `app/automation_schedule.py` | Next slot equal for each fixture schedule; mutation of target/key/password/policy invalidates |
| I-14 | Profile fingerprint and credential assignment binding | `automation_store.profile_fingerprint` | Recomputed fingerprints equal; changed profile refuses the assigned password |
| I-15 | ADMIN_USERS variant B and start-up admin rules | `app/auth.py` | Admin set equal; listed admin marked and not demotable |
| I-16 | Ports, volumes, UID/GID, Unraid paths, `/health`, `/ready`, hardened profile | `Dockerfile`, Compose including `docker-compose.hardened.yml`, `unraid/webssh.xml` | Container test in K9 starts on a migrated volume as 1000 and as 99:100 with a bind mount, and with `read_only`, tmpfs `/tmp` and dropped capabilities |
| I-17 | Python 3.3.x keeps working on `DATA_DIR` after a Go run, with `go/` present | `app/backup_manager.py`, `app/secret_rotation.py` | After a migration and Go use: start 3.3.x, `backup create`, `backup verify`, restore of an export and of a `--recovery-snapshot`, `rotate-secret-key`; all succeed |
| I-18 | The content of `go/` never breaks a Python backup or restore, and Go data carried in a Python archive never reaches Go through a Go restore | section 2.1, 5.6 step 7 | `go/` contains only regular files and directories after every scenario; a Python archive with `data/go/` restored by Go leaves the Go database unchanged apart from the restored legacy entities |
| I-22 | A Python export, online backup or snapshot made after a way back contains no decryptable Go secret | section 2.2 | Take each archive kind with 3.3.x after a Go run; no member under `logs/`; with only the archive's `secret_key`, no sealed record of the archived `go/webssh.db` decrypts |
| I-23 | Loss or mismatch of the keyring material never leads silently to unreadable or lost data | section 2.2, S9 | Remove or replace `keyring-material`: Go stops in S9 with the message, nothing is changed; restoring the file starts normally; `--replace` and the purge backup recover as described |
| I-24 | No Python 3.3.x path deletes Go data without Go noticing | 5.1 S1a, section 2.2 | Python export restore without `go/`: next start S1a; with the marker removed as well: S1 |
| I-26 | An interrupted `legacy purge` is always completed and never leads to a migration from a partial legacy source | 5.9, S10 | Crash injection after each single file removal: the next start is S10, resumes the removal and ends in S4; `--replace`, `--dry-run` and migration are refused while S10 lasts |
| I-27 | `--replace` in S9 creates no material while a Go database exists and never loses the old database | 5.4 | In S9: the old database is moved byte for byte into `go/replaced-<UTC>/` and any non-matching material into `logs/.webssh-go/replaced-<UTC>/`, never into `go/`; only then is new material created; with the original material restored, the moved database opens and decrypts; every refusal (wrong `SECRET_KEY`, no space, Python running, no legacy source) moves nothing |
| I-25 | The keyring material exists in at least one verified copy at every moment of the move after `legacy purge`, and after it only in `go/` | 5.9 | Crash injection after each step of the move: the next start resolves to exactly one copy in the right place and starts; differing copies give S9; a fresh installation never creates `logs/.webssh-go/` |
| I-19 | Go writes nothing outside the Go-owned paths of section 2 | section 2 | File listing diff of `DATA_DIR` and `BACKUP_TEMP_DIR` before and after every scenario, in addition to I-01 |
| I-20 | Secret rotation refused while legacy data exists | 4.9 | `rotate-secret-key` in S2, S3 and S5 is refused with the explanation; after `legacy purge` it runs; then restart, Python backup restore with `data/secret_key` works |
| I-21 | LDAP secret helper: `python /app/deployment/ldap_secret_cli.py set-password\|install-ca\|status\|remove`, file names `ldap_bind_password` and `ldap_ca.pem`, mount `/run/webssh-auth`, modes 0700/0600 | `docker-compose.ldap.yml`, inventory `config-cli-schema-data.md` 4.5, C-IDP-14 | The `ldap-tools` service of the unchanged `docker-compose.ldap.yml` runs against the Go image; files and modes equal. Decided: an argv shim like D-15 ([ADR 0011](../adr/0011-http-api-and-cli-surface.md)), no change to the Compose file |

## 8. Test plan for K10

All tests run against a fresh copy of `tests/golden/fixture/datadir.tar`
(unpacked with `filter='data'` semantics) and the manifest as oracle. Each
test asserts I-01 at the end.

### 8.1 Golden data set

- One test per entity row of section 3: counts, field equality, decrypted
  values against `values`, and the functional check of the Verification
  column.
- Sign-in for every fixture account with its manifest password; the locked
  account is refused; TOTP and passkey MFA complete with the manifest code
  and assertion; one recovery code works once.
- Lab runs (testlab, section 3a of the G0 plan): SSH with every migrated key
  type and format, through the jump host and the SOCKS proxy, with the
  migrated saved password; Samba share listing; the active schedule runs
  without re-approval; reattach of a persistent tmux session.
- Vault import with the manifest passphrase yields the manifest passwords.
- Restore of `export.zip`, `online.zip` and `online-recovery-snapshot.zip`
  into an empty Go installation and into a migrated one.
- Determinism: two migrations of the same source produce the same logical
  dump of the Go database (sealed values excluded, compared after
  unsealing) and the same report apart from timestamps and paths.
- Idempotence: a second start is S2 and changes nothing.

### 8.2 Boundary cases

Fixture extensions needed (the generator in `tests/golden/` covers them in a
follow-up): non-empty global notepad; persistent `ssh_sessions` rows with
display names; workspace presets and tour state; store files at schema 0 and
1 and `commands.json` in the object form; vault version 1; `created_at` NULL;
an interrupted key deletion; a schedule with a stale claim and one with an
incarnation of a deleted account; a host context for a deleted profile;
`recovery-check.json`; a `restore-status.json` per state; DSA and
passphrase-protected legacy key files; a Python backup with `data/go/` and one with `data/logs/` members; `SECRET_KEY` variants of I-08 (CRLF file, placeholder with spaces, empty file, conflicting legacy path); a Python backup with an outdated `data/secret_key` while the environment secret is set; `created_at` vectors of section 2; an LDAP revocation fence; `sqlite_stat1`, an extra index, an unknown table, a trigger and a view in `app.db`; a malformed `recovery-check.json`; an `@cert-authority` line;
a database created by an older Python release with missing additive columns;
`ADMIN_USERS` naming a missing account; records above current limits.

### 8.3 Negative tests

- **Manipulated legacy data:** one flipped bit per Fernet token (SSH key,
  TOTP, GitHub secret) and per GCM ciphertext and tag (named credential) is
  STOP naming entity, user and record; wrong `SECRET_KEY` is STOP before
  anything is written; a `keys.json` filename with `..` or `/`, a symlinked
  user directory or key file, a JSON store with an unknown future version,
  an unknown column in a migrated table, a malformed `session_epoch`, an
  invalid `known_hosts` line, duplicate credential ids, a passkey with an
  invalid COSE key: each STOP, naming user and file. Triggers, views,
  `sqlite_stat1`, extra indexes and unknown unrelated tables are reported,
  not STOP. A tampered
  vault ciphertext passes the structural check and fails at import exactly
  as in Python.
- **Manipulated Python backups:** every rejection rule of inventory 4.6
  (zip slip, duplicate members, size and hash mismatch, compression bomb,
  encryption bit, symlink member, SQLite side files, extra member, unsorted
  manifest); tolerant normalisation of non-canonical paths for Python
  archives only (D-30).
- **Aborted migration:** fault injection at every step boundary of 5.2
  (during each capability step, at each sub-step of step 10) and `kill -9`
  of the process; the next start ends in S1 or S2, never in a mixed state,
  and I-01 holds. The same for `--replace`: the result is the old database
  (S3) or the new one (S2).
- **Stale side files:** `--replace` and activation with a leftover
  `webssh.db-wal` and `-shm` of an earlier database; the new database opens
  clean and contains none of the old rows.
- **Full disk:** a size-limited file system for the Go directory; the space
  check refuses up front; with the check bypassed by a test hook, `ENOSPC`
  during staging writes leads to STOP and cleanup.
- **Python beside Go:** a helper process holding a SQLite lock, a held
  `operation.lock`, and a writer that modifies a user store during the
  migration; each STOP, the last one through the digest re-check. A writer
  after activation: within the check interval `/ready` fails and
  state-changing requests are refused (5.7).
- **Way back:** after a migration, run Python 3.3.x on the same
  `DATA_DIR`, change data, take a backup and restore it (I-17, I-18); each
  row of the table in 5.8 ends in the state it names; S3 is resolved by
  `webssh migrate --replace`, which writes the Go backup, migrates the new
  state and starts.
- **Rotation:** `rotate-secret-key` with legacy data present is refused
  (I-20); in S5 `legacy purge` records the entry and rotation then runs.
- **Keyring material:** missing, truncated and foreign material, and a
  volume restore without `logs/.webssh-go/`: S9, nothing written (I-23);
  a Python export after a way back does not decrypt (I-22).
- **Marker:** Python restore of an export without `go/`: S1a; marker removed
  too: S1 (I-24).
- **Interrupted purge:** crash after each file removal (I-26); a crash
  before the material move and after each of its steps (I-25).
- **`--replace` in S9:** I-27.
- **Purge:** `legacy purge` with an unwritable backup target aborts and
  removes nothing; with a valid target it writes and verifies the backup
  before removing legacy files; only `--skip-backup` skips it.
- **Read-only legacy files:** the migration succeeds when every legacy file
  and directory except `logs/` and `go/` is read-only.

### 8.4 Method

- Property-based tests generate legacy stores within Python's validators and
  check that migration plus read-back is lossless.
- Mutation testing on the verification code: a mutant that skips or weakens
  a check must make a test fail.
- A differential test runs the Python app on the fixture and the Go
  migration, and compares what the UI shows for each entity (lists,
  effective settings, schedule status).

## 9. Open points and residual risks

- The package map has no named owner for the notes table; 4.5 proposes
  `internal/hosts`.
- The file names inside the Go directory are working names until B1.
- The fixture extensions of 8.2 are generated (`tests/golden/legacy/`,
  `datadir-extended.tar`, the variants and the four boundary backups of
  the legacy manifest).
- Residual risk: a Python process beside Go is detected only by the
  periodic check of 5.7, so writes within one interval can reach both
  systems. The upgrade documentation tells operators to remove the Python
  container first.
- Residual risk, limited to the time before `legacy purge`: an operator
  who empties `logs/` including hidden directories hits S9; the ways out of
  section 2.2 apply, including `migrate --replace` from the legacy data that
  still exists. Nothing is lost silently. After the purge the material lives
  in `go/` and is part of every Go backup.
- Residual risk: a Python restore after a way back from an archive without
  `go/` removes the Go database file; Go stops in S1a and the data is only
  recoverable from a volume or Go backup. The documentation of the way back
  says so.
