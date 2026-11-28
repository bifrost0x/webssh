# Data Storage and Persistence

All durable WebSSH state belongs under `DATA_DIR`. Mount that directory on
persistent storage and back it up as one unit.

Container deployments require an absolute `DATA_DIR`. WebSSH derives the
logs, the key directory and the generated `secret_key` from this single
root and refuses ambiguous or conflicting secret files. A `SECRET_KEY` from
the environment or a secret manager stays outside this filesystem contract.

## Directory layout

```text
DATA_DIR/
|-- secret_key                    generated SECRET_KEY (when not set in the environment)
|-- go/
|   |-- webssh.db                 the database
|   |-- keyring-material          key material (new installations, after legacy purge)
|   |-- webssh.lock               one server per data directory
|   |-- migration-report-<UTC>.json
|   |-- restore-status.json
|   |-- replaced-<UTC>/           databases set aside by migrate --replace,
|   |                             and their keys once a restore replaced them
|   `-- deleted_users/<id>-<UTC>/ copies of deleted accounts
|-- logs/
|   |-- security_audit.log
|   `-- .webssh-go/               while 3.3 data exists: keyring-material, migrated
`-- keys/
```

An installation upgraded from 3.3 also holds the 3.3 data next to `go/`:
`app.db`, `app_settings.json`, `session_epoch`, `known_hosts`, `users/`,
`deleted_users/` and older single-user files. 3.4 reads it once, never
changes it, and keeps it for the [way back to 3.3](Upgrading-to-3.4#way-back-to-33)
until `webssh legacy purge` removes it.

WebSSH creates `DATA_DIR`, `logs/`, `keys/`, `go/` and `logs/.webssh-go/`
with mode 0700 and its files with mode 0600. `go/` must contain only
regular files and directories; a symbolic link there stops the start.

## The database

`go/webssh.db` is a SQLite database in WAL mode with `synchronous=FULL`. It
holds every account, factor, session, host, key, command, runbook,
schedule, saved password, setting and the state of background jobs. At a
clean stop WebSSH switches it to `journal_mode=DELETE`, so no `-wal` or
`-shm` file remains and a file copy of a stopped installation is complete.
At start WebSSH runs an integrity check; a damaged database stops the
start and is never replaced automatically.

SQLite is part of the one-process architecture. Do not run two WebSSH
servers or containers against the same data directory; the lock in
`go/webssh.lock` refuses the second one.

Do not edit the database while WebSSH is running. Use the interface or the
commands of `webssh`.

## Sealed secrets

SSH keys, saved passwords, TOTP secrets, provider secrets and the other
secrets are sealed with AES-256-GCM. The keys are derived with HKDF from
`SECRET_KEY` and 32 random bytes of key material, separately for every
purpose. The database stores the identifier of the key in use.

The database, `SECRET_KEY` and the key material form one recovery
boundary:

- Copying the database without `SECRET_KEY` and the material is not a
  valid migration.
- Replacing `SECRET_KEY` by hand makes every sealed secret unreadable; use
  `webssh rotate-secret-key`.
- While the 3.3 data exists, the material is
  `logs/.webssh-go/keyring-material`. Do not delete `logs/.webssh-go/`. After
  `legacy purge` the material moves to `go/keyring-material`.
- A missing or mismatched material file stops the start. The message names
  the file and the ways out; nothing is overwritten.

## Oversized connection stores

Profile, jump-host and SOCKS5-proxy collections above their normal limits
stay listable, but they cannot grow. For a collection too large to handle
in the interface, `webssh connection-store` lists non-secret summaries and
deletes exact records:

```bash
webssh connection-store list \
  --username USER --kind socks-proxies --confirm-offline
webssh connection-store delete \
  --username USER --kind socks-proxies --selector SELECTOR --confirm-offline
```

Use `--kind profiles`, `--kind jump-hosts` or `--kind socks-proxies`.
Recovery still refuses to delete a route referenced by saved hosts, never
grows a collection and enforces the separate recovery ceilings
(`CONNECTION_STORE_RECOVERY_MAX_*`). List again after each deletion; the
selector binds one record's position and content.

## Upgrades and migrations

The data of 3.3 and earlier 3.x releases is migrated once, at the first
start of 3.4, into the database. Every record is checked after it is
copied, the result is activated in one step, and the 3.3 files stay as
they were. Data from releases older than what 3.3 can read is not a
supported direct upgrade; upgrade to 3.3 first. See
[Upgrading to 3.4](Upgrading-to-3.4).

Later schema changes of the database are applied by WebSSH at start.
Always take a verified backup before upgrading across versions.

## Deleted accounts

Deleting an account writes a verified copy of its rows to
`go/deleted_users/<id>-<UTC>/`: one JSON Lines file per table and a
manifest with row counts and SHA-256 values, mode 0600. Sealed secrets stay
sealed in the copy. The copies are kept until an operator removes them;
they are an integrity mechanism, not a retention policy, so apply an
explicit policy to this sensitive data. Backups never include them.

Account IDs are never reused.

## Permissions

Run the container or process under a dedicated identity and restrict
`DATA_DIR` to it. A numeric ID shared with other containers, such as
`99:100` on Unraid, does not isolate the data from them; see
[Install on Unraid](Install-on-Unraid). Avoid network filesystems with weak
locking or rename semantics unless their behaviour has been tested with
SQLite.

## Backup rule

Use WebSSH's backup for a live instance. For an offline filesystem backup,
stop WebSSH and copy the complete directory, including the hidden
`logs/.webssh-go/`. See
[Backup, Restore, and Secret Rotation](Backup-Restore-and-Secret-Rotation).
