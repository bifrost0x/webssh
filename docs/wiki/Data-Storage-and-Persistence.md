# Data Storage and Persistence

All durable WebSSH state belongs under `DATA_DIR`. Mount that directory on persistent storage and back it up as one coordinated unit.

## Directory layout

Typical content includes:

```text
DATA_DIR/
|-- app.db
|-- secret_key
|-- logs/
|   `-- security_audit.log
|-- users/
|   `-- user_<id>/
|       |-- profiles.json
|       |-- commands.json
|       |-- command_sets.json
|       |-- jump_hosts.json
|       |-- settings.json
|       |-- notes.json
|       |-- keys.json
|       `-- known_hosts
`-- deleted_users/
```

Exact auxiliary files can evolve. Do not selectively copy only the database and assume the installation is recoverable.

## SQLite data

`app.db` stores relational security and runtime metadata, including:

- local users and administrator state;
- active/revoked socket session metadata;
- persistent SSH session metadata;
- Passkey credentials and challenges;
- recovery-code hashes;
- OIDC identities and one-use login state;
- LDAP identity links and authorization metadata.

SQLite is part of the one-process architecture. Do not run multiple independent WebSSH workers or containers against the same database and data directory.

## Per-user files

Profiles, commands, command sets, jump hosts, application settings, notes, encrypted SSH keys, and known-host trust are isolated below `users/user_<id>/`. Every application access must also enforce authenticated user ownership; path separation alone is not the authorization control.

## Atomic JSON updates

JSON-backed state follows a full load-modify-save cycle while holding the shared storage lock. Writes use an atomic temporary-file replacement and filesystem synchronization. Corrupt JSON is not silently replaced with an empty default because doing so could turn a recoverable incident into permanent data loss.

Do not edit these files while WebSSH is running. Use the UI or supported APIs, or stop every process before a controlled offline repair.

## Additive migrations

Persisted JSON schemas are migrated additively. Current schema version 2 covers profiles, command sets, jump hosts, keys, settings, and application settings. Before changing a file, migration creates a private backup and writes the upgraded representation atomically.

Database changes likewise preserve existing installations. Always take a verified native backup before upgrading across versions.

## Encrypted SSH keys

Private keys are encrypted with user-specific Fernet material derived from `SECRET_KEY:user_id` using PBKDF2-HMAC-SHA256 and 600,000 iterations. The key record, application secret, and user ID are therefore part of one recovery boundary.

Copying user files without `app.db` and the matching `SECRET_KEY` is not a valid migration. Replacing `SECRET_KEY` manually can make stored keys unreadable.

## Deleted accounts

User deletion first moves the user's directory to a quarantine area under `deleted_users`. If the database transaction fails, WebSSH attempts to restore the directory. Quarantine is an integrity mechanism, not an indefinite retention or backup strategy; apply an explicit policy to this sensitive residual data.

## Permissions

Run the container or process under a dedicated identity and restrict `DATA_DIR` to it. Secret files should be read-only wherever possible. Avoid network filesystems with weak locking or atomic-rename semantics unless their behavior has been tested with SQLite and WebSSH's write pattern.

## Backup rule

Use WebSSH's native backup workflow for a live instance. For an offline filesystem backup, stop every WebSSH process first and capture the complete directory consistently. See [Backup, Restore, and Secret Rotation](Backup-Restore-and-Secret-Rotation).
