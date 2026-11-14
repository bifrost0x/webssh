# Data Storage and Persistence

All durable WebSSH state belongs under `DATA_DIR`. Mount that directory on persistent storage and back it up as one coordinated unit.

Container deployments require an absolute `DATA_DIR`. The entrypoint derives
the logs, SSH-key storage, and generated `secret_key` from this single
canonical root and refuses ambiguous legacy/new secret files. External secret
manager values remain outside this filesystem contract.

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
|       |-- socks_proxies.json
|       |-- settings.json
|       |-- notes.json
|       |-- host_context.json
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

Profiles, commands, command sets, jump hosts, SOCKS5 proxies, application settings, notes, encrypted SSH keys, and known-host trust are isolated below `users/user_<id>/`. Every application access must also enforce authenticated user ownership; path separation alone is not the authorization control.

### SOCKS5 route metadata

`socks_proxies.json` contains a `schema_version` of `2` and a `socks_proxies`
array. Each record contains a UUID `id`, `name`, `host`, integer `port`,
`auth_type` (`none` or `password`), `username`, boolean `remote_dns`, and
`created_at`. Password authentication requires a username of 1–255 UTF-8 bytes;
without authentication the username is empty. IDs are unique. Malformed records,
duplicate IDs and unknown fields are rejected without overwriting the store.

Profiles contain only an optional `socks_proxy_id` reference. The server resolves
that reference from the owning account's live store before saving or connecting.
It cannot coexist with a jump-host route or Tailscale SSH. Proxy passwords are
not part of either JSON document: reusable passwords belong to the encrypted
`credentials.json` store, with a separate `socks:<id>` resource assignment.

Profile and route mutations share the `command-config:<user_id>` coordinator
before their store locks. All three connection files count toward
`CONNECTION_CONFIG_MAX_BYTES`; `CONNECTION_STORE_MAX_BYTES` bounds each file.
A missing proxy file represents an empty store, including after restoring an
older backup. A corrupt file is never treated as an empty one.

## Atomic JSON updates

JSON-backed state follows a full load-modify-save cycle while holding the shared storage lock. Writes use an atomic temporary-file replacement and filesystem synchronization. Corrupt JSON is not silently replaced with an empty default because doing so could turn a recoverable incident into permanent data loss.

Do not edit these files while WebSSH is running. Use the UI or supported APIs.
For an oversized profile, jump-host or SOCKS5-proxy store, stop every process and use
the `connection-store` Flask CLI so recovery remains inside the configured hard
byte and record ceilings; avoid hand-editing JSON.

For example, list bounded proxy summaries and delete one exact record with the
selector returned by that listing:

```bash
python -m flask --app start connection-store list \
  --username USER --kind socks-proxies --confirm-offline
python -m flask --app start connection-store delete \
  --username USER --kind socks-proxies --selector SELECTOR --confirm-offline
```

Recovery still refuses to delete a proxy referenced by saved hosts. It permits
shrinking an oversized store, never growing it, and enforces the separate hard
recovery ceilings before and after parsing. List again after each deletion.

## Additive migrations

Persisted JSON schemas are migrated additively. Profiles currently use schema version 3; command sets, jump hosts, SOCKS5 proxies, keys, settings, application settings, and SMB shares use version 2. Before changing a file, migration creates a private backup and writes the upgraded representation atomically. The profile v3 migration removes transient Tailscale launch-authorization state from disk; that state is derived from the live server policy for each response.

Database changes likewise preserve existing installations. Always take a verified native backup before upgrading across versions.

Saved SSH sessions add nullable `socks_proxy_id` and boolean `via_socks` columns.
The additive migration leaves existing rows without a proxy and sets
`via_socks=false`; it does not rewrite existing connection profiles. SOCKS proxy
JSON migrations from unversioned data through versions 1 and 2 only add or advance
the schema marker.

Releases without SOCKS5 support keep an unknown `socks_proxy_id` in profiles but
ignore it, so a downgraded instance connects those hosts directly. Saved
passwords stay unusable there because their route binding no longer matches, but
SSH keys and passwords entered at connect time would reach the target without
the proxy. Before downgrading, remove the SOCKS5 route from every host in the
updated application, or restore the complete pre-upgrade backup with its
matching secret into a separate directory.

### Workspace upgrade and rollback

The workspace update adds a nullable `profile_id` column to saved SSH sessions.
Existing sessions do not need a profile association. Per-host notes and shortcuts
use a separate `host_context.json` file; existing global notes remain in settings.
Server mutations remain disabled unless explicitly enabled by the operator.

Before upgrading, retain a verified backup and the matching application secret.
Test restoration into a separate data directory; never run two versions against
the same live directory.

Parameterized command sets require the updated application. Older versions
reject a command-set collection containing the new `argv` steps, including its
ordinary sets, rather than silently dropping unsupported entries. They do not
overwrite that collection. If these sets have been created, remove them through
the updated application's UI before downgrading, or restore the complete
pre-upgrade backup with its matching secret into a separate directory. Restoring
that backup also discards changes made since it was created; preserve a current
backup before choosing this route. Do not hand-edit the stored JSON.

## Encrypted SSH keys

Private keys are encrypted with user-specific Fernet material derived from `SECRET_KEY:user_id` using PBKDF2-HMAC-SHA256 and 600,000 iterations. The key record, application secret, and user ID are therefore part of one recovery boundary.

Copying user files without `app.db` and the matching `SECRET_KEY` is not a valid migration. Replacing `SECRET_KEY` manually can make stored keys unreadable.

## Deleted accounts

User deletion first moves the user's directory to a quarantine area under `deleted_users`. If the database transaction fails, WebSSH attempts to restore the directory. Quarantine is an integrity mechanism, not an indefinite retention or backup strategy; apply an explicit policy to this sensitive residual data.

## Permissions

Run the container or process under a dedicated identity and restrict `DATA_DIR` to it. Secret files should be read-only wherever possible. Avoid network filesystems with weak locking or atomic-rename semantics unless their behavior has been tested with SQLite and WebSSH's write pattern.

## Backup rule

Use WebSSH's native backup workflow for a live instance. For an offline filesystem backup, stop every WebSSH process first and capture the complete directory consistently. See [Backup, Restore, and Secret Rotation](Backup-Restore-and-Secret-Rotation).

Online restore has a second persistence boundary: its private rollback journal
and emergency archive must use a durable absolute `BACKUP_TEMP_DIR` outside
`DATA_DIR`, with `BACKUP_RECOVERY_DURABLE=true`. Do not place that directory on
ephemeral container storage.
