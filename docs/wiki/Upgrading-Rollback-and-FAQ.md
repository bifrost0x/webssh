# Upgrading, Rollback and FAQ

Treat an upgrade as an application-image change against persistent state. Keep
the data volume intact unless a verified restore is explicitly required.

## Before upgrading

1. Read the release notes.
2. Create a native backup and download it to encrypted off-host storage.
3. Verify the archive.
4. Record the deployed image digest.
5. Keep the previous immutable image available.
6. Confirm free disk space and the container restart policy.
7. Record any Compose overlays and external secret files.

## Compose upgrade

```bash
docker compose pull webssh
docker compose up -d
docker compose ps
docker compose logs --tail=200 webssh
```

With production and LDAP overlays, use the same ordered file list for pull,
config inspection, and startup:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  -f docker-compose.production.yml \
  config

docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  -f docker-compose.production.yml \
  pull webssh

docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  -f docker-compose.production.yml \
  up -d
```

Use all Compose files from the same release or commit.

## Post-upgrade verification

- `/health` returns 200.
- `/ready` returns 200.
- Administrator and standard-user login work.
- Existing stored-key metadata is readable.
- A direct SSH terminal opens.
- Host-key trust behaves as expected.
- SFTP listing and a small transfer work.
- Optional identity providers work.
- Logs show no migration, maintenance, or permission error.

## Image-only rollback

If the new runtime fails but persistent data is intact, stop the candidate and
start the previously recorded immutable image against the same `/app/data`
volume. Do not restore or rewrite data merely to roll back the image.

After rollback, verify readiness, login, stored keys, terminal access, and SFTP.
If the newer application migrated data beyond the older version's supported
schema, image-only rollback may be blocked; consult release notes and the native
backup compatibility result before forcing any change.

## Restore rollback

Use restore only when persistent state is damaged or an intentional state
rollback is required. Restore is destructive and invalidates all browser
sessions. Prefer a backup produced by the same or an older compatible schema.
Backups from a newer schema are rejected by an older WebSSH release.

See [Backup, Restore and Secret Rotation](Backup-Restore-and-Secret-Rotation).

## Frequently asked questions

### Can I run multiple Gunicorn workers or replicas?

No. Live SSH transports, Socket.IO coordination, and quota state are
process-local. Use exactly one `gthread` worker. Increase threads only within
the documented bounds and preserve at least four HTTP threads.

### Does Redis enable multiple workers?

No. Redis can preserve rate-limit counters across restarts. It does not
externalize live SSH sessions or runtime coordination.

### Is WebSSH end-to-end encrypted?

No. HTTPS protects browser-to-WebSSH traffic and SSH protects
WebSSH-to-target traffic. The WebSSH process necessarily sees terminal and file
data between those links.

### Are SSH passwords stored?

Connection and jump-host passwords are not written to profiles, the database,
or audit logs. They are used during connection establishment and references are
dropped afterward. Python cannot guarantee secure zeroing of secret bytes from
process memory.

### Why did tmux fall back to a normal shell?

tmux must be installed and usable on the remote host. If unavailable, WebSSH
opens a regular shell.

### Why does `/ready` fail while `/health` succeeds?

`/health` proves only that the process can answer. `/ready` also checks runtime
admission, maintenance mode, SQLite, and writable durable storage.

### Can LDAP users use a local password as fallback?

No. LDAP linking makes the account exclusively directory-managed, removes its
dormant local password and alternative local factors, and prevents privilege
mapping. Keep a separate local break-glass administrator.

### Does disabling LDAP restore old passwords?

No. Disabling the overlay removes LDAP routes and invalidates linked sessions,
but linked accounts do not regain old local credentials. Unlinking a user while
LDAP is operational requires setting a new local password.

### Does a native backup include LDAP secrets?

LDAP identity mappings in the SQLite database are included. The separate bind
password and CA secret volume is intentionally excluded.

### Why was a changed SSH host key rejected?

WebSSH stores first-use trust persistently. A changed key can indicate a server
rebuild, DNS/IP reassignment, or interception. Verify the new fingerprint out of
band, remove the old trust record deliberately, and reconnect.

### Can I use a CDN for frontend libraries?

The supported frontend is offline-capable and serves pinned vendored assets
from `static/vendor/`. Runtime CDN dependencies conflict with that security and
integrity model.

### Where is persistent data stored?

Under `DATA_DIR`: `/app/data` in the container and `./data` by default for a
source checkout. See [Data Storage and Persistence](Data-Storage-and-Persistence).

### How do I report a vulnerability?

Do not open a public issue. Use the repository's private
[security-advisory form](https://github.com/bifrost0x/webssh/security/advisories/new)
or the contact listed in `SECURITY.md`.
