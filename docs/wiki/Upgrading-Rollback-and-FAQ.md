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

Use all Compose files from the same release or commit. The production overlay
preserves established resource limits, temporary mounts and custom runtime paths.
Additional restrictions are explicit in `docker-compose.hardened.yml`; append it
to every command only when that deployment has been configured and tested for it.
If already using the restrictions introduced with PR #223, include the new
hardened overlay to retain them when updating Compose files. Otherwise updating
the production file removes those previously implicit limits on recreation.
Existing image-only upgrades do not change container settings. Review the merged
configuration before recreating containers; keep data and recovery volumes intact.

## v2.6.0 compatibility

Keep a complete pre-upgrade data backup, matching secrets and the previous image digest.
Session profile metadata is migrated additively; private host context is included in
native backups. After using new parameterized `argv` command-set steps, older releases
cannot read the affected collection. Remove these sets through the updated UI before
an image-only downgrade, or restore the complete pre-upgrade data/secret backup into
an isolated installation. Do not assume that changing the image alone reverses new formats.
See [data storage](Data-Storage-and-Persistence.md) for the collection contract.

SFTP permissions and server mutations remain disabled by default. Uncomment
`SFTP_CHMOD_ENABLED=true` or `SERVER_OPERATIONS_ENABLED=true` under Compose
`environment` only when required, then recreate the service. Use all Compose files
from the same release. The flags grant no additional remote privileges.
See [SFTP permissions](SFTP-File-Workspace-and-Transfers.md) and
[server operations](Administration-Audit-and-Diagnostics.md) for prerequisites and limits.

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

Browser tabs opened before an upgrade may still run an incompatible Socket.IO
client. WebSSH rejects the mismatch before restoring or registering runtime
sessions. Clients that support the wire-revision check reload once and then
show a persistent manual reload action instead of retrying in a loop. A tab
from an older release cannot interpret the structured refusal and may show
only that it was disconnected; reload that tab manually. Clear an intervening
proxy or browser cache if a current tab still reports a mismatch.

## Image-only rollback

If the new runtime fails but persistent data is intact, stop the candidate and
start the previously recorded immutable image against the same `/app/data`
volume. Do not restore or rewrite data merely to roll back the image.

After rollback, verify readiness, login, stored keys, terminal access, and SFTP.
Tabs from a wire-revision-aware newer image detect that the older server omits
or reports a different revision and reload once to fetch that server's bundle.
Reload manually if a tab remains disconnected after the rollback.
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
