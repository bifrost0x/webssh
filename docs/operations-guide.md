# Operations guide

This guide covers running the Go server of WebSSH 3.4: the image and its
data, a new installation, the upgrade from 3.3, a trial on a copy of
existing data, backups, secret rotation, the way back and the checks that
show an installation works. What changes for users compared with 3.3 is
listed in [Upgrading to 3.4](wiki/Upgrading-to-3.4.md).

Supported are the container image for `linux/amd64` and `linux/arm64`
(Docker, Docker Compose, Unraid) and a [source build on
Linux](wiki/Installation-from-Source.md).

## The image

| | |
|---|---|
| Image | `ghcr.io/bifrost0x/webssh` |
| Program | `/app/webssh`, the entrypoint of the image |
| Default command | `serve --bind 0.0.0.0:5000` |
| Port in the container | 5000 |
| Volumes | `/app/data` (`DATA_DIR`), `/app/recovery` (`BACKUP_TEMP_DIR` in the supplied Compose files) |
| Runtime user | 1000:1000 (Unraid template: 99:100) |
| Health check | `/app/webssh healthcheck` (asks `/ready` on the local port) |
| Shell | none |

The image contains only the program, CA certificates and time zone data.
Every administrative task is a command of `/app/webssh`:

```bash
docker compose exec webssh /app/webssh help
docker compose exec webssh /app/webssh version
```

| Command | Purpose | Server |
|---|---|---|
| `serve` | run the server until SIGTERM or SIGINT | – |
| `healthcheck` | exit 0 when `/ready` answers on the local port | running |
| `create-admin --username NAME [--password-file PATH]` | create an administrator or promote an account | running or stopped |
| `reset-password --username NAME [--password-file PATH]` | set a new password for a local account and end its sign-ins | running or stopped |
| `issue-factor-bootstrap --username NAME --action passkey.enroll\|totp.enroll` | one-use code for a GitHub-only account's first factor | running or stopped |
| `ldap-secret [--secret-dir DIR] set-password\|install-ca\|status\|remove` | manage the LDAP secret volume | – |
| `connection-store list\|delete … --confirm-offline` | inspect or reduce an oversized connection store | running or stopped |
| `migrate --dry-run` | print the migration report without changing anything | stopped |
| `migrate --replace` | migrate the 3.3 data again, keeping the current database as a backup | stopped |
| `legacy purge [--backup-to DIR \| --skip-backup] [--yes]` | remove the 3.3 data after the migration | stopped |
| `backup create [--destination ARCHIVE] [--without-secret-key] --confirm-offline` | write a backup | stopped |
| `backup verify ARCHIVE` | check an archive | – |
| `backup restore ARCHIVE --confirm-offline [--recovery-snapshot]` | restore an archive | stopped |
| `rotate-secret-key --confirm-offline` | rotate the generated `SECRET_KEY` and reseal stored secrets | stopped |

"Stopped" means that no WebSSH server uses the data directory. Run those
commands in a one-off container with the same volumes and configuration:

```bash
docker compose stop webssh
docker compose run --rm webssh backup create --confirm-offline
docker compose up -d
```

`--password-file` must name a regular file; without it the command asks
twice on the terminal (`docker compose exec -it …`). The 3.3 forms
`/app/entrypoint.sh flask --app start:app <command>` and
`python /app/deployment/ldap_secret_cli.py <command>` still work and print
the new form.

## What is in `DATA_DIR`

| Path | Content | Notes |
|---|---|---|
| `secret_key` | generated `SECRET_KEY` (when not set in the environment) | never removed by WebSSH |
| `go/webssh.db` | the database | mode 0600, regular file |
| `go/keyring-material` | key material, together with `SECRET_KEY` | on new installations and after `legacy purge` |
| `logs/.webssh-go/keyring-material` | the same material while 3.3 data exists | **do not delete** |
| `logs/.webssh-go/migrated` | marker of the migration | |
| `go/migration-report-<UTC>.json` | migration reports | mode 0600 |
| `go/replaced-<UTC>/` | databases set aside by `migrate --replace` | |
| `go/deleted_users/<id>-<UTC>/` | verified copies of deleted accounts | removed only by an operator |
| `go/restore-status.json` | state of the last restore | |
| `go/webssh.lock` | lock against a second server on the same data | |
| `logs/security_audit.log` | audit log, same format as 3.3 | shared with 3.3 after a way back |
| `app.db`, `app_settings.json`, `users/`, `keys/`, … | the 3.3 data | read only; removed by `legacy purge` |

Without the keyring material, saved SSH keys, saved passwords and second
factors cannot be read. Back up the whole volume, including the hidden
directory below `logs/`, or use `backup create`, which includes it.

## New installation

```bash
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml
docker compose up -d
docker compose exec -it webssh /app/webssh create-admin --username admin
```

Open `http://<host>:5000` and sign in. On a new installation the first
account can also be created in the browser while
`BOOTSTRAP_REGISTRATION_ENABLED` allows it; creating it with
`create-admin` avoids the race. For HTTPS, passkeys and Internet exposure
follow [Production Deployment](wiki/Production-Deployment.md).

## Upgrade from 3.3

1. Make a 3.3 backup and copy it off the host; preferably also copy the
   data volume while WebSSH is stopped.
2. Stop and remove the 3.3 container: `docker compose down` (keeps the
   volumes).
3. Replace the Compose file with the one of 3.4, or remove any `command:`
   or `entrypoint:` that starts a shell, `gunicorn` or `python`. The
   `healthcheck:` blocks of the 3.3 Compose files keep working; health
   checks of your own that run other programs report `unhealthy`. Keep
   `SECRET_KEY` if you set it before.
4. Optional: `docker compose run --rm webssh migrate --dry-run` prints the
   report without writing to `DATA_DIR`. Its scratch database lives in
   `TMPDIR` (default `/tmp`) and needs three times the size of `app.db`
   plus 64 MiB there; with a small `/tmp` tmpfs set `TMPDIR` to a larger
   writable path outside `DATA_DIR`.
5. Start: `docker compose pull && docker compose up -d`.
6. Check the log and the report:

   ```bash
   docker compose logs webssh | grep -E 'data state|migration|kept in place'
   docker compose exec webssh /app/webssh version
   ```

   The report is `DATA_DIR/go/migration-report-<UTC>.json`. In it,
   `result` is `completed`, `pending` is empty and `legacy_untouched.equal`
   is `true`. `warnings` and `pending_actions` list what users or
   administrators still have to do.
7. Sign in. Every user signs in once after the update.

If the start stops, the log names the reason and the way out; the table in
[Upgrading to 3.4](wiki/Upgrading-to-3.4.md#when-the-first-start-stops)
explains each one.

On Unraid: stop the container, update it, and start it again. The template
keeps the paths below `/mnt/user/appdata/webssh`. Commands run from the
Unraid terminal with `docker exec -it webssh /app/webssh <command>`.

## Trial on a copy of existing data

To try 3.4 without touching a running 3.3 installation, run it on a copy of
the data volume, on its own port. The copy is throwaway: nothing done in
the trial goes back to 3.3.

1. Stop 3.3 for the copy; an open database or lock makes the migration
   stop.

   ```bash
   docker volume ls                       # find the 3.3 data volume
   docker stop webssh
   docker run --rm -v <3.3-data-volume>:/from:ro -v webssh_trial_data:/to \
     alpine cp -a /from/. /to/
   docker start webssh
   ```

   Any image with a shell does for the copy; `cp -a` keeps the owner
   1000:1000.
2. Start 3.4 on the copy, on port 5001:

   ```bash
   docker run -d --name webssh-trial -p 5001:5000 \
     -v webssh_trial_data:/app/data -v webssh_trial_recovery:/app/recovery \
     -e DEPLOYMENT_PROFILE=homelab -e CORS_ORIGINS='*' -e ALLOW_CORS_WILDCARD=true \
     -e SESSION_COOKIE_SECURE=false -e BACKUP_TEMP_DIR=/app/recovery \
     ghcr.io/bifrost0x/webssh:3.4.0
   docker logs webssh-trial | grep -E 'data state|migration'
   ```

   To test an unreleased revision, build the image from the repository
   instead and use `webssh:local` in place of the published tag:

   ```bash
   docker build --build-arg VCS_REF=$(git rev-parse HEAD) -t webssh:local .
   ```

3. If 3.3 received `SECRET_KEY` from the environment, pass the same value
   (`-e SECRET_KEY`, taken from your shell, never written to a file in the
   repository). Otherwise the trial stops with "SECRET_KEY does not match
   the stored data" before writing anything.
4. Open `http://<LAN-IP>:5001`.

Passkeys need HTTPS and the host name they were registered under. Over
`http://<LAN-IP>` they do not work, over `http://localhost` they do. For a
trial with passkeys, put the trial behind an HTTPS reverse proxy with the
same host name as the 3.3 installation and set `TRUSTED_PROXIES=1`,
`TRUSTED_PROXY_CIDRS` (the proxy's address) and `SESSION_COOKIE_SECURE=true`.

To take a newer copy, remove the trial (`docker rm -f webssh-trial`,
`docker volume rm webssh_trial_data webssh_trial_recovery`) and repeat
from step 1, or re-migrate the existing copy:

```bash
docker stop webssh-trial
docker run --rm -v webssh_trial_data:/app/data -v webssh_trial_recovery:/app/recovery \
  -e BACKUP_TEMP_DIR=/app/recovery ghcr.io/bifrost0x/webssh:3.4.0 migrate --replace
docker start webssh-trial
```

Never run `legacy purge` on a trial copy; it has no use there.

Under rootless Docker with the default RootlessKit port driver every client
appears with one internal address: all clients then share the per-address
sign-in limits, and the audit log shows that address.

## What to check after an upgrade or in a trial

Work through the areas you use. Each line names the expected result.

- **Sign-in:** password, TOTP, recovery code, passkey (HTTPS), LDAP, OIDC,
  GitHub as configured. Existing accounts keep their factors.
  Administrators of `ADMIN_USERS` stay administrators.
- **Administration:** account list, create, lock, unlock, MFA reset,
  delete (a copy appears in `go/deleted_users/`), feature switches,
  integration switches, audit export and retention, operations view,
  support report.
- **Hosts:** profiles, groups, jump hosts, SOCKS5 proxies, SSH keys
  (upload asks for a step-up), host notes, host context, presets, known
  hosts and global host keys, profile export and import.
- **Terminal:** password and key sign-in, jump hosts, SOCKS5 with and
  without login, host-key confirmation, keyboard-interactive one-time
  codes, reconnect after a page reload, persistent tmux sessions (detach,
  reattach), startup commands, command sets, Herdr session mode, SSH
  gateway, Tailscale SSH.
- **Files:** SFTP of a terminal session, Quick SFTP (asks about unknown
  host keys), SMB shares, upload, download, folder download as ZIP,
  server-to-server copy, editor with conflict detection, permissions.
- **Saved passwords:** create, assign to a host, jump host, SOCKS5 proxy and
  SMB share, connect with them, import of an old automation vault.
- **Automation:** runbooks, a run against a host, run history and export,
  schedules (approved ones run without a new approval; `stale` ones ask
  for review).
- **Overview and operations:** overview board, discovery and reachability
  (permissions), insights, server operations.
- **Backup:** online backup and download, `backup verify`, restore of a 3.4
  archive and of a 3.3 archive on a disposable instance.
- **Health:** `docker inspect --format '{{.State.Health.Status}}' webssh`
  shows `healthy`; `curl -fsS http://localhost:5000/ready` answers
  `{"status":"ready"}`.

For Tailscale SSH, a test on a real tailnet should cover a sign-in with the
shared identity, a refused account and remote user, a tailnet host reached
with ordinary SSH (refused on a new installation, allowed with the
migrated setting while the start warning is shown) and an ACL `check` rule.
The automated tests use a stand-in for tailscaled (a network namespace with
`tailscale0`, the node route in table 52 and an OpenSSH server), so
tailscaled itself, MagicDNS, exit nodes, subnet routes, IPv6 over the
tailnet and the `check` mode have not been verified.

## Backup and restore

Details are in [Backup, Restore, and Secret
Rotation](wiki/Backup-Restore-and-Secret-Rotation.md). In short:

- Online: **Settings Center → Backup & Restore** creates an archive for one
  download. Restore uploads an archive, asks twice and restarts WebSSH
  inside the running process.
- Offline:

  ```bash
  docker compose stop webssh
  docker compose run --rm webssh backup create --destination /app/recovery/webssh.tar --confirm-offline
  docker compose run --rm webssh backup verify /app/recovery/webssh.tar
  docker compose up -d
  ```

- Archives are tar files with a manifest and include `SECRET_KEY` and the
  keyring material unless `--without-secret-key` is given (then only the
  key is left out). They are not encrypted; store them encrypted and off
  the host.
- 3.3 backups restore through the migration. 3.4 backups do not restore on
  3.3.

## Secret rotation

`rotate-secret-key` replaces the generated `DATA_DIR/secret_key` and
reseals every stored secret. It refuses while `SECRET_KEY` comes from the
environment, while a server runs and while the 3.3 data still exists.

```bash
docker compose stop webssh
docker compose run --rm webssh rotate-secret-key --confirm-offline
docker compose up -d
```

It writes a recovery snapshot first and prints its path. All sign-ins end.

## Way back to 3.3 and removing the 3.3 data

Until `legacy purge` the way back is the 3.3 image on the same volumes;
changes made in 3.4 are not there. When 3.4 starts again after 3.3 has
changed the data, it stops and asks for `migrate --replace`. Once the way
back is no longer needed, remove the 3.3 data with `legacy purge`. Both are
described step by step in [Upgrading to
3.4](wiki/Upgrading-to-3.4.md#way-back-to-33).

## Limits worth knowing

- At most 10 SSH sessions at the same time, 5 per account
  (`QUOTA_SSH_SESSION_GLOBAL`, `QUOTA_SSH_SESSION_PER_USER`). Two accounts
  with five sessions lock everyone else out; raise the limits for more
  users.
- Live connections: 48 per server, 8 per account
  (`MAX_SOCKET_CONNECTIONS`, `MAX_SOCKET_CONNECTIONS_PER_USER`); every browser
  tab uses one.
- A detached terminal whose program keeps printing stays open until its
  owner signs out.
- `TRUSTED_PROXIES` above 0 without `TRUSTED_PROXY_CIDRS` trusts the
  forwarded headers of every client. Set both.
- Migrating a store close to the 64 MiB file limit needs about 1 GB of
  memory for a moment.
- The ciphers `aes192-cbc` and `aes256-cbc` and the MAC `hmac-md5` are not
  supported.

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Container `unhealthy`, log fine | a health check of your own that runs another program than the 3.3 Compose files did | use `/app/webssh healthcheck` or remove the `healthcheck:` block |
| Exit 2, "the image has no shell" | a `command:` or `entrypoint:` that starts `sh`, `gunicorn` or `python` | remove the override |
| Start stops, "SECRET_KEY does not match the stored data" | `SECRET_KEY` differs from the one 3.3 used | pass the same value |
| Start stops, "migrate --replace" named | 3.3 changed its data after the migration, or `go/` is missing | `migrate --replace` with the service stopped |
| Start stops, keyring material missing | `logs/.webssh-go/` or `go/keyring-material` lost | restore it from the volume backup, see the message |
| `/ready` 503, "maintenance" | restore, rotation or a changed 3.3 source | wait for the restore; stop the second 3.3 container and restart |
| Live connection fails behind a proxy | proxy does not forward `/ws` upgrades or `Origin` | see [Reverse Proxy and Subfolder Deployment](wiki/Reverse-Proxy-and-Subfolder-Deployment.md) |
| Warning about `TZ` | POSIX time zone rule | use an IANA name |
| Warning about an ignored variable | a 3.3-only variable such as `GUNICORN_THREADS` | remove it once the way back is no longer needed |

More checks: [Health Checks and Troubleshooting](wiki/Health-Checks-and-Troubleshooting.md).

## For maintainers: test commands

- Gateway, Tailscale and network policy unit and difference tests:
  `go test ./internal/ssh/gateway ./internal/ssh/tailscale ./internal/netpolicy`.
- Warpgate: `internal/ssh/gateway/testdata/warpgate-up.sh` starts a
  throwaway Warpgate on the lab network, then
  `WEBSSH_WARPGATE_DIR=… go test -tags warpgate -run Warpgate ./internal/ssh/gateway ./cmd/webssh`;
  `warpgate-down.sh` removes it.
- Lab tests: `go test -tags lab -run Lab ./cmd/... ./internal/...`.
- Network namespaces: `internal/netpolicy/testdata/netns-test.sh lab` and
  `… crafted`; they compare with the recorded route answers of the 3.3
  release (`testdata/python_routes.json`), and with
  `WEBSSH_PYTHON_ORACLE=live` also with that release itself, taken from a
  worktree named by `WEBSSH_PYTHON_ROOT` (see
  [Development and Testing](wiki/Development-and-Testing.md#difference-tests-against-33)).
- Migration report on a copy: `webssh migrate --dry-run` with `DATA_DIR`
  pointing at the copy.
