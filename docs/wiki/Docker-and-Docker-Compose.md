# Docker and Docker Compose

The official image is published at `ghcr.io/bifrost0x/webssh` for
`linux/amd64` and `linux/arm64`. It contains one program, `/app/webssh`, CA
certificates and time zone data; there is no shell and no Python. The container
runs as the non-root user 1000:1000 and starts `/app/webssh serve --bind
0.0.0.0:5000`. The program belongs to root and is read-only for that user;
WebSSH writes only to `/app/data`, `/app/recovery` and temporary directories.
Keep custom write paths such as `DATA_DIR` or `BACKUP_TEMP_DIR` on a mounted
volume.

Upgrading from 3.3 (the Python image)? Read [Upgrading to 3.4](Upgrading-to-3.4)
first and use the 3.4 Compose file: the 3.3 file calls Python in its health
check.

## Commands in the container

Administrative tasks are commands of the program:

```bash
docker compose exec webssh /app/webssh help
docker compose exec -it webssh /app/webssh create-admin --username admin
docker compose exec webssh /app/webssh version
```

Commands that need the server stopped (`backup create|restore`,
`rotate-secret-key`, `migrate`, `legacy purge`) run in a one-off container with
the same volumes:

```bash
docker compose stop webssh
docker compose run --rm webssh backup create --confirm-offline
docker compose up -d
```

`docker compose exec webssh sh` does not work, and a Compose `command:` or
`entrypoint:` that starts a shell, `gunicorn` or `python` exits with an error.
The 3.3 forms `/app/entrypoint.sh flask --app start:app <command>` and
`python /app/deployment/ldap_secret_cli.py <command>` still work and print the
new form; they are removed in the next major release.

On Unraid, use the template described in [Install on Unraid](Install-on-Unraid).

## Persistent volume

Mount `/app/data` persistently:

```yaml
services:
  webssh:
    image: ghcr.io/bifrost0x/webssh:latest
    volumes:
      - webssh_data:/app/data

volumes:
  webssh_data:
```

Without this volume, users, profiles, keys, host trust, settings, backups, and
the auto-generated application secret disappear with the container.

The repository Compose file also mounts `webssh_recovery` at `/app/recovery`.
This separate durable volume stores online-restore rollback state and must not
be nested below or shared with `/app/data`.

## Base homelab deployment

```bash
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml
docker compose up -d
```

The base file publishes `5000:5000`, sets `DEPLOYMENT_PROFILE=homelab`, allows
wildcard CORS, uses HTTP-compatible cookies, enables tmux integration, and
persists `/app/data`.

Edit the Compose file to use a specific origin whenever possible:

```yaml
environment:
  - CORS_ORIGINS=http://192.0.2.10:5000
  - ALLOW_CORS_WILDCARD=false
```

## Optional SFTP permissions (chmod)

chmod is disabled by default. To enable it for all WebSSH users, remove the `#`
from `# - SFTP_CHMOD_ENABLED=true` in the base Compose file's `environment`
section. For the production overlay, the equivalent optional entry is
`# SFTP_CHMOD_ENABLED: "true"`.

```bash
docker compose up -d --force-recreate webssh
# With the production overlay, use the same files as the running deployment:
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --force-recreate webssh
```

Run the command matching your deployment. Restarting an existing container alone
does not apply a changed environment. Keep the data and recovery volumes mounted.
Comment out the setting again, or set false, and recreate to disable it.

Users then reload WebSSH, reconnect and open an SFTP directory. The SSH server
must advertise `lsetstat@openssh.com` version 1, and the remote account must be
allowed to change the selected file's permissions. SMB is not supported.
See the [file workspace manual](SFTP-File-Workspace-and-Transfers#unix-permissions)
for usage, troubleshooting and the remaining path, hardlink and ACL boundaries.

## Application secret

When `SECRET_KEY` is not supplied, WebSSH creates a strong secret and persists
it at `DATA_DIR/secret_key`. This makes ordinary container
recreation safe as long as the data volume is preserved.

If the container `DATA_DIR` is overridden, it must be absolute and that exact
directory must be mounted persistently. Logs, keys, and `secret_key` all move
together. If a legacy `/app/data/secret_key` exists, copy it to the new
`DATA_DIR` with mode `0600` before starting; startup refuses to silently create
a second encryption root. An explicitly supplied external `SECRET_KEY` still
takes precedence and is not copied into the data directory.

Provide an external secret only when the deployment has a deliberate secret
management policy. A changed or lost `SECRET_KEY` invalidates browser sessions
and prevents decryption of stored SSH keys. Stored secrets also depend on the
key material in `DATA_DIR/go/keyring-material` (or
`logs/.webssh-go/keyring-material` while 3.3 data exists); keep the whole volume.

## Lifecycle and stop grace

The base service uses `stop_grace_period: 40s`. WebSSH accepts an application
shutdown grace of 1 to 30 seconds and defaults to 5. During shutdown it stops
accepting new work, signals runtime jobs, and waits only for the bounded grace.

Keep Docker's stop grace longer than `RUNTIME_SHUTDOWN_GRACE_SECONDS` so the
application can cancel readers and transfers before Docker sends a forced kill.

## Healthcheck

The image runs `/app/webssh healthcheck` every 30 seconds. It asks `/ready` on
`127.0.0.1:$PORT` and then on port 5000, follows no redirects and ignores
`HTTP_PROXY`. The Compose file needs no `healthcheck:` block of its own; a block
copied from 3.3 that calls `python` keeps the container `unhealthy`. `/ready`
waits for:

- the application runtime to accept work;
- maintenance mode to be inactive;
- a successful SQLite query;
- a create/write/fsync/delete probe in `DATA_DIR`.

Inspect state with:

```bash
docker compose ps
docker inspect --format '{{json .State.Health}}' webssh
docker compose logs --tail=200 webssh
```

## Updating the image

Before updating, create and download a verified backup, and record the image
digest that is running now so you can roll back to it:

```bash
docker image inspect \
  "$(docker inspect webssh --format '{{.Image}}')" \
  --format '{{index .RepoDigests 0}}'
```

Then update:

```bash
docker compose pull webssh
docker compose up -d
docker compose ps
curl -fsS http://localhost:5000/ready
```

If an earlier image already created the `webssh_recovery` volume with a
root-owned `/app/recovery` and startup now reports `Permission denied`, stop the
service before repairing it. An empty recovery volume may be removed and
recreated by Compose. Never remove a non-empty recovery volume during or after
an interrupted restore; preserve its contents and have an administrator change
the volume root to the image's `appuser` UID/GID with mode `0700` instead.

Use an immutable version tag or digest for controlled production rollouts.

## Rate-limit storage

Rate-limit counters live in the WebSSH process and start empty after a restart.
Redis is no longer supported: `RATELIMIT_STORAGE_URL` is accepted, ignored and
named in a startup warning (`memory://` is accepted silently). Remove the Redis
service once the way back to 3.3 is no longer needed.

## Optional overlays

Compose files are applied from left to right. Later overlays win.

Production:

```bash
export WEBSSH_ORIGIN=https://ssh.example.com
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  up -d
```

LDAP plus production:

```bash
export WEBSSH_ORIGIN=https://ssh.example.com
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  -f docker-compose.production.yml \
  up -d
```

Always use base and overlay files from the same release or commit. The LDAP
overlay adds a read-only secret mount to WebSSH and a separate helper profile;
the production overlay follows it so its security settings are authoritative.
Optionally append `-f docker-compose.hardened.yml` after production to enable
additional container restrictions. Check custom writable paths, runtime UID/GID
and resource budgets before opting in; see
[container boundaries](https://github.com/bifrost0x/webssh/blob/main/docs/production-container.md).

## Inspect the effective configuration

Before changing a running deployment:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  config
```

For LDAP, include `docker-compose.ldap.yml` in the same order used for startup.
Review published ports, environment values, mounts, and the selected image.

## Backup boundary

The `webssh_data` volume is covered by the native backup format, including the
key material. The separate
LDAP bind-password and CA volume is intentionally not included. Treat both as
secrets and document how each is restored.

## Related pages

- [Production Deployment](Production-Deployment)
- [LDAP and Active Directory](LDAP-and-Active-Directory)
- [Backup, Restore and Secret Rotation](Backup-Restore-and-Secret-Rotation)
- [Upgrading, Rollback and FAQ](Upgrading-Rollback-and-FAQ)
