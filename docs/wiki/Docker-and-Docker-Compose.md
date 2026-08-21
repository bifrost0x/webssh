# Docker and Docker Compose

The official image is published at `ghcr.io/bifrost0x/webssh`. The container
runs as a non-root user and starts Gunicorn with one `gthread` worker.

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

## Application secret

When `SECRET_KEY` is not supplied, the container entrypoint creates a strong
secret and persists it at `DATA_DIR/secret_key`. This makes ordinary container
recreation safe as long as the data volume is preserved.

Provide an external secret only when the deployment has a deliberate secret
management policy. A changed or lost `SECRET_KEY` invalidates browser sessions
and prevents decryption of stored SSH keys.

## Lifecycle and stop grace

The base service uses `stop_grace_period: 40s`. WebSSH accepts an application
shutdown grace of 1 to 30 seconds and defaults to 5. During shutdown it stops
accepting new work, signals runtime jobs, and waits only for the bounded grace.

Keep Docker's stop grace longer than `RUNTIME_SHUTDOWN_GRACE_SECONDS` so the
application can cancel readers and transfers before Docker sends a forced kill.

## Healthcheck

The image and Compose file probe `/ready` from inside the container. The default
healthcheck waits for:

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

Before updating, create and download a verified backup. Then:

```bash
docker compose pull webssh
docker compose up -d
docker compose ps
curl -fsS http://localhost:5000/ready
```

Record the currently deployed immutable image digest before replacing it:

```bash
docker image inspect \
  ghcr.io/bifrost0x/webssh:latest \
  --format '{{index .RepoDigests 0}}'
```

Use an immutable version tag or digest for controlled production rollouts.

## Optional Redis rate-limit storage

The default `memory://` backend resets rate counters when the process restarts.
To keep counters while Redis remains available, enable the private Redis service
from the supplied Compose comments and set:

```yaml
environment:
  - RATELIMIT_STORAGE_URL=redis://redis:6379/0
```

Do not publish the Redis port. If Redis becomes unavailable, WebSSH uses an
in-memory fallback and periodically retries the external backend.

Redis does not make multiple WebSSH workers safe. Live SSH transports and other
coordination remain process-local.

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
the production overlay must remain last so its security settings are
authoritative.

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

The `webssh_data` volume is covered by the native backup format. The separate
LDAP bind-password and CA volume is intentionally not included. Treat both as
secrets and document how each is restored.

## Related pages

- [Production Deployment](Production-Deployment)
- [LDAP and Active Directory](LDAP-and-Active-Directory)
- [Backup, Restore and Secret Rotation](Backup-Restore-and-Secret-Rotation)
- [Upgrading, Rollback and FAQ](Upgrading-Rollback-and-FAQ)
