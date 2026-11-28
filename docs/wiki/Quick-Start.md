# Quick Start

This guide starts a persistent WebSSH instance for evaluation or homelab use.
For an Internet-facing installation, continue with
[Production Deployment](Production-Deployment) before accepting users.
On Unraid, use [Install on Unraid](Install-on-Unraid) instead.

## Prerequisites

- Docker Engine with the Compose plugin, or another Docker-compatible runtime.
- TCP port `5000` available on the host.
- At least one SSH server that the WebSSH container can reach.
- A modern browser.

## Option 1: Docker Compose

Download the homelab Compose file and start WebSSH:

```bash
mkdir webssh-deployment
cd webssh-deployment
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml
docker compose up -d
```

PowerShell:

```powershell
New-Item -ItemType Directory -Path webssh-deployment
Set-Location webssh-deployment
Invoke-WebRequest `
  https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml `
  -OutFile docker-compose.yml
docker compose up -d
```

Open `http://localhost:5000` or replace `localhost` with the host address.

## Option 2: Docker run

```bash
docker run -d \
  --name webssh \
  -p 5000:5000 \
  -e DEPLOYMENT_PROFILE=homelab \
  -e CORS_ORIGINS='*' \
  -e ALLOW_CORS_WILDCARD=true \
  -e TRUSTED_PROXIES=0 \
  -e SESSION_COOKIE_SECURE=false \
  -e TMUX_SESSION_PREFIX=webssh \
  -e BACKUP_TEMP_DIR=/app/recovery \
  -e BACKUP_RECOVERY_DURABLE=true \
  -v webssh_data:/app/data \
  -v webssh_recovery:/app/recovery \
  --restart unless-stopped \
  --stop-timeout 40 \
  ghcr.io/bifrost0x/webssh:latest
```

These are the settings of the homelab Compose file. Open
`http://localhost:5000` or replace `localhost` with the host address.
`SESSION_COOKIE_SECURE=false` lets browsers keep the session cookie over plain
HTTP; use it only on a trusted network, and switch to HTTPS before anyone else
can reach the port.

The named volumes are essential. `webssh_data` preserves users, settings, keys,
host trust, and the generated application secret across container updates;
`webssh_recovery` keeps the staging area for online backup restore.

## Create the first administrator

A fresh homelab instance with an empty database redirects to `/register`.
Exactly the first browser-created account becomes administrator. The one-time
bootstrap path closes atomically once that account exists. Open WebSSH by its
IP address or `localhost` for this step: through a DNS name the first account
is refused unless the name is listed in `ALLOWED_HOSTS`, so that a foreign
page that points its own name at your server cannot claim the instance.

Create the account immediately on a trusted network. Never expose an unclaimed
fresh instance to untrusted clients.

If you prefer an explicit CLI bootstrap, set `BOOTSTRAP_REGISTRATION_ENABLED=false`,
recreate the container (with Compose: `docker compose up -d`; with `docker run`:
remove it and run it again with the added `-e`), and run:

```bash
docker compose exec webssh \
  /app/webssh create-admin --username admin
```

The command prompts for the password without echoing it. Running it for an
existing username promotes that account without changing its password.

## Verify the instance

Check container state and readiness:

```bash
docker compose ps
curl -fsS http://localhost:5000/health
curl -fsS http://localhost:5000/ready
```

Expected responses:

```json
{"status":"ok"}
```

```json
{"status":"ready"}
```

Then sign in and perform a small functional check:

1. Open **Quick Connect**.
2. Enter the SSH hostname, port, remote username, and one authentication method.
3. Review and accept the host key only after checking the fingerprint when that
   assurance is available.
4. Open a terminal and run a harmless command such as `uname -a`.
5. Open the SFTP workspace and list the remote home directory.
6. Disconnect the session.

## Understand the default homelab settings

The base Compose file intentionally configures:

- `DEPLOYMENT_PROFILE=homelab`
- wildcard CORS for trusted-network convenience;
- non-secure browser cookies for HTTP;
- tmux support enabled, with persistent sessions selected explicitly per connection;
- one WebSSH process with bounded connection and session limits;
- persistent state in the `webssh_data` volume.

These defaults are convenient on a trusted LAN but are not a production
security profile.

## Common first-start problems

### The page does not load

```bash
docker compose ps
docker compose logs --tail=200 webssh
```

Confirm that another process is not already using port `5000` and that the
container healthcheck is not failing.

### `/ready` returns HTTP 503

The response lists only failed component categories. Typical causes are an
unwritable data volume, SQLite failure, active maintenance mode, or a runtime
that is shutting down. See [Health Checks and Troubleshooting](Health-Checks-and-Troubleshooting).

### SSH cannot reach a host

Verify connectivity from the container network, not only from the Docker host.
Check DNS resolution, firewall rules, the SSH port, and `BLOCK_INTERNAL_SSH`.

### tmux is not used

tmux must be installed on the remote SSH host. If it is unavailable, WebSSH
falls back to a regular shell.

## Next steps

- [Docker and Docker Compose](Docker-and-Docker-Compose)
- [Production Deployment](Production-Deployment)
- [Users and Account Management](Users-and-Account-Management)
- [SSH Connections and Host Keys](SSH-Connections-and-Host-Keys)
- [Backup, Restore and Secret Rotation](Backup-Restore-and-Secret-Rotation)
