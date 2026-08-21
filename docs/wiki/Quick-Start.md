# Quick Start

This guide starts a persistent WebSSH instance for evaluation or homelab use.
For an Internet-facing installation, continue with
[Production Deployment](Production-Deployment) before accepting users.

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
  -e CORS_ORIGINS=http://localhost:5000 \
  -v webssh_data:/app/data \
  --restart unless-stopped \
  ghcr.io/bifrost0x/webssh:latest
```

The named volume is essential. It preserves users, settings, keys, host trust,
and the generated application secret across container updates.

## Create the first administrator

A fresh homelab instance with an empty database redirects to `/register`.
Exactly the first browser-created account becomes administrator. The one-time
bootstrap path closes atomically once that account exists.

Create the account immediately on a trusted network. Never expose an unclaimed
fresh instance to untrusted clients.

If you prefer an explicit CLI bootstrap, disable browser bootstrap and run:

```bash
docker compose exec webssh \
  /app/entrypoint.sh flask --app start:app create-admin --username admin
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
- tmux support enabled and selected by default;
- one Gunicorn worker with a bounded thread pool;
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
