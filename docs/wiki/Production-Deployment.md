# Production Deployment

Use this profile for an Internet-facing or otherwise untrusted multi-user
deployment. WebSSH treats production settings as a validated security contract:
unsafe combinations stop startup instead of merely logging warnings.

## Architecture

A recommended deployment has these boundaries:

```text
Browser --HTTPS--> trusted reverse proxy --private HTTP--> WebSSH
                                                    |
                                                    +--SSH/SFTP--> targets
```

Only the trusted reverse proxy should reach WebSSH's backend port. Protect the
Docker host, data volume, logs, and backups as privileged infrastructure.

## Requirements

- Docker Compose 2.24.4 or newer. The production overlay uses `!override` to
  replace the homelab port binding.
- A public DNS name and trusted TLS certificate.
- A reverse proxy that supports WebSocket upgrade.
- A persistent `/app/data` volume.
- A recorded backup and rollback image before updates.

## Deploy with the production overlay

```bash
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.production.yml

export WEBSSH_ORIGIN=https://ssh.example.com

docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  config

docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  up -d
```

The overlay binds WebSSH to `127.0.0.1:5000` by default. A reverse proxy on the
same host can use that address. For a containerized proxy, remove public port
publishing and connect both services to a private Docker network.

## Create the administrator

Browser bootstrap and public registration are disabled in production. Create
or promote an administrator from the trusted host:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  exec webssh \
  /app/entrypoint.sh flask --app start:app create-admin --username admin
```

For non-interactive automation, use `--password-file` with a private regular,
non-symlink file mounted into the container. The command removes one trailing
newline and never prints the password.

## Enforced production settings

The supplied overlay configures:

```yaml
DEPLOYMENT_PROFILE: production
CORS_ORIGINS: ${WEBSSH_ORIGIN}
ALLOW_CORS_WILDCARD: "false"
SESSION_COOKIE_SECURE: "true"
REGISTRATION_ENABLED: "False"
BOOTSTRAP_REGISTRATION_ENABLED: "false"
BLOCK_INTERNAL_SSH: "true"
TRUSTED_PROXIES: ${TRUSTED_PROXIES:-1}
```

Production startup rejects:

- debug mode;
- wildcard or missing browser origins;
- insecure browser cookies;
- browser bootstrap or open registration;
- disabled internal-target blocking;
- an unspecified proxy trust boundary.

Set `TRUSTED_PROXIES=0` explicitly only when WebSSH accepts no proxy headers.
When the value is non-zero, a client that can bypass the proxy may spoof
forwarded information, so restrict the backend network path.

## Reverse proxy checklist

The proxy must:

- terminate HTTPS;
- preserve the public `Host` header;
- forward `X-Forwarded-Proto`;
- forward the client address through the expected number of trusted layers;
- support WebSocket `Upgrade` and `Connection` headers;
- avoid exposing the plain backend to clients.

See [Reverse Proxy and Subfolder Deployment](Reverse-Proxy-and-Subfolder-Deployment)
for nginx, Traefik, and Caddy examples.

## Identity options

Local accounts remain the recovery foundation.

- Keep at least one local administrator with tested recovery material.
- OIDC requires explicit stable `(issuer, subject)` linking; it never trusts
  email alone.
- LDAP/Active Directory requires explicit stable identity linking; linked users
  are non-admin and cannot fall back to local passwords or alternative factors.
- Passkeys require the exact public RP ID and HTTPS origin.

Enable optional identity only after the base local-admin deployment works.

## Target-network policy

Production enables `BLOCK_INTERNAL_SSH=true`, blocking loopback, link-local,
private, and reserved targets after DNS resolution. This reduces the risk that
untrusted users use WebSSH as an SSRF or internal network pivot.

If the real use case requires private targets, do not simply relax the flag on
a broadly accessible service. Restrict users and network access, isolate the
instance, and document the exception.

## Capacity contract

Keep exactly one Gunicorn worker. Defaults are:

- `GUNICORN_THREADS=64`
- `MAX_SOCKET_CONNECTIONS=48`
- `MAX_SOCKET_CONNECTIONS_PER_USER=8`
- at least four threads reserved for HTTP routes and streamed transfers.

The bounded runtime executor defaults to the required minimum derived from
cleanup loops, allowed SSH readers, and background jobs. Enabling LDAP adds one
permanent revalidation job to that minimum.

## Operational checks

After deployment:

```bash
curl -fsS https://ssh.example.com/health
curl -fsS https://ssh.example.com/ready
docker compose ps
docker compose logs --tail=200 webssh
```

Verify:

1. HTTPS redirects and certificate validation.
2. Secure cookies in the browser.
3. The registration page is unavailable.
4. Administrator login and recovery.
5. A direct SSH connection and host-key trust.
6. SFTP listing and a small transfer.
7. Graceful container restart and readiness recovery.

## Before every upgrade

- Create and download a verified backup.
- Record the deployed immutable image digest.
- Review release notes and persistent-data compatibility.
- Keep the previous image available.
- Confirm that the restart policy is `unless-stopped` or an equivalent managed
  restart policy.

## Related pages

- [Security Model and Hardening](Security-Model-and-Hardening)
- [Backup, Restore and Secret Rotation](Backup-Restore-and-Secret-Rotation)
- [Health Checks and Troubleshooting](Health-Checks-and-Troubleshooting)
