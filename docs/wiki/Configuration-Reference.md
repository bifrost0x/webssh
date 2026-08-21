# Configuration Reference

WebSSH reads configuration from environment variables. A local `.env` file is loaded with `override=False`, so variables supplied by the operating system, container runtime, or secret manager take precedence.

Start from the repository's `.env.example`. The tables below describe the operational contract; check that file when upgrading because new options may be added.

## Core settings

| Variable | Purpose | Default or requirement |
|---|---|---|
| `SECRET_KEY` | Encrypts and signs security-sensitive state | Required for direct production starts. The container entrypoint can generate and persist it in the data volume. |
| `DATA_DIR` | SQLite database and per-user data root | `/app/data` in the container |
| `DEPLOYMENT_PROFILE` | Selects deployment safeguards | `homelab`; use `production` for Internet-facing deployments |
| `DEBUG` | Flask debug mode | `False`; never enable in production |
| `HOST` | Application bind address | `127.0.0.1` outside the container |
| `PORT` | Application listen port | `5000` |
| `APPLICATION_ROOT` | URL prefix for subfolder deployments | Empty/root |

Treat `SECRET_KEY` as long-lived installation state. Replacing it without the supported rotation workflow invalidates encrypted SSH keys and signed state. See [Backup, Restore, and Secret Rotation](Backup-Restore-and-Secret-Rotation).

## Browser origin, proxy, and cookies

| Variable | Purpose |
|---|---|
| `CORS_ORIGINS` | Comma-separated Socket.IO/browser origin allowlist |
| `ALLOW_CORS_WILDCARD` | Allows `*`; homelab-only and rejected as a production origin policy |
| `TRUSTED_PROXIES` | Number of trusted reverse-proxy layers; `0` means none |
| `SESSION_COOKIE_SECURE` | Sends the session cookie only over HTTPS |
| `SESSION_TIMEOUT` | Idle SSH session timeout in seconds; default `1800` |

The production profile requires explicit HTTPS origins, secure cookies, and explicit trusted proxies. Wildcard origins are not a production configuration. See [Reverse Proxy and Subfolder Deployment](Reverse-Proxy-and-Subfolder-Deployment).

## Registration and local authentication

| Variable | Purpose | Default |
|---|---|---|
| `REGISTRATION_ENABLED` | Allows public creation of additional local accounts | `False`; production rejects `True` |
| `BOOTSTRAP_REGISTRATION_ENABLED` | Allows exactly one first administrator to be created in a fresh homelab database | Homelab default; disabled and rejected by the production profile |
| `ADMIN_PANEL_ENABLED` | Can disable the administrator panel | Enabled |
| `ADMIN_USERS` | Comma-separated existing usernames promoted at startup | Empty |

Prefer `flask create-admin` for controlled deployments. Public registration is independent of LDAP and OIDC sign-in.

## SSH network policy

| Variable | Purpose |
|---|---|
| `BLOCK_INTERNAL_SSH` | Blocks SSH connections to loopback, private, link-local, and other protected targets according to the network policy |
| `PROXY_JUMP_REMOTE_DNS_ALLOWLIST` | Exact hostnames a trusted bastion may resolve remotely |

`BLOCK_INTERNAL_SSH=true` is appropriate for an Internet-facing gateway but can conflict with homelab use. Resolve and validate the exact target policy before enabling it. Host-key verification remains a separate control.

## Runtime capacity

| Variable | Default | Contract |
|---|---:|---|
| `GUNICORN_THREADS` | `64` | Supported range `8` to `256` |
| `MAX_SOCKET_CONNECTIONS` | `48` | Global admitted Socket.IO connections |
| `MAX_SOCKET_CONNECTIONS_PER_USER` | `8` | Per-user Socket.IO connections |
| `BACKGROUND_WORKERS` | Calculated baseline | Bounded executor; minimum is cleanup jobs plus global SSH-session and background-job quotas |
| `RUNTIME_SHUTDOWN_GRACE_SECONDS` | `5` | Graceful shutdown window; supported range `1` to `30` seconds |

Production requires exactly one Gunicorn worker with `gthread`. Live SSH channels and part of the coordination state are process-local. Increasing worker count does not scale WebSSH safely.

Keep at least four HTTP threads free:

```text
GUNICORN_THREADS - MAX_SOCKET_CONNECTIONS >= 4
```

LDAP adds a bounded cleanup task to the same runtime lifecycle; size background capacity as one combined budget.

## User quotas

| Variable | Default |
|---|---:|
| `QUOTA_SSH_SESSION_GLOBAL` | `10` |
| `QUOTA_SSH_SESSION_PER_USER` | `5` |
| `QUOTA_QUICK_CONNECTION_GLOBAL` | `12` |
| `QUOTA_QUICK_CONNECTION_PER_USER` | `3` |
| `QUOTA_TRANSFER_GLOBAL` | `8` |
| `QUOTA_TRANSFER_PER_USER` | `2` |
| `QUOTA_TEMP_BYTES_GLOBAL` | `1073741824` |
| `QUOTA_TEMP_BYTES_PER_USER` | `536870912` |
| `QUOTA_BACKGROUND_JOB_GLOBAL` | `4` |
| `QUOTA_BACKGROUND_JOB_PER_USER` | `1` |

Connection, transfer, background-work, and thread limits form one capacity model. Do not raise one limit in isolation without checking HTTP reserve, memory, remote-server capacity, and shutdown behavior.

## Rate limiting

| Variable | Default |
|---|---|
| `RATELIMIT_ENABLED` | `true` |
| `RATELIMIT_STORAGE_URL` | `memory://` |
| `RATELIMIT_DEFAULT` | `200 per hour` |
| `RATELIMIT_LOGIN_LIMIT` | `5 per minute` |
| `RATELIMIT_REAUTH` | `5 per minute` |
| `SSH_CONNECT_RATELIMIT` | `10 per minute` |

`memory://` is process-local and counters reset when the process restarts. Use a `redis://` URL for durable, shared counters. Redis does not change the one-worker architecture.

## File transfers and editor limits

| Variable | Default |
|---|---:|
| `MAX_DOWNLOAD_SIZE` | `104857600` (100 MiB) |
| `MAX_ZIP_DOWNLOAD_SIZE` | `524288000` (500 MiB) |
| `MAX_TRANSFER_MEMBERS` | `10000` |
| `MAX_PREVIEW_SIZE` | `512000` bytes |
| `MAX_PREVIEW_TAIL_LINES` | `10000` |
| `MAX_SUPPORTED_FILE_SIZE` | `1073741824` (1 GiB) |
| `SFTP_OPERATION_TIMEOUT` | `30` seconds |
| `MAX_EDITOR_FILE_SIZE` | `5242880` (5 MiB) |
| `TRANSFER_TEMP_DIR` | `DATA_DIR/tmp` |

Bulk uploads and downloads are streamed over HTTP; Socket.IO carries control events and bounded editor content rather than entire files. Align proxy request-body and timeout limits with WebSSH when increasing an application limit.

## Feature switches and tmux

| Variable | Default or purpose |
|---|---|
| `TMUX_ENABLED` | `false`; enables persistent remote tmux sessions |
| `TMUX_DEFAULT` | `false`; preselects tmux in the connection dialog |
| `TMUX_SESSION_PREFIX` | `webssh` |
| `HOST_KEY_MANAGEMENT_ENABLED` | `true` |
| `RECOVERY_CODES_ENABLED` | `true` |
| `AUDIT_EXPORT_ENABLED` | `true` |
| `MAX_RECOVERY_JSON_SIZE` | `4096` bytes |

## Passkey settings

| Variable | Purpose |
|---|---|
| `WEBAUTHN_ENABLED` | Enables Passkey registration and login |
| `WEBAUTHN_RP_ID` | Public domain only; defaults to `localhost` |
| `WEBAUTHN_RP_NAME` | Display name; defaults to `WebSSH` |
| `WEBAUTHN_ORIGIN` | Exact browser origin, including scheme and optional port |
| `MAX_WEBAUTHN_JSON_SIZE` | Request ceiling; defaults to 64 KiB |

## Audit and backup

| Variable | Default |
|---|---:|
| `AUDIT_LOG_MAX_BYTES` | `10485760` |
| `AUDIT_LOG_BACKUP_COUNT` | `5` |
| `BACKUP_UPLOAD_MAX_SIZE` | `1073741824` |
| `BACKUP_OPERATION_TIMEOUT` | `1800` |
| `BACKUP_DOWNLOAD_TTL` | `600` |
| `BACKUP_MAX_MEMBERS` | `10000` |
| `BACKUP_MAX_FILE_SIZE` | `1073741824` |
| `BACKUP_MAX_TOTAL_SIZE` | `10737418240` |
| `BACKUP_MAX_COMPRESSION_RATIO` | `200` |
| `BACKUP_MAX_MANIFEST_SIZE` | `10485760` |
| `BACKUP_TEMP_DIR` | System temporary directory under `webssh-backup-operations` |

Audit export scans at most 50,000 records and declares truncation in response metadata. Backup safety limits also cap archive member count, individual size, total size, compression ratio, and manifest size.

## OIDC, LDAP, Passkeys, and Tailscale

Identity-provider variables are grouped in their dedicated pages:

- [LDAP and Active Directory](LDAP-and-Active-Directory)
- [OpenID Connect](OpenID-Connect)
- [Passkeys and Recovery Codes](Passkeys-and-Recovery-Codes)
- [Tailscale SSH](Tailscale-SSH)

All optional identity providers are disabled until explicitly configured. Do not place bind passwords, OIDC client secrets, or other reusable credentials directly in Compose YAML committed to source control.

## Validate effective configuration

Render the merged Compose configuration before deployment:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  config
```

Add `-f docker-compose.ldap.yml` when LDAP is enabled. Confirm the effective bind address, origins, cookie mode, registration state, proxy trust, volumes, and secret files before starting the service.
