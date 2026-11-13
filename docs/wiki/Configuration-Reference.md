# Configuration Reference

WebSSH reads configuration from environment variables. A local `.env` file is loaded with `override=False`, so variables supplied by the operating system, container runtime, or secret manager take precedence.

Start from the repository's `.env.example`. The tables below describe the operational contract; check that file when upgrading because new options may be added.

## Core settings

| Variable | Purpose | Default or requirement |
|---|---|---|
| `SECRET_KEY` | Encrypts and signs security-sensitive state | Required for direct production starts. The container entrypoint can generate and persist it in the data volume. |
| `DATA_DIR` | Canonical SQLite, key, log, and generated-secret root | `/app/data` in the container; container overrides must be absolute and persistent |
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
| `HOST_DISCOVERY_ENABLED` | Offers manual SSH host discovery in a network range under Hosts → Find hosts | `true`; `false` in production |
| `SOCKETIO_ALLOW_ANY_ORIGIN` | With `CORS_ORIGINS=*`, realtime connections accept only pages served from the address used for WebSSH. `true` accepts any origin again; rejected in production | `false` |
| `TRUSTED_PROXIES` | Number of trusted reverse-proxy layers; `0` means none. Saved passwords and automation still work behind a TLS proxy at `0`: a page the browser loaded over `https://` from the same host counts as HTTPS. Set it to trust forwarded client addresses |
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
| `SSH_ALLOWED_INTERNAL_NETWORKS` | Comma-separated private networks (CIDR or single addresses) that stay reachable while `BLOCK_INTERNAL_SSH=true`; see below |
| `PROXY_JUMP_REMOTE_DNS_ALLOWLIST` | Exact hostnames a trusted bastion may resolve remotely |
| `SERVER_OPERATIONS_ENABLED` | Optional authoritative environment override; otherwise Admin → Integrations controls reviewed, step-up protected service/container actions, process TERM and reboot. Product default: `false` |

`BLOCK_INTERNAL_SSH=true` is appropriate for an Internet-facing gateway but can conflict with homelab use. Resolve and validate the exact target policy before enabling it. Host-key verification remains a separate control.

`SSH_ALLOWED_INTERNAL_NETWORKS` keeps `BLOCK_INTERNAL_SSH=true` in place and re-admits only the listed private networks, for example `10.20.0.0/16,fd00:20::/64`. It applies to direct targets, Jump Hosts and file-transfer connections, and it is accepted by the production profile. Entries must lie inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or `fc00::/7`; host bits, broader networks or any other range stop startup. Loopback, link-local (including cloud metadata addresses), multicast, reserved and IPv4-mapped IPv6 addresses always stay blocked. Every connection admitted through the list is recorded in the audit log.

## Runtime capacity

| Variable | Default | Contract |
|---|---:|---|
| `GUNICORN_THREADS` | `64` | Supported range `8` to `256` |
| `MAX_SOCKET_CONNECTIONS` | `48` | Global admitted Socket.IO connections |
| `MAX_SOCKET_CONNECTIONS_PER_USER` | `8` | Per-user Socket.IO connections |
| `BACKGROUND_WORKERS` | Calculated baseline | Bounded executor; minimum is cleanup jobs plus global SSH-session and background-job quotas. A lower explicit value is raised to the minimum with a startup warning |
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
| `SSH_KEY_WRITE_RATELIMIT` | `30 per minute` |
| `SSH_KEY_LIST_RATELIMIT` | `30 per minute` |
| `CONNECTION_MUTATION_RATELIMIT` | `60 per minute` |

Key listings and the refresh after renaming, replacing, or deleting a key share
`SSH_KEY_LIST_RATELIMIT` per user across browser connections. Admission is checked
before the mutation; when exhausted, the change is rejected without altering the
key. Accepted changes retain their acknowledgement and updated key list. Usability
is still checked against the current key files, without caching decrypted keys.

## SSH key and live-output limits

| Variable | Default |
|---|---:|
| `SSH_KEY_MAX_RECORDS` | `100` |
| `SSH_KEY_STORE_MAX_BYTES` | `8388608` (8 MiB encrypted) |
| `SSH_OUTPUT_MAX_UNACKED_BYTES_PER_SOCKET` | `524288` (512 KiB) |
| `SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_SOCKET` | `128` |
| `SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER` | `1024` |
| `SSH_OUTPUT_MAX_UNACKED_EVENTS_GLOBAL` | `8192` |
| `SSH_OUTPUT_MAX_UNACKED_BYTES_PER_USER` | `4194304` (4 MiB) |
| `SSH_OUTPUT_MAX_UNACKED_BYTES_GLOBAL` | `33554432` (32 MiB) |
| `SSH_OUTPUT_ACK_TIMEOUT_SECONDS` | `10` seconds |

The key limits reject only storage growth. A pre-existing store above the byte
limit remains readable and can be renamed, deleted, or replaced with smaller
keys. Live terminal output is acknowledged by each browser. If one browser
keeps an acknowledgement budget blocked for the configured timeout, WebSSH
applies SSH backpressure and then disconnects only that browser; the underlying
SSH or persistent tmux session remains available for reconnect.

All terminals in one browser connection share a delivery window of at most eight
unacknowledged output events, further constrained by the budgets above. This
paces SSH readers and keeps bursts of output ACKs below Engine.IO's polling
packet limit, with room for control traffic. Waiting for a delivery slot does
not itself mean that an ACK is overdue. The configured timeout still applies
to each outstanding output event. Opening more terminal tabs does not create
additional Socket.IO connections.

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
| `SFTP_CHMOD_ENABLED` | Optional authoritative override; otherwise Admin → Integrations controls SFTP Unix permissions (product default `false`), requiring `lsetstat@openssh.com` v1; separate file/folder modes, optional recursive preview jobs with bounded resource use; SFTP only |
| `SFTP_MAX_PACKET_BYTES` | `1048576` (1 MiB) |
| `SFTP_MAX_HANDLE_BYTES` | `16384` (16 KiB) |
| `MAX_EDITOR_FILE_SIZE` | `5242880` (5 MiB) |
| `EDITOR_SAVE_BYTES_PER_MINUTE` | `20971520` (20 MiB per user) |
| `TRANSFER_TEMP_DIR` | `DATA_DIR/tmp` |
| `FILE_CONTROL_MAX_PATH_BYTES` | `4096` bytes |
| `FILE_CONTROL_BYTES_PER_MINUTE` | `2097152` (2 MiB per user) |
| `REMOTE_FILENAME_MAX_BYTES` | `4096` bytes |
| `REMOTE_LISTING_MAX_METADATA_BYTES` | `4194304` (4 MiB) |
| `REMOTE_LISTING_PAGE_SIZE` | `500` entries |
| `REMOTE_LISTING_SNAPSHOT_TTL_SECONDS` | `60` seconds |
| `REMOTE_LISTING_SNAPSHOT_MAX_STATES` | `8` snapshots per process |
| `REMOTE_LISTING_SNAPSHOT_MAX_PER_USER` | `4` snapshots per user |
| `CONNECTION_STORE_RECOVERY_MAX_BYTES` | `16777216` (16 MiB) |
| `CONNECTION_STORE_RECOVERY_MAX_RECORDS` | `10000` |

Bulk uploads and downloads are streamed over HTTP; Socket.IO carries control events and bounded editor content rather than entire files. Align proxy request-body and timeout limits with WebSSH when increasing an application limit.

Enable file permission changes under **Settings → Administration → Integrations**.
`SFTP_CHMOD_ENABLED` is an optional authoritative environment override, not a
required activation step. See [Unix permissions](SFTP-File-Workspace-and-Transfers#unix-permissions).

SFTP directory responses are paged. Declared protocol packet and opaque handle
size, raw entry count (including `.` and `..`), filename, longname, aggregate
metadata, and file-control budgets are enforced before data is retained or
reflected.

## Saved connection limits

| Variable | Default |
|---|---:|
| `PROFILE_MAX_RECORDS` | `500` |
| `JUMP_HOST_MAX_RECORDS` | `100` |
| `CONNECTION_STORE_MAX_BYTES` | `2097152` (2 MiB per store) |
| `CONNECTION_CONFIG_MAX_BYTES` | `4194304` (4 MiB combined) |

Legacy stores above a normal limit are quarantined from the browser UI. After
stopping every WebSSH process, `flask --app start connection-store list` and
`connection-store delete` provide a non-secret, bounded recovery path up to
the separate recovery ceilings shown above. Growth is rejected, and profile
and jump-host key references remain ownership checked.

## Feature switches and tmux

| Variable | Default or purpose |
|---|---|
| `TMUX_ENABLED` | Optional override of Admin → Integrations; product default `true` (tmux available) |
| `TMUX_DEFAULT` | Optional override of Admin → Integrations; product default `false` (not preselected) |
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
| `BACKUP_RECOVERY_DURABLE` | `false`; must be `true` with durable external storage for online restore |

Audit export scans at most 50,000 records and declares truncation in response metadata. Backup safety limits also cap archive member count, individual size, total size, compression ratio, and manifest size.

`BACKUP_TEMP_DIR` may remain ephemeral for backup creation. Online restore
additionally requires it to be absolute, private, outside `DATA_DIR`, and
durable across process/container replacement.

## OIDC, GitHub, LDAP, Passkeys, and Tailscale

Identity-provider variables are grouped in their dedicated pages:

- [LDAP and Active Directory](LDAP-and-Active-Directory)
- [OpenID Connect](OpenID-Connect)
- [GitHub Authentication](GitHub-Authentication)
- [Passkeys and Recovery Codes](Passkeys-and-Recovery-Codes)
- [Tailscale SSH](Tailscale-SSH)

All optional identity providers are disabled until explicitly configured. GitHub is the exception to the environment-variable model: its complete configuration and encrypted client secret are managed in the Admin Panel, so no Compose or `.env` entries are required. Do not place bind passwords, OIDC client secrets, or other reusable credentials directly in Compose YAML committed to source control.

## Validate effective configuration

Render the merged Compose configuration before deployment:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  config
```

Add `-f docker-compose.ldap.yml` when LDAP is enabled. Confirm the effective bind address, origins, cookie mode, registration state, proxy trust, volumes, and secret files before starting the service.


## Runtime settings and existing Compose files

Manage file permission changes, server operations, tmux availability and the
initial tmux selection under **Settings → Administration → Integrations**.
Sensitive changes require administrator reauthentication and are audited.

For `SFTP_CHMOD_ENABLED`, `SERVER_OPERATIONS_ENABLED`, `TMUX_ENABLED` and
`TMUX_DEFAULT`, priority is: explicitly supplied environment value, saved Admin
setting, product default. Both explicit `true` and explicit `false` lock the UI;
an empty value counts as not supplied.
Compose/environment includes variables passed by Docker, systemd, a shell or the
application's `.env`; the application cannot identify which file supplied them.
Settings shows the key, effective value, stored value and source. Edit or remove
the variable and recreate the container to release the lock. Existing sessions
remain open; reload clients and reconnect SFTP after changing capabilities.

Until an administrator changes a switch, its stored value follows the last
explicit environment value, so removing the variable keeps the behavior the
operator set last. An administrator's own choice is retained under an override
and becomes effective again when that override is removed. Without the variable,
an administrator can enable the feature in the web interface; set it explicitly
to `false` to keep it off. Older Compose files do not need replacing.
Server actions and chmod are off by default; tmux is available by default and
never preselected, matching every Compose file shipped before 3.0.
Disabling server operations prevents new actions without undoing commands already
sent to a server. Remote account privileges are never expanded by these switches.

`AUTOMATION_ENABLED` follows the same rule. `REGISTRATION_ENABLED` remains only
the initial value, as in 2.x: a choice saved in Administration wins, and the
production profile always prohibits public self-registration. Password storage
remains an Admin policy. Authentication features retain their separate deployment-capability,
readiness and Admin-activation checks: allowing a capability does not enroll users
or bypass provider, HTTPS, origin, RP-ID or recovery checks. Networking, identity
provider trust, secrets, resource ceilings, mounts and backup recovery paths remain
deployment configuration. Audit retention is already managed in Administration.

Signed-in users see links to support WebSSH development in the account menu
and the Settings side panel. **Project support links** in Administration →
Integrations hides them for all users; the links load nothing from external
sites until a user follows one.

TOTP capability is available by default in 3.0; Admin activation remains off
until explicitly enabled. `TOTP_ENABLED=false` is the optional operator kill
switch. Existing enrolled users and saved activation choices are retained.


### Existing deployments and new installations

Updating an existing deployment's image through `latest` does not replace its
Compose file. Keep that file and its custom values. With an old Compose that
sets `TMUX_ENABLED=true`, version 3.0 continues to use `true`. Administration
shows Compose/environment as the authoritative source, the exact variable,
the effective value and the saved Admin value. The switch remains locked while
the override exists. The first 3.0 start saves the supplied value if no Admin
value exists; subsequent image updates do not replace saved Admin choices.
This behavior also applies to `TMUX_DEFAULT`, file permissions and server actions.

The current example Compose is for new installations. It leaves the runtime
feature overrides commented out so administrators can manage them immediately
in Administration → Integrations. Product defaults apply until an Admin value
is saved: tmux available but not preselected; file permissions and server
operations off. The defaults match the previous example Compose, so replacing
an old Compose file does not change tmux behavior. See the upgrade table in
the WebSSH 3 notes for all upgrade paths.
Network, authentication and other advanced deployment examples remain present.

Moving an existing deployment to Admin-managed settings is optional: start 3.0
with its original Compose, inspect the saved values, then remove only the
corresponding environment entries and recreate the container. The saved values
become effective. The rest of the deployment file stays intact.

Do not replace a customized old Compose with a new-installation template during
an image upgrade. Removed historical environment values cannot be reconstructed
if version 3.0 has never seen them. If a saved Admin value differs from the
current override, inspect it before removing the override.
