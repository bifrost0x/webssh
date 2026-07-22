<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/banner.svg" alt="Web SSH Terminal" width="500">
</p>

<p align="center">
  <strong>A modern, feature-rich web-based SSH terminal with SFTP file manager</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#themes">Themes</a> •
  <a href="#security">Security</a>
</p>

<p align="center">
  <!-- Statische Badges -->
  <a href="https://hub.docker.com/r/ghcr.io/bifrost0x/webssh"><img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs Welcome">
  <a href="https://bifrost0x.github.io/webssh/"><img src="https://img.shields.io/badge/code%20graph-live-blueviolet" alt="Code Graph"></a>
  <br>
  <!-- GitHub Actions Workflows -->
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/tests.yml">
    <img src="https://github.com/bifrost0x/webssh/actions/workflows/tests.yml/badge.svg" alt="Tests">
  </a>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/github-code-scanning/codeql">
    <img src="https://github.com/bifrost0x/webssh/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL">
  </a>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/dependabot/dependabot-updates">
    <img src="https://github.com/bifrost0x/webssh/actions/workflows/dependabot/dependabot-updates/badge.svg" alt="Dependabot Updates">
  </a>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/dependabot/update-graph">
    <img src="https://github.com/bifrost0x/webssh/actions/workflows/dependabot/update-graph/badge.svg" alt="Dependency Graph">
  </a>
  <br>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/dependency-graph/auto-submission">
    <img src="https://github.com/bifrost0x/webssh/actions/workflows/dependency-graph/auto-submission/badge.svg" alt="Automatic Dependency Submission">
  </a>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/docker-publish.yml">
    <img src="https://github.com/bifrost0x/webssh/actions/workflows/docker-publish.yml/badge.svg" alt="Build and Publish Docker Image">
  </a>
</p>

---

## Overview

Web SSH Terminal is a self-hosted web application that provides secure SSH access to your servers directly from your browser. Perfect for homelabs, server management, and teams that need browser-based terminal access. It is multi-user from the ground up, with individual accounts and per-user profiles, keys, and settings.

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/webssh-demo.gif" alt="Demo" width="800">
</p>

## Features

### Terminal

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/connection-panel.png" alt="Connection Panel" width="800">
</p>

- **Broadcast Input** - Send a command to all open SSH sessions simultaneously (cluster-SSH style)
- **Multi-Session Support** - Up to 10 concurrent SSH sessions with tabs
- **Split Panes** - 1, 2, or 4-pane layouts for monitoring multiple servers
- **Session Persistence** - Sessions survive page refreshes
- **Persistent tmux Sessions** - Keep remote shells and running commands alive across browser closes and WebSSH restarts, then reattach later
- **Manual Reconnect** - Reconnect from a session tab; SSH-key sessions can reconnect directly, while password sessions reopen the pre-filled connection form
- **Post-Connect Command Sets** - Build named, ordered command sequences and assign one to a connection or saved profile
- **Persistent Session Names** - Custom tab names are retained for persistent sessions across browsers
- **Configurable Scrollback** - Set 50 to 10,000 terminal lines and navigate them with the custom scrollbar
- **Copy/Paste** - Full clipboard support
- **Keyboard Shortcuts** - Ctrl+K command palette, Ctrl+F search, Ctrl+1–9 tab switching
- **Terminal Search** - Regex or plain-text in-terminal search (Ctrl+F)
- **Save Transcript** - Download the session output as a text file
- **Recent Connections** - Quick reconnect from your connection history
- **Session Notes** - Per-session notes, auto-saved as you type
- **Command Palette** - Fuzzy command launcher (Ctrl+K)

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/multi.png" alt="Split Panes" width="700">
</p>

### File Manager (SFTP)
- **Dual-Pane Browser** - Side-by-side file browsing
- **Drag & Drop** - Transfer files between local and remote
- **Server-to-Server** - Direct transfer between SSH hosts
- **Batch Operations** - Multi-select for bulk actions
- **Context Menu** - Right-click for quick actions
- **File Preview** - Inline preview for images and code (syntax-highlighted), with log tail mode
- **Folder Download as ZIP** - Download entire directories as a ZIP archive
- **Quick Connect** - Browse files over SFTP without opening a terminal session
- **Local Filesystem Source** - Use your browser's local files as a transfer source
- **Transfer Queue** - Progress tracking with conflict resolution (skip / overwrite / apply to all)
- **Efficient Binary Transfer** - Raw binary streaming (~33% smaller than base64)
- **Inline Editor** - Edit text files directly in the browser and save back over SFTP

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/filemanager.png" alt="File Manager" width="700">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/file-editing.gif" alt="Inline File Editor" width="800">
</p>

### Security
- **Encrypted Key Storage** - SSH keys encrypted at rest (Fernet / AES-128-CBC + HMAC)
- **Per-User Key Encryption** - Encryption key derived per user (`SECRET_KEY` + user id)
- **Secure Authentication** - bcrypt password hashing
- **CSRF Protection** - Token-based request validation
- **Rate Limiting** - Brute-force protection
- **Security Headers** - HSTS, CSP, X-Frame-Options
- **SSRF Protection** - Optionally block SSH to internal/loopback addresses (`BLOCK_INTERNAL_SSH`)
- **Host Key Auditing** - Persistent `known_hosts` policy with change detection
- **Audit Logging** - Structured JSON logs for auth, SSH, and file events
- **Session Ownership Checks** - Guards against cross-user session hijacking

### Customization
- **10 Themes** - Dark, light, and colorful options
- **6 Languages** - English, Vietnamese, German, French, Spanish, Chinese
- **Connection Profiles** - Save server configurations
- **Jump Hosts / ProxyJump** - Reach targets through a bastion; save jump hosts once, pick them per connection, with a clear "via &lt;bastion&gt;" indicator on the session
- **Command Library** - Store frequently used commands
- **OS-Aware Command Library** - Filter commands by detected OS (Linux / macOS / BSD / Windows)
- **Reusable Command Sets** - Combine library commands and free-text steps, reorder them, and reuse the result across profiles
- **SSH Key Management** - Import RSA, Ed25519, and ECDSA keys, encrypted at rest
- **Notepad** - Persistent scratchpad for notes, commands, and snippets
- **Mobile-Friendly** - Responsive layout for phones and tablets

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/commandlibrary.png" alt="Command Library" width="700">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/keys.png" alt="SSH Key Management" width="700">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/mobile.png" alt="Mobile View" width="350">
</p>

### Administration
- **Admin Panel** - Dedicated `/admin` page for administrators (role-gated)
- **User Management** - Create, lock/unlock, promote/demote and delete users; deletion revokes live access and quarantines the user's files outside the active user namespace
- **Audit Log Viewer** - Browse security events with level filter, search and pagination
- **Registration Toggle** - Enable or disable self-registration at runtime (hides the public sign-up link)
- **Zero-Touch Bootstrap** - First registered user becomes admin; when upgrading an older install, the oldest existing account is granted admin automatically (additional admins configurable via `ADMIN_USERS`)

### Deployment
- **Docker & Docker Compose** - Single-command deployment with healthcheck
- **Reverse Proxy Ready** - Traefik, nginx, and Caddy examples included
- **Subfolder Deployment** - Host under a URL subpath like `/webssh` (see [Subfolder Deployment](#subfolder-deployment))
- **Homelab Friendly** - Wildcard CORS mode for internal networks

## Quick Start

### Docker (Recommended)

```bash
# Run with Docker — SECRET_KEY is auto-generated and persisted to the volume
docker run -d \
  --name webssh \
  -p 5000:5000 \
  -e CORS_ORIGINS=http://localhost:5000 \
  -v webssh_data:/app/data \
  --restart unless-stopped \
  ghcr.io/bifrost0x/webssh:latest
```

> **Note:** Mounting a volume on `/app/data` keeps your users, keys, and the
> generated `SECRET_KEY` across updates. Set `SECRET_KEY` explicitly only for
> multi-replica deployments.

Open http://localhost:5000 and create your first account.

### Docker Compose

```bash
# Download docker-compose.yml
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml

# Start the service — SECRET_KEY is auto-generated and persisted to the volume
docker compose up -d
```

Open http://localhost:5000 and create your first account.

> **Tip:** Edit `docker-compose.yml` directly to change settings. No `.env` file needed!

### Tailscale SSH

Tailscale SSH is disabled by default because every authorized WebSSH account
uses the WebSSH node's **same Tailscale identity**. Enable it only for trusted
administrators or explicitly allowed homelab users. Use a dedicated Tailscale
tag, narrow ACL/SSH rules, and the optional WebSSH target and remote-username
allowlists. The backend enforces these controls; hiding the UI option is not the
security boundary.

Before enabling the feature, create the first administrator from a trusted
network and disable self-registration in the Admin Panel. Do not enable the
shared Tailscale identity on a fresh, publicly reachable installation: the
first registered WebSSH account becomes an administrator.

See [Tailscale SSH deployment and security](docs/tailscale-ssh.md) for all
configuration variables, ACL guidance, audit behavior, and a Docker sidecar
example with persistent Tailscale state.

### Persistent tmux Sessions

The provided `docker-compose.yml` enables persistent tmux sessions and selects
them by default for new connections. tmux must be installed on the remote SSH
host, not inside the WebSSH container. WebSSH checks the target before starting
a persistent session; if tmux is unavailable, it logs a warning and falls back
to a regular shell without failing the SSH connection.

Closing the browser, an idle timeout, or restarting WebSSH leaves the remote
tmux session running so it can be reattached later. Explicitly disconnecting a
session from the WebSSH interface terminates its remote tmux session.

### Commands After Connecting

The connection dialog lets you select one optional, named **command set**. Use
**Create new** directly beside the selector, or open **Commands** and switch to
the **Command Sets** tab to manage all sets. The builder can search the complete
command library by name, command text, parameters, description, or category and
filter the results by operating system.

A command set is an ordered list of steps. A step can reference a command from
the command library or contain free text. Library steps use the command's
current parameters by default; disable **Use library parameters** to provide an
override or intentionally leave the override empty. Free-text steps can stay in
the set or be moved into the command library with **Save as library command**.
Steps can be reordered by drag and drop or by the accessible up/down buttons.

New command sets enable **Run commands with sudo** by default. When enabled,
WebSSH prefixes each non-empty resolved command line unless it already starts
with `sudo`; blank and comment-only lines remain unchanged. Existing command sets from an earlier version and sets produced by legacy conversion keep sudo disabled, so upgrading or converting does not change what runs.

WebSSH does not store or answer a sudo password. If the remote account requires
one, its normal prompt appears in the terminal. The added prefixes count toward
the existing maximum 4096 characters for the resolved command text. No
additional environment variable, Compose setting, or service is required.

Profiles store only the selected command-set ID. Editing a set or one of its
referenced library commands therefore updates every profile that uses it. A set
cannot be deleted while a profile references it, and a user-created library
command cannot be deleted while a set references it. The UI reports the
profiles or sets that must be changed first.

After a new SSH connection succeeds, WebSSH resolves the latest referenced
commands on the server, validates the combined text (maximum 4096 characters),
and sends the steps to the remote interactive shell in their saved order. The
commands run on the remote SSH host, never inside the WebSSH container.
Reattaching to an existing persistent tmux session does not run them again.

Existing profiles that still contain the former free-text startup commands keep
working after an update. They show a legacy notice in the connection dialog and
can be converted into a named set. Conversion creates the set first, then links
the profile; the old text remains stored as a fallback but is ignored while the
new set reference is valid.

Command output and errors appear normally in the terminal. WebSSH does not
interpret a command's exit status or stop later lines because an earlier command
failed; any different control flow still follows the behavior of the remote
shell and the commands themselves. Treat command sets like any other remote
administration automation: review their contents and grant WebSSH accounts only
the SSH privileges they actually need.

No additional environment variable, Compose setting, frontend build step, or
external service is required. Command sets are stored per user in the existing
`DATA_DIR` volume alongside profiles and the command library.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/bifrost0x/webssh.git
cd webssh

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set required environment variable
export SECRET_KEY=$(openssl rand -hex 32)

# Run the application
python start.py
```

### Building Docker Image

```bash
docker build -t webssh:local .
```

## Configuration

### Environment Variables

#### Core
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | No | auto | Session encryption key. Auto-generated and persisted to `DATA_DIR/secret_key` on first run (Docker). Set explicitly for multi-replica setups or non-Docker production: `openssl rand -hex 32` |
| `DEBUG` | No | `False` | Enable debug mode (development only) |
| `DATA_DIR` | No | `/app/data` | Persistent data directory |

#### Server
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HOST` | No | `127.0.0.1` | Bind address (`0.0.0.0` in Docker) |
| `PORT` | No | `5000` | Listen port |
| `APPLICATION_ROOT` | No | - | URL subpath when deploying under a prefix (e.g. `/webssh`). See [Subfolder Deployment](#subfolder-deployment) |
| `TRUSTED_PROXIES` | No | `0` | Set `1` when behind a reverse proxy |

#### CORS & Security Headers
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CORS_ORIGINS` | No | `localhost:5000` | Allowed origins for CORS (comma-separated) |
| `ALLOW_CORS_WILDCARD` | No | `false` | Set `true` to allow `*` as CORS origin (homelab use only) |
| `SESSION_COOKIE_SECURE` | No | Auto | Set `true`/`false` to explicitly control secure cookies (auto-enabled in production) |

#### Features
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REGISTRATION_ENABLED` | No | `True` | Initial self-registration state (can be toggled later in the Admin Panel) |
| `ADMIN_USERS` | No | - | Comma-separated usernames granted admin on startup (e.g. `alice,bob`) |
| `SESSION_TIMEOUT` | No | `1800` | Idle SSH session timeout in seconds (30 minutes) |
| `BLOCK_INTERNAL_SSH` | No | `false` | Block SSH connections to internal/loopback addresses (`true` or `false`) |
| `TMUX_ENABLED` | No | `false` | Show and allow persistent tmux sessions. The provided Compose file sets this to `true` |
| `TMUX_DEFAULT` | No | `false` | Select persistent tmux for new connections by default. The provided Compose file sets this to `true` |
| `TMUX_SESSION_PREFIX` | No | `webssh` | Prefix used for tmux session names created on remote hosts |
| `TAILSCALE_SSH_ENABLED` | No | `false` | Enable shared-identity Tailscale SSH for administrators and explicitly allowed users |
| `TAILSCALE_SSH_ALLOWED_WEBSSH_USERS` | No | - | Comma-separated non-admin WebSSH usernames allowed to use Tailscale SSH |
| `TAILSCALE_SSH_ALLOWED_TARGETS` | No | - | Optional comma-separated exact host/IP allowlist for Tailscale SSH targets |
| `TAILSCALE_SSH_ALLOWED_REMOTE_USERS` | No | - | Optional comma-separated exact remote OS username allowlist for Tailscale SSH |
| `MAX_DOWNLOAD_SIZE` | No | `104857600` | Maximum file download size in bytes (100 MB) |
| `MAX_ZIP_DOWNLOAD_SIZE` | No | `524288000` | Maximum ZIP download size in bytes (500 MB) |
| `MAX_EDITOR_FILE_SIZE` | No | `5242880` | Maximum file size editable in the inline editor in bytes (5 MB) |

#### Rate Limiting
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RATELIMIT_ENABLED` | No | `True` | Enable rate limiting (`true` or `false`) |
| `RATELIMIT_LOGIN_LIMIT` | No | `5 per minute` | Login rate limit (format: `N per {second\|minute\|hour}`) |
| `SSH_CONNECT_RATELIMIT` | No | `10 per minute` | Per-user limit on SSH connection attempts (`ssh_connect` / `quick_connect`; format: `N per {second\|minute\|hour}`) |
| `RATELIMIT_DEFAULT` | No | `200 per hour` | Default rate limit for endpoints (format: `N per {second\|minute\|hour}`) |
| `RATELIMIT_STORAGE_URL` | No | `memory://` | Rate-limit storage (`memory://`, `redis://`, or `rediss://`). Redis preserves counters across app restarts while the Redis service remains available; it does not remove the single-worker requirement. |

### Configuration via .env file

Instead of exporting every variable, you can place them in a `.env` file in the
project root. It is loaded automatically on startup. Copy the provided template
to get started:

```bash
cp .env.example .env
# edit .env and set at least SECRET_KEY
python start.py
```

Real environment variables (set via the shell, Docker, or systemd) always take
precedence over values in `.env`, so the file works safely alongside existing
deployments. `.env` is git-ignored — never commit your real secrets.

### Reverse Proxy Setup

#### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.webssh.rule=Host(`ssh.example.com`)"
  - "traefik.http.routers.webssh.tls.certresolver=letsencrypt"
  - "traefik.http.services.webssh.loadbalancer.server.port=5000"
```

#### Nginx

```nginx
location / {
    proxy_pass http://webssh:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

#### Caddy

```caddyfile
ssh.example.com {
    reverse_proxy webssh:5000
}
```

### Subfolder Deployment

To serve the app under a URL subpath like `https://server.local/webssh`, set:

```bash
APPLICATION_ROOT=/webssh
TRUSTED_PROXIES=1
```

Then configure your reverse proxy to strip the prefix and forward it via `X-Forwarded-Prefix`.

#### Nginx (subfolder)

```nginx
location /webssh/ {
    proxy_pass http://webssh:5000/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /webssh;
}
```

#### Traefik (subfolder)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.webssh.rule=Host(`server.local`) && PathPrefix(`/webssh`)"
  - "traefik.http.middlewares.webssh-strip.stripprefix.prefixes=/webssh"
  - "traefik.http.middlewares.webssh-prefix.headers.customrequestheaders.X-Forwarded-Prefix=/webssh"
  - "traefik.http.routers.webssh.middlewares=webssh-strip,webssh-prefix"
  - "traefik.http.services.webssh.loadbalancer.server.port=5000"
```

#### Caddy (subfolder)

```caddyfile
server.local {
    handle_path /webssh/* {
        reverse_proxy webssh:5000 {
            header_up X-Forwarded-Prefix /webssh
        }
    }
}
```

### Homelab Configuration

For homelab use where you access the service from various internal IPs:

```bash
CORS_ORIGINS=*
ALLOW_CORS_WILDCARD=true
TRUSTED_PROXIES=1
```

> **Note:** Only use wildcard CORS in trusted network environments.

## Themes

Web SSH Terminal includes 10 themes:

| Theme | Style | Theme | Style |
|-------|-------|-------|-------|
| Glass Ops | Dark Blue | Paper Ops | Light |
| Retro Future | Amber | Noir Terminal | Purple |
| Solar Drift | Blue/Gold | Arctic Ice | Cyan |
| Rose Gold | Rose | Cyberpunk Neon | Magenta |
| Emerald Matrix | Matrix Green | Obsidian | Pure Black |

<p align="center">
  <img src="https://raw.githubusercontent.com/bifrost0x/webssh/main/assets/themes.png" alt="Themes" width="700">
</p>

## Security

### Best Practices

1. **Always use HTTPS** in production (terminate TLS at reverse proxy)
2. **Generate unique SECRET_KEY** for each deployment
3. **Set specific CORS_ORIGINS** instead of wildcard
4. **Enable TRUSTED_PROXIES** only when behind a proxy
5. **Use strong passwords** (minimum 8 characters enforced)

### Security Features

- **Password Hashing**: bcrypt with automatic salt
- **Constant-time Login**: failed logins run a dummy hash so response timing does not reveal whether an account exists (user-enumeration resistant)
- **Key Encryption**: Fernet (AES-128-CBC + HMAC) for SSH keys at rest
- **Rate Limiting**: 5 login attempts per minute per IP, plus a per-user cap on SSH connection attempts (`ssh_connect` / `quick_connect`) to prevent abuse as a brute-force/scan proxy
- **CSRF Tokens**: All forms protected
- **Secure Cookies**: HttpOnly, SameSite=Lax, Secure (in production)
- **Security Headers**: HSTS, CSP, X-Content-Type-Options, X-Frame-Options
- **SSRF Protection**: with `BLOCK_INTERNAL_SSH=true`, hostnames are resolved and connections to loopback, link-local (incl. cloud-metadata `169.254.169.254`), private, and reserved addresses are blocked — a hostname that resolves to an internal address cannot bypass the guard
- **Upload Limits**: bounded sizes for file uploads, editor saves, notepad, and SSH key uploads to prevent resource exhaustion
- **Folder Download Limits**: `MAX_ZIP_DOWNLOAD_SIZE` is enforced both when a ZIP is created on the remote host and while it is streamed to the Web SSH Terminal server; the SFTP fallback enforces the same configured cap

### Paramiko 5 SSH Compatibility

Web SSH Terminal uses Paramiko 5 and supports imported RSA, Ed25519, and
ECDSA private keys. Modern RSA keys remain supported when the server negotiates
RSA/SHA-2 signatures. Passphrase-encrypted imported private keys are not
currently supported.

Paramiko 5 no longer supports DSA/DSS, RSA signatures using SHA-1
(`ssh-rsa` as a signature algorithm), SHA-1 key exchange, GSSAPI, or
group-exchange parameters below 2048 bits. Required SSH servers must offer
modern algorithms; Web SSH Terminal does not re-enable the removed algorithms.
Existing DSA/DSS key files are not deleted or rewritten automatically and must
be replaced before upgrading.

Before deploying the upgrade, run the read-only compatibility check against a
copy of `DATA_DIR`, using the same `SECRET_KEY` that encrypted the stored
keys:

```bash
SECRET_KEY='the-current-deployment-secret' \
python scripts/check_paramiko5_readiness.py \
  --data-dir /absolute/path/to/copied-data
```

Exit code `0` means every discovered key is compatible. Exit code `2`
means rollout is blocked by an unsupported, encrypted, unreadable, or unsafe
key entry. Never point the check at the active writable data volume; it is
designed for a read-only snapshot and never migrates plaintext legacy keys.
Its report omits key content, configured key names, filenames, paths, and the
`SECRET_KEY`.

### Hosting & Data Protection

Web SSH Terminal is the SSH/SFTP client: the browser connects to this server,
and this server opens the connection to the target host. For team use or a
hosted deployment, treat the Web SSH Terminal host as trusted infrastructure.

#### Data processed by the server

While a connection is being established or is active, the server handles:

- **SSH credentials during connection setup.** Target and jump-host passwords,
  or the decrypted private key selected for authentication, are passed to
  Paramiko. Passwords are not written to profiles, the database, or audit logs,
  and credentials are not kept in the in-memory SSH session object. Local
  references are dropped after the connection attempt; Python does not provide
  a guarantee that secret bytes are securely zeroed from process memory.
- **Terminal data.** Keystrokes, remote output, broadcast input, and transcript
  data are relayed through the server.
- **SFTP data.** Uploads, downloads, previews, editor saves, and ZIP folder
  downloads pass through the server process.

The persistent data directory contains:

- The SQLite database with usernames, bcrypt password hashes, account flags,
  timestamps, browser-session metadata, and SSH-session metadata. SSH transport
  connections themselves remain in memory; the database record does not make a
  connection survive a server restart.
- Per-user JSON files for profiles, jump hosts, commands, notepad content, and
  settings. Saved profiles and jump-host definitions do not contain passwords.
- Encrypted SSH private keys and their metadata.
- Quarantined files from deleted accounts under
  `DATA_DIR/deleted_users/user_<id>_<uuid>`. Deleting an account revokes its
  live access and moves its active `users/user_<id>` directory atomically out
  of the active namespace; it does not securely erase the retained files.
- Persistent `known_hosts` fingerprints.
- Application and audit logs. Depending on the event, audit entries include
  usernames, source IPs, user agents, target hosts, filenames, sizes, and
  timestamps.

An administrator with access to the host or Python process can observe live
session content. Access to the data volume exposes account metadata, saved
configuration, logs, and — with the default Docker setup — the persisted
`SECRET_KEY`. Restrict access to the host, data volume, logs, and backups.

#### Security boundary

- SSH connection passwords are not intentionally persisted. Web SSH Terminal
  login passwords are stored only as bcrypt hashes.
- The project contains no built-in telemetry and serves its frontend libraries
  from `static/vendor/` instead of runtime CDNs. Connections explicitly
  requested by users, such as SSH targets and DNS lookups, still leave the host.
- This is **not end-to-end encryption between the browser and target host**.
  TLS protects browser-to-server traffic when configured at the reverse proxy,
  and SSH protects server-to-target traffic, but the Web SSH Terminal process
  necessarily handles terminal and file data in plaintext between those links.

#### SSH key protection

- Private keys are encrypted at rest with Fernet (AES-128-CBC with
  HMAC-SHA256 authentication).
- A per-user Fernet key is derived with PBKDF2-HMAC-SHA256 (600,000 iterations)
  from `SECRET_KEY` and the user id. One user's derived key therefore does not
  decrypt another user's key files.
- The keys directory is set to `0700`, and key files are written with `0600`
  permissions.
- Keys are decrypted when needed for authentication. Legacy plaintext key files
  are migrated to the encrypted format when first read.
- `SECRET_KEY` is the root of trust. Docker generates it on first start and
  stores it in `DATA_DIR/secret_key` unless supplied through the environment.
  Anyone with both the encrypted key files and this secret can decrypt the
  keys. For stronger separation, provide `SECRET_KEY` through an external
  secrets mechanism and protect backups of `DATA_DIR` accordingly.

#### Session protection

Browser sessions use Flask-Login cookies signed with `SECRET_KEY`. Session and
remember-me cookies are `HttpOnly`, `SameSite=Lax`, and secure by default outside
debug mode unless explicitly overridden with `SESSION_COOKIE_SECURE`. Remember-me
cookies last seven days. Logins without “Remember me” use browser-session
cookies; the application does not currently enforce a separate 30-minute HTTP
idle timeout. Forms are protected by Flask-WTF CSRF tokens. Login attempts are
rate-limited, unknown-user checks perform a dummy bcrypt verification, and new
or changed passwords are limited to 72 bytes when encoded as UTF-8 before they
are passed to bcrypt.

Locking or deleting an account immediately rejects further HTTP and WebSocket
authorization and revokes its tracked Socket.IO, SSH, and temporary SFTP
connections. An explicit logout performs the same live-connection cleanup.

Authenticated application WebSocket events use `socket_login_required`.
Session-scoped terminal and SFTP operations additionally verify ownership before
acting on a session, and terminal output is emitted to the owning user's private
room. SSH connection attempts are rate-limited per user. `SESSION_TIMEOUT`
(default: 1800 seconds) closes idle SSH sessions, and at most ten live SSH
sessions are retained by one application process.

New host keys use a persistent trust-on-first-use policy: the fingerprint is
stored and logged. A changed key for a known host is rejected by Paramiko. The
optional `BLOCK_INTERNAL_SSH` guard additionally blocks loopback, link-local,
private, and reserved targets after DNS resolution.

#### Operator responsibilities

- Terminate TLS at a trusted reverse proxy and configure `CORS_ORIGINS`,
  `TRUSTED_PROXIES`, and secure cookies for the public hostname.
- Restrict and encrypt backups of `DATA_DIR`; they may contain logs, account
  metadata, encrypted private keys, and the Docker-generated `SECRET_KEY`.
- Define a retention and secure-disposal policy for `DATA_DIR/deleted_users`.
  Account deletion quarantines those files to prevent numeric user-id reuse
  from exposing them, but does not wipe them automatically.
- Configure log rotation and a retention policy. The application writes log
  files but does not rotate them itself.
- Keep the service single-worker while SSH state remains in memory. Running
  multiple workers does not share live SSH sessions.

### Reporting Security Issues

Please report security vulnerabilities by opening a GitHub issue or contacting the maintainers directly. Do not disclose security issues publicly until they have been addressed.

## API

Web SSH Terminal uses WebSocket (Socket.IO) for real-time communication. HTTP routes handle authentication, the main UI is served over WebSocket.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main application |
| `/login` | GET/POST | Authentication |
| `/register` | GET/POST | User registration |
| `/logout` | POST | End the browser login and revoke tracked Socket.IO, SSH, and temporary SFTP connections |
| `/change-password` | GET/POST | Password change |
| `/api/upload` | POST | File upload (multipart) |
| `/admin`, `/admin/api/*` | GET/POST | Admin panel: user management, audit log, settings (admin-only) |
| `/socket.io/` | WS | Terminal, SFTP, profiles, keys, commands |

## Development

### Running Tests

```bash
pytest tests/
```

### Code Style

```bash
# Format code
black .

# Lint
flake8 .
```

### Frontend Assets

Browser libraries (xterm.js, socket.io-client, highlight.js, Material Icons) are
**vendored** into `static/vendor/` and served locally — no CDN requests, so the
app works fully offline/air-gapped. Versions are pinned in `package.json`; the
committed files under `static/vendor/` are what runs in production.

Node is only needed to *update* these assets, never at runtime:

```bash
npm install            # fetch pinned versions into node_modules/
npm run vendor         # copy them into static/vendor/
# commit the changed static/vendor/ files
```

To bump a library, change its version in `package.json`, then re-run the two
commands above. Dependabot keeps `package.json` up to date.

### Project Structure

> Vollständiger Abhängigkeitsgraphdes Tools
<a href="https://bifrost0x.github.io/webssh/">
  <img src="https://img.shields.io/badge/Interaktive%20Code--Map-%E2%86%97%20live-blueviolet?style=for-the-badge" alt="Interaktive Code-Map">
</a>


```
webssh/
├── app/                    # Flask application (20 modules)
│   ├── __init__.py        # App factory, routes, security headers
│   ├── auth.py            # Authentication + rate limiting
│   ├── models.py          # SQLAlchemy models
│   ├── socket_events.py   # WebSocket event handlers
│   ├── ssh_manager.py     # SSH connection management
│   ├── sftp_handler.py    # SFTP file operations
│   ├── connection_pool.py # SSH connection pooling
│   ├── key_manager.py     # SSH key storage
│   ├── key_encryption.py  # SSH key encryption at rest
│   ├── ssh_key_loader.py  # Shared Paramiko private-key validation
│   ├── profile_manager.py # Connection profiles
│   ├── jump_host_manager.py # Jump host (bastion) storage
│   ├── command_manager.py # Command library
│   ├── binary_transfer.py # Binary file transfer protocol
│   ├── user_settings.py   # User preferences
│   ├── user_lifecycle.py  # Account revocation and deletion quarantine
│   ├── app_settings.py    # Runtime app settings (e.g. registration toggle)
│   ├── storage_utils.py   # Atomic JSON writes + per-user locks
│   ├── audit_logger.py    # Security audit logging
│   └── decorators.py      # Shared decorators
├── static/
│   ├── css/               # Stylesheets (4 files)
│   ├── js/                # Frontend JavaScript (15 modules)
│   └── vendor/            # Vendored browser libs (see Frontend Assets)
├── templates/             # Jinja2 templates (5 files)
├── config.py              # Central configuration
├── scripts/               # Vendor and readiness utilities
├── start.py               # Entry point
├── Dockerfile             # Container definition
└── docker-compose.yml     # Compose file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [xterm.js](https://xtermjs.org/) - Terminal emulator
- [Paramiko](https://www.paramiko.org/) - SSH implementation
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/) - WebSocket support
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM

---

<p align="center">
  Made with ❤️ for the homelab community
</p>
