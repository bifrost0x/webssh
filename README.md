<p align="center">
  <img src="assets/banner.svg" alt="WebSSH" width="500">
</p>

<p align="center">
  <strong>A secure, self-hosted SSH and SFTP workspace for homelabs and teams.</strong>
</p>

<p align="center">
  <a href="https://bifrost0x.github.io/webssh/">Product site</a> ·
  <a href="https://github.com/bifrost0x/webssh/wiki">Documentation</a> ·
  <a href="https://github.com/bifrost0x/webssh/pkgs/container/webssh">Container image</a> ·
  <a href="https://github.com/bifrost0x/webssh/discussions">Discussions</a>
</p>

<p align="center">
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/tests.yml"><img src="https://github.com/bifrost0x/webssh/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/github-code-scanning/codeql"><img src="https://github.com/bifrost0x/webssh/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/bifrost0x/webssh/pkgs/container/webssh"><img src="https://img.shields.io/badge/container-GHCR-2496ED?logo=docker&logoColor=white" alt="GitHub Container Registry"></a>
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white" alt="Python 3.11 or newer">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea44f" alt="MIT License"></a>
  <a href="https://bifrost0x.github.io/webssh/code-graph/"><img src="https://img.shields.io/badge/Interaktive%20Code--Map-open-6f42c1" alt="Interactive code map"></a>
</p>

## Product tour

<p align="center">
  <img src="assets/webssh-demo.gif" alt="WebSSH tour showing a focused terminal, split sessions, the SFTP workspace, and account security" width="1100">
</p>

WebSSH keeps terminal work, files, commands, diagnostics, and notes in one
responsive browser workspace. It is self-hosted, multi-user, and built without
a hosted control plane or runtime CDN dependencies.

## Why WebSSH

- **One workspace, not a terminal tab.** Keep SSH sessions, SFTP sources,
  commands, live Linux context, and notes aligned with the active server.
- **Self-hosted by design.** Accounts, profiles, encrypted keys, host trust,
  audit records, and application data remain on your WebSSH instance.
- **Safe operational boundaries.** Authentication, ownership checks, network
  policy, host-key verification, quotas, and bounded runtime work are explicit.
- **Useful from phone to workstation.** The same interface adapts from a focused
  mobile shell to multi-pane desktop operations.

## Features

### Terminal workspace

- Multiple SSH sessions with tabs and 1-, 2-, or 4-pane layouts.
- Persistent remote shells through tmux when tmux is available on the target.
- Saved connections, jump hosts, key, password, and optional Tailscale SSH
  authentication paths.
- Broadcast input, terminal search, transcripts, reconnect controls, and
  configurable scrollback.
- Session-aware Files, Commands, Diagnostics, and Notes contexts.
- **Active Session Monitoring** for supported Linux resource and runtime data.
- **Expanded Diagnostics** for resource history, processes, systemd services,
  and Docker containers.
- **Clipboard-Only Service Actions** that prepare allowlisted commands without
  executing the service change inside WebSSH.

### Files and transfers

- Source-first SFTP and opt-in SMB workspace with independent tabs and one or
  two file panes.
- Uploads, downloads, previews, inline text editing, and common file operations.
- Streamed HTTP bulk transfers with Socket.IO limited to control events and
  bounded editor content.
- Server-to-server transfers across SFTP and SMB sources with progress,
  cancellation, explicit conflict handling, and a shared transfer queue.
- Same-source moves between folders without silently replacing existing items.
- Stable, visible transfer reasons such as permission denied, conflict,
  unavailable source, timeout, and configured-limit violations.
- Per-user ownership checks, size limits, quotas, and path validation.

SMB is disabled by default (`SMB_ENABLED=false`). Enabling it also requires an
exact `SMB_ALLOWED_TARGETS` server allowlist. WebSSH fixes SMB connections to
TCP 445 and requires SMB 3.1.1, signing, encryption, and secure negotiation;
the current authentication mode is NTLM. Guest access, DFS, Kerberos, and
automatic reconnect are not supported. SMB credentials are used for one
temporary connection. Passwords and authentication secrets are never stored by
WebSSH. Users may save non-secret, per-user share definitions containing a
display name, host, share, domain, and username.

For Active Directory and TrueNAS, first try the DNS domain (for example
`example.com`) with the account name (for example `alice`). Alternatively,
leave the domain field empty and use a UPN such as `alice@example.com`. NetBIOS
domain names may not be accepted by every server.

After connecting, WebSSH non-destructively checks root listing, file creation,
directory creation, and child deletion access. The workspace labels confirmed
write access, confirmed root read-only access, or unknown access; deeper ACLs
can still differ. Uploads and remote copies never silently overwrite an
existing destination: replace, skip, or cancel requires an explicit choice,
and replacement fails closed when the backend cannot provide an atomic rename.
SMB uses separate control and transfer sessions so browsing does not wait for a
bulk stream. Cancellation is a single idempotent request, and known oversized
operations report both the actual size and exact configured limit. Inline SMB
editing preserves revision checks and offers an explicit recoverable-swap path
when atomic replacement is unavailable.
Supported SMB targets must refuse symlink and wide-link traversal (for Samba,
use `follow symlinks = no` and `wide links = no`). WebSSH additionally opens
files and directories without following reparse points and validates existing
path components before remote operations.

This is a two-link trust boundary: browser TLS protects browser-to-WebSSH
traffic, while SMB encryption protects WebSSH-to-share traffic. The WebSSH process
necessarily handles the submitted credentials and transferred file contents, so
run it only on a trusted host and allowlist only trusted shares.

### Identity and security

- Local multi-user accounts with isolated profiles, keys, files, settings, and
  SSH host trust.
- Optional Passkeys, authenticator apps (TOTP), and one-time Recovery Codes.
- Optional OIDC, admin-configured GitHub App, and LDAP/Active Directory sign-in with conservative account
  linking and assurance handling.
- Action-bound confirmation for protected account and administrative changes.
- Encrypted SSH private-key storage and per-user known-host decisions.
- CSRF protection, secure response headers, rate limits, request limits, audit
  logging, and production fail-closed checks.

### Operations and administration

- Docker and Docker Compose deployment with a persistent data volume.
- Health and readiness endpoints for deployment checks.
- User administration, registration controls, security feature gates, and
  structured audit export and retention.
- Native backup and restore with maintenance mode, staging isolation, quotas,
  explicit confirmation, and bounded execution.
- Optional Redis-backed rate-limit counters.
- Vendored browser dependencies, restrictive CSP, and no built-in telemetry.

## Screenshots

### Focused session workspace

<p align="center">
  <img src="assets/workspace-overview.png" alt="Connected WebSSH terminal with active-session controls and a notes workspace" width="1100">
</p>

The active session stays central while contextual tools remain close at hand.

### Multiple live sessions

<p align="center">
  <img src="assets/multi-session.png" alt="WebSSH desktop workspace with two live terminal panes and four session tabs" width="1100">
</p>

Split panes make side-by-side observation and coordinated work visible without
mixing session ownership or terminal state.

### File workspace

<p align="center">
  <img src="assets/sftp-workspace.png" alt="WebSSH dual-pane file workspace with trusted sources and a transfer queue" width="1100">
</p>

Each pane has an explicit source, endpoint, path, trust state, and selection.

<p align="center">
  <img src="assets/file-editing.gif" alt="WebSSH file workflow from dual-pane browsing through preview, editing, save confirmation, and transfer completion" width="1100">
</p>

### Security Center

<p align="center">
  <img src="assets/security-center.png" alt="WebSSH Security Center showing sign-in assurance, SSH host trust, Passkeys, TOTP, and Recovery Codes" width="1100">
</p>

The Security Center explains how the current sign-in confirms protected
changes and keeps factors and SSH trust in one account-owned view.

### Mobile workspace

<p align="center">
  <img src="assets/mobile-workspace.png" alt="WebSSH mobile terminal workspace with responsive session controls and connection status" width="360">
</p>

## Quick Start

The supplied Compose file is intended for evaluation and trusted homelab
networks. It stores the database, generated application secret, user data, and
encrypted keys in the `webssh_data` volume.

```bash
mkdir webssh-deployment
cd webssh-deployment
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml
docker compose up -d
```

Open <http://localhost:5000>. On a new instance, create the first administrator
immediately from a trusted network. The one-time browser bootstrap closes after
that account exists.

Verify the container and readiness endpoint:

```bash
docker compose ps
curl -fsS http://localhost:5000/ready
```

For an Internet-facing instance, do not expose this homelab configuration
unchanged. Use the production overlay, an HTTPS reverse proxy, exact origins,
secure cookies, disabled browser registration, internal-target blocking, and
explicit trusted-proxy settings.

Read the [Quick Start](https://github.com/bifrost0x/webssh/wiki/Quick-Start) or
the complete [Production Deployment](https://github.com/bifrost0x/webssh/wiki/Production-Deployment)
guide before accepting users.

## Security Boundary

<p align="center">
  <img src="docs/media/diagrams/system-trust-boundaries.png" alt="WebSSH trust boundaries from the browser through the single application process to owned SSH and SFTP targets" width="1100">
</p>

WebSSH is trusted infrastructure. It processes connection credentials,
terminal input and output, and file data while establishing and maintaining SSH
and SFTP sessions. It is not an end-to-end encrypted relay that is blind to
session contents.

Keep these deployment contracts intact:

- Terminate HTTPS at a trusted boundary and protect the WebSSH host, data
  volume, logs, backups, and administrator accounts.
- Review SSH host-key fingerprints before trusting them and investigate
  unexpected changes.
- Production uses exactly **one Gunicorn `gthread` worker**. Live SSH state and
  part of the resource coordination are process-local; multiple workers or
  replicas are not supported without an external session-state architecture.
- Thread count, socket admission, per-user socket limits, background workers,
  and quotas form one capacity model. Keep HTTP capacity reserved.
- External OIDC or LDAP identity never bypasses the local account, ownership,
  or authorization model. Retain a tested local break-glass administrator.
- Backups can contain the persisted application secret and encrypted private
  keys together. Protect and test them accordingly.

See the [Security Model and Hardening](https://github.com/bifrost0x/webssh/wiki/Security-Model-and-Hardening)
guide and the project's [security policy](SECURITY.md) before exposing WebSSH
to untrusted networks.

## Documentation

The README is the project entry point. Detailed installation, operation,
security, authentication, recovery, and development guidance lives in the
[WebSSH Wiki](https://github.com/bifrost0x/webssh/wiki). Its
[versioned source](docs/wiki/Home.md) is reviewed with the code through pull
requests and published automatically after changes reach `main`.

| Goal | Guide |
|---|---|
| Install with Docker | [Docker and Docker Compose](https://github.com/bifrost0x/webssh/wiki/Docker-and-Docker-Compose) |
| Deploy behind HTTPS | [Production Deployment](https://github.com/bifrost0x/webssh/wiki/Production-Deployment) |
| Configure every setting | [Configuration Reference](https://github.com/bifrost0x/webssh/wiki/Configuration-Reference) |
| Connect and verify hosts | [SSH Connections and Host Keys](https://github.com/bifrost0x/webssh/wiki/SSH-Connections-and-Host-Keys) |
| Use terminal and tmux sessions | [Terminal and Persistent tmux Sessions](https://github.com/bifrost0x/webssh/wiki/Terminal-and-Persistent-tmux-Sessions) |
| Work with files and transfers | [SFTP File Workspace and Transfers](https://github.com/bifrost0x/webssh/wiki/SFTP-File-Workspace-and-Transfers) |
| Configure authentication | [Authentication Overview](https://github.com/bifrost0x/webssh/wiki/Authentication-Overview) |
| Run backup or restore | [Backup, Restore and Secret Rotation](https://github.com/bifrost0x/webssh/wiki/Backup-Restore-and-Secret-Rotation) |
| Troubleshoot health checks | [Health Checks and Troubleshooting](https://github.com/bifrost0x/webssh/wiki/Health-Checks-and-Troubleshooting) |
| Understand the runtime | [Architecture and Runtime Lifecycle](https://github.com/bifrost0x/webssh/wiki/Architecture-and-Runtime-Lifecycle) |
| Develop and test locally | [Development and Testing](https://github.com/bifrost0x/webssh/wiki/Development-and-Testing) |

Additional project views:

- [Product site](https://bifrost0x.github.io/webssh/)
- [Interactive code graph](https://bifrost0x.github.io/webssh/code-graph/)
- [Container image](https://github.com/bifrost0x/webssh/pkgs/container/webssh)

## Contributing and Support

Bug reports and focused pull requests are welcome. For feature proposals and
architecture ideas, start with [GitHub Discussions](https://github.com/bifrost0x/webssh/discussions)
so the security and runtime boundaries can be reviewed before implementation.

- Read [Development and Testing](https://github.com/bifrost0x/webssh/wiki/Development-and-Testing).
- Use [Issues](https://github.com/bifrost0x/webssh/issues) for reproducible bugs.
- Report vulnerabilities privately through
  [GitHub Security Advisories](https://github.com/bifrost0x/webssh/security/advisories/new).
- Support ongoing work through [Buy Me a Coffee](https://buymeacoffee.com/bifrost0x).

## License

WebSSH is available under the [MIT License](LICENSE).
