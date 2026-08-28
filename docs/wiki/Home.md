# WebSSH Wiki

WebSSH is a secure, self-hosted workspace for browser-based SSH terminals and
SFTP file operations. It is designed for homelabs, server administration, and
teams that want multi-user browser access without sending connection data to a
hosted control plane.

This Wiki is the long-form operator and user guide. For the compact project
overview, screenshots, release badges, and source code, visit the
[WebSSH repository](https://github.com/bifrost0x/webssh).

## What WebSSH provides

- Multiple simultaneous SSH sessions with tabs and split-pane layouts.
- A source-first SFTP workspace with independent tabs, one or two file areas,
  previews, inline editing, uploads, downloads, and server-to-server transfers.
- Per-user saved profiles, SSH keys, jump hosts, commands, command sets,
  notepad data, settings, and SSH host-key trust.
- Persistent remote shells through tmux.
- Linux session diagnostics for resources, processes, systemd services, and
  Docker containers.
- Local accounts, optional Passkeys and authenticator apps (TOTP), Recovery
  Codes, OIDC, GitHub App sign-in, and optional LDAP/Active Directory authentication with
  conservative authentication assurance.
- Administrative user management, structured audit logs, backup and restore,
  and security controls suitable for a trusted self-hosted deployment.
- A fully local browser runtime: vendored frontend dependencies and no built-in
  telemetry.

The WebSSH 2.0 interface uses a responsive, focused session workspace: terminal,
Files, Commands, Notes, and supported Linux insights stay aligned with the
selected SSH session across desktop, tablet, and mobile layouts.

## Choose your path

| Goal | Start here |
|---|---|
| Try WebSSH on a trusted network | [Quick Start](Quick-Start) |
| Understand volumes, images, and Compose | [Docker and Docker Compose](Docker-and-Docker-Compose) |
| Expose WebSSH through HTTPS | [Production Deployment](Production-Deployment) |
| Configure every environment setting | [Configuration Reference](Configuration-Reference) |
| Connect to SSH hosts safely | [SSH Connections and Host Keys](SSH-Connections-and-Host-Keys) |
| Enable LDAP or Active Directory | [LDAP and Active Directory](LDAP-and-Active-Directory) |
| Enable GitHub App sign-in | [GitHub Authentication](GitHub-Authentication) |
| Operate backups and recovery | [Backup, Restore and Secret Rotation](Backup-Restore-and-Secret-Rotation) |
| Diagnose an unhealthy instance | [Health Checks and Troubleshooting](Health-Checks-and-Troubleshooting) |
| Contribute code or documentation | [Development and Testing](Development-and-Testing) |

## Deployment model at a glance

![WebSSH trust boundaries from the browser through the single WebSSH process to owned SSH and SFTP targets](https://github.com/bifrost0x/webssh/blob/main/docs/media/diagrams/system-trust-boundaries.png?raw=true)

The supported path keeps authentication, ownership checks, network policy,
host-key verification, bounded runtime work, persisted state, and audit records
inside explicit boundaries. Optional OIDC or LDAP identity never bypasses the
local WebSSH account and resource-ownership model.

The browser connects to WebSSH over HTTP or HTTPS. WebSSH then opens the SSH
and SFTP connections to target hosts. WebSSH therefore processes terminal
input/output, file data, and connection credentials while establishing or
maintaining sessions. It is trusted infrastructure, not an end-to-end encrypted
relay that is blind to session contents.

Persistent state lives below `DATA_DIR` (normally `/app/data` in the container).
Live Paramiko SSH transports, active terminal readers, temporary SFTP
connections, and quota coordination are process-local.

> **Single-worker requirement:** production must run exactly one Gunicorn
> `gthread` worker. Increasing the thread count is supported within the
> documented range; adding application workers or replicas is not supported
> without an external session-state architecture.

## Homelab versus production

The supplied base Compose file uses `DEPLOYMENT_PROFILE=homelab`. It keeps HTTP
and private-network use convenient and reports unsafe combinations as warnings.
It is not the recommended Internet-facing configuration.

The production Compose overlay enables `DEPLOYMENT_PROFILE=production`, binds
the backend to loopback, requires a specific public HTTPS origin, enables secure
cookies, closes browser registration, blocks internal SSH targets, and requires
an explicit trusted-proxy boundary. Unsafe combinations stop startup.

Read [Production Deployment](Production-Deployment) before exposing WebSSH to
untrusted networks.

## Security starting points

- Protect WebSSH with HTTPS and a trusted reverse proxy.
- Restrict access to the host, data volume, logs, and backups.
- Keep a tested local break-glass administrator when enabling external identity.
- Review host-key fingerprints after first use and treat changes as incidents.
- Keep `BLOCK_INTERNAL_SSH=true` for exposed multi-user deployments unless a
  reviewed use case requires private targets.
- Back up `DATA_DIR` securely; a backup may contain the persisted `SECRET_KEY`
  and encrypted private keys together.
- Use the [Security Model and Hardening](Security-Model-and-Hardening) page as
  the deployment checklist.

## Documentation scope

These pages track the current WebSSH project and cover public, supported
behavior. Disabled UI placeholders are not documented as usable features.
Where a feature is optional, its page states the feature flag, prerequisites,
security boundary, activation procedure, and rollback path.

## Useful project links

- [Source repository](https://github.com/bifrost0x/webssh)
- [Container image](https://github.com/bifrost0x/webssh/pkgs/container/webssh)
- [Issues](https://github.com/bifrost0x/webssh/issues)
- [Discussions](https://github.com/bifrost0x/webssh/discussions)
- [Security advisories](https://github.com/bifrost0x/webssh/security/advisories)
- [Interactive code graph](https://bifrost0x.github.io/webssh/code-graph/)
