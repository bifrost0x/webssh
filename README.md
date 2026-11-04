<p align="center">
  <img src="static/images/webssh-logo.svg" alt="WebSSH" width="128" height="128">
</p>

# WebSSH

A self-hosted SSH and SFTP workspace for homelabs and teams. Open terminals,
manage files, and keep server commands and notes together in your browser.
Accounts, connection profiles, and application data stay on your instance.

<p>
  <a href="https://github.com/bifrost0x/webssh/actions/workflows/tests.yml"><img src="https://github.com/bifrost0x/webssh/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/python-3.11+-3776AB" alt="Python 3.11 or newer">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2ea44f" alt="Apache License 2.0"></a>
  <a href="https://getwebssh.com/code-graph/"><img src="https://img.shields.io/badge/Interactive%20Code--Map-open-6f42c1" alt="Interactive code map"></a>
</p>

[Website](https://getwebssh.com/) ·
[Documentation](https://github.com/bifrost0x/webssh/wiki) ·
[Releases](https://github.com/bifrost0x/webssh/releases) ·
[Container image](https://github.com/bifrost0x/webssh/pkgs/container/webssh) ·
<a href="https://www.youtube.com/watch?v=mw_qXUnYYVs">Watch the tour</a>

![WebSSH terminal and session workspace](assets/workspace-overview.png)

## Features

- **Browser terminals:** multiple SSH sessions, tabs, split panes, search,
  transcripts, broadcast input, and locally served terminal fonts.
- **Persistent shells:** optional remote tmux sessions, reconnect controls,
  and opt-in folder synchronization with explicit Bash prompt setup.
- **Connections and commands:** saved profiles, jump hosts, encrypted SSH keys,
  reusable Command Sets, and SSH password, key, and PAM MFA authentication.
- **Files:** dual-pane SFTP browsing, uploads and downloads, server-to-server
  transfers, previews, text editing with change review, and opt-in Unix permissions.
  Encrypted SMB shares are optional and require an explicit target allowlist.
- **Session tools:** Session-aware Files, Commands, Diagnostics, and Notes contexts;
  Active Session Monitoring, Expanded Diagnostics, and Clipboard-Only Service Actions.
  Direct server mutations require separate opt-in configuration.
- **Multi-user access:** isolated account data and host-key trust, optional
  Passkeys, TOTP, Recovery Codes, OIDC, GitHub App, and LDAP/Active Directory sign-in.
- **Administration:** user management, audit export, native backup and restore,
  readiness checks, and optional Redis-backed rate limits.

Browser scripts, styles, icons, and fonts are served locally. Node.js is used
for development tooling and vendor updates; it is not required at runtime.

## Quick Start

Requires Docker Engine and Docker Compose. The default configuration is for
trusted homelab networks and publishes port 5000. It persists the database,
application secret, user settings, and encrypted keys in the `webssh_data` volume.

```bash
mkdir webssh-deployment
cd webssh-deployment
curl -O https://raw.githubusercontent.com/bifrost0x/webssh/main/docker-compose.yml
docker compose up -d
```

Open [http://localhost:5000](http://localhost:5000) and create the first
administrator immediately from a trusted network. The one-time browser
bootstrap closes after that account exists.

```bash
docker compose ps
curl -fsS http://localhost:5000/ready
```

The supplied Compose file follows the `latest` image. For controlled upgrades,
pin a published version or immutable image digest and keep Compose files from
the same release. Back up the data and matching secrets before upgrading;
see [upgrade and rollback guidance](https://github.com/bifrost0x/webssh/wiki/Upgrading-Rollback-and-FAQ).

For Internet-facing deployments, use an HTTPS reverse proxy and the
[production overlay](https://github.com/bifrost0x/webssh/wiki/Production-Deployment).
Configure exact origins, secure cookies, trusted proxies, and SSH target policy;
do not expose the default homelab setup unchanged.

## Security and deployment

WebSSH handles connection credentials, terminal contents, and transferred files.
Protect the host, administrator accounts, data volume, logs, and backups as
trusted infrastructure. Verify SSH host-key fingerprints before accepting trust.

- Run exactly **one Gunicorn `gthread` worker**. SSH state is process-local;
  multiple workers or replicas are unsupported.
- Preserve the configured socket, thread, background-worker, and quota limits.
- Optional SMB, Tailscale SSH, SFTP chmod, and server mutations need explicit
  configuration. Feature flags do not grant additional remote privileges.
- Retain a tested local administrator when enabling external authentication.
- Backups may contain both the application secret and encrypted keys; protect
  them like credentials.

Read the [security model](https://github.com/bifrost0x/webssh/wiki/Security-Model-and-Hardening)
and [security policy](SECURITY.md). Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/bifrost0x/webssh/security/advisories/new).

## Documentation

The [WebSSH Wiki](https://github.com/bifrost0x/webssh/wiki) contains the operator
and user guides. Its [versioned source](docs/wiki/Home.md) is reviewed with the
code and published after changes reach `main`.

| Task | Guide |
|---|---|
| Install and connect | [Quick Start](https://github.com/bifrost0x/webssh/wiki/Quick-Start) |
| Deploy behind HTTPS | [Production Deployment](https://github.com/bifrost0x/webssh/wiki/Production-Deployment) |
| Configure the instance | [Configuration Reference](https://github.com/bifrost0x/webssh/wiki/Configuration-Reference) |
| Configure authentication | [Authentication Overview](https://github.com/bifrost0x/webssh/wiki/Authentication-Overview) |
| Work with files | [SFTP and transfers](https://github.com/bifrost0x/webssh/wiki/SFTP-File-Workspace-and-Transfers) |
| Back up and recover | [Backup and restore](https://github.com/bifrost0x/webssh/wiki/Backup-Restore-and-Secret-Rotation) |
| Develop and test | [Development and Testing](https://github.com/bifrost0x/webssh/wiki/Development-and-Testing) |

See also [screenshots and workflow previews](docs/screenshots.md),
[roadmap](ROADMAP.md), [release history](docs/project-history.md), and
[production container options](docs/production-container.md).

## Contributing and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
Use [Issues](https://github.com/bifrost0x/webssh/issues) for reproducible bugs
and [Discussions](https://github.com/bifrost0x/webssh/discussions) for feature ideas.
You can support development through [Buy Me a Coffee](https://buymeacoffee.com/bifrost0x).

## License

WebSSH is licensed under the [Apache License 2.0](LICENSE).
Bundled components retain their own licenses; see [licensing](docs/licensing.md),
[NOTICE](NOTICE), and [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
