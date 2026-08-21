# Security Model and Hardening

WebSSH is a privileged gateway: it receives SSH credentials, opens remote sessions, processes terminal data, and transfers files. HTTPS protects browser traffic in transit, but WebSSH itself necessarily sees the material needed to perform those operations. It is not end-to-end encrypted between the browser and the SSH server.

## Trust boundaries

Protect all of the following as sensitive systems:

- the WebSSH host and container runtime;
- `DATA_DIR`, its backups, and the persisted `SECRET_KEY`;
- the reverse proxy and TLS private keys;
- LDAP bind, OIDC client, Redis, and other infrastructure credentials;
- administrator browsers and accounts;
- networks from WebSSH to SSH, LDAP, OIDC, Redis, and DNS endpoints.

A compromise of the WebSSH process or its host can expose active terminal/file data and credentials supplied to it.

## Built-in controls

WebSSH includes:

- CSRF protection for HTTP forms and authenticated Socket.IO event contracts;
- `HttpOnly`, `SameSite=Lax` session cookies and `Secure` cookies in production;
- Content Security Policy, HSTS in production, frame denial, MIME sniffing prevention, referrer policy, and permissions policy;
- per-user ownership checks for sessions, transfers, files, profiles, keys, and host-key data;
- bounded connection, transfer, temporary-storage, and background-work quotas;
- login, reauthentication, connection, backup, and default rate limits;
- explicit SSH target policy and per-user host-key verification;
- encrypted private-key storage derived per user;
- security audit logging and administrator reauthentication;
- bounded maintenance, shutdown, backup, and restore workflows.

These are defense layers, not a reason to expose a default homelab configuration directly to the Internet.

## Production baseline

For Internet exposure:

1. Use `docker-compose.production.yml` in addition to the base Compose file.
2. Terminate modern HTTPS at a maintained reverse proxy.
3. Bind WebSSH to loopback or a private network, not a public interface.
4. Set exact HTTPS `CORS_ORIGINS`; never use a wildcard.
5. Set `TRUSTED_PROXIES` to the exact number of trusted proxy layers.
6. Keep `SESSION_COOKIE_SECURE=true`.
7. Disable public registration and browser admin bootstrap.
8. Confirm that production's mandatory internal-target blocking matches the intended SSH target network.
9. Use Redis-backed rate limiting when counters must survive restarts.
10. Protect and test backups, recovery codes, and the local administrator path.

## SSH credentials and private keys

Stored SSH private keys are encrypted with Fernet. The per-user encryption material is derived using PBKDF2-HMAC-SHA256 with 600,000 iterations from `SECRET_KEY:user_id`. This reduces exposure from a copied data directory alone, but it does not protect keys from a running, fully compromised application that also has the secret.

Prefer scoped remote accounts, least privilege, short-lived credentials where possible, and SSH server-side restrictions. Never write passwords, tokens, or private-key contents to logs.

## Host-key verification

WebSSH uses a per-user known-hosts store and trust-on-first-use workflow. A newly trusted key is pinned. A changed key is rejected until the discrepancy is independently investigated and the old trust record is explicitly revoked.

Do not train users to accept changed keys as routine. Validate the remote host's fingerprint through a separate channel.

## Identity-provider hardening

- LDAP: use `ldaps://` or StartTLS, validate the server certificate, use a read-only least-privileged service account, and restrict user/group filters.
- OIDC: use a trusted issuer, exact redirect URIs, a secret file, and explicit domain or subject policy where required.
- Passkeys: keep recovery codes offline and revoke lost authenticators promptly.
- Tailscale SSH: use tight WebSSH-user, target, and remote-user allowlists; the node identity is shared.

LDAP/AD authentication does not copy directory passwords into WebSSH and does not automatically create local accounts. Authentication is denied unless a local account and explicit directory link already exist.

## Data at rest and backups

The SQLite database, user JSON files, known-host data, notes, profiles, commands, and encrypted keys live in `DATA_DIR`. Native backups may also contain the persisted `SECRET_KEY`, making them sufficient to decrypt stored key material. Encrypt backups separately and restrict access and retention.

## Vulnerability reporting

Do not disclose suspected vulnerabilities in a public issue. Follow the private reporting channels in the repository's `SECURITY.md`, such as a GitHub private security advisory or the listed security contact.

## Hardening verification

Before exposure, verify effective configuration rather than the intended `.env` alone:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  config
```

Then confirm HTTPS redirects, secure cookies, origin rejection, proxy IP handling, registration state, SSH target policy, host-key behavior, rate limiting, `/ready`, backup download expiry, and restore maintenance behavior.
