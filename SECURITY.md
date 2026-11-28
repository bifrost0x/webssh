# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

I take security seriously. If you discover a security vulnerability in WebSSH, please report it responsibly.

### How to Report

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via:
- **Email:** dwight@scranton.de
- **GitHub Security Advisories:** [Report a vulnerability](https://github.com/bifrost0x/webssh/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Resolution Target:** Within 30 days (depending on complexity)

### Disclosure Policy

- Please give me reasonable time to fix the issue before public disclosure
- I will credit reporters in the release notes (unless you prefer to stay anonymous)

## Security Model

### Authentication & Authorization

| Feature | Implementation |
|---------|----------------|
| Password Hashing | Argon2id with a random salt; bcrypt hashes taken over from 3.3 are verified and rehashed at the next sign-in |
| Session Management | Server-side sessions; the cookie holds a random token, the database only its MAC |
| WebSocket Auth | Session-based with ownership verification |
| CSRF Protection | Token bound to the browser and the session, required on every state-changing request |
| Rate Limiting | 5 login attempts per minute per IP |
| Passkeys | Optional WebAuthn with exact RP ID/origin checks, user verification, and one-use server-side challenges |
| TOTP | Optional authenticator-app MFA with per-user encrypted secrets, bounded enrollment, and replay-safe time-step consumption |
| Recovery | Single-use codes hashed at rest; usable only after valid primary authentication and restricted until factor replacement or explicit MFA disable |
| LDAP | Optional StartTLS/LDAPS authentication with certificate verification, stable directory identities, and fail-closed session revalidation |
| OIDC | Optional authorization-code flow with PKCE, nonce/state validation, explicit issuer/subject linking, and operator-defined signed `acr`/`amr` assurance |
| GitHub | Optional admin-configured GitHub App flow with PKCE, server-side one-use state, immutable numeric identity links, fail-closed organization policy, and non-admin-only provisioning |
| Admin Step-up | One-use five-minute grants bound to the current authentication session, exact action, exact target, and required assurance |

### Data Protection

| Data | Protection |
|------|------------|
| SSH Private Keys | Encrypted at rest with AES-256-GCM, each ciphertext bound to its record |
| GitHub Client Secret | Encrypted in the application database with a domain-separated key derived from the persisted `SECRET_KEY`; write-only in the Admin API |
| Key Derivation | HKDF-SHA256 from `SECRET_KEY` and the keyring material, one subkey per purpose ([ADR 0008](docs/adr/0008-keyring-for-secrets-at-rest.md)) |
| File Permissions | Keys stored with 0600, directories with 0700 |

### Network Security

| Feature | Implementation |
|---------|----------------|
| Security Headers | CSP, X-Frame-Options (DENY), X-Content-Type-Options, HSTS |
| CORS | Configurable, safe localhost-only default if unset |
| WebSocket | Authenticated, room-based isolation per user |
| Reverse Proxy | Forwarded headers trusted only with `TRUSTED_PROXIES` and from `TRUSTED_PROXY_CIDRS` |
| Request Bodies | Unsafe control requests are capped at 64 KiB before CSRF parsing; Recovery uses 4 KiB, WebAuthn uses 64 KiB, and SFTP uploads retain their separate streaming limit |

### SSH Security

| Feature | Implementation |
|---------|----------------|
| Host Key Verification | Trust-on-First-Use (TOFU) with persistent storage |
| Host Key Logging | New keys logged with fingerprint for audit |
| Connection Isolation | Session ownership verified on every operation |
| Credential Handling | Cleared from memory after use |
| Stored-key work | Connection attempt rate limiting precedes stored-key decryption; encrypted key stores have atomic count and byte growth limits |
| Remote clipboard | Persistent-tmux OSC 52 requests require a fresh, visible browser action; replayed and plain-SSH output cannot write the clipboard |
| Live output | Per-browser ACK accounting with per-socket, per-user, and global bounds applies SSH backpressure; a stalled browser is disconnected without closing its SSH/tmux session |

## Security Best Practices for Deployment

### Required

1. **Select and satisfy the production security profile**
   ```bash
   export DEPLOYMENT_PROFILE=production
   export DEBUG=False
   export CORS_ORIGINS=https://ssh.example.com
   export ALLOW_CORS_WILDCARD=false
   export SESSION_COOKIE_SECURE=true
   export REGISTRATION_ENABLED=False
   export BLOCK_INTERNAL_SSH=true
   export TRUSTED_PROXIES=1
   ```
   Production startup fails closed if these boundaries are unsafe or
   ambiguous. Set `TRUSTED_PROXIES=0` explicitly only when no proxy headers are
   trusted. Secure cookies remain required when TLS terminates at the proxy.
   When proxy headers are trusted, restrict the backend port to that proxy.
   The supplied production Compose override binds it to `127.0.0.1:5000`;
   use a private, unpublished network for a containerized reverse proxy.

2. **Set a strong SECRET_KEY**
   ```bash
   export SECRET_KEY=$(openssl rand -hex 32)
   ```

3. **Bootstrap the first administrator**
   ```bash
   webssh create-admin --username admin
   ```
   With Docker Compose, run:
   ```bash
   docker compose exec -it webssh /app/webssh create-admin --username admin
   ```
   The command prompts without echoing the password. This explicit path is
   recommended for production, where public registration is disabled. If an
   operator enables registration on a fresh installation, the first registered
   account becomes administrator and every later account remains a standard
   user. Never expose an unclaimed fresh instance to untrusted networks.

4. **Use TLS** - Deploy behind a reverse proxy with HTTPS

5. **Set specific CORS origins**
   ```bash
   export CORS_ORIGINS=https://your-domain.com
   ```

### Recommended

6. **Set TRUSTED_PROXIES** to the exact number of trusted proxy layers
   ```bash
   export TRUSTED_PROXIES=1
   ```

7. **Restrict network access** - Don't expose directly to the internet without protection

8. **Regular updates** - Keep the container image updated

9. **Create and verify offline backups**
   ```bash
   webssh backup create \
     --destination /secure-backups/webssh.tar \
     --confirm-offline
   webssh backup verify /secure-backups/webssh.tar
   ```
   Stop every WebSSH process using `DATA_DIR` before create, restore, or
   rotation operations. Native exports exclude saved remote passwords, legacy
   password vaults, SSH key directories (including metadata), and quarantined
   deleted-user data. Normal restore ignores these even in historical archives
   and clears existing copies. Reimport keys, recreate passwords, reassign
   credentials, then review and re-enable schedules. Archives retain account
   authentication data (password hashes, MFA data and provider secrets) and may
   include the persisted `SECRET_KEY`. They do not automatically remove secrets
   embedded in commands, notes or run history. Encrypt them separately, restrict
   access, and define retention and secure deletion. Historical archives are not
   rewritten and may still contain remote credentials.

10. **Rotate only a persisted application secret**
    ```bash
    webssh rotate-secret-key --confirm-offline
    ```
    The command refuses while a server uses `DATA_DIR`, while `SECRET_KEY`
    comes from the environment and while 3.3 data still exists (run
    `webssh legacy purge` first after an upgrade from 3.3). Before it changes
    anything it writes a recovery archive and prints its path; it then seals
    every stored secret again in one database transaction. Rotate secrets
    owned by an external secret manager through that manager and a separately
    controlled key migration. Recovery archives retain encrypted credentials
    for rollback; restrict access and manage their retention and cleanup.

11. **Keep a tested local break-glass administrator**
    OIDC and LDAP remain deployment-gated, while GitHub App authentication is
    configured at runtime in the Admin Panel. Every provider can fail
    independently of WebSSH. Keep at least one local administrator with a
    strong password and tested Passkey or TOTP factor. Store its Recovery Codes
    offline. GitHub-provisioned accounts can never become administrators.

### Optional MFA and assurance

MFA is not globally mandatory. An account continues to use its existing login
until that user enrolls a Passkey or authenticator app and explicitly enables
MFA. LDAP users can enroll local WebSSH factors after a recent directory login;
their directory password is neither retained nor converted into a local
password.

OIDC authentication is basic assurance unless a signed claim exactly matches
the provider-specific `OIDC_MFA_*` or `OIDC_PHISHING_RESISTANT_*` configuration.
Do not copy claim values from another provider. Verify the provider's token
contract and Conditional Access/authentication policy, then test both positive
and negative claims. Mobile push is an identity-provider capability, not a
WebSSH push service. Administrator provider reauthentication requests
`prompt=login`, `max_age=0`, and configured `OIDC_STEP_UP_ACR_VALUES`.

Recovery Codes do not replace the primary credential. After a successful
password or LDAP primary step, one code creates a restricted recovery session.
Only the Security page, replacement-factor enrollment, explicit MFA disable,
logout, and required static resources are available. A code is atomically
consumed and cannot be replayed.

Sensitive administrator mutations require action-bound step-up. Grants are
opaque, stored only as hashes server-side, consumed before route execution,
and never stored in browser local/session storage. A rule or feature-toggle
change does not kill existing browser or SSH sessions: affected users receive
the new policy on later authentication/enrollment, while active SSH work ends
through the normal configured session lifetime. Explicit account lock, delete,
and MFA-reset operations still revoke the target account as documented.

### Container Security

The Docker image is built `FROM scratch` and runs as the non-root user
1000:1000 with:
- One statically linked program, `/app/webssh`, owned by root and read-only
  for the service user; only the data and recovery directories are writable
- No shell, no package manager and no interpreter; `/bin/sh` and `python`
  are links to the program that accept only the health checks and helper
  commands of the 3.3 Compose files
- Restricted file permissions (0700 on data directories)
- No unnecessary capabilities
- Health check enabled (`/app/webssh healthcheck`)
- A separate `debug` variant with a BusyBox shell for troubleshooting only

Keep the previously deployed immutable image by its recorded registry digest
as the image-only rollback artifact. Redeploy it with the existing
`/app/data` volume and verify readiness, login, stored keys, terminal, and
SFTP. Successful publishes retain a verified `image-release-<commit-sha>`
Actions artifact containing the immutable registry reference for 90 days.
Preserve the deployed revision's artifact before an upgrade. The way back
from 3.4 to 3.3 is described in
[Upgrading to 3.4](docs/wiki/Upgrading-to-3.4.md#way-back-to-33).

## Known Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| In-Memory Rate Limiting | Counters live in the process and start empty after a restart | Exactly one server per `DATA_DIR`, enforced by a lock |
| TOFU Host Keys | Unknown keys require explicit confirmation before authentication | Verify the fingerprint through a trusted channel before accepting it |
| Deployment-gated identity features | Passkeys, TOTP, OIDC, and LDAP require both deployment allowance and Admin activation | Configure exact origins/provider settings, validate readiness, and keep local administrator recovery tested before activation |
| Runtime GitHub authentication | A bad callback, revoked client secret, missing organization permission, or GitHub outage can prevent provider login | Configure the GitHub App in the Admin Panel, use the exact callback, validate organization policy, and keep local administrator recovery tested |
| OIDC claim semantics vary | `acr` and `amr` do not have universal assurance meanings | Allowlist only values documented and tested for the configured provider; otherwise WebSSH treats the login as basic assurance |
| In-process live sessions | Active SSH state lives in the one WebSSH process | Run exactly one server per `DATA_DIR` and use the normal session lifetime instead of policy-triggered mass termination |

## Security Audit

This project has not undergone a formal third-party security audit. The code has been reviewed with security best practices in mind, but use in high-security environments should include additional review.

## Changelog

Security-relevant changes will be documented in release notes with the `[SECURITY]` tag.
