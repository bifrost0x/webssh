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
| Password Hashing | bcrypt with auto-generated salt |
| Session Management | Flask-Login with secure cookies |
| WebSocket Auth | Session-based with ownership verification |
| CSRF Protection | Flask-WTF tokens on all forms |
| Rate Limiting | 5 login attempts per minute per IP |
| Passkeys | Optional WebAuthn with exact RP ID/origin checks, user verification, and one-use server-side challenges |
| Recovery | Single-use codes hashed at rest; administrator regeneration requires reauthentication and target confirmation |
| OIDC | Optional authorization-code flow with PKCE, nonce/state validation, and explicit issuer/subject linking |

### Data Protection

| Data | Protection |
|------|------------|
| SSH Private Keys | Encrypted at rest using Fernet (AES-128-CBC + HMAC) |
| Key Derivation | PBKDF2-SHA256 with 600,000 iterations |
| Per-User Isolation | Keys derived from `SECRET_KEY + user_id` |
| File Permissions | Keys stored with 0600, directories with 0700 |

### Network Security

| Feature | Implementation |
|---------|----------------|
| Security Headers | CSP, X-Frame-Options (DENY), X-Content-Type-Options, HSTS |
| CORS | Configurable, safe localhost-only default if unset |
| WebSocket | Authenticated, room-based isolation per user |
| Reverse Proxy | ProxyFix support via `TRUSTED_PROXIES` |

### SSH Security

| Feature | Implementation |
|---------|----------------|
| Host Key Verification | Trust-on-First-Use (TOFU) with persistent storage |
| Host Key Logging | New keys logged with fingerprint for audit |
| Connection Isolation | Session ownership verified on every operation |
| Credential Handling | Cleared from memory after use |

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
   flask --app start:app create-admin --username admin
   ```
   With Docker Compose, run:
   ```bash
   docker compose exec webssh /app/entrypoint.sh flask --app start:app create-admin --username admin
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
   flask --app start:app backup create \
     --destination /secure-backups/webssh.zip \
     --confirm-offline
   flask --app start:app backup verify /secure-backups/webssh.zip
   ```
   Stop every WebSSH process using `DATA_DIR` before create, restore, or
   rotation operations. Backups contain security-sensitive data and may include
   the persisted `SECRET_KEY`; encrypt them separately, restrict access, and
   define retention and secure deletion.

10. **Rotate only a persisted application secret**
    ```bash
    flask --app start:app rotate-secret-key --confirm-offline
    ```
    The command first creates and verifies a backup, stages and verifies every
    re-encrypted SSH key, and publishes `DATA_DIR/secret_key` last. It refuses
    an externally supplied secret that is missing from or differs from the
    persisted file. Rotate secrets owned by an external secret manager through
    that manager and a separately controlled key migration.

### Container Security

The Docker image runs as non-root user (`appuser`) with:
- Restricted file permissions (0700 on data directories)
- No unnecessary capabilities
- Health check enabled
- Gunicorn 26 `gthread` runtime with exactly one worker and a bounded,
  configurable `GUNICORN_THREADS` value (default: 3)
- Native Socket.IO threading only; no Eventlet worker or monkey patching path

`greenlet` can appear in the universal lock only because SQLAlchemy declares it
as a platform-marked transitive dependency. It is not a selectable WebSSH
runtime and must not be removed independently; changing that dependency graph
requires its own reviewed SQLAlchemy upgrade.

Keep the previously deployed immutable image by its recorded registry digest
as the image-only rollback artifact for the Gunicorn-26 runtime. Redeploy it
with the existing `/app/data` volume and verify readiness, login, stored keys,
terminal, and SFTP. No persistent-data rollback or format rewrite is required.

## Known Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| In-Memory Rate Limiting | Bypassed with multiple workers | Use single worker (default) |
| TOFU Host Keys | First connection auto-accepted | Review logs for new host keys |
| Optional identity features | WebAuthn and OIDC are disabled by default | Configure exact public origins and keep local administrator recovery tested before enabling OIDC |
| No LDAP | LDAP is not implemented | Use local accounts or the optional reviewed OIDC integration |

## Security Audit

This project has not undergone a formal third-party security audit. The code has been reviewed with security best practices in mind, but use in high-security environments should include additional review.

## Changelog

Security-relevant changes will be documented in release notes with the `[SECURITY]` tag.
