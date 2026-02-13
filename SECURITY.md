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

1. **Set a strong SECRET_KEY**
   ```bash
   export SECRET_KEY=$(openssl rand -hex 32)
   ```

2. **Use TLS** - Deploy behind a reverse proxy with HTTPS

3. **Set specific CORS origins** (defaults to localhost if unset)
   ```bash
   export CORS_ORIGINS=https://your-domain.com
   ```

### Recommended

4. **Enable TRUSTED_PROXIES** when behind a reverse proxy
   ```bash
   export TRUSTED_PROXIES=1
   ```

5. **Restrict network access** - Don't expose directly to the internet without protection

6. **Regular updates** - Keep the container image updated

### Container Security

The Docker image runs as non-root user (`appuser`) with:
- Restricted file permissions (0700 on data directories)
- No unnecessary capabilities
- Health check enabled

## Known Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| In-Memory Rate Limiting | Bypassed with multiple workers | Use single worker (default) |
| TOFU Host Keys | First connection auto-accepted | Review logs for new host keys |
| No MFA | Single-factor authentication only | Use strong passwords, restrict network access |
| No LDAP/SSO | Local accounts only | Planned for future release |

## Security Audit

This project has not undergone a formal third-party security audit. The code has been reviewed with security best practices in mind, but use in high-security environments should include additional review.

## Changelog

Security-relevant changes will be documented in release notes with the `[SECURITY]` tag.
