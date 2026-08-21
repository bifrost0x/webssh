# OpenID Connect

WebSSH provides optional OIDC authorization-code authentication with PKCE. It
is disabled by default and never auto-provisions a WebSSH account.

## Identity model

An administrator links an exact provider identity to an existing local account:

```text
(normalized issuer, subject) -> WebSSH user
```

Email addresses and usernames are not identity keys. Optional subject and email
domain allowlists are additional policy checks.

OIDC identities cannot be linked to LDAP-managed accounts.

## Provider requirements

- OIDC discovery and authorization-code flow.
- Exact HTTPS issuer.
- Registered WebSSH client ID.
- Client secret stored in a private read-only file.
- Exact callback URL ending in `/oidc/callback`.
- Claims containing a stable `sub` and the expected issuer.

Loopback HTTP callback is accepted only in the homelab profile. Use HTTPS for
real deployments.

## Configuration

```bash
OIDC_ENABLED=true
OIDC_ISSUER=https://idp.example.com
OIDC_CLIENT_ID=webssh
OIDC_CLIENT_SECRET_FILE=/run/secrets/webssh_oidc_client_secret
OIDC_REDIRECT_URI=https://ssh.example.com/oidc/callback
OIDC_ALLOWED_SUBJECTS=
OIDC_ALLOWED_DOMAINS=example.com
OIDC_LOGIN_RATE_LIMIT=10 per minute
```

| Variable | Purpose |
|---|---|
| `OIDC_ENABLED` | Register and expose OIDC integration |
| `OIDC_ISSUER` | Exact provider issuer URL |
| `OIDC_CLIENT_ID` | Registered client ID |
| `OIDC_CLIENT_SECRET_FILE` | Absolute private secret-file path |
| `OIDC_REDIRECT_URI` | Exact registered callback |
| `OIDC_ALLOWED_SUBJECTS` | Optional comma-separated subject allowlist |
| `OIDC_ALLOWED_DOMAINS` | Optional email-domain policy |
| `OIDC_LOGIN_RATE_LIMIT` | Per-IP start and callback limit |

Do not place the client secret directly in `.env` or Compose environment. Mount
the file read-only and restrict it to the service account.

## Protocol protections

WebSSH creates a random state, nonce, PKCE verifier, and browser-session binding
for each login. The state record is stored server-side, consumed once, and
deleted before the identity is accepted. The callback validates state binding,
expiry, token claims, nonce, issuer, subject policy, domain policy, account link,
and account state.

Provider failures return a generic unavailable response and do not expose token
or secret details.

## Link an identity

1. Enable OIDC and restart WebSSH.
2. Sign in as a local administrator.
3. Create or select the target local account.
4. In the Admin Panel, choose the OIDC link action.
5. Provide the exact provider subject.
6. Reauthenticate with the administrator password.
7. Confirm the exact target username.
8. Sign out and test OIDC login with the target identity.

The mapping is unique. A provider identity cannot be attached to multiple users.

## Unlink an identity

The administrator must reauthenticate and confirm the exact target username.
Unlinking removes only the mapping; the underlying local account remains.

Before unlinking the user's only practical sign-in method, verify a local
password, passkey, or recovery path.

## Allowlists

### Subject allowlist

`OIDC_ALLOWED_SUBJECTS` restricts accepted stable subjects. It is strongest when
the provider has a manageable fixed set of users.

### Email-domain policy

`OIDC_ALLOWED_DOMAINS` requires a matching email claim and domain. It is an
admission condition only. Linking and login still resolve identity by issuer
and subject.

## Failure behavior

| Symptom | Check |
|---|---|
| OIDC button absent | `OIDC_ENABLED` and startup logs |
| Provider unavailable | discovery URL, DNS, TLS, secret file, egress |
| Callback rejected | exact callback, state cookie, proxy origin, system time |
| Identity not linked | Admin mapping for issuer and subject |
| Domain rejected | email claim and `OIDC_ALLOWED_DOMAINS` |
| User rejected after link | locked account or LDAP-managed state |

## Recovery

Keep a local break-glass administrator. If the provider fails, local accounts
continue to use their configured factors. OIDC does not introduce automatic
account creation or privilege mapping.
