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
OIDC_MFA_AMR_VALUES=
OIDC_MFA_ACR_VALUES=
OIDC_PHISHING_RESISTANT_AMR_VALUES=
OIDC_PHISHING_RESISTANT_ACR_VALUES=
OIDC_STEP_UP_ACR_VALUES=
STEP_UP_MAX_AGE_SECONDS=300
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
| `OIDC_MFA_AMR_VALUES` | Exact signed `amr` values treated as MFA |
| `OIDC_MFA_ACR_VALUES` | Exact signed `acr` values treated as MFA |
| `OIDC_PHISHING_RESISTANT_AMR_VALUES` | Exact signed `amr` values treated as phishing-resistant |
| `OIDC_PHISHING_RESISTANT_ACR_VALUES` | Exact signed `acr` values treated as phishing-resistant |
| `OIDC_STEP_UP_ACR_VALUES` | Provider-specific assurance requested for Admin Step-up |
| `STEP_UP_MAX_AGE_SECONDS` | Age of recent strong authentication that may be reused (60-900 seconds) |

Do not place the client secret directly in `.env` or Compose environment. Mount
the file read-only and restrict it to the service account.

Deployment configuration does not activate the login button by itself. After a
successful restart and readiness check, activate OIDC under **Admin → Settings
→ Authentication features**. If `OIDC_ENABLED` is false or provider startup
validation failed, the toggle is locked; selecting it cannot start or repair
OIDC from the browser.

## Assurance and MFA claims

`acr` and `amr` values are provider-specific. WebSSH never guesses their
meaning. It normalizes only bounded signed token claims and compares them to the
exact operator-configured sets above:

- a match in `OIDC_PHISHING_RESISTANT_*` produces phishing-resistant assurance;
- otherwise a match in `OIDC_MFA_*` produces MFA assurance;
- missing, malformed, conflicting, or unmapped evidence remains basic.

Configure values only from the documentation and observed signed tokens of this
exact provider/app policy. A basic OIDC login cannot bypass MFA already enabled
on the linked WebSSH account; WebSSH continues with an available local Passkey,
TOTP, or Recovery second factor.

### Push on a mobile device

WebSSH does not send push notifications. Push works when the OIDC provider's
authentication policy invokes its own mobile app and returns a signed `acr` or
`amr` value that the operator mapped. This commonly requires provider-side MFA
or Conditional Access policy, app registration, and an allowed callback. Test
both a successful push and a password-only login before trusting the mapping.

## OIDC administrator Step-up

For a sensitive Admin action, WebSSH can open provider reauthentication with
`prompt=login`, `max_age=0`, and `OIDC_STEP_UP_ACR_VALUES`. The callback must:

- belong to the currently authenticated administrator;
- return the same linked issuer and subject;
- contain a current `auth_time`;
- meet the requested exact signed assurance;
- consume the one-use state successfully.

Only then does WebSSH create a one-use five-minute grant bound to the exact
Admin action and target. The popup returns no grant in its URL; the opener polls
once and sends the grant directly in the protected request.

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
6. Complete the administrator's available Step-up method.
7. Confirm the exact target username.
8. Sign out and test OIDC login with the target identity.

The mapping is unique. A provider identity cannot be attached to multiple users.

## Unlink an identity

The administrator must complete action-bound Step-up and confirm the exact
target username.
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
| Admin toggle disabled | Deployment flag or provider readiness failed; fix Compose/secret/discovery and recreate the container |
| Provider unavailable | discovery URL, DNS, TLS, secret file, egress |
| Callback rejected | exact callback, state cookie, proxy origin, system time |
| Identity not linked | Admin mapping for issuer and subject |
| Domain rejected | email claim and `OIDC_ALLOWED_DOMAINS` |
| User rejected after link | locked account or LDAP-managed state |

## Recovery

Keep a local break-glass administrator. If the provider fails, local accounts
continue to use their configured factors. OIDC does not introduce automatic
account creation or privilege mapping.

Disabling OIDC in the Admin Panel blocks later OIDC starts without forcibly
terminating existing browser or SSH sessions. Existing work reaches its normal
configured lifetime. Explicit account lock, deletion, and MFA reset still
revoke the target account.
