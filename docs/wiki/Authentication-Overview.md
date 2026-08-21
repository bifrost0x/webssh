# Authentication Overview

WebSSH supports local credentials plus optional external identity methods. All
methods resolve to an existing WebSSH `User`; identity providers do not grant
unbounded access to application state.

Authentication assurance is derived conservatively from the completed method
and its verified factors. Missing, malformed, or unmapped provider claims never
upgrade a session silently.

## Method comparison

| Method | Default | Identity binding | Suitable for |
|---|---:|---|---|
| Local password | Enabled | WebSSH username | Bootstrap, break-glass, ordinary local accounts |
| Passkey/WebAuthn | Disabled | Credential owned by a local account | Phishing-resistant local sign-in |
| Authenticator app (TOTP) | Disabled | Encrypted secret owned by a local account | Optional second factor after password, LDAP, or basic OIDC |
| Recovery code | Enabled | One-time code owned by a local account | Second-factor recovery after valid primary login |
| OIDC | Disabled | Exact issuer and subject linked by an admin | Existing OpenID Provider |
| LDAP/Active Directory | Disabled | Stable directory ID linked by an admin | Lab or organization directory authentication |

## Common controls

![WebSSH authentication assurance flow from primary identity through optional MFA and Recovery to administrator step-up](https://github.com/bifrost0x/webssh/blob/main/docs/media/diagrams/authentication-assurance.png?raw=true)

Primary authentication, account MFA, Recovery, and administrator Step-up are
separate contracts. Recovery never substitutes for the primary credential, and
an authenticated Admin session still needs a fresh one-use grant for each
sensitive action and target.

- Flask-Login manages browser authentication.
- Forms use Flask-WTF CSRF protection.
- Unknown-user password checks perform dummy bcrypt work.
- Login and reauthentication paths are rate-limited.
- Session cookies are `HttpOnly` and `SameSite=Lax`; production requires the
  `Secure` flag.
- Lock, deletion, logout, and failed LDAP revalidation revoke tracked live
  resources.
- Authenticated Socket.IO events use `socket_login_required` and resource
  operations add ownership checks.

## Deployment and Admin feature gates

Passkeys, TOTP, OIDC, LDAP, and Recovery each have three states:

1. Compose/environment configuration allows the feature.
2. Startup validation reports its dependencies and provider configuration ready.
3. An administrator activates it under **Admin → Settings → Authentication features**.

All three must be true. If, for example, `OIDC_ENABLED=false` in Compose, the
Admin toggle cannot start OIDC: it is locked with a deployment-configuration
reason. Recreate the container with valid configuration first, verify readiness,
then activate the feature. This two-step contract keeps the default Docker
homelab functional and prevents a browser-only setting from creating an
incomplete or unsafe provider setup.

Disabling a feature blocks later login or enrollment attempts. It does not
force-close an already authenticated browser session or active SSH work. Those
sessions retain their ordinary idle/lifetime limits. Explicit account lock,
delete, logout, or administrator MFA reset remains a revoking operation.

## Optional MFA

MFA is never forced globally. Users without an enrolled and enabled factor keep
their current login. Once a user enables MFA, password or LDAP performs the
primary step and WebSSH offers only factors actually available to that account:
Passkey, TOTP, and Recovery when enabled. A signed OIDC login can satisfy MFA
only when its exact `acr` or `amr` value matches operator configuration.

## Local passwords

WebSSH passwords are bcrypt hashes with generated salts. They are separate from
SSH target passwords. Target passwords are used for connection establishment
and are not written into profiles, the database, or audit logs.

Keep one local administrator even when external identity is enabled. An
external provider outage should not remove the operator's only recovery path.

## Passkeys

Passkeys are username-less discoverable WebAuthn credentials. The browser and
server must agree on the exact RP ID and origin. HTTPS is required outside the
localhost homelab exception.

Server-side challenges are bound to the browser session, one use only, and
expire after five minutes.

See [Passkeys and Recovery Codes](Passkeys-and-Recovery-Codes).

## Recovery codes

Recovery codes are one-time second-factor recovery for accounts that enabled
MFA. WebSSH stores only domain-separated hashes and performs fixed expensive
verification work. A new set invalidates the old set. The primary password or
LDAP verification must succeed before a code can be submitted.

The resulting recovery session is restricted to `/security`, replacement-factor
enrollment, explicit MFA disable, logout, and required static resources. Store
the plaintext set offline; it cannot be displayed again.

## OpenID Connect

OIDC uses the authorization-code flow with PKCE, nonce, state, and a
session-bound one-use login record. An administrator must link the exact issuer
and subject to a local account. Optional subject and email-domain rules are
additional admission filters, not identity keys.

Assurance is conservative: absent, malformed, or unmapped signed claims remain
`BASIC`. Provider push can be used only through the provider's own policy and a
documented signed claim; WebSSH does not operate a mobile push service.

See [OpenID Connect](OpenID-Connect).

## LDAP and Active Directory

LDAP uses mandatory certificate-verified StartTLS or LDAPS. A service account
searches for exactly one entry, then WebSSH binds with the submitted user
password. The password is not stored.

An administrator links the directory's stable ID to an existing non-admin
account. The primary credential becomes exclusively LDAP-managed and is
periodically revalidated fail-closed. After a recent directory login the user
may enroll local Passkey or TOTP second factors; WebSSH never stores the LDAP
password.

See [LDAP and Active Directory](LDAP-and-Active-Directory).

## Login-mode separation

The login UI presents optional identity methods as deliberate modes. A user who
chooses LDAP enters a dedicated LDAP form with a clear way back instead of
mixing directory fields into the local login form.

This separation matters operationally: local, OIDC, Passkey, TOTP, Recovery,
and LDAP flows have different failure and recovery semantics.

## Administrator step-up

Sensitive Admin mutations require a fresh, action-bound authorization. Local
administrators without MFA confirm their password. MFA-enabled administrators
use Passkey or TOTP. Recent sufficient OIDC assurance may be reused; otherwise
WebSSH opens provider reauthentication with `prompt=login`, `max_age=0`, and
configured `acr_values`.

The opaque grant lasts at most five minutes, works once, and is bound to the
current server-side authentication session, exact action, exact target, and
required assurance. A token for locking user 7 cannot promote user 7, lock user
8, or be replayed. It is never placed in browser local/session storage.

## Session revocation

Account revocation is broader than clearing a cookie. WebSSH attempts to cancel
transfers, disconnect Socket.IO sessions, close SSH sessions, close pooled
connections, and remove persisted session metadata.

LDAP adds periodic directory revalidation. A missing or changed identity,
directory exclusion, TLS failure, or outage fails the managed user's later
authorization. Feature-policy changes themselves do not mass-kill existing SSH
sessions; users can finish within the normal configured lifetime.

## Recommended rollout order

1. Deploy WebSSH with a local administrator.
2. Test local login and store break-glass Recovery Codes offline.
3. Put the instance behind its final HTTPS origin.
4. Allow and activate Passkeys/TOTP, then let a pilot user enroll voluntarily.
5. Configure one external provider.
6. Link one non-admin pilot account.
7. Test provider outage and rollback behavior.
8. Expand only after the break-glass path is verified.
